from abc import ABC, abstractmethod
from typing import List, Dict, Set, Optional, Any
import asyncio
from dataclasses import dataclass
from enum import Enum

from utils.logging import main_logger
from utils.helpers import DomainValidator


class SourceStatus(Enum):
    """Status of a subdomain discovery source"""
    READY = "ready"
    RUNNING = "running" 
    COMPLETED = "completed"
    FAILED = "failed"
    DISABLED = "disabled"


@dataclass
class SubdomainResult:
    """Result from subdomain discovery"""
    subdomain: str
    source: str
    ip_address: Optional[str] = None
    confidence: float = 1.0
    metadata: Optional[Dict[str, Any]] = None
    
    def __post_init__(self):
        """Validate and normalize subdomain"""
        self.subdomain = DomainValidator.normalize_domain(self.subdomain)
        if not DomainValidator.is_valid_domain(self.subdomain):
            raise ValueError(f"Invalid subdomain format: {self.subdomain}")


class BaseSubdomainSource(ABC):
    """Base class for all subdomain discovery sources"""
    
    def __init__(self, name: str, description: str = "", enabled: bool = True):
        self.name = name
        self.description = description
        self.enabled = enabled
        self.status = SourceStatus.READY
        self.results = []
        self.errors = []
        self.config = {}
    
    @abstractmethod
    async def discover(self, target: str, **kwargs) -> List[SubdomainResult]:
        """
        Discover subdomains for the target domain
        
        Args:
            target: Target domain to discover subdomains for
            **kwargs: Additional configuration parameters
            
        Returns:
            List of SubdomainResult objects
        """
        pass
    
    def configure(self, config: Dict[str, Any]):
        """Configure the source with settings"""
        self.config.update(config)
    
    def validate_target(self, target: str) -> bool:
        """Validate target domain"""
        return DomainValidator.is_valid_domain(target)
    
    def filter_results(self, results: List[str], target: str) -> List[str]:
        """Filter and validate discovered subdomains"""
        filtered = []
        target_normalized = DomainValidator.normalize_domain(target)
        
        for subdomain in results:
            try:
                normalized = DomainValidator.normalize_domain(subdomain)
                if (DomainValidator.is_valid_domain(normalized) and 
                    DomainValidator.is_subdomain(normalized, target_normalized)):
                    filtered.append(normalized)
            except Exception as e:
                main_logger.debug(f"Filtering error for {subdomain}: {e}")
        
        return list(set(filtered))  # Remove duplicates
    
    def set_status(self, status: SourceStatus, message: str = ""):
        """Set source status with optional message"""
        self.status = status
        if message:
            if status == SourceStatus.FAILED:
                self.errors.append(message)
                main_logger.error(f"{self.name}: {message}")
            else:
                main_logger.debug(f"{self.name}: {message}")
    
    async def run_discovery(self, target: str, **kwargs) -> List[SubdomainResult]:
        """Run discovery with error handling and status management"""
        if not self.enabled:
            self.set_status(SourceStatus.DISABLED)
            return []
        
        if not self.validate_target(target):
            self.set_status(SourceStatus.FAILED, f"Invalid target domain: {target}")
            return []
        
        try:
            self.set_status(SourceStatus.RUNNING, f"Starting discovery for {target}")
            results = await self.discover(target, **kwargs)
            
            # Validate results
            valid_results = []
            for result in results:
                if isinstance(result, SubdomainResult):
                    if DomainValidator.is_subdomain(result.subdomain, target):
                        valid_results.append(result)
                    else:
                        main_logger.debug(f"Filtered out-of-scope: {result.subdomain}")
            
            self.results.extend(valid_results)
            self.set_status(SourceStatus.COMPLETED, f"Found {len(valid_results)} subdomains")
            return valid_results
            
        except Exception as e:
            self.set_status(SourceStatus.FAILED, f"Discovery failed: {str(e)}")
            return []
    
    def get_stats(self) -> Dict[str, Any]:
        """Get source statistics"""
        return {
            'name': self.name,
            'status': self.status.value,
            'results_count': len(self.results),
            'errors_count': len(self.errors),
            'enabled': self.enabled,
            'description': self.description
        }


class PassiveSource(BaseSubdomainSource):
    """Base class for passive subdomain discovery sources"""
    
    def __init__(self, name: str, description: str = "", api_key: str = None, rate_limit: int = 10):
        super().__init__(name, description)
        self.api_key = api_key
        self.rate_limit = rate_limit  # requests per second
        self._semaphore = asyncio.Semaphore(rate_limit)
    
    async def rate_limited_request(self, func, *args, **kwargs):
        """Execute function with rate limiting"""
        async with self._semaphore:
            result = await func(*args, **kwargs)
            await asyncio.sleep(1 / self.rate_limit)  # Rate limiting
            return result


class ActiveSource(BaseSubdomainSource):
    """Base class for active subdomain discovery sources"""
    
    def __init__(self, name: str, description: str = "", wordlist_path: str = None):
        super().__init__(name, description)
        self.wordlist_path = wordlist_path
        self.wordlist = []
        self.max_concurrent = 100
    
    def load_wordlist(self, wordlist_path: str = None) -> List[str]:
        """Load wordlist for brute force discovery"""
        from ..utils.helpers import FileHelper
        
        path = wordlist_path or self.wordlist_path
        if path:
            self.wordlist = FileHelper.read_wordlist(path)
        
        if not self.wordlist:
            # Default basic wordlist
            self.wordlist = [
                'www', 'mail', 'ftp', 'api', 'admin', 'test', 'dev', 'staging',
                'blog', 'shop', 'store', 'cdn', 'static', 'assets', 'img',
                'images', 'js', 'css', 'uploads', 'files', 'docs', 'support',
                'help', 'portal', 'dashboard', 'panel', 'login', 'auth',
                'secure', 'ssl', 'vpn', 'remote', 'access', 'gateway'
            ]
        
        return self.wordlist


class SourceManager:
    """Manager for coordinating multiple subdomain discovery sources"""
    
    def __init__(self):
        self.sources = {}
        self.results = []
        self.all_subdomains = set()
    
    def register_source(self, source: BaseSubdomainSource):
        """Register a subdomain discovery source"""
        self.sources[source.name] = source
        main_logger.info(f"Registered source: {source.name}")
    
    def enable_source(self, name: str):
        """Enable a specific source"""
        if name in self.sources:
            self.sources[name].enabled = True
    
    def disable_source(self, name: str):
        """Disable a specific source"""
        if name in self.sources:
            self.sources[name].enabled = False
    
    def configure_source(self, name: str, config: Dict[str, Any]):
        """Configure a specific source"""
        if name in self.sources:
            self.sources[name].configure(config)
    
    async def discover_all(self, target: str, sources: List[str] = None, 
                          parallel: bool = True, **kwargs) -> List[SubdomainResult]:
        """
        Run discovery using multiple sources
        
        Args:
            target: Target domain
            sources: List of source names to use (None for all enabled)
            parallel: Run sources in parallel or sequentially
            **kwargs: Additional configuration for sources
            
        Returns:
            Combined list of SubdomainResult objects
        """
        if sources is None:
            active_sources = [s for s in self.sources.values() if s.enabled]
        else:
            active_sources = [self.sources[name] for name in sources if name in self.sources]
        
        if not active_sources:
            main_logger.warning("No active sources available for discovery")
            return []
        
        main_logger.info(f"Starting discovery with {len(active_sources)} sources: {[s.name for s in active_sources]}")
        
        all_results = []
        
        if parallel:
            # Run sources in parallel
            tasks = [source.run_discovery(target, **kwargs) for source in active_sources]
            results_list = await asyncio.gather(*tasks, return_exceptions=True)
            
            for i, results in enumerate(results_list):
                if isinstance(results, Exception):
                    main_logger.error(f"Source {active_sources[i].name} failed: {results}")
                else:
                    all_results.extend(results)
        else:
            # Run sources sequentially
            for source in active_sources:
                results = await source.run_discovery(target, **kwargs)
                all_results.extend(results)
        
        # Deduplicate results while preserving source attribution
        unique_results = {}
        for result in all_results:
            key = result.subdomain
            if key not in unique_results:
                unique_results[key] = result
            else:
                # Merge sources if same subdomain found by multiple sources
                existing = unique_results[key]
                if result.source not in existing.source:
                    existing.source += f", {result.source}"
                # Use higher confidence
                if result.confidence > existing.confidence:
                    existing.confidence = result.confidence
                # Merge metadata
                if result.metadata:
                    if not existing.metadata:
                        existing.metadata = {}
                    existing.metadata.update(result.metadata)
        
        final_results = list(unique_results.values())
        self.results = final_results
        self.all_subdomains = {r.subdomain for r in final_results}
        
        main_logger.success(f"Discovery completed: {len(final_results)} unique subdomains found")
        return final_results
    
    def get_source_stats(self) -> Dict[str, Dict[str, Any]]:
        """Get statistics for all sources"""
        return {name: source.get_stats() for name, source in self.sources.items()}
    
    def get_summary(self) -> Dict[str, Any]:
        """Get overall discovery summary"""
        return {
            'total_sources': len(self.sources),
            'enabled_sources': sum(1 for s in self.sources.values() if s.enabled),
            'total_subdomains': len(self.all_subdomains),
            'source_stats': self.get_source_stats()
        }