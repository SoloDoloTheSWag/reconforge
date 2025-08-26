from abc import ABC, abstractmethod
from typing import List, Dict, Optional, Any, Set
from enum import Enum
from dataclasses import dataclass
import asyncio
from datetime import datetime

from utils.logging import main_logger


class VulnerabilitySeverity(Enum):
    """Severity levels for vulnerabilities"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium" 
    LOW = "low"
    INFO = "info"


class ScannerStatus(Enum):
    """Status of vulnerability scanner"""
    READY = "ready"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    DISABLED = "disabled"


@dataclass
class VulnerabilityResult:
    """Result from vulnerability scanning"""
    title: str
    severity: VulnerabilitySeverity
    vulnerability_type: str
    target: str
    description: str = ""
    url: Optional[str] = None
    method: Optional[str] = None
    payload: Optional[str] = None
    response: Optional[str] = None
    template_id: Optional[str] = None
    cvss_score: Optional[float] = None
    cve_id: Optional[str] = None
    reference_urls: List[str] = None
    verified: bool = False
    confidence: float = 1.0
    metadata: Optional[Dict[str, Any]] = None
    
    def __post_init__(self):
        """Initialize default values"""
        if self.reference_urls is None:
            self.reference_urls = []
        if self.metadata is None:
            self.metadata = {}


@dataclass
class ServiceInfo:
    """Information about discovered service"""
    host: str
    port: int
    protocol: str = "tcp"
    service_name: Optional[str] = None
    service_version: Optional[str] = None
    banner: Optional[str] = None
    state: str = "open"
    ssl_enabled: bool = False
    fingerprint: Optional[Dict[str, Any]] = None
    
    def __post_init__(self):
        """Initialize default values"""
        if self.fingerprint is None:
            self.fingerprint = {}


class BaseVulnerabilityScanner(ABC):
    """Base class for all vulnerability scanners"""
    
    def __init__(self, name: str, description: str = "", enabled: bool = True):
        self.name = name
        self.description = description
        self.enabled = enabled
        self.status = ScannerStatus.READY
        self.results = []
        self.errors = []
        self.config = {}
        self.start_time = None
        self.end_time = None
    
    @abstractmethod
    async def scan(self, targets: List[str], **kwargs) -> List[VulnerabilityResult]:
        """
        Scan targets for vulnerabilities
        
        Args:
            targets: List of target URLs/IPs to scan
            **kwargs: Additional configuration parameters
            
        Returns:
            List of VulnerabilityResult objects
        """
        pass
    
    def configure(self, config: Dict[str, Any]):
        """Configure the scanner with settings"""
        self.config.update(config)
    
    def set_status(self, status: ScannerStatus, message: str = ""):
        """Set scanner status with optional message"""
        self.status = status
        if message:
            if status == ScannerStatus.FAILED:
                self.errors.append(message)
                main_logger.error(f"{self.name}: {message}")
            else:
                main_logger.debug(f"{self.name}: {message}")
    
    def validate_targets(self, targets: List[str]) -> List[str]:
        """Validate and filter targets"""
        valid_targets = []
        
        for target in targets:
            if self.is_valid_target(target):
                valid_targets.append(target)
            else:
                main_logger.debug(f"Invalid target filtered: {target}")
        
        return valid_targets
    
    def is_valid_target(self, target: str) -> bool:
        """Check if target is valid for scanning"""
        return bool(target and isinstance(target, str))
    
    async def run_scan(self, targets: List[str], **kwargs) -> List[VulnerabilityResult]:
        """Run scan with error handling and status management"""
        if not self.enabled:
            self.set_status(ScannerStatus.DISABLED)
            return []
        
        valid_targets = self.validate_targets(targets)
        if not valid_targets:
            self.set_status(ScannerStatus.FAILED, "No valid targets provided")
            return []
        
        try:
            self.start_time = datetime.now()
            self.set_status(ScannerStatus.RUNNING, f"Starting scan of {len(valid_targets)} targets")
            
            results = await self.scan(valid_targets, **kwargs)
            
            # Validate and filter results
            valid_results = []
            for result in results:
                if isinstance(result, VulnerabilityResult):
                    valid_results.append(result)
                else:
                    main_logger.debug(f"Invalid result filtered: {result}")
            
            self.results.extend(valid_results)
            self.end_time = datetime.now()
            duration = (self.end_time - self.start_time).total_seconds()
            
            self.set_status(ScannerStatus.COMPLETED, 
                          f"Found {len(valid_results)} vulnerabilities in {duration:.1f}s")
            return valid_results
            
        except Exception as e:
            self.end_time = datetime.now()
            self.set_status(ScannerStatus.FAILED, f"Scan failed: {str(e)}")
            return []
    
    def get_stats(self) -> Dict[str, Any]:
        """Get scanner statistics"""
        duration = None
        if self.start_time and self.end_time:
            duration = (self.end_time - self.start_time).total_seconds()
        
        # Count results by severity
        severity_counts = {}
        for result in self.results:
            sev = result.severity.value
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
        return {
            'name': self.name,
            'status': self.status.value,
            'results_count': len(self.results),
            'errors_count': len(self.errors),
            'enabled': self.enabled,
            'description': self.description,
            'duration': duration,
            'severity_breakdown': severity_counts
        }


class PortScanner(BaseVulnerabilityScanner):
    """Base class for port scanning functionality"""
    
    def __init__(self, name: str, description: str = "", common_ports: List[int] = None):
        super().__init__(name, description)
        self.common_ports = common_ports or [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995,
            1723, 3306, 3389, 5432, 5900, 8080, 8443, 8888
        ]
    
    async def scan_ports(self, target: str, ports: List[int] = None, 
                        timeout: int = 3) -> List[ServiceInfo]:
        """Scan ports on target"""
        ports_to_scan = ports or self.common_ports
        results = []
        
        # Create semaphore to limit concurrent connections
        semaphore = asyncio.Semaphore(50)
        
        # Create tasks for all port checks
        tasks = [
            self._check_port(semaphore, target, port, timeout)
            for port in ports_to_scan
        ]
        
        # Execute all tasks
        port_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filter successful results
        for result in port_results:
            if isinstance(result, ServiceInfo):
                results.append(result)
        
        return results
    
    async def _check_port(self, semaphore: asyncio.Semaphore, 
                         target: str, port: int, timeout: int) -> Optional[ServiceInfo]:
        """Check if port is open"""
        async with semaphore:
            try:
                future = asyncio.open_connection(target, port)
                reader, writer = await asyncio.wait_for(future, timeout=timeout)
                
                # Try to get banner
                banner = ""
                try:
                    writer.write(b'\r\n')
                    await writer.drain()
                    data = await asyncio.wait_for(reader.read(1024), timeout=2)
                    banner = data.decode('utf-8', errors='ignore').strip()
                except:
                    pass
                
                writer.close()
                await writer.wait_closed()
                
                # Detect service
                service_name = self._detect_service(port, banner)
                ssl_enabled = port in [443, 993, 995, 636] or 'ssl' in banner.lower()
                
                return ServiceInfo(
                    host=target,
                    port=port,
                    service_name=service_name,
                    banner=banner[:200] if banner else None,  # Limit banner length
                    ssl_enabled=ssl_enabled
                )
                
            except Exception:
                return None
    
    def _detect_service(self, port: int, banner: str = "") -> Optional[str]:
        """Detect service based on port and banner"""
        # Common port to service mapping
        port_services = {
            21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
            80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc", 
            139: "netbios-ssn", 143: "imap", 443: "https", 993: "imaps",
            995: "pop3s", 1723: "pptp", 3306: "mysql", 3389: "rdp",
            5432: "postgresql", 5900: "vnc", 8080: "http-alt", 8443: "https-alt"
        }
        
        service = port_services.get(port, "unknown")
        
        # Banner-based detection
        if banner:
            banner_lower = banner.lower()
            if 'ssh' in banner_lower:
                service = "ssh"
            elif 'http' in banner_lower:
                service = "http"
            elif 'ftp' in banner_lower:
                service = "ftp"
            elif 'smtp' in banner_lower:
                service = "smtp"
            elif 'pop3' in banner_lower:
                service = "pop3"
            elif 'mysql' in banner_lower:
                service = "mysql"
        
        return service


class WebScanner(BaseVulnerabilityScanner):
    """Base class for web application vulnerability scanners"""
    
    def __init__(self, name: str, description: str = ""):
        super().__init__(name, description)
        self.user_agent = "ReconForge/1.0 (Security Scanner)"
        self.timeout = 10
        self.max_redirects = 5
    
    async def check_web_service(self, url: str) -> Dict[str, Any]:
        """Check if URL is a valid web service"""
        from ..utils.helpers import HTTPHelper
        
        try:
            response = await HTTPHelper.make_request(
                url, 
                timeout=self.timeout,
                headers={'User-Agent': self.user_agent}
            )
            
            if 'error' in response:
                return None
            
            return {
                'url': response['url'],
                'status': response['status'],
                'headers': response['headers'],
                'title': HTTPHelper.extract_title(response.get('content', '')),
                'server': response.get('server', ''),
                'technologies': HTTPHelper.detect_technologies(
                    response['headers'], 
                    response.get('content', '')
                ),
                'content_length': response['size']
            }
            
        except Exception as e:
            main_logger.debug(f"Web service check failed for {url}: {e}")
            return None
    
    def is_web_target(self, target: str) -> bool:
        """Check if target is a web service"""
        return target.startswith(('http://', 'https://'))
    
    def normalize_url(self, target: str) -> str:
        """Normalize target to proper URL format"""
        if not target.startswith(('http://', 'https://')):
            # Try HTTPS first, then HTTP
            return f"https://{target}"
        return target


class ScannerManager:
    """Manager for coordinating multiple vulnerability scanners"""
    
    def __init__(self):
        self.scanners = {}
        self.results = []
        self.all_vulnerabilities = []
    
    def register_scanner(self, scanner: BaseVulnerabilityScanner):
        """Register a vulnerability scanner"""
        self.scanners[scanner.name] = scanner
        main_logger.info(f"Registered scanner: {scanner.name}")
    
    def enable_scanner(self, name: str):
        """Enable a specific scanner"""
        if name in self.scanners:
            self.scanners[name].enabled = True
    
    def disable_scanner(self, name: str):
        """Disable a specific scanner"""
        if name in self.scanners:
            self.scanners[name].enabled = False
    
    def configure_scanner(self, name: str, config: Dict[str, Any]):
        """Configure a specific scanner"""
        if name in self.scanners:
            self.scanners[name].configure(config)
    
    async def scan_all(self, targets: List[str], scanners: List[str] = None,
                      parallel: bool = True, **kwargs) -> List[VulnerabilityResult]:
        """
        Run vulnerability scans using multiple scanners
        
        Args:
            targets: List of targets to scan
            scanners: List of scanner names to use (None for all enabled)
            parallel: Run scanners in parallel or sequentially
            **kwargs: Additional configuration for scanners
            
        Returns:
            Combined list of VulnerabilityResult objects
        """
        if scanners is None:
            active_scanners = [s for s in self.scanners.values() if s.enabled]
        else:
            active_scanners = [self.scanners[name] for name in scanners if name in self.scanners]
        
        if not active_scanners:
            main_logger.warning("No active scanners available")
            return []
        
        main_logger.info(f"Starting scans with {len(active_scanners)} scanners: {[s.name for s in active_scanners]}")
        
        all_results = []
        
        if parallel:
            # Run scanners in parallel
            tasks = [scanner.run_scan(targets, **kwargs) for scanner in active_scanners]
            results_list = await asyncio.gather(*tasks, return_exceptions=True)
            
            for i, results in enumerate(results_list):
                if isinstance(results, Exception):
                    main_logger.error(f"Scanner {active_scanners[i].name} failed: {results}")
                else:
                    all_results.extend(results)
        else:
            # Run scanners sequentially
            for scanner in active_scanners:
                results = await scanner.run_scan(targets, **kwargs)
                all_results.extend(results)
        
        # Deduplicate results
        unique_results = []
        seen = set()
        
        for result in all_results:
            # Create a unique key for deduplication
            key = (result.title, result.target, result.vulnerability_type, result.severity.value)
            if key not in seen:
                seen.add(key)
                unique_results.append(result)
        
        self.results = unique_results
        self.all_vulnerabilities = unique_results
        
        main_logger.success(f"Vulnerability scanning completed: {len(unique_results)} unique vulnerabilities found")
        return unique_results
    
    def get_scanner_stats(self) -> Dict[str, Dict[str, Any]]:
        """Get statistics for all scanners"""
        return {name: scanner.get_stats() for name, scanner in self.scanners.items()}
    
    def get_summary(self) -> Dict[str, Any]:
        """Get overall scanning summary"""
        # Count by severity
        severity_counts = {}
        for vuln in self.all_vulnerabilities:
            sev = vuln.severity.value
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
        return {
            'total_scanners': len(self.scanners),
            'enabled_scanners': sum(1 for s in self.scanners.values() if s.enabled),
            'total_vulnerabilities': len(self.all_vulnerabilities),
            'severity_breakdown': severity_counts,
            'scanner_stats': self.get_scanner_stats()
        }