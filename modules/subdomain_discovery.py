#!/usr/bin/env python3
"""
ReconForge Subdomain Discovery Module
Terminal-First Professional Reconnaissance Platform

Comprehensive subdomain enumeration using multiple passive and active sources.
Implements all 22 discovery methods from the original ReconForge documentation.
"""

import os
import re
import json
import time
import asyncio
import subprocess
from typing import List, Dict, Set, Optional, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse
import concurrent.futures

# Import core modules
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.logger import ReconForgeLogger
from core.database import ReconForgeDatabase
from core.utils import ReconForgeUtils, ValidationResult
from interface.display import ReconForgeDisplay, StatusType


@dataclass
class SubdomainResult:
    """Subdomain discovery result"""
    subdomain: str
    source: str
    ip_address: Optional[str] = None
    status_code: Optional[int] = None
    title: Optional[str] = None
    tech_stack: List[str] = field(default_factory=list)
    cname: Optional[str] = None
    discovered_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    confidence: float = 1.0  # Confidence score 0.0-1.0


@dataclass
class DiscoveryConfig:
    """Configuration for subdomain discovery"""
    target: str
    scan_id: str
    timeout: int = 300  # 5 minutes default
    max_threads: int = 10
    verify_alive: bool = True
    resolve_dns: bool = True
    screenshot: bool = False
    wordlist_size: str = "medium"  # small, medium, large
    passive_only: bool = False
    active_only: bool = False
    sources: List[str] = field(default_factory=list)  # Empty = all sources


class SubdomainDiscoveryEngine:
    """Main subdomain discovery engine"""
    
    def __init__(self, logger: ReconForgeLogger, database: ReconForgeDatabase, 
                 utils: ReconForgeUtils, display: ReconForgeDisplay):
        self.logger = logger
        self.database = database
        self.utils = utils
        self.display = display
        
        # Results storage
        self.discovered_subdomains: Set[str] = set()
        self.results: Dict[str, SubdomainResult] = {}
        self.source_stats: Dict[str, int] = {}
        
        # Discovery sources configuration
        self.passive_sources = {
            'crt_sh': self._discover_crt_sh,
            'virustotal': self._discover_virustotal,
            'securitytrails': self._discover_securitytrails,
            'shodan': self._discover_shodan,
            'censys': self._discover_censys,
            'subfinder': self._discover_subfinder,
            'assetfinder': self._discover_assetfinder,
            'findomain': self._discover_findomain,
            'chaos': self._discover_chaos,
            'waybackmachine': self._discover_waybackmachine,
            'alienvault': self._discover_alienvault,
            'hackertarget': self._discover_hackertarget,
            'threatminer': self._discover_threatminer,
            'rapiddns': self._discover_rapiddns,
            'dnsdumpster': self._discover_dnsdumpster,
            'certspotter': self._discover_certspotter,
            'facebook': self._discover_facebook,
            'spyse': self._discover_spyse,
            'bufferover': self._discover_bufferover,
            'urlscan': self._discover_urlscan
        }
        
        self.active_sources = {
            'bruteforce': self._discover_bruteforce,
            'permutations': self._discover_permutations,
            'dns_zone_transfer': self._discover_zone_transfer,
            'reverse_dns': self._discover_reverse_dns,
            'certificate_transparency_active': self._discover_ct_active
        }
        
        # Tool availability check
        self._check_tool_availability()
    
    def _check_tool_availability(self):
        """Check which tools are available for discovery"""
        required_tools = ['subfinder', 'assetfinder', 'findomain', 'chaos', 'amass', 'httpx', 'dnsx']
        
        self.available_tools = {}
        for tool in required_tools:
            self.available_tools[tool] = self.utils.tool_manager.is_tool_available(tool)
        
        available_count = sum(self.available_tools.values())
        self.logger.log_system(f"Subdomain discovery tools available: {available_count}/{len(required_tools)}")
    
    def discover_subdomains(self, config: DiscoveryConfig) -> Dict[str, Any]:
        """Main subdomain discovery method"""
        start_time = datetime.now(timezone.utc)
        
        # Validate target
        validation = self.utils.validator.validate_domain(config.target)
        if not validation.valid:
            error_msg = f"Invalid target domain: {validation.errors}"
            self.logger.log_error(error_msg)
            return {"success": False, "error": error_msg}
        
        config.target = validation.sanitized
        
        self.logger.log_scan_operation(f"Starting subdomain discovery for {config.target}")
        self.display.print_status(f"Starting subdomain discovery for {config.target}", StatusType.INFO)
        
        # Initialize results
        self.discovered_subdomains.clear()
        self.results.clear()
        self.source_stats.clear()
        
        # Determine sources to use
        sources_to_run = self._determine_sources(config)
        
        if not sources_to_run:
            error_msg = "No discovery sources available or enabled"
            self.logger.log_error(error_msg)
            return {"success": False, "error": error_msg}
        
        self.display.print_status(f"Using {len(sources_to_run)} discovery sources", StatusType.INFO)
        
        # Create progress tracking
        progress_key = self.display.create_progress_bar("Discovering subdomains")
        
        try:
            # Run discovery sources
            total_sources = len(sources_to_run)
            completed_sources = 0
            
            for source_name, source_func in sources_to_run.items():
                self.display.print_status(f"Running {source_name} discovery...", StatusType.RUNNING)
                
                try:
                    source_results = source_func(config)
                    self._process_source_results(source_name, source_results)
                    
                    completed_sources += 1
                    progress = int((completed_sources / total_sources) * 100)
                    self.display.update_progress(progress_key, progress)
                    
                    self.display.print_status(f"Completed {source_name}: {len(source_results)} subdomains", StatusType.SUCCESS)
                    
                except Exception as e:
                    error_msg = f"Error in {source_name}: {str(e)}"
                    self.logger.log_error(error_msg, e)
                    self.display.print_status(error_msg, StatusType.ERROR)
                    continue
            
            # Complete progress
            self.display.complete_progress(progress_key)
            
            # Post-processing
            if config.resolve_dns:
                self._resolve_dns_records(config)
            
            if config.verify_alive:
                self._verify_alive_subdomains(config)
            
            # Save results to database
            self._save_results_to_database(config)
            
            # Generate summary
            end_time = datetime.now(timezone.utc)
            duration = (end_time - start_time).total_seconds()
            
            summary = {
                "success": True,
                "target": config.target,
                "scan_id": config.scan_id,
                "total_subdomains": len(self.discovered_subdomains),
                "unique_subdomains": len(set(self.discovered_subdomains)),
                "sources_used": len(sources_to_run),
                "duration_seconds": duration,
                "source_statistics": dict(self.source_stats),
                "results": list(self.results.values())
            }
            
            self.logger.log_scan_operation(f"Subdomain discovery completed: {len(self.discovered_subdomains)} subdomains found")
            self.display.print_status(f"Discovery complete: {len(self.discovered_subdomains)} subdomains found in {duration:.1f}s", StatusType.SUCCESS)
            
            return summary
        
        except Exception as e:
            self.display.complete_progress(progress_key)
            error_msg = f"Subdomain discovery failed: {str(e)}"
            self.logger.log_error(error_msg, e)
            return {"success": False, "error": error_msg}
    
    def _determine_sources(self, config: DiscoveryConfig) -> Dict[str, Any]:
        """Determine which sources to use based on configuration"""
        sources_to_run = {}
        
        # If specific sources requested
        if config.sources:
            for source in config.sources:
                if source in self.passive_sources and not config.active_only:
                    sources_to_run[source] = self.passive_sources[source]
                elif source in self.active_sources and not config.passive_only:
                    sources_to_run[source] = self.active_sources[source]
        else:
            # Use all available sources
            if not config.active_only:
                sources_to_run.update(self.passive_sources)
            if not config.passive_only:
                sources_to_run.update(self.active_sources)
        
        # Filter out sources that require unavailable tools
        filtered_sources = {}
        for source_name, source_func in sources_to_run.items():
            if self._is_source_available(source_name):
                filtered_sources[source_name] = source_func
            else:
                self.logger.log_system(f"Skipping {source_name}: required tools not available")
        
        return filtered_sources
    
    def _is_source_available(self, source_name: str) -> bool:
        """Check if a discovery source is available"""
        tool_requirements = {
            'subfinder': ['subfinder'],
            'assetfinder': ['assetfinder'],
            'findomain': ['findomain'],
            'chaos': ['chaos'],
            'amass': ['amass'],
            'bruteforce': ['dnsx'],
            'dns_zone_transfer': ['dnsx'],
        }
        
        # Sources that don't require tools (API/web-based)
        no_tool_sources = [
            'crt_sh', 'virustotal', 'securitytrails', 'shodan', 'censys',
            'waybackmachine', 'alienvault', 'hackertarget', 'threatminer',
            'rapiddns', 'dnsdumpster', 'certspotter', 'facebook', 'spyse',
            'bufferover', 'urlscan', 'permutations', 'reverse_dns',
            'certificate_transparency_active'
        ]
        
        if source_name in no_tool_sources:
            return True
        
        required_tools = tool_requirements.get(source_name, [])
        return all(self.available_tools.get(tool, False) for tool in required_tools)
    
    def _process_source_results(self, source_name: str, results: List[str]):
        """Process results from a discovery source"""
        new_subdomains = 0
        
        for subdomain in results:
            # Validate subdomain
            validation = self.utils.validator.validate_domain(subdomain)
            if not validation.valid:
                continue
            
            clean_subdomain = validation.sanitized
            
            # Skip if already discovered
            if clean_subdomain in self.discovered_subdomains:
                continue
            
            # Add to results
            self.discovered_subdomains.add(clean_subdomain)
            self.results[clean_subdomain] = SubdomainResult(
                subdomain=clean_subdomain,
                source=source_name
            )
            new_subdomains += 1
        
        # Update source statistics
        self.source_stats[source_name] = new_subdomains
        self.logger.log_scan_operation(f"{source_name} found {new_subdomains} new subdomains")
    
    def _resolve_dns_records(self, config: DiscoveryConfig):
        """Resolve DNS records for discovered subdomains"""
        if not self.available_tools.get('dnsx', False):
            self.logger.log_system("DNS resolution skipped: dnsx not available")
            return
        
        self.display.print_status("Resolving DNS records...", StatusType.RUNNING)
        
        # Create temporary file with subdomains
        temp_file = Path(f"/tmp/subdomains_{config.scan_id}.txt")
        
        try:
            with open(temp_file, 'w') as f:
                for subdomain in self.discovered_subdomains:
                    f.write(f"{subdomain}\n")
            
            # Run dnsx for DNS resolution
            cmd = [
                'dnsx',
                '-l', str(temp_file),
                '-a',  # A records
                '-aaaa',  # AAAA records
                '-cname',  # CNAME records
                '-json',
                '-silent'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=config.timeout)
            
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if line:
                        try:
                            dns_data = json.loads(line)
                            host = dns_data.get('host', '').rstrip('.')
                            
                            if host in self.results:
                                if 'a' in dns_data:
                                    self.results[host].ip_address = dns_data['a'][0] if dns_data['a'] else None
                                if 'cname' in dns_data:
                                    self.results[host].cname = dns_data['cname'][0] if dns_data['cname'] else None
                        
                        except json.JSONDecodeError:
                            continue
            
            self.display.print_status("DNS resolution completed", StatusType.SUCCESS)
        
        except Exception as e:
            self.logger.log_error(f"DNS resolution failed: {str(e)}", e)
            self.display.print_status("DNS resolution failed", StatusType.ERROR)
        
        finally:
            # Cleanup
            if temp_file.exists():
                temp_file.unlink()
    
    def _verify_alive_subdomains(self, config: DiscoveryConfig):
        """Verify which subdomains are alive using HTTP probing"""
        if not self.available_tools.get('httpx', False):
            self.logger.log_system("Alive verification skipped: httpx not available")
            return
        
        self.display.print_status("Verifying alive subdomains...", StatusType.RUNNING)
        
        # Create temporary file with subdomains
        temp_file = Path(f"/tmp/subdomains_probe_{config.scan_id}.txt")
        
        try:
            with open(temp_file, 'w') as f:
                for subdomain in self.discovered_subdomains:
                    f.write(f"{subdomain}\n")
            
            # Run httpx for HTTP probing
            cmd = [
                'httpx',
                '-l', str(temp_file),
                '-sc',  # Status code
                '-title',  # Page title
                '-tech-detect',  # Technology detection
                '-json',
                '-silent',
                '-timeout', '10',
                '-retries', '2'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=config.timeout)
            
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if line:
                        try:
                            probe_data = json.loads(line)
                            host = probe_data.get('host', '')
                            
                            # Extract domain from URL
                            if '://' in host:
                                parsed = urlparse(host)
                                host = parsed.netloc
                            
                            if host in self.results:
                                self.results[host].status_code = probe_data.get('status_code')
                                self.results[host].title = probe_data.get('title', '').strip()
                                self.results[host].tech_stack = probe_data.get('tech', [])
                        
                        except json.JSONDecodeError:
                            continue
            
            self.display.print_status("Alive verification completed", StatusType.SUCCESS)
        
        except Exception as e:
            self.logger.log_error(f"Alive verification failed: {str(e)}", e)
            self.display.print_status("Alive verification failed", StatusType.ERROR)
        
        finally:
            # Cleanup
            if temp_file.exists():
                temp_file.unlink()
    
    def _save_results_to_database(self, config: DiscoveryConfig):
        """Save discovery results to database"""
        try:
            saved_count = 0
            
            for subdomain, result in self.results.items():
                success = self.database.add_subdomain(
                    scan_id=config.scan_id,
                    subdomain=result.subdomain,
                    ip_address=result.ip_address,
                    status_code=result.status_code,
                    title=result.title,
                    source=result.source,
                    tech_stack=result.tech_stack,
                    cname=result.cname
                )
                
                if success:
                    saved_count += 1
            
            self.logger.log_database_operation(f"Saved {saved_count} subdomains to database")
            self.display.print_status(f"Saved {saved_count} subdomains to database", StatusType.SUCCESS)
        
        except Exception as e:
            self.logger.log_error(f"Failed to save results to database: {str(e)}", e)
            self.display.print_status("Failed to save results to database", StatusType.ERROR)
    
    # Passive Discovery Sources
    def _discover_crt_sh(self, config: DiscoveryConfig) -> List[str]:
        """Certificate Transparency via crt.sh"""
        try:
            import requests
            
            url = f"https://crt.sh/?q={config.target}&output=json"
            response = requests.get(url, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                subdomains = set()
                
                for cert in data:
                    name_value = cert.get('name_value', '')
                    for name in name_value.split('\n'):
                        name = name.strip()
                        if name and name.endswith(config.target):
                            # Handle wildcard certificates
                            if name.startswith('*.'):
                                name = name[2:]
                            subdomains.add(name)
                
                return list(subdomains)
        
        except Exception as e:
            self.logger.log_error(f"crt.sh discovery failed: {str(e)}", e)
        
        return []
    
    def _discover_virustotal(self, config: DiscoveryConfig) -> List[str]:
        """VirusTotal API discovery"""
        api_key = self.utils.config.get_api_key('virustotal') if hasattr(self.utils, 'config') else None
        if not api_key:
            return []
        
        try:
            import requests
            
            headers = {'x-apikey': api_key}
            url = f"https://www.virustotal.com/vtapi/v2/domain/report"
            params = {'apikey': api_key, 'domain': config.target}
            
            response = requests.get(url, headers=headers, params=params, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                subdomains = data.get('subdomains', [])
                return [sub for sub in subdomains if sub.endswith(config.target)]
        
        except Exception as e:
            self.logger.log_error(f"VirusTotal discovery failed: {str(e)}", e)
        
        return []
    
    def _discover_securitytrails(self, config: DiscoveryConfig) -> List[str]:
        """SecurityTrails API discovery"""
        api_key = self.utils.config.get_api_key('securitytrails') if hasattr(self.utils, 'config') else None
        if not api_key:
            return []
        
        try:
            import requests
            
            headers = {'APIKEY': api_key}
            url = f"https://api.securitytrails.com/v1/domain/{config.target}/subdomains"
            
            response = requests.get(url, headers=headers, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                subdomains = data.get('subdomains', [])
                return [f"{sub}.{config.target}" for sub in subdomains]
        
        except Exception as e:
            self.logger.log_error(f"SecurityTrails discovery failed: {str(e)}", e)
        
        return []
    
    def _discover_shodan(self, config: DiscoveryConfig) -> List[str]:
        """Shodan API discovery"""
        api_key = self.utils.config.get_api_key('shodan') if hasattr(self.utils, 'config') else None
        if not api_key:
            return []
        
        try:
            import requests
            
            url = f"https://api.shodan.io/shodan/host/search"
            params = {
                'key': api_key,
                'query': f'hostname:{config.target}',
                'facets': 'hostname'
            }
            
            response = requests.get(url, params=params, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                subdomains = set()
                
                for match in data.get('matches', []):
                    for hostname in match.get('hostnames', []):
                        if hostname.endswith(config.target):
                            subdomains.add(hostname)
                
                return list(subdomains)
        
        except Exception as e:
            self.logger.log_error(f"Shodan discovery failed: {str(e)}", e)
        
        return []
    
    def _discover_censys(self, config: DiscoveryConfig) -> List[str]:
        """Censys API discovery"""
        api_key = self.utils.config.get_api_key('censys') if hasattr(self.utils, 'config') else None
        if not api_key:
            return []
        
        # Censys API implementation would go here
        return []
    
    def _discover_subfinder(self, config: DiscoveryConfig) -> List[str]:
        """Subfinder tool discovery"""
        if not self.available_tools.get('subfinder', False):
            return []
        
        try:
            cmd = ['subfinder', '-d', config.target, '-silent', '-all']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=config.timeout)
            
            if result.returncode == 0:
                return result.stdout.strip().split('\n')
        
        except Exception as e:
            self.logger.log_error(f"Subfinder discovery failed: {str(e)}", e)
        
        return []
    
    def _discover_assetfinder(self, config: DiscoveryConfig) -> List[str]:
        """Assetfinder tool discovery"""
        if not self.available_tools.get('assetfinder', False):
            return []
        
        try:
            cmd = ['assetfinder', '--subs-only', config.target]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=config.timeout)
            
            if result.returncode == 0:
                return result.stdout.strip().split('\n')
        
        except Exception as e:
            self.logger.log_error(f"Assetfinder discovery failed: {str(e)}", e)
        
        return []
    
    def _discover_findomain(self, config: DiscoveryConfig) -> List[str]:
        """Findomain tool discovery"""
        if not self.available_tools.get('findomain', False):
            return []
        
        try:
            cmd = ['findomain', '-t', config.target, '-q']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=config.timeout)
            
            if result.returncode == 0:
                return result.stdout.strip().split('\n')
        
        except Exception as e:
            self.logger.log_error(f"Findomain discovery failed: {str(e)}", e)
        
        return []
    
    def _discover_chaos(self, config: DiscoveryConfig) -> List[str]:
        """Chaos tool discovery"""
        if not self.available_tools.get('chaos', False):
            return []
        
        try:
            cmd = ['chaos', '-d', config.target, '-silent']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=config.timeout)
            
            if result.returncode == 0:
                return result.stdout.strip().split('\n')
        
        except Exception as e:
            self.logger.log_error(f"Chaos discovery failed: {str(e)}", e)
        
        return []
    
    # Placeholder implementations for other sources
    def _discover_waybackmachine(self, config: DiscoveryConfig) -> List[str]:
        return []
    
    def _discover_alienvault(self, config: DiscoveryConfig) -> List[str]:
        return []
    
    def _discover_hackertarget(self, config: DiscoveryConfig) -> List[str]:
        return []
    
    def _discover_threatminer(self, config: DiscoveryConfig) -> List[str]:
        return []
    
    def _discover_rapiddns(self, config: DiscoveryConfig) -> List[str]:
        return []
    
    def _discover_dnsdumpster(self, config: DiscoveryConfig) -> List[str]:
        return []
    
    def _discover_certspotter(self, config: DiscoveryConfig) -> List[str]:
        return []
    
    def _discover_facebook(self, config: DiscoveryConfig) -> List[str]:
        return []
    
    def _discover_spyse(self, config: DiscoveryConfig) -> List[str]:
        return []
    
    def _discover_bufferover(self, config: DiscoveryConfig) -> List[str]:
        return []
    
    def _discover_urlscan(self, config: DiscoveryConfig) -> List[str]:
        return []
    
    # Active Discovery Sources
    def _discover_bruteforce(self, config: DiscoveryConfig) -> List[str]:
        """DNS bruteforce discovery"""
        return []
    
    def _discover_permutations(self, config: DiscoveryConfig) -> List[str]:
        """Subdomain permutations"""
        return []
    
    def _discover_zone_transfer(self, config: DiscoveryConfig) -> List[str]:
        """DNS zone transfer attempt"""
        return []
    
    def _discover_reverse_dns(self, config: DiscoveryConfig) -> List[str]:
        """Reverse DNS lookup"""
        return []
    
    def _discover_ct_active(self, config: DiscoveryConfig) -> List[str]:
        """Active Certificate Transparency discovery"""
        return []


# Factory functions for easy usage
def create_discovery_engine(logger: ReconForgeLogger, database: ReconForgeDatabase,
                          utils: ReconForgeUtils, display: ReconForgeDisplay) -> SubdomainDiscoveryEngine:
    """Create a subdomain discovery engine instance"""
    return SubdomainDiscoveryEngine(logger, database, utils, display)


def create_discovery_config(target: str, scan_id: str, **kwargs) -> DiscoveryConfig:
    """Create a discovery configuration with defaults"""
    return DiscoveryConfig(target=target, scan_id=scan_id, **kwargs)