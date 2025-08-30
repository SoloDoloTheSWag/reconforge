#!/usr/bin/env python3
"""
ReconForge Web Enumeration Module
Terminal-First Professional Reconnaissance Platform

Comprehensive web application enumeration including directory discovery,
file discovery, technology detection, and content analysis.
"""

import os
import re
import json
import subprocess
import requests
from typing import List, Dict, Set, Optional, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urljoin, urlparse
import concurrent.futures
from enum import Enum
import threading

# Import core modules
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.logger import ReconForgeLogger
from core.database import ReconForgeDatabase
from core.utils import ReconForgeUtils, ValidationResult
from interface.display import ReconForgeDisplay, StatusType


class DiscoveryType(Enum):
    """Web discovery types"""
    DIRECTORY = "directory"
    FILE = "file"
    ENDPOINT = "endpoint"
    PARAMETER = "parameter"
    SUBDOMAIN = "subdomain"
    VHOST = "virtual_host"


class ResponseType(Enum):
    """HTTP response types"""
    SUCCESS = "success"  # 2xx
    REDIRECT = "redirect"  # 3xx
    CLIENT_ERROR = "client_error"  # 4xx
    SERVER_ERROR = "server_error"  # 5xx
    TIMEOUT = "timeout"
    ERROR = "error"


@dataclass
class TechnologyInfo:
    """Detected technology information"""
    name: str
    version: Optional[str] = None
    confidence: float = 1.0
    categories: List[str] = field(default_factory=list)
    cpe: Optional[str] = None
    website: Optional[str] = None


@dataclass
class WebResource:
    """Web resource discovery result"""
    url: str
    discovery_type: DiscoveryType
    status_code: int
    response_type: ResponseType
    content_length: int
    content_type: Optional[str] = None
    title: Optional[str] = None
    server: Optional[str] = None
    technologies: List[TechnologyInfo] = field(default_factory=list)
    response_time: float = 0.0
    redirect_location: Optional[str] = None
    discovered_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    source: str = "unknown"
    interesting: bool = False
    security_headers: Dict[str, str] = field(default_factory=dict)


@dataclass
class EnumerationConfig:
    """Web enumeration configuration"""
    targets: List[str]
    scan_id: str
    discovery_types: List[DiscoveryType] = field(default_factory=lambda: [DiscoveryType.DIRECTORY, DiscoveryType.FILE])
    wordlists: Dict[str, str] = field(default_factory=dict)
    extensions: List[str] = field(default_factory=lambda: ['php', 'html', 'js', 'txt', 'xml', 'json'])
    max_threads: int = 20
    timeout: int = 10
    max_redirects: int = 3
    user_agent: str = "ReconForge/2.0"
    custom_headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)
    status_codes_include: List[int] = field(default_factory=lambda: [200, 204, 301, 302, 307, 308, 401, 403, 405])
    status_codes_exclude: List[int] = field(default_factory=list)
    content_length_filter: Optional[Tuple[int, int]] = None  # (min, max)
    follow_redirects: bool = False
    recursive_depth: int = 2
    rate_limit: int = 100  # requests per second
    verify_ssl: bool = False
    proxy: Optional[str] = None
    scan_timeout: int = 1800  # 30 minutes


class WebEnumerator:
    """Main web enumeration engine"""
    
    def __init__(self, logger: ReconForgeLogger, database: ReconForgeDatabase, 
                 utils: ReconForgeUtils, display: ReconForgeDisplay):
        self.logger = logger
        self.database = database
        self.utils = utils
        self.display = display
        
        # Results storage
        self.discovered_resources: List[WebResource] = []
        self.scan_stats: Dict[str, Any] = {}
        
        # Threading controls
        self.thread_lock = threading.RLock()
        
        # Enumeration methods
        self.enumerators = {
            'gobuster': self._enumerate_gobuster,
            'ffuf': self._enumerate_ffuf,
            'dirb': self._enumerate_dirb,
            'httpx': self._enumerate_httpx,
            'custom_crawler': self._enumerate_custom_crawler,
            'wayback_urls': self._enumerate_wayback_urls,
            'gau_urls': self._enumerate_gau_urls
        }
        
        # Built-in wordlists
        self._setup_wordlists()
        
        # Technology detection patterns
        self._setup_technology_detection()
        
        # Tool availability check
        self._check_tool_availability()
    
    def _check_tool_availability(self):
        """Check which web enumeration tools are available"""
        required_tools = ['gobuster', 'ffuf', 'dirb', 'httpx', 'waybackurls', 'gau']
        
        self.available_tools = {}
        for tool in required_tools:
            self.available_tools[tool] = self.utils.tool_manager.is_tool_available(tool)
        
        available_count = sum(self.available_tools.values())
        self.logger.log_system(f"Web enumeration tools available: {available_count}/{len(required_tools)}")
    
    def _setup_wordlists(self):
        """Setup built-in wordlists"""
        self.wordlists = {
            'common_directories': [
                'admin', 'administrator', 'login', 'wp-admin', 'cpanel', 'phpmyadmin',
                'api', 'v1', 'v2', 'dev', 'test', 'staging', 'backup', 'old',
                'files', 'uploads', 'images', 'css', 'js', 'assets', 'static',
                'includes', 'config', 'conf', 'settings', 'database', 'db',
                'logs', 'log', 'tmp', 'temp', 'cache', 'private', 'public'
            ],
            'common_files': [
                'robots.txt', 'sitemap.xml', '.htaccess', 'web.config', 'crossdomain.xml',
                'config.php', 'wp-config.php', 'configuration.php', 'settings.php',
                'database.php', 'connect.php', 'connection.php', 'db.php',
                'index.php', 'index.html', 'default.html', 'home.html',
                'readme.txt', 'README.md', 'changelog.txt', 'version.txt',
                'info.php', 'phpinfo.php', 'test.php', 'debug.php'
            ],
            'backup_files': [
                'backup.sql', 'database.sql', 'db.sql', 'dump.sql',
                'backup.zip', 'backup.tar.gz', 'backup.rar',
                'site.zip', 'www.zip', 'web.zip', 'source.zip',
                'config.bak', 'config.old', 'config.backup'
            ],
            'sensitive_files': [
                '.git/HEAD', '.svn/entries', '.env', '.env.local', '.env.production',
                'composer.json', 'package.json', 'yarn.lock', 'Gemfile',
                'requirements.txt', 'pom.xml', 'build.gradle',
                'server-status', 'server-info', 'status'
            ]
        }
    
    def _setup_technology_detection(self):
        """Setup technology detection patterns"""
        self.tech_patterns = {
            'headers': {
                'X-Powered-By': {
                    'PHP': r'PHP/([\d.]+)',
                    'ASP.NET': r'ASP\.NET',
                    'Express': r'Express'
                },
                'Server': {
                    'Apache': r'Apache/([\d.]+)',
                    'Nginx': r'nginx/([\d.]+)',
                    'IIS': r'Microsoft-IIS/([\d.]+)',
                    'Cloudflare': r'cloudflare'
                },
                'Set-Cookie': {
                    'PHPSESSID': r'PHPSESSID',
                    'JSESSIONID': r'JSESSIONID',
                    'ASP.NET_SessionId': r'ASP\.NET_SessionId'
                }
            },
            'content': {
                'WordPress': [
                    r'/wp-content/',
                    r'/wp-includes/',
                    r'wp-json/wp/v2'
                ],
                'Drupal': [
                    r'/sites/default/',
                    r'/modules/',
                    r'Drupal\.settings'
                ],
                'Joomla': [
                    r'/components/',
                    r'/modules/',
                    r'joomla'
                ],
                'Laravel': [
                    r'laravel_session',
                    r'/vendor/laravel/'
                ],
                'Django': [
                    r'csrfmiddlewaretoken',
                    r'__admin_media_prefix__'
                ]
            }
        }
    
    def enumerate_web_content(self, config: EnumerationConfig) -> Dict[str, Any]:
        """Main web enumeration method"""
        start_time = datetime.now(timezone.utc)
        
        # Validate targets
        validated_targets = self._validate_web_targets(config.targets)
        if not validated_targets:
            error_msg = "No valid web targets provided"
            self.logger.log_error(error_msg)
            return {"success": False, "error": error_msg}
        
        config.targets = validated_targets
        
        self.logger.log_scan_operation(f"Starting web enumeration for {len(config.targets)} targets")
        self.display.print_status(f"Starting web enumeration for {len(config.targets)} targets", StatusType.INFO)
        
        # Initialize results
        self.discovered_resources.clear()
        self.scan_stats = {
            "total_targets": len(config.targets),
            "total_requests": 0,
            "resources_found": 0,
            "interesting_resources": 0,
            "technologies_detected": 0,
            "enumerators_used": []
        }
        
        # Determine enumerators to use
        enumerators_to_run = self._determine_enumerators(config)
        
        if not enumerators_to_run:
            error_msg = "No web enumerators available or enabled"
            self.logger.log_error(error_msg)
            return {"success": False, "error": error_msg}
        
        self.display.print_status(f"Using {len(enumerators_to_run)} web enumerators", StatusType.INFO)
        
        # Create progress tracking
        progress_key = self.display.create_progress_bar("Enumerating web content")
        
        try:
            # Run web enumerators
            total_enumerators = len(enumerators_to_run)
            completed_enumerators = 0
            
            for enum_name, enum_func in enumerators_to_run.items():
                self.display.print_status(f"Running {enum_name} enumeration...", StatusType.RUNNING)
                
                try:
                    enum_results = enum_func(config)
                    self._process_enumeration_results(enum_name, enum_results)
                    
                    completed_enumerators += 1
                    progress = int((completed_enumerators / total_enumerators) * 100)
                    self.display.update_progress(progress_key, progress)
                    
                    resource_count = len(enum_results)
                    self.display.print_status(f"Completed {enum_name}: {resource_count} resources", StatusType.SUCCESS)
                    
                except Exception as e:
                    error_msg = f"Error in {enum_name}: {str(e)}"
                    self.logger.log_error(error_msg, e)
                    self.display.print_status(error_msg, StatusType.ERROR)
                    continue
            
            # Complete progress
            self.display.complete_progress(progress_key)
            
            # Post-processing
            self._deduplicate_resources()
            self._analyze_technologies()
            self._mark_interesting_resources()
            self._save_results_to_database(config)
            
            # Generate summary
            end_time = datetime.now(timezone.utc)
            duration = (end_time - start_time).total_seconds()
            
            self._calculate_statistics()
            
            summary = {
                "success": True,
                "scan_id": config.scan_id,
                "targets": config.targets,
                "statistics": self.scan_stats,
                "duration_seconds": duration,
                "resources": [self._resource_to_dict(r) for r in self.discovered_resources]
            }
            
            resource_count = len(self.discovered_resources)
            interesting_count = len([r for r in self.discovered_resources if r.interesting])
            
            self.logger.log_scan_operation(f"Web enumeration completed: {resource_count} resources, {interesting_count} interesting")
            self.display.print_status(f"Enumeration complete: {resource_count} resources ({interesting_count} interesting) in {duration:.1f}s", StatusType.SUCCESS)
            
            return summary
        
        except Exception as e:
            self.display.complete_progress(progress_key)
            error_msg = f"Web enumeration failed: {str(e)}"
            self.logger.log_error(error_msg, e)
            return {"success": False, "error": error_msg}
    
    def _validate_web_targets(self, targets: List[str]) -> List[str]:
        """Validate web targets"""
        validated_targets = []
        
        for target in targets:
            # Ensure target has protocol
            if not target.startswith(('http://', 'https://')):
                target = f"https://{target}"
            
            validation = self.utils.validator.validate_url(target)
            if validation.valid:
                validated_targets.append(validation.sanitized)
            else:
                self.logger.log_error(f"Invalid web target: {target} - {validation.errors}")
        
        return validated_targets
    
    def _determine_enumerators(self, config: EnumerationConfig) -> Dict[str, Any]:
        """Determine which enumerators to use"""
        enumerators_to_run = {}
        
        # Priority order based on tool availability and effectiveness
        priority_order = ['gobuster', 'ffuf', 'httpx', 'wayback_urls', 'gau_urls', 'custom_crawler', 'dirb']
        
        for enum_name in priority_order:
            if self._is_enumerator_available(enum_name):
                enumerators_to_run[enum_name] = self.enumerators[enum_name]
                self.scan_stats["enumerators_used"].append(enum_name)
            else:
                self.logger.log_system(f"Skipping {enum_name}: dependencies not available")
        
        return enumerators_to_run
    
    def _is_enumerator_available(self, enum_name: str) -> bool:
        """Check if an enumerator is available"""
        tool_requirements = {
            'gobuster': ['gobuster'],
            'ffuf': ['ffuf'],
            'dirb': ['dirb'],
            'httpx': ['httpx'],
            'wayback_urls': ['waybackurls'],
            'gau_urls': ['gau'],
            'custom_crawler': []  # Built-in
        }
        
        required_tools = tool_requirements.get(enum_name, [])
        if not required_tools:
            return True  # Built-in enumerators
        
        return all(self.available_tools.get(tool, False) for tool in required_tools)
    
    def _process_enumeration_results(self, enum_name: str, results: List[WebResource]):
        """Process results from an enumerator"""
        with self.thread_lock:
            for resource in results:
                resource.source = enum_name
                self.discovered_resources.append(resource)
        
        self.logger.log_scan_operation(f"{enum_name} found {len(results)} web resources")
    
    def _deduplicate_resources(self):
        """Remove duplicate resources"""
        seen = set()
        unique_resources = []
        
        for resource in self.discovered_resources:
            # Create signature for deduplication
            signature = f"{resource.url}:{resource.status_code}"
            
            if signature not in seen:
                seen.add(signature)
                unique_resources.append(resource)
        
        removed_count = len(self.discovered_resources) - len(unique_resources)
        if removed_count > 0:
            self.logger.log_system(f"Removed {removed_count} duplicate resources")
        
        self.discovered_resources = unique_resources
    
    def _analyze_technologies(self):
        """Analyze discovered technologies across all resources"""
        tech_counter = {}
        
        for resource in self.discovered_resources:
            for tech in resource.technologies:
                tech_key = f"{tech.name}:{tech.version or 'unknown'}"
                if tech_key not in tech_counter:
                    tech_counter[tech_key] = 0
                tech_counter[tech_key] += 1
        
        self.scan_stats["technologies_detected"] = len(tech_counter)
        self.scan_stats["technology_summary"] = dict(sorted(tech_counter.items(), key=lambda x: x[1], reverse=True)[:10])
    
    def _mark_interesting_resources(self):
        """Mark resources as interesting based on various criteria"""
        interesting_patterns = [
            r'admin', r'login', r'config', r'backup', r'database',
            r'\.env', r'\.git', r'\.svn', r'phpinfo', r'server-status',
            r'wp-config', r'robots\.txt', r'sitemap\.xml'
        ]
        
        interesting_status_codes = [401, 403, 500, 502, 503]
        
        for resource in self.discovered_resources:
            # Check URL patterns
            url_lower = resource.url.lower()
            if any(re.search(pattern, url_lower) for pattern in interesting_patterns):
                resource.interesting = True
                continue
            
            # Check status codes
            if resource.status_code in interesting_status_codes:
                resource.interesting = True
                continue
            
            # Check for large content
            if resource.content_length > 100000:  # > 100KB
                resource.interesting = True
                continue
            
            # Check for interesting headers
            interesting_headers = ['x-powered-by', 'server', 'x-version']
            if any(header.lower() in resource.security_headers for header in interesting_headers):
                resource.interesting = True
                continue
    
    def _calculate_statistics(self):
        """Calculate enumeration statistics"""
        self.scan_stats["resources_found"] = len(self.discovered_resources)
        self.scan_stats["interesting_resources"] = len([r for r in self.discovered_resources if r.interesting])
        
        # Status code breakdown
        status_codes = {}
        for resource in self.discovered_resources:
            status = resource.status_code
            if status not in status_codes:
                status_codes[status] = 0
            status_codes[status] += 1
        
        self.scan_stats["status_code_breakdown"] = status_codes
        
        # Discovery type breakdown
        discovery_types = {}
        for resource in self.discovered_resources:
            dtype = resource.discovery_type.value
            if dtype not in discovery_types:
                discovery_types[dtype] = 0
            discovery_types[dtype] += 1
        
        self.scan_stats["discovery_type_breakdown"] = discovery_types
    
    def _save_results_to_database(self, config: EnumerationConfig):
        """Save enumeration results to database"""
        try:
            saved_count = 0
            
            for resource in self.discovered_resources:
                # Save as subdomain entry (adapting to existing schema)
                tech_list = [f"{tech.name}:{tech.version or 'unknown'}" for tech in resource.technologies]
                
                success = self.database.add_subdomain(
                    scan_id=config.scan_id,
                    subdomain=resource.url,
                    ip_address=urlparse(resource.url).netloc,
                    status_code=resource.status_code,
                    title=resource.title or f"{resource.discovery_type.value} resource",
                    source="web_enum",
                    tech_stack=tech_list,
                    cname=resource.server
                )
                
                if success:
                    saved_count += 1
            
            self.logger.log_database_operation(f"Saved {saved_count} web resources to database")
            self.display.print_status(f"Saved {saved_count} resources to database", StatusType.SUCCESS)
        
        except Exception as e:
            self.logger.log_error(f"Failed to save web enumeration results to database: {str(e)}", e)
            self.display.print_status("Failed to save results to database", StatusType.ERROR)
    
    def _resource_to_dict(self, resource: WebResource) -> Dict[str, Any]:
        """Convert web resource to dictionary"""
        return {
            "url": resource.url,
            "discovery_type": resource.discovery_type.value,
            "status_code": resource.status_code,
            "content_length": resource.content_length,
            "content_type": resource.content_type,
            "title": resource.title,
            "server": resource.server,
            "technologies": [{
                "name": tech.name,
                "version": tech.version,
                "confidence": tech.confidence
            } for tech in resource.technologies],
            "response_time": resource.response_time,
            "interesting": resource.interesting,
            "source": resource.source,
            "discovered_at": resource.discovered_at.isoformat()
        }
    
    # Enumerator Implementations
    def _enumerate_gobuster(self, config: EnumerationConfig) -> List[WebResource]:
        """Gobuster directory/file enumeration"""
        if not self.available_tools.get('gobuster', False):
            return []
        
        resources = []
        
        try:
            for target in config.targets:
                # Create wordlist file
                wordlist_file = Path(f"/tmp/gobuster_wordlist_{config.scan_id}.txt")
                
                # Combine wordlists based on discovery types
                combined_wordlist = []
                for dtype in config.discovery_types:
                    if dtype == DiscoveryType.DIRECTORY:
                        combined_wordlist.extend(self.wordlists['common_directories'])
                    elif dtype == DiscoveryType.FILE:
                        combined_wordlist.extend(self.wordlists['common_files'])
                        combined_wordlist.extend(self.wordlists['backup_files'])
                        combined_wordlist.extend(self.wordlists['sensitive_files'])
                
                # Remove duplicates and write to file
                unique_words = list(set(combined_wordlist))
                with open(wordlist_file, 'w') as f:
                    for word in unique_words:
                        f.write(f"{word}\n")
                
                # Build gobuster command
                cmd = [
                    'gobuster', 'dir',
                    '-u', target,
                    '-w', str(wordlist_file),
                    '-t', str(config.max_threads),
                    '--timeout', f"{config.timeout}s",
                    '-q',  # Quiet mode
                    '--no-error'
                ]
                
                # Add extensions
                if config.extensions:
                    cmd.extend(['-x', ','.join(config.extensions)])
                
                # Add status codes
                if config.status_codes_include:
                    status_codes = ','.join(map(str, config.status_codes_include))
                    cmd.extend(['-s', status_codes])
                
                # Add user agent
                cmd.extend(['-a', config.user_agent])
                
                # Add custom headers
                for header, value in config.custom_headers.items():
                    cmd.extend(['-H', f"{header}: {value}"])
                
                self.logger.log_tool_execution(f"Running gobuster: {' '.join(cmd)}")
                
                # Run gobuster
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=config.scan_timeout)
                
                if result.returncode == 0:
                    resources.extend(self._parse_gobuster_output(result.stdout, target))
                
                # Cleanup
                if wordlist_file.exists():
                    wordlist_file.unlink()
        
        except Exception as e:
            self.logger.log_error(f"Gobuster enumeration failed: {str(e)}", e)
        
        return resources
    
    def _parse_gobuster_output(self, output: str, base_url: str) -> List[WebResource]:
        """Parse gobuster output"""
        resources = []
        
        for line in output.strip().split('\n'):
            if line and not line.startswith('='):
                # Parse gobuster line format: /path (Status: 200) [Size: 1234]
                match = re.match(r'(/[^\s]*)\s+\(Status:\s+(\d+)\)\s+\[Size:\s+(\d+)\]', line)
                if match:
                    path, status_code, content_length = match.groups()
                    
                    resource = WebResource(
                        url=urljoin(base_url, path),
                        discovery_type=DiscoveryType.DIRECTORY if not '.' in path.split('/')[-1] else DiscoveryType.FILE,
                        status_code=int(status_code),
                        response_type=self._classify_response_type(int(status_code)),
                        content_length=int(content_length)
                    )
                    
                    resources.append(resource)
        
        return resources
    
    def _enumerate_ffuf(self, config: EnumerationConfig) -> List[WebResource]:
        """FFUF web fuzzer enumeration"""
        if not self.available_tools.get('ffuf', False):
            return []
        
        resources = []
        
        try:
            for target in config.targets:
                # Create wordlist file
                wordlist_file = Path(f"/tmp/ffuf_wordlist_{config.scan_id}.txt")
                
                # Combine wordlists
                combined_wordlist = []
                for dtype in config.discovery_types:
                    if dtype == DiscoveryType.DIRECTORY:
                        combined_wordlist.extend(self.wordlists['common_directories'])
                    elif dtype == DiscoveryType.FILE:
                        combined_wordlist.extend(self.wordlists['common_files'])
                
                unique_words = list(set(combined_wordlist))
                with open(wordlist_file, 'w') as f:
                    for word in unique_words:
                        f.write(f"{word}\n")
                
                # Prepare target URL with FUZZ keyword
                if target.endswith('/'):
                    fuzz_url = f"{target}FUZZ"
                else:
                    fuzz_url = f"{target}/FUZZ"
                
                # Build ffuf command
                cmd = [
                    'ffuf',
                    '-u', fuzz_url,
                    '-w', str(wordlist_file),
                    '-t', str(config.max_threads),
                    '-timeout', str(config.timeout),
                    '-o', f"/tmp/ffuf_output_{config.scan_id}.json",
                    '-of', 'json',
                    '-s'  # Silent mode
                ]
                
                # Add extensions
                if config.extensions:
                    for ext in config.extensions:
                        cmd.extend(['-e', f".{ext}"])
                
                # Add status code filters
                if config.status_codes_include:
                    status_codes = ','.join(map(str, config.status_codes_include))
                    cmd.extend(['-mc', status_codes])
                
                self.logger.log_tool_execution(f"Running ffuf: {' '.join(cmd)}")
                
                # Run ffuf
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=config.scan_timeout)
                
                output_file = Path(f"/tmp/ffuf_output_{config.scan_id}.json")
                if result.returncode == 0 and output_file.exists():
                    resources.extend(self._parse_ffuf_output(output_file, target))
                
                # Cleanup
                for temp_file in [wordlist_file, output_file]:
                    if temp_file.exists():
                        temp_file.unlink()
        
        except Exception as e:
            self.logger.log_error(f"FFUF enumeration failed: {str(e)}", e)
        
        return resources
    
    def _parse_ffuf_output(self, output_file: Path, base_url: str) -> List[WebResource]:
        """Parse FFUF JSON output"""
        resources = []
        
        try:
            with open(output_file, 'r') as f:
                data = json.load(f)
            
            for result in data.get('results', []):
                resource = WebResource(
                    url=result.get('url', ''),
                    discovery_type=DiscoveryType.DIRECTORY if not '.' in result.get('url', '').split('/')[-1] else DiscoveryType.FILE,
                    status_code=result.get('status', 0),
                    response_type=self._classify_response_type(result.get('status', 0)),
                    content_length=result.get('length', 0),
                    response_time=result.get('duration', 0) / 1000  # Convert to seconds
                )
                
                resources.append(resource)
        
        except Exception as e:
            self.logger.log_error(f"Failed to parse FFUF output: {str(e)}", e)
        
        return resources
    
    def _enumerate_httpx(self, config: EnumerationConfig) -> List[WebResource]:
        """HTTPx web probing"""
        if not self.available_tools.get('httpx', False):
            return []
        
        resources = []
        
        try:
            # Create target file
            target_file = Path(f"/tmp/httpx_targets_{config.scan_id}.txt")
            with open(target_file, 'w') as f:
                for target in config.targets:
                    f.write(f"{target}\n")
            
            # Build httpx command
            cmd = [
                'httpx',
                '-l', str(target_file),
                '-title',
                '-tech-detect',
                '-server',
                '-status-code',
                '-content-length',
                '-response-time',
                '-json',
                '-silent'
            ]
            
            self.logger.log_tool_execution(f"Running httpx: {' '.join(cmd)}")
            
            # Run httpx
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=config.scan_timeout)
            
            if result.returncode == 0:
                resources = self._parse_httpx_output(result.stdout)
            
            # Cleanup
            if target_file.exists():
                target_file.unlink()
        
        except Exception as e:
            self.logger.log_error(f"HTTPx enumeration failed: {str(e)}", e)
        
        return resources
    
    def _parse_httpx_output(self, output: str) -> List[WebResource]:
        """Parse HTTPx JSON output"""
        resources = []
        
        for line in output.strip().split('\n'):
            if line:
                try:
                    data = json.loads(line)
                    
                    # Extract technologies
                    technologies = []
                    for tech in data.get('tech', []):
                        technologies.append(TechnologyInfo(name=tech))
                    
                    resource = WebResource(
                        url=data.get('url', ''),
                        discovery_type=DiscoveryType.ENDPOINT,
                        status_code=data.get('status_code', 0),
                        response_type=self._classify_response_type(data.get('status_code', 0)),
                        content_length=data.get('content_length', 0),
                        content_type=data.get('content_type'),
                        title=data.get('title'),
                        server=data.get('webserver'),
                        technologies=technologies,
                        response_time=data.get('response_time', 0) / 1000  # Convert to seconds
                    )
                    
                    resources.append(resource)
                
                except json.JSONDecodeError:
                    continue
        
        return resources
    
    def _classify_response_type(self, status_code: int) -> ResponseType:
        """Classify HTTP response type"""
        if 200 <= status_code < 300:
            return ResponseType.SUCCESS
        elif 300 <= status_code < 400:
            return ResponseType.REDIRECT
        elif 400 <= status_code < 500:
            return ResponseType.CLIENT_ERROR
        elif 500 <= status_code < 600:
            return ResponseType.SERVER_ERROR
        else:
            return ResponseType.ERROR
    
    # Placeholder implementations for other enumerators
    def _enumerate_dirb(self, config: EnumerationConfig) -> List[WebResource]:
        return []
    
    def _enumerate_custom_crawler(self, config: EnumerationConfig) -> List[WebResource]:
        return []
    
    def _enumerate_wayback_urls(self, config: EnumerationConfig) -> List[WebResource]:
        return []
    
    def _enumerate_gau_urls(self, config: EnumerationConfig) -> List[WebResource]:
        return []


# Factory functions
def create_web_enumerator(logger: ReconForgeLogger, database: ReconForgeDatabase,
                         utils: ReconForgeUtils, display: ReconForgeDisplay) -> WebEnumerator:
    """Create a web enumerator instance"""
    return WebEnumerator(logger, database, utils, display)


def create_enumeration_config(targets: List[str], scan_id: str, **kwargs) -> EnumerationConfig:
    """Create an enumeration configuration with defaults"""
    return EnumerationConfig(targets=targets, scan_id=scan_id, **kwargs)