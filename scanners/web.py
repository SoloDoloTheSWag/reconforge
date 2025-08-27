import asyncio
import subprocess
import json
import tempfile
from pathlib import Path
from typing import List, Dict, Optional, Any
from urllib.parse import urljoin, urlparse
import re

from scanners.base import WebScanner, VulnerabilityResult, VulnerabilitySeverity
from utils.logging import main_logger
from utils.helpers import HTTPHelper, ToolValidator
from scanners.nikto import get_nikto_scanner


class HTTPXScanner(WebScanner):
    """HTTPX scanner for web service discovery and basic probing"""
    
    def __init__(self):
        super().__init__("httpx", "HTTP toolkit for web service discovery")
        self.ports = [80, 443, 8080, 8443, 8000, 8888, 9000]
        self.follow_redirects = True
        self.check_title = True
        self.check_status_code = True
        self.check_content_length = True
        self.check_tech = True
    
    async def scan(self, targets: List[str], **kwargs) -> List[VulnerabilityResult]:
        """Run HTTPX scan on targets"""
        if not ToolValidator.check_tool('httpx')['available']:
            raise Exception("HTTPX is not installed or not available")
        
        # Create temporary file for targets
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as targets_file:
            for target in targets:
                # If target doesn't have protocol, add both HTTP and HTTPS
                if not target.startswith(('http://', 'https://')):
                    targets_file.write(f"http://{target}\n")
                    targets_file.write(f"https://{target}\n")
                else:
                    targets_file.write(f"{target}\n")
            targets_file_path = targets_file.name
        
        try:
            # Build HTTPX command
            cmd = [
                "httpx",
                "-l", targets_file_path,
                "-json",
                "-silent",
                "-no-color",
                "-timeout", str(self.timeout),
                "-retries", "2",
                "-rate-limit", "100"
            ]
            
            # Add probe options
            if self.follow_redirects:
                cmd.append("-fr")
            
            if self.check_title:
                cmd.append("-title")
            
            if self.check_status_code:
                cmd.append("-status-code")
            
            if self.check_content_length:
                cmd.append("-content-length")
            
            if self.check_tech:
                cmd.append("-tech-detect")
            
            # Add custom ports if specified
            if kwargs.get('ports'):
                cmd.extend(["-p", ",".join(map(str, kwargs['ports']))])
            
            # Run HTTPX
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                main_logger.warning(f"HTTPX finished with return code {process.returncode}")
            
            # Parse results
            results = await self._parse_httpx_results(stdout.decode())
            
            return results
            
        finally:
            # Clean up temporary file
            Path(targets_file_path).unlink(missing_ok=True)
    
    async def _parse_httpx_results(self, output: str) -> List[VulnerabilityResult]:
        """Parse HTTPX JSON output"""
        results = []
        
        for line in output.strip().split('\n'):
            if not line.strip():
                continue
            
            try:
                data = json.loads(line)
                vuln_results = self._analyze_httpx_response(data)
                results.extend(vuln_results)
                
            except json.JSONDecodeError:
                continue
        
        return results
    
    def _analyze_httpx_response(self, data: Dict[str, Any]) -> List[VulnerabilityResult]:
        """Analyze HTTPX response for security issues"""
        results = []
        url = data.get('url', '')
        status_code = data.get('status_code', 0)
        title = data.get('title', '')
        tech = data.get('tech', [])
        content_length = data.get('content_length', 0)
        
        # Check for information disclosure
        if status_code == 200:
            # Directory listing detection
            if any(keyword in title.lower() for keyword in ['index of', 'directory listing']):
                results.append(VulnerabilityResult(
                    title="Directory Listing Enabled",
                    severity=VulnerabilitySeverity.MEDIUM,
                    vulnerability_type="Information Disclosure",
                    target=url,
                    description="Directory listing is enabled, potentially exposing sensitive files",
                    url=url,
                    verified=True,
                    confidence=0.9,
                    metadata={"tool": "httpx", "title": title}
                ))
            
            # Admin panel detection
            admin_indicators = ['admin', 'administrator', 'management', 'control panel', 'dashboard']
            if any(indicator in title.lower() for indicator in admin_indicators):
                results.append(VulnerabilityResult(
                    title="Admin Panel Discovered",
                    severity=VulnerabilitySeverity.LOW,
                    vulnerability_type="Information Disclosure",
                    target=url,
                    description=f"Administrative interface discovered: {title}",
                    url=url,
                    verified=True,
                    confidence=0.8,
                    metadata={"tool": "httpx", "title": title}
                ))
        
        # Check for server errors
        if status_code >= 500:
            results.append(VulnerabilityResult(
                title=f"Server Error ({status_code})",
                severity=VulnerabilitySeverity.LOW,
                vulnerability_type="Server Error",
                target=url,
                description=f"Server returned error status code {status_code}",
                url=url,
                verified=True,
                confidence=0.7,
                metadata={"tool": "httpx", "status_code": status_code}
            ))
        
        # Technology stack analysis
        if tech:
            for technology in tech:
                # Check for vulnerable technologies (basic examples)
                if self._is_vulnerable_tech(technology):
                    results.append(VulnerabilityResult(
                        title=f"Potentially Vulnerable Technology: {technology}",
                        severity=VulnerabilitySeverity.INFO,
                        vulnerability_type="Technology Detection",
                        target=url,
                        description=f"Application uses {technology} which may have known vulnerabilities",
                        url=url,
                        verified=True,
                        confidence=0.6,
                        metadata={"tool": "httpx", "technology": technology}
                    ))
        
        return results
    
    def _is_vulnerable_tech(self, tech: str) -> bool:
        """Check if technology is known to be vulnerable (basic check)"""
        # This is a basic example - in practice you'd want more sophisticated checks
        vulnerable_indicators = [
            'apache/2.2', 'apache/2.0', 'nginx/1.0', 'iis/6.0', 'iis/7.0',
            'php/5.', 'php/4.', 'wordpress/3.', 'wordpress/4.0'
        ]
        
        tech_lower = tech.lower()
        return any(indicator in tech_lower for indicator in vulnerable_indicators)


class SubdomainTakeoverScanner(WebScanner):
    """Scanner for subdomain takeover vulnerabilities"""
    
    def __init__(self):
        super().__init__("subdomain_takeover", "Subdomain takeover vulnerability scanner")
        self.fingerprints = self._load_takeover_fingerprints()
    
    def _load_takeover_fingerprints(self) -> Dict[str, Dict[str, Any]]:
        """Load subdomain takeover fingerprints"""
        return {
            "amazon_s3": {
                "cname": ["amazonaws.com"],
                "response": ["NoSuchBucket", "The specified bucket does not exist"],
                "service": "Amazon S3"
            },
            "github": {
                "cname": ["github.io", "github.com"],
                "response": ["There isn't a GitHub Pages site here", "404 - File not found"],
                "service": "GitHub Pages"
            },
            "heroku": {
                "cname": ["herokuapp.com", "herokussl.com"],
                "response": ["No such app", "There's nothing here"],
                "service": "Heroku"
            },
            "shopify": {
                "cname": ["myshopify.com"],
                "response": ["Sorry, this shop is currently unavailable"],
                "service": "Shopify"
            },
            "fastly": {
                "cname": ["fastly.com"],
                "response": ["Fastly error: unknown domain"],
                "service": "Fastly CDN"
            },
            "cloudfront": {
                "cname": ["cloudfront.net"],
                "response": ["Bad request", "ERROR: The request could not be satisfied"],
                "service": "Amazon CloudFront"
            },
            "azure": {
                "cname": ["azurewebsites.net", "azure.com"],
                "response": ["Web Site not found", "The resource you are looking for has been removed"],
                "service": "Microsoft Azure"
            }
        }
    
    async def scan(self, targets: List[str], **kwargs) -> List[VulnerabilityResult]:
        """Scan for subdomain takeover vulnerabilities"""
        results = []
        
        for target in targets:
            vuln_result = await self._check_subdomain_takeover(target)
            if vuln_result:
                results.append(vuln_result)
        
        return results
    
    async def _check_subdomain_takeover(self, domain: str) -> Optional[VulnerabilityResult]:
        """Check single domain for takeover vulnerability"""
        try:
            # Resolve CNAME records
            from ..utils.helpers import NetworkHelper
            dns_info = await NetworkHelper.resolve_domain(domain)
            
            if not dns_info.get('cname'):
                return None
            
            cname_records = dns_info['cname']
            
            # Check each CNAME against fingerprints
            for cname in cname_records:
                for service_name, fingerprint in self.fingerprints.items():
                    if any(pattern in cname.lower() for pattern in fingerprint['cname']):
                        # Found matching CNAME, check HTTP response
                        http_result = await self._check_http_response(domain, fingerprint)
                        if http_result:
                            return VulnerabilityResult(
                                title=f"Subdomain Takeover Possible ({fingerprint['service']})",
                                severity=VulnerabilitySeverity.HIGH,
                                vulnerability_type="Subdomain Takeover",
                                target=domain,
                                description=f"Domain {domain} points to {fingerprint['service']} but may be unclaimed",
                                url=f"https://{domain}",
                                verified=True,
                                confidence=http_result['confidence'],
                                metadata={
                                    "tool": "subdomain_takeover",
                                    "service": fingerprint['service'],
                                    "cname": cname,
                                    "response_indicators": http_result['indicators']
                                }
                            )
            
            return None
            
        except Exception as e:
            main_logger.debug(f"Subdomain takeover check failed for {domain}: {e}")
            return None
    
    async def _check_http_response(self, domain: str, fingerprint: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Check HTTP response for takeover indicators"""
        try:
            # Try both HTTP and HTTPS
            for protocol in ['https', 'http']:
                url = f"{protocol}://{domain}"
                
                response = await HTTPHelper.make_request(url, timeout=self.timeout)
                
                if 'error' in response:
                    continue
                
                content = response.get('content', '').lower()
                status_code = response.get('status', 0)
                
                # Check for response indicators
                found_indicators = []
                for indicator in fingerprint['response']:
                    if indicator.lower() in content:
                        found_indicators.append(indicator)
                
                if found_indicators:
                    confidence = 0.8 if status_code == 404 else 0.6
                    return {
                        'confidence': confidence,
                        'indicators': found_indicators,
                        'status_code': status_code
                    }
            
            return None
            
        except Exception:
            return None


class DirectoryBruteforcer(WebScanner):
    """Directory and file brute force scanner"""
    
    def __init__(self, wordlist_path: str = None):
        super().__init__("directory_brute", "Directory and file brute force scanner")
        self.wordlist_path = wordlist_path
        self.wordlist = self._load_wordlist()
        self.interesting_files = [
            '.env', '.git', 'config.php', 'database.php', 'wp-config.php',
            'admin.php', 'login.php', 'backup.sql', 'dump.sql', 'robots.txt',
            'sitemap.xml', '.htaccess', 'web.config', 'composer.json'
        ]
    
    def _load_wordlist(self) -> List[str]:
        """Load directory wordlist"""
        if self.wordlist_path:
            from ..utils.helpers import FileHelper
            return FileHelper.read_wordlist(self.wordlist_path)
        else:
            # Default wordlist
            return [
                'admin', 'administrator', 'api', 'app', 'backup', 'config',
                'css', 'data', 'db', 'dev', 'docs', 'downloads', 'files',
                'images', 'img', 'include', 'includes', 'js', 'lib', 'login',
                'logs', 'mail', 'old', 'php', 'private', 'public', 'src',
                'static', 'temp', 'test', 'tmp', 'upload', 'uploads', 'var',
                'web', 'www', 'assets', 'cache', 'tools', 'util', 'utils'
            ]
    
    async def scan(self, targets: List[str], **kwargs) -> List[VulnerabilityResult]:
        """Run directory brute force scan"""
        results = []
        
        for target in targets:
            if not self.is_web_target(target):
                target = self.normalize_url(target)
            
            # Check if target is accessible
            base_check = await self.check_web_service(target)
            if not base_check:
                continue
            
            # Brute force directories
            dir_results = await self._brute_force_directories(target)
            results.extend(dir_results)
            
            # Check for interesting files
            file_results = await self._check_interesting_files(target)
            results.extend(file_results)
        
        return results
    
    async def _brute_force_directories(self, base_url: str) -> List[VulnerabilityResult]:
        """Brute force directories"""
        results = []
        
        # Create semaphore for concurrency control
        semaphore = asyncio.Semaphore(20)
        
        # Create tasks
        tasks = [
            self._check_directory(semaphore, base_url, directory)
            for directory in self.wordlist
        ]
        
        # Execute tasks
        dir_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        for result in dir_results:
            if isinstance(result, VulnerabilityResult):
                results.append(result)
        
        return results
    
    async def _check_directory(self, semaphore: asyncio.Semaphore, 
                              base_url: str, directory: str) -> Optional[VulnerabilityResult]:
        """Check if directory exists"""
        async with semaphore:
            try:
                url = urljoin(base_url.rstrip('/') + '/', directory + '/')
                
                response = await HTTPHelper.make_request(url, timeout=5)
                
                if 'error' in response:
                    return None
                
                status_code = response.get('status', 0)
                
                # Check for interesting responses
                if status_code in [200, 403]:
                    content = response.get('content', '')
                    title = HTTPHelper.extract_title(content)
                    
                    severity = VulnerabilitySeverity.LOW
                    description = f"Directory found: {directory}"
                    
                    # Check for directory listing
                    if 'index of' in content.lower() or 'directory listing' in content.lower():
                        severity = VulnerabilitySeverity.MEDIUM
                        description = f"Directory listing enabled: {directory}"
                    
                    # Check for sensitive directories
                    sensitive_dirs = ['admin', 'config', 'backup', 'private', '.git', 'db']
                    if any(sens_dir in directory.lower() for sens_dir in sensitive_dirs):
                        severity = VulnerabilitySeverity.MEDIUM
                        description = f"Sensitive directory found: {directory}"
                    
                    return VulnerabilityResult(
                        title=f"Directory Discovered: /{directory}/",
                        severity=severity,
                        vulnerability_type="Directory Discovery",
                        target=base_url,
                        description=description,
                        url=url,
                        verified=True,
                        confidence=0.8 if status_code == 200 else 0.6,
                        metadata={
                            "tool": "directory_brute",
                            "status_code": status_code,
                            "title": title,
                            "directory": directory
                        }
                    )
                
                return None
                
            except Exception:
                return None
    
    async def _check_interesting_files(self, base_url: str) -> List[VulnerabilityResult]:
        """Check for interesting files"""
        results = []
        
        # Create semaphore for concurrency control
        semaphore = asyncio.Semaphore(10)
        
        # Create tasks
        tasks = [
            self._check_file(semaphore, base_url, filename)
            for filename in self.interesting_files
        ]
        
        # Execute tasks
        file_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        for result in file_results:
            if isinstance(result, VulnerabilityResult):
                results.append(result)
        
        return results
    
    async def _check_file(self, semaphore: asyncio.Semaphore, 
                         base_url: str, filename: str) -> Optional[VulnerabilityResult]:
        """Check if file exists and is accessible"""
        async with semaphore:
            try:
                url = urljoin(base_url.rstrip('/') + '/', filename)
                
                response = await HTTPHelper.make_request(url, timeout=5)
                
                if 'error' in response:
                    return None
                
                status_code = response.get('status', 0)
                
                if status_code == 200:
                    content = response.get('content', '')
                    
                    # Determine severity based on file type
                    severity = VulnerabilitySeverity.MEDIUM
                    if filename in ['.env', 'config.php', 'wp-config.php', 'database.php']:
                        severity = VulnerabilitySeverity.HIGH
                    elif filename in ['backup.sql', 'dump.sql', '.git']:
                        severity = VulnerabilitySeverity.HIGH
                    elif filename in ['robots.txt', 'sitemap.xml']:
                        severity = VulnerabilitySeverity.INFO
                    
                    return VulnerabilityResult(
                        title=f"Sensitive File Exposed: {filename}",
                        severity=severity,
                        vulnerability_type="File Exposure",
                        target=base_url,
                        description=f"Sensitive file {filename} is accessible",
                        url=url,
                        verified=True,
                        confidence=0.9,
                        metadata={
                            "tool": "directory_brute",
                            "filename": filename,
                            "content_preview": content[:200] if content else ""
                        }
                    )
                
                return None
                
            except Exception:
                return None


def get_web_scanners(config: Dict[str, Any] = None) -> List[WebScanner]:
    """Get all web vulnerability scanners"""
    config = config or {}
    scanners = []
    
    # HTTPX scanner (always available if tool exists)
    if ToolValidator.check_tool('httpx')['available']:
        httpx_scanner = HTTPXScanner()
        httpx_scanner.configure(config)
        scanners.append(httpx_scanner)
    
    # Subdomain takeover scanner
    takeover_scanner = SubdomainTakeoverScanner()
    takeover_scanner.configure(config)
    scanners.append(takeover_scanner)
    
    # Directory brute forcer
    dir_scanner = DirectoryBruteforcer(config.get('directory_wordlist'))
    dir_scanner.configure(config)
    scanners.append(dir_scanner)
    
    # Nikto web vulnerability scanner
    if ToolValidator.check_tool('nikto')['available']:
        nikto_scanner = get_nikto_scanner()
        nikto_scanner.configure(config)
        scanners.append(nikto_scanner)
    
    # Wapiti scanner
    try:
        from scanners.wapiti import get_wapiti_scanners
        wapiti_scanners = get_wapiti_scanners(config)
        scanners.extend(wapiti_scanners)
    except ImportError:
        pass
    
    # OWASP ZAP scanners
    try:
        from scanners.zap import get_zap_scanners
        zap_scanners = get_zap_scanners(config)
        scanners.extend(zap_scanners)
    except ImportError:
        pass
    
    # testssl scanner for SSL/TLS testing
    try:
        from scanners.testssl import get_testssl_scanners
        testssl_scanners = get_testssl_scanners(config)
        scanners.extend(testssl_scanners)
    except ImportError:
        pass
    
    return scanners