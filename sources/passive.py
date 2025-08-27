import aiohttp
import asyncio
import subprocess
import json
import re
from typing import List, Dict, Optional
from urllib.parse import quote

from sources.base import PassiveSource, SubdomainResult
from utils.logging import main_logger
from utils.helpers import HTTPHelper, ToolValidator


class SubfinderSource(PassiveSource):
    """Subfinder passive subdomain discovery"""
    
    def __init__(self, config_file: str = None):
        super().__init__("subfinder", "Fast passive subdomain enumeration tool")
        self.config_file = config_file
    
    async def discover(self, target: str, **kwargs) -> List[SubdomainResult]:
        """Run subfinder discovery"""
        cmd = ["subfinder", "-d", target, "-silent", "-o", "-"]
        
        if self.config_file:
            cmd.extend(["-config", self.config_file])
        
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                raise Exception(f"Subfinder failed: {stderr.decode()}")
            
            subdomains = stdout.decode().strip().split('\n')
            filtered = self.filter_results(subdomains, target)
            
            return [
                SubdomainResult(
                    subdomain=sub,
                    source=self.name,
                    confidence=0.9,
                    metadata={"tool": "subfinder"}
                ) for sub in filtered
            ]
            
        except Exception as e:
            main_logger.error(f"Subfinder discovery failed: {e}")
            raise


class AssetfinderSource(PassiveSource):
    """Assetfinder passive subdomain discovery"""
    
    def __init__(self):
        super().__init__("assetfinder", "Find domains and subdomains related to a given domain")
    
    async def discover(self, target: str, **kwargs) -> List[SubdomainResult]:
        """Run assetfinder discovery"""
        cmd = ["assetfinder", target]
        
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                raise Exception(f"Assetfinder failed: {stderr.decode()}")
            
            subdomains = stdout.decode().strip().split('\n')
            filtered = self.filter_results(subdomains, target)
            
            return [
                SubdomainResult(
                    subdomain=sub,
                    source=self.name,
                    confidence=0.8,
                    metadata={"tool": "assetfinder"}
                ) for sub in filtered
            ]
            
        except Exception as e:
            main_logger.error(f"Assetfinder discovery failed: {e}")
            raise


class AmassSource(PassiveSource):
    """Amass passive subdomain discovery"""
    
    def __init__(self, config_file: str = None):
        super().__init__("amass", "In-depth DNS enumeration and network mapping", rate_limit=5)
        self.config_file = config_file
    
    async def discover(self, target: str, **kwargs) -> List[SubdomainResult]:
        """Run amass enum discovery"""
        cmd = ["amass", "enum", "-d", target, "-passive", "-silent"]
        
        if self.config_file:
            cmd.extend(["-config", self.config_file])
        
        # Add timeout for amass as it can run for a long time
        timeout = kwargs.get('timeout', 300)  # 5 minutes default
        
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(), 
                    timeout=timeout
                )
            except asyncio.TimeoutError:
                process.terminate()
                await process.wait()
                raise Exception(f"Amass timed out after {timeout} seconds")
            
            if process.returncode != 0:
                raise Exception(f"Amass failed: {stderr.decode()}")
            
            subdomains = stdout.decode().strip().split('\n')
            filtered = self.filter_results(subdomains, target)
            
            return [
                SubdomainResult(
                    subdomain=sub,
                    source=self.name,
                    confidence=0.95,
                    metadata={"tool": "amass", "mode": "passive"}
                ) for sub in filtered
            ]
            
        except Exception as e:
            main_logger.error(f"Amass discovery failed: {e}")
            raise


class CrtShSource(PassiveSource):
    """Certificate Transparency logs via crt.sh"""
    
    def __init__(self):
        super().__init__("crt_sh", "Certificate Transparency log search")
    
    async def discover(self, target: str, **kwargs) -> List[SubdomainResult]:
        """Query crt.sh for certificates"""
        url = f"https://crt.sh/?q=%25.{target}&output=json"
        
        try:
            response = await HTTPHelper.make_request(url, timeout=30)
            
            if 'error' in response:
                raise Exception(response['error'])
            
            if response.get('status') != 200:
                raise Exception(f"HTTP {response.get('status')}")
            
            data = json.loads(response.get('content', '[]'))
            subdomains = set()
            
            for cert in data:
                name_value = cert.get('name_value', '')
                # Handle multi-line certificate names
                for line in name_value.split('\n'):
                    line = line.strip()
                    if line and not line.startswith('*'):  # Skip wildcards for now
                        subdomains.add(line)
            
            filtered = self.filter_results(list(subdomains), target)
            
            return [
                SubdomainResult(
                    subdomain=sub,
                    source=self.name,
                    confidence=0.9,
                    metadata={"tool": "crt.sh", "source": "certificate_transparency"}
                ) for sub in filtered
            ]
            
        except Exception as e:
            main_logger.error(f"crt.sh discovery failed: {e}")
            raise


class SecurityTrailsSource(PassiveSource):
    """SecurityTrails API subdomain discovery"""
    
    def __init__(self, api_key: str = None):
        super().__init__("securitytrails", "SecurityTrails passive DNS data", api_key=api_key)
    
    async def discover(self, target: str, **kwargs) -> List[SubdomainResult]:
        """Query SecurityTrails API"""
        if not self.api_key:
            raise Exception("SecurityTrails API key required")
        
        url = f"https://api.securitytrails.com/v1/domain/{target}/subdomains"
        headers = {"APIKEY": self.api_key}
        
        try:
            response = await HTTPHelper.make_request(url, headers=headers, timeout=30)
            
            if 'error' in response:
                raise Exception(response['error'])
            
            if response.get('status') == 401:
                raise Exception("Invalid API key")
            
            if response.get('status') != 200:
                raise Exception(f"HTTP {response.get('status')}")
            
            data = json.loads(response.get('content', '{}'))
            subdomains = data.get('subdomains', [])
            
            # Prepend subdomains with target domain
            full_domains = [f"{sub}.{target}" for sub in subdomains if sub]
            filtered = self.filter_results(full_domains, target)
            
            return [
                SubdomainResult(
                    subdomain=sub,
                    source=self.name,
                    confidence=0.95,
                    metadata={"tool": "securitytrails", "api": True}
                ) for sub in filtered
            ]
            
        except Exception as e:
            main_logger.error(f"SecurityTrails discovery failed: {e}")
            raise


class VirusTotalSource(PassiveSource):
    """VirusTotal API subdomain discovery"""
    
    def __init__(self, api_key: str = None):
        super().__init__("virustotal", "VirusTotal domain information", api_key=api_key)
    
    async def discover(self, target: str, **kwargs) -> List[SubdomainResult]:
        """Query VirusTotal API for domain information"""
        if not self.api_key:
            raise Exception("VirusTotal API key required")
        
        url = f"https://www.virustotal.com/vtapi/v2/domain/report"
        params = {
            'apikey': self.api_key,
            'domain': target
        }
        
        try:
            response = await HTTPHelper.make_request(
                url, 
                method='GET', 
                headers={'User-Agent': 'ReconForge/1.0'},
                timeout=30
            )
            
            if 'error' in response:
                raise Exception(response['error'])
            
            if response.get('status') != 200:
                raise Exception(f"HTTP {response.get('status')}")
            
            data = json.loads(response.get('content', '{}'))
            
            subdomains = set()
            
            # Extract from detected_subdomains
            if 'detected_subdomains' in data:
                subdomains.update(data['detected_subdomains'])
            
            # Extract from undetected_subdomains
            if 'undetected_subdomains' in data:
                subdomains.update(data['undetected_subdomains'])
            
            # Extract from DNS records
            if 'dns_records' in data:
                for record in data['dns_records']:
                    if record.get('type') in ['A', 'AAAA', 'CNAME']:
                        value = record.get('value', '')
                        if '.' in value and target in value:
                            subdomains.add(value)
            
            filtered = self.filter_results(list(subdomains), target)
            
            return [
                SubdomainResult(
                    subdomain=sub,
                    source=self.name,
                    confidence=0.9,
                    metadata={"tool": "virustotal", "api": True}
                ) for sub in filtered
            ]
            
        except Exception as e:
            main_logger.error(f"VirusTotal discovery failed: {e}")
            raise


class WaybackSource(PassiveSource):
    """Wayback Machine URL discovery for subdomains"""
    
    def __init__(self):
        super().__init__("wayback", "Internet Archive Wayback Machine URLs")
    
    async def discover(self, target: str, **kwargs) -> List[SubdomainResult]:
        """Extract subdomains from Wayback Machine URLs"""
        try:
            # Try using waybackurls tool first
            if ToolValidator.check_tool('waybackurls')['available']:
                return await self._discover_with_tool(target)
            else:
                return await self._discover_with_api(target)
                
        except Exception as e:
            main_logger.error(f"Wayback discovery failed: {e}")
            raise
    
    async def _discover_with_tool(self, target: str) -> List[SubdomainResult]:
        """Use waybackurls tool"""
        cmd = ["waybackurls", target]
        
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        stdout, stderr = await process.communicate()
        
        if process.returncode != 0:
            raise Exception(f"waybackurls failed: {stderr.decode()}")
        
        urls = stdout.decode().strip().split('\n')
        subdomains = self._extract_subdomains_from_urls(urls, target)
        filtered = self.filter_results(subdomains, target)
        
        return [
            SubdomainResult(
                subdomain=sub,
                source=self.name,
                confidence=0.85,
                metadata={"tool": "waybackurls", "source": "wayback_machine"}
            ) for sub in filtered
        ]
    
    async def _discover_with_api(self, target: str) -> List[SubdomainResult]:
        """Use Wayback Machine API"""
        url = f"http://web.archive.org/cdx/search/cdx?url=*.{target}/*&output=json&fl=original&collapse=urlkey"
        
        response = await HTTPHelper.make_request(url, timeout=30)
        
        if 'error' in response:
            raise Exception(response['error'])
        
        if response.get('status') != 200:
            raise Exception(f"HTTP {response.get('status')}")
        
        try:
            data = json.loads(response.get('content', '[]'))
            urls = [item[0] for item in data[1:] if len(item) > 0]  # Skip header
            subdomains = self._extract_subdomains_from_urls(urls, target)
            filtered = self.filter_results(subdomains, target)
            
            return [
                SubdomainResult(
                    subdomain=sub,
                    source=self.name,
                    confidence=0.85,
                    metadata={"tool": "wayback_api", "source": "wayback_machine"}
                ) for sub in filtered
            ]
        except json.JSONDecodeError:
            # Sometimes the API returns non-JSON data
            content = response.get('content', '')
            urls = [line.strip() for line in content.split('\n') if line.strip()]
            subdomains = self._extract_subdomains_from_urls(urls, target)
            filtered = self.filter_results(subdomains, target)
            
            return [
                SubdomainResult(
                    subdomain=sub,
                    source=self.name,
                    confidence=0.8,
                    metadata={"tool": "wayback_api", "source": "wayback_machine"}
                ) for sub in filtered
            ]
    
    def _extract_subdomains_from_urls(self, urls: List[str], target: str) -> List[str]:
        """Extract subdomains from list of URLs"""
        subdomains = set()
        
        for url in urls:
            if not url or not isinstance(url, str):
                continue
                
            try:
                # Extract hostname from URL
                if '://' not in url:
                    url = 'http://' + url
                
                from urllib.parse import urlparse
                parsed = urlparse(url)
                hostname = parsed.hostname
                
                if hostname and target in hostname:
                    subdomains.add(hostname)
                    
            except Exception:
                continue
        
        return list(subdomains)


class GAUSource(PassiveSource):
    """GetAllUrls (GAU) source for subdomain discovery"""
    
    def __init__(self):
        super().__init__("gau", "Get All URLs for subdomain discovery")
    
    async def discover(self, target: str, **kwargs) -> List[SubdomainResult]:
        """Use GAU tool to find URLs and extract subdomains"""
        cmd = ["gau", target]
        
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                raise Exception(f"GAU failed: {stderr.decode()}")
            
            urls = stdout.decode().strip().split('\n')
            subdomains = self._extract_subdomains_from_urls(urls, target)
            filtered = self.filter_results(subdomains, target)
            
            return [
                SubdomainResult(
                    subdomain=sub,
                    source=self.name,
                    confidence=0.8,
                    metadata={"tool": "gau"}
                ) for sub in filtered
            ]
            
        except Exception as e:
            main_logger.error(f"GAU discovery failed: {e}")
            raise
    
    def _extract_subdomains_from_urls(self, urls: List[str], target: str) -> List[str]:
        """Extract subdomains from URLs"""
        subdomains = set()
        
        for url in urls:
            if not url or not isinstance(url, str):
                continue
                
            try:
                from urllib.parse import urlparse
                parsed = urlparse(url if '://' in url else 'http://' + url)
                hostname = parsed.hostname
                
                if hostname and target in hostname:
                    subdomains.add(hostname)
                    
            except Exception:
                continue
        
        return list(subdomains)


class ShodanSource(PassiveSource):
    """Shodan passive subdomain discovery"""
    
    def __init__(self, api_key: str = None):
        super().__init__("shodan", "Shodan search engine for Internet-connected devices", api_key=api_key)
    
    async def discover(self, target: str, **kwargs) -> List[SubdomainResult]:
        """Query Shodan API for subdomain information"""
        if not self.api_key:
            raise Exception("Shodan API key required")
        
        url = "https://api.shodan.io/shodan/host/search"
        params = {
            'key': self.api_key,
            'query': f'hostname:{target}',
            'facets': 'domain'
        }
        
        try:
            response = await HTTPHelper.make_request(
                url, 
                method='GET',
                headers={'User-Agent': 'ReconForge/1.0'},
                timeout=30
            )
            
            if 'error' in response:
                raise Exception(response['error'])
            
            if response.get('status') == 401:
                raise Exception("Invalid Shodan API key")
            
            if response.get('status') != 200:
                raise Exception(f"HTTP {response.get('status')}")
            
            data = json.loads(response.get('content', '{}'))
            subdomains = set()
            
            # Extract hostnames from matches
            for match in data.get('matches', []):
                hostnames = match.get('hostnames', [])
                for hostname in hostnames:
                    if target in hostname:
                        subdomains.add(hostname)
                
                # Also check the domain field
                domains = match.get('domains', [])
                for domain in domains:
                    if target in domain:
                        subdomains.add(domain)
            
            filtered = self.filter_results(list(subdomains), target)
            
            return [
                SubdomainResult(
                    subdomain=sub,
                    source=self.name,
                    confidence=0.9,
                    metadata={"tool": "shodan", "api": True, "source": "search_results"}
                ) for sub in filtered
            ]
            
        except Exception as e:
            main_logger.error(f"Shodan discovery failed: {e}")
            raise


class CensysSource(PassiveSource):
    """Censys passive subdomain discovery"""
    
    def __init__(self, api_id: str = None, api_secret: str = None):
        super().__init__("censys", "Censys Internet scanning platform")
        self.api_id = api_id
        self.api_secret = api_secret
    
    async def discover(self, target: str, **kwargs) -> List[SubdomainResult]:
        """Query Censys API for certificate data"""
        if not self.api_id or not self.api_secret:
            raise Exception("Censys API credentials required")
        
        url = "https://search.censys.io/api/v2/certificates/search"
        
        import base64
        auth_string = base64.b64encode(f"{self.api_id}:{self.api_secret}".encode()).decode()
        headers = {
            'Authorization': f'Basic {auth_string}',
            'Content-Type': 'application/json',
            'User-Agent': 'ReconForge/1.0'
        }
        
        payload = {
            'q': f'names: {target}',
            'per_page': 100
        }
        
        try:
            response = await HTTPHelper.make_request(
                url,
                method='POST',
                headers=headers,
                data=json.dumps(payload),
                timeout=30
            )
            
            if 'error' in response:
                raise Exception(response['error'])
            
            if response.get('status') == 401:
                raise Exception("Invalid Censys API credentials")
            
            if response.get('status') != 200:
                raise Exception(f"HTTP {response.get('status')}")
            
            data = json.loads(response.get('content', '{}'))
            subdomains = set()
            
            # Extract names from certificate results
            for result in data.get('result', {}).get('hits', []):
                names = result.get('names', [])
                for name in names:
                    # Skip wildcards and extract valid subdomains
                    if not name.startswith('*') and target in name:
                        subdomains.add(name)
            
            filtered = self.filter_results(list(subdomains), target)
            
            return [
                SubdomainResult(
                    subdomain=sub,
                    source=self.name,
                    confidence=0.95,
                    metadata={"tool": "censys", "api": True, "source": "certificates"}
                ) for sub in filtered
            ]
            
        except Exception as e:
            main_logger.error(f"Censys discovery failed: {e}")
            raise


class FacebookCTSource(PassiveSource):
    """Facebook Certificate Transparency API"""
    
    def __init__(self):
        super().__init__("facebook_ct", "Facebook Certificate Transparency database")
    
    async def discover(self, target: str, **kwargs) -> List[SubdomainResult]:
        """Query Facebook CT API"""
        url = f"https://graph.facebook.com/certificates"
        params = {
            'query': target,
            'fields': 'domains',
            'limit': '1000',
            'access_token': 'anonymous'  # Facebook CT allows anonymous access
        }
        
        try:
            response = await HTTPHelper.make_request(url, timeout=30)
            
            if 'error' in response:
                raise Exception(response['error'])
            
            if response.get('status') != 200:
                raise Exception(f"HTTP {response.get('status')}")
            
            data = json.loads(response.get('content', '{}'))
            subdomains = set()
            
            # Extract domains from certificate data
            for cert in data.get('data', []):
                domains = cert.get('domains', [])
                for domain in domains:
                    if not domain.startswith('*') and target in domain:
                        subdomains.add(domain)
            
            filtered = self.filter_results(list(subdomains), target)
            
            return [
                SubdomainResult(
                    subdomain=sub,
                    source=self.name,
                    confidence=0.9,
                    metadata={"tool": "facebook_ct", "source": "certificate_transparency"}
                ) for sub in filtered
            ]
            
        except Exception as e:
            main_logger.error(f"Facebook CT discovery failed: {e}")
            raise


class RapidDNSSource(PassiveSource):
    """RapidDNS passive DNS database"""
    
    def __init__(self):
        super().__init__("rapiddns", "RapidDNS passive DNS database")
    
    async def discover(self, target: str, **kwargs) -> List[SubdomainResult]:
        """Query RapidDNS database"""
        url = f"https://rapiddns.io/subdomain/{target}"
        
        try:
            response = await HTTPHelper.make_request(
                url,
                headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'},
                timeout=30
            )
            
            if 'error' in response:
                raise Exception(response['error'])
            
            if response.get('status') != 200:
                raise Exception(f"HTTP {response.get('status')}")
            
            content = response.get('content', '')
            
            # Parse HTML to extract subdomains (simple regex approach)
            import re
            subdomain_pattern = r'([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*' + re.escape(target)
            matches = re.findall(subdomain_pattern, content)
            
            # Clean up matches
            subdomains = set()
            for match in matches:
                if isinstance(match, tuple):
                    # Extract the full match from tuple
                    full_match = ''.join(match) + target
                    if full_match.endswith(target):
                        subdomains.add(full_match)
                elif isinstance(match, str) and match.endswith(target):
                    subdomains.add(match)
            
            filtered = self.filter_results(list(subdomains), target)
            
            return [
                SubdomainResult(
                    subdomain=sub,
                    source=self.name,
                    confidence=0.85,
                    metadata={"tool": "rapiddns", "source": "passive_dns"}
                ) for sub in filtered
            ]
            
        except Exception as e:
            main_logger.error(f"RapidDNS discovery failed: {e}")
            raise


class DNSDBSource(PassiveSource):
    """Farsight DNSDB passive DNS database"""
    
    def __init__(self, api_key: str = None):
        super().__init__("dnsdb", "Farsight DNSDB passive DNS database", api_key=api_key)
    
    async def discover(self, target: str, **kwargs) -> List[SubdomainResult]:
        """Query DNSDB API"""
        if not self.api_key:
            raise Exception("DNSDB API key required")
        
        url = f"https://api.dnsdb.info/lookup/rrset/name/*.{target}"
        headers = {
            'X-API-Key': self.api_key,
            'User-Agent': 'ReconForge/1.0'
        }
        
        try:
            response = await HTTPHelper.make_request(url, headers=headers, timeout=30)
            
            if 'error' in response:
                raise Exception(response['error'])
            
            if response.get('status') == 401:
                raise Exception("Invalid DNSDB API key")
            
            if response.get('status') != 200:
                raise Exception(f"HTTP {response.get('status')}")
            
            content = response.get('content', '')
            subdomains = set()
            
            # Parse NDJSON format
            for line in content.split('\n'):
                if not line.strip():
                    continue
                try:
                    record = json.loads(line)
                    rrname = record.get('rrname', '')
                    if rrname and target in rrname:
                        # Remove trailing dot from DNS names
                        clean_name = rrname.rstrip('.')
                        if clean_name != target:  # Don't include the target domain itself
                            subdomains.add(clean_name)
                except json.JSONDecodeError:
                    continue
            
            filtered = self.filter_results(list(subdomains), target)
            
            return [
                SubdomainResult(
                    subdomain=sub,
                    source=self.name,
                    confidence=0.95,
                    metadata={"tool": "dnsdb", "api": True, "source": "passive_dns"}
                ) for sub in filtered
            ]
            
        except Exception as e:
            main_logger.error(f"DNSDB discovery failed: {e}")
            raise


def get_passive_sources(config: Dict[str, any] = None) -> List[PassiveSource]:
    """Get all available passive sources with configuration"""
    config = config or {}
    
    sources = []
    
    # Always available sources
    sources.append(SubfinderSource(config.get('subfinder_config')))
    sources.append(AssetfinderSource())
    sources.append(AmassSource(config.get('amass_config')))
    sources.append(CrtShSource())
    sources.append(WaybackSource())
    sources.append(FacebookCTSource())
    sources.append(RapidDNSSource())
    
    # Check for tool availability
    if ToolValidator.check_tool('gau')['available']:
        sources.append(GAUSource())
    
    # API-dependent sources
    if config.get('securitytrails_api_key'):
        sources.append(SecurityTrailsSource(config['securitytrails_api_key']))
    
    if config.get('virustotal_api_key'):
        sources.append(VirusTotalSource(config['virustotal_api_key']))
    
    if config.get('shodan_api_key'):
        sources.append(ShodanSource(config['shodan_api_key']))
    
    if config.get('censys_api_id') and config.get('censys_api_secret'):
        sources.append(CensysSource(config['censys_api_id'], config['censys_api_secret']))
    
    if config.get('dnsdb_api_key'):
        sources.append(DNSDBSource(config['dnsdb_api_key']))
    
    return sources