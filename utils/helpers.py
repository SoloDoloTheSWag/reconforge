import re
import subprocess
import asyncio
import aiohttp
import ipaddress
import socket
import json
import yaml
from pathlib import Path
from typing import List, Dict, Optional, Union, Any, Set
from datetime import datetime, timedelta
from urllib.parse import urlparse, urljoin
import dns.resolver
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import ssl
import hashlib
import base64

from .logging import main_logger

class ToolValidator:
    """Validate and check required tools installation"""
    
    REQUIRED_TOOLS = {
        'subfinder': {'cmd': 'subfinder -version', 'description': 'Subdomain discovery tool'},
        'assetfinder': {'cmd': 'assetfinder --help', 'description': 'Asset discovery tool'},
        'amass': {'cmd': 'amass -version', 'description': 'Network mapping tool'},
        'shuffledns': {'cmd': 'shuffledns -version', 'description': 'DNS resolver'},
        'nuclei': {'cmd': 'nuclei -version', 'description': 'Vulnerability scanner'},
        'httpx': {'cmd': 'httpx -version', 'description': 'HTTP toolkit'},
        'nmap': {'cmd': 'nmap --version', 'description': 'Network scanner'},
        'sqlmap': {'cmd': 'sqlmap --version', 'description': 'SQL injection tool'},
        'subzy': {'cmd': 'subzy --help', 'description': 'Subdomain takeover tool'},
        'waybackurls': {'cmd': 'waybackurls -h', 'description': 'Wayback URL finder'},
        'gau': {'cmd': 'gau --help', 'description': 'GetAllUrls tool'},
        'nikto': {'cmd': 'nikto -Version', 'description': 'Web vulnerability scanner'},
        'gobuster': {'cmd': 'gobuster version', 'description': 'Directory/file brute-forcer'},
        'masscan': {'cmd': 'masscan --help', 'description': 'Fast port scanner'},
    }
    
    @staticmethod
    def check_tool(tool_name: str) -> Dict[str, Any]:
        """Check if a tool is installed and working"""
        if tool_name not in ToolValidator.REQUIRED_TOOLS:
            return {'available': False, 'error': f'Unknown tool: {tool_name}'}
        
        tool_info = ToolValidator.REQUIRED_TOOLS[tool_name]
        try:
            result = subprocess.run(
                tool_info['cmd'].split(),
                capture_output=True,
                text=True,
                timeout=10
            )
            return {
                'available': result.returncode in [0, 1],  # Some tools return 1 for help
                'version': result.stdout.strip() or result.stderr.strip(),
                'description': tool_info['description']
            }
        except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError) as e:
            return {
                'available': False,
                'error': str(e),
                'description': tool_info['description']
            }
    
    @staticmethod
    def check_all_tools() -> Dict[str, Dict[str, Any]]:
        """Check all required tools"""
        results = {}
        for tool_name in ToolValidator.REQUIRED_TOOLS:
            results[tool_name] = ToolValidator.check_tool(tool_name)
        return results
    
    @staticmethod
    def get_missing_tools() -> List[str]:
        """Get list of missing tools"""
        results = ToolValidator.check_all_tools()
        return [tool for tool, info in results.items() if not info['available']]

class DomainValidator:
    """Validate and normalize domain names"""
    
    # Regex for domain validation
    DOMAIN_REGEX = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
    )
    
    @staticmethod
    def is_valid_domain(domain: str) -> bool:
        """Check if domain format is valid"""
        if not domain or len(domain) > 255:
            return False
        
        # Remove protocol if present
        if '://' in domain:
            domain = urlparse(f"http://{domain}").netloc
        
        # Remove port if present
        domain = domain.split(':')[0]
        
        return bool(DomainValidator.DOMAIN_REGEX.match(domain))
    
    @staticmethod
    def normalize_domain(domain: str) -> str:
        """Normalize domain name"""
        # Remove protocol
        if '://' in domain:
            from urllib.parse import urlparse
            parsed = urlparse(domain)
            domain = parsed.netloc
        
        # Remove port
        domain = domain.split(':')[0]
        
        # Convert to lowercase
        domain = domain.lower().strip()
        
        return domain
    
    @staticmethod
    def is_subdomain(subdomain: str, domain: str) -> bool:
        """Check if subdomain belongs to domain"""
        subdomain = DomainValidator.normalize_domain(subdomain)
        domain = DomainValidator.normalize_domain(domain)
        
        if subdomain == domain:
            return True
        
        return subdomain.endswith(f'.{domain}')
    
    @staticmethod
    def extract_root_domain(domain: str) -> str:
        """Extract root domain from subdomain"""
        domain = DomainValidator.normalize_domain(domain)
        parts = domain.split('.')
        
        # Handle common TLDs
        if len(parts) >= 3 and parts[-2] in ['co', 'com', 'org', 'net', 'gov']:
            return '.'.join(parts[-3:])
        elif len(parts) >= 2:
            return '.'.join(parts[-2:])
        else:
            return domain

class NetworkHelper:
    """Network-related utility functions"""
    
    @staticmethod
    async def resolve_domain(domain: str) -> Dict[str, Any]:
        """Resolve domain to IP addresses"""
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            
            result = {
                'domain': domain,
                'ipv4': [],
                'ipv6': [],
                'mx': [],
                'txt': [],
                'cname': [],
                'ns': []
            }
            
            # A records
            try:
                answers = resolver.resolve(domain, 'A')
                result['ipv4'] = [str(answer) for answer in answers]
            except dns.exception.DNSException:
                pass
            
            # AAAA records
            try:
                answers = resolver.resolve(domain, 'AAAA')
                result['ipv6'] = [str(answer) for answer in answers]
            except dns.exception.DNSException:
                pass
            
            # MX records
            try:
                answers = resolver.resolve(domain, 'MX')
                result['mx'] = [f"{answer.preference} {answer.exchange}" for answer in answers]
            except dns.exception.DNSException:
                pass
            
            # TXT records
            try:
                answers = resolver.resolve(domain, 'TXT')
                result['txt'] = [str(answer) for answer in answers]
            except dns.exception.DNSException:
                pass
            
            # CNAME records
            try:
                answers = resolver.resolve(domain, 'CNAME')
                result['cname'] = [str(answer) for answer in answers]
            except dns.exception.DNSException:
                pass
            
            # NS records
            try:
                answers = resolver.resolve(domain, 'NS')
                result['ns'] = [str(answer) for answer in answers]
            except dns.exception.DNSException:
                pass
            
            return result
            
        except Exception as e:
            main_logger.error(f"DNS resolution failed for {domain}: {e}")
            return {'domain': domain, 'error': str(e)}
    
    @staticmethod
    def is_ip_address(address: str) -> bool:
        """Check if string is a valid IP address"""
        try:
            ipaddress.ip_address(address)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def is_private_ip(ip: str) -> bool:
        """Check if IP address is private"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private
        except ValueError:
            return False
    
    @staticmethod
    async def check_port_open(host: str, port: int, timeout: int = 3) -> bool:
        """Check if a port is open on a host"""
        try:
            future = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(future, timeout=timeout)
            writer.close()
            await writer.wait_closed()
            return True
        except Exception:
            return False
    
    @staticmethod
    async def get_ssl_info(domain: str, port: int = 443) -> Dict[str, Any]:
        """Get SSL certificate information"""
        try:
            context = ssl.create_default_context()
            
            with socket.create_connection((domain, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert_der = ssock.getpeercert(binary_form=True)
                    cert = x509.load_der_x509_certificate(cert_der, default_backend())
                    
                    return {
                        'subject': cert.subject.rfc4514_string(),
                        'issuer': cert.issuer.rfc4514_string(),
                        'version': cert.version,
                        'serial_number': str(cert.serial_number),
                        'not_valid_before': cert.not_valid_before.isoformat(),
                        'not_valid_after': cert.not_valid_after.isoformat(),
                        'expired': cert.not_valid_after < datetime.utcnow(),
                        'san': [name.value for name in cert.extensions.get_extension_for_oid(
                            x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
                        ).value] if cert.extensions else []
                    }
        except Exception as e:
            return {'error': str(e)}

class FileHelper:
    """File and directory utility functions"""
    
    @staticmethod
    def ensure_directory(path: Union[str, Path]) -> Path:
        """Ensure directory exists, create if not"""
        path = Path(path)
        path.mkdir(parents=True, exist_ok=True)
        return path
    
    @staticmethod
    def safe_filename(filename: str) -> str:
        """Create safe filename from string"""
        # Replace unsafe characters
        safe = re.sub(r'[<>:"/\\|?*]', '_', filename)
        # Remove multiple underscores
        safe = re.sub(r'_+', '_', safe)
        # Remove leading/trailing underscores and dots
        safe = safe.strip('_.')
        # Ensure not empty
        return safe if safe else 'unnamed'
    
    @staticmethod
    def read_wordlist(file_path: Union[str, Path]) -> List[str]:
        """Read wordlist file and return list of words"""
        try:
            path = Path(file_path)
            if not path.exists():
                main_logger.error(f"Wordlist file not found: {file_path}")
                return []
            
            with path.open('r', encoding='utf-8', errors='ignore') as f:
                words = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            
            main_logger.info(f"Loaded {len(words)} words from {file_path}")
            return words
            
        except Exception as e:
            main_logger.error(f"Failed to read wordlist {file_path}: {e}")
            return []
    
    @staticmethod
    def write_results(data: List[str], file_path: Union[str, Path], append: bool = False) -> bool:
        """Write results to file"""
        try:
            path = Path(file_path)
            FileHelper.ensure_directory(path.parent)
            
            mode = 'a' if append else 'w'
            with path.open(mode, encoding='utf-8') as f:
                for item in data:
                    f.write(f"{item}\n")
            
            main_logger.success(f"Results written to {file_path}")
            return True
            
        except Exception as e:
            main_logger.error(f"Failed to write results to {file_path}: {e}")
            return False

class DataProcessor:
    """Data processing and analysis utilities"""
    
    @staticmethod
    def deduplicate_domains(domains: List[str]) -> List[str]:
        """Remove duplicate domains while preserving order"""
        seen = set()
        result = []
        
        for domain in domains:
            domain_clean = DomainValidator.normalize_domain(domain)
            if domain_clean not in seen and DomainValidator.is_valid_domain(domain_clean):
                seen.add(domain_clean)
                result.append(domain_clean)
        
        return result
    
    @staticmethod
    def filter_subdomains(domains: List[str], target_domain: str) -> List[str]:
        """Filter domains to only include valid subdomains of target"""
        target_clean = DomainValidator.normalize_domain(target_domain)
        result = []
        
        for domain in domains:
            if DomainValidator.is_subdomain(domain, target_clean):
                result.append(DomainValidator.normalize_domain(domain))
        
        return DataProcessor.deduplicate_domains(result)
    
    @staticmethod
    def sort_domains_by_level(domains: List[str]) -> List[str]:
        """Sort domains by subdomain level (fewer dots first)"""
        def domain_level(domain):
            return domain.count('.')
        
        return sorted(domains, key=domain_level)
    
    @staticmethod
    def group_by_tld(domains: List[str]) -> Dict[str, List[str]]:
        """Group domains by top-level domain"""
        groups = {}
        
        for domain in domains:
            tld = domain.split('.')[-1]
            if tld not in groups:
                groups[tld] = []
            groups[tld].append(domain)
        
        return groups
    
    @staticmethod
    def extract_keywords(domains: List[str]) -> Dict[str, int]:
        """Extract and count keywords from subdomain names"""
        keywords = {}
        
        for domain in domains:
            parts = domain.replace('.', '-').split('-')
            for part in parts:
                if len(part) > 2 and part.isalpha():
                    part_lower = part.lower()
                    keywords[part_lower] = keywords.get(part_lower, 0) + 1
        
        # Sort by frequency
        return dict(sorted(keywords.items(), key=lambda x: x[1], reverse=True))

class HTTPHelper:
    """HTTP-related utility functions"""
    
    @staticmethod
    async def make_request(url: str, method: str = 'GET', headers: Dict = None, 
                          data: Any = None, timeout: int = 10) -> Dict[str, Any]:
        """Make HTTP request with error handling"""
        default_headers = {
            'User-Agent': 'ReconForge/1.0 (Security Research)'
        }
        
        if headers:
            default_headers.update(headers)
        
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout)) as session:
                async with session.request(method, url, headers=default_headers, data=data) as response:
                    result = {
                        'url': str(response.url),
                        'status': response.status,
                        'headers': dict(response.headers),
                        'size': len(await response.read()) if response.content else 0,
                        'redirect_history': [str(r.url) for r in response.history],
                        'timing': response.headers.get('Server-Timing', ''),
                        'server': response.headers.get('Server', ''),
                        'powered_by': response.headers.get('X-Powered-By', ''),
                        'content_type': response.headers.get('Content-Type', ''),
                    }
                    
                    # Get response text for small responses
                    if result['size'] < 1024 * 100:  # 100KB limit
                        try:
                            result['content'] = await response.text()
                        except Exception:
                            result['content'] = ''
                    
                    return result
                    
        except asyncio.TimeoutError:
            return {'error': 'Request timeout', 'url': url}
        except Exception as e:
            return {'error': str(e), 'url': url}
    
    @staticmethod
    def extract_title(html: str) -> str:
        """Extract title from HTML content"""
        title_match = re.search(r'<title[^>]*>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
        if title_match:
            title = title_match.group(1).strip()
            # Clean up title
            title = re.sub(r'\s+', ' ', title)
            return title[:200]  # Limit length
        return ''
    
    @staticmethod
    def detect_technologies(headers: Dict[str, str], content: str = '') -> List[str]:
        """Detect web technologies from headers and content"""
        technologies = []
        
        # Server header
        server = headers.get('server', '').lower()
        if 'apache' in server:
            technologies.append('Apache')
        elif 'nginx' in server:
            technologies.append('Nginx')
        elif 'iis' in server:
            technologies.append('IIS')
        elif 'cloudflare' in server:
            technologies.append('Cloudflare')
        
        # X-Powered-By header
        powered_by = headers.get('x-powered-by', '').lower()
        if 'php' in powered_by:
            technologies.append('PHP')
        elif 'asp.net' in powered_by:
            technologies.append('ASP.NET')
        elif 'express' in powered_by:
            technologies.append('Express.js')
        
        # Content analysis (basic)
        if content:
            content_lower = content.lower()
            if 'wordpress' in content_lower:
                technologies.append('WordPress')
            if 'drupal' in content_lower:
                technologies.append('Drupal')
            if 'joomla' in content_lower:
                technologies.append('Joomla')
            if 'react' in content_lower:
                technologies.append('React')
            if 'vue.js' in content_lower:
                technologies.append('Vue.js')
            if 'angular' in content_lower:
                technologies.append('Angular')
        
        return list(set(technologies))

class ConfigManager:
    """Configuration file management"""
    
    @staticmethod
    def load_config(config_path: Union[str, Path]) -> Dict[str, Any]:
        """Load configuration from file"""
        try:
            path = Path(config_path)
            if not path.exists():
                return {}
            
            with path.open('r', encoding='utf-8') as f:
                if path.suffix.lower() == '.json':
                    return json.load(f)
                elif path.suffix.lower() in ['.yml', '.yaml']:
                    return yaml.safe_load(f) or {}
                else:
                    # Try JSON first, then YAML
                    content = f.read()
                    try:
                        return json.loads(content)
                    except json.JSONDecodeError:
                        return yaml.safe_load(content) or {}
                        
        except Exception as e:
            main_logger.error(f"Failed to load config from {config_path}: {e}")
            return {}
    
    @staticmethod
    def save_config(config: Dict[str, Any], config_path: Union[str, Path]) -> bool:
        """Save configuration to file"""
        try:
            path = Path(config_path)
            FileHelper.ensure_directory(path.parent)
            
            with path.open('w', encoding='utf-8') as f:
                if path.suffix.lower() == '.json':
                    json.dump(config, f, indent=2, ensure_ascii=False)
                else:
                    yaml.dump(config, f, default_flow_style=False, allow_unicode=True)
            
            return True
            
        except Exception as e:
            main_logger.error(f"Failed to save config to {config_path}: {e}")
            return False

class ReportGenerator:
    """Generate reports in various formats"""
    
    @staticmethod
    def generate_text_report(data: Dict[str, Any]) -> str:
        """Generate plain text report"""
        lines = []
        lines.append("="*80)
        lines.append(f"ReconForge Security Assessment Report")
        lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("="*80)
        lines.append("")
        
        # Scan summary
        if 'scan_info' in data:
            scan = data['scan_info']
            lines.append("SCAN INFORMATION")
            lines.append("-" * 40)
            lines.append(f"Target: {scan.get('target', 'N/A')}")
            lines.append(f"Scan Type: {scan.get('scan_type', 'N/A')}")
            lines.append(f"Status: {scan.get('status', 'N/A')}")
            lines.append(f"Duration: {scan.get('duration', 'N/A')} seconds")
            lines.append("")
        
        # Statistics
        if 'stats' in data:
            stats = data['stats']
            lines.append("STATISTICS")
            lines.append("-" * 40)
            lines.append(f"Total Subdomains: {stats.get('total_subdomains', 0)}")
            lines.append(f"Total Vulnerabilities: {stats.get('total_vulnerabilities', 0)}")
            lines.append(f"Total Services: {stats.get('total_services', 0)}")
            lines.append("")
            
            # Vulnerability breakdown
            if 'vulnerabilities_by_severity' in stats:
                lines.append("Vulnerabilities by Severity:")
                for severity, count in stats['vulnerabilities_by_severity'].items():
                    lines.append(f"  {severity.upper()}: {count}")
                lines.append("")
        
        # Subdomains
        if 'subdomains' in data and data['subdomains']:
            lines.append("DISCOVERED SUBDOMAINS")
            lines.append("-" * 40)
            for subdomain in data['subdomains']:
                ip_info = f" [{subdomain.get('ip_address', 'N/A')}]" if subdomain.get('ip_address') else ""
                status = f" ({subdomain.get('status_code', 'N/A')})" if subdomain.get('status_code') else ""
                lines.append(f"  {subdomain.get('subdomain', 'N/A')}{ip_info}{status}")
            lines.append("")
        
        # Vulnerabilities
        if 'vulnerabilities' in data and data['vulnerabilities']:
            lines.append("VULNERABILITIES")
            lines.append("-" * 40)
            for vuln in data['vulnerabilities']:
                lines.append(f"  [{vuln.get('severity', 'N/A').upper()}] {vuln.get('title', 'N/A')}")
                lines.append(f"    Target: {vuln.get('subdomain', 'N/A')}")
                lines.append(f"    Type: {vuln.get('vulnerability_type', 'N/A')}")
                if vuln.get('description'):
                    lines.append(f"    Description: {vuln.get('description', '')[:200]}...")
                lines.append("")
        
        return '\n'.join(lines)
    
    @staticmethod
    def generate_json_report(data: Dict[str, Any]) -> str:
        """Generate JSON report"""
        report = {
            'report_info': {
                'generated': datetime.now().isoformat(),
                'tool': 'ReconForge',
                'version': '1.0'
            },
            **data
        }
        return json.dumps(report, indent=2, ensure_ascii=False, default=str)
    
    @staticmethod
    def generate_csv_data(items: List[Dict[str, Any]]) -> str:
        """Generate CSV data from list of dictionaries"""
        if not items:
            return ""
        
        import csv
        import io
        
        output = io.StringIO()
        if items:
            writer = csv.DictWriter(output, fieldnames=items[0].keys())
            writer.writeheader()
            for item in items:
                writer.writerow(item)
        
        return output.getvalue()
    
    @staticmethod
    def generate_html_report(data: Dict[str, Any]) -> str:
        """Generate HTML report"""
        html = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ReconForge Security Assessment Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; line-height: 1.6; }
        .header { background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }
        .section { margin: 20px 0; }
        .stats { display: flex; gap: 20px; flex-wrap: wrap; }
        .stat-box { background: #ecf0f1; padding: 15px; border-radius: 5px; min-width: 150px; }
        table { width: 100%; border-collapse: collapse; margin: 10px 0; }
        th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
        th { background: #34495e; color: white; }
        .severity-critical { color: #e74c3c; font-weight: bold; }
        .severity-high { color: #f39c12; font-weight: bold; }
        .severity-medium { color: #f1c40f; font-weight: bold; }
        .severity-low { color: #27ae60; }
        .vulnerability { background: #f8f9fa; padding: 15px; margin: 10px 0; border-left: 4px solid #3498db; }
    </style>
</head>
<body>"""
        
        # Header
        scan_info = data.get('scan_info', {})
        html += f"""
    <div class="header">
        <h1>ReconForge Security Assessment Report</h1>
        <p>Target: {scan_info.get('target', 'N/A')}</p>
        <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p>Scan Type: {scan_info.get('scan_type', 'N/A')}</p>
    </div>
"""
        
        # Statistics
        stats = data.get('stats', {})
        html += """
    <div class="section">
        <h2>Assessment Summary</h2>
        <div class="stats">"""
        
        html += f"""
            <div class="stat-box">
                <h3>{stats.get('total_subdomains', 0)}</h3>
                <p>Subdomains Discovered</p>
            </div>
            <div class="stat-box">
                <h3>{stats.get('total_vulnerabilities', 0)}</h3>
                <p>Vulnerabilities Found</p>
            </div>
            <div class="stat-box">
                <h3>{stats.get('total_services', 0)}</h3>
                <p>Services Identified</p>
            </div>
        </div>
    </div>
"""
        
        # Vulnerability breakdown
        vuln_by_severity = stats.get('vulnerabilities_by_severity', {})
        if vuln_by_severity:
            html += """
    <div class="section">
        <h2>Vulnerability Breakdown</h2>
        <table>
            <tr><th>Severity</th><th>Count</th></tr>"""
            
            for severity, count in vuln_by_severity.items():
                severity_class = f"severity-{severity.lower()}"
                html += f'<tr><td class="{severity_class}">{severity.upper()}</td><td>{count}</td></tr>'
            
            html += "</table></div>"
        
        # Subdomains
        subdomains = data.get('subdomains', [])
        if subdomains:
            html += """
    <div class="section">
        <h2>Discovered Subdomains</h2>
        <table>
            <tr><th>Subdomain</th><th>IP Address</th><th>Status Code</th><th>Title</th></tr>"""
            
            for sub in subdomains:
                html += f"""
                <tr>
                    <td>{sub.get('subdomain', 'N/A')}</td>
                    <td>{sub.get('ip_address', 'N/A')}</td>
                    <td>{sub.get('status_code', 'N/A')}</td>
                    <td>{sub.get('title', 'N/A')[:50]}...</td>
                </tr>"""
            
            html += "</table></div>"
        
        # Vulnerabilities
        vulnerabilities = data.get('vulnerabilities', [])
        if vulnerabilities:
            html += '<div class="section"><h2>Vulnerabilities</h2>'
            
            for vuln in vulnerabilities:
                severity_class = f"severity-{vuln.get('severity', 'low').lower()}"
                html += f"""
                <div class="vulnerability">
                    <h3 class="{severity_class}">[{vuln.get('severity', 'N/A').upper()}] {vuln.get('title', 'N/A')}</h3>
                    <p><strong>Target:</strong> {vuln.get('subdomain', 'N/A')}</p>
                    <p><strong>Type:</strong> {vuln.get('vulnerability_type', 'N/A')}</p>
                    <p><strong>URL:</strong> {vuln.get('url', 'N/A')}</p>
                    <p><strong>Description:</strong> {vuln.get('description', 'No description')}</p>
                </div>"""
            
            html += "</div>"
        
        html += """
</body>
</html>"""
        
        return html
    
    @staticmethod
    def generate_markdown_report(data: Dict[str, Any]) -> str:
        """Generate Markdown report"""
        lines = []
        
        # Header
        scan_info = data.get('scan_info', {})
        lines.append("# ReconForge Security Assessment Report")
        lines.append("")
        lines.append(f"**Target:** {scan_info.get('target', 'N/A')}")
        lines.append(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"**Scan Type:** {scan_info.get('scan_type', 'N/A')}")
        lines.append("")
        
        # Statistics
        stats = data.get('stats', {})
        lines.append("## Assessment Summary")
        lines.append("")
        lines.append(f"- **Subdomains Discovered:** {stats.get('total_subdomains', 0)}")
        lines.append(f"- **Vulnerabilities Found:** {stats.get('total_vulnerabilities', 0)}")
        lines.append(f"- **Services Identified:** {stats.get('total_services', 0)}")
        lines.append("")
        
        # Vulnerability breakdown
        vuln_by_severity = stats.get('vulnerabilities_by_severity', {})
        if vuln_by_severity:
            lines.append("### Vulnerability Breakdown")
            lines.append("")
            for severity, count in vuln_by_severity.items():
                emoji = "🔴" if severity == "critical" else "🟠" if severity == "high" else "🟡" if severity == "medium" else "🟢"
                lines.append(f"- {emoji} **{severity.upper()}:** {count}")
            lines.append("")
        
        # Subdomains
        subdomains = data.get('subdomains', [])
        if subdomains:
            lines.append("## Discovered Subdomains")
            lines.append("")
            lines.append("| Subdomain | IP Address | Status Code | Title |")
            lines.append("|-----------|------------|-------------|-------|")
            
            for sub in subdomains:
                subdomain = sub.get('subdomain', 'N/A')
                ip_addr = sub.get('ip_address', 'N/A')
                status = sub.get('status_code', 'N/A')
                title = sub.get('title', 'N/A')[:50] + ("..." if len(sub.get('title', '')) > 50 else "")
                lines.append(f"| {subdomain} | {ip_addr} | {status} | {title} |")
            
            lines.append("")
        
        # Vulnerabilities
        vulnerabilities = data.get('vulnerabilities', [])
        if vulnerabilities:
            lines.append("## Vulnerabilities")
            lines.append("")
            
            for vuln in vulnerabilities:
                severity = vuln.get('severity', 'low').upper()
                emoji = "🔴" if severity == "CRITICAL" else "🟠" if severity == "HIGH" else "🟡" if severity == "MEDIUM" else "🟢"
                
                lines.append(f"### {emoji} [{severity}] {vuln.get('title', 'N/A')}")
                lines.append("")
                lines.append(f"- **Target:** {vuln.get('subdomain', 'N/A')}")
                lines.append(f"- **Type:** {vuln.get('vulnerability_type', 'N/A')}")
                lines.append(f"- **URL:** {vuln.get('url', 'N/A')}")
                lines.append(f"- **Description:** {vuln.get('description', 'No description')}")
                lines.append("")
        
        return '\n'.join(lines)