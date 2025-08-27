import re
import subprocess
import asyncio
import aiohttp
import ipaddress
import socket
import json
import yaml
import os
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
        'gobuster': {'cmd': 'gobuster --help', 'description': 'Directory/file brute-forcer'},
        'masscan': {'cmd': 'masscan --help', 'description': 'Fast port scanner'},
    }
    
    @staticmethod
    def check_tool(tool_name: str) -> Dict[str, Any]:
        """Check if a tool is installed and working"""
        if tool_name not in ToolValidator.REQUIRED_TOOLS:
            return {'available': False, 'error': f'Unknown tool: {tool_name}'}
        
        tool_info = ToolValidator.REQUIRED_TOOLS[tool_name]
        try:
            # Create environment with Go tools in PATH
            env = os.environ.copy()
            gopath = subprocess.run(['go', 'env', 'GOPATH'], capture_output=True, text=True)
            if gopath.returncode == 0:
                go_bin_path = f"{gopath.stdout.strip()}/bin"
                env['PATH'] = f"{env.get('PATH', '')}:{go_bin_path}"
            
            result = subprocess.run(
                tool_info['cmd'].split(),
                capture_output=True,
                text=True,
                timeout=10,
                env=env
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
    """Generate comprehensive reports in various formats"""
    
    @staticmethod
    def generate_text_report(data: Dict[str, Any]) -> str:
        """Generate enhanced plain text report"""
        lines = []
        lines.append("="*80)
        lines.append(f"ReconForge Security Assessment Report")
        lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("="*80)
        lines.append("")
        
        # Executive Summary
        lines.append("EXECUTIVE SUMMARY")
        lines.append("-" * 40)
        total_vulns = data.get('stats', {}).get('total_vulnerabilities', 0)
        critical_vulns = data.get('stats', {}).get('critical_vulnerabilities', 0)
        high_vulns = data.get('stats', {}).get('high_vulnerabilities', 0)
        
        if total_vulns == 0:
            lines.append("✓ No vulnerabilities were identified during the assessment.")
        elif critical_vulns > 0:
            lines.append(f"⚠  CRITICAL: {critical_vulns} critical vulnerabilities require immediate attention.")
        elif high_vulns > 0:
            lines.append(f"⚠  HIGH RISK: {high_vulns} high-severity vulnerabilities identified.")
        else:
            lines.append(f"ℹ  {total_vulns} vulnerabilities identified with medium/low severity.")
        
        lines.append("")
        
        # Scan summary
        if 'scan_info' in data:
            scan = data['scan_info']
            lines.append("SCAN INFORMATION")
            lines.append("-" * 40)
            lines.append(f"Target: {scan.get('target', 'N/A')}")
            lines.append(f"Scan Type: {scan.get('scan_type', 'N/A')}")
            lines.append(f"Status: {scan.get('status', 'N/A')}")
            lines.append(f"Started: {scan.get('started_at', 'N/A')}")
            lines.append(f"Duration: {scan.get('duration', 'N/A')} seconds")
            lines.append(f"Modules Used: {len(scan.get('modules_used', []))}")
            lines.append("")
        
        # Statistics
        if 'stats' in data:
            stats = data['stats']
            lines.append("STATISTICS")
            lines.append("-" * 40)
            lines.append(f"Total Subdomains: {stats.get('total_subdomains', 0)}")
            lines.append(f"Live Subdomains: {stats.get('live_subdomains', 0)}")
            lines.append(f"Total Vulnerabilities: {stats.get('total_vulnerabilities', 0)}")
            lines.append(f"Total Services: {stats.get('total_services', 0)}")
            lines.append(f"Unique Technologies: {stats.get('unique_technologies', 0)}")
            lines.append("")
            
            # Vulnerability breakdown
            if 'vulnerabilities_by_severity' in stats:
                lines.append("Vulnerabilities by Severity:")
                for severity, count in stats['vulnerabilities_by_severity'].items():
                    emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢", "info": "ℹ️"}.get(severity.lower(), "")
                    lines.append(f"  {emoji} {severity.upper()}: {count}")
                lines.append("")
            
            # Top vulnerability types
            if 'top_vulnerability_types' in stats:
                lines.append("Top Vulnerability Types:")
                for vuln_type, count in stats['top_vulnerability_types'].items():
                    lines.append(f"  • {vuln_type}: {count}")
                lines.append("")
        
        # Risk Assessment
        lines.append("RISK ASSESSMENT")
        lines.append("-" * 40)
        risk_score = ReportGenerator._calculate_risk_score(data)
        risk_level = ReportGenerator._get_risk_level(risk_score)
        lines.append(f"Overall Risk Score: {risk_score}/100")
        lines.append(f"Risk Level: {risk_level}")
        lines.append("")
        
        # Key Findings
        if 'vulnerabilities' in data and data['vulnerabilities']:
            critical_findings = [v for v in data['vulnerabilities'] if v.get('severity') == 'critical']
            high_findings = [v for v in data['vulnerabilities'] if v.get('severity') == 'high']
            
            if critical_findings or high_findings:
                lines.append("KEY FINDINGS")
                lines.append("-" * 40)
                
                for vuln in critical_findings[:5]:  # Top 5 critical
                    lines.append(f"🔴 CRITICAL: {vuln.get('title', 'Unknown')}")
                    lines.append(f"   Target: {vuln.get('target', 'N/A')}")
                    lines.append(f"   Description: {vuln.get('description', 'N/A')[:100]}...")
                    lines.append("")
                
                for vuln in high_findings[:5]:  # Top 5 high
                    lines.append(f"🟠 HIGH: {vuln.get('title', 'Unknown')}")
                    lines.append(f"   Target: {vuln.get('target', 'N/A')}")
                    lines.append(f"   Description: {vuln.get('description', 'N/A')[:100]}...")
                    lines.append("")
        
        # Subdomains
        if 'subdomains' in data and data['subdomains']:
            lines.append("DISCOVERED SUBDOMAINS")
            lines.append("-" * 40)
            
            # Group by status
            live_subdomains = [s for s in data['subdomains'] if s.get('status_code') and str(s['status_code']).startswith(('2', '3'))]
            dead_subdomains = [s for s in data['subdomains'] if not s.get('status_code') or str(s['status_code']).startswith(('4', '5'))]
            
            lines.append(f"Live Subdomains ({len(live_subdomains)}):")
            for subdomain in live_subdomains[:20]:  # Limit to 20
                ip_info = f" [{subdomain.get('ip_address', 'N/A')}]" if subdomain.get('ip_address') else ""
                status = f" ({subdomain.get('status_code', 'N/A')})" if subdomain.get('status_code') else ""
                lines.append(f"  ✓ {subdomain.get('subdomain', 'N/A')}{ip_info}{status}")
            
            if len(live_subdomains) > 20:
                lines.append(f"  ... and {len(live_subdomains) - 20} more")
            lines.append("")
        
        # Recommendations
        lines.append("RECOMMENDATIONS")
        lines.append("-" * 40)
        recommendations = ReportGenerator._generate_recommendations(data)
        for i, rec in enumerate(recommendations, 1):
            lines.append(f"{i}. {rec}")
        lines.append("")
        
        # Technical Details
        lines.append("TECHNICAL DETAILS")
        lines.append("-" * 40)
        lines.append(f"ReconForge Version: 1.1.0")
        lines.append(f"Scan ID: {data.get('scan_info', {}).get('id', 'N/A')}")
        lines.append(f"Report Format: Plain Text")
        lines.append("="*80)
        
        return "\n".join(lines)
    
    @staticmethod 
    def generate_html_report(data: Dict[str, Any]) -> str:
        """Generate comprehensive HTML report with charts"""
        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ReconForge Security Report - {data.get('scan_info', {}).get('target', 'Unknown')}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.1/font/bootstrap-icons.css">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        .severity-critical {{ background: #dc3545; color: white; }}
        .severity-high {{ background: #fd7e14; color: white; }}
        .severity-medium {{ background: #ffc107; color: black; }}
        .severity-low {{ background: #198754; color: white; }}
        .severity-info {{ background: #0dcaf0; color: black; }}
        .risk-critical {{ color: #dc3545; font-weight: bold; }}
        .risk-high {{ color: #fd7e14; font-weight: bold; }}
        .risk-medium {{ color: #ffc107; font-weight: bold; }}
        .risk-low {{ color: #198754; font-weight: bold; }}
        .chart-container {{ width: 100%; height: 300px; }}
    </style>
</head>
<body>
    <div class="container-fluid py-4">
        <!-- Header -->
        <div class="row mb-4">
            <div class="col-12">
                <div class="card bg-primary text-white">
                    <div class="card-body">
                        <h1 class="card-title"><i class="bi bi-shield-check"></i> ReconForge Security Assessment Report</h1>
                        <p class="card-text">Target: <strong>{data.get('scan_info', {}).get('target', 'Unknown')}</strong></p>
                        <p class="card-text">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                    </div>
                </div>
            </div>
        </div>

        <!-- Executive Summary -->
        <div class="row mb-4">
            <div class="col-12">
                <div class="card">
                    <div class="card-header">
                        <h2 class="card-title mb-0"><i class="bi bi-clipboard-check"></i> Executive Summary</h2>
                    </div>
                    <div class="card-body">
                        {ReportGenerator._generate_executive_summary_html(data)}
                    </div>
                </div>
            </div>
        </div>

        <!-- Statistics Dashboard -->
        <div class="row mb-4">
            <div class="col-md-3 mb-3">
                <div class="card text-center">
                    <div class="card-body">
                        <h3 class="text-primary">{data.get('stats', {}).get('total_subdomains', 0)}</h3>
                        <p class="text-muted">Subdomains</p>
                    </div>
                </div>
            </div>
            <div class="col-md-3 mb-3">
                <div class="card text-center">
                    <div class="card-body">
                        <h3 class="text-danger">{data.get('stats', {}).get('total_vulnerabilities', 0)}</h3>
                        <p class="text-muted">Vulnerabilities</p>
                    </div>
                </div>
            </div>
            <div class="col-md-3 mb-3">
                <div class="card text-center">
                    <div class="card-body">
                        <h3 class="text-info">{data.get('stats', {}).get('total_services', 0)}</h3>
                        <p class="text-muted">Services</p>
                    </div>
                </div>
            </div>
            <div class="col-md-3 mb-3">
                <div class="card text-center">
                    <div class="card-body">
                        <h3 class="text-warning">{ReportGenerator._calculate_risk_score(data)}</h3>
                        <p class="text-muted">Risk Score</p>
                    </div>
                </div>
            </div>
        </div>

        <!-- Charts Row -->
        <div class="row mb-4">
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        <h5>Vulnerability Distribution</h5>
                    </div>
                    <div class="card-body">
                        <canvas id="vulnChart" class="chart-container"></canvas>
                    </div>
                </div>
            </div>
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        <h5>Discovery Sources</h5>
                    </div>
                    <div class="card-body">
                        <canvas id="sourcesChart" class="chart-container"></canvas>
                    </div>
                </div>
            </div>
        </div>

        <!-- Vulnerabilities Table -->
        {ReportGenerator._generate_vulnerabilities_table_html(data)}

        <!-- Subdomains Table -->
        {ReportGenerator._generate_subdomains_table_html(data)}

        <!-- Recommendations -->
        <div class="row mb-4">
            <div class="col-12">
                <div class="card">
                    <div class="card-header">
                        <h2 class="card-title mb-0"><i class="bi bi-lightbulb"></i> Recommendations</h2>
                    </div>
                    <div class="card-body">
                        {ReportGenerator._generate_recommendations_html(data)}
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // Initialize charts
        {ReportGenerator._generate_chart_scripts(data)}
    </script>
</body>
</html>"""
        return html
    
    @staticmethod
    def generate_json_report(data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive JSON report"""
        return {
            "report_metadata": {
                "generated_at": datetime.now().isoformat(),
                "reconforge_version": "1.1.0",
                "report_format": "json",
                "report_type": "comprehensive"
            },
            "scan_info": data.get('scan_info', {}),
            "executive_summary": {
                "risk_score": ReportGenerator._calculate_risk_score(data),
                "risk_level": ReportGenerator._get_risk_level(ReportGenerator._calculate_risk_score(data)),
                "total_findings": len(data.get('vulnerabilities', [])),
                "critical_findings": len([v for v in data.get('vulnerabilities', []) if v.get('severity') == 'critical']),
                "recommendations_count": len(ReportGenerator._generate_recommendations(data))
            },
            "statistics": data.get('stats', {}),
            "vulnerabilities": data.get('vulnerabilities', []),
            "subdomains": data.get('subdomains', []),
            "services": data.get('services', []),
            "pentest_results": data.get('pentest_results', []),
            "recommendations": ReportGenerator._generate_recommendations(data),
            "technical_details": {
                "modules_used": data.get('scan_info', {}).get('modules_used', []),
                "sources_used": data.get('scan_info', {}).get('sources_used', []),
                "scan_duration": data.get('scan_info', {}).get('duration', 0),
                "scan_id": data.get('scan_info', {}).get('id')
            }
        }
    
    @staticmethod
    def generate_xml_report(data: Dict[str, Any]) -> str:
        """Generate XML report compatible with security tools"""
        import xml.etree.ElementTree as ET
        
        root = ET.Element("reconforge_report")
        root.set("version", "1.1.0")
        root.set("generated", datetime.now().isoformat())
        
        # Scan info
        scan_info = ET.SubElement(root, "scan_info")
        scan_data = data.get('scan_info', {})
        for key, value in scan_data.items():
            elem = ET.SubElement(scan_info, key)
            elem.text = str(value)
        
        # Statistics
        stats = ET.SubElement(root, "statistics")
        stats_data = data.get('stats', {})
        for key, value in stats_data.items():
            elem = ET.SubElement(stats, key)
            elem.text = str(value)
        
        # Vulnerabilities
        vulnerabilities = ET.SubElement(root, "vulnerabilities")
        for vuln in data.get('vulnerabilities', []):
            vuln_elem = ET.SubElement(vulnerabilities, "vulnerability")
            for key, value in vuln.items():
                elem = ET.SubElement(vuln_elem, key)
                elem.text = str(value)
        
        # Subdomains
        subdomains = ET.SubElement(root, "subdomains")
        for subdomain in data.get('subdomains', []):
            sub_elem = ET.SubElement(subdomains, "subdomain")
            for key, value in subdomain.items():
                elem = ET.SubElement(sub_elem, key)
                elem.text = str(value)
        
        return ET.tostring(root, encoding='unicode', method='xml')
    
    @staticmethod
    def generate_csv_report(data: Dict[str, Any], report_type: str = 'vulnerabilities') -> str:
        """Generate CSV report for specific data type"""
        import csv
        import io
        
        output = io.StringIO()
        
        if report_type == 'vulnerabilities':
            vulnerabilities = data.get('vulnerabilities', [])
            if vulnerabilities:
                fieldnames = ['title', 'severity', 'target', 'description', 'url', 'cve_id', 'confidence', 'verified']
                writer = csv.DictWriter(output, fieldnames=fieldnames)
                writer.writeheader()
                
                for vuln in vulnerabilities:
                    writer.writerow({
                        'title': vuln.get('title', ''),
                        'severity': vuln.get('severity', ''),
                        'target': vuln.get('target', ''),
                        'description': vuln.get('description', ''),
                        'url': vuln.get('url', ''),
                        'cve_id': vuln.get('cve_id', ''),
                        'confidence': vuln.get('confidence', ''),
                        'verified': vuln.get('verified', '')
                    })
        
        elif report_type == 'subdomains':
            subdomains = data.get('subdomains', [])
            if subdomains:
                fieldnames = ['subdomain', 'ip_address', 'status_code', 'title', 'technologies', 'source']
                writer = csv.DictWriter(output, fieldnames=fieldnames)
                writer.writeheader()
                
                for sub in subdomains:
                    writer.writerow({
                        'subdomain': sub.get('subdomain', ''),
                        'ip_address': sub.get('ip_address', ''),
                        'status_code': sub.get('status_code', ''),
                        'title': sub.get('title', ''),
                        'technologies': ', '.join(sub.get('technologies', [])),
                        'source': sub.get('source', '')
                    })
        
        return output.getvalue()
    
    @staticmethod
    def _calculate_risk_score(data: Dict[str, Any]) -> int:
        """Calculate overall risk score (0-100)"""
        score = 0
        vulnerabilities = data.get('vulnerabilities', [])
        
        # Weight vulnerabilities by severity
        for vuln in vulnerabilities:
            severity = vuln.get('severity', '').lower()
            if severity == 'critical':
                score += 25
            elif severity == 'high':
                score += 15
            elif severity == 'medium':
                score += 8
            elif severity == 'low':
                score += 3
            elif severity == 'info':
                score += 1
        
        # Cap at 100
        return min(score, 100)
    
    @staticmethod
    def _get_risk_level(score: int) -> str:
        """Get risk level based on score"""
        if score >= 80:
            return "CRITICAL"
        elif score >= 60:
            return "HIGH"
        elif score >= 40:
            return "MEDIUM"
        elif score >= 20:
            return "LOW"
        else:
            return "MINIMAL"
    
    @staticmethod
    def _generate_recommendations(data: Dict[str, Any]) -> List[str]:
        """Generate security recommendations based on findings"""
        recommendations = []
        vulnerabilities = data.get('vulnerabilities', [])
        
        # Group vulnerabilities by type
        vuln_types = {}
        for vuln in vulnerabilities:
            vuln_type = vuln.get('vulnerability_type', 'Unknown')
            if vuln_type not in vuln_types:
                vuln_types[vuln_type] = 0
            vuln_types[vuln_type] += 1
        
        # Generate specific recommendations
        if 'SQL Injection' in vuln_types:
            recommendations.append("Implement parameterized queries and input validation to prevent SQL injection attacks")
        
        if 'Cross-Site Scripting' in vuln_types:
            recommendations.append("Apply proper output encoding and Content Security Policy to mitigate XSS vulnerabilities")
        
        if 'Remote Code Execution' in vuln_types:
            recommendations.append("URGENT: Patch RCE vulnerabilities immediately and restrict system command execution")
        
        if 'Server-Side Request Forgery' in vuln_types:
            recommendations.append("Implement URL validation and network segmentation to prevent SSRF attacks")
        
        if 'XML External Entity' in vuln_types:
            recommendations.append("Disable XML external entity processing and validate XML input properly")
        
        # General recommendations
        critical_count = len([v for v in vulnerabilities if v.get('severity') == 'critical'])
        if critical_count > 0:
            recommendations.append("Prioritize remediation of critical vulnerabilities within 24-48 hours")
        
        subdomain_count = len(data.get('subdomains', []))
        if subdomain_count > 50:
            recommendations.append("Review and inventory discovered subdomains for unauthorized or forgotten assets")
        
        # Default recommendations
        if not recommendations:
            recommendations.extend([
                "Implement regular security assessments and penetration testing",
                "Keep all systems and applications up to date with security patches",
                "Deploy Web Application Firewall (WAF) for additional protection",
                "Implement comprehensive logging and monitoring solutions"
            ])
        
        return recommendations
    
    @staticmethod
    def _generate_executive_summary_html(data: Dict[str, Any]) -> str:
        """Generate HTML executive summary"""
        total_vulns = data.get('stats', {}).get('total_vulnerabilities', 0)
        critical_vulns = len([v for v in data.get('vulnerabilities', []) if v.get('severity') == 'critical'])
        high_vulns = len([v for v in data.get('vulnerabilities', []) if v.get('severity') == 'high'])
        risk_score = ReportGenerator._calculate_risk_score(data)
        risk_level = ReportGenerator._get_risk_level(risk_score)
        
        html = f'<div class="alert alert-'
        
        if critical_vulns > 0:
            html += 'danger" role="alert">'
            html += f'<i class="bi bi-exclamation-triangle-fill"></i> <strong>CRITICAL FINDINGS:</strong> '
            html += f'{critical_vulns} critical vulnerabilities require immediate attention.'
        elif high_vulns > 0:
            html += 'warning" role="alert">'
            html += f'<i class="bi bi-exclamation-triangle"></i> <strong>HIGH RISK:</strong> '
            html += f'{high_vulns} high-severity vulnerabilities identified.'
        elif total_vulns > 0:
            html += 'info" role="alert">'
            html += f'<i class="bi bi-info-circle"></i> {total_vulns} vulnerabilities identified with medium/low severity.'
        else:
            html += 'success" role="alert">'
            html += '<i class="bi bi-check-circle"></i> No vulnerabilities were identified during the assessment.'
        
        html += '</div>'
        html += f'<p>Overall Risk Level: <span class="risk-{risk_level.lower()}">{risk_level}</span> (Score: {risk_score}/100)</p>'
        
        return html
    
    @staticmethod
    def _generate_vulnerabilities_table_html(data: Dict[str, Any]) -> str:
        """Generate HTML vulnerabilities table"""
        vulnerabilities = data.get('vulnerabilities', [])
        
        if not vulnerabilities:
            return '<div class="alert alert-success">No vulnerabilities found.</div>'
        
        html = '''
        <div class="row mb-4">
            <div class="col-12">
                <div class="card">
                    <div class="card-header">
                        <h2 class="card-title mb-0"><i class="bi bi-bug"></i> Vulnerabilities</h2>
                    </div>
                    <div class="card-body">
                        <div class="table-responsive">
                            <table class="table table-striped">
                                <thead>
                                    <tr>
                                        <th>Severity</th>
                                        <th>Title</th>
                                        <th>Target</th>
                                        <th>Type</th>
                                        <th>Confidence</th>
                                        <th>CVE</th>
                                    </tr>
                                </thead>
                                <tbody>
        '''
        
        # Sort by severity
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        sorted_vulns = sorted(vulnerabilities, key=lambda x: severity_order.get(x.get('severity', 'info'), 4))
        
        for vuln in sorted_vulns:
            severity = vuln.get('severity', 'info')
            confidence = vuln.get('confidence', 0)
            confidence_percent = int(confidence * 100) if isinstance(confidence, float) else confidence
            
            html += f'''
                    <tr>
                        <td><span class="badge severity-{severity}">{severity.upper()}</span></td>
                        <td>{vuln.get('title', 'Unknown')[:50]}...</td>
                        <td><small>{vuln.get('target', 'N/A')}</small></td>
                        <td>{vuln.get('vulnerability_type', 'Unknown')}</td>
                        <td>{confidence_percent}%</td>
                        <td>{vuln.get('cve_id', 'N/A')}</td>
                    </tr>
            '''
        
        html += '''
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        '''
        
        return html
    
    @staticmethod
    def _generate_subdomains_table_html(data: Dict[str, Any]) -> str:
        """Generate HTML subdomains table"""
        subdomains = data.get('subdomains', [])
        
        if not subdomains:
            return '<div class="alert alert-info">No subdomains discovered.</div>'
        
        html = '''
        <div class="row mb-4">
            <div class="col-12">
                <div class="card">
                    <div class="card-header">
                        <h2 class="card-title mb-0"><i class="bi bi-globe"></i> Discovered Subdomains</h2>
                    </div>
                    <div class="card-body">
                        <div class="table-responsive">
                            <table class="table table-striped">
                                <thead>
                                    <tr>
                                        <th>Subdomain</th>
                                        <th>IP Address</th>
                                        <th>Status</th>
                                        <th>Title</th>
                                        <th>Technologies</th>
                                        <th>Source</th>
                                    </tr>
                                </thead>
                                <tbody>
        '''
        
        for subdomain in subdomains[:50]:  # Limit to 50 for HTML display
            status_code = subdomain.get('status_code', 'N/A')
            status_class = 'success' if str(status_code).startswith(('2', '3')) else 'secondary'
            technologies = ', '.join(subdomain.get('technologies', []))
            
            html += f'''
                    <tr>
                        <td><strong>{subdomain.get('subdomain', 'N/A')}</strong></td>
                        <td><code>{subdomain.get('ip_address', 'N/A')}</code></td>
                        <td><span class="badge bg-{status_class}">{status_code}</span></td>
                        <td>{subdomain.get('title', 'N/A')[:30]}...</td>
                        <td><small>{technologies[:50]}...</small></td>
                        <td>{subdomain.get('source', 'N/A')}</td>
                    </tr>
            '''
        
        if len(subdomains) > 50:
            html += f'<tr><td colspan="6" class="text-center"><em>... and {len(subdomains) - 50} more subdomains</em></td></tr>'
        
        html += '''
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        '''
        
        return html
    
    @staticmethod
    def _generate_recommendations_html(data: Dict[str, Any]) -> str:
        """Generate HTML recommendations"""
        recommendations = ReportGenerator._generate_recommendations(data)
        
        html = '<ol class="list-group list-group-numbered">'
        for rec in recommendations:
            html += f'<li class="list-group-item">{rec}</li>'
        html += '</ol>'
        
        return html
    
    @staticmethod
    def _generate_chart_scripts(data: Dict[str, Any]) -> str:
        """Generate JavaScript for charts"""
        vulnerabilities = data.get('vulnerabilities', [])
        subdomains = data.get('subdomains', [])
        
        # Vulnerability severity distribution
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'info').lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        # Source distribution
        source_counts = {}
        for sub in subdomains:
            source = sub.get('source', 'Unknown')
            source_counts[source] = source_counts.get(source, 0) + 1
        
        js = f'''
        // Vulnerability distribution chart
        const vulnCtx = document.getElementById('vulnChart').getContext('2d');
        new Chart(vulnCtx, {{
            type: 'doughnut',
            data: {{
                labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
                datasets: [{{
                    data: [{severity_counts['critical']}, {severity_counts['high']}, {severity_counts['medium']}, {severity_counts['low']}, {severity_counts['info']}],
                    backgroundColor: ['#dc3545', '#fd7e14', '#ffc107', '#198754', '#0dcaf0']
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{
                    legend: {{
                        position: 'bottom'
                    }}
                }}
            }}
        }});
        
        // Sources distribution chart
        const sourcesCtx = document.getElementById('sourcesChart').getContext('2d');
        new Chart(sourcesCtx, {{
            type: 'bar',
            data: {{
                labels: {list(source_counts.keys())},
                datasets: [{{
                    label: 'Subdomains',
                    data: {list(source_counts.values())},
                    backgroundColor: '#0d6efd'
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{
                    legend: {{
                        display: false
                    }}
                }}
            }}
        }});
        '''
        
        return js
        
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