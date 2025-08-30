#!/usr/bin/env python3
"""
ReconForge Common Utilities Module
Terminal-First Professional Reconnaissance Platform

This module provides common utilities for security validation, tool management,
domain validation, and file operations used throughout the ReconForge platform.
"""

import os
import re
import sys
import json
import shlex
import hashlib
import ipaddress
import subprocess
import time
import threading
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple, Union, Set
from dataclasses import dataclass
from urllib.parse import urlparse
from datetime import datetime, timezone

from .logger import ReconForgeLogger


@dataclass
class ToolInfo:
    """Information about a security tool"""
    name: str
    command: str
    path: Optional[str] = None
    version: Optional[str] = None
    available: bool = False
    required_args: Optional[List[str]] = None
    description: Optional[str] = None


@dataclass
class ValidationResult:
    """Result of input validation"""
    valid: bool
    sanitized: Optional[str] = None
    errors: List[str] = None
    warnings: List[str] = None

    def __post_init__(self):
        if self.errors is None:
            self.errors = []
        if self.warnings is None:
            self.warnings = []


class SecurityValidator:
    """Handles security validation and sanitization"""
    
    # Dangerous characters that should be blocked in command injection
    DANGEROUS_CHARS = [';', '|', '&', '$', '`', '(', ')', '{', '}', '[', ']', '<', '>', '"', "'", '\\']
    
    # Allowed characters for different input types
    DOMAIN_PATTERN = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$')
    IP_PATTERN = re.compile(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')
    URL_PATTERN = re.compile(r'^https?://[^\s/$.?#].[^\s]*$', re.IGNORECASE)
    FILENAME_PATTERN = re.compile(r'^[a-zA-Z0-9_.-]+$')
    
    def __init__(self, logger: ReconForgeLogger):
        self.logger = logger
    
    def validate_domain(self, domain: str) -> ValidationResult:
        """Validate and sanitize domain names"""
        if not domain:
            return ValidationResult(valid=False, errors=["Domain cannot be empty"])
        
        # Remove protocol if present
        domain = domain.strip()
        if domain.startswith(('http://', 'https://')):
            parsed = urlparse(domain)
            domain = parsed.netloc or parsed.path
        
        # Remove port if present
        domain = domain.split(':')[0]
        
        # Check length
        if len(domain) > 253:
            return ValidationResult(valid=False, errors=["Domain name too long (max 253 characters)"])
        
        # Check format
        if not self.DOMAIN_PATTERN.match(domain):
            return ValidationResult(valid=False, errors=["Invalid domain format"])
        
        # Check for dangerous characters
        if any(char in domain for char in self.DANGEROUS_CHARS):
            return ValidationResult(valid=False, errors=["Domain contains dangerous characters"])
        
        return ValidationResult(valid=True, sanitized=domain.lower())
    
    def validate_ip_address(self, ip: str) -> ValidationResult:
        """Validate IP addresses"""
        if not ip:
            return ValidationResult(valid=False, errors=["IP address cannot be empty"])
        
        try:
            # Try to parse as IP address
            addr = ipaddress.ip_address(ip.strip())
            
            # Check for private/reserved addresses
            warnings = []
            if addr.is_private:
                warnings.append("IP address is in private range")
            if addr.is_reserved:
                warnings.append("IP address is in reserved range")
            if addr.is_loopback:
                warnings.append("IP address is loopback")
            
            return ValidationResult(valid=True, sanitized=str(addr), warnings=warnings)
        
        except ValueError as e:
            return ValidationResult(valid=False, errors=[f"Invalid IP address: {str(e)}"])
    
    def validate_url(self, url: str) -> ValidationResult:
        """Validate URLs"""
        if not url:
            return ValidationResult(valid=False, errors=["URL cannot be empty"])
        
        url = url.strip()
        
        # Check basic format
        if not self.URL_PATTERN.match(url):
            return ValidationResult(valid=False, errors=["Invalid URL format"])
        
        try:
            parsed = urlparse(url)
            
            # Validate scheme
            if parsed.scheme not in ('http', 'https'):
                return ValidationResult(valid=False, errors=["Only HTTP/HTTPS URLs allowed"])
            
            # Validate hostname
            if parsed.hostname:
                domain_result = self.validate_domain(parsed.hostname)
                if not domain_result.valid:
                    return ValidationResult(valid=False, errors=domain_result.errors)
            
            return ValidationResult(valid=True, sanitized=url)
        
        except Exception as e:
            return ValidationResult(valid=False, errors=[f"URL validation error: {str(e)}"])
    
    def validate_filename(self, filename: str) -> ValidationResult:
        """Validate filenames for security"""
        if not filename:
            return ValidationResult(valid=False, errors=["Filename cannot be empty"])
        
        filename = filename.strip()
        
        # Check for dangerous patterns
        if filename in ('.', '..'):
            return ValidationResult(valid=False, errors=["Invalid filename"])
        
        if filename.startswith('.'):
            return ValidationResult(valid=False, warnings=["Hidden files may not be intended"])
        
        # Check for dangerous characters
        if not self.FILENAME_PATTERN.match(filename):
            return ValidationResult(valid=False, errors=["Filename contains invalid characters"])
        
        # Check length
        if len(filename) > 255:
            return ValidationResult(valid=False, errors=["Filename too long"])
        
        return ValidationResult(valid=True, sanitized=filename)
    
    def sanitize_command_arg(self, arg: str) -> ValidationResult:
        """Sanitize command line arguments"""
        if not arg:
            return ValidationResult(valid=True, sanitized="")
        
        # Check for command injection patterns
        if any(char in arg for char in self.DANGEROUS_CHARS):
            return ValidationResult(valid=False, errors=["Argument contains dangerous characters"])
        
        # Use shell escaping
        sanitized = shlex.quote(str(arg))
        return ValidationResult(valid=True, sanitized=sanitized)
    
    def validate_port_range(self, port_range: str) -> ValidationResult:
        """Validate port ranges for scanning"""
        if not port_range:
            return ValidationResult(valid=False, errors=["Port range cannot be empty"])
        
        port_range = port_range.strip()
        
        try:
            # Handle single port
            if '-' not in port_range:
                port = int(port_range)
                if 1 <= port <= 65535:
                    return ValidationResult(valid=True, sanitized=str(port))
                else:
                    return ValidationResult(valid=False, errors=["Port must be between 1-65535"])
            
            # Handle port range
            start, end = port_range.split('-', 1)
            start_port = int(start.strip())
            end_port = int(end.strip())
            
            if not (1 <= start_port <= 65535 and 1 <= end_port <= 65535):
                return ValidationResult(valid=False, errors=["Ports must be between 1-65535"])
            
            if start_port > end_port:
                return ValidationResult(valid=False, errors=["Invalid port range: start > end"])
            
            # Limit range size for safety
            if (end_port - start_port) > 10000:
                return ValidationResult(valid=False, warnings=["Large port ranges may impact performance"])
            
            return ValidationResult(valid=True, sanitized=f"{start_port}-{end_port}")
            
        except ValueError:
            return ValidationResult(valid=False, errors=["Invalid port format"])


class RateLimiter:
    """Simple rate limiter for API calls and tool executions"""
    
    def __init__(self, logger: ReconForgeLogger):
        self.logger = logger
        self.call_times = {}
        self.call_counts = {}
        self.lock = threading.Lock()
    
    def check_rate_limit(self, operation: str, max_calls: int = 10, time_window: int = 60) -> bool:
        """Check if operation is within rate limits"""
        current_time = time.time()
        
        with self.lock:
            if operation not in self.call_times:
                self.call_times[operation] = []
                self.call_counts[operation] = 0
            
            # Remove old calls outside time window
            self.call_times[operation] = [
                t for t in self.call_times[operation] 
                if current_time - t < time_window
            ]
            
            # Check if we're at the limit
            if len(self.call_times[operation]) >= max_calls:
                self.logger.log_security_event(
                    f"Rate limit exceeded for {operation}: {len(self.call_times[operation])}/{max_calls} calls in {time_window}s"
                )
                return False
            
            # Record this call
            self.call_times[operation].append(current_time)
            self.call_counts[operation] += 1
            return True
    
    def get_stats(self) -> Dict[str, Any]:
        """Get rate limiting statistics"""
        current_time = time.time()
        stats = {}
        
        with self.lock:
            for operation in self.call_times:
                recent_calls = [
                    t for t in self.call_times[operation] 
                    if current_time - t < 60
                ]
                stats[operation] = {
                    'total_calls': self.call_counts[operation],
                    'recent_calls': len(recent_calls),
                    'last_call': max(self.call_times[operation]) if self.call_times[operation] else None
                }
        
        return stats


class ToolManager:
    """Manages security tools and their availability"""
    
    # Core security tools used by ReconForge
    TOOLS_CONFIG = {
        'subfinder': {
            'command': 'subfinder',
            'description': 'Fast passive subdomain enumeration',
            'test_args': ['-version']
        },
        'assetfinder': {
            'command': 'assetfinder',
            'description': 'Subdomain discovery tool',
            'test_args': ['--help']
        },
        'amass': {
            'command': 'amass',
            'description': 'Network mapping of attack surfaces',
            'test_args': ['enum', '-version']
        },
        'nuclei': {
            'command': 'nuclei',
            'description': 'Vulnerability scanner based on templates',
            'test_args': ['-version']
        },
        'httpx': {
            'command': 'httpx',
            'description': 'Fast HTTP prober',
            'test_args': ['-version']
        },
        'nmap': {
            'command': 'nmap',
            'description': 'Network mapper and port scanner',
            'test_args': ['--version']
        },
        'gobuster': {
            'command': 'gobuster',
            'description': 'Directory and file brute forcer',
            'test_args': ['version']
        },
        'sqlmap': {
            'command': 'sqlmap',
            'description': 'SQL injection testing tool',
            'test_args': ['--version']
        },
        'masscan': {
            'command': 'masscan',
            'description': 'Fast port scanner',
            'test_args': ['--version']
        },
        'ffuf': {
            'command': 'ffuf',
            'description': 'Fast web fuzzer',
            'test_args': ['-V']
        },
        'waybackurls': {
            'command': 'waybackurls',
            'description': 'Fetch URLs from Wayback Machine',
            'test_args': ['-h']
        },
        'gau': {
            'command': 'gau',
            'description': 'Get All URLs from various sources',
            'test_args': ['-version']
        },
        'dnsx': {
            'command': 'dnsx',
            'description': 'Fast DNS toolkit',
            'test_args': ['-version']
        },
        'subzy': {
            'command': 'subzy',
            'description': 'Subdomain takeover checker',
            'test_args': ['-version']
        },
        'chaos': {
            'command': 'chaos',
            'description': 'Subdomain discovery via Chaos API',
            'test_args': ['-version']
        }
    }
    
    def __init__(self, logger: ReconForgeLogger):
        self.logger = logger
        self.tools: Dict[str, ToolInfo] = {}
        self._scan_tools()
    
    def _scan_tools(self):
        """Scan system for available tools"""
        self.logger.log_system("Starting tool availability scan")
        
        for tool_name, config in self.TOOLS_CONFIG.items():
            tool_info = ToolInfo(
                name=tool_name,
                command=config['command'],
                description=config.get('description', ''),
                required_args=config.get('test_args', [])
            )
            
            # Check if tool is available in PATH
            tool_path = self._find_tool_path(config['command'])
            if tool_path:
                tool_info.path = tool_path
                tool_info.available = True
                
                # Try to get version
                version = self._get_tool_version(config['command'], config.get('test_args', []))
                if version:
                    tool_info.version = version
                
                self.logger.log_system(f"Tool {tool_name} found at {tool_path}")
            else:
                self.logger.log_system(f"Tool {tool_name} not found in PATH")
            
            self.tools[tool_name] = tool_info
        
        available_count = sum(1 for tool in self.tools.values() if tool.available)
        self.logger.log_system(f"Tool scan complete: {available_count}/{len(self.tools)} tools available")
    
    def _find_tool_path(self, command: str) -> Optional[str]:
        """Find tool path in system PATH"""
        try:
            result = subprocess.run(['which', command], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                return result.stdout.strip()
        except (subprocess.TimeoutExpired, subprocess.SubprocessError):
            pass
        return None
    
    def _get_tool_version(self, command: str, test_args: List[str]) -> Optional[str]:
        """Get tool version information"""
        try:
            cmd = [command] + test_args
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            # Tool version might be in stdout or stderr
            output = (result.stdout + result.stderr).strip()
            if output:
                # Extract version from output
                lines = output.split('\n')
                for line in lines:
                    if any(keyword in line.lower() for keyword in ['version', 'v']):
                        return line.strip()
                
                # If no version line found, return first line
                return lines[0].strip() if lines else None
        
        except (subprocess.TimeoutExpired, subprocess.SubprocessError):
            pass
        return None
    
    def is_tool_available(self, tool_name: str) -> bool:
        """Check if a tool is available"""
        return tool_name in self.tools and self.tools[tool_name].available
    
    def get_tool_info(self, tool_name: str) -> Optional[ToolInfo]:
        """Get information about a tool"""
        return self.tools.get(tool_name)
    
    def get_available_tools(self) -> List[ToolInfo]:
        """Get list of all available tools"""
        return [tool for tool in self.tools.values() if tool.available]
    
    def get_missing_tools(self) -> List[ToolInfo]:
        """Get list of missing tools"""
        return [tool for tool in self.tools.values() if not tool.available]
    
    def refresh_tool_availability(self):
        """Refresh tool availability scan"""
        self.logger.log_system("Refreshing tool availability")
        self._scan_tools()


class FileOperations:
    """Handles secure file operations"""
    
    def __init__(self, logger: ReconForgeLogger):
        self.logger = logger
        self.validator = SecurityValidator(logger)
    
    def create_directory(self, path: Union[str, Path], mode: int = 0o755) -> bool:
        """Create directory securely"""
        try:
            path = Path(path)
            
            # Validate path
            if self._is_dangerous_path(path):
                self.logger.log_security(f"Rejected dangerous directory path: {path}")
                return False
            
            path.mkdir(parents=True, exist_ok=True, mode=mode)
            self.logger.log_system(f"Created directory: {path}")
            return True
        
        except Exception as e:
            self.logger.log_error(f"Failed to create directory {path}: {str(e)}")
            return False
    
    def write_file(self, path: Union[str, Path], content: str, mode: int = 0o644) -> bool:
        """Write file securely"""
        try:
            path = Path(path)
            
            # Validate path
            if self._is_dangerous_path(path):
                self.logger.log_security(f"Rejected dangerous file path: {path}")
                return False
            
            # Create parent directory if needed
            path.parent.mkdir(parents=True, exist_ok=True)
            
            # Write file
            path.write_text(content, encoding='utf-8')
            path.chmod(mode)
            
            self.logger.log_system(f"Wrote file: {path} ({len(content)} bytes)")
            return True
        
        except Exception as e:
            self.logger.log_error(f"Failed to write file {path}: {str(e)}")
            return False
    
    def read_file(self, path: Union[str, Path]) -> Optional[str]:
        """Read file securely"""
        try:
            path = Path(path)
            
            # Validate path
            if self._is_dangerous_path(path):
                self.logger.log_security(f"Rejected dangerous file path: {path}")
                return None
            
            if not path.exists():
                self.logger.log_error(f"File does not exist: {path}")
                return None
            
            content = path.read_text(encoding='utf-8')
            self.logger.log_system(f"Read file: {path} ({len(content)} bytes)")
            return content
        
        except Exception as e:
            self.logger.log_error(f"Failed to read file {path}: {str(e)}")
            return None
    
    def delete_file(self, path: Union[str, Path]) -> bool:
        """Delete file securely"""
        try:
            path = Path(path)
            
            # Validate path
            if self._is_dangerous_path(path):
                self.logger.log_security(f"Rejected dangerous file path: {path}")
                return False
            
            if path.exists():
                path.unlink()
                self.logger.log_system(f"Deleted file: {path}")
                return True
            
            return False
        
        except Exception as e:
            self.logger.log_error(f"Failed to delete file {path}: {str(e)}")
            return False
    
    def get_file_hash(self, path: Union[str, Path]) -> Optional[str]:
        """Get SHA256 hash of file"""
        try:
            path = Path(path)
            
            if not path.exists():
                return None
            
            with open(path, 'rb') as f:
                content = f.read()
                return hashlib.sha256(content).hexdigest()
        
        except Exception as e:
            self.logger.log_error(f"Failed to hash file {path}: {str(e)}")
            return None
    
    def _is_dangerous_path(self, path: Path) -> bool:
        """Check if path is potentially dangerous"""
        try:
            # Resolve to absolute path
            abs_path = path.resolve()
            
            # Check for path traversal
            if '..' in str(path):
                return True
            
            # Check for system directories
            dangerous_dirs = [
                '/bin', '/sbin', '/usr/bin', '/usr/sbin',
                '/etc', '/proc', '/sys', '/dev',
                '/boot', '/root'
            ]
            
            for dangerous in dangerous_dirs:
                if str(abs_path).startswith(dangerous):
                    return True
            
            return False
        
        except Exception:
            # If we can't validate, assume dangerous
            return True


class ReconForgeUtils:
    """Main utilities class - aggregates all utility functions"""
    
    def __init__(self, logger: ReconForgeLogger):
        self.logger = logger
        self.validator = SecurityValidator(logger)
        self.tool_manager = ToolManager(logger)
        self.file_ops = FileOperations(logger)
        self.rate_limiter = RateLimiter(logger)
    
    def format_bytes(self, bytes_count: int) -> str:
        """Format byte count to human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_count < 1024.0:
                return f"{bytes_count:.1f} {unit}"
            bytes_count /= 1024.0
        return f"{bytes_count:.1f} PB"
    
    def format_duration(self, seconds: float) -> str:
        """Format duration in seconds to human readable format"""
        if seconds < 1:
            return f"{seconds*1000:.0f}ms"
        elif seconds < 60:
            return f"{seconds:.1f}s"
        elif seconds < 3600:
            minutes = int(seconds // 60)
            secs = int(seconds % 60)
            return f"{minutes}m {secs}s"
        else:
            hours = int(seconds // 3600)
            minutes = int((seconds % 3600) // 60)
            return f"{hours}h {minutes}m"
    
    def get_timestamp(self) -> str:
        """Get current timestamp in ISO format"""
        return datetime.now(timezone.utc).isoformat()
    
    def parse_comma_separated(self, value: str) -> List[str]:
        """Parse comma-separated values safely"""
        if not value:
            return []
        
        items = []
        for item in value.split(','):
            item = item.strip()
            if item:
                items.append(item)
        
        return items
    
    def merge_dictionaries(self, *dicts: Dict[str, Any]) -> Dict[str, Any]:
        """Merge multiple dictionaries safely"""
        result = {}
        for d in dicts:
            if isinstance(d, dict):
                result.update(d)
        return result
    
    def safe_json_loads(self, json_str: str) -> Optional[Dict[str, Any]]:
        """Safely parse JSON string"""
        try:
            return json.loads(json_str)
        except (json.JSONDecodeError, TypeError):
            return None
    
    def safe_json_dumps(self, data: Any, indent: int = 2) -> str:
        """Safely serialize to JSON string"""
        try:
            return json.dumps(data, indent=indent, default=str, ensure_ascii=False)
        except (TypeError, ValueError):
            return "{}"
    
    def extract_domains_from_text(self, text: str) -> Set[str]:
        """Extract potential domains from text"""
        domains = set()
        
        # Domain pattern
        domain_pattern = r'\b([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
        
        for match in re.finditer(domain_pattern, text):
            domain = match.group().lower()
            validation = self.validator.validate_domain(domain)
            if validation.valid:
                domains.add(validation.sanitized)
        
        return domains
    
    def extract_ips_from_text(self, text: str) -> Set[str]:
        """Extract IP addresses from text"""
        ips = set()
        
        # IP pattern
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        
        for match in re.finditer(ip_pattern, text):
            ip = match.group()
            validation = self.validator.validate_ip_address(ip)
            if validation.valid:
                ips.add(validation.sanitized)
        
        return ips
    
    def generate_session_id(self) -> str:
        """Generate unique session ID"""
        timestamp = str(int(datetime.now(timezone.utc).timestamp()))
        random_data = os.urandom(16)
        combined = f"{timestamp}{random_data.hex()}"
        return hashlib.sha256(combined.encode()).hexdigest()[:16]
    
    def is_port_valid(self, port: Union[int, str]) -> bool:
        """Check if port number is valid"""
        try:
            port_num = int(port)
            return 1 <= port_num <= 65535
        except (ValueError, TypeError):
            return False
    
    def get_system_info(self) -> Dict[str, str]:
        """Get basic system information"""
        return {
            'platform': sys.platform,
            'python_version': sys.version.split()[0],
            'working_directory': os.getcwd(),
            'user': os.getenv('USER', 'unknown'),
            'home': os.getenv('HOME', '/tmp'),
            'path_separator': os.pathsep,
            'timestamp': self.get_timestamp()
        }