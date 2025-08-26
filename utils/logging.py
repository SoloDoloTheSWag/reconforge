import logging
import sys
from datetime import datetime
from pathlib import Path
from rich.console import Console
from rich.logging import RichHandler
from rich.theme import Theme
from typing import Optional

# Custom theme for rich console
custom_theme = Theme({
    "info": "cyan",
    "warning": "yellow",
    "error": "bold red",
    "critical": "bold white on red",
    "success": "bold green",
    "debug": "dim blue",
    "highlight": "bold magenta"
})

console = Console(theme=custom_theme)

class ReconForgeLogger:
    """Custom logger for ReconForge with rich formatting and file logging"""
    
    def __init__(self, name: str = "reconforge", log_level: str = "INFO", log_file: Optional[str] = None):
        self.name = name
        self.logger = logging.getLogger(name)
        self.logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))
        
        # Clear existing handlers
        self.logger.handlers.clear()
        
        # Setup console handler with rich formatting
        console_handler = RichHandler(
            console=console,
            show_time=True,
            show_path=True,
            markup=True,
            rich_tracebacks=True
        )
        console_handler.setFormatter(logging.Formatter(
            fmt="%(message)s",
            datefmt="[%X]"
        ))
        self.logger.addHandler(console_handler)
        
        # Setup file handler if specified
        if log_file:
            self.setup_file_logging(log_file)
    
    def setup_file_logging(self, log_file: str):
        """Setup file logging with rotation"""
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        file_handler = logging.FileHandler(log_path, mode='a', encoding='utf-8')
        file_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(file_formatter)
        self.logger.addHandler(file_handler)
    
    def info(self, message: str, **kwargs):
        """Log info message"""
        self.logger.info(f"[info]ℹ️  {message}[/info]", extra=kwargs)
    
    def success(self, message: str, **kwargs):
        """Log success message"""
        self.logger.info(f"[success]✅ {message}[/success]", extra=kwargs)
    
    def warning(self, message: str, **kwargs):
        """Log warning message"""
        self.logger.warning(f"[warning]⚠️  {message}[/warning]", extra=kwargs)
    
    def error(self, message: str, **kwargs):
        """Log error message"""
        self.logger.error(f"[error]❌ {message}[/error]", extra=kwargs)
    
    def critical(self, message: str, **kwargs):
        """Log critical message"""
        self.logger.critical(f"[critical]🚨 {message}[/critical]", extra=kwargs)
    
    def debug(self, message: str, **kwargs):
        """Log debug message"""
        self.logger.debug(f"[debug]🔧 {message}[/debug]", extra=kwargs)
    
    def highlight(self, message: str, **kwargs):
        """Log highlighted message"""
        self.logger.info(f"[highlight]🎯 {message}[/highlight]", extra=kwargs)

class ScanLogger:
    """Specialized logger for scan operations"""
    
    def __init__(self, scan_id: int, target: str, log_dir: str = "logs"):
        self.scan_id = scan_id
        self.target = target
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        # Create scan-specific log file
        log_file = self.log_dir / f"scan_{scan_id}_{target.replace('.', '_')}.log"
        self.logger = ReconForgeLogger(
            name=f"scan_{scan_id}",
            log_file=str(log_file)
        )
        
        self.start_time = datetime.now()
        self.logger.info(f"Starting scan for {target} (ID: {scan_id})")
    
    def log_subdomain_found(self, subdomain: str, source: str, ip: Optional[str] = None):
        """Log discovered subdomain"""
        ip_info = f" [{ip}]" if ip else ""
        self.logger.success(f"Found subdomain: {subdomain}{ip_info} (source: {source})")
    
    def log_vulnerability_found(self, vuln_type: str, severity: str, target: str, details: str = ""):
        """Log discovered vulnerability"""
        severity_emoji = {
            'critical': '🔥',
            'high': '🚨',
            'medium': '⚠️',
            'low': 'ℹ️'
        }.get(severity.lower(), '❓')
        
        self.logger.highlight(f"{severity_emoji} {severity.upper()} {vuln_type} found on {target}")
        if details:
            self.logger.debug(f"Details: {details}")
    
    def log_service_found(self, host: str, port: int, service: str, version: str = ""):
        """Log discovered service"""
        version_info = f" ({version})" if version else ""
        self.logger.info(f"Service found: {host}:{port} - {service}{version_info}")
    
    def log_tool_execution(self, tool_name: str, command: str, success: bool, output: str = ""):
        """Log tool execution"""
        status = "✅" if success else "❌"
        self.logger.debug(f"{status} {tool_name}: {command}")
        if not success and output:
            self.logger.error(f"Tool failed with output: {output[:500]}...")
    
    def log_scan_complete(self, stats: dict):
        """Log scan completion with statistics"""
        duration = datetime.now() - self.start_time
        
        self.logger.success("Scan completed!")
        self.logger.info(f"Duration: {duration}")
        self.logger.info(f"Subdomains found: {stats.get('subdomains', 0)}")
        self.logger.info(f"Vulnerabilities found: {stats.get('vulnerabilities', 0)}")
        self.logger.info(f"Services discovered: {stats.get('services', 0)}")
    
    def log_pentest_result(self, test_type: str, target: str, success: bool, details: str = ""):
        """Log penetration test result"""
        status = "✅ SUCCESS" if success else "❌ FAILED"
        self.logger.highlight(f"Pentest {test_type} on {target}: {status}")
        if details:
            self.logger.debug(f"Details: {details}")

# Global logger instances
main_logger = ReconForgeLogger("reconforge", log_file="logs/reconforge.log")
web_logger = ReconForgeLogger("web", log_file="logs/web.log")

def get_scan_logger(scan_id: int, target: str) -> ScanLogger:
    """Get a scan-specific logger"""
    return ScanLogger(scan_id, target)

def setup_logging(level: str = "INFO", log_file: Optional[str] = None) -> ReconForgeLogger:
    """Setup logging configuration"""
    return ReconForgeLogger("reconforge", level, log_file)