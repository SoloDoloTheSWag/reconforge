#!/usr/bin/env python3
"""
ReconForge Metasploit Integration Module
Terminal-First Professional Reconnaissance Platform

Secure integration with Metasploit Framework for authorized penetration testing.
Includes safety controls, payload generation, and exploitation capabilities.
"""

import os
import re
import json
import subprocess
import tempfile
from typing import List, Dict, Set, Optional, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from enum import Enum
import xml.etree.ElementTree as ET

# Import core modules
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.logger import ReconForgeLogger
from core.database import ReconForgeDatabase
from core.utils import ReconForgeUtils, ValidationResult
from interface.display import ReconForgeDisplay, StatusType


class PayloadCategory(Enum):
    """Metasploit payload categories"""
    SINGLE = "singles"
    STAGER = "stagers"
    STAGE = "stages"


class ExploitCategory(Enum):
    """Metasploit exploit categories"""
    AUXILIARY = "auxiliary"
    EXPLOIT = "exploit"
    POST = "post"
    ENCODER = "encoder"
    NOP = "nop"


class SafetyLevel(Enum):
    """Safety levels for Metasploit operations"""
    SAFE = "safe"           # Only safe auxiliary modules
    MODERATE = "moderate"   # Include some exploitation
    AGGRESSIVE = "aggressive"  # Full exploitation capabilities


@dataclass
class MetasploitPayload:
    """Metasploit payload information"""
    name: str
    category: PayloadCategory
    platform: str
    arch: str
    size: Optional[int] = None
    description: Optional[str] = None
    options: Dict[str, str] = field(default_factory=dict)
    requirements: List[str] = field(default_factory=list)


@dataclass
class MetasploitExploit:
    """Metasploit exploit information"""
    name: str
    category: ExploitCategory
    targets: List[str] = field(default_factory=list)
    platform: List[str] = field(default_factory=list)
    description: Optional[str] = None
    rank: Optional[str] = None
    disclosure_date: Optional[str] = None
    options: Dict[str, str] = field(default_factory=dict)


@dataclass
class MetasploitConfig:
    """Configuration for Metasploit operations"""
    targets: List[str]
    scan_id: str
    safety_level: SafetyLevel = SafetyLevel.SAFE
    workspace: Optional[str] = None
    db_connect: bool = True
    timeout: int = 300  # 5 minutes
    max_concurrent: int = 3
    auto_cleanup: bool = True
    require_authorization: bool = True
    allowed_modules: List[str] = field(default_factory=list)
    forbidden_modules: List[str] = field(default_factory=list)
    custom_payloads: List[str] = field(default_factory=list)


class MetasploitIntegration:
    """Main Metasploit Framework integration"""
    
    def __init__(self, logger: ReconForgeLogger, database: ReconForgeDatabase, 
                 utils: ReconForgeUtils, display: ReconForgeDisplay):
        """Initialize Metasploit integration"""
        self.logger = logger
        self.database = database
        self.utils = utils
        self.display = display
        
        # Metasploit paths and configuration
        self.msfconsole_path = None
        self.msfvenom_path = None
        self.msf_db_path = None
        
        # Safety and control
        self.safety_enabled = True
        self.require_confirmation = True
        
        # Initialize Metasploit environment
        self._initialize_metasploit()
        
        # Safety controls
        self.safe_auxiliary_modules = [
            'auxiliary/scanner/portscan/tcp',
            'auxiliary/scanner/http/http_version',
            'auxiliary/scanner/smb/smb_version',
            'auxiliary/scanner/ssh/ssh_version',
            'auxiliary/gather/enum_dns',
            'auxiliary/scanner/discovery/udp_sweep',
            'auxiliary/scanner/http/dir_scanner',
            'auxiliary/scanner/http/files_dir',
            'auxiliary/scanner/ssl/openssl_heartbleed'
        ]
        
        self.forbidden_modules = [
            'exploit/windows/smb/ms17_010_eternalblue',  # Too dangerous for default use
            'exploit/multi/handler',  # Requires careful handling
            'auxiliary/dos/',  # DoS attacks forbidden by default
            'auxiliary/scanner/smb/smb_login',  # Brute force attacks
        ]
    
    def _initialize_metasploit(self) -> bool:
        """Initialize Metasploit Framework"""
        try:
            # Check for Metasploit installation
            self.msfconsole_path = self._find_msf_binary('msfconsole')
            self.msfvenom_path = self._find_msf_binary('msfvenom')
            
            if not self.msfconsole_path or not self.msfvenom_path:
                self.logger.log_error("Metasploit Framework not found", None)
                return False
            
            # Test Metasploit functionality
            if not self._test_metasploit():
                self.logger.log_error("Metasploit Framework test failed", None)
                return False
            
            self.logger.log_system("Metasploit Framework initialized successfully")
            return True
            
        except Exception as e:
            self.logger.log_error(f"Metasploit initialization failed: {str(e)}", e)
            return False
    
    def _find_msf_binary(self, binary_name: str) -> Optional[str]:
        """Find Metasploit binary path"""
        try:
            result = subprocess.run(['which', binary_name], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                return result.stdout.strip()
            return None
        except Exception:
            return None
    
    def _test_metasploit(self) -> bool:
        """Test Metasploit functionality"""
        try:
            # Test msfconsole
            cmd = [self.msfconsole_path, '-q', '-x', 'version;exit']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode != 0:
                return False
                
            # Test msfvenom
            cmd = [self.msfvenom_path, '--help-formats']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            return result.returncode == 0
            
        except Exception as e:
            self.logger.log_error(f"Metasploit test failed: {str(e)}", e)
            return False
    
    def is_available(self) -> bool:
        """Check if Metasploit is available"""
        return self.msfconsole_path is not None and self.msfvenom_path is not None
    
    def get_version_info(self) -> Dict[str, str]:
        """Get Metasploit version information"""
        try:
            cmd = [self.msfconsole_path, '-q', '-x', 'version;exit']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                version_info = {}
                for line in result.stdout.split('\n'):
                    if 'Framework:' in line:
                        version_info['framework'] = line.split(':', 1)[1].strip()
                    elif 'Console:' in line:
                        version_info['console'] = line.split(':', 1)[1].strip()
                return version_info
                
            return {"error": "Could not get version information"}
            
        except Exception as e:
            return {"error": str(e)}
    
    def list_safe_modules(self) -> List[str]:
        """List safe auxiliary modules for reconnaissance"""
        return self.safe_auxiliary_modules.copy()
    
    def run_auxiliary_scan(self, config: MetasploitConfig, module_name: str, 
                          options: Dict[str, str]) -> Dict[str, Any]:
        """Run a safe auxiliary scan"""
        try:
            # Safety check
            if not self._is_module_safe(module_name):
                raise ValueError(f"Module {module_name} is not in the safe list")
            
            if config.safety_level == SafetyLevel.SAFE and module_name not in self.safe_auxiliary_modules:
                raise ValueError(f"Module {module_name} not allowed at SAFE level")
            
            self.display.print_status(f"Running Metasploit auxiliary: {module_name}", StatusType.RUNNING)
            
            # Build Metasploit command
            commands = [
                f"use {module_name}",
            ]
            
            # Set options
            for key, value in options.items():
                commands.append(f"set {key} {value}")
            
            # Add safety options
            commands.extend([
                "set VERBOSE true",
                "run",
                "exit"
            ])
            
            # Execute
            cmd_string = ';'.join(commands)
            cmd = [self.msfconsole_path, '-q', '-x', cmd_string]
            
            result = subprocess.run(cmd, capture_output=True, text=True, 
                                  timeout=config.timeout)
            
            # Parse results
            scan_result = {
                'success': result.returncode == 0,
                'module': module_name,
                'options': options,
                'output': result.stdout,
                'errors': result.stderr,
                'targets': config.targets,
                'scan_id': config.scan_id,
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
            
            if result.returncode == 0:
                self.display.print_status(f"Metasploit scan completed: {module_name}", StatusType.SUCCESS)
            else:
                self.display.print_status(f"Metasploit scan failed: {module_name}", StatusType.ERROR)
            
            return scan_result
            
        except Exception as e:
            self.logger.log_error(f"Metasploit auxiliary scan failed: {str(e)}", e)
            return {
                'success': False,
                'error': str(e),
                'module': module_name,
                'scan_id': config.scan_id
            }
    
    def generate_payload(self, payload_name: str, options: Dict[str, str], 
                        output_format: str = 'raw') -> Dict[str, Any]:
        """Generate payload using msfvenom"""
        try:
            # Safety check for payload
            if not self._is_payload_safe(payload_name):
                raise ValueError(f"Payload {payload_name} is not permitted")
            
            self.display.print_status(f"Generating Metasploit payload: {payload_name}", StatusType.RUNNING)
            
            # Build msfvenom command
            cmd = [self.msfvenom_path, '-p', payload_name]
            
            # Add options
            for key, value in options.items():
                cmd.extend([f"{key}={value}"])
            
            # Set output format
            cmd.extend(['-f', output_format])
            
            # Execute
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            payload_result = {
                'success': result.returncode == 0,
                'payload': payload_name,
                'format': output_format,
                'options': options,
                'output': result.stdout if result.returncode == 0 else None,
                'errors': result.stderr,
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
            
            if result.returncode == 0:
                self.display.print_status("Payload generated successfully", StatusType.SUCCESS)
            else:
                self.display.print_status("Payload generation failed", StatusType.ERROR)
            
            return payload_result
            
        except Exception as e:
            self.logger.log_error(f"Payload generation failed: {str(e)}", e)
            return {
                'success': False,
                'error': str(e),
                'payload': payload_name
            }
    
    def _is_module_safe(self, module_name: str) -> bool:
        """Check if a module is safe to use"""
        # Check forbidden modules
        for forbidden in self.forbidden_modules:
            if forbidden in module_name:
                return False
        
        # For now, only allow auxiliary modules in safe mode
        if self.safety_enabled:
            return module_name.startswith('auxiliary/scanner/') or module_name in self.safe_auxiliary_modules
        
        return True
    
    def _is_payload_safe(self, payload_name: str) -> bool:
        """Check if a payload is safe to generate"""
        # Only allow reverse shell payloads for testing
        safe_payloads = [
            'generic/shell_reverse_tcp',
            'generic/shell_bind_tcp',
            'linux/x86/shell_reverse_tcp',
            'linux/x64/shell_reverse_tcp',
            'windows/shell_reverse_tcp',
            'windows/x64/shell_reverse_tcp'
        ]
        
        if self.safety_enabled:
            return any(safe in payload_name for safe in safe_payloads)
        
        return True
    
    def run_port_scan(self, targets: List[str], ports: str = "1-1000") -> Dict[str, Any]:
        """Run Metasploit TCP port scan"""
        config = MetasploitConfig(targets=targets, scan_id=f"msf_scan_{int(datetime.now().timestamp())}")
        
        for target in targets:
            options = {
                'RHOSTS': target,
                'PORTS': ports,
                'THREADS': '10'
            }
            
            result = self.run_auxiliary_scan(config, 'auxiliary/scanner/portscan/tcp', options)
            return result
    
    def run_http_version_scan(self, targets: List[str]) -> Dict[str, Any]:
        """Run HTTP version detection"""
        config = MetasploitConfig(targets=targets, scan_id=f"msf_http_{int(datetime.now().timestamp())}")
        
        for target in targets:
            # Extract hostname from URL if needed
            if target.startswith('http'):
                from urllib.parse import urlparse
                parsed = urlparse(target)
                hostname = parsed.hostname
                port = parsed.port or (443 if parsed.scheme == 'https' else 80)
            else:
                hostname = target
                port = 80
            
            options = {
                'RHOSTS': hostname,
                'RPORT': str(port),
                'THREADS': '5'
            }
            
            result = self.run_auxiliary_scan(config, 'auxiliary/scanner/http/http_version', options)
            return result


# Factory functions
def create_metasploit_integration(logger: ReconForgeLogger, database: ReconForgeDatabase,
                                utils: ReconForgeUtils, display: ReconForgeDisplay) -> MetasploitIntegration:
    """Create Metasploit integration instance"""
    return MetasploitIntegration(logger, database, utils, display)


def create_metasploit_config(targets: List[str], scan_id: str, **kwargs) -> MetasploitConfig:
    """Create Metasploit configuration with defaults"""
    return MetasploitConfig(targets=targets, scan_id=scan_id, **kwargs)


# Safety validation function
def validate_metasploit_safety(module_name: str, payload_name: Optional[str] = None) -> bool:
    """Validate that Metasploit operations are safe for authorized testing"""
    msf = MetasploitIntegration(None, None, None, None)
    
    if module_name and not msf._is_module_safe(module_name):
        return False
        
    if payload_name and not msf._is_payload_safe(payload_name):
        return False
        
    return True


if __name__ == "__main__":
    # Test Metasploit integration
    from core.logger import ReconForgeLogger
    from core.database import ReconForgeDatabase
    from core.utils import ReconForgeUtils
    from interface.display import ReconForgeDisplay
    
    logger = ReconForgeLogger()
    database = ReconForgeDatabase()
    utils = ReconForgeUtils(logger)
    display = ReconForgeDisplay()
    
    msf = create_metasploit_integration(logger, database, utils, display)
    
    print(f"Metasploit available: {msf.is_available()}")
    print(f"Version info: {msf.get_version_info()}")
    print(f"Safe modules: {len(msf.list_safe_modules())}")