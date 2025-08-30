#!/usr/bin/env python3
"""
ReconForge Port Scanning Module
Terminal-First Professional Reconnaissance Platform

Comprehensive port scanning and service detection using Nmap, Masscan,
and custom scanning techniques for network reconnaissance.
"""

import os
import re
import json
import xml.etree.ElementTree as ET
import subprocess
from typing import List, Dict, Set, Optional, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from ipaddress import ip_address, ip_network
import concurrent.futures
from enum import Enum

# Import core modules
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.logger import ReconForgeLogger
from core.database import ReconForgeDatabase
from core.utils import ReconForgeUtils, ValidationResult
from interface.display import ReconForgeDisplay, StatusType


class PortState(Enum):
    """Port states"""
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    UNFILTERED = "unfiltered"
    OPEN_FILTERED = "open|filtered"
    CLOSED_FILTERED = "closed|filtered"


class ScanType(Enum):
    """Port scan types"""
    TCP_SYN = "syn"
    TCP_CONNECT = "connect"
    UDP = "udp"
    TCP_ACK = "ack"
    TCP_WINDOW = "window"
    TCP_MAIMON = "maimon"
    TCP_NULL = "null"
    TCP_FIN = "fin"
    TCP_XMAS = "xmas"
    IDLE = "idle"
    SCTP_INIT = "sI"
    SCTP_COOKIE_ECHO = "sO"


@dataclass
class ServiceInfo:
    """Service detection information"""
    name: str
    product: Optional[str] = None
    version: Optional[str] = None
    extrainfo: Optional[str] = None
    confidence: Optional[int] = None
    cpe: List[str] = field(default_factory=list)
    script_results: Dict[str, str] = field(default_factory=dict)


@dataclass
class PortResult:
    """Port scanning result"""
    host: str
    port: int
    protocol: str  # tcp, udp, sctp
    state: PortState
    service: Optional[ServiceInfo] = None
    reason: Optional[str] = None
    reason_ttl: Optional[int] = None
    discovered_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class HostResult:
    """Host scanning result"""
    host: str
    hostname: Optional[str] = None
    state: str = "unknown"  # up, down, unknown
    os_matches: List[Dict[str, Any]] = field(default_factory=list)
    ports: List[PortResult] = field(default_factory=list)
    scan_time: float = 0.0
    discovered_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class ScanConfig:
    """Port scanning configuration"""
    targets: List[str]
    scan_id: str
    ports: str = "1-65535"  # Port range or specific ports
    scan_type: ScanType = ScanType.TCP_SYN
    timing_template: int = 3  # Nmap timing (0-5)
    max_rate: Optional[int] = None  # Packets per second
    service_detection: bool = True
    os_detection: bool = False
    script_scan: bool = False
    udp_scan: bool = False
    stealth_mode: bool = False
    aggressive_mode: bool = False
    timeout: int = 1800  # 30 minutes
    max_retries: int = 2
    host_timeout: int = 300  # 5 minutes per host
    exclude_hosts: List[str] = field(default_factory=list)
    custom_scripts: List[str] = field(default_factory=list)
    output_format: str = "xml"  # xml, json, greppable


class PortScanner:
    """Main port scanning engine"""
    
    def __init__(self, logger: ReconForgeLogger, database: ReconForgeDatabase, 
                 utils: ReconForgeUtils, display: ReconForgeDisplay):
        self.logger = logger
        self.database = database
        self.utils = utils
        self.display = display
        
        # Results storage
        self.host_results: List[HostResult] = []
        self.scan_stats: Dict[str, Any] = {}
        
        # Scanner configurations
        self.scanners = {
            'nmap': self._scan_nmap,
            'masscan': self._scan_masscan,
            'custom_tcp': self._scan_custom_tcp,
            'custom_udp': self._scan_custom_udp
        }
        
        # Common ports for quick scans
        self.common_ports = {
            'top_100': '7,9,13,21-23,25-26,37,53,79-81,88,106,110-111,113,119,135,139,143-144,179,199,389,427,443-445,465,513-515,543-544,548,554,587,631,646,873,990,993,995,1025-1029,1110,1433,1720,1723,1755,1900,2000-2001,2049,2121,2717,3000,3128,3306,3389,3986,4899,5000,5009,5051,5060,5101,5190,5357,5432,5631,5666,5800,5900,6000-6001,6646,7070,8000,8008-8009,8080-8081,8443,8888,9100,9999-10000,32768,49152-49157',
            'top_1000': 'nmap-services top 1000',
            'common_web': '80,443,8000,8080,8443,8888,9000,9090',
            'common_db': '1433,1521,3306,5432,27017,6379',
            'common_admin': '22,23,80,443,993,995,3389,5900,5901',
            'all_tcp': '1-65535',
            'all_udp': '1-65535'
        }
        
        # Tool availability check
        self._check_tool_availability()
    
    def _check_tool_availability(self):
        """Check which scanning tools are available"""
        required_tools = ['nmap', 'masscan']
        
        self.available_tools = {}
        for tool in required_tools:
            self.available_tools[tool] = self.utils.tool_manager.is_tool_available(tool)
        
        available_count = sum(self.available_tools.values())
        self.logger.log_system(f"Port scanning tools available: {available_count}/{len(required_tools)}")
    
    def scan_ports(self, config: ScanConfig) -> Dict[str, Any]:
        """Main port scanning method"""
        start_time = datetime.now(timezone.utc)
        
        # Validate and prepare targets
        validated_targets = self._validate_targets(config.targets)
        if not validated_targets:
            error_msg = "No valid targets provided"
            self.logger.log_error(error_msg)
            return {"success": False, "error": error_msg}
        
        config.targets = validated_targets
        
        self.logger.log_scan_operation(f"Starting port scan for {len(config.targets)} targets")
        self.display.print_status(f"Starting port scan for {len(config.targets)} targets", StatusType.INFO)
        
        # Initialize results
        self.host_results.clear()
        self.scan_stats = {
            "total_targets": len(config.targets),
            "total_hosts_scanned": 0,
            "total_ports_scanned": 0,
            "open_ports_found": 0,
            "services_detected": 0,
            "scan_duration": 0.0
        }
        
        # Determine scanner to use
        scanner_func = self._determine_scanner(config)
        if not scanner_func:
            error_msg = "No suitable port scanner available"
            self.logger.log_error(error_msg)
            return {"success": False, "error": error_msg}
        
        # Resolve port specification
        port_list = self._resolve_port_specification(config.ports)
        if not port_list:
            error_msg = f"Invalid port specification: {config.ports}"
            self.logger.log_error(error_msg)
            return {"success": False, "error": error_msg}
        
        self.display.print_status(f"Scanning {len(port_list)} ports on {len(config.targets)} targets", StatusType.INFO)
        
        # Create progress tracking
        progress_key = self.display.create_progress_bar("Scanning ports")
        
        try:
            # Run port scan
            self.display.print_status("Running port scan...", StatusType.RUNNING)
            
            scan_results = scanner_func(config)
            self._process_scan_results(scan_results)
            
            self.display.update_progress(progress_key, 90)
            
            # Service detection if enabled
            if config.service_detection and self.host_results:
                self.display.print_status("Performing service detection...", StatusType.RUNNING)
                self._perform_service_detection(config)
            
            # OS detection if enabled
            if config.os_detection and self.host_results:
                self.display.print_status("Performing OS detection...", StatusType.RUNNING)
                self._perform_os_detection(config)
            
            # Script scanning if enabled
            if config.script_scan and self.host_results:
                self.display.print_status("Running security scripts...", StatusType.RUNNING)
                self._perform_script_scanning(config)
            
            self.display.complete_progress(progress_key)
            
            # Save results to database
            self._save_results_to_database(config)
            
            # Calculate statistics
            self._calculate_statistics()
            
            # Generate summary
            end_time = datetime.now(timezone.utc)
            duration = (end_time - start_time).total_seconds()
            
            self.scan_stats["scan_duration"] = duration
            
            summary = {
                "success": True,
                "scan_id": config.scan_id,
                "targets": config.targets,
                "statistics": self.scan_stats,
                "hosts": [self._host_to_dict(host) for host in self.host_results]
            }
            
            open_ports = sum(len([p for p in host.ports if p.state == PortState.OPEN]) for host in self.host_results)
            
            self.logger.log_scan_operation(f"Port scan completed: {len(self.host_results)} hosts, {open_ports} open ports")
            self.display.print_status(f"Scan complete: {len(self.host_results)} hosts, {open_ports} open ports in {duration:.1f}s", StatusType.SUCCESS)
            
            return summary
        
        except Exception as e:
            self.display.complete_progress(progress_key)
            error_msg = f"Port scanning failed: {str(e)}"
            self.logger.log_error(error_msg, e)
            return {"success": False, "error": error_msg}
    
    def _validate_targets(self, targets: List[str]) -> List[str]:
        """Validate and resolve targets"""
        validated_targets = []
        
        for target in targets:
            try:
                # Check if it's an IP address
                ip_address(target)
                validated_targets.append(target)
                continue
            except ValueError:
                pass
            
            try:
                # Check if it's a network range
                ip_network(target, strict=False)
                validated_targets.append(target)
                continue
            except ValueError:
                pass
            
            # Validate as domain
            validation = self.utils.validator.validate_domain(target)
            if validation.valid:
                validated_targets.append(validation.sanitized)
            else:
                self.logger.log_error(f"Invalid target: {target} - {validation.errors}")
        
        return validated_targets
    
    def _determine_scanner(self, config: ScanConfig) -> Optional[callable]:
        """Determine which scanner to use"""
        if config.stealth_mode and self.available_tools.get('nmap', False):
            return self.scanners['nmap']
        elif config.aggressive_mode and self.available_tools.get('masscan', False):
            return self.scanners['masscan']
        elif self.available_tools.get('nmap', False):
            return self.scanners['nmap']
        elif self.available_tools.get('masscan', False):
            return self.scanners['masscan']
        else:
            return self.scanners.get('custom_tcp')
    
    def _resolve_port_specification(self, ports: str) -> List[int]:
        """Resolve port specification to list of ports"""
        if ports in self.common_ports:
            if ports == 'top_1000':
                # Return top 1000 ports (placeholder)
                return list(range(1, 1001))
            elif ports == 'all_tcp':
                return list(range(1, 65536))
            else:
                return self._parse_port_string(self.common_ports[ports])
        else:
            return self._parse_port_string(ports)
    
    def _parse_port_string(self, port_string: str) -> List[int]:
        """Parse port string (e.g., '22,80,443,8000-8100') into list of ports"""
        ports = set()
        
        for part in port_string.split(','):
            part = part.strip()
            
            if '-' in part:
                try:
                    start, end = map(int, part.split('-', 1))
                    ports.update(range(start, end + 1))
                except ValueError:
                    continue
            else:
                try:
                    ports.add(int(part))
                except ValueError:
                    continue
        
        return sorted(list(ports))
    
    def _process_scan_results(self, results: List[HostResult]):
        """Process and store scan results"""
        self.host_results.extend(results)
        
        for host in results:
            self.logger.log_scan_operation(f"Host {host.host}: {len(host.ports)} ports scanned")
    
    def _calculate_statistics(self):
        """Calculate scan statistics"""
        self.scan_stats["total_hosts_scanned"] = len(self.host_results)
        
        total_ports = 0
        open_ports = 0
        services_detected = 0
        
        for host in self.host_results:
            total_ports += len(host.ports)
            for port in host.ports:
                if port.state == PortState.OPEN:
                    open_ports += 1
                if port.service and port.service.name:
                    services_detected += 1
        
        self.scan_stats["total_ports_scanned"] = total_ports
        self.scan_stats["open_ports_found"] = open_ports
        self.scan_stats["services_detected"] = services_detected
    
    def _save_results_to_database(self, config: ScanConfig):
        """Save scan results to database"""
        try:
            saved_hosts = 0
            
            for host in self.host_results:
                # Create scan entry for host
                host_scan_data = {
                    "host": host.host,
                    "hostname": host.hostname,
                    "state": host.state,
                    "os_matches": host.os_matches,
                    "scan_time": host.scan_time
                }
                
                # Save ports as scan results (adapting to existing schema)
                for port in host.ports:
                    if port.state == PortState.OPEN:
                        self.database.add_subdomain(
                            scan_id=config.scan_id,
                            subdomain=f"{host.host}:{port.port}",
                            ip_address=host.host,
                            status_code=port.port,  # Using status_code field for port
                            title=f"{port.protocol.upper()} Port {port.port}",
                            source="port_scan",
                            tech_stack=[port.service.name] if port.service else [],
                            cname=host.hostname
                        )
                
                saved_hosts += 1
            
            self.logger.log_database_operation(f"Saved {saved_hosts} host scan results to database")
            self.display.print_status(f"Saved {saved_hosts} host results to database", StatusType.SUCCESS)
        
        except Exception as e:
            self.logger.log_error(f"Failed to save scan results to database: {str(e)}", e)
            self.display.print_status("Failed to save scan results to database", StatusType.ERROR)
    
    def _host_to_dict(self, host: HostResult) -> Dict[str, Any]:
        """Convert host result to dictionary"""
        return {
            "host": host.host,
            "hostname": host.hostname,
            "state": host.state,
            "ports": [{
                "port": port.port,
                "protocol": port.protocol,
                "state": port.state.value,
                "service": {
                    "name": port.service.name if port.service else None,
                    "product": port.service.product if port.service else None,
                    "version": port.service.version if port.service else None
                } if port.service else None
            } for port in host.ports],
            "os_matches": host.os_matches,
            "scan_time": host.scan_time,
            "discovered_at": host.discovered_at.isoformat()
        }
    
    # Scanner Implementations
    def _scan_nmap(self, config: ScanConfig) -> List[HostResult]:
        """Nmap scanner implementation"""
        if not self.available_tools.get('nmap', False):
            return []
        
        host_results = []
        
        try:
            # Create target list
            target_file = Path(f"/tmp/nmap_targets_{config.scan_id}.txt")
            with open(target_file, 'w') as f:
                for target in config.targets:
                    f.write(f"{target}\n")
            
            # Create output file
            output_file = Path(f"/tmp/nmap_output_{config.scan_id}.xml")
            
            # Build nmap command
            cmd = ['nmap']
            
            # Add scan type
            if config.scan_type == ScanType.TCP_SYN:
                cmd.append('-sS')
            elif config.scan_type == ScanType.TCP_CONNECT:
                cmd.append('-sT')
            elif config.scan_type == ScanType.UDP:
                cmd.append('-sU')
            elif config.scan_type == ScanType.TCP_ACK:
                cmd.append('-sA')
            
            # Add timing template
            cmd.extend(['-T', str(config.timing_template)])
            
            # Add ports
            cmd.extend(['-p', config.ports])
            
            # Add targets
            cmd.extend(['-iL', str(target_file)])
            
            # Add output format
            cmd.extend(['-oX', str(output_file)])
            
            # Add service detection
            if config.service_detection:
                cmd.append('-sV')
            
            # Add OS detection
            if config.os_detection:
                cmd.append('-O')
            
            # Add script scanning
            if config.script_scan:
                cmd.append('-sC')
            
            # Add custom scripts
            if config.custom_scripts:
                cmd.extend(['--script', ','.join(config.custom_scripts)])
            
            # Add rate limiting
            if config.max_rate:
                cmd.extend(['--max-rate', str(config.max_rate)])
            
            # Add host timeout
            cmd.extend(['--host-timeout', f"{config.host_timeout}s"])
            
            # Add retries
            cmd.extend(['--max-retries', str(config.max_retries)])
            
            # Add exclusions
            if config.exclude_hosts:
                exclude_file = Path(f"/tmp/nmap_exclude_{config.scan_id}.txt")
                with open(exclude_file, 'w') as f:
                    for host in config.exclude_hosts:
                        f.write(f"{host}\n")
                cmd.extend(['--excludefile', str(exclude_file)])
            
            self.logger.log_tool_execution(f"Running nmap: {' '.join(cmd)}")
            
            # Run nmap
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=config.timeout)
            
            if result.returncode == 0 and output_file.exists():
                host_results = self._parse_nmap_xml(output_file)
            else:
                self.logger.log_error(f"Nmap scan failed: {result.stderr}")
            
            # Cleanup
            for temp_file in [target_file, output_file]:
                if temp_file.exists():
                    temp_file.unlink()
            
            if config.exclude_hosts and exclude_file.exists():
                exclude_file.unlink()
        
        except Exception as e:
            self.logger.log_error(f"Nmap scanning failed: {str(e)}", e)
        
        return host_results
    
    def _parse_nmap_xml(self, xml_file: Path) -> List[HostResult]:
        """Parse nmap XML output"""
        host_results = []
        
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            for host_elem in root.findall('.//host'):
                # Get host information
                address_elem = host_elem.find('.//address[@addrtype="ipv4"]')
                if address_elem is None:
                    continue
                
                host_ip = address_elem.get('addr')
                
                # Get hostname
                hostname = None
                hostname_elem = host_elem.find('.//hostname')
                if hostname_elem is not None:
                    hostname = hostname_elem.get('name')
                
                # Get host state
                status_elem = host_elem.find('.//status')
                host_state = status_elem.get('state') if status_elem is not None else 'unknown'
                
                # Create host result
                host_result = HostResult(
                    host=host_ip,
                    hostname=hostname,
                    state=host_state
                )
                
                # Parse ports
                ports_elem = host_elem.find('.//ports')
                if ports_elem is not None:
                    for port_elem in ports_elem.findall('.//port'):
                        port_num = int(port_elem.get('portid'))
                        protocol = port_elem.get('protocol')
                        
                        # Get port state
                        state_elem = port_elem.find('.//state')
                        port_state = PortState.CLOSED
                        if state_elem is not None:
                            state_str = state_elem.get('state', 'closed')
                            try:
                                port_state = PortState(state_str)
                            except ValueError:
                                port_state = PortState.CLOSED
                        
                        # Get service information
                        service = None
                        service_elem = port_elem.find('.//service')
                        if service_elem is not None:
                            service = ServiceInfo(
                                name=service_elem.get('name', ''),
                                product=service_elem.get('product'),
                                version=service_elem.get('version'),
                                extrainfo=service_elem.get('extrainfo'),
                                confidence=int(service_elem.get('conf', 0))
                            )
                        
                        # Create port result
                        port_result = PortResult(
                            host=host_ip,
                            port=port_num,
                            protocol=protocol,
                            state=port_state,
                            service=service
                        )
                        
                        host_result.ports.append(port_result)
                
                # Parse OS detection results
                os_elem = host_elem.find('.//os')
                if os_elem is not None:
                    for osmatch_elem in os_elem.findall('.//osmatch'):
                        os_match = {
                            'name': osmatch_elem.get('name'),
                            'accuracy': int(osmatch_elem.get('accuracy', 0))
                        }
                        host_result.os_matches.append(os_match)
                
                host_results.append(host_result)
        
        except Exception as e:
            self.logger.log_error(f"Failed to parse nmap XML: {str(e)}", e)
        
        return host_results
    
    def _scan_masscan(self, config: ScanConfig) -> List[HostResult]:
        """Masscan scanner implementation"""
        if not self.available_tools.get('masscan', False):
            return []
        
        host_results = []
        
        try:
            # Create output file
            output_file = Path(f"/tmp/masscan_output_{config.scan_id}.json")
            
            # Build masscan command
            cmd = ['masscan']
            
            # Add targets
            cmd.extend(config.targets)
            
            # Add ports
            cmd.extend(['-p', config.ports])
            
            # Add output format
            cmd.extend(['-oJ', str(output_file)])
            
            # Add rate limiting
            if config.max_rate:
                cmd.extend(['--rate', str(config.max_rate)])
            
            self.logger.log_tool_execution(f"Running masscan: {' '.join(cmd)}")
            
            # Run masscan
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=config.timeout)
            
            if result.returncode == 0 and output_file.exists():
                host_results = self._parse_masscan_json(output_file)
            else:
                self.logger.log_error(f"Masscan failed: {result.stderr}")
            
            # Cleanup
            if output_file.exists():
                output_file.unlink()
        
        except Exception as e:
            self.logger.log_error(f"Masscan scanning failed: {str(e)}", e)
        
        return host_results
    
    def _parse_masscan_json(self, json_file: Path) -> List[HostResult]:
        """Parse masscan JSON output"""
        host_results = []
        hosts_dict = {}
        
        try:
            with open(json_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    
                    data = json.loads(line)
                    
                    ip = data.get('ip')
                    port_info = data.get('ports', [{}])[0]
                    port = port_info.get('port')
                    protocol = port_info.get('proto', 'tcp')
                    status = port_info.get('status', 'open')
                    
                    if ip not in hosts_dict:
                        hosts_dict[ip] = HostResult(
                            host=ip,
                            state='up'
                        )
                    
                    port_result = PortResult(
                        host=ip,
                        port=port,
                        protocol=protocol,
                        state=PortState.OPEN if status == 'open' else PortState.CLOSED
                    )
                    
                    hosts_dict[ip].ports.append(port_result)
            
            host_results = list(hosts_dict.values())
        
        except Exception as e:
            self.logger.log_error(f"Failed to parse masscan JSON: {str(e)}", e)
        
        return host_results
    
    # Placeholder implementations for service/OS detection
    def _perform_service_detection(self, config: ScanConfig):
        """Perform additional service detection"""
        # This would enhance service detection beyond basic scanning
        pass
    
    def _perform_os_detection(self, config: ScanConfig):
        """Perform additional OS detection"""
        # This would enhance OS fingerprinting
        pass
    
    def _perform_script_scanning(self, config: ScanConfig):
        """Perform script-based scanning"""
        # This would run additional security scripts
        pass
    
    # Custom scanner implementations (placeholder)
    def _scan_custom_tcp(self, config: ScanConfig) -> List[HostResult]:
        """Custom TCP scanner (fallback)"""
        return []
    
    def _scan_custom_udp(self, config: ScanConfig) -> List[HostResult]:
        """Custom UDP scanner (fallback)"""
        return []


# Factory functions
def create_port_scanner(logger: ReconForgeLogger, database: ReconForgeDatabase,
                       utils: ReconForgeUtils, display: ReconForgeDisplay) -> PortScanner:
    """Create a port scanner instance"""
    return PortScanner(logger, database, utils, display)


def create_scan_config(targets: List[str], scan_id: str, **kwargs) -> ScanConfig:
    """Create a scan configuration with defaults"""
    return ScanConfig(targets=targets, scan_id=scan_id, **kwargs)