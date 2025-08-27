import asyncio
import subprocess
import json
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List, Dict, Optional, Any

from scanners.base import BaseVulnerabilityScanner, VulnerabilityResult, VulnerabilitySeverity
from utils.logging import main_logger
from utils.helpers import FileHelper, ToolValidator


class WapitiScanner(BaseVulnerabilityScanner):
    """Wapiti web vulnerability scanner integration"""
    
    def __init__(self):
        super().__init__("wapiti", "Wapiti web application vulnerability scanner")
        self.level = "1"  # Scanning level
        self.timeout = 600  # 10 minutes default timeout
        self.max_depth = 5
        self.max_links = 1000
        self.excluded_modules = ["backup", "htaccess", "log4shell"]  # Modules to exclude
        
    def configure(self, config: Dict[str, Any]):
        """Configure Wapiti scanner"""
        super().configure(config)
        
        if 'level' in config:
            self.level = str(config['level'])
        if 'timeout' in config:
            self.timeout = config['timeout']
        if 'max_depth' in config:
            self.max_depth = config['max_depth']
        if 'max_links' in config:
            self.max_links = config['max_links']
        if 'excluded_modules' in config:
            self.excluded_modules = config['excluded_modules']
    
    async def scan(self, targets: List[str], **kwargs) -> List[VulnerabilityResult]:
        """Run Wapiti scan on targets"""
        if not ToolValidator.check_tool('wapiti')['available']:
            raise Exception("Wapiti is not installed or not available")
        
        all_results = []
        
        for target in targets:
            results = await self._scan_single_target(target, **kwargs)
            all_results.extend(results)
        
        return all_results
    
    async def _scan_single_target(self, target: str, **kwargs) -> List[VulnerabilityResult]:
        """Scan a single target with Wapiti"""
        # Create temporary directory for output
        with tempfile.TemporaryDirectory() as temp_dir:
            output_file = Path(temp_dir) / f"wapiti_{target.replace('://', '_').replace('/', '_')}.json"
            
            # Build Wapiti command
            cmd = [
                "wapiti",
                "-u", target,
                "--format", "json",
                "--output", str(output_file),
                "--level", self.level,
                "--max-depth", str(self.max_depth),
                "--max-links-per-page", str(self.max_links),
                "--flush-attacks",
                "--color"
            ]
            
            # Add excluded modules
            if self.excluded_modules:
                for module in self.excluded_modules:
                    cmd.extend(["--skip", module])
            
            # Add custom options from kwargs
            if kwargs.get('modules'):
                for module in kwargs['modules']:
                    cmd.extend(["-m", module])
            
            if kwargs.get('cookie'):
                cmd.extend(["-c", kwargs['cookie']])
            
            if kwargs.get('auth_type') and kwargs.get('auth_credentials'):
                cmd.extend(["--auth-type", kwargs['auth_type']])
                cmd.extend(["--auth-cred", kwargs['auth_credentials']])
            
            try:
                main_logger.info(f"Running Wapiti scan: {' '.join(cmd[:6])}...")
                
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                
                try:
                    stdout, stderr = await asyncio.wait_for(
                        process.communicate(),
                        timeout=self.timeout
                    )
                except asyncio.TimeoutError:
                    process.terminate()
                    await process.wait()
                    raise Exception(f"Wapiti scan timed out after {self.timeout} seconds")
                
                if process.returncode != 0:
                    error_msg = stderr.decode() if stderr else "Unknown error"
                    main_logger.warning(f"Wapiti finished with return code {process.returncode}: {error_msg}")
                
                # Parse results
                results = await self._parse_wapiti_results(str(output_file), target)
                return results
                
            except Exception as e:
                main_logger.error(f"Wapiti scan failed for {target}: {e}")
                return []
    
    async def _parse_wapiti_results(self, results_file: str, target: str) -> List[VulnerabilityResult]:
        """Parse Wapiti JSON output"""
        results = []
        results_path = Path(results_file)
        
        if not results_path.exists():
            main_logger.warning("Wapiti results file not found")
            return results
        
        try:
            with results_path.open('r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Parse vulnerabilities
            for vuln_category in data.get('vulnerabilities', {}):
                for vuln_data in data['vulnerabilities'][vuln_category]:
                    vuln_result = self._convert_wapiti_result(vuln_data, vuln_category, target)
                    if vuln_result:
                        results.append(vuln_result)
            
            # Parse anomalies
            for anomaly_category in data.get('anomalies', {}):
                for anomaly_data in data['anomalies'][anomaly_category]:
                    anomaly_result = self._convert_wapiti_anomaly(anomaly_data, anomaly_category, target)
                    if anomaly_result:
                        results.append(anomaly_result)
        
        except Exception as e:
            main_logger.error(f"Failed to parse Wapiti results: {e}")
        
        return results
    
    def _convert_wapiti_result(self, vuln_data: Dict[str, Any], category: str, target: str) -> Optional[VulnerabilityResult]:
        """Convert Wapiti vulnerability to VulnerabilityResult"""
        try:
            method = vuln_data.get('method', 'GET')
            path = vuln_data.get('path', '')
            parameter = vuln_data.get('parameter', '')
            info = vuln_data.get('info', '')
            
            # Determine severity based on category
            severity_map = {
                'SQL Injection': VulnerabilitySeverity.CRITICAL,
                'Cross Site Scripting': VulnerabilitySeverity.HIGH,
                'File Handling': VulnerabilitySeverity.HIGH,
                'Command Execution': VulnerabilitySeverity.CRITICAL,
                'CRLF Injection': VulnerabilitySeverity.MEDIUM,
                'XXE': VulnerabilitySeverity.HIGH,
                'SSRF': VulnerabilitySeverity.HIGH,
                'Open Redirect': VulnerabilitySeverity.MEDIUM,
                'Potentially dangerous file': VulnerabilitySeverity.MEDIUM,
                'Backup file': VulnerabilitySeverity.LOW,
                'Htaccess Bypass': VulnerabilitySeverity.MEDIUM
            }
            
            severity = severity_map.get(category, VulnerabilitySeverity.MEDIUM)
            
            # Build full URL
            full_url = target.rstrip('/') + path if path.startswith('/') else f"{target.rstrip('/')}/{path}"
            
            # Generate title
            title = f"{category}"
            if parameter:
                title += f" in parameter '{parameter}'"
            
            # Generate description
            description = f"Wapiti detected {category.lower()}"
            if parameter:
                description += f" in the '{parameter}' parameter"
            description += f" via {method} request to {path}"
            if info:
                description += f"\n\nDetails: {info}"
            
            return VulnerabilityResult(
                title=title,
                severity=severity,
                vulnerability_type=category,
                target=target,
                description=description,
                url=full_url,
                method=method,
                parameter=parameter,
                verified=True,
                confidence=0.8,
                metadata={
                    "wapiti_category": category,
                    "path": path,
                    "method": method,
                    "parameter": parameter,
                    "info": info,
                    "raw_result": vuln_data
                }
            )
            
        except Exception as e:
            main_logger.debug(f"Failed to convert Wapiti result: {e}")
            return None
    
    def _convert_wapiti_anomaly(self, anomaly_data: Dict[str, Any], category: str, target: str) -> Optional[VulnerabilityResult]:
        """Convert Wapiti anomaly to VulnerabilityResult"""
        try:
            method = anomaly_data.get('method', 'GET')
            path = anomaly_data.get('path', '')
            info = anomaly_data.get('info', '')
            
            # Anomalies are typically lower severity
            severity = VulnerabilitySeverity.LOW
            
            full_url = target.rstrip('/') + path if path.startswith('/') else f"{target.rstrip('/')}/{path}"
            
            title = f"Anomaly: {category}"
            description = f"Wapiti detected an anomaly: {category.lower()}"
            if info:
                description += f"\n\nDetails: {info}"
            
            return VulnerabilityResult(
                title=title,
                severity=severity,
                vulnerability_type=f"Anomaly - {category}",
                target=target,
                description=description,
                url=full_url,
                method=method,
                verified=False,
                confidence=0.6,
                metadata={
                    "wapiti_anomaly": category,
                    "path": path,
                    "method": method,
                    "info": info,
                    "raw_result": anomaly_data
                }
            )
            
        except Exception as e:
            main_logger.debug(f"Failed to convert Wapiti anomaly: {e}")
            return None


def get_wapiti_scanners(config: Dict[str, Any] = None) -> List[BaseVulnerabilityScanner]:
    """Get configured Wapiti scanners"""
    config = config or {}
    scanners = []
    
    # Main Wapiti scanner
    main_scanner = WapitiScanner()
    main_scanner.configure(config)
    scanners.append(main_scanner)
    
    return scanners