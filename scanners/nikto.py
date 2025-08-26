import asyncio
import subprocess
import json
import xml.etree.ElementTree as ET
import tempfile
from pathlib import Path
from typing import List, Dict, Optional, Any

from scanners.base import BaseVulnerabilityScanner, VulnerabilityResult, VulnerabilitySeverity
from utils.logging import main_logger
from utils.helpers import ToolValidator


class NiktoScanner(BaseVulnerabilityScanner):
    """Nikto web vulnerability scanner integration"""
    
    def __init__(self):
        super().__init__("nikto", "Web server vulnerability scanner")
        self.timeout = 300  # 5 minutes
        self.max_redirects = 5
        self.user_agent = "ReconForge-Nikto/1.0"
        self.output_format = "xml"
    
    def configure(self, config: Dict[str, Any]):
        """Configure Nikto scanner"""
        super().configure(config)
        
        if 'timeout' in config:
            self.timeout = config['timeout']
        if 'max_redirects' in config:
            self.max_redirects = config['max_redirects']
        if 'user_agent' in config:
            self.user_agent = config['user_agent']
    
    async def scan(self, targets: List[str], **kwargs) -> List[VulnerabilityResult]:
        """Run Nikto scan on targets"""
        if not ToolValidator.check_tool('nikto')['available']:
            main_logger.warning("Nikto is not installed, skipping scan")
            return []
        
        results = []
        
        for target in targets:
            try:
                target_results = await self._scan_target(target)
                results.extend(target_results)
            except Exception as e:
                main_logger.error(f"Nikto scan failed for {target}: {e}")
                continue
        
        return results
    
    async def _scan_target(self, target: str) -> List[VulnerabilityResult]:
        """Scan a single target with Nikto"""
        # Ensure target has protocol
        if not target.startswith(('http://', 'https://')):
            target = f"http://{target}"
        
        # Create temporary output file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as output_file:
            output_path = output_file.name
        
        # Build Nikto command
        cmd = [
            "nikto",
            "-host", target,
            "-output", output_path,
            "-Format", self.output_format,
            "-timeout", str(self.timeout),
            "-maxtime", str(self.timeout),
            "-useragent", self.user_agent,
            "-maxredirect", str(self.max_redirects),
            "-nointeractive"
        ]
        
        try:
            # Run Nikto scan
            main_logger.info(f"Starting Nikto scan for {target}")
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), timeout=self.timeout + 60
            )
            
            # Parse results regardless of return code (Nikto returns non-zero when vulnerabilities found)
            results = self._parse_nikto_output(output_path, target)
            
            main_logger.info(f"Nikto scan completed for {target}: {len(results)} findings")
            return results
            
        except asyncio.TimeoutError:
            main_logger.error(f"Nikto scan timed out for {target}")
            return []
        except Exception as e:
            main_logger.error(f"Error running Nikto on {target}: {e}")
            return []
        finally:
            # Clean up temporary file
            try:
                Path(output_path).unlink(missing_ok=True)
            except Exception:
                pass
    
    def _parse_nikto_output(self, output_path: str, target: str) -> List[VulnerabilityResult]:
        """Parse Nikto XML output"""
        results = []
        
        try:
            if not Path(output_path).exists():
                main_logger.warning(f"Nikto output file not found: {output_path}")
                return []
            
            tree = ET.parse(output_path)
            root = tree.getroot()
            
            # Parse scan details
            scan_details = root.find('.//scandetails')
            if scan_details is None:
                main_logger.warning("No scan details found in Nikto output")
                return []
            
            target_ip = scan_details.get('targetip', 'Unknown')
            target_port = scan_details.get('targetport', '80')
            
            # Parse vulnerabilities
            for item in root.findall('.//item'):
                try:
                    vuln_id = item.get('id', '')
                    osvdb_id = item.get('osvdbid', '')
                    method = item.get('method', 'GET')
                    
                    # Get description
                    description_elem = item.find('description')
                    description = description_elem.text if description_elem is not None else "No description"
                    
                    # Get URI
                    uri_elem = item.find('uri')
                    uri = uri_elem.text if uri_elem is not None else ""
                    
                    # Full URL
                    full_url = f"{target.rstrip('/')}{uri}" if uri else target
                    
                    # Determine severity based on OSVDB ID and description
                    severity = self._determine_severity(description, osvdb_id)
                    
                    # Extract vulnerability type from description
                    vuln_type = self._extract_vulnerability_type(description)
                    
                    result = VulnerabilityResult(
                        title=f"Nikto: {description[:100]}...",
                        description=description,
                        severity=severity,
                        vulnerability_type=vuln_type,
                        url=full_url,
                        method=method,
                        scanner=self.name,
                        metadata={
                            "nikto_id": vuln_id,
                            "osvdb_id": osvdb_id,
                            "target_ip": target_ip,
                            "target_port": target_port,
                            "uri": uri
                        }
                    )
                    
                    results.append(result)
                    
                except Exception as e:
                    main_logger.error(f"Error parsing Nikto item: {e}")
                    continue
            
        except ET.ParseError as e:
            main_logger.error(f"Error parsing Nikto XML output: {e}")
        except Exception as e:
            main_logger.error(f"Unexpected error parsing Nikto output: {e}")
        
        return results
    
    def _determine_severity(self, description: str, osvdb_id: str) -> VulnerabilitySeverity:
        """Determine vulnerability severity based on description and OSVDB ID"""
        desc_lower = description.lower()
        
        # Critical vulnerabilities
        critical_keywords = [
            'remote code execution', 'sql injection', 'command injection',
            'authentication bypass', 'privilege escalation', 'backdoor'
        ]
        
        # High vulnerabilities  
        high_keywords = [
            'cross-site scripting', 'xss', 'directory traversal', 'file inclusion',
            'password', 'admin', 'default credentials', 'unrestricted file upload'
        ]
        
        # Medium vulnerabilities
        medium_keywords = [
            'information disclosure', 'configuration', 'version disclosure',
            'ssl', 'tls', 'certificate', 'redirect', 'csrf'
        ]
        
        for keyword in critical_keywords:
            if keyword in desc_lower:
                return VulnerabilitySeverity.CRITICAL
        
        for keyword in high_keywords:
            if keyword in desc_lower:
                return VulnerabilitySeverity.HIGH
        
        for keyword in medium_keywords:
            if keyword in desc_lower:
                return VulnerabilitySeverity.MEDIUM
        
        # Default to low for other findings
        return VulnerabilitySeverity.LOW
    
    def _extract_vulnerability_type(self, description: str) -> str:
        """Extract vulnerability type from description"""
        desc_lower = description.lower()
        
        if 'cross-site scripting' in desc_lower or 'xss' in desc_lower:
            return 'Cross-Site Scripting (XSS)'
        elif 'sql injection' in desc_lower:
            return 'SQL Injection'
        elif 'directory traversal' in desc_lower:
            return 'Directory Traversal'
        elif 'file inclusion' in desc_lower:
            return 'File Inclusion'
        elif 'authentication' in desc_lower:
            return 'Authentication Issues'
        elif 'ssl' in desc_lower or 'tls' in desc_lower:
            return 'SSL/TLS Issues'
        elif 'information disclosure' in desc_lower:
            return 'Information Disclosure'
        elif 'configuration' in desc_lower:
            return 'Security Misconfiguration'
        else:
            return 'Web Application Vulnerability'


def get_nikto_scanner() -> NiktoScanner:
    """Factory function to create Nikto scanner"""
    return NiktoScanner()