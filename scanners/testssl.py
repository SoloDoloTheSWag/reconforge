import asyncio
import subprocess
import json
import tempfile
from pathlib import Path
from typing import List, Dict, Optional, Any
from urllib.parse import urlparse

from scanners.base import BaseVulnerabilityScanner, VulnerabilityResult, VulnerabilitySeverity
from utils.logging import main_logger
from utils.helpers import ToolValidator


class TestSSLScanner(BaseVulnerabilityScanner):
    """testssl.sh SSL/TLS vulnerability scanner integration"""
    
    def __init__(self):
        super().__init__("testssl", "testssl.sh SSL/TLS security scanner")
        self.timeout = 300  # 5 minutes default timeout
        self.check_severity = ["HIGH", "MEDIUM", "LOW"]
        self.protocols = True
        self.ciphers = True
        self.vulnerabilities = True
    
    def configure(self, config: Dict[str, Any]):
        """Configure testssl scanner"""
        super().configure(config)
        
        if 'timeout' in config:
            self.timeout = config['timeout']
        if 'check_severity' in config:
            self.check_severity = config['check_severity']
        if 'protocols' in config:
            self.protocols = config['protocols']
        if 'ciphers' in config:
            self.ciphers = config['ciphers']
        if 'vulnerabilities' in config:
            self.vulnerabilities = config['vulnerabilities']
    
    async def scan(self, targets: List[str], **kwargs) -> List[VulnerabilityResult]:
        """Run testssl scan on targets"""
        if not ToolValidator.check_tool('testssl.sh')['available']:
            raise Exception("testssl.sh is not installed or not available")
        
        all_results = []
        
        for target in targets:
            results = await self._scan_single_target(target, **kwargs)
            all_results.extend(results)
        
        return all_results
    
    async def _scan_single_target(self, target: str, **kwargs) -> List[VulnerabilityResult]:
        """Scan a single target with testssl"""
        # Extract host and port from target
        host, port = self._parse_target(target)
        if not host:
            main_logger.warning(f"Could not parse target: {target}")
            return []
        
        # Create temporary file for JSON output
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            output_file = f.name
        
        try:
            # Build testssl command
            cmd = [
                "testssl.sh",
                "--jsonfile", output_file,
                "--quiet",
                "--color", "0"
            ]
            
            # Add scan options
            if self.protocols:
                cmd.append("--protocols")
            
            if self.ciphers:
                cmd.append("--ciphers")
            
            if self.vulnerabilities:
                cmd.append("--vulnerabilities")
            
            # Add severity filters
            if "HIGH" in self.check_severity:
                cmd.append("--severity=HIGH")
            elif "MEDIUM" in self.check_severity:
                cmd.append("--severity=MEDIUM")
            elif "LOW" in self.check_severity:
                cmd.append("--severity=LOW")
            
            # Add target
            if port != 443:
                cmd.append(f"{host}:{port}")
            else:
                cmd.append(host)
            
            main_logger.info(f"Running testssl scan: {' '.join(cmd[:5])}...")
            
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
                raise Exception(f"testssl scan timed out after {self.timeout} seconds")
            
            # Parse results (testssl returns non-zero for vulnerabilities found)
            results = await self._parse_testssl_results(output_file, target, host, port)
            return results
            
        except Exception as e:
            main_logger.error(f"testssl scan failed for {target}: {e}")
            return []
        finally:
            # Clean up temporary file
            Path(output_file).unlink(missing_ok=True)
    
    def _parse_target(self, target: str) -> tuple[str, int]:
        """Parse target URL/host to extract host and port"""
        if '://' in target:
            parsed = urlparse(target)
            host = parsed.hostname
            port = parsed.port
            
            if not port:
                port = 443 if parsed.scheme == 'https' else 80
        else:
            # Handle host:port format
            if ':' in target:
                parts = target.split(':')
                host = parts[0]
                try:
                    port = int(parts[1])
                except ValueError:
                    port = 443
            else:
                host = target
                port = 443
        
        return host, port
    
    async def _parse_testssl_results(self, results_file: str, target: str, host: str, port: int) -> List[VulnerabilityResult]:
        """Parse testssl JSON output"""
        results = []
        results_path = Path(results_file)
        
        if not results_path.exists():
            main_logger.warning("testssl results file not found")
            return results
        
        try:
            with results_path.open('r', encoding='utf-8') as f:
                # testssl outputs one JSON object per line
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    
                    try:
                        data = json.loads(line)
                        vuln_result = self._convert_testssl_result(data, target, host, port)
                        if vuln_result:
                            results.append(vuln_result)
                    except json.JSONDecodeError:
                        continue
        
        except Exception as e:
            main_logger.error(f"Failed to parse testssl results: {e}")
        
        return results
    
    def _convert_testssl_result(self, data: Dict[str, Any], target: str, host: str, port: int) -> Optional[VulnerabilityResult]:
        """Convert testssl result to VulnerabilityResult"""
        try:
            test_id = data.get('id', '')
            finding = data.get('finding', '')
            severity = data.get('severity', 'INFO')
            cve = data.get('cve', '')
            
            # Skip informational entries without findings
            if not finding or finding in ['', 'not offered', 'not vulnerable', 'No']:
                return None
            
            # Map testssl severity to our severity
            severity_map = {
                'CRITICAL': VulnerabilitySeverity.CRITICAL,
                'HIGH': VulnerabilitySeverity.HIGH,
                'MEDIUM': VulnerabilitySeverity.MEDIUM,
                'LOW': VulnerabilitySeverity.LOW,
                'INFO': VulnerabilitySeverity.INFO,
                'WARN': VulnerabilitySeverity.MEDIUM,
                'OK': VulnerabilitySeverity.INFO
            }
            
            vuln_severity = severity_map.get(severity.upper(), VulnerabilitySeverity.INFO)
            
            # Skip OK/INFO findings unless they're specifically requested
            if vuln_severity in [VulnerabilitySeverity.INFO] and severity.upper() == 'OK':
                return None
            
            # Determine vulnerability type
            vuln_type = self._determine_ssl_vuln_type(test_id, finding)
            
            # Build title and description
            title = self._build_ssl_title(test_id, finding, cve)
            description = self._build_ssl_description(data, finding, cve)
            
            # Determine confidence based on testssl findings
            confidence = 0.9  # testssl is generally reliable
            if severity.upper() in ['HIGH', 'CRITICAL']:
                confidence = 0.95
            elif severity.upper() in ['MEDIUM']:
                confidence = 0.8
            else:
                confidence = 0.7
            
            # Check if this is a verified vulnerability
            verified = severity.upper() not in ['INFO', 'OK'] and finding not in ['not vulnerable', 'not affected']
            
            return VulnerabilityResult(
                title=title,
                severity=vuln_severity,
                vulnerability_type=vuln_type,
                target=target,
                description=description,
                url=f"https://{host}:{port}" if port != 443 else f"https://{host}",
                cve_id=cve if cve else None,
                verified=verified,
                confidence=confidence,
                metadata={
                    "testssl_id": test_id,
                    "testssl_severity": severity,
                    "ssl_host": host,
                    "ssl_port": port,
                    "finding": finding,
                    "cve": cve,
                    "raw_result": data
                }
            )
            
        except Exception as e:
            main_logger.debug(f"Failed to convert testssl result: {e}")
            return None
    
    def _determine_ssl_vuln_type(self, test_id: str, finding: str) -> str:
        """Determine SSL/TLS vulnerability type"""
        test_id_lower = test_id.lower()
        finding_lower = finding.lower()
        
        type_mappings = {
            'heartbleed': 'Heartbleed',
            'ccs': 'CCS Injection',
            'ticketbleed': 'Ticketbleed',
            'robot': 'ROBOT Attack',
            'secure_renego': 'Secure Renegotiation',
            'crime': 'CRIME',
            'breach': 'BREACH',
            'poodle': 'POODLE',
            'tls_fallback_scsv': 'TLS Fallback SCSV',
            'sweet32': 'Sweet32',
            'freak': 'FREAK',
            'drown': 'DROWN',
            'logjam': 'Logjam',
            'beast': 'BEAST',
            'lucky13': 'Lucky13',
            'rc4': 'RC4 Cipher',
            'ssl': 'SSL Protocol',
            'tls': 'TLS Configuration',
            'cipher': 'Cipher Suite',
            'certificate': 'Certificate Issue',
            'hsts': 'HSTS'
        }
        
        for key, vuln_type in type_mappings.items():
            if key in test_id_lower or key in finding_lower:
                return vuln_type
        
        return 'SSL/TLS Configuration Issue'
    
    def _build_ssl_title(self, test_id: str, finding: str, cve: str) -> str:
        """Build title for SSL/TLS vulnerability"""
        vuln_type = self._determine_ssl_vuln_type(test_id, finding)
        
        if cve:
            return f"{vuln_type} ({cve})"
        else:
            return vuln_type
    
    def _build_ssl_description(self, data: Dict[str, Any], finding: str, cve: str) -> str:
        """Build description for SSL/TLS vulnerability"""
        description = f"SSL/TLS security issue detected: {finding}"
        
        if cve:
            description += f"\n\nCVE: {cve}"
        
        # Add additional context from testssl data
        if data.get('severity'):
            description += f"\nSeverity: {data['severity']}"
        
        if data.get('id'):
            description += f"\nTest ID: {data['id']}"
        
        return description


def get_testssl_scanners(config: Dict[str, Any] = None) -> List[BaseVulnerabilityScanner]:
    """Get configured testssl scanners"""
    config = config or {}
    scanners = []
    
    # Main testssl scanner
    main_scanner = TestSSLScanner()
    main_scanner.configure(config)
    scanners.append(main_scanner)
    
    return scanners