import asyncio
import subprocess
import json
import time
import requests
from pathlib import Path
from typing import List, Dict, Optional, Any

from scanners.base import BaseVulnerabilityScanner, VulnerabilityResult, VulnerabilitySeverity
from utils.logging import main_logger
from utils.helpers import ToolValidator


class ZAPScanner(BaseVulnerabilityScanner):
    """OWASP ZAP vulnerability scanner integration"""
    
    def __init__(self, zap_proxy_host: str = "127.0.0.1", zap_proxy_port: int = 8080):
        super().__init__("zap", "OWASP ZAP web application security scanner")
        self.zap_host = zap_proxy_host
        self.zap_port = zap_proxy_port
        self.zap_api_key = None
        self.timeout = 1800  # 30 minutes default timeout
        self.spider_timeout = 300  # 5 minutes spider timeout
        self.scan_timeout = 900   # 15 minutes active scan timeout
    
    def configure(self, config: Dict[str, Any]):
        """Configure ZAP scanner"""
        super().configure(config)
        
        if 'zap_host' in config:
            self.zap_host = config['zap_host']
        if 'zap_port' in config:
            self.zap_port = config['zap_port']
        if 'zap_api_key' in config:
            self.zap_api_key = config['zap_api_key']
        if 'timeout' in config:
            self.timeout = config['timeout']
        if 'spider_timeout' in config:
            self.spider_timeout = config['spider_timeout']
        if 'scan_timeout' in config:
            self.scan_timeout = config['scan_timeout']
    
    async def scan(self, targets: List[str], **kwargs) -> List[VulnerabilityResult]:
        """Run ZAP scan on targets"""
        if not self._check_zap_available():
            raise Exception("OWASP ZAP is not available or not running")
        
        all_results = []
        
        for target in targets:
            results = await self._scan_single_target(target, **kwargs)
            all_results.extend(results)
        
        return all_results
    
    def _check_zap_available(self) -> bool:
        """Check if ZAP proxy is available"""
        try:
            response = requests.get(
                f"http://{self.zap_host}:{self.zap_port}",
                timeout=5
            )
            return True
        except:
            return False
    
    async def _scan_single_target(self, target: str, **kwargs) -> List[VulnerabilityResult]:
        """Scan a single target with ZAP"""
        try:
            main_logger.info(f"Starting ZAP scan for {target}")
            
            # Step 1: Spider the target
            spider_id = await self._start_spider(target)
            if spider_id:
                await self._wait_for_spider(spider_id)
            
            # Step 2: Start active scan
            scan_id = await self._start_active_scan(target)
            if scan_id:
                await self._wait_for_scan(scan_id)
            
            # Step 3: Get results
            results = await self._get_scan_results(target)
            return results
            
        except Exception as e:
            main_logger.error(f"ZAP scan failed for {target}: {e}")
            return []
    
    async def _start_spider(self, target: str) -> Optional[str]:
        """Start ZAP spider scan"""
        try:
            url = f"http://{self.zap_host}:{self.zap_port}/JSON/spider/action/scan/"
            params = {
                'url': target,
                'recurse': 'true',
                'inScopeOnly': 'false'
            }
            
            if self.zap_api_key:
                params['apikey'] = self.zap_api_key
            
            response = requests.get(url, params=params, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            spider_id = data.get('scan')
            
            if spider_id:
                main_logger.info(f"Started ZAP spider scan {spider_id} for {target}")
                return spider_id
            
            return None
            
        except Exception as e:
            main_logger.error(f"Failed to start ZAP spider: {e}")
            return None
    
    async def _wait_for_spider(self, spider_id: str):
        """Wait for spider scan to complete"""
        try:
            start_time = time.time()
            
            while time.time() - start_time < self.spider_timeout:
                url = f"http://{self.zap_host}:{self.zap_port}/JSON/spider/view/status/"
                params = {'scanId': spider_id}
                
                if self.zap_api_key:
                    params['apikey'] = self.zap_api_key
                
                response = requests.get(url, params=params, timeout=30)
                response.raise_for_status()
                
                data = response.json()
                status = int(data.get('status', 0))
                
                if status >= 100:
                    main_logger.info(f"ZAP spider scan {spider_id} completed")
                    break
                
                await asyncio.sleep(5)
            
        except Exception as e:
            main_logger.error(f"Error waiting for ZAP spider: {e}")
    
    async def _start_active_scan(self, target: str) -> Optional[str]:
        """Start ZAP active scan"""
        try:
            url = f"http://{self.zap_host}:{self.zap_port}/JSON/ascan/action/scan/"
            params = {
                'url': target,
                'recurse': 'true',
                'inScopeOnly': 'false'
            }
            
            if self.zap_api_key:
                params['apikey'] = self.zap_api_key
            
            response = requests.get(url, params=params, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            scan_id = data.get('scan')
            
            if scan_id:
                main_logger.info(f"Started ZAP active scan {scan_id} for {target}")
                return scan_id
            
            return None
            
        except Exception as e:
            main_logger.error(f"Failed to start ZAP active scan: {e}")
            return None
    
    async def _wait_for_scan(self, scan_id: str):
        """Wait for active scan to complete"""
        try:
            start_time = time.time()
            
            while time.time() - start_time < self.scan_timeout:
                url = f"http://{self.zap_host}:{self.zap_port}/JSON/ascan/view/status/"
                params = {'scanId': scan_id}
                
                if self.zap_api_key:
                    params['apikey'] = self.zap_api_key
                
                response = requests.get(url, params=params, timeout=30)
                response.raise_for_status()
                
                data = response.json()
                status = int(data.get('status', 0))
                
                if status >= 100:
                    main_logger.info(f"ZAP active scan {scan_id} completed")
                    break
                
                await asyncio.sleep(10)
            
        except Exception as e:
            main_logger.error(f"Error waiting for ZAP active scan: {e}")
    
    async def _get_scan_results(self, target: str) -> List[VulnerabilityResult]:
        """Get ZAP scan results"""
        try:
            url = f"http://{self.zap_host}:{self.zap_port}/JSON/core/view/alerts/"
            params = {'baseurl': target}
            
            if self.zap_api_key:
                params['apikey'] = self.zap_api_key
            
            response = requests.get(url, params=params, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            alerts = data.get('alerts', [])
            
            results = []
            for alert in alerts:
                vuln_result = self._convert_zap_alert(alert, target)
                if vuln_result:
                    results.append(vuln_result)
            
            return results
            
        except Exception as e:
            main_logger.error(f"Failed to get ZAP results: {e}")
            return []
    
    def _convert_zap_alert(self, alert: Dict[str, Any], target: str) -> Optional[VulnerabilityResult]:
        """Convert ZAP alert to VulnerabilityResult"""
        try:
            alert_name = alert.get('alert', '')
            risk = alert.get('risk', 'Medium')
            confidence = alert.get('confidence', 'Medium')
            description = alert.get('description', '')
            solution = alert.get('solution', '')
            reference = alert.get('reference', '')
            url = alert.get('url', target)
            param = alert.get('param', '')
            evidence = alert.get('evidence', '')
            
            # Map ZAP risk levels to our severity
            risk_map = {
                'High': VulnerabilitySeverity.HIGH,
                'Medium': VulnerabilitySeverity.MEDIUM,
                'Low': VulnerabilitySeverity.LOW,
                'Informational': VulnerabilitySeverity.INFO
            }
            
            severity = risk_map.get(risk, VulnerabilitySeverity.MEDIUM)
            
            # Map confidence to our confidence score
            confidence_map = {
                'High': 0.9,
                'Medium': 0.7,
                'Low': 0.5,
                'False Positive': 0.1
            }
            
            confidence_score = confidence_map.get(confidence, 0.7)
            
            # Determine if verified based on confidence
            verified = confidence in ['High', 'Medium']
            
            return VulnerabilityResult(
                title=alert_name,
                severity=severity,
                vulnerability_type=alert_name,
                target=target,
                description=description,
                url=url,
                parameter=param if param else None,
                evidence=evidence if evidence else None,
                solution=solution if solution else None,
                reference_urls=[reference] if reference else [],
                verified=verified,
                confidence=confidence_score,
                metadata={
                    "zap_risk": risk,
                    "zap_confidence": confidence,
                    "zap_evidence": evidence,
                    "raw_alert": alert
                }
            )
            
        except Exception as e:
            main_logger.debug(f"Failed to convert ZAP alert: {e}")
            return None


class ZAPHeadlessScanner(BaseVulnerabilityScanner):
    """ZAP Baseline scanner for headless operation"""
    
    def __init__(self):
        super().__init__("zap_baseline", "OWASP ZAP Baseline Scanner (headless)")
        self.timeout = 600  # 10 minutes
    
    async def scan(self, targets: List[str], **kwargs) -> List[VulnerabilityResult]:
        """Run ZAP baseline scan"""
        if not ToolValidator.check_tool('zap-baseline.py')['available']:
            if not ToolValidator.check_tool('docker')['available']:
                raise Exception("ZAP baseline requires either zap-baseline.py or Docker")
            return await self._scan_with_docker(targets, **kwargs)
        else:
            return await self._scan_with_baseline(targets, **kwargs)
    
    async def _scan_with_baseline(self, targets: List[str], **kwargs) -> List[VulnerabilityResult]:
        """Scan using zap-baseline.py script"""
        all_results = []
        
        for target in targets:
            try:
                # Create temporary file for results
                import tempfile
                with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as f:
                    results_file = f.name
                
                cmd = [
                    "zap-baseline.py",
                    "-t", target,
                    "-J", results_file,
                    "-a"  # Include the alpha active and passive scan rules
                ]
                
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=self.timeout
                )
                
                # Parse results
                results = await self._parse_baseline_results(results_file, target)
                all_results.extend(results)
                
                # Clean up
                Path(results_file).unlink(missing_ok=True)
                
            except Exception as e:
                main_logger.error(f"ZAP baseline scan failed for {target}: {e}")
        
        return all_results
    
    async def _scan_with_docker(self, targets: List[str], **kwargs) -> List[VulnerabilityResult]:
        """Scan using Docker ZAP container"""
        all_results = []
        
        for target in targets:
            try:
                import tempfile
                with tempfile.TemporaryDirectory() as temp_dir:
                    results_file = Path(temp_dir) / "baseline_report.json"
                    
                    cmd = [
                        "docker", "run", "--rm",
                        "-v", f"{temp_dir}:/zap/wrk/:rw",
                        "owasp/zap2docker-stable",
                        "zap-baseline.py",
                        "-t", target,
                        "-J", "baseline_report.json"
                    ]
                    
                    process = await asyncio.create_subprocess_exec(
                        *cmd,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )
                    
                    stdout, stderr = await asyncio.wait_for(
                        process.communicate(),
                        timeout=self.timeout
                    )
                    
                    # Parse results
                    results = await self._parse_baseline_results(str(results_file), target)
                    all_results.extend(results)
                
            except Exception as e:
                main_logger.error(f"ZAP Docker baseline scan failed for {target}: {e}")
        
        return all_results
    
    async def _parse_baseline_results(self, results_file: str, target: str) -> List[VulnerabilityResult]:
        """Parse ZAP baseline JSON results"""
        results = []
        results_path = Path(results_file)
        
        if not results_path.exists():
            return results
        
        try:
            with results_path.open('r', encoding='utf-8') as f:
                data = json.load(f)
            
            # ZAP baseline results have site -> alerts structure
            site_data = data.get('site', [])
            if site_data:
                alerts = site_data[0].get('alerts', [])
                
                zap_scanner = ZAPScanner()
                for alert in alerts:
                    vuln_result = zap_scanner._convert_zap_alert(alert, target)
                    if vuln_result:
                        results.append(vuln_result)
        
        except Exception as e:
            main_logger.error(f"Failed to parse ZAP baseline results: {e}")
        
        return results


def get_zap_scanners(config: Dict[str, Any] = None) -> List[BaseVulnerabilityScanner]:
    """Get configured ZAP scanners"""
    config = config or {}
    scanners = []
    
    # ZAP Proxy scanner (requires running ZAP instance)
    if config.get('zap_proxy_enabled', False):
        proxy_scanner = ZAPScanner(
            zap_proxy_host=config.get('zap_host', '127.0.0.1'),
            zap_proxy_port=config.get('zap_port', 8080)
        )
        proxy_scanner.configure(config)
        scanners.append(proxy_scanner)
    
    # ZAP Baseline scanner (headless)
    baseline_scanner = ZAPHeadlessScanner()
    baseline_scanner.configure(config)
    scanners.append(baseline_scanner)
    
    return scanners