import asyncio
import subprocess
import json
import tempfile
from pathlib import Path
from typing import List, Dict, Optional, Any

from scanners.base import BaseVulnerabilityScanner, VulnerabilityResult, VulnerabilitySeverity
from utils.logging import main_logger
from utils.helpers import FileHelper, ToolValidator


class NucleiScanner(BaseVulnerabilityScanner):
    """Nuclei vulnerability scanner integration"""
    
    def __init__(self, templates_path: str = None, custom_templates: List[str] = None):
        super().__init__("nuclei", "Fast and customizable vulnerability scanner")
        self.templates_path = templates_path
        self.custom_templates = custom_templates or []
        self.rate_limit = 150  # requests per second
        self.timeout = 10
        self.retries = 1
        self.severity_filter = ["critical", "high", "medium", "low", "info"]
    
    def configure(self, config: Dict[str, Any]):
        """Configure Nuclei scanner"""
        super().configure(config)
        
        if 'rate_limit' in config:
            self.rate_limit = config['rate_limit']
        if 'timeout' in config:
            self.timeout = config['timeout']
        if 'severity_filter' in config:
            self.severity_filter = config['severity_filter']
        if 'templates_path' in config:
            self.templates_path = config['templates_path']
        if 'custom_templates' in config:
            self.custom_templates = config['custom_templates']
    
    async def scan(self, targets: List[str], **kwargs) -> List[VulnerabilityResult]:
        """Run Nuclei scan on targets"""
        if not ToolValidator.check_tool('nuclei')['available']:
            raise Exception("Nuclei is not installed or not available")
        
        # Create temporary files for targets and results
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as targets_file:
            for target in targets:
                targets_file.write(f"{target}\n")
            targets_file_path = targets_file.name
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as results_file:
            results_file_path = results_file.name
        
        try:
            # Build Nuclei command
            cmd = [
                "nuclei",
                "-l", targets_file_path,
                "-json",
                "-o", results_file_path,
                "-rate-limit", str(self.rate_limit),
                "-timeout", str(self.timeout),
                "-retries", str(self.retries),
                "-no-color",
                "-silent"
            ]
            
            # Add severity filter
            if self.severity_filter:
                cmd.extend(["-severity", ",".join(self.severity_filter)])
            
            # Add template configuration
            if self.templates_path:
                cmd.extend(["-t", self.templates_path])
            elif self.custom_templates:
                for template in self.custom_templates:
                    cmd.extend(["-t", template])
            else:
                # Use default templates
                cmd.append("-tags")
                cmd.append("cve,oast,default")
            
            # Add additional options from kwargs
            if kwargs.get('exclude_tags'):
                cmd.extend(["-exclude-tags", kwargs['exclude_tags']])
            
            if kwargs.get('include_tags'):
                cmd.extend(["-include-tags", kwargs['include_tags']])
            
            if kwargs.get('template_id'):
                cmd.extend(["-template-id", kwargs['template_id']])
            
            if kwargs.get('author'):
                cmd.extend(["-author", kwargs['author']])
            
            # Run Nuclei
            main_logger.info(f"Running Nuclei scan with command: {' '.join(cmd)}")
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                error_msg = stderr.decode() if stderr else "Unknown error"
                main_logger.warning(f"Nuclei finished with return code {process.returncode}: {error_msg}")
            
            # Parse results
            results = await self._parse_nuclei_results(results_file_path)
            
            return results
            
        finally:
            # Clean up temporary files
            Path(targets_file_path).unlink(missing_ok=True)
            Path(results_file_path).unlink(missing_ok=True)
    
    async def _parse_nuclei_results(self, results_file: str) -> List[VulnerabilityResult]:
        """Parse Nuclei JSON output"""
        results = []
        results_path = Path(results_file)
        
        if not results_path.exists():
            main_logger.warning("Nuclei results file not found")
            return results
        
        try:
            with results_path.open('r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    
                    try:
                        result_data = json.loads(line)
                        vuln_result = self._convert_nuclei_result(result_data)
                        if vuln_result:
                            results.append(vuln_result)
                    except json.JSONDecodeError as e:
                        main_logger.debug(f"Failed to parse Nuclei result line: {e}")
                        continue
        
        except Exception as e:
            main_logger.error(f"Failed to parse Nuclei results: {e}")
        
        return results
    
    def _convert_nuclei_result(self, result_data: Dict[str, Any]) -> Optional[VulnerabilityResult]:
        """Convert Nuclei result to VulnerabilityResult"""
        try:
            # Extract basic information
            template_id = result_data.get("template-id", "")
            template_name = result_data.get("template", "")
            matched_at = result_data.get("matched-at", "")
            host = result_data.get("host", "")
            
            # Extract template info
            info = result_data.get("info", {})
            title = info.get("name", template_id)
            description = info.get("description", "")
            severity = info.get("severity", "info")
            tags = info.get("tags", [])
            author = info.get("author", [])
            reference = info.get("reference", [])
            
            # Extract matcher information
            matcher_name = result_data.get("matcher-name", "")
            matcher_status = result_data.get("matcher-status", True)
            
            # Extract request/response data if available
            curl_command = result_data.get("curl-command", "")
            extracted_results = result_data.get("extracted-results", [])
            
            # Map severity
            severity_map = {
                "critical": VulnerabilitySeverity.CRITICAL,
                "high": VulnerabilitySeverity.HIGH,
                "medium": VulnerabilitySeverity.MEDIUM,
                "low": VulnerabilitySeverity.LOW,
                "info": VulnerabilitySeverity.INFO
            }
            
            vuln_severity = severity_map.get(severity.lower(), VulnerabilitySeverity.INFO)
            
            # Determine vulnerability type from tags
            vuln_type = self._determine_vulnerability_type(tags, template_id)
            
            # Extract CVE if present
            cve_id = None
            for tag in tags:
                if tag.startswith("cve-"):
                    cve_id = tag.upper()
                    break
            
            # Calculate confidence based on matcher status and severity
            confidence = 1.0 if matcher_status else 0.8
            if severity == "info":
                confidence *= 0.7
            
            return VulnerabilityResult(
                title=title,
                severity=vuln_severity,
                vulnerability_type=vuln_type,
                target=host or matched_at,
                description=description,
                url=matched_at if matched_at.startswith('http') else None,
                template_id=template_id,
                cve_id=cve_id,
                reference_urls=reference if isinstance(reference, list) else [reference] if reference else [],
                verified=matcher_status,
                confidence=confidence,
                metadata={
                    "nuclei_template": template_name,
                    "matcher_name": matcher_name,
                    "tags": tags,
                    "author": author,
                    "curl_command": curl_command,
                    "extracted_results": extracted_results,
                    "raw_result": result_data
                }
            )
            
        except Exception as e:
            main_logger.debug(f"Failed to convert Nuclei result: {e}")
            return None
    
    def _determine_vulnerability_type(self, tags: List[str], template_id: str) -> str:
        """Determine vulnerability type from tags and template ID"""
        # Priority mapping for vulnerability types
        type_mappings = {
            "sqli": "SQL Injection",
            "xss": "Cross-Site Scripting",
            "lfi": "Local File Inclusion",
            "rfi": "Remote File Inclusion",
            "rce": "Remote Code Execution",
            "ssrf": "Server-Side Request Forgery",
            "xxe": "XML External Entity",
            "csrf": "Cross-Site Request Forgery",
            "idor": "Insecure Direct Object Reference",
            "auth-bypass": "Authentication Bypass",
            "info-disclosure": "Information Disclosure",
            "directory-traversal": "Directory Traversal",
            "file-upload": "File Upload Vulnerability",
            "subdomain-takeover": "Subdomain Takeover",
            "cve": "CVE",
            "misconfig": "Misconfiguration",
            "exposed": "Exposed Service",
            "default-login": "Default Credentials",
            "backup": "Backup File Exposure",
            "panel": "Admin Panel Discovery",
            "tech": "Technology Detection",
            "dns": "DNS Issue"
        }
        
        # Check tags first
        for tag in tags:
            tag_lower = tag.lower()
            for key, vuln_type in type_mappings.items():
                if key in tag_lower:
                    return vuln_type
        
        # Check template ID
        template_lower = template_id.lower()
        for key, vuln_type in type_mappings.items():
            if key in template_lower:
                return vuln_type
        
        return "Generic Vulnerability"
    
    async def update_templates(self) -> bool:
        """Update Nuclei templates"""
        try:
            main_logger.info("Updating Nuclei templates...")
            
            cmd = ["nuclei", "-update-templates", "-silent"]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                main_logger.success("Nuclei templates updated successfully")
                return True
            else:
                main_logger.error(f"Failed to update Nuclei templates: {stderr.decode()}")
                return False
                
        except Exception as e:
            main_logger.error(f"Failed to update Nuclei templates: {e}")
            return False
    
    def get_template_info(self) -> Dict[str, Any]:
        """Get information about available templates"""
        try:
            import subprocess
            result = subprocess.run(
                ["nuclei", "-tl"],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                templates = result.stdout.strip().split('\n')
                return {
                    'total_templates': len([t for t in templates if t.strip()]),
                    'templates_list': templates
                }
            else:
                return {'error': result.stderr}
                
        except Exception as e:
            return {'error': str(e)}


class CustomNucleiScanner(BaseVulnerabilityScanner):
    """Custom Nuclei scanner with specific template sets"""
    
    def __init__(self, name: str, description: str, templates: List[str], 
                 severity_filter: List[str] = None):
        super().__init__(name, description)
        self.templates = templates
        self.severity_filter = severity_filter or ["critical", "high", "medium"]
        self.nuclei_scanner = NucleiScanner()
    
    async def scan(self, targets: List[str], **kwargs) -> List[VulnerabilityResult]:
        """Run scan with custom templates"""
        # Configure the underlying Nuclei scanner
        config = {
            'custom_templates': self.templates,
            'severity_filter': self.severity_filter
        }
        config.update(kwargs)
        
        self.nuclei_scanner.configure(config)
        return await self.nuclei_scanner.scan(targets, **kwargs)


def get_nuclei_scanners(config: Dict[str, Any] = None) -> List[BaseVulnerabilityScanner]:
    """Get configured Nuclei scanners"""
    config = config or {}
    scanners = []
    
    # Main Nuclei scanner
    main_scanner = NucleiScanner(
        templates_path=config.get('templates_path'),
        custom_templates=config.get('custom_templates')
    )
    main_scanner.configure(config)
    scanners.append(main_scanner)
    
    # Web application focused scanner
    web_scanner = CustomNucleiScanner(
        name="nuclei_web",
        description="Nuclei web application vulnerability scanner",
        templates=["cves/", "vulnerabilities/", "misconfiguration/"],
        severity_filter=["critical", "high", "medium"]
    )
    scanners.append(web_scanner)
    
    # CVE focused scanner
    cve_scanner = CustomNucleiScanner(
        name="nuclei_cve",
        description="Nuclei CVE-focused scanner",
        templates=["cves/"],
        severity_filter=["critical", "high"]
    )
    scanners.append(cve_scanner)
    
    # Misconfiguration scanner
    misconfig_scanner = CustomNucleiScanner(
        name="nuclei_misconfig",
        description="Nuclei misconfiguration scanner",
        templates=["misconfiguration/", "exposed-panels/", "default-logins/"],
        severity_filter=["high", "medium", "low"]
    )
    scanners.append(misconfig_scanner)
    
    return scanners