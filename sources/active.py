import asyncio
import subprocess
import socket
import dns.resolver
from typing import List, Dict, Optional
from pathlib import Path

from sources.base import ActiveSource, SubdomainResult
from utils.logging import main_logger
from utils.helpers import NetworkHelper, FileHelper, ToolValidator


class DNSBruteforceSource(ActiveSource):
    """DNS brute force subdomain discovery"""
    
    def __init__(self, wordlist_path: str = None, threads: int = 100):
        super().__init__("dns_brute", "DNS brute force subdomain enumeration", wordlist_path)
        self.threads = threads
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 3
        self.resolver.lifetime = 3
    
    async def discover(self, target: str, **kwargs) -> List[SubdomainResult]:
        """Perform DNS brute force discovery"""
        wordlist = self.load_wordlist(kwargs.get('wordlist_path'))
        
        if not wordlist:
            raise Exception("No wordlist available for DNS brute force")
        
        main_logger.info(f"Starting DNS brute force with {len(wordlist)} words")
        
        # Create semaphore to limit concurrent DNS queries
        semaphore = asyncio.Semaphore(self.threads)
        
        # Create tasks for all subdomain checks
        tasks = [
            self._check_subdomain(semaphore, word, target)
            for word in wordlist
        ]
        
        # Execute all tasks
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filter successful results
        valid_results = []
        for result in results:
            if isinstance(result, SubdomainResult):
                valid_results.append(result)
            elif isinstance(result, Exception):
                main_logger.debug(f"DNS query failed: {result}")
        
        main_logger.success(f"DNS brute force completed: {len(valid_results)} subdomains found")
        return valid_results
    
    async def _check_subdomain(self, semaphore: asyncio.Semaphore, 
                              prefix: str, target: str) -> Optional[SubdomainResult]:
        """Check if subdomain exists via DNS"""
        async with semaphore:
            subdomain = f"{prefix}.{target}"
            
            try:
                # Try A record first
                answers = self.resolver.resolve(subdomain, 'A')
                ip_addresses = [str(answer) for answer in answers]
                
                return SubdomainResult(
                    subdomain=subdomain,
                    source=self.name,
                    ip_address=ip_addresses[0] if ip_addresses else None,
                    confidence=0.95,
                    metadata={
                        "method": "dns_brute_force",
                        "record_type": "A",
                        "all_ips": ip_addresses
                    }
                )
                
            except dns.resolver.NXDOMAIN:
                return None
            except Exception as e:
                main_logger.debug(f"DNS error for {subdomain}: {e}")
                return None


class ShuffleDNSSource(ActiveSource):
    """ShuffleDNS-based subdomain discovery"""
    
    def __init__(self, wordlist_path: str = None, resolvers_file: str = None):
        super().__init__("shuffledns", "Mass DNS resolution with shuffledns", wordlist_path)
        self.resolvers_file = resolvers_file
    
    async def discover(self, target: str, **kwargs) -> List[SubdomainResult]:
        """Run shuffledns discovery"""
        wordlist_path = kwargs.get('wordlist_path', self.wordlist_path)
        
        if not wordlist_path:
            # Create temporary wordlist
            wordlist = self.load_wordlist()
            temp_wordlist = Path(f"/tmp/reconforge_wordlist_{target}.txt")
            FileHelper.write_results(wordlist, temp_wordlist)
            wordlist_path = str(temp_wordlist)
        
        cmd = [
            "shuffledns", 
            "-d", target,
            "-w", wordlist_path,
            "-silent"
        ]
        
        if self.resolvers_file:
            cmd.extend(["-r", self.resolvers_file])
        
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                raise Exception(f"ShuffleDNS failed: {stderr.decode()}")
            
            # Parse shuffledns output (format: subdomain [ip])
            lines = stdout.decode().strip().split('\n')
            results = []
            
            for line in lines:
                if not line.strip():
                    continue
                
                # Parse format: "subdomain.example.com [1.2.3.4]"
                if '[' in line and ']' in line:
                    subdomain = line.split('[')[0].strip()
                    ip = line.split('[')[1].split(']')[0].strip()
                else:
                    subdomain = line.strip()
                    ip = None
                
                if subdomain and self.validate_target(subdomain):
                    results.append(SubdomainResult(
                        subdomain=subdomain,
                        source=self.name,
                        ip_address=ip,
                        confidence=0.95,
                        metadata={"tool": "shuffledns", "method": "dns_resolution"}
                    ))
            
            # Clean up temporary wordlist
            if 'temp_wordlist' in locals():
                temp_wordlist.unlink(missing_ok=True)
            
            return results
            
        except Exception as e:
            main_logger.error(f"ShuffleDNS discovery failed: {e}")
            raise


class GobusterSource(ActiveSource):
    """Gobuster DNS mode for subdomain discovery"""
    
    def __init__(self, wordlist_path: str = None, threads: int = 50):
        super().__init__("gobuster_dns", "Gobuster DNS mode subdomain enumeration", wordlist_path)
        self.threads = threads
    
    async def discover(self, target: str, **kwargs) -> List[SubdomainResult]:
        """Run gobuster in DNS mode"""
        wordlist_path = kwargs.get('wordlist_path', self.wordlist_path)
        
        if not wordlist_path:
            # Use default wordlist
            wordlist = self.load_wordlist()
            temp_wordlist = Path(f"/tmp/reconforge_gobuster_{target}.txt")
            FileHelper.write_results(wordlist, temp_wordlist)
            wordlist_path = str(temp_wordlist)
        
        cmd = [
            "gobuster", "dns",
            "-d", target,
            "-w", wordlist_path,
            "-t", str(self.threads),
            "--no-color",
            "-q"  # quiet mode
        ]
        
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                raise Exception(f"Gobuster failed: {stderr.decode()}")
            
            # Parse gobuster output
            lines = stdout.decode().strip().split('\n')
            results = []
            
            for line in lines:
                if not line.strip() or 'Found:' not in line:
                    continue
                
                # Extract subdomain from "Found: subdomain.example.com"
                parts = line.split('Found:')
                if len(parts) > 1:
                    subdomain = parts[1].strip()
                    if self.validate_target(subdomain):
                        # Resolve IP for the subdomain
                        ip = await self._resolve_ip(subdomain)
                        
                        results.append(SubdomainResult(
                            subdomain=subdomain,
                            source=self.name,
                            ip_address=ip,
                            confidence=0.9,
                            metadata={"tool": "gobuster", "mode": "dns"}
                        ))
            
            # Clean up temporary wordlist
            if 'temp_wordlist' in locals():
                temp_wordlist.unlink(missing_ok=True)
            
            return results
            
        except Exception as e:
            main_logger.error(f"Gobuster DNS discovery failed: {e}")
            raise
    
    async def _resolve_ip(self, domain: str) -> Optional[str]:
        """Resolve domain to IP address"""
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 3
            answers = resolver.resolve(domain, 'A')
            return str(answers[0])
        except:
            return None


class PureDNSSource(ActiveSource):
    """PureDNS-based subdomain discovery"""
    
    def __init__(self, wordlist_path: str = None, resolvers_file: str = None):
        super().__init__("puredns", "Fast domain resolver and subdomain bruteforcer", wordlist_path)
        self.resolvers_file = resolvers_file
    
    async def discover(self, target: str, **kwargs) -> List[SubdomainResult]:
        """Run puredns brute force"""
        wordlist_path = kwargs.get('wordlist_path', self.wordlist_path)
        
        if not wordlist_path:
            wordlist = self.load_wordlist()
            temp_wordlist = Path(f"/tmp/reconforge_puredns_{target}.txt")
            FileHelper.write_results(wordlist, temp_wordlist)
            wordlist_path = str(temp_wordlist)
        
        cmd = [
            "puredns", "bruteforce",
            wordlist_path,
            target,
            "--quiet"
        ]
        
        if self.resolvers_file:
            cmd.extend(["--resolvers", self.resolvers_file])
        
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                raise Exception(f"PureDNS failed: {stderr.decode()}")
            
            subdomains = stdout.decode().strip().split('\n')
            filtered = self.filter_results(subdomains, target)
            
            # Resolve IPs for found subdomains
            results = []
            for subdomain in filtered:
                ip = await self._resolve_ip(subdomain)
                results.append(SubdomainResult(
                    subdomain=subdomain,
                    source=self.name,
                    ip_address=ip,
                    confidence=0.95,
                    metadata={"tool": "puredns", "method": "bruteforce"}
                ))
            
            # Clean up temporary wordlist
            if 'temp_wordlist' in locals():
                temp_wordlist.unlink(missing_ok=True)
            
            return results
            
        except Exception as e:
            main_logger.error(f"PureDNS discovery failed: {e}")
            raise
    
    async def _resolve_ip(self, domain: str) -> Optional[str]:
        """Resolve domain to IP address"""
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 2
            answers = resolver.resolve(domain, 'A')
            return str(answers[0])
        except:
            return None


class MassDNSSource(ActiveSource):
    """MassDNS-based subdomain discovery"""
    
    def __init__(self, wordlist_path: str = None, resolvers_file: str = None):
        super().__init__("massdns", "High-performance DNS stub resolver", wordlist_path)
        self.resolvers_file = resolvers_file or "/opt/massdns/lists/resolvers.txt"
    
    async def discover(self, target: str, **kwargs) -> List[SubdomainResult]:
        """Run massdns discovery"""
        wordlist_path = kwargs.get('wordlist_path', self.wordlist_path)
        
        if not wordlist_path:
            wordlist = self.load_wordlist()
            temp_wordlist = Path(f"/tmp/reconforge_massdns_{target}.txt")
            # Create full subdomain list for massdns
            subdomains = [f"{word}.{target}" for word in wordlist]
            FileHelper.write_results(subdomains, temp_wordlist)
            wordlist_path = str(temp_wordlist)
        
        output_file = f"/tmp/massdns_output_{target}.txt"
        
        cmd = [
            "massdns",
            "-r", self.resolvers_file,
            "-t", "A",
            "-o", "S",
            "-w", output_file,
            wordlist_path
        ]
        
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                raise Exception(f"MassDNS failed: {stderr.decode()}")
            
            # Parse massdns output
            results = []
            output_path = Path(output_file)
            
            if output_path.exists():
                with output_path.open('r') as f:
                    for line in f:
                        parts = line.strip().split()
                        if len(parts) >= 3 and parts[1] == 'A':
                            subdomain = parts[0].rstrip('.')
                            ip = parts[2]
                            
                            if self.validate_target(subdomain):
                                results.append(SubdomainResult(
                                    subdomain=subdomain,
                                    source=self.name,
                                    ip_address=ip,
                                    confidence=0.95,
                                    metadata={"tool": "massdns", "record_type": "A"}
                                ))
                
                # Clean up output file
                output_path.unlink(missing_ok=True)
            
            # Clean up temporary wordlist
            if 'temp_wordlist' in locals():
                temp_wordlist.unlink(missing_ok=True)
            
            return results
            
        except Exception as e:
            main_logger.error(f"MassDNS discovery failed: {e}")
            raise


class DNSReconSource(ActiveSource):
    """DNSRecon-based subdomain discovery"""
    
    def __init__(self, wordlist_path: str = None):
        super().__init__("dnsrecon", "DNS enumeration and network mapping", wordlist_path)
    
    async def discover(self, target: str, **kwargs) -> List[SubdomainResult]:
        """Run dnsrecon discovery"""
        cmd = [
            "dnsrecon",
            "-d", target,
            "-t", "brt",  # Brute force
            "--lifetime", "3",
            "--json", f"/tmp/dnsrecon_{target}.json"
        ]
        
        wordlist_path = kwargs.get('wordlist_path', self.wordlist_path)
        if wordlist_path:
            cmd.extend(["-D", wordlist_path])
        
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            # Parse JSON output
            import json
            json_file = Path(f"/tmp/dnsrecon_{target}.json")
            results = []
            
            if json_file.exists():
                try:
                    with json_file.open('r') as f:
                        data = json.load(f)
                    
                    for record in data:
                        if record.get('type') == 'A':
                            subdomain = record.get('name', '').rstrip('.')
                            ip = record.get('address')
                            
                            if subdomain and self.validate_target(subdomain):
                                results.append(SubdomainResult(
                                    subdomain=subdomain,
                                    source=self.name,
                                    ip_address=ip,
                                    confidence=0.9,
                                    metadata={"tool": "dnsrecon", "record_type": "A"}
                                ))
                
                except json.JSONDecodeError:
                    pass
                
                # Clean up JSON file
                json_file.unlink(missing_ok=True)
            
            return results
            
        except Exception as e:
            main_logger.error(f"DNSRecon discovery failed: {e}")
            raise


def get_active_sources(config: Dict[str, any] = None) -> List[ActiveSource]:
    """Get all available active sources with configuration"""
    config = config or {}
    
    sources = []
    
    # Built-in DNS brute force (always available)
    sources.append(DNSBruteforceSource(
        wordlist_path=config.get('wordlist_path'),
        threads=config.get('dns_threads', 100)
    ))
    
    # Tool-dependent sources
    if ToolValidator.check_tool('shuffledns')['available']:
        sources.append(ShuffleDNSSource(
            wordlist_path=config.get('wordlist_path'),
            resolvers_file=config.get('resolvers_file')
        ))
    
    if ToolValidator.check_tool('gobuster')['available']:
        sources.append(GobusterSource(
            wordlist_path=config.get('wordlist_path'),
            threads=config.get('gobuster_threads', 50)
        ))
    
    if ToolValidator.check_tool('puredns')['available']:
        sources.append(PureDNSSource(
            wordlist_path=config.get('wordlist_path'),
            resolvers_file=config.get('resolvers_file')
        ))
    
    if ToolValidator.check_tool('massdns')['available']:
        sources.append(MassDNSSource(
            wordlist_path=config.get('wordlist_path'),
            resolvers_file=config.get('resolvers_file')
        ))
    
    if ToolValidator.check_tool('dnsrecon')['available']:
        sources.append(DNSReconSource(
            wordlist_path=config.get('wordlist_path')
        ))
    
    return sources