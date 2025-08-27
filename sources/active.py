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


class FFuFSource(ActiveSource):
    """FFuF-based subdomain discovery"""
    
    def __init__(self, wordlist_path: str = None, threads: int = 40):
        super().__init__("ffuf", "Fast web fuzzer for subdomain discovery", wordlist_path)
        self.threads = threads
    
    async def discover(self, target: str, **kwargs) -> List[SubdomainResult]:
        """Run FFuF for subdomain discovery via virtual host fuzzing"""
        wordlist_path = kwargs.get('wordlist_path', self.wordlist_path)
        
        if not wordlist_path:
            wordlist = self.load_wordlist()
            temp_wordlist = Path(f"/tmp/reconforge_ffuf_{target}.txt")
            FileHelper.write_results(wordlist, temp_wordlist)
            wordlist_path = str(temp_wordlist)
        
        output_file = f"/tmp/ffuf_output_{target}.json"
        
        cmd = [
            "ffuf",
            "-u", f"http://FUZZ.{target}",
            "-w", wordlist_path,
            "-t", str(self.threads),
            "-fc", "404",  # Filter common 404s
            "-fs", "0",    # Filter size 0 responses
            "-o", output_file,
            "-of", "json",
            "-silent"
        ]
        
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                raise Exception(f"FFuF failed: {stderr.decode()}")
            
            # Parse FFuF JSON output
            results = []
            output_path = Path(output_file)
            
            if output_path.exists():
                try:
                    with output_path.open('r') as f:
                        data = json.loads(f.read())
                    
                    for result in data.get('results', []):
                        url = result.get('url', '')
                        status_code = result.get('status', 0)
                        content_length = result.get('length', 0)
                        
                        if url and status_code in [200, 301, 302, 403]:
                            from urllib.parse import urlparse
                            parsed = urlparse(url)
                            subdomain = parsed.hostname
                            
                            if subdomain and self.validate_target(subdomain):
                                # Resolve IP for the subdomain
                                ip = await self._resolve_ip(subdomain)
                                
                                results.append(SubdomainResult(
                                    subdomain=subdomain,
                                    source=self.name,
                                    ip_address=ip,
                                    confidence=0.85,
                                    metadata={
                                        "tool": "ffuf", 
                                        "status_code": status_code,
                                        "content_length": content_length,
                                        "url": url
                                    }
                                ))
                
                except json.JSONDecodeError:
                    pass
                
                # Clean up output file
                output_path.unlink(missing_ok=True)
            
            # Clean up temporary wordlist
            if 'temp_wordlist' in locals():
                temp_wordlist.unlink(missing_ok=True)
            
            return results
            
        except Exception as e:
            main_logger.error(f"FFuF discovery failed: {e}")
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


class AlterationSource(ActiveSource):
    """DNS alteration-based subdomain discovery"""
    
    def __init__(self, wordlist_path: str = None):
        super().__init__("alteration", "DNS alteration-based subdomain discovery", wordlist_path)
        self.alterations = [
            'www', 'mail', 'email', 'webmail', 'secure', 'docs', 'admin', 'test',
            'staging', 'dev', 'development', 'prod', 'production', 'demo', 'api',
            'mobile', 'm', 'blog', 'news', 'shop', 'store', 'ftp', 'vpn',
            'remote', 'portal', 'support', 'help', 'app', 'apps', 'cdn',
            'static', 'assets', 'img', 'images', 'file', 'files', 'download',
            'upload', 'media', 'video', 'audio', 'stream', 'live', 'chat'
        ]
    
    async def discover(self, target: str, **kwargs) -> List[SubdomainResult]:
        """Discover subdomains using alteration patterns"""
        results = []
        
        # Create semaphore to limit concurrent DNS queries
        semaphore = asyncio.Semaphore(50)
        
        # Get base subdomain patterns from existing subdomains (if provided)
        known_subdomains = kwargs.get('known_subdomains', [])
        test_candidates = set()
        
        # Add basic alterations
        for alt in self.alterations:
            test_candidates.add(f"{alt}.{target}")
        
        # Add number-based alterations
        for i in range(1, 11):
            test_candidates.add(f"www{i}.{target}")
            test_candidates.add(f"mail{i}.{target}")
            test_candidates.add(f"test{i}.{target}")
        
        # Add geographic alterations
        geos = ['us', 'eu', 'asia', 'uk', 'ca', 'au', 'de', 'fr', 'jp', 'cn']
        for geo in geos:
            test_candidates.add(f"{geo}.{target}")
            test_candidates.add(f"www-{geo}.{target}")
        
        # If we have known subdomains, generate variations
        for subdomain in known_subdomains:
            if target in subdomain:
                prefix = subdomain.replace(f".{target}", "")
                if prefix:
                    # Add numbered variants
                    for i in range(1, 6):
                        test_candidates.add(f"{prefix}{i}.{target}")
                    
                    # Add common suffixes
                    for suffix in ['new', 'old', 'backup', 'test', 'dev', 'prod']:
                        test_candidates.add(f"{prefix}-{suffix}.{target}")
        
        # Create tasks for all subdomain checks
        tasks = [
            self._check_subdomain_alteration(semaphore, candidate)
            for candidate in test_candidates
        ]
        
        # Execute all tasks
        task_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filter successful results
        for result in task_results:
            if isinstance(result, SubdomainResult):
                results.append(result)
            elif isinstance(result, Exception):
                main_logger.debug(f"Alteration DNS query failed: {result}")
        
        return results
    
    async def _check_subdomain_alteration(self, semaphore: asyncio.Semaphore, 
                                        subdomain: str) -> Optional[SubdomainResult]:
        """Check if alteration subdomain exists via DNS"""
        async with semaphore:
            try:
                resolver = dns.resolver.Resolver()
                resolver.timeout = 3
                resolver.lifetime = 3
                
                # Try A record first
                answers = resolver.resolve(subdomain, 'A')
                ip_addresses = [str(answer) for answer in answers]
                
                return SubdomainResult(
                    subdomain=subdomain,
                    source=self.name,
                    ip_address=ip_addresses[0] if ip_addresses else None,
                    confidence=0.9,
                    metadata={
                        "method": "dns_alteration",
                        "record_type": "A",
                        "all_ips": ip_addresses
                    }
                )
                
            except dns.resolver.NXDOMAIN:
                return None
            except Exception as e:
                main_logger.debug(f"DNS alteration error for {subdomain}: {e}")
                return None


class PermutationSource(ActiveSource):
    """DNS permutation-based subdomain discovery"""
    
    def __init__(self, wordlist_path: str = None):
        super().__init__("permutation", "DNS permutation-based subdomain discovery", wordlist_path)
    
    async def discover(self, target: str, **kwargs) -> List[SubdomainResult]:
        """Discover subdomains using permutation techniques"""
        # Use dnstwist if available
        if ToolValidator.check_tool('dnstwist')['available']:
            return await self._discover_with_dnstwist(target)
        else:
            return await self._discover_with_manual_permutation(target)
    
    async def _discover_with_dnstwist(self, target: str) -> List[SubdomainResult]:
        """Use dnstwist for domain permutation"""
        cmd = ["dnstwist", "--format", "json", target]
        
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                raise Exception(f"dnstwist failed: {stderr.decode()}")
            
            # Parse dnstwist JSON output
            results = []
            try:
                data = json.loads(stdout.decode())
                for entry in data:
                    domain_name = entry.get('domain-name', '')
                    dns_a = entry.get('dns-a', [])
                    fuzzer = entry.get('fuzzer', '')
                    
                    if domain_name and dns_a and domain_name != target:
                        results.append(SubdomainResult(
                            subdomain=domain_name,
                            source=self.name,
                            ip_address=dns_a[0] if dns_a else None,
                            confidence=0.8,
                            metadata={
                                "tool": "dnstwist",
                                "fuzzer": fuzzer,
                                "all_ips": dns_a
                            }
                        ))
            
            except json.JSONDecodeError:
                pass
            
            return results
            
        except Exception as e:
            main_logger.error(f"dnstwist discovery failed: {e}")
            raise
    
    async def _discover_with_manual_permutation(self, target: str) -> List[SubdomainResult]:
        """Manual domain permutation when dnstwist is not available"""
        results = []
        domain_parts = target.split('.')
        
        if len(domain_parts) < 2:
            return results
        
        base_domain = '.'.join(domain_parts[-2:])  # Last two parts (domain.tld)
        
        # Common character substitutions and additions
        char_subs = {
            'o': ['0'], 'i': ['1'], 'l': ['1'], 'e': ['3'], 'a': ['@'],
            's': ['$'], 'g': ['9'], 'b': ['6'], 't': ['7']
        }
        
        # Generate permutations
        permutations = set()
        
        # Character substitution
        for char, subs in char_subs.items():
            if char in base_domain:
                for sub in subs:
                    permutations.add(base_domain.replace(char, sub))
        
        # Character insertion
        common_inserts = ['-', '1', '2', '0', 'x']
        for insert in common_inserts:
            domain_name = domain_parts[-2]
            # Insert at various positions
            for i in range(len(domain_name) + 1):
                new_name = domain_name[:i] + insert + domain_name[i:]
                permutations.add(f"{new_name}.{domain_parts[-1]}")
        
        # Test permutations
        semaphore = asyncio.Semaphore(30)
        tasks = [
            self._check_permutation(semaphore, perm)
            for perm in permutations
        ]
        
        task_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in task_results:
            if isinstance(result, SubdomainResult):
                results.append(result)
        
        return results
    
    async def _check_permutation(self, semaphore: asyncio.Semaphore, 
                                domain: str) -> Optional[SubdomainResult]:
        """Check if permutated domain exists"""
        async with semaphore:
            try:
                resolver = dns.resolver.Resolver()
                resolver.timeout = 3
                
                answers = resolver.resolve(domain, 'A')
                ip_addresses = [str(answer) for answer in answers]
                
                return SubdomainResult(
                    subdomain=domain,
                    source=self.name,
                    ip_address=ip_addresses[0] if ip_addresses else None,
                    confidence=0.7,
                    metadata={
                        "method": "dns_permutation",
                        "record_type": "A",
                        "all_ips": ip_addresses
                    }
                )
                
            except (dns.resolver.NXDOMAIN, Exception):
                return None


def get_active_sources(config: Dict[str, any] = None) -> List[ActiveSource]:
    """Get all available active sources with configuration"""
    config = config or {}
    
    sources = []
    
    # Built-in DNS brute force (always available)
    sources.append(DNSBruteforceSource(
        wordlist_path=config.get('wordlist_path'),
        threads=config.get('dns_threads', 100)
    ))
    
    # Built-in alteration and permutation sources (always available)
    sources.append(AlterationSource(wordlist_path=config.get('wordlist_path')))
    sources.append(PermutationSource(wordlist_path=config.get('wordlist_path')))
    
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
    
    if ToolValidator.check_tool('ffuf')['available']:
        sources.append(FFuFSource(
            wordlist_path=config.get('wordlist_path'),
            threads=config.get('ffuf_threads', 40)
        ))
    
    return sources