#!/usr/bin/env python3
"""
ReconForge - Professional Penetration Testing Framework
Main CLI Interface

Usage:
    reconforge.py discover <target> [options]
    reconforge.py scan <target> [options] 
    reconforge.py pentest <target> [options]
    reconforge.py full <target> [options]
    reconforge.py web [options]
    reconforge.py tools --check
    reconforge.py tools --install
    reconforge.py --version
"""

import asyncio
import sys
import os
import signal
from pathlib import Path
from typing import List, Dict, Any, Optional
import click
import json
from datetime import datetime

# Add project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

# Change to project directory for relative imports
os.chdir(project_root)

from utils.database import ReconForgeDB
from utils.logging import setup_logging, get_scan_logger, main_logger
from utils.helpers import ToolValidator, DomainValidator, ConfigManager, ReportGenerator
from sources.base import SourceManager
from sources.passive import get_passive_sources
from sources.active import get_active_sources
from scanners.base import ScannerManager
from scanners.nuclei import get_nuclei_scanners
from scanners.web import get_web_scanners
from pentest.base import PentestManager, get_pentest_modules

# Version
__version__ = "1.2.0"

# Global managers
source_manager = SourceManager()
scanner_manager = ScannerManager()
pentest_manager = PentestManager()

# Database
db = ReconForgeDB()

# Configuration
config = {}


def load_config():
    """Load configuration from file"""
    global config
    config_path = project_root / "config.json"
    config = ConfigManager.load_config(config_path)
    
    # Set defaults if not present
    defaults = {
        'log_level': 'INFO',
        'output_dir': 'exports',
        'database_path': 'data/reconforge.db',
        'max_concurrent': 100,
        'timeout': 30,
        'rate_limit': 150
    }
    
    for key, value in defaults.items():
        if key not in config:
            config[key] = value


def setup_managers():
    """Initialize all managers with their sources/scanners/modules"""
    # Register subdomain discovery sources
    passive_sources = get_passive_sources(config)
    for source in passive_sources:
        source_manager.register_source(source)
    
    active_sources = get_active_sources(config)
    for source in active_sources:
        source_manager.register_source(source)
    
    # Register vulnerability scanners
    nuclei_scanners = get_nuclei_scanners(config)
    for scanner in nuclei_scanners:
        scanner_manager.register_scanner(scanner)
    
    web_scanners = get_web_scanners(config)
    for scanner in web_scanners:
        scanner_manager.register_scanner(scanner)
    
    # Register penetration testing modules
    pentest_modules = get_pentest_modules(config)
    for module in pentest_modules:
        pentest_manager.register_module(module)


def signal_handler(signum, frame):
    """Handle interrupt signals"""
    main_logger.warning("Received interrupt signal, stopping...")
    sys.exit(1)


def setup_signal_handlers():
    """Setup signal handlers for graceful shutdown"""
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)


@click.group()
@click.option('--debug', is_flag=True, help='Enable debug logging')
@click.option('--config-file', type=click.Path(), help='Configuration file path')
@click.version_option(__version__)
def cli(debug, config_file):
    """ReconForge - Professional Penetration Testing Framework"""
    # Setup logging
    log_level = 'DEBUG' if debug else config.get('log_level', 'INFO')
    setup_logging(log_level, 'logs/reconforge.log')
    
    # Load custom config if provided
    if config_file:
        custom_config = ConfigManager.load_config(config_file)
        config.update(custom_config)
    
    # Setup signal handlers
    setup_signal_handlers()
    
    # Initialize managers
    setup_managers()


@cli.command()
@click.argument('target')
@click.option('--passive-only', is_flag=True, help='Use only passive discovery methods')
@click.option('--active-only', is_flag=True, help='Use only active discovery methods')
@click.option('--sources', help='Comma-separated list of sources to use')
@click.option('--wordlist', type=click.Path(), help='Custom wordlist for active discovery')
@click.option('--output', type=click.Path(), help='Output file for results')
@click.option('--format', type=click.Choice(['json', 'csv', 'txt']), default='json', help='Output format')
def discover(target, passive_only, active_only, sources, wordlist, output, format):
    """Discover subdomains for target domain"""
    
    async def run_discovery():
        # Validate target
        if not DomainValidator.is_valid_domain(target):
            main_logger.error(f"Invalid domain: {target}")
            return
        
        target_clean = DomainValidator.normalize_domain(target)
        main_logger.info(f"Starting subdomain discovery for: {target_clean}")
        
        # Create scan in database
        scan_id = db.create_scan(target_clean, 'subdomain_discovery', {
            'passive_only': passive_only,
            'active_only': active_only,
            'sources': sources,
            'wordlist': wordlist
        })
        
        # Get scan logger
        scan_logger = get_scan_logger(scan_id, target_clean)
        
        try:
            # Determine which sources to use
            source_names = None
            if sources:
                source_names = [s.strip() for s in sources.split(',')]
            elif passive_only:
                source_names = [name for name, source in source_manager.sources.items() 
                               if hasattr(source, 'rate_limit')]  # Passive sources have rate_limit
            elif active_only:
                source_names = [name for name, source in source_manager.sources.items() 
                               if hasattr(source, 'wordlist')]  # Active sources have wordlist
            
            # Configure wordlist for active sources if provided
            if wordlist:
                for name, source in source_manager.sources.items():
                    if hasattr(source, 'wordlist_path'):
                        source.wordlist_path = wordlist
            
            # Run discovery
            results = await source_manager.discover_all(
                target_clean, 
                sources=source_names,
                parallel=True
            )
            
            # Store results in database
            for result in results:
                db.add_subdomain(
                    scan_id=scan_id,
                    subdomain=result.subdomain,
                    ip_address=result.ip_address,
                    discovery_source=result.source
                )
                
                scan_logger.log_subdomain_found(
                    result.subdomain, 
                    result.source, 
                    result.ip_address
                )
            
            # Update scan status
            db.update_scan_status(scan_id, 'completed', total_subdomains=len(results))
            
            # Get statistics
            stats = source_manager.get_summary()
            scan_logger.log_scan_complete({'subdomains': len(results)})
            
            # Output results
            if output:
                await output_results(results, output, format, 'subdomains')
            
            main_logger.success(f"Discovery completed: {len(results)} subdomains found")
            
            # Print summary
            print(f"\n🎯 Subdomain Discovery Summary")
            print(f"Target: {target_clean}")
            print(f"Subdomains found: {len(results)}")
            print(f"Sources used: {stats['enabled_sources']}")
            
            if results:
                print(f"\n📋 Discovered Subdomains:")
                for result in results[:20]:  # Show first 20
                    ip_info = f" [{result.ip_address}]" if result.ip_address else ""
                    print(f"  • {result.subdomain}{ip_info}")
                
                if len(results) > 20:
                    print(f"  ... and {len(results) - 20} more")
        
        except Exception as e:
            db.update_scan_status(scan_id, 'failed')
            scan_logger.logger.error(f"Discovery failed: {e}")
            raise
    
    asyncio.run(run_discovery())


@cli.command()
@click.argument('target')
@click.option('--scanners', help='Comma-separated list of scanners to use')
@click.option('--severity', type=click.Choice(['critical', 'high', 'medium', 'low', 'info']), 
              help='Minimum severity level to report')
@click.option('--nuclei-templates', help='Custom Nuclei templates path')
@click.option('--output', type=click.Path(), help='Output file for results')
@click.option('--format', type=click.Choice(['json', 'csv', 'txt']), default='json', help='Output format')
def scan(target, scanners, severity, nuclei_templates, output, format):
    """Scan target for vulnerabilities"""
    
    async def run_scan():
        # Validate target
        if not target.startswith('http') and not DomainValidator.is_valid_domain(target):
            main_logger.error(f"Invalid target: {target}")
            return
        
        main_logger.info(f"Starting vulnerability scan for: {target}")
        
        # Create scan in database
        scan_id = db.create_scan(target, 'vulnerability_scan', {
            'scanners': scanners,
            'severity': severity,
            'nuclei_templates': nuclei_templates
        })
        
        # Get scan logger
        scan_logger = get_scan_logger(scan_id, target)
        
        try:
            # Configure scanners
            if nuclei_templates:
                scanner_manager.configure_scanner('nuclei', {'templates_path': nuclei_templates})
            
            if severity:
                for scanner_name in scanner_manager.scanners:
                    if 'nuclei' in scanner_name:
                        scanner_manager.configure_scanner(scanner_name, {'severity_filter': [severity]})
            
            # Determine scanner list
            scanner_names = None
            if scanners:
                scanner_names = [s.strip() for s in scanners.split(',')]
            
            # Prepare targets list
            targets = [target]
            
            # Run vulnerability scanning
            results = await scanner_manager.scan_all(
                targets,
                scanners=scanner_names,
                parallel=True
            )
            
            # Store results in database
            for result in results:
                vuln_id = db.add_vulnerability(scan_id, {
                    'subdomain': result.target,
                    'vulnerability_type': result.vulnerability_type,
                    'severity': result.severity.value,
                    'title': result.title,
                    'description': result.description,
                    'url': result.url,
                    'method': result.method,
                    'payload': result.payload,
                    'template_id': result.template_id,
                    'cvss_score': result.cvss_score,
                    'cve_id': result.cve_id,
                    'reference_urls': result.reference_urls
                })
                
                scan_logger.log_vulnerability_found(
                    result.vulnerability_type,
                    result.severity.value,
                    result.target
                )
            
            # Update scan status
            db.update_scan_status(scan_id, 'completed', total_vulns=len(results))
            
            # Get statistics
            stats = scanner_manager.get_summary()
            scan_logger.log_scan_complete({'vulnerabilities': len(results)})
            
            # Output results
            if output:
                await output_results(results, output, format, 'vulnerabilities')
            
            main_logger.success(f"Scanning completed: {len(results)} vulnerabilities found")
            
            # Print summary
            print(f"\n🔍 Vulnerability Scan Summary")
            print(f"Target: {target}")
            print(f"Vulnerabilities found: {len(results)}")
            print(f"Scanners used: {stats['enabled_scanners']}")
            
            if results:
                # Group by severity
                by_severity = {}
                for result in results:
                    sev = result.severity.value
                    if sev not in by_severity:
                        by_severity[sev] = []
                    by_severity[sev].append(result)
                
                print(f"\n🚨 Vulnerabilities by Severity:")
                for sev in ['critical', 'high', 'medium', 'low', 'info']:
                    if sev in by_severity:
                        print(f"  {sev.upper()}: {len(by_severity[sev])}")
                
                # Show critical/high vulnerabilities
                critical_high = [r for r in results if r.severity.value in ['critical', 'high']]
                if critical_high:
                    print(f"\n⚠️  Critical/High Vulnerabilities:")
                    for vuln in critical_high[:10]:
                        print(f"  • [{vuln.severity.value.upper()}] {vuln.title} - {vuln.target}")
        
        except Exception as e:
            db.update_scan_status(scan_id, 'failed')
            scan_logger.logger.error(f"Scanning failed: {e}")
            raise
    
    asyncio.run(run_scan())


@cli.command()
@click.argument('target')
@click.option('--modules', help='Comma-separated list of pentest modules to use')
@click.option('--sequential', is_flag=True, help='Run modules sequentially instead of parallel')
@click.option('--output', type=click.Path(), help='Output file for results')
@click.option('--format', type=click.Choice(['json', 'csv', 'txt']), default='json', help='Output format')
def pentest(target, modules, sequential, output, format):
    """Execute penetration tests against target"""
    
    async def run_pentest():
        main_logger.info(f"Starting penetration testing for: {target}")
        
        # Create scan in database
        scan_id = db.create_scan(target, 'penetration_test', {
            'modules': modules,
            'sequential': sequential
        })
        
        # Get scan logger
        scan_logger = get_scan_logger(scan_id, target)
        
        try:
            # Determine module list
            module_names = None
            if modules:
                module_names = [m.strip() for m in modules.split(',')]
            
            # Run penetration testing
            results = await pentest_manager.execute_all(
                target,
                modules=module_names,
                parallel=not sequential
            )
            
            # Store results in database
            for result in results:
                pentest_id = db.add_pentest_result(scan_id, {
                    'target': result.target,
                    'test_type': result.test_type,
                    'command': result.command,
                    'output': result.output,
                    'success': result.success,
                    'severity': result.severity.value,
                    'impact': result.impact,
                    'recommendations': result.recommendations,
                    'artifacts': result.artifacts
                })
                
                scan_logger.log_pentest_result(
                    result.test_type,
                    result.target,
                    result.success
                )
            
            # Update scan status
            db.update_scan_status(scan_id, 'completed')
            
            # Get statistics
            stats = pentest_manager.get_summary()
            successful = sum(1 for r in results if r.success)
            scan_logger.log_scan_complete({'pentests': len(results), 'successful': successful})
            
            # Output results
            if output:
                await output_results(results, output, format, 'pentests')
            
            main_logger.success(f"Pentesting completed: {len(results)} tests ({successful} successful)")
            
            # Print summary
            print(f"\n🎯 Penetration Test Summary")
            print(f"Target: {target}")
            print(f"Tests executed: {len(results)}")
            print(f"Successful exploits: {successful}")
            print(f"Modules used: {stats['enabled_modules']}")
            
            if successful > 0:
                successful_tests = [r for r in results if r.success]
                print(f"\n✅ Successful Exploits:")
                for test in successful_tests:
                    print(f"  • [{test.severity.value.upper()}] {test.test_type} - {test.target}")
                    print(f"    Impact: {test.impact}")
        
        except Exception as e:
            db.update_scan_status(scan_id, 'failed')
            scan_logger.logger.error(f"Pentesting failed: {e}")
            raise
    
    asyncio.run(run_pentest())


@cli.command()
@click.argument('target')
@click.option('--passive-only', is_flag=True, help='Skip active discovery and pentesting')
@click.option('--skip-pentest', is_flag=True, help='Skip penetration testing phase')
@click.option('--output-dir', type=click.Path(), help='Output directory for all results')
def full(target, passive_only, skip_pentest, output_dir):
    """Run complete reconnaissance and penetration testing workflow"""
    
    async def run_full_scan():
        # Validate target
        if not DomainValidator.is_valid_domain(target):
            main_logger.error(f"Invalid domain: {target}")
            return
        
        target_clean = DomainValidator.normalize_domain(target)
        main_logger.info(f"Starting full assessment for: {target_clean}")
        
        # Create main scan
        scan_id = db.create_scan(target_clean, 'full_assessment', {
            'passive_only': passive_only,
            'skip_pentest': skip_pentest
        })
        
        scan_logger = get_scan_logger(scan_id, target_clean)
        
        try:
            # Phase 1: Subdomain Discovery
            main_logger.highlight("Phase 1: Subdomain Discovery")
            
            source_names = None
            if passive_only:
                source_names = [name for name, source in source_manager.sources.items() 
                               if hasattr(source, 'rate_limit')]
            
            subdomains = await source_manager.discover_all(
                target_clean,
                sources=source_names,
                parallel=True
            )
            
            # Store subdomains
            for result in subdomains:
                db.add_subdomain(
                    scan_id=scan_id,
                    subdomain=result.subdomain,
                    ip_address=result.ip_address,
                    discovery_source=result.source
                )
            
            main_logger.success(f"Found {len(subdomains)} subdomains")
            
            # Phase 2: Vulnerability Scanning
            main_logger.highlight("Phase 2: Vulnerability Scanning")
            
            # Prepare targets for scanning
            web_targets = []
            for subdomain in subdomains:
                web_targets.extend([
                    f"https://{subdomain.subdomain}",
                    f"http://{subdomain.subdomain}"
                ])
            
            # Limit targets to avoid overwhelming scans
            if len(web_targets) > 50:
                main_logger.info(f"Limiting scan to top 50 targets from {len(web_targets)} discovered")
                web_targets = web_targets[:50]
            
            vulnerabilities = await scanner_manager.scan_all(web_targets, parallel=True)
            
            # Store vulnerabilities
            for vuln in vulnerabilities:
                db.add_vulnerability(scan_id, {
                    'subdomain': vuln.target,
                    'vulnerability_type': vuln.vulnerability_type,
                    'severity': vuln.severity.value,
                    'title': vuln.title,
                    'description': vuln.description,
                    'url': vuln.url,
                    'template_id': vuln.template_id,
                    'cve_id': vuln.cve_id
                })
            
            main_logger.success(f"Found {len(vulnerabilities)} vulnerabilities")
            
            # Phase 3: Penetration Testing
            if not skip_pentest:
                main_logger.highlight("Phase 3: Penetration Testing")
                
                # Select high-value targets for pentesting
                pentest_targets = [target_clean] + [s.subdomain for s in subdomains[:5]]
                pentest_results = []
                
                for pentest_target in pentest_targets:
                    results = await pentest_manager.execute_all(
                        pentest_target,
                        parallel=False  # Sequential for pentesting
                    )
                    pentest_results.extend(results)
                    
                    # Store results
                    for result in results:
                        db.add_pentest_result(scan_id, {
                            'target': result.target,
                            'test_type': result.test_type,
                            'command': result.command,
                            'output': result.output,
                            'success': result.success,
                            'severity': result.severity.value,
                            'impact': result.impact,
                            'recommendations': result.recommendations
                        })
                
                successful_pentests = sum(1 for r in pentest_results if r.success)
                main_logger.success(f"Completed {len(pentest_results)} pentests ({successful_pentests} successful)")
            
            # Update final scan status
            db.update_scan_status(
                scan_id, 
                'completed', 
                total_subdomains=len(subdomains),
                total_vulns=len(vulnerabilities)
            )
            
            # Generate comprehensive report
            if output_dir:
                await generate_full_report(scan_id, output_dir)
            
            # Print final summary
            print_full_summary(target_clean, subdomains, vulnerabilities, 
                             pentest_results if not skip_pentest else [])
            
        except Exception as e:
            db.update_scan_status(scan_id, 'failed')
            scan_logger.logger.error(f"Full scan failed: {e}")
            raise
    
    asyncio.run(run_full_scan())


@cli.command()
@click.option('--host', default='0.0.0.0', help='Host to bind web interface')
@click.option('--port', default=8000, help='Port for web interface')
@click.option('--dev', is_flag=True, help='Enable development mode with auto-reload')
def web(host, port, dev):
    """Start the web dashboard interface"""
    import uvicorn
    
    main_logger.info(f"Starting web interface on {host}:{port}")
    
    uvicorn.run(
        "app.main:app",
        host=host,
        port=port,
        reload=dev,
        log_level="info"
    )


@cli.group()
def tools():
    """Tool management commands"""
    pass


@tools.command('check')
def check_tools():
    """Check installation status of all required tools"""
    print("🔧 Checking tool installation status...\n")
    
    results = ToolValidator.check_all_tools()
    
    available = []
    missing = []
    
    for tool_name, info in results.items():
        if info['available']:
            available.append((tool_name, info.get('description', '')))
            print(f"✅ {tool_name:<15} - {info.get('description', '')}")
        else:
            missing.append((tool_name, info.get('description', ''), info.get('error', '')))
            print(f"❌ {tool_name:<15} - {info.get('description', '')} (Error: {info.get('error', 'Not found')})")
    
    print(f"\n📊 Summary:")
    print(f"Available tools: {len(available)}")
    print(f"Missing tools: {len(missing)}")
    
    if missing:
        print(f"\n💡 Run 'reconforge tools install' to install missing tools")


@tools.command('install')
@click.option('--force', is_flag=True, help='Force reinstallation of all tools')
def install_tools(force):
    """Install all required tools using the install script"""
    install_script = project_root / "install.sh"
    
    if not install_script.exists():
        main_logger.error("Install script not found!")
        return
    
    main_logger.info("Running tool installation script...")
    
    try:
        import subprocess
        result = subprocess.run(
            ["bash", str(install_script)],
            check=True,
            capture_output=True,
            text=True
        )
        
        print(result.stdout)
        if result.stderr:
            print("Warnings:", result.stderr)
        
        main_logger.success("Tool installation completed!")
        
    except subprocess.CalledProcessError as e:
        main_logger.error(f"Installation failed: {e}")
        if e.stdout:
            print("Output:", e.stdout)
        if e.stderr:
            print("Error:", e.stderr)


async def output_results(results, output_file, format_type, result_type):
    """Output results to file in specified format"""
    from utils.helpers import FileHelper
    
    output_path = Path(output_file)
    FileHelper.ensure_directory(output_path.parent)
    
    if format_type == 'json':
        if result_type == 'subdomains':
            data = [{'subdomain': r.subdomain, 'source': r.source, 'ip': r.ip_address} for r in results]
        elif result_type == 'vulnerabilities':
            data = [{'title': r.title, 'severity': r.severity.value, 'target': r.target, 
                    'type': r.vulnerability_type} for r in results]
        elif result_type == 'pentests':
            data = [{'test_type': r.test_type, 'target': r.target, 'success': r.success,
                    'severity': r.severity.value} for r in results]
        
        with output_path.open('w') as f:
            json.dump(data, f, indent=2)
    
    elif format_type == 'csv':
        if result_type == 'subdomains':
            lines = ['subdomain,source,ip_address']
            lines.extend([f"{r.subdomain},{r.source},{r.ip_address or ''}" for r in results])
        elif result_type == 'vulnerabilities':
            lines = ['title,severity,target,type']
            lines.extend([f"{r.title},{r.severity.value},{r.target},{r.vulnerability_type}" for r in results])
        elif result_type == 'pentests':
            lines = ['test_type,target,success,severity']
            lines.extend([f"{r.test_type},{r.target},{r.success},{r.severity.value}" for r in results])
        
        with output_path.open('w') as f:
            f.write('\n'.join(lines))
    
    elif format_type == 'txt':
        lines = []
        if result_type == 'subdomains':
            lines = [r.subdomain for r in results]
        elif result_type == 'vulnerabilities':
            lines = [f"[{r.severity.value.upper()}] {r.title} - {r.target}" for r in results]
        elif result_type == 'pentests':
            lines = [f"[{'SUCCESS' if r.success else 'FAILED'}] {r.test_type} - {r.target}" for r in results]
        
        with output_path.open('w') as f:
            f.write('\n'.join(lines))
    
    main_logger.success(f"Results saved to {output_path}")


async def generate_full_report(scan_id: int, output_dir: str):
    """Generate comprehensive report for full scan"""
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    
    # Get scan data
    scan_info = db.get_scan(scan_id)
    subdomains = db.get_subdomains(scan_id)
    vulnerabilities = db.get_vulnerabilities(scan_id)
    pentests = db.get_pentest_results(scan_id)
    stats = db.get_scan_stats(scan_id)
    
    report_data = {
        'scan_info': scan_info,
        'subdomains': subdomains,
        'vulnerabilities': vulnerabilities,
        'pentest_results': pentests,
        'stats': stats
    }
    
    # Generate different format reports
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    target = scan_info['target'].replace('.', '_')
    
    # JSON report
    json_file = output_path / f"reconforge_report_{target}_{timestamp}.json"
    json_content = ReportGenerator.generate_json_report(report_data)
    with json_file.open('w') as f:
        f.write(json_content)
    
    # Text report
    txt_file = output_path / f"reconforge_report_{target}_{timestamp}.txt"
    txt_content = ReportGenerator.generate_text_report(report_data)
    with txt_file.open('w') as f:
        f.write(txt_content)
    
    # CSV files
    if subdomains:
        csv_file = output_path / f"subdomains_{target}_{timestamp}.csv"
        csv_content = ReportGenerator.generate_csv_data(subdomains)
        with csv_file.open('w') as f:
            f.write(csv_content)
    
    main_logger.success(f"Full reports generated in {output_path}")
    
    # Record exports
    db.add_export_record(scan_id, 'json', str(json_file), json_file.stat().st_size)
    db.add_export_record(scan_id, 'txt', str(txt_file), txt_file.stat().st_size)
    if subdomains:
        db.add_export_record(scan_id, 'csv', str(csv_file), csv_file.stat().st_size)


def print_full_summary(target: str, subdomains, vulnerabilities, pentests):
    """Print comprehensive summary for full scan"""
    print(f"\n🎯 ReconForge Full Assessment Summary")
    print("=" * 60)
    print(f"Target: {target}")
    print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    
    print(f"📊 Discovery Results:")
    print(f"  Subdomains found: {len(subdomains)}")
    
    if vulnerabilities:
        vuln_by_severity = {}
        for vuln in vulnerabilities:
            sev = vuln.severity.value
            vuln_by_severity[sev] = vuln_by_severity.get(sev, 0) + 1
        
        print(f"  Total vulnerabilities: {len(vulnerabilities)}")
        for sev in ['critical', 'high', 'medium', 'low']:
            if sev in vuln_by_severity:
                print(f"    {sev.upper()}: {vuln_by_severity[sev]}")
    
    if pentests:
        successful = sum(1 for p in pentests if p.success)
        print(f"  Penetration tests: {len(pentests)} ({successful} successful)")
    
    print()
    
    # Show top findings
    if subdomains:
        print("🔍 Top Subdomains:")
        for sub in subdomains[:10]:
            ip_info = f" [{sub.get('ip_address', 'N/A')}]" if sub.get('ip_address') else ""
            print(f"  • {sub['subdomain']}{ip_info}")
        if len(subdomains) > 10:
            print(f"  ... and {len(subdomains) - 10} more")
        print()
    
    # Show critical vulnerabilities
    if vulnerabilities:
        critical_vulns = [v for v in vulnerabilities if v.severity.value in ['critical', 'high']]
        if critical_vulns:
            print("🚨 Critical/High Vulnerabilities:")
            for vuln in critical_vulns[:5]:
                print(f"  • [{vuln.severity.value.upper()}] {vuln.title}")
            if len(critical_vulns) > 5:
                print(f"  ... and {len(critical_vulns) - 5} more")
            print()
    
    # Show successful pentests
    if pentests:
        successful_tests = [p for p in pentests if p.success]
        if successful_tests:
            print("✅ Successful Penetration Tests:")
            for test in successful_tests[:5]:
                print(f"  • {test.test_type} - {test.target}")
            if len(successful_tests) > 5:
                print(f"  ... and {len(successful_tests) - 5} more")
            print()


if __name__ == '__main__':
    # Load configuration
    load_config()
    
    # Run CLI
    cli()