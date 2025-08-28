#!/usr/bin/env python3
"""
ReconForge Interactive Terminal Interface
Professional terminal-based reconnaissance and penetration testing platform
"""

import os
import sys
import asyncio
import signal
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any
import json

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.prompt import Prompt, Confirm, IntPrompt
from rich.text import Text
from rich.align import Align
from rich.columns import Columns
from rich.live import Live
from rich.layout import Layout
from rich import box

# Add parent directory to path for imports
sys.path.append(str(Path(__file__).parent.parent))

from utils.database import ReconForgeDB
from utils.logging import setup_logging, get_scan_logger, main_logger
import logging
from utils.helpers import ToolValidator, DomainValidator, ConfigManager, ReportGenerator
from sources.base import SourceManager
from sources.passive import get_passive_sources
from sources.active import get_active_sources
from scanners.base import ScannerManager
from scanners.nuclei import get_nuclei_scanners
from scanners.web import get_web_scanners
from pentest.base import PentestManager, get_pentest_modules


class ReconForgeTerminal:
    """Interactive terminal interface for ReconForge"""
    
    def __init__(self):
        self.console = Console()
        self.db = ReconForgeDB()
        self.config = {}
        self.current_session = {}
        self.navigation_stack = []
        
        # Setup terminal-specific logging
        self.terminal_logger = self.setup_terminal_logging()
        
        # Initialize managers
        self.source_manager = SourceManager()
        self.scanner_manager = ScannerManager()
        self.pentest_manager = PentestManager()
        
        # Load configuration and setup
        self.load_config()
        self.setup_managers()
        self.setup_signal_handlers()
        
        # Terminal state
        self.running = True
        self.current_target = None
    
    def setup_terminal_logging(self):
        """Setup comprehensive logging for terminal interface"""
        # Create terminal-specific logger
        terminal_logger = logging.getLogger('terminal_interface')
        terminal_logger.setLevel(logging.DEBUG)
        
        # Ensure logs directory exists
        log_dir = Path('logs')
        log_dir.mkdir(exist_ok=True)
        
        # Create file handler for terminal test log
        log_file = log_dir / 'terminal_test.log'
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)
        
        # Create detailed formatter
        formatter = logging.Formatter(
            '%(asctime)s | %(levelname)-8s | %(funcName)-20s | %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(formatter)
        
        # Add handler to logger
        if not terminal_logger.handlers:
            terminal_logger.addHandler(file_handler)
        
        terminal_logger.info("=== TERMINAL INTERFACE SESSION STARTED ===")
        terminal_logger.info(f"ReconForge v1.3.1 Terminal Interface Initialized")
        terminal_logger.info(f"Session ID: {datetime.now().strftime('%Y%m%d_%H%M%S')}")
        
        return terminal_logger
        
    def load_config(self):
        """Load configuration from file"""
        config_path = Path(__file__).parent.parent / "config.json"
        self.config = ConfigManager.load_config(config_path)
        
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
            if key not in self.config:
                self.config[key] = value
    
    def setup_managers(self):
        """Initialize all managers with their sources/scanners/modules"""
        # Register subdomain discovery sources
        passive_sources = get_passive_sources(self.config)
        for source in passive_sources:
            self.source_manager.register_source(source)
        
        active_sources = get_active_sources(self.config)
        for source in active_sources:
            self.source_manager.register_source(source)
        
        # Register vulnerability scanners
        nuclei_scanners = get_nuclei_scanners(self.config)
        for scanner in nuclei_scanners:
            self.scanner_manager.register_scanner(scanner)
        
        web_scanners = get_web_scanners(self.config)
        for scanner in web_scanners:
            self.scanner_manager.register_scanner(scanner)
        
        # Register penetration testing modules
        pentest_modules = get_pentest_modules(self.config)
        for module in pentest_modules:
            self.pentest_manager.register_module(module)
    
    def setup_signal_handlers(self):
        """Setup signal handlers for graceful shutdown"""
        def signal_handler(signum, frame):
            self.console.print("\n[red]Received interrupt signal, stopping...[/red]")
            self.running = False
            sys.exit(0)
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
    
    def clear_screen(self):
        """Clear the terminal screen"""
        os.system('clear' if os.name == 'posix' else 'cls')
    
    def print_banner(self):
        """Print ReconForge banner"""
        banner = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                           ReconForge v1.3.1                                 ║
║              Professional Reconnaissance & Penetration Testing              ║
║                        Interactive Terminal Interface                        ║
╚══════════════════════════════════════════════════════════════════════════════╝
        """
        self.console.print(Panel(
            Align.center(Text(banner.strip(), style="bold cyan")),
            box=box.DOUBLE,
            style="cyan"
        ))
    
    def print_breadcrumbs(self):
        """Print current navigation breadcrumbs"""
        if self.navigation_stack:
            breadcrumb = " > ".join(self.navigation_stack)
            self.console.print(f"[dim]Navigation: {breadcrumb}[/dim]")
            self.console.print()
    
    def print_main_menu(self):
        """Display the main menu"""
        self.clear_screen()
        self.print_banner()
        
        # Current session info
        if self.current_target:
            session_panel = Panel(
                f"[green]Active Target:[/green] {self.current_target}\n"
                f"[blue]Session Time:[/blue] {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                title="Current Session",
                style="green"
            )
            self.console.print(session_panel)
            self.console.print()
        
        # Main menu options
        menu_table = Table(show_header=False, box=box.SIMPLE)
        menu_table.add_column("Option", style="cyan", width=4)
        menu_table.add_column("Description", style="white")
        menu_table.add_column("Status", style="dim", width=15)
        
        menu_items = [
            ("1", "Subdomain Discovery", f"({len(self.source_manager.sources)} sources)"),
            ("2", "Vulnerability Scanning", f"({len(self.scanner_manager.scanners)} scanners)"),
            ("3", "Port Scanning & Service Detection", "(nmap, masscan)"),
            ("4", "Directory Enumeration", "(gobuster, dirb)"),
            ("5", "SQL Injection Testing", "(sqlmap)"),
            ("6", "Exploitation Toolkit", f"({len(self.pentest_manager.modules)} modules)"),
            ("7", "Report Generation & Export", "(JSON, HTML, CSV)"),
            ("8", "Scan History & Database", f"({self.get_scan_count()} scans)"),
            ("9", "Launch Web Dashboard", "(FastAPI server)"),
            ("10", "Tool Configuration", "(settings, API keys)"),
            ("0", "Exit", "")
        ]
        
        for option, desc, status in menu_items:
            menu_table.add_row(f"[bold cyan]{option}[/bold cyan]", desc, status)
        
        menu_panel = Panel(
            menu_table,
            title="ReconForge Professional Reconnaissance Platform",
            style="cyan"
        )
        
        self.console.print(menu_panel)
        self.console.print()
    
    def get_scan_count(self) -> int:
        """Get total number of scans in database"""
        try:
            with self.db.get_connection() as conn:
                cursor = conn.execute("SELECT COUNT(*) FROM scans")
                return cursor.fetchone()[0]
        except:
            return 0
    
    def get_user_choice(self, prompt_text: str = "Select an option") -> str:
        """Get user input with validation"""
        try:
            self.terminal_logger.debug(f"Prompting user: {prompt_text}")
            choice = Prompt.ask(f"[bold green]{prompt_text}[/bold green]", default="0")
            self.terminal_logger.info(f"User selected: '{choice}' for prompt: {prompt_text}")
            return choice
        except (KeyboardInterrupt, EOFError) as e:
            self.terminal_logger.warning(f"User input interrupted: {type(e).__name__}")
            return "0"
        except Exception as e:
            self.terminal_logger.error(f"Error getting user input: {str(e)}")
            return "0"
    
    async def handle_subdomain_discovery(self):
        """Handle subdomain discovery menu and operations"""
        self.navigation_stack = ["Main Menu", "Subdomain Discovery"]
        
        while True:
            self.clear_screen()
            self.print_banner()
            self.print_breadcrumbs()
            
            # Show available sources
            sources_table = Table(title="Available Discovery Sources", box=box.ROUNDED)
            sources_table.add_column("Name", style="cyan")
            sources_table.add_column("Type", style="yellow")
            sources_table.add_column("Status", style="green")
            sources_table.add_column("Description", style="white")
            
            for name, source in self.source_manager.sources.items():
                source_type = "Passive" if hasattr(source, 'rate_limit') else "Active"
                status = "✓ Ready" if source.enabled else "✗ Disabled"
                sources_table.add_row(name, source_type, status, source.description)
            
            self.console.print(sources_table)
            self.console.print()
            
            # Discovery menu
            discovery_menu = Table(show_header=False, box=box.SIMPLE)
            discovery_menu.add_column("Option", style="cyan", width=4)
            discovery_menu.add_column("Description", style="white")
            
            discovery_options = [
                ("1", "Start New Discovery Scan"),
                ("2", "Passive Discovery Only"),
                ("3", "Active Discovery Only"),
                ("4", "Custom Source Selection"),
                ("5", "View Recent Discoveries"),
                ("6", "Export Discovery Results"),
                ("b", "Back to Main Menu")
            ]
            
            for option, desc in discovery_options:
                discovery_menu.add_row(f"[bold cyan]{option}[/bold cyan]", desc)
            
            self.console.print(Panel(discovery_menu, title="Subdomain Discovery Options"))
            
            choice = self.get_user_choice("Choose discovery option")
            
            if choice == "1":
                await self.run_full_discovery()
            elif choice == "2":
                await self.run_passive_discovery()
            elif choice == "3":
                await self.run_active_discovery()
            elif choice == "4":
                await self.run_custom_discovery()
            elif choice == "5":
                self.view_recent_discoveries()
            elif choice == "6":
                await self.export_discovery_results()
            elif choice.lower() == "b":
                self.navigation_stack.pop()
                break
            else:
                self.console.print("[red]Invalid option. Please try again.[/red]")
                input("Press Enter to continue...")
    
    async def run_full_discovery(self):
        """Run full subdomain discovery"""
        try:
            self.terminal_logger.info("Starting full subdomain discovery")
            target = self.get_target_input()
            if not target:
                self.terminal_logger.warning("No target provided for discovery")
                return
            
            self.current_target = target
            self.terminal_logger.info(f"Target set to: {target}")
            
            # Create scan in database
            scan_id = self.db.create_scan(target, 'subdomain_discovery', {
                'discovery_type': 'full',
                'passive_sources': True,
                'active_sources': True
            })
            self.terminal_logger.info(f"Created scan in database with ID: {scan_id}")
            
            self.console.print(f"[green]Starting full subdomain discovery for: {target}[/green]")
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                console=self.console
            ) as progress:
                
                task = progress.add_task("Discovering subdomains...", total=100)
                
                try:
                    self.terminal_logger.info("Running discovery with all sources")
                    # Run discovery
                    results = await self.source_manager.discover_all(
                        target,
                        sources=None,  # Use all sources
                        parallel=True
                    )
                    
                    self.terminal_logger.info(f"Discovery completed. Found {len(results)} results")
                    
                    # Store results in database
                    for result in results:
                        self.db.add_subdomain(
                            scan_id=scan_id,
                            subdomain=result.subdomain,
                            ip_address=result.ip_address,
                            source=result.source
                        )
                    
                    progress.update(task, completed=100)
                    
                    # Complete scan
                    self.db.complete_scan(scan_id, len(results), 'subdomain_discovery')
                    self.terminal_logger.info(f"Scan {scan_id} marked as completed")
                    
                    # Display results
                    self.display_discovery_results(results, target)
                    
                except Exception as e:
                    self.terminal_logger.error(f"Discovery scan failed: {str(e)}", exc_info=True)
                    self.console.print(f"[red]Discovery failed: {str(e)}[/red]")
                    self.db.fail_scan(scan_id, str(e))
                    self.terminal_logger.info(f"Scan {scan_id} marked as failed")
                
                input("Press Enter to continue...")
                
        except Exception as e:
            self.terminal_logger.error(f"Error in run_full_discovery: {str(e)}", exc_info=True)
    
    async def run_passive_discovery(self):
        """Run passive-only subdomain discovery"""
        target = self.get_target_input()
        if not target:
            return
        
        # Filter to passive sources only
        passive_sources = [name for name, source in self.source_manager.sources.items() 
                          if hasattr(source, 'rate_limit')]
        
        await self.run_discovery_with_sources(target, passive_sources, "Passive")
    
    async def run_active_discovery(self):
        """Run active-only subdomain discovery"""
        target = self.get_target_input()
        if not target:
            return
        
        # Filter to active sources only
        active_sources = [name for name, source in self.source_manager.sources.items() 
                         if hasattr(source, 'wordlist')]
        
        await self.run_discovery_with_sources(target, active_sources, "Active")
    
    async def run_custom_discovery(self):
        """Run custom source selection discovery"""
        target = self.get_target_input()
        if not target:
            return
        
        # Let user select sources
        available_sources = list(self.source_manager.sources.keys())
        
        self.console.print("[cyan]Available Sources:[/cyan]")
        for i, source in enumerate(available_sources, 1):
            source_obj = self.source_manager.sources[source]
            source_type = "Passive" if hasattr(source_obj, 'rate_limit') else "Active"
            status = "✓" if source_obj.enabled else "✗"
            self.console.print(f"  {i:2d}. [{source_type[:1].lower()}]{status}[/{source_type[:1].lower()}] {source}")
        
        self.console.print("\n[dim]Enter source numbers separated by commas (e.g., 1,3,5) or 'all' for all sources[/dim]")
        selection = Prompt.ask("[bold green]Select sources[/bold green]", default="all")
        
        if selection.lower() == "all":
            selected_sources = available_sources
        else:
            try:
                indices = [int(x.strip()) for x in selection.split(',')]
                selected_sources = [available_sources[i-1] for i in indices if 1 <= i <= len(available_sources)]
            except (ValueError, IndexError):
                self.console.print("[red]Invalid selection. Using all sources.[/red]")
                selected_sources = available_sources
        
        if not selected_sources:
            self.console.print("[red]No sources selected.[/red]")
            return
        
        await self.run_discovery_with_sources(target, selected_sources, "Custom")
    
    async def run_discovery_with_sources(self, target: str, source_list: List[str], discovery_type: str):
        """Run discovery with specific sources"""
        self.current_target = target
        
        # Create scan in database
        scan_id = self.db.create_scan(target, 'subdomain_discovery', {
            'discovery_type': discovery_type.lower(),
            'sources': source_list
        })
        
        self.console.print(f"[green]Starting {discovery_type.lower()} subdomain discovery for: {target}[/green]")
        self.console.print(f"[blue]Using {len(source_list)} sources[/blue]")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=self.console
        ) as progress:
            
            task = progress.add_task(f"Running {discovery_type.lower()} discovery...", total=100)
            
            try:
                # Run discovery
                results = await self.source_manager.discover_all(
                    target,
                    sources=source_list,
                    parallel=True
                )
                
                # Store results in database
                for result in results:
                    self.db.add_subdomain(
                        scan_id=scan_id,
                        subdomain=result.subdomain,
                        ip_address=result.ip_address,
                        source=result.source
                    )
                
                progress.update(task, completed=100)
                
                # Complete scan
                self.db.complete_scan(scan_id, len(results), 'subdomain_discovery')
                
                # Display results
                self.display_discovery_results(results, target)
                
            except Exception as e:
                self.console.print(f"[red]Discovery failed: {str(e)}[/red]")
                self.db.fail_scan(scan_id, str(e))
            
            input("Press Enter to continue...")
    
    def display_discovery_results(self, results: List, target: str):
        """Display discovery results in a formatted table"""
        if not results:
            self.console.print("[yellow]No subdomains discovered.[/yellow]")
            return
        
        # Create results table
        results_table = Table(title=f"Discovery Results for {target}", box=box.ROUNDED)
        results_table.add_column("Subdomain", style="cyan")
        results_table.add_column("IP Address", style="green")
        results_table.add_column("Source", style="yellow")
        
        # Sort results by subdomain
        sorted_results = sorted(results, key=lambda x: x.subdomain)
        
        # Display first 50 results (pagination)
        display_count = min(50, len(sorted_results))
        for result in sorted_results[:display_count]:
            ip_addr = result.ip_address if result.ip_address else "N/A"
            results_table.add_row(result.subdomain, ip_addr, result.source)
        
        self.console.print(results_table)
        
        if len(sorted_results) > 50:
            self.console.print(f"[dim]Showing first 50 of {len(sorted_results)} results[/dim]")
        
        # Summary
        unique_subdomains = len(set(r.subdomain for r in results))
        unique_sources = len(set(r.source for r in results))
        
        summary_panel = Panel(
            f"[green]Total Subdomains:[/green] {unique_subdomains}\n"
            f"[blue]Total Results:[/blue] {len(results)}\n"
            f"[yellow]Sources Used:[/yellow] {unique_sources}",
            title="Discovery Summary",
            style="green"
        )
        
        self.console.print(summary_panel)
    
    def get_target_input(self) -> Optional[str]:
        """Get and validate target domain input"""
        try:
            self.terminal_logger.debug("Requesting target domain input from user")
            target = Prompt.ask("[bold green]Enter target domain[/bold green]")
            
            if not target:
                self.terminal_logger.warning("No target domain specified by user")
                self.console.print("[red]No target specified.[/red]")
                return None
            
            self.terminal_logger.info(f"User entered target: {target}")
            
            # Validate domain
            if not DomainValidator.is_valid_domain(target):
                self.terminal_logger.warning(f"Invalid domain format entered: {target}")
                self.console.print(f"[red]Invalid domain format: {target}[/red]")
                return None
            
            normalized_target = DomainValidator.normalize_domain(target)
            self.terminal_logger.info(f"Target validated and normalized to: {normalized_target}")
            return normalized_target
            
        except Exception as e:
            self.terminal_logger.error(f"Error getting target input: {str(e)}", exc_info=True)
            self.console.print(f"[red]Error getting target input: {str(e)}[/red]")
            return None
    
    def view_recent_discoveries(self):
        """View recent discovery scans"""
        self.console.print("[cyan]Recent Subdomain Discovery Scans:[/cyan]")
        
        try:
            with self.db.get_connection() as conn:
                cursor = conn.execute("""
                    SELECT id, target, status, start_time, total_subdomains 
                    FROM scans 
                    WHERE scan_type = 'subdomain_discovery' 
                    ORDER BY start_time DESC 
                    LIMIT 10
                """)
                
                scans = cursor.fetchall()
                
                if not scans:
                    self.console.print("[yellow]No recent discovery scans found.[/yellow]")
                    input("Press Enter to continue...")
                    return
                
                # Create scans table
                scans_table = Table(title="Recent Discovery Scans", box=box.ROUNDED)
                scans_table.add_column("ID", style="cyan")
                scans_table.add_column("Target", style="green")
                scans_table.add_column("Status", style="yellow")
                scans_table.add_column("Date", style="blue")
                scans_table.add_column("Subdomains", style="magenta")
                
                for scan in scans:
                    date_str = scan[3][:19] if scan[3] else "N/A"
                    subdomain_count = scan[4] if scan[4] else 0
                    scans_table.add_row(
                        str(scan[0]), scan[1], scan[2], date_str, str(subdomain_count)
                    )
                
                self.console.print(scans_table)
                
        except Exception as e:
            self.console.print(f"[red]Error fetching scan history: {str(e)}[/red]")
        
        input("Press Enter to continue...")
    
    async def export_discovery_results(self):
        """Export discovery results to file"""
        # Get available scans
        try:
            with self.db.get_connection() as conn:
                cursor = conn.execute("""
                    SELECT id, target, start_time, total_subdomains 
                    FROM scans 
                    WHERE scan_type = 'subdomain_discovery' AND status = 'completed'
                    ORDER BY start_time DESC 
                    LIMIT 20
                """)
                
                scans = cursor.fetchall()
                
                if not scans:
                    self.console.print("[yellow]No completed discovery scans found to export.[/yellow]")
                    input("Press Enter to continue...")
                    return
                
                # Show available scans
                scans_table = Table(title="Available Scans for Export", box=box.ROUNDED)
                scans_table.add_column("ID", style="cyan")
                scans_table.add_column("Target", style="green")
                scans_table.add_column("Date", style="blue")
                scans_table.add_column("Subdomains", style="magenta")
                
                for i, scan in enumerate(scans, 1):
                    date_str = scan[2][:19] if scan[2] else "N/A"
                    subdomain_count = scan[3] if scan[3] else 0
                    scans_table.add_row(
                        str(i), scan[1], date_str, str(subdomain_count)
                    )
                
                self.console.print(scans_table)
                
                # Get user selection
                scan_choice = IntPrompt.ask(
                    "[bold green]Select scan to export[/bold green]",
                    default=1
                )
                
                if 1 <= scan_choice <= len(scans):
                    selected_scan = scans[scan_choice - 1]
                    scan_id = selected_scan[0]
                    
                    # Get export format
                    format_choice = Prompt.ask(
                        "[bold green]Export format[/bold green]",
                        choices=["json", "csv", "txt"],
                        default="json"
                    )
                    
                    # Export results
                    await self.export_scan_results(scan_id, selected_scan[1], format_choice)
                    
                else:
                    self.console.print("[red]Invalid scan selection.[/red]")
                    
        except Exception as e:
            self.console.print(f"[red]Error exporting results: {str(e)}[/red]")
        
        input("Press Enter to continue...")
    
    async def export_scan_results(self, scan_id: int, target: str, format_type: str):
        """Export scan results in specified format"""
        try:
            # Get scan results
            with self.db.get_connection() as conn:
                cursor = conn.execute("""
                    SELECT subdomain, ip_address, discovery_source, created_at
                    FROM subdomains 
                    WHERE scan_id = ?
                    ORDER BY subdomain
                """, (scan_id,))
                
                results = cursor.fetchall()
                
                if not results:
                    self.console.print("[yellow]No results found for this scan.[/yellow]")
                    return
                
                # Generate filename
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"discovery_{target}_{timestamp}.{format_type}"
                
                # Ensure exports directory exists
                exports_dir = Path("exports")
                exports_dir.mkdir(exist_ok=True)
                
                filepath = exports_dir / filename
                
                # Export based on format
                if format_type == "json":
                    export_data = {
                        "target": target,
                        "scan_id": scan_id,
                        "export_time": datetime.now().isoformat(),
                        "total_results": len(results),
                        "subdomains": [
                            {
                                "subdomain": row[0],
                                "ip_address": row[1],
                                "source": row[2],
                                "discovered_at": row[3]
                            }
                            for row in results
                        ]
                    }
                    
                    with open(filepath, 'w') as f:
                        json.dump(export_data, f, indent=2)
                        
                elif format_type == "csv":
                    import csv
                    with open(filepath, 'w', newline='') as f:
                        writer = csv.writer(f)
                        writer.writerow(["Subdomain", "IP Address", "Source", "Discovered At"])
                        for row in results:
                            writer.writerow(row)
                            
                elif format_type == "txt":
                    with open(filepath, 'w') as f:
                        f.write(f"Discovery Results for {target}\n")
                        f.write(f"Scan ID: {scan_id}\n")
                        f.write(f"Export Time: {datetime.now().isoformat()}\n")
                        f.write(f"Total Results: {len(results)}\n\n")
                        
                        for row in results:
                            f.write(f"{row[0]}")
                            if row[1]:
                                f.write(f" [{row[1]}]")
                            f.write(f" (via {row[2]})\n")
                
                self.console.print(f"[green]Results exported to: {filepath}[/green]")
                
        except Exception as e:
            self.console.print(f"[red]Export failed: {str(e)}[/red]")
    
    async def launch_web_dashboard(self):
        """Launch the web dashboard"""
        self.console.print("[cyan]Launching ReconForge Web Dashboard...[/cyan]")
        
        # Import and start web server
        try:
            from app.main import app
            import uvicorn
            
            self.console.print("[green]Starting web server on http://localhost:8000[/green]")
            self.console.print("[dim]Press Ctrl+C to stop the web server and return to terminal[/dim]")
            
            # Run web server
            uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")
            
        except Exception as e:
            self.console.print(f"[red]Failed to start web dashboard: {str(e)}[/red]")
            input("Press Enter to continue...")
    
    async def run(self):
        """Main terminal interface loop"""
        try:
            # Setup logging
            setup_logging(self.config.get('log_level', 'INFO'), 'logs/reconforge.log')
            self.terminal_logger.info("Starting main terminal interface loop")
            
            while self.running:
                try:
                    self.terminal_logger.debug("Displaying main menu")
                    self.print_main_menu()
                    
                    choice = self.get_user_choice("Select an option")
                    
                    self.terminal_logger.info(f"Processing main menu choice: {choice}")
                    
                    if choice == "1":
                        self.terminal_logger.info("Entering subdomain discovery module")
                        await self.handle_subdomain_discovery()
                    elif choice == "2":
                        self.terminal_logger.info("Entering vulnerability scanning module")
                        await self.handle_vulnerability_scanning()
                    elif choice == "3":
                        self.terminal_logger.info("Entering port scanning module")
                        await self.handle_port_scanning()
                    elif choice == "4":
                        self.terminal_logger.info("Entering directory enumeration module")
                        await self.handle_directory_enumeration()
                    elif choice == "5":
                        self.terminal_logger.info("Entering SQL injection testing module")
                        await self.handle_sql_injection()
                    elif choice == "6":
                        self.terminal_logger.info("Entering exploitation toolkit module")
                        await self.handle_exploitation_toolkit()
                    elif choice == "7":
                        self.terminal_logger.info("Entering report generation module")
                        await self.handle_report_generation()
                    elif choice == "8":
                        self.terminal_logger.info("Entering scan history module")
                        await self.handle_scan_history()
                    elif choice == "9":
                        self.terminal_logger.info("Launching web dashboard")
                        await self.launch_web_dashboard()
                    elif choice == "10":
                        self.terminal_logger.info("Entering tool configuration module")
                        await self.handle_tool_configuration()
                    elif choice == "0":
                        self.terminal_logger.info("User requested exit")
                        if Confirm.ask("[bold red]Are you sure you want to exit ReconForge?[/bold red]"):
                            self.terminal_logger.info("User confirmed exit")
                            self.console.print("[green]Thanks for using ReconForge! 🚀[/green]")
                            self.running = False
                        else:
                            self.terminal_logger.info("User cancelled exit")
                    else:
                        self.terminal_logger.warning(f"Invalid menu option selected: {choice}")
                        self.console.print("[red]Invalid option. Please try again.[/red]")
                        input("Press Enter to continue...")
                        
                except Exception as e:
                    self.terminal_logger.error(f"Error in main menu loop: {str(e)}", exc_info=True)
                    self.console.print(f"[red]An error occurred: {str(e)}[/red]")
                    input("Press Enter to continue...")
                    
        except Exception as e:
            self.terminal_logger.critical(f"Critical error in terminal interface: {str(e)}", exc_info=True)
            self.console.print(f"[red]Critical error: {str(e)}[/red]")
        finally:
            self.terminal_logger.info("=== TERMINAL INTERFACE SESSION ENDED ===")
            self.terminal_logger.info(f"Session duration: Started at initialization")
    
    async def handle_vulnerability_scanning(self):
        """Handle vulnerability scanning menu and operations"""
        self.navigation_stack = ["Main Menu", "Vulnerability Scanning"]
        
        while True:
            self.clear_screen()
            self.print_banner()
            self.print_breadcrumbs()
            
            # Show available scanners
            scanners_table = Table(title="Available Vulnerability Scanners", box=box.ROUNDED)
            scanners_table.add_column("Scanner", style="cyan")
            scanners_table.add_column("Type", style="yellow")
            scanners_table.add_column("Status", style="green")
            scanners_table.add_column("Description", style="white")
            
            for name, scanner in self.scanner_manager.scanners.items():
                status = "✓ Ready" if scanner.enabled else "✗ Disabled"
                scanner_type = getattr(scanner, 'scanner_type', 'Generic')
                scanners_table.add_row(name, scanner_type, status, scanner.description)
            
            self.console.print(scanners_table)
            self.console.print()
            
            # Scanning menu
            scanning_menu = Table(show_header=False, box=box.SIMPLE)
            scanning_menu.add_column("Option", style="cyan", width=4)
            scanning_menu.add_column("Description", style="white")
            
            scanning_options = [
                ("1", "Quick Vulnerability Scan"),
                ("2", "Comprehensive Security Assessment"),
                ("3", "Custom Scanner Selection"),
                ("4", "SSL/TLS Security Testing"),
                ("5", "Web Application Scanning"),
                ("6", "View Recent Scans"),
                ("7", "Export Scan Results"),
                ("b", "Back to Main Menu")
            ]
            
            for option, desc in scanning_options:
                scanning_menu.add_row(f"[bold cyan]{option}[/bold cyan]", desc)
            
            self.console.print(Panel(scanning_menu, title="Vulnerability Scanning Options"))
            
            choice = self.get_user_choice("Choose scanning option")
            
            if choice == "1":
                await self.run_quick_vulnerability_scan()
            elif choice == "2":
                await self.run_comprehensive_scan()
            elif choice == "3":
                await self.run_custom_scanner_selection()
            elif choice == "4":
                await self.run_ssl_scan()
            elif choice == "5":
                await self.run_web_app_scan()
            elif choice == "6":
                self.view_recent_vulnerability_scans()
            elif choice == "7":
                await self.export_vulnerability_results()
            elif choice.lower() == "b":
                self.navigation_stack.pop()
                break
            else:
                self.console.print("[red]Invalid option. Please try again.[/red]")
                input("Press Enter to continue...")
    
    async def run_quick_vulnerability_scan(self):
        """Run a quick vulnerability scan using Nuclei"""
        target = self.get_target_input()
        if not target:
            return
        
        self.current_target = target
        
        # Create scan in database
        scan_id = self.db.create_scan(target, 'vulnerability_scan', {
            'scan_type': 'quick',
            'scanners': ['nuclei'],
            'severity_filter': ['critical', 'high', 'medium']
        })
        
        self.console.print(f"[green]Starting quick vulnerability scan for: {target}[/green]")
        self.console.print("[blue]Using Nuclei with critical, high, and medium severity templates[/blue]")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=self.console
        ) as progress:
            
            task = progress.add_task("Scanning for vulnerabilities...", total=100)
            
            try:
                # Get nuclei scanner
                nuclei_scanner = self.scanner_manager.scanners.get('nuclei')
                if not nuclei_scanner:
                    self.console.print("[red]Nuclei scanner not available[/red]")
                    return
                
                # Run scan
                results = await nuclei_scanner.scan([target], severity=['critical', 'high', 'medium'], timeout=30)
                
                # Store results in database
                for result in results:
                    self.db.add_vulnerability_simple(
                        scan_id=scan_id,
                        target=result.get('target', target),
                        vulnerability_type=result.get('template_id', 'unknown'),
                        severity=result.get('severity', 'info'),
                        title=result.get('title', 'Unknown Vulnerability'),
                        description=result.get('description', ''),
                        url=result.get('matched_at', '')
                    )
                
                progress.update(task, completed=100)
                
                # Complete scan
                self.db.complete_scan(scan_id, len(results), 'vulnerability_scan')
                
                # Display results
                self.display_vulnerability_results(results, target)
                
            except Exception as e:
                self.console.print(f"[red]Vulnerability scan failed: {str(e)}[/red]")
                self.db.fail_scan(scan_id, str(e))
            
            input("Press Enter to continue...")
    
    def display_vulnerability_results(self, results: List, target: str):
        """Display vulnerability scan results"""
        if not results:
            self.console.print("[green]No vulnerabilities found! 🎉[/green]")
            return
        
        # Group by severity
        severity_counts = {}
        for result in results:
            severity = result.get('severity', 'info')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        # Display summary
        summary_table = Table(title=f"Vulnerability Summary for {target}", box=box.ROUNDED)
        summary_table.add_column("Severity", style="bold")
        summary_table.add_column("Count", style="bold")
        summary_table.add_column("Status", style="bold")
        
        severity_colors = {
            'critical': 'red',
            'high': 'orange3',
            'medium': 'yellow',
            'low': 'blue',
            'info': 'dim'
        }
        
        for severity in ['critical', 'high', 'medium', 'low', 'info']:
            count = severity_counts.get(severity, 0)
            if count > 0:
                color = severity_colors.get(severity, 'white')
                summary_table.add_row(
                    f"[{color}]{severity.upper()}[/{color}]",
                    f"[{color}]{count}[/{color}]",
                    f"[{color}]{'🚨' if severity in ['critical', 'high'] else '⚠️' if severity == 'medium' else 'ℹ️'}[/{color}]"
                )
        
        self.console.print(summary_table)
        self.console.print()
        
        # Display detailed results (first 20)
        if len(results) > 0:
            details_table = Table(title="Vulnerability Details", box=box.ROUNDED)
            details_table.add_column("Template", style="cyan")
            details_table.add_column("Severity", style="bold")
            details_table.add_column("Title", style="white")
            details_table.add_column("URL", style="dim")
            
            display_count = min(20, len(results))
            for result in results[:display_count]:
                severity = result.get('severity', 'info')
                color = severity_colors.get(severity, 'white')
                
                details_table.add_row(
                    result.get('template_id', 'Unknown'),
                    f"[{color}]{severity.upper()}[/{color}]",
                    result.get('title', 'Unknown Vulnerability'),
                    result.get('matched_at', 'N/A')
                )
            
            self.console.print(details_table)
            
            if len(results) > 20:
                self.console.print(f"[dim]Showing first 20 of {len(results)} vulnerabilities[/dim]")
    
    def view_recent_vulnerability_scans(self):
        """View recent vulnerability scans"""
        self.console.print("[cyan]Recent Vulnerability Scans:[/cyan]")
        
        try:
            with self.db.get_connection() as conn:
                cursor = conn.execute("""
                    SELECT id, target, status, start_time, total_vulns 
                    FROM scans 
                    WHERE scan_type = 'vulnerability_scan' 
                    ORDER BY start_time DESC 
                    LIMIT 10
                """)
                
                scans = cursor.fetchall()
                
                if not scans:
                    self.console.print("[yellow]No recent vulnerability scans found.[/yellow]")
                    input("Press Enter to continue...")
                    return
                
                # Create scans table
                scans_table = Table(title="Recent Vulnerability Scans", box=box.ROUNDED)
                scans_table.add_column("ID", style="cyan")
                scans_table.add_column("Target", style="green")
                scans_table.add_column("Status", style="yellow")
                scans_table.add_column("Date", style="blue")
                scans_table.add_column("Vulnerabilities", style="red")
                
                for scan in scans:
                    date_str = scan[3][:19] if scan[3] else "N/A"
                    vuln_count = scan[4] if scan[4] else 0
                    status_color = "green" if scan[2] == "completed" else "yellow" if scan[2] == "running" else "red"
                    
                    scans_table.add_row(
                        str(scan[0]), 
                        scan[1], 
                        f"[{status_color}]{scan[2]}[/{status_color}]", 
                        date_str, 
                        str(vuln_count)
                    )
                
                self.console.print(scans_table)
                
        except Exception as e:
            self.console.print(f"[red]Error fetching scan history: {str(e)}[/red]")
        
        input("Press Enter to continue...")
    
    async def run_comprehensive_scan(self):
        """Run comprehensive vulnerability scan using multiple scanners"""
        self.console.print("[yellow]Comprehensive Vulnerability Scanning - Coming soon![/yellow]")
        self.console.print("[dim]This will use multiple scanners: Nuclei, Nikto, Wapiti, and ZAP[/dim]")
        input("Press Enter to continue...")
    
    async def run_custom_scanner_selection(self):
        """Run custom scanner selection"""
        self.console.print("[yellow]Custom Scanner Selection - Coming soon![/yellow]")
        self.console.print("[dim]This will allow you to select specific scanners[/dim]")
        input("Press Enter to continue...")
    
    async def run_ssl_scan(self):
        """Run SSL/TLS security testing"""
        self.console.print("[yellow]SSL/TLS Security Testing - Coming soon![/yellow]")
        self.console.print("[dim]This will use TestSSL for certificate and TLS configuration testing[/dim]")
        input("Press Enter to continue...")
    
    async def run_web_app_scan(self):
        """Run web application scanning"""
        self.console.print("[yellow]Web Application Scanning - Coming soon![/yellow]")
        self.console.print("[dim]This will use specialized web app scanners like Wapiti and Nikto[/dim]")
        input("Press Enter to continue...")
    
    async def export_vulnerability_results(self):
        """Export vulnerability scan results"""
        self.console.print("[yellow]Vulnerability Results Export - Coming soon![/yellow]")
        self.console.print("[dim]This will allow exporting vulnerability scan results in multiple formats[/dim]")
        input("Press Enter to continue...")
    
    async def handle_port_scanning(self):
        """Placeholder for port scanning menu"""
        self.console.print("[yellow]Port Scanning module - Coming soon![/yellow]")
        input("Press Enter to continue...")
    
    async def handle_directory_enumeration(self):
        """Placeholder for directory enumeration menu"""
        self.console.print("[yellow]Directory Enumeration module - Coming soon![/yellow]")
        input("Press Enter to continue...")
    
    async def handle_sql_injection(self):
        """Placeholder for SQL injection menu"""
        self.console.print("[yellow]SQL Injection Testing module - Coming soon![/yellow]")
        input("Press Enter to continue...")
    
    async def handle_exploitation_toolkit(self):
        """Placeholder for exploitation toolkit menu"""
        self.console.print("[yellow]Exploitation Toolkit module - Coming soon![/yellow]")
        input("Press Enter to continue...")
    
    async def handle_report_generation(self):
        """Placeholder for report generation menu"""
        self.console.print("[yellow]Report Generation module - Coming soon![/yellow]")
        input("Press Enter to continue...")
    
    async def handle_scan_history(self):
        """Placeholder for scan history menu"""
        self.console.print("[yellow]Scan History module - Coming soon![/yellow]")
        input("Press Enter to continue...")
    
    async def handle_tool_configuration(self):
        """Placeholder for tool configuration menu"""
        self.console.print("[yellow]Tool Configuration module - Coming soon![/yellow]")
        input("Press Enter to continue...")


async def main():
    """Main entry point for terminal interface"""
    terminal = ReconForgeTerminal()
    await terminal.run()


if __name__ == "__main__":
    asyncio.run(main())