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
        
        # Target management and tracking
        self.targets = {}  # target -> {scans: [], subdomains: [], vulnerabilities: [], last_scan: timestamp}
        self.active_scans = {}  # scan_id -> {target, type, status, progress, start_time}
        self.current_target = None
        
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
    
    def get_terminal_size(self):
        """Get current terminal dimensions"""
        try:
            size = os.get_terminal_size()
            return size.columns, size.lines
        except:
            return 80, 24  # Default fallback
    
    def print_banner(self):
        """Print compact ReconForge banner"""
        width, height = self.get_terminal_size()
        
        # Only show banner if terminal is tall enough
        if height > 20:
            banner_text = "ReconForge v1.3.1 - Professional Reconnaissance & Penetration Testing"
            self.console.print(f"[bold cyan]{banner_text.center(width)}[/bold cyan]")
            self.console.print("[dim]" + "─" * width + "[/dim]")
        else:
            # Ultra compact mode for small terminals
            self.console.print("[bold cyan]ReconForge v1.3.1[/bold cyan]")
    
    def print_breadcrumbs(self):
        """Print current navigation breadcrumbs"""
        if self.navigation_stack:
            breadcrumb = " > ".join(self.navigation_stack)
            self.console.print(f"[dim]Navigation: {breadcrumb}[/dim]")
            self.console.print()
    
    def print_main_menu(self):
        """Display the main menu with adaptive split-screen layout"""
        self.clear_screen()
        self.print_banner()
        
        width, height = self.get_terminal_size()
        
        # Adaptive layout based on terminal size
        if width < 100 or height < 15:
            # Compact single-column layout for small terminals
            self.print_compact_menu()
        else:
            # Full split-screen layout for larger terminals using Columns
            from rich.columns import Columns
            
            # Left panel: Main menu
            left_panel = self.create_main_menu_panel()
            
            # Right panel: Active scans and targets  
            right_panel = self.create_right_panel()
            
            # Create side-by-side columns that fit content height
            columns = Columns([left_panel, right_panel], equal=False, expand=False)
            self.console.print(columns)
    
    def print_compact_menu(self):
        """Display compact single-column menu for small terminals"""
        width, height = self.get_terminal_size()
        
        # Current target info (compact)
        if self.current_target:
            self.console.print(f"[green]Target:[/green] {self.current_target}")
        
        # Compact menu options
        compact_table = Table(show_header=False, box=None, padding=(0, 1))
        compact_table.add_column("Option", style="cyan", width=3)
        compact_table.add_column("Description", style="white")
        compact_table.add_column("Status", style="dim", width=12)
        
        menu_items = [
            ("1", "Subdomain Discovery", f"({len(self.source_manager.sources)})"),
            ("2", "Vulnerability Scanning", f"({len(self.scanner_manager.scanners)})"),
            ("3", "Port Scanning", "(nmap)"),
            ("4", "Directory Enum", "(gobuster)"),
            ("5", "SQL Injection", "(sqlmap)"),
            ("6", "Exploitation", f"({len(self.pentest_manager.modules)})"),
            ("7", "Reports", "(export)"),
            ("8", "History", f"({self.get_scan_count()})"),
            ("9", "Web Dashboard", "(web)"),
            ("10", "Configuration", "(config)"),
            ("t", "Targets", f"({len(self.targets)})"),
            ("0", "Exit", "")
        ]
        
        for option, desc, status in menu_items:
            compact_table.add_row(f"[bold]{option}[/bold]", desc, status)
        
        # Show basic stats inline
        stats_line = (f"[yellow]Scans: {self.get_scan_count()}[/yellow] | "
                     f"[red]Active: {len(self.active_scans)}[/red] | " 
                     f"[blue]Targets: {len(self.targets)}[/blue]")
        
        # Display compact layout
        self.console.print(Panel(compact_table, title="ReconForge", style="cyan", padding=(0, 1)))
        self.console.print(stats_line)
    
    def create_main_menu_panel(self):
        """Create the main menu panel"""
        # Current target info
        target_info = ""
        if self.current_target:
            target_info = f"[green]Current Target:[/green] {self.current_target}\n"
        
        # Main menu options with dynamic width
        width, height = self.get_terminal_size()
        
        # Adaptive table sizing
        if width > 120:
            menu_table = Table(show_header=False, box=box.SIMPLE, padding=(0, 1))
            menu_table.add_column("Option", style="cyan", width=4)
            menu_table.add_column("Description", style="white")
            menu_table.add_column("Status", style="dim", width=18)
        else:
            menu_table = Table(show_header=False, box=box.SIMPLE, padding=(0, 1))
            menu_table.add_column("Option", style="cyan", width=3)
            menu_table.add_column("Description", style="white")
            menu_table.add_column("Status", style="dim", width=12)
        
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
            ("", "", ""),  # Spacer
            ("t", "Target Management", f"({len(self.targets)} targets)"),
            ("0", "Exit", "")
        ]
        
        for option, desc, status in menu_items:
            if option:  # Skip empty spacer rows
                menu_table.add_row(f"[bold cyan]{option}[/bold cyan]", desc, status)
            else:
                menu_table.add_row("", "", "")  # Spacer
        
        # If we have target_info, create a renderable group
        if target_info:
            from rich.console import Group
            menu_content = Group(target_info, "", menu_table)
        else:
            menu_content = menu_table
        
        width, height = self.get_terminal_size()
        
        # Minimal padding and title for compact design  
        padding = (0, 1)  # Always use minimal padding
        title = "ReconForge Professional Platform" if width > 80 else "ReconForge"
        
        return Panel(
            menu_content,
            title=title,
            style="cyan", 
            padding=padding,
            height=None  # Let panel fit content height
        )
    
    def create_right_panel(self):
        """Create the right panel showing active scans and targets"""
        from rich.text import Text
        width, height = self.get_terminal_size()
        
        content = []
        
        # Active Scans Section (compact)
        content.append("[bold yellow]🔄 Active Scans[/bold yellow]")
        
        if self.active_scans:
            active_table = Table(show_header=False, box=None, padding=(0, 0))
            active_table.add_column("Scan", style="cyan", width=8)
            active_table.add_column("Target", style="green", width=12)  
            active_table.add_column("Status", style="yellow", width=6)
            
            # Show fewer items for small terminals
            max_items = 3 if height < 20 else 5
            for scan_id, scan_info in list(self.active_scans.items())[:max_items]:
                target_short = scan_info['target'][:10] + "..." if len(scan_info['target']) > 12 else scan_info['target']
                active_table.add_row(
                    scan_info['type'][:8],
                    target_short, 
                    scan_info['status'][:6]
                )
            
            content.append(active_table)
        else:
            content.append("[dim]No active scans[/dim]")
        
        content.append("")  # Reduced spacing
        
        # Targets Section (compact)
        content.append("[bold blue]🎯 Tracked Targets[/bold blue]")
        
        if self.targets:
            targets_table = Table(show_header=False, box=None, padding=(0, 0))
            targets_table.add_column("Target", style="cyan", width=15)
            targets_table.add_column("Scans", style="magenta", width=5)
            targets_table.add_column("Subs", style="green", width=4)
            
            # Show fewer targets for small terminals
            max_targets = 4 if height < 20 else 6
            for target, info in list(self.targets.items())[:max_targets]:
                target_display = target[:13] + "..." if len(target) > 15 else target
                
                # Mark current target
                if target == self.current_target:
                    target_display = f"▶{target_display}"
                
                targets_table.add_row(
                    target_display,
                    str(len(info.get('scans', []))),
                    str(len(info.get('subdomains', [])))
                )
            
            content.append(targets_table)
        else:
            content.append("[dim]No targets tracked[/dim]")
        
        content.append("")  # Reduced spacing
        
        # Quick Stats Section (compact)
        content.append("[bold green]📊 Quick Stats[/bold green]")
        
        # Compact stats format
        if height < 20:
            # Ultra compact for small terminals
            stats_text = f"[yellow]{self.get_scan_count()}[/yellow] scans | [red]{len(self.active_scans)}[/red] active | [blue]{len(self.targets)}[/blue] targets"
        else:
            # Normal compact format
            stats_text = (
                f"Total Scans: [yellow]{self.get_scan_count()}[/yellow]\n"
                f"Active: [red]{len(self.active_scans)}[/red] | "
                f"Targets: [blue]{len(self.targets)}[/blue]\n"
                f"Time: [dim]{datetime.now().strftime('%H:%M:%S')}[/dim]"
            )
        content.append(stats_text)
        
        # Create a proper renderable group for the right panel
        from rich.console import Group
        
        renderables = []
        for item in content:
            if isinstance(item, str):
                renderables.append(item)
            else:
                renderables.append(item)
        
        width, height = self.get_terminal_size()
        
        # Minimal padding and title for compact design
        padding = (0, 1)  # Always use minimal padding
        title = "Live Status" if width > 100 else "Status"
        
        return Panel(
            Group(*renderables),
            title=title,
            style="green",
            padding=padding,
            height=None  # Let panel fit content height
        )
    
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
        
        # Add to active scans tracking
        self.add_active_scan(scan_id, target, f'subdomain_{discovery_type.lower()}')
        
        # Initialize target if not exists
        if target not in self.targets:
            self.targets[target] = {
                'scans': [],
                'subdomains': [],
                'vulnerabilities': [],
                'last_scan': None,
                'created': datetime.now().isoformat()
            }
        
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
                
                # Update target tracking
                self.update_target_info(target, f'subdomain_{discovery_type.lower()}', len(results))
                
                # Store subdomains in target tracking
                if target in self.targets:
                    for result in results:
                        if result.subdomain not in [s.get('subdomain') for s in self.targets[target]['subdomains']]:
                            self.targets[target]['subdomains'].append({
                                'subdomain': result.subdomain,
                                'ip_address': result.ip_address,
                                'source': result.source,
                                'discovered_at': datetime.now().isoformat()
                            })
                
                # Remove from active scans
                self.remove_active_scan(scan_id)
                
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
    
    def safe_input(self, prompt: str = "Press Enter to continue...") -> str:
        """Safely handle input with EOF protection"""
        try:
            return input(prompt)
        except (EOFError, KeyboardInterrupt):
            # User interrupted - return empty string to continue gracefully
            return ""
    
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
                    elif choice.lower() == "t":
                        self.terminal_logger.info("Entering target management module")
                        await self.handle_target_management()
                    elif choice == "0":
                        self.terminal_logger.info("User requested exit")
                        try:
                            if Confirm.ask("[bold red]Are you sure you want to exit ReconForge?[/bold red]"):
                                self.terminal_logger.info("User confirmed exit")
                                self.console.print("[green]Thanks for using ReconForge! 🚀[/green]")
                                self.running = False
                            else:
                                self.terminal_logger.info("User cancelled exit")
                        except (EOFError, KeyboardInterrupt):
                            # User interrupted with Ctrl+C or EOF - exit gracefully
                            self.terminal_logger.info("User interrupted exit confirmation - exiting")
                            self.console.print("[green]Thanks for using ReconForge! 🚀[/green]")
                            self.running = False
                    else:
                        self.terminal_logger.warning(f"Invalid menu option selected: {choice}")
                        self.console.print("[red]Invalid option. Please try again.[/red]")
                        self.safe_input()
                        
                except Exception as e:
                    self.terminal_logger.error(f"Error in main menu loop: {str(e)}", exc_info=True)
                    self.console.print(f"[red]An error occurred: {str(e)}[/red]")
                    self.safe_input()
                    
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
        
        # Add to active scans tracking
        self.add_active_scan(scan_id, target, 'vulnerability_quick')
        
        # Initialize target if not exists
        if target not in self.targets:
            self.targets[target] = {
                'scans': [],
                'subdomains': [],
                'vulnerabilities': [],
                'last_scan': None,
                'created': datetime.now().isoformat()
            }
        
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
    
    async def run_quick_port_scan(self):
        """Run a quick port scan on common ports"""
        target = self.get_target_input()
        if not target:
            return
        
        self.current_target = target
        
        # Create scan in database
        scan_id = self.db.create_scan(target, 'port_scan', {
            'scan_type': 'quick',
            'port_range': 'common',
            'timeout': 3
        })
        
        self.console.print(f"[green]Starting quick port scan for: {target}[/green]")
        self.console.print("[blue]Scanning common ports (21, 22, 23, 25, 53, 80, 443, etc.)[/blue]")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=self.console
        ) as progress:
            
            task = progress.add_task("Scanning ports...", total=100)
            
            try:
                # Import port scanner
                from scanners.base import PortScanner
                port_scanner = PortScanner("Quick Port Scanner")
                
                # Run port scan
                results = await port_scanner.scan_ports(target)
                progress.update(task, completed=100)
                
                if results:
                    self.console.print(f"\n[green]Found {len(results)} open ports:[/green]")
                    
                    # Display results in table
                    results_table = Table(box=box.ROUNDED)
                    results_table.add_column("Port", style="cyan")
                    results_table.add_column("Protocol", style="yellow")
                    results_table.add_column("State", style="green")
                    results_table.add_column("Service", style="white")
                    results_table.add_column("Banner", style="dim")
                    
                    for service in results:
                        banner = service.banner[:50] + "..." if service.banner and len(service.banner) > 50 else (service.banner or "")
                        results_table.add_row(
                            str(service.port),
                            service.protocol,
                            service.state,
                            service.service_name or "unknown",
                            banner
                        )
                    
                    self.console.print(results_table)
                    
                    # Save results to database
                    for service in results:
                        self.db.add_service(scan_id, service.host, service.port, 
                                          service_name=service.service_name, 
                                          banner=service.banner, 
                                          state=service.state)
                    
                    self.db.complete_scan(scan_id, len(results))
                    
                    # Update target tracking
                    self.update_target_info(target, 'vulnerability_quick', len(results))
                    
                    # Store vulnerabilities in target tracking
                    if target in self.targets and results:
                        for vuln in results:
                            self.targets[target]['vulnerabilities'].append({
                                'title': vuln.title,
                                'severity': vuln.severity.value,
                                'type': vuln.vulnerability_type,
                                'discovered_at': datetime.now().isoformat()
                            })
                    
                    # Remove from active scans
                    self.remove_active_scan(scan_id)
                    
                else:
                    self.console.print("[yellow]No open ports found[/yellow]")
                    self.db.complete_scan(scan_id, 0)
                    
            except Exception as e:
                progress.update(task, completed=100)
                self.console.print(f"[red]Port scan failed: {e}[/red]")
                self.terminal_logger.error(f"Port scan failed: {e}")
                self.db.fail_scan(scan_id, str(e))
        
        input("\nPress Enter to continue...")
    
    async def run_full_port_scan(self):
        """Run a full port scan on all ports 1-65535"""
        target = self.get_target_input()
        if not target:
            return
        
        self.console.print(f"[yellow]Warning: Full port scan can take 10+ minutes[/yellow]")
        confirm = input("Continue? (y/N): ")
        if confirm.lower() != 'y':
            return
        
        self.current_target = target
        
        # Create scan in database
        scan_id = self.db.create_scan(target, 'port_scan', {
            'scan_type': 'full',
            'port_range': '1-65535',
            'timeout': 1
        })
        
        self.console.print(f"[green]Starting full port scan for: {target}[/green]")
        self.console.print("[blue]Scanning all ports 1-65535 (this may take a while)[/blue]")
        
        try:
            # Use nmap for full scan
            import subprocess
            cmd = f"nmap -p- --min-rate 1000 -T4 {target}"
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=self.console
            ) as progress:
                
                task = progress.add_task("Running nmap full scan...", total=None)
                
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=1800)
                
                if result.returncode == 0:
                    output = result.stdout
                    self.console.print("[green]Scan completed successfully[/green]")
                    self.console.print("\n[cyan]Nmap Results:[/cyan]")
                    self.console.print(output)
                    
                    # Parse and save results (basic parsing)
                    open_ports = []
                    for line in output.split('\n'):
                        if '/tcp' in line and 'open' in line:
                            port = line.split('/')[0].strip()
                            service = line.split()[-1] if len(line.split()) > 2 else 'unknown'
                            open_ports.append({'port': port, 'service': service})
                            self.db.add_service(scan_id, target, int(port), 
                                               service_name=service, service_version='', state='open')
                    
                    self.db.complete_scan(scan_id, len(open_ports))
                    self.console.print(f"\n[green]Found {len(open_ports)} open ports[/green]")
                    
                else:
                    self.console.print(f"[red]Nmap scan failed: {result.stderr}[/red]")
                    self.db.fail_scan(scan_id, result.stderr)
                    
        except subprocess.TimeoutExpired:
            self.console.print("[red]Scan timed out after 30 minutes[/red]")
            self.db.fail_scan(scan_id, "Timeout")
        except Exception as e:
            self.console.print(f"[red]Full port scan failed: {e}[/red]")
            self.terminal_logger.error(f"Full port scan failed: {e}")
            self.db.fail_scan(scan_id, str(e))
        
        input("\nPress Enter to continue...")
    
    async def run_custom_port_scan(self):
        """Run a custom port range scan"""
        target = self.get_target_input()
        if not target:
            return
        
        port_range = input("Enter port range (e.g., 80,443 or 8000-9000): ")
        if not port_range:
            self.console.print("[red]Port range is required[/red]")
            return
        
        self.current_target = target
        
        # Create scan in database
        scan_id = self.db.create_scan(target, 'port_scan', {
            'scan_type': 'custom',
            'port_range': port_range,
            'timeout': 3
        })
        
        self.console.print(f"[green]Starting custom port scan for: {target}[/green]")
        self.console.print(f"[blue]Scanning ports: {port_range}[/blue]")
        
        try:
            # Use nmap for custom range
            import subprocess
            cmd = f"nmap -p{port_range} {target}"
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=self.console
            ) as progress:
                
                task = progress.add_task("Running custom port scan...", total=None)
                
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=300)
                
                if result.returncode == 0:
                    output = result.stdout
                    self.console.print("[green]Scan completed successfully[/green]")
                    self.console.print("\n[cyan]Nmap Results:[/cyan]")
                    self.console.print(output)
                    
                    # Parse and save results
                    open_ports = []
                    for line in output.split('\n'):
                        if '/tcp' in line and 'open' in line:
                            port = line.split('/')[0].strip()
                            service = line.split()[-1] if len(line.split()) > 2 else 'unknown'
                            open_ports.append({'port': port, 'service': service})
                            self.db.add_service(scan_id, target, int(port), 
                                               service_name=service, service_version='', state='open')
                    
                    self.db.complete_scan(scan_id, len(open_ports))
                    self.console.print(f"\n[green]Found {len(open_ports)} open ports[/green]")
                    
                else:
                    self.console.print(f"[red]Nmap scan failed: {result.stderr}[/red]")
                    self.db.fail_scan(scan_id, result.stderr)
                    
        except subprocess.TimeoutExpired:
            self.console.print("[red]Scan timed out after 5 minutes[/red]")
            self.db.fail_scan(scan_id, "Timeout")
        except Exception as e:
            self.console.print(f"[red]Custom port scan failed: {e}[/red]")
            self.terminal_logger.error(f"Custom port scan failed: {e}")
            self.db.fail_scan(scan_id, str(e))
        
        input("\nPress Enter to continue...")
    
    async def run_service_detection(self):
        """Run service detection on open ports"""
        target = self.get_target_input()
        if not target:
            return
        
        self.current_target = target
        
        # Create scan in database
        scan_id = self.db.create_scan(target, 'service_detection', {
            'scan_type': 'service_detection',
            'timeout': 10
        })
        
        self.console.print(f"[green]Starting service detection for: {target}[/green]")
        self.console.print("[blue]Detecting services and versions on open ports[/blue]")
        
        try:
            # Use nmap for service detection
            import subprocess
            cmd = f"nmap -sV -sC {target}"
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=self.console
            ) as progress:
                
                task = progress.add_task("Running service detection...", total=None)
                
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=600)
                
                if result.returncode == 0:
                    output = result.stdout
                    self.console.print("[green]Service detection completed[/green]")
                    self.console.print("\n[cyan]Service Detection Results:[/cyan]")
                    self.console.print(output)
                    
                    # Parse and save results
                    services_found = 0
                    for line in output.split('\n'):
                        if '/tcp' in line and 'open' in line:
                            parts = line.split()
                            if len(parts) >= 3:
                                port = parts[0].split('/')[0]
                                service = parts[2] if len(parts) > 2 else 'unknown'
                                version = ' '.join(parts[3:]) if len(parts) > 3 else ''
                                self.db.add_service(scan_id, target, int(port), 
                                                   service_name=service, service_version=version, state='open')
                                services_found += 1
                    
                    self.db.complete_scan(scan_id, services_found)
                    
                else:
                    self.console.print(f"[red]Service detection failed: {result.stderr}[/red]")
                    self.db.fail_scan(scan_id, result.stderr)
                    
        except subprocess.TimeoutExpired:
            self.console.print("[red]Scan timed out after 10 minutes[/red]")
            self.db.fail_scan(scan_id, "Timeout")
        except Exception as e:
            self.console.print(f"[red]Service detection failed: {e}[/red]")
            self.terminal_logger.error(f"Service detection failed: {e}")
            self.db.fail_scan(scan_id, str(e))
        
        input("\nPress Enter to continue...")
    
    def view_recent_port_scans(self):
        """View recent port scanning results"""
        self.console.print("[cyan]Recent Port Scans:[/cyan]")
        
        try:
            # Get recent port scans from database
            scans = self.db.get_recent_scans('port_scan', limit=10)
            
            if scans:
                scans_table = Table(box=box.ROUNDED)
                scans_table.add_column("ID", style="cyan")
                scans_table.add_column("Target", style="yellow")
                scans_table.add_column("Type", style="green")
                scans_table.add_column("Status", style="white")
                scans_table.add_column("Results", style="magenta")
                scans_table.add_column("Date", style="dim")
                
                for scan in scans:
                    scans_table.add_row(
                        str(scan[0]),  # id
                        scan[1],       # target
                        scan[2],       # scan_type
                        scan[4],       # status
                        str(scan[6]),  # results_count
                        str(scan[5])[:19] if scan[5] else ""  # created_at
                    )
                
                self.console.print(scans_table)
            else:
                self.console.print("[yellow]No recent port scans found[/yellow]")
                
        except Exception as e:
            self.console.print(f"[red]Failed to retrieve port scans: {e}[/red]")
            self.terminal_logger.error(f"Failed to retrieve port scans: {e}")
        
        input("\nPress Enter to continue...")
    
    async def handle_port_scanning(self):
        """Handle port scanning operations"""
        self.navigation_stack.append('Port Scanning')
        
        while True:
            self.print_banner()
            self.print_breadcrumbs()
            
            # Show port scanning options
            scanning_menu = Table(show_header=False, box=box.SIMPLE)
            scanning_menu.add_column("Option", style="cyan", width=4)
            scanning_menu.add_column("Description", style="white")
            
            scanning_options = [
                ("1", "Quick Port Scan (Common Ports)"),
                ("2", "Full Port Scan (All Ports)"),
                ("3", "Custom Port Range"),
                ("4", "Service Detection"),
                ("5", "View Recent Port Scans"),
                ("b", "Back to Main Menu")
            ]
            
            for option, desc in scanning_options:
                scanning_menu.add_row(f"[bold cyan]{option}[/bold cyan]", desc)
            
            self.console.print(Panel(scanning_menu, title="Port Scanning Options"))
            
            choice = self.get_user_choice("Choose scanning option")
            
            if choice == "1":
                await self.run_quick_port_scan()
            elif choice == "2":
                await self.run_full_port_scan()
            elif choice == "3":
                await self.run_custom_port_scan()
            elif choice == "4":
                await self.run_service_detection()
            elif choice == "5":
                self.view_recent_port_scans()
            elif choice.lower() == "b":
                self.navigation_stack.pop()
                break
            else:
                self.console.print("[red]Invalid option. Please try again.[/red]")
                input("Press Enter to continue...")
    
    async def handle_directory_enumeration(self):
        """Handle directory enumeration operations"""
        self.navigation_stack.append('Directory Enumeration')
        
        while True:
            self.print_banner()
            self.print_breadcrumbs()
            
            # Show directory enumeration options
            enum_menu = Table(show_header=False, box=box.SIMPLE)
            enum_menu.add_column("Option", style="cyan", width=4)
            enum_menu.add_column("Description", style="white")
            
            enum_options = [
                ("1", "Quick Directory Scan (Common directories)"),
                ("2", "Comprehensive Directory Brute Force"),
                ("3", "File Extension Discovery"),
                ("4", "Custom Wordlist Scan"),
                ("5", "View Recent Directory Scans"),
                ("b", "Back to Main Menu")
            ]
            
            for option, desc in enum_options:
                enum_menu.add_row(f"[bold cyan]{option}[/bold cyan]", desc)
            
            self.console.print(Panel(enum_menu, title="Directory Enumeration Options"))
            
            choice = self.get_user_choice("Choose enumeration option")
            
            if choice == "1":
                await self.run_quick_directory_scan()
            elif choice == "2":
                await self.run_comprehensive_directory_scan()
            elif choice == "3":
                await self.run_file_extension_discovery()
            elif choice == "4":
                await self.run_custom_wordlist_scan()
            elif choice == "5":
                self.view_recent_directory_scans()
            elif choice.lower() == "b":
                self.navigation_stack.pop()
                break
            else:
                self.console.print("[red]Invalid option. Please try again.[/red]")
                input("Press Enter to continue...")
    
    async def handle_sql_injection(self):
        """Handle SQL injection testing operations"""
        self.navigation_stack.append('SQL Injection Testing')
        
        while True:
            self.print_banner()
            self.print_breadcrumbs()
            
            # Show SQL injection testing options
            sqli_menu = Table(show_header=False, box=box.SIMPLE)
            sqli_menu.add_column("Option", style="cyan", width=4)
            sqli_menu.add_column("Description", style="white")
            
            sqli_options = [
                ("1", "URL-based SQL Injection Test"),
                ("2", "Form-based SQL Injection Test"),
                ("3", "Database Enumeration"),
                ("4", "Advanced SQLMap Scan"),
                ("5", "View Recent SQL Injection Tests"),
                ("b", "Back to Main Menu")
            ]
            
            for option, desc in sqli_options:
                sqli_menu.add_row(f"[bold cyan]{option}[/bold cyan]", desc)
            
            self.console.print(Panel(sqli_menu, title="SQL Injection Testing Options"))
            
            choice = self.get_user_choice("Choose testing option")
            
            if choice == "1":
                await self.run_url_sql_injection_test()
            elif choice == "2":
                await self.run_form_sql_injection_test()
            elif choice == "3":
                await self.run_database_enumeration()
            elif choice == "4":
                await self.run_advanced_sqlmap_scan()
            elif choice == "5":
                self.view_recent_sql_injection_tests()
            elif choice.lower() == "b":
                self.navigation_stack.pop()
                break
            else:
                self.console.print("[red]Invalid option. Please try again.[/red]")
                input("Press Enter to continue...")
    
    async def handle_exploitation_toolkit(self):
        """Handle exploitation toolkit operations"""
        self.navigation_stack.append('Exploitation Toolkit')
        
        while True:
            self.print_banner()
            self.print_breadcrumbs()
            
            # Show exploitation toolkit options
            exploit_menu = Table(show_header=False, box=box.SIMPLE)
            exploit_menu.add_column("Option", style="cyan", width=4)
            exploit_menu.add_column("Description", style="white")
            
            exploit_options = [
                ("1", "SSRF (Server-Side Request Forgery) Testing"),
                ("2", "XXE (XML External Entity) Testing"),
                ("3", "RCE (Remote Code Execution) Testing"),
                ("4", "Directory Traversal Testing"),
                ("5", "Metasploit Framework Integration"),
                ("6", "View Recent Exploitation Tests"),
                ("b", "Back to Main Menu")
            ]
            
            for option, desc in exploit_options:
                exploit_menu.add_row(f"[bold cyan]{option}[/bold cyan]", desc)
            
            self.console.print(Panel(exploit_menu, title="Exploitation Toolkit Options"))
            
            choice = self.get_user_choice("Choose exploitation option")
            
            if choice == "1":
                await self.run_ssrf_testing()
            elif choice == "2":
                await self.run_xxe_testing()
            elif choice == "3":
                await self.run_rce_testing()
            elif choice == "4":
                await self.run_directory_traversal_testing()
            elif choice == "5":
                await self.run_metasploit_integration()
            elif choice == "6":
                self.view_recent_exploitation_tests()
            elif choice.lower() == "b":
                self.navigation_stack.pop()
                break
            else:
                self.console.print("[red]Invalid option. Please try again.[/red]")
                input("Press Enter to continue...")
    
    async def handle_report_generation(self):
        """Handle report generation operations"""
        self.navigation_stack.append('Report Generation')
        
        while True:
            self.print_banner()
            self.print_breadcrumbs()
            
            # Show report generation options
            report_menu = Table(show_header=False, box=box.SIMPLE)
            report_menu.add_column("Option", style="cyan", width=4)
            report_menu.add_column("Description", style="white")
            
            report_options = [
                ("1", "Generate JSON Report"),
                ("2", "Generate HTML Report"),
                ("3", "Generate CSV Export"),
                ("4", "Generate Text Summary"),
                ("5", "Export All Scan Data"),
                ("6", "View Export History"),
                ("b", "Back to Main Menu")
            ]
            
            for option, desc in report_options:
                report_menu.add_row(f"[bold cyan]{option}[/bold cyan]", desc)
            
            self.console.print(Panel(report_menu, title="Report Generation Options"))
            
            choice = self.get_user_choice("Choose report option")
            
            if choice == "1":
                await self.generate_json_report()
            elif choice == "2":
                await self.generate_html_report()
            elif choice == "3":
                await self.generate_csv_export()
            elif choice == "4":
                await self.generate_text_summary()
            elif choice == "5":
                await self.export_all_scan_data()
            elif choice == "6":
                self.view_export_history()
            elif choice.lower() == "b":
                self.navigation_stack.pop()
                break
            else:
                self.console.print("[red]Invalid option. Please try again.[/red]")
                input("Press Enter to continue...")
    
    async def handle_scan_history(self):
        """Handle scan history operations"""
        self.navigation_stack.append('Scan History')
        
        while True:
            self.print_banner()
            self.print_breadcrumbs()
            
            # Show scan history options
            history_menu = Table(show_header=False, box=box.SIMPLE)
            history_menu.add_column("Option", style="cyan", width=4)
            history_menu.add_column("Description", style="white")
            
            history_options = [
                ("1", "View All Recent Scans"),
                ("2", "View Subdomain Discovery History"),
                ("3", "View Vulnerability Scan History"),
                ("4", "View Port Scan History"),
                ("5", "View SQL Injection Test History"),
                ("6", "Search Scan History"),
                ("7", "Delete Old Scans"),
                ("b", "Back to Main Menu")
            ]
            
            for option, desc in history_options:
                history_menu.add_row(f"[bold cyan]{option}[/bold cyan]", desc)
            
            self.console.print(Panel(history_menu, title="Scan History Options"))
            
            choice = self.get_user_choice("Choose history option")
            
            if choice == "1":
                self.view_all_recent_scans()
            elif choice == "2":
                self.view_subdomain_scan_history()
            elif choice == "3":
                self.view_vulnerability_scan_history()
            elif choice == "4":
                self.view_port_scan_history()
            elif choice == "5":
                self.view_sql_injection_history()
            elif choice == "6":
                self.search_scan_history()
            elif choice == "7":
                self.delete_old_scans()
            elif choice.lower() == "b":
                self.navigation_stack.pop()
                break
            else:
                self.console.print("[red]Invalid option. Please try again.[/red]")
                input("Press Enter to continue...")
    
    async def handle_tool_configuration(self):
        """Handle tool configuration operations"""
        self.navigation_stack.append('Tool Configuration')
        
        while True:
            self.print_banner()
            self.print_breadcrumbs()
            
            # Show tool configuration options
            config_menu = Table(show_header=False, box=box.SIMPLE)
            config_menu.add_column("Option", style="cyan", width=4)
            config_menu.add_column("Description", style="white")
            
            config_options = [
                ("1", "Check Tool Installation Status"),
                ("2", "Configure API Keys"),
                ("3", "Update Tool Settings"),
                ("4", "Install Missing Tools"),
                ("5", "Test Tool Functionality"),
                ("6", "View Configuration"),
                ("b", "Back to Main Menu")
            ]
            
            for option, desc in config_options:
                config_menu.add_row(f"[bold cyan]{option}[/bold cyan]", desc)
            
            self.console.print(Panel(config_menu, title="Tool Configuration Options"))
            
            choice = self.get_user_choice("Choose configuration option")
            
            if choice == "1":
                await self.check_tool_installation()
            elif choice == "2":
                self.configure_api_keys()
            elif choice == "3":
                self.update_tool_settings()
            elif choice == "4":
                await self.install_missing_tools()
            elif choice == "5":
                await self.test_tool_functionality()
            elif choice == "6":
                self.view_configuration()
            elif choice.lower() == "b":
                self.navigation_stack.pop()
                break
            else:
                self.console.print("[red]Invalid option. Please try again.[/red]")
                input("Press Enter to continue...")
    
    async def run_quick_directory_scan(self):
        """Run a quick directory scan using common directories"""
        target = self.get_target_input()
        if not target:
            return
        
        # Ensure target has protocol
        if not target.startswith(('http://', 'https://')):
            protocol = input("Enter protocol (http/https) [default: http]: ").strip() or "http"
            target = f"{protocol}://{target}"
        
        self.current_target = target
        
        # Create scan in database
        scan_id = self.db.create_scan(target, 'directory_enum', {
            'scan_type': 'quick',
            'wordlist': 'common',
            'extensions': []
        })
        
        self.console.print(f"[green]Starting quick directory scan for: {target}[/green]")
        self.console.print("[blue]Using common directory names[/blue]")
        
        try:
            # Use gobuster for directory enumeration
            import subprocess
            cmd = f"gobuster dir -u {target} -w /usr/share/wordlists/dirb/common.txt -q --no-error"
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=self.console
            ) as progress:
                
                task = progress.add_task("Running directory enumeration...", total=None)
                
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=300)
                
                if result.returncode == 0:
                    output = result.stdout
                    if output.strip():
                        self.console.print("[green]Directory scan completed[/green]")
                        self.console.print("\n[cyan]Found Directories:[/cyan]")
                        self.console.print(output)
                        self.db.complete_scan(scan_id, len(output.split('\n')))
                    else:
                        self.console.print("[yellow]No directories found[/yellow]")
                        self.db.complete_scan(scan_id, 0)
                else:
                    self.console.print(f"[red]Gobuster scan failed: {result.stderr}[/red]")
                    self.db.fail_scan(scan_id, result.stderr)
                    
        except subprocess.TimeoutExpired:
            self.console.print("[red]Scan timed out after 5 minutes[/red]")
            self.db.fail_scan(scan_id, "Timeout")
        except FileNotFoundError:
            self.console.print("[red]Gobuster not found. Please install gobuster.[/red]")
            self.db.fail_scan(scan_id, "Gobuster not installed")
        except Exception as e:
            self.console.print(f"[red]Directory scan failed: {e}[/red]")
            self.terminal_logger.error(f"Directory scan failed: {e}")
            self.db.fail_scan(scan_id, str(e))
        
        input("\nPress Enter to continue...")
    
    def view_recent_directory_scans(self):
        """View recent directory enumeration results"""
        self.console.print("[cyan]Recent Directory Scans:[/cyan]")
        
        try:
            # Get recent directory scans from database
            scans = self.db.get_recent_scans('directory_enum', limit=10)
            
            if scans:
                scans_table = Table(box=box.ROUNDED)
                scans_table.add_column("ID", style="cyan")
                scans_table.add_column("Target", style="yellow")
                scans_table.add_column("Type", style="green")
                scans_table.add_column("Status", style="white")
                scans_table.add_column("Results", style="magenta")
                scans_table.add_column("Date", style="dim")
                
                for scan in scans:
                    scans_table.add_row(
                        str(scan[0]),  # id
                        scan[1],       # target
                        scan[2],       # scan_type
                        scan[4],       # status
                        str(scan[6]),  # results_count
                        str(scan[5])[:19] if scan[5] else ""  # created_at
                    )
                
                self.console.print(scans_table)
            else:
                self.console.print("[yellow]No recent directory scans found[/yellow]")
                
        except Exception as e:
            self.console.print(f"[red]Failed to retrieve directory scans: {e}[/red]")
            self.terminal_logger.error(f"Failed to retrieve directory scans: {e}")
        
        input("\nPress Enter to continue...")
    
    async def run_url_sql_injection_test(self):
        """Run SQL injection test on a specific URL"""
        target = input("Enter target URL with parameter (e.g., http://example.com/page?id=1): ")
        if not target:
            self.console.print("[red]URL is required[/red]")
            return
        
        self.current_target = target
        
        # Create scan in database
        scan_id = self.db.create_scan(target, 'sql_injection', {
            'scan_type': 'url_based',
            'tool': 'sqlmap'
        })
        
        self.console.print(f"[green]Starting SQL injection test for: {target}[/green]")
        self.console.print("[blue]Using SQLMap for automated testing[/blue]")
        
        try:
            # Use sqlmap for SQL injection testing
            import subprocess
            cmd = f"sqlmap -u '{target}' --batch --risk=1 --level=1 --threads=5 --timeout=10"
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=self.console
            ) as progress:
                
                task = progress.add_task("Running SQL injection test...", total=None)
                
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=600)
                
                if result.returncode == 0:
                    output = result.stdout
                    self.console.print("[green]SQL injection test completed[/green]")
                    self.console.print("\n[cyan]SQLMap Results:[/cyan]")
                    
                    # Parse output for vulnerabilities
                    if "is vulnerable" in output.lower() or "injectable" in output.lower():
                        self.console.print("[red]🚨 SQL INJECTION VULNERABILITY FOUND! 🚨[/red]")
                        # Extract vulnerable parameters
                        vuln_lines = [line for line in output.split('\n') if 'vulnerable' in line.lower() or 'injectable' in line.lower()]
                        for line in vuln_lines[:5]:  # Show first 5 matches
                            self.console.print(f"[yellow]{line.strip()}[/yellow]")
                        self.db.add_vulnerability_simple(scan_id, target, 'sql_injection', 'high', 'SQL Injection vulnerability found', 'sqlmap')
                        vuln_count = 1
                    else:
                        self.console.print("[green]No SQL injection vulnerabilities found[/green]")
                        vuln_count = 0
                    
                    self.console.print("\n[dim]Full SQLMap output:[/dim]")
                    self.console.print(output[:1000] + "..." if len(output) > 1000 else output)
                    
                    self.db.complete_scan(scan_id, vuln_count)
                    
                else:
                    self.console.print(f"[red]SQLMap test failed: {result.stderr}[/red]")
                    self.db.fail_scan(scan_id, result.stderr)
                    
        except subprocess.TimeoutExpired:
            self.console.print("[red]Test timed out after 10 minutes[/red]")
            self.db.fail_scan(scan_id, "Timeout")
        except FileNotFoundError:
            self.console.print("[red]SQLMap not found. Please install sqlmap.[/red]")
            self.db.fail_scan(scan_id, "SQLMap not installed")
        except Exception as e:
            self.console.print(f"[red]SQL injection test failed: {e}[/red]")
            self.terminal_logger.error(f"SQL injection test failed: {e}")
            self.db.fail_scan(scan_id, str(e))
        
        input("\nPress Enter to continue...")
    
    async def run_form_sql_injection_test(self):
        """Run SQL injection test on forms"""
        target = input("Enter target URL with login form (e.g., http://example.com/login.php): ")
        if not target:
            self.console.print("[red]URL is required[/red]")
            return
        
        self.current_target = target
        
        # Create scan in database
        scan_id = self.db.create_scan(target, 'sql_injection', {
            'scan_type': 'form_based',
            'tool': 'sqlmap'
        })
        
        self.console.print(f"[green]Starting form-based SQL injection test for: {target}[/green]")
        self.console.print("[blue]Using SQLMap to detect and test forms[/blue]")
        
        try:
            # Use sqlmap with form detection
            import subprocess
            cmd = f"sqlmap -u '{target}' --forms --batch --risk=1 --level=1 --threads=5 --timeout=10"
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=self.console
            ) as progress:
                
                task = progress.add_task("Testing forms for SQL injection...", total=None)
                
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=600)
                
                if result.returncode == 0:
                    output = result.stdout
                    self.console.print("[green]Form-based SQL injection test completed[/green]")
                    
                    # Parse output for vulnerabilities
                    if "is vulnerable" in output.lower() or "injectable" in output.lower():
                        self.console.print("[red]🚨 FORM SQL INJECTION VULNERABILITY FOUND! 🚨[/red]")
                        # Extract vulnerable parameters
                        vuln_lines = [line for line in output.split('\n') if 'vulnerable' in line.lower() or 'injectable' in line.lower()]
                        for line in vuln_lines[:3]:
                            self.console.print(f"[yellow]{line.strip()}[/yellow]")
                        self.db.add_vulnerability_simple(scan_id, target, 'sql_injection', 'high', 'Form-based SQL Injection vulnerability found', 'sqlmap')
                        vuln_count = 1
                    else:
                        self.console.print("[green]No form-based SQL injection vulnerabilities found[/green]")
                        vuln_count = 0
                    
                    self.console.print("\n[cyan]Forms detected and tested:[/cyan]")
                    form_lines = [line for line in output.split('\n') if 'form' in line.lower()][:5]
                    for line in form_lines:
                        self.console.print(f"[dim]{line.strip()}[/dim]")
                    
                    self.db.complete_scan(scan_id, vuln_count)
                    
                else:
                    self.console.print(f"[red]Form SQL injection test failed: {result.stderr}[/red]")
                    self.db.fail_scan(scan_id, result.stderr)
                    
        except subprocess.TimeoutExpired:
            self.console.print("[red]Test timed out after 10 minutes[/red]")
            self.db.fail_scan(scan_id, "Timeout")
        except FileNotFoundError:
            self.console.print("[red]SQLMap not found. Please install sqlmap.[/red]")
            self.db.fail_scan(scan_id, "SQLMap not installed")
        except Exception as e:
            self.console.print(f"[red]Form SQL injection test failed: {e}[/red]")
            self.terminal_logger.error(f"Form SQL injection test failed: {e}")
            self.db.fail_scan(scan_id, str(e))
        
        input("\nPress Enter to continue...")
    
    async def run_database_enumeration(self):
        """Run database enumeration after finding SQL injection"""
        target = input("Enter vulnerable URL (from previous test): ")
        if not target:
            self.console.print("[red]URL is required[/red]")
            return
        
        self.console.print(f"[yellow]Warning: Database enumeration will actively exploit the vulnerability[/yellow]")
        confirm = input("Continue with enumeration? (y/N): ")
        if confirm.lower() != 'y':
            return
        
        self.current_target = target
        
        # Create scan in database
        scan_id = self.db.create_scan(target, 'sql_injection', {
            'scan_type': 'enumeration',
            'tool': 'sqlmap'
        })
        
        self.console.print(f"[green]Starting database enumeration for: {target}[/green]")
        self.console.print("[blue]Enumerating databases, tables, and columns[/blue]")
        
        try:
            # Use sqlmap for database enumeration
            import subprocess
            cmd = f"sqlmap -u '{target}' --batch --dbs --tables --columns --timeout=20"
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=self.console
            ) as progress:
                
                task = progress.add_task("Enumerating database structure...", total=None)
                
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=900)
                
                if result.returncode == 0:
                    output = result.stdout
                    self.console.print("[green]Database enumeration completed[/green]")
                    
                    # Parse and display databases
                    if "available databases" in output.lower():
                        self.console.print("\n[cyan]Found Databases:[/cyan]")
                        db_section = False
                        for line in output.split('\n'):
                            if "available databases" in line.lower():
                                db_section = True
                                continue
                            elif db_section and line.strip():
                                if line.startswith('[') and 'INFO' in line:
                                    continue
                                elif line.strip() and not line.startswith('Database:'):
                                    self.console.print(f"[yellow]• {line.strip()}[/yellow]")
                                elif line.startswith('Database:'):
                                    break
                    
                    # Parse and display tables
                    if "tables" in output.lower():
                        self.console.print("\n[cyan]Found Tables:[/cyan]")
                        table_lines = [line for line in output.split('\n') if 'table' in line.lower()][:10]
                        for line in table_lines:
                            if not line.startswith('[') or 'INFO' not in line:
                                self.console.print(f"[dim]{line.strip()}[/dim]")
                    
                    self.db.complete_scan(scan_id, 1)
                    
                else:
                    self.console.print(f"[red]Database enumeration failed: {result.stderr}[/red]")
                    self.db.fail_scan(scan_id, result.stderr)
                    
        except subprocess.TimeoutExpired:
            self.console.print("[red]Enumeration timed out after 15 minutes[/red]")
            self.db.fail_scan(scan_id, "Timeout")
        except FileNotFoundError:
            self.console.print("[red]SQLMap not found. Please install sqlmap.[/red]")
            self.db.fail_scan(scan_id, "SQLMap not installed")
        except Exception as e:
            self.console.print(f"[red]Database enumeration failed: {e}[/red]")
            self.terminal_logger.error(f"Database enumeration failed: {e}")
            self.db.fail_scan(scan_id, str(e))
        
        input("\nPress Enter to continue...")
    
    async def run_advanced_sqlmap_scan(self):
        """Run advanced SQLMap scan with custom options"""
        target = input("Enter target URL: ")
        if not target:
            self.console.print("[red]URL is required[/red]")
            return
        
        self.console.print("[cyan]Advanced SQLMap Options:[/cyan]")
        self.console.print("[dim]Leave blank for default values[/dim]")
        
        risk_level = input("Risk level (1-3) [default: 1]: ").strip() or "1"
        level = input("Level (1-5) [default: 1]: ").strip() or "1"
        threads = input("Threads (1-10) [default: 5]: ").strip() or "5"
        technique = input("Technique (B,E,U,S,T,Q) [default: all]: ").strip()
        
        self.current_target = target
        
        # Create scan in database
        scan_id = self.db.create_scan(target, 'sql_injection', {
            'scan_type': 'advanced',
            'tool': 'sqlmap',
            'risk': risk_level,
            'level': level,
            'threads': threads
        })
        
        self.console.print(f"[green]Starting advanced SQL injection scan for: {target}[/green]")
        self.console.print(f"[blue]Risk: {risk_level}, Level: {level}, Threads: {threads}[/blue]")
        
        try:
            # Build sqlmap command
            import subprocess
            cmd = f"sqlmap -u '{target}' --batch --risk={risk_level} --level={level} --threads={threads} --timeout=15"
            
            if technique:
                cmd += f" --technique={technique}"
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=self.console
            ) as progress:
                
                task = progress.add_task("Running advanced SQL injection scan...", total=None)
                
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=900)
                
                if result.returncode == 0:
                    output = result.stdout
                    self.console.print("[green]Advanced SQL injection scan completed[/green]")
                    
                    # Analyze results
                    if "is vulnerable" in output.lower() or "injectable" in output.lower():
                        self.console.print("[red]🚨 SQL INJECTION VULNERABILITIES FOUND! 🚨[/red]")
                        
                        # Extract injection techniques found
                        techniques = []
                        if "boolean-based blind" in output.lower():
                            techniques.append("Boolean-based blind")
                        if "time-based blind" in output.lower():
                            techniques.append("Time-based blind")
                        if "error-based" in output.lower():
                            techniques.append("Error-based")
                        if "union query" in output.lower():
                            techniques.append("UNION query")
                        
                        if techniques:
                            self.console.print(f"[yellow]Injection techniques found: {', '.join(techniques)}[/yellow]")
                        
                        self.db.add_vulnerability_simple(scan_id, target, 'sql_injection', 'high', 
                                                        f'Advanced SQL Injection found: {techniques}', 'sqlmap')
                        vuln_count = len(techniques) or 1
                    else:
                        self.console.print("[green]No SQL injection vulnerabilities found[/green]")
                        vuln_count = 0
                    
                    # Show summary
                    self.console.print("\n[cyan]Scan Summary:[/cyan]")
                    summary_lines = [line for line in output.split('\n') if 'tested' in line.lower() or 'parameter' in line.lower()][:5]
                    for line in summary_lines:
                        if not line.startswith('['):
                            self.console.print(f"[dim]{line.strip()}[/dim]")
                    
                    self.db.complete_scan(scan_id, vuln_count)
                    
                else:
                    self.console.print(f"[red]Advanced SQL injection scan failed: {result.stderr}[/red]")
                    self.db.fail_scan(scan_id, result.stderr)
                    
        except subprocess.TimeoutExpired:
            self.console.print("[red]Scan timed out after 15 minutes[/red]")
            self.db.fail_scan(scan_id, "Timeout")
        except FileNotFoundError:
            self.console.print("[red]SQLMap not found. Please install sqlmap.[/red]")
            self.db.fail_scan(scan_id, "SQLMap not installed")
        except Exception as e:
            self.console.print(f"[red]Advanced SQL injection scan failed: {e}[/red]")
            self.terminal_logger.error(f"Advanced SQL injection scan failed: {e}")
            self.db.fail_scan(scan_id, str(e))
        
        input("\nPress Enter to continue...")
    
    def view_recent_sql_injection_tests(self):
        """View recent SQL injection test results"""
        self.console.print("[cyan]Recent SQL Injection Tests:[/cyan]")
        
        try:
            # Get recent SQL injection scans from database
            scans = self.db.get_recent_scans('sql_injection', limit=10)
            
            if scans:
                scans_table = Table(box=box.ROUNDED)
                scans_table.add_column("ID", style="cyan")
                scans_table.add_column("Target", style="yellow")
                scans_table.add_column("Type", style="green")
                scans_table.add_column("Status", style="white")
                scans_table.add_column("Vulnerabilities", style="red")
                scans_table.add_column("Date", style="dim")
                
                for scan in scans:
                    scans_table.add_row(
                        str(scan[0]),  # id
                        scan[1][:30] + "..." if len(scan[1]) > 30 else scan[1],  # target
                        scan[2],       # scan_type
                        scan[4],       # status
                        str(scan[6]),  # results_count
                        str(scan[5])[:19] if scan[5] else ""  # created_at
                    )
                
                self.console.print(scans_table)
            else:
                self.console.print("[yellow]No recent SQL injection tests found[/yellow]")
                
        except Exception as e:
            self.console.print(f"[red]Failed to retrieve SQL injection tests: {e}[/red]")
            self.terminal_logger.error(f"Failed to retrieve SQL injection tests: {e}")
        
        input("\nPress Enter to continue...")
    
    # Basic implementations for the remaining methods
    async def run_ssrf_testing(self):
        """Run SSRF testing using pentest modules"""
        target = self.get_target_input()
        if not target:
            return
        
        self.console.print(f"[green]Starting SSRF testing for: {target}[/green]")
        
        try:
            from pentest.ssrf import SSRFTester
            ssrf_tester = SSRFTester()
            results = await ssrf_tester.test(target)
            
            if results:
                self.console.print("[red]SSRF vulnerabilities found![/red]")
                for result in results[:5]:
                    self.console.print(f"[yellow]{result.title}[/yellow]")
            else:
                self.console.print("[green]No SSRF vulnerabilities found[/green]")
                
        except Exception as e:
            self.console.print(f"[red]SSRF testing failed: {e}[/red]")
        
        input("\nPress Enter to continue...")
    
    async def run_xxe_testing(self):
        """Run XXE testing using pentest modules"""
        target = self.get_target_input()
        if not target:
            return
        
        self.console.print(f"[green]Starting XXE testing for: {target}[/green]")
        
        try:
            from pentest.xxe import XXETester
            xxe_tester = XXETester()
            results = await xxe_tester.test(target)
            
            if results:
                self.console.print("[red]XXE vulnerabilities found![/red]")
                for result in results[:5]:
                    self.console.print(f"[yellow]{result.title}[/yellow]")
            else:
                self.console.print("[green]No XXE vulnerabilities found[/green]")
                
        except Exception as e:
            self.console.print(f"[red]XXE testing failed: {e}[/red]")
        
        input("\nPress Enter to continue...")
    
    async def run_rce_testing(self):
        """Run RCE testing using pentest modules"""
        target = self.get_target_input()
        if not target:
            return
        
        self.console.print(f"[green]Starting RCE testing for: {target}[/green]")
        
        try:
            from pentest.rce import RCETester
            rce_tester = RCETester()
            results = await rce_tester.test(target)
            
            if results:
                self.console.print("[red]RCE vulnerabilities found![/red]")
                for result in results[:5]:
                    self.console.print(f"[yellow]{result.title}[/yellow]")
            else:
                self.console.print("[green]No RCE vulnerabilities found[/green]")
                
        except Exception as e:
            self.console.print(f"[red]RCE testing failed: {e}[/red]")
        
        input("\nPress Enter to continue...")
    
    async def run_directory_traversal_testing(self):
        """Run directory traversal testing using pentest modules"""
        target = self.get_target_input()
        if not target:
            return
        
        self.console.print(f"[green]Starting directory traversal testing for: {target}[/green]")
        
        try:
            from pentest.directory_traversal import DirectoryTraversalTester
            dt_tester = DirectoryTraversalTester()
            results = await dt_tester.test(target)
            
            if results:
                self.console.print("[red]Directory traversal vulnerabilities found![/red]")
                for result in results[:5]:
                    self.console.print(f"[yellow]{result.title}[/yellow]")
            else:
                self.console.print("[green]No directory traversal vulnerabilities found[/green]")
                
        except Exception as e:
            self.console.print(f"[red]Directory traversal testing failed: {e}[/red]")
        
        input("\nPress Enter to continue...")
    
    async def run_metasploit_integration(self):
        """Run Metasploit integration for exploitation"""
        target = self.get_target_input()
        if not target:
            return
        
        self.console.print(f"[green]Starting Metasploit integration for: {target}[/green]")
        self.console.print("[yellow]WARNING: This will attempt safe exploitation tests only[/yellow]")
        
        confirm = Confirm.ask("Continue with Metasploit testing?")
        if not confirm:
            return
        
        try:
            from pentest.metasploit import MetasploitIntegration
            msf = MetasploitIntegration()
            results = await msf.run_safe_tests(target)
            
            if results:
                self.console.print("[red]Exploitable vulnerabilities found![/red]")
                for result in results[:5]:
                    self.console.print(f"[yellow]{result.title}[/yellow]")
            else:
                self.console.print("[green]No exploitable vulnerabilities found[/green]")
                
        except Exception as e:
            self.console.print(f"[red]Metasploit integration failed: {e}[/red]")
        
        input("\nPress Enter to continue...")
    
    async def generate_json_report(self):
        """Generate JSON report of scan results"""
        self.console.print("[green]Generating JSON report...[/green]")
        
        try:
            # Get all scan data from database
            scans = self.db.get_recent_scans(limit=50)
            
            import json
            import os
            from datetime import datetime
            
            report_data = {
                'generated_at': datetime.now().isoformat(),
                'total_scans': len(scans),
                'scans': []
            }
            
            for scan in scans:
                report_data['scans'].append({
                    'id': scan[0],
                    'target': scan[1],
                    'scan_type': scan[2],
                    'status': scan[4],
                    'results_count': scan[6],
                    'created_at': str(scan[5])
                })
            
            # Ensure exports directory exists
            os.makedirs('exports', exist_ok=True)
            
            filename = f"exports/reconforge_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            
            with open(filename, 'w') as f:
                json.dump(report_data, f, indent=2)
            
            self.console.print(f"[green]JSON report saved to: {filename}[/green]")
            
        except Exception as e:
            self.console.print(f"[red]Failed to generate JSON report: {e}[/red]")
        
        input("\nPress Enter to continue...")
    
    def view_all_recent_scans(self):
        """View all recent scans across all types"""
        self.console.print("[cyan]All Recent Scans:[/cyan]")
        
        try:
            scans = self.db.get_recent_scans(limit=20)
            
            if scans:
                scans_table = Table(box=box.ROUNDED)
                scans_table.add_column("ID", style="cyan")
                scans_table.add_column("Target", style="yellow")
                scans_table.add_column("Type", style="green")
                scans_table.add_column("Status", style="white")
                scans_table.add_column("Results", style="magenta")
                scans_table.add_column("Date", style="dim")
                
                for scan in scans:
                    scans_table.add_row(
                        str(scan[0]),
                        scan[1][:30] + "..." if len(scan[1]) > 30 else scan[1],
                        scan[2],
                        scan[4],
                        str(scan[6]),
                        str(scan[5])[:19] if scan[5] else ""
                    )
                
                self.console.print(scans_table)
            else:
                self.console.print("[yellow]No recent scans found[/yellow]")
                
        except Exception as e:
            self.console.print(f"[red]Failed to retrieve scans: {e}[/red]")
        
        input("\nPress Enter to continue...")
    
    async def check_tool_installation(self):
        """Check installation status of all security tools"""
        self.console.print("[cyan]Checking tool installation status...[/cyan]")
        
        tools_to_check = [
            ('nmap', 'Network scanner'),
            ('gobuster', 'Directory brute forcer'),
            ('sqlmap', 'SQL injection tester'),
            ('subfinder', 'Subdomain finder'),
            ('nuclei', 'Vulnerability scanner'),
            ('nikto', 'Web vulnerability scanner'),
            ('hydra', 'Login brute forcer'),
            ('wapiti', 'Web app scanner'),
            ('testssl.sh', 'SSL/TLS tester'),
            ('amass', 'Asset discovery')
        ]
        
        tools_table = Table(box=box.ROUNDED)
        tools_table.add_column("Tool", style="cyan")
        tools_table.add_column("Description", style="white")
        tools_table.add_column("Status", style="green")
        
        import subprocess
        
        for tool, description in tools_to_check:
            try:
                # Check if tool is available in PATH
                result = subprocess.run(f"which {tool}", shell=True, capture_output=True, text=True)
                if result.returncode == 0:
                    status = "✓ Installed"
                    style = "green"
                else:
                    status = "✗ Missing"
                    style = "red"
                    
                tools_table.add_row(tool, description, f"[{style}]{status}[/{style}]")
                
            except Exception:
                tools_table.add_row(tool, description, "[red]✗ Error[/red]")
        
        self.console.print(tools_table)
        input("\nPress Enter to continue...")
    
    def view_configuration(self):
        """View current ReconForge configuration"""
        self.console.print("[cyan]Current Configuration:[/cyan]")
        
        try:
            import os
            import json
            
            config_file = 'config.json'
            if os.path.exists(config_file):
                with open(config_file, 'r') as f:
                    config = json.load(f)
                
                config_table = Table(box=box.ROUNDED)
                config_table.add_column("Setting", style="cyan")
                config_table.add_column("Value", style="yellow")
                
                for key, value in config.items():
                    # Hide sensitive values
                    if 'key' in key.lower() or 'token' in key.lower() or 'password' in key.lower():
                        display_value = "[HIDDEN]" if value else "[NOT SET]"
                    else:
                        display_value = str(value)
                    
                    config_table.add_row(key, display_value)
                
                self.console.print(config_table)
            else:
                self.console.print("[yellow]No configuration file found[/yellow]")
                
        except Exception as e:
            self.console.print(f"[red]Failed to load configuration: {e}[/red]")
        
        input("\nPress Enter to continue...")
    
    async def handle_target_management(self):
        """Handle target management operations"""
        self.navigation_stack.append('Target Management')
        
        while True:
            self.print_banner()
            self.print_breadcrumbs()
            
            # Show target management options
            target_menu = Table(show_header=False, box=box.SIMPLE)
            target_menu.add_column("Option", style="cyan", width=4)
            target_menu.add_column("Description", style="white")
            
            target_options = [
                ("1", "Add New Target"),
                ("2", "Switch Active Target"),
                ("3", "View Target Details"),
                ("4", "Target Statistics"),
                ("5", "Export Target Data"),
                ("6", "Remove Target"),
                ("7", "View All Targets"),
                ("b", "Back to Main Menu")
            ]
            
            for option, desc in target_options:
                target_menu.add_row(f"[bold cyan]{option}[/bold cyan]", desc)
            
            self.console.print(Panel(target_menu, title="Target Management Options"))
            
            # Show current targets
            if self.targets:
                self.console.print("\n[cyan]Current Targets:[/cyan]")
                targets_table = Table(box=box.ROUNDED)
                targets_table.add_column("Target", style="yellow")
                targets_table.add_column("Scans", style="green")
                targets_table.add_column("Subdomains", style="blue")
                targets_table.add_column("Vulnerabilities", style="red")
                targets_table.add_column("Last Scan", style="dim")
                
                for target, info in self.targets.items():
                    status = "▶ " if target == self.current_target else "  "
                    targets_table.add_row(
                        status + target,
                        str(len(info.get('scans', []))),
                        str(len(info.get('subdomains', []))),
                        str(len(info.get('vulnerabilities', []))),
                        info.get('last_scan', 'Never')[:19] if info.get('last_scan') else 'Never'
                    )
                
                self.console.print(targets_table)
            
            choice = self.get_user_choice("Choose target management option")
            
            if choice == "1":
                await self.add_new_target()
            elif choice == "2":
                await self.switch_active_target()
            elif choice == "3":
                await self.view_target_details()
            elif choice == "4":
                self.view_target_statistics()
            elif choice == "5":
                await self.export_target_data()
            elif choice == "6":
                await self.remove_target()
            elif choice == "7":
                self.view_all_targets()
            elif choice.lower() == "b":
                self.navigation_stack.pop()
                break
            else:
                self.console.print("[red]Invalid option. Please try again.[/red]")
                input("Press Enter to continue...")
    
    async def add_new_target(self):
        """Add a new target to track"""
        target = input("Enter new target (domain or IP): ").strip()
        if not target:
            self.console.print("[red]Target is required[/red]")
            return
        
        if target in self.targets:
            self.console.print(f"[yellow]Target {target} is already tracked[/yellow]")
            return
        
        # Initialize target
        self.targets[target] = {
            'scans': [],
            'subdomains': [],
            'vulnerabilities': [],
            'last_scan': None,
            'created': datetime.now().isoformat()
        }
        
        self.console.print(f"[green]Target {target} added successfully[/green]")
        
        # Ask if user wants to make it active
        if not self.current_target:
            make_active = input("Make this your active target? (Y/n): ").strip().lower()
            if make_active != 'n':
                self.current_target = target
                self.console.print(f"[green]Active target set to: {target}[/green]")
        
        input("Press Enter to continue...")
    
    async def switch_active_target(self):
        """Switch to a different active target"""
        if not self.targets:
            self.console.print("[yellow]No targets available. Add a target first.[/yellow]")
            input("Press Enter to continue...")
            return
        
        self.console.print("[cyan]Available Targets:[/cyan]")
        target_list = list(self.targets.keys())
        
        for i, target in enumerate(target_list, 1):
            status = "▶ [ACTIVE] " if target == self.current_target else "  "
            self.console.print(f"[yellow]{i}.[/yellow] {status}{target}")
        
        try:
            choice = input("\nSelect target number (or press Enter to cancel): ").strip()
            if not choice:
                return
            
            target_index = int(choice) - 1
            if 0 <= target_index < len(target_list):
                self.current_target = target_list[target_index]
                self.console.print(f"[green]Active target switched to: {self.current_target}[/green]")
            else:
                self.console.print("[red]Invalid selection[/red]")
                
        except ValueError:
            self.console.print("[red]Invalid input[/red]")
        
        input("Press Enter to continue...")
    
    async def view_target_details(self):
        """View detailed information about a target"""
        if not self.targets:
            self.console.print("[yellow]No targets available[/yellow]")
            input("Press Enter to continue...")
            return
        
        # Select target or use current
        target = self.current_target
        if len(self.targets) > 1:
            target_choice = input(f"Target to view [default: {self.current_target or 'none'}]: ").strip()
            if target_choice and target_choice in self.targets:
                target = target_choice
        
        if not target or target not in self.targets:
            self.console.print("[red]Invalid or no target selected[/red]")
            input("Press Enter to continue...")
            return
        
        info = self.targets[target]
        
        # Create detailed view
        details_table = Table(title=f"Target Details: {target}", box=box.ROUNDED)
        details_table.add_column("Attribute", style="cyan")
        details_table.add_column("Value", style="white")
        
        details_table.add_row("Target", target)
        details_table.add_row("Created", info.get('created', 'Unknown')[:19])
        details_table.add_row("Last Scan", info.get('last_scan', 'Never')[:19] if info.get('last_scan') else 'Never')
        details_table.add_row("Total Scans", str(len(info.get('scans', []))))
        details_table.add_row("Subdomains Found", str(len(info.get('subdomains', []))))
        details_table.add_row("Vulnerabilities", str(len(info.get('vulnerabilities', []))))
        
        self.console.print(details_table)
        
        # Show recent scans if available
        if info.get('scans'):
            self.console.print("\n[cyan]Recent Scans:[/cyan]")
            for scan in info['scans'][-5:]:  # Last 5 scans
                self.console.print(f"[dim]{scan.get('type', 'Unknown')} - {scan.get('status', 'Unknown')} - {scan.get('date', 'Unknown')[:19]}[/dim]")
        
        input("\nPress Enter to continue...")
    
    def update_target_info(self, target: str, scan_type: str, results_count: int):
        """Update target information after a scan"""
        if target not in self.targets:
            self.targets[target] = {
                'scans': [],
                'subdomains': [],
                'vulnerabilities': [],
                'last_scan': None,
                'created': datetime.now().isoformat()
            }
        
        # Add scan to target history
        scan_info = {
            'type': scan_type,
            'status': 'completed',
            'results_count': results_count,
            'date': datetime.now().isoformat()
        }
        
        self.targets[target]['scans'].append(scan_info)
        self.targets[target]['last_scan'] = datetime.now().isoformat()
        
        # Keep only last 10 scans per target
        if len(self.targets[target]['scans']) > 10:
            self.targets[target]['scans'] = self.targets[target]['scans'][-10:]
    
    def add_active_scan(self, scan_id: int, target: str, scan_type: str):
        """Add a scan to active scans tracking"""
        self.active_scans[scan_id] = {
            'target': target,
            'type': scan_type,
            'status': 'running',
            'progress': 0,
            'start_time': datetime.now().isoformat()
        }
    
    def remove_active_scan(self, scan_id: int):
        """Remove a scan from active scans tracking"""
        if scan_id in self.active_scans:
            del self.active_scans[scan_id]
    
    def update_scan_progress(self, scan_id: int, progress: int, status: str = None):
        """Update scan progress"""
        if scan_id in self.active_scans:
            self.active_scans[scan_id]['progress'] = progress
            if status:
                self.active_scans[scan_id]['status'] = status
    
    def view_all_targets(self):
        """View all targets with summary information"""
        if not self.targets:
            self.console.print("[yellow]No targets tracked[/yellow]")
            input("Press Enter to continue...")
            return
        
        targets_table = Table(title="All Targets Summary", box=box.ROUNDED)
        targets_table.add_column("Target", style="cyan")
        targets_table.add_column("Status", style="green")
        targets_table.add_column("Scans", style="yellow")
        targets_table.add_column("Subdomains", style="blue")
        targets_table.add_column("Vulnerabilities", style="red")
        targets_table.add_column("Last Activity", style="dim")
        
        for target, info in self.targets.items():
            status = "🎯 Active" if target == self.current_target else "⚫ Tracked"
            targets_table.add_row(
                target,
                status,
                str(len(info.get('scans', []))),
                str(len(info.get('subdomains', []))),
                str(len(info.get('vulnerabilities', []))),
                info.get('last_scan', 'Never')[:10] if info.get('last_scan') else 'Never'
            )
        
        self.console.print(targets_table)
        input("\nPress Enter to continue...")
    
    def view_subdomain_scan_history(self):
        """View subdomain discovery scan history"""
        self.console.print("[bold cyan]Subdomain Discovery History[/bold cyan]\n")
        
        scans = self.db.get_scans(limit=50)
        subdomain_scans = [scan for scan in scans if scan.get('scan_type') == 'discovery']
        
        if not subdomain_scans:
            self.console.print("[yellow]No subdomain discovery scans found.[/yellow]")
            input("\nPress Enter to continue...")
            return
        
        history_table = Table(show_header=True, box=box.ROUNDED)
        history_table.add_column("ID", style="cyan", width=6)
        history_table.add_column("Target", style="white", width=25)
        history_table.add_column("Status", style="green", width=10)
        history_table.add_column("Subdomains", style="yellow", width=10)
        history_table.add_column("Date", style="blue", width=12)
        
        for scan in subdomain_scans[:20]:
            status_color = "green" if scan.get('status') == 'completed' else "red"
            history_table.add_row(
                str(scan.get('id', '')),
                scan.get('target', 'Unknown'),
                f"[{status_color}]{scan.get('status', 'Unknown')}[/{status_color}]",
                str(scan.get('total_subdomains', 0)),
                scan.get('created_at', 'Unknown')[:10]
            )
        
        self.console.print(history_table)
        input("\nPress Enter to continue...")
    
    def view_vulnerability_scan_history(self):
        """View vulnerability scan history"""
        self.console.print("[bold cyan]Vulnerability Scan History[/bold cyan]\n")
        
        scans = self.db.get_scans(limit=50)
        vuln_scans = [scan for scan in scans if scan.get('scan_type') == 'vulnerability']
        
        if not vuln_scans:
            self.console.print("[yellow]No vulnerability scans found.[/yellow]")
            input("\nPress Enter to continue...")
            return
        
        history_table = Table(show_header=True, box=box.ROUNDED)
        history_table.add_column("ID", style="cyan", width=6)
        history_table.add_column("Target", style="white", width=25)
        history_table.add_column("Status", style="green", width=10)
        history_table.add_column("Vulns", style="red", width=8)
        history_table.add_column("Critical", style="red", width=8)
        history_table.add_column("Date", style="blue", width=12)
        
        for scan in vuln_scans[:20]:
            status_color = "green" if scan.get('status') == 'completed' else "red"
            vulns = scan.get('vulnerabilities', [])
            critical_count = len([v for v in vulns if v.get('severity') == 'critical'])
            
            history_table.add_row(
                str(scan.get('id', '')),
                scan.get('target', 'Unknown'),
                f"[{status_color}]{scan.get('status', 'Unknown')}[/{status_color}]",
                str(len(vulns)),
                str(critical_count),
                scan.get('created_at', 'Unknown')[:10]
            )
        
        self.console.print(history_table)
        input("\nPress Enter to continue...")
    
    def view_port_scan_history(self):
        """View port scan history"""
        self.console.print("[bold cyan]Port Scan History[/bold cyan]\n")
        
        scans = self.db.get_scans(limit=50)
        port_scans = [scan for scan in scans if scan.get('scan_type') == 'port_scan']
        
        if not port_scans:
            self.console.print("[yellow]No port scans found.[/yellow]")
            input("\nPress Enter to continue...")
            return
        
        history_table = Table(show_header=True, box=box.ROUNDED)
        history_table.add_column("ID", style="cyan", width=6)
        history_table.add_column("Target", style="white", width=25)
        history_table.add_column("Status", style="green", width=10)
        history_table.add_column("Services", style="yellow", width=10)
        history_table.add_column("Date", style="blue", width=12)
        
        for scan in port_scans[:20]:
            status_color = "green" if scan.get('status') == 'completed' else "red"
            history_table.add_row(
                str(scan.get('id', '')),
                scan.get('target', 'Unknown'),
                f"[{status_color}]{scan.get('status', 'Unknown')}[/{status_color}]",
                str(scan.get('total_services', 0)),
                scan.get('created_at', 'Unknown')[:10]
            )
        
        self.console.print(history_table)
        input("\nPress Enter to continue...")
    
    def view_sql_injection_history(self):
        """View SQL injection test history"""
        self.console.print("[bold cyan]SQL Injection Test History[/bold cyan]\n")
        
        scans = self.db.get_scans(limit=50)
        sql_scans = [scan for scan in scans if scan.get('scan_type') == 'sql_injection']
        
        if not sql_scans:
            self.console.print("[yellow]No SQL injection tests found.[/yellow]")
            input("\nPress Enter to continue...")
            return
        
        history_table = Table(show_header=True, box=box.ROUNDED)
        history_table.add_column("ID", style="cyan", width=6)
        history_table.add_column("Target", style="white", width=25)
        history_table.add_column("Status", style="green", width=10)
        history_table.add_column("Results", style="yellow", width=10)
        history_table.add_column("Date", style="blue", width=12)
        
        for scan in sql_scans[:20]:
            status_color = "green" if scan.get('status') == 'completed' else "red"
            history_table.add_row(
                str(scan.get('id', '')),
                scan.get('target', 'Unknown'),
                f"[{status_color}]{scan.get('status', 'Unknown')}[/{status_color}]",
                str(len(scan.get('vulnerabilities', []))),
                scan.get('created_at', 'Unknown')[:10]
            )
        
        self.console.print(history_table)
        input("\nPress Enter to continue...")
    
    def view_export_history(self):
        """View report export history"""
        self.console.print("[bold cyan]Export History[/bold cyan]\n")
        
        # Get export records from database
        try:
            with self.db.get_connection() as conn:
                exports = conn.execute('''
                    SELECT e.*, s.target 
                    FROM exports e
                    LEFT JOIN scans s ON e.scan_id = s.id
                    ORDER BY e.created_at DESC
                    LIMIT 20
                ''').fetchall()
                
                if not exports:
                    self.console.print("[yellow]No exports found.[/yellow]")
                    input("\nPress Enter to continue...")
                    return
                
                export_table = Table(show_header=True, box=box.ROUNDED)
                export_table.add_column("ID", style="cyan", width=6)
                export_table.add_column("Target", style="white", width=20)
                export_table.add_column("Type", style="green", width=10)
                export_table.add_column("Size", style="yellow", width=10)
                export_table.add_column("Date", style="blue", width=12)
                
                for export in exports:
                    size_kb = export['file_size'] // 1024 if export['file_size'] else 0
                    export_table.add_row(
                        str(export['id']),
                        export['target'] or 'Unknown',
                        export['export_type'],
                        f"{size_kb}KB",
                        export['created_at'][:10]
                    )
                
                self.console.print(export_table)
                
        except Exception as e:
            self.console.print(f"[red]Error retrieving export history: {e}[/red]")
        
        input("\nPress Enter to continue...")


async def main():
    """Main entry point for terminal interface"""
    terminal = ReconForgeTerminal()
    await terminal.run()


if __name__ == "__main__":
    asyncio.run(main())