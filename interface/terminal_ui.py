#!/usr/bin/env python3
"""
ReconForge Terminal UI
Terminal-First Professional Reconnaissance Platform

Main terminal interface that integrates display, menus, and core functionality
to provide a comprehensive reconnaissance platform interface.
"""

import os
import sys
import time
from typing import Dict, Any, Optional, List, Callable
from datetime import datetime, timezone

from interface.display import ReconForgeDisplay, DisplayTheme, StatusType
from interface.menus import Menu, MenuNavigator, MenuContext, MenuConfig, create_menu, create_menu_config
from core.logger import ReconForgeLogger
from core.config import ReconForgeConfig
from core.database import ReconForgeDatabase
from core.utils import ReconForgeUtils


class TerminalUI:
    """Main terminal interface for ReconForge"""
    
    def __init__(self, logger: ReconForgeLogger, config: ReconForgeConfig, 
                 database: ReconForgeDatabase, utils: ReconForgeUtils):
        """Initialize terminal interface"""
        self.logger = logger
        self.config = config
        self.database = database
        self.utils = utils
        
        # Get terminal theme from config
        theme_name = config.get('TERMINAL', 'theme', 'default')
        theme_map = {
            'default': DisplayTheme.DEFAULT,
            'dark': DisplayTheme.DARK,
            'light': DisplayTheme.LIGHT,
            'hacker': DisplayTheme.HACKER
        }
        theme = theme_map.get(theme_name.lower(), DisplayTheme.DEFAULT)
        
        # Initialize display
        self.display = ReconForgeDisplay(theme)
        
        # Initialize menu context
        self.context = MenuContext(logger, config, database, utils)
        
        # Initialize menu navigator
        self.navigator = MenuNavigator(self.display, self.context)
        
        # Interface state
        self.running = False
        self.startup_time = datetime.now(timezone.utc)
        
        # Create main menu structure
        self.main_menu = self._create_main_menu()
        
        self.logger.log_system("Terminal UI initialized")
    
    def run(self) -> int:
        """Run the terminal interface"""
        try:
            self.running = True
            self.logger.log_system("Starting terminal interface")
            
            # Set terminal title
            self.display.set_title("ReconForge - Professional Reconnaissance Platform")
            
            # Show startup banner
            self._show_startup_banner()
            
            # Check for first-time setup
            if self._needs_first_time_setup():
                if not self._run_first_time_setup():
                    return 1
            
            # Show tool status
            self._show_startup_status()
            
            # Enter main menu loop
            result = self.navigator.run_menu(self.main_menu)
            
            if result == "exit":
                self._show_goodbye_message()
                return 0
            
            return 0
        
        except KeyboardInterrupt:
            self.logger.log_system("Terminal interface interrupted by user")
            self._show_goodbye_message()
            return 0
        
        except Exception as e:
            error_msg = f"Terminal interface error: {str(e)}"
            self.logger.log_error(error_msg)
            self.display.print_status(error_msg, StatusType.ERROR)
            import traceback
            self.logger.log_error(f"Terminal UI traceback: {traceback.format_exc()}")
            return 1
        
        finally:
            self.running = False
    
    def _show_startup_banner(self):
        """Show startup banner and information"""
        self.display.clear_screen()
        self.display.print_banner("2.0.0")
        
        # Show system information
        system_info = {
            "Platform": sys.platform,
            "Python": sys.version.split()[0],
            "Working Dir": os.path.basename(os.getcwd()),
            "Session": self.context.session_data.get('session_id', 'Unknown')[:8] + "..."
        }
        
        self.display.print_key_value_pairs(system_info, "System Information", columns=2)
        self.display.print_empty_lines()
    
    def _show_startup_status(self):
        """Show tool availability and system status"""
        available_tools = self.utils.tool_manager.get_available_tools()
        missing_tools = self.utils.tool_manager.get_missing_tools()
        
        status_info = [
            f"Available Tools: {len(available_tools)}/{len(available_tools) + len(missing_tools)}",
            f"Database: Connected",
            f"Configuration: Loaded",
            f"Logging: Active"
        ]
        
        for info in status_info:
            self.display.print_status(info, StatusType.SUCCESS)
        
        if missing_tools:
            self.display.print_status(f"Missing {len(missing_tools)} tools - some features may be limited", StatusType.WARNING)
            
            if len(missing_tools) <= 5:  # Show missing tools if not too many
                missing_names = [tool.name for tool in missing_tools[:5]]
                self.display.print_status(f"Missing: {', '.join(missing_names)}", StatusType.INFO)
        
        self.display.print_empty_lines()
        self.display.prompt_input("Press Enter to continue...")
    
    def _needs_first_time_setup(self) -> bool:
        """Check if first-time setup is needed"""
        return not self.config.get('GENERAL', 'setup_completed', False)
    
    def _run_first_time_setup(self) -> bool:
        """Run first-time setup wizard"""
        self.display.clear_screen()
        self.display.print_header("Welcome to ReconForge!", "First-time setup wizard")
        
        self.display.print_status("Welcome to ReconForge! Let's get you set up.", StatusType.INFO)
        self.display.print_empty_lines()
        
        try:
            # Ask for user preferences
            setup_data = {}
            
            # Terminal theme
            themes = ["default", "dark", "hacker", "light"]
            current_theme = self.config.get('TERMINAL', 'theme', 'default')
            
            self.display.console.print("Choose your terminal theme:")
            theme_choice = self.display.prompt_choice("Theme", themes, current_theme)
            setup_data['theme'] = theme_choice
            
            # API Keys setup prompt
            if self.display.prompt_confirm("Would you like to configure API keys now? (You can do this later)", default=False):
                self._setup_api_keys()
            
            # Tool check
            self.display.print_status("Checking tool availability...", StatusType.INFO)
            self.utils.tool_manager.refresh_tool_availability()
            
            # Save setup completion
            self.config.set_setting('GENERAL', 'setup_completed', True)
            self.config.set_setting('GENERAL', 'setup_date', datetime.now().isoformat())
            self.config.set_setting('TERMINAL', 'theme', setup_data['theme'])
            self.config.save_config()
            
            self.display.print_status("Setup completed successfully!", StatusType.SUCCESS)
            self.display.prompt_input("Press Enter to continue...")
            
            return True
        
        except KeyboardInterrupt:
            self.display.print_status("Setup cancelled", StatusType.WARNING)
            return False
        except Exception as e:
            self.display.print_status(f"Setup error: {str(e)}", StatusType.ERROR)
            return False
    
    def _setup_api_keys(self):
        """Setup API keys"""
        self.display.print_header("API Keys Configuration")
        
        api_services = [
            ("shodan", "Shodan API", "For enhanced reconnaissance"),
            ("virustotal", "VirusTotal API", "For malware and reputation checking"),
            ("censys", "Censys API", "For internet-wide scanning"),
            ("securitytrails", "SecurityTrails API", "For DNS and domain intelligence")
        ]
        
        for key, name, description in api_services:
            self.display.console.print(f"\n[{self.display.colors['accent']}]{name}[/]: {description}")
            
            if self.display.prompt_confirm(f"Configure {name}?", default=False):
                api_key = self.display.prompt_input(f"Enter {name} API key (will be encrypted)")
                if api_key.strip():
                    self.config.set_api_key(key, api_key.strip())
                    self.display.print_status(f"{name} API key configured", StatusType.SUCCESS)
    
    def _show_goodbye_message(self):
        """Show goodbye message"""
        self.display.clear_screen()
        runtime = (datetime.now(timezone.utc) - self.startup_time).total_seconds()
        
        goodbye_text = f"""
Thank you for using ReconForge!

Session Statistics:
• Runtime: {self.utils.format_duration(runtime)}
• Commands Executed: {len(self.navigator.get_navigation_history())}

Stay secure! 🔒
        """
        
        self.display.print_panel(goodbye_text, title="Goodbye", border_style=self.display.colors['primary'])
    
    def _create_main_menu(self) -> Menu:
        """Create the main menu structure"""
        # Menu configuration
        config = create_menu_config(
            show_descriptions=True,
            show_shortcuts=True,
            show_breadcrumbs=True,
            clear_on_navigate=True
        )
        
        # Create main menu
        main_menu = create_menu("ReconForge Main Menu", 
                               "Professional Reconnaissance Platform", 
                               config=config)
        
        # Reconnaissance submenu
        recon_menu = self._create_reconnaissance_menu()
        main_menu.add_submenu("recon", "🔍 Reconnaissance", recon_menu, 
                             "Passive and active reconnaissance modules", "r")
        
        # Vulnerability Assessment submenu
        vuln_menu = self._create_vulnerability_menu()
        main_menu.add_submenu("vuln", "🛡️  Vulnerability Assessment", vuln_menu,
                             "Security scanning and vulnerability detection", "v")
        
        # Exploitation submenu (if tools available)
        if self.utils.tool_manager.is_tool_available('sqlmap'):
            exploit_menu = self._create_exploitation_menu()
            main_menu.add_submenu("exploit", "⚡ Exploitation", exploit_menu,
                                 "Safe exploitation and penetration testing", "e")
        
        # Results & Reports submenu
        results_menu = self._create_results_menu()
        main_menu.add_submenu("results", "📊 Results & Reports", results_menu,
                             "View scan results and generate reports", "s")
        
        # Tools & Utilities submenu
        tools_menu = self._create_tools_menu()
        main_menu.add_submenu("tools", "🔧 Tools & Utilities", tools_menu,
                             "Tool management and utility functions", "t")
        
        # Configuration submenu
        config_menu = self._create_configuration_menu()
        main_menu.add_submenu("config", "⚙️  Configuration", config_menu,
                             "Application settings and configuration", "c")
        
        return main_menu
    
    def _create_reconnaissance_menu(self) -> Menu:
        """Create reconnaissance submenu"""
        menu = create_menu("Reconnaissance", "Passive and Active Discovery")
        
        # Subdomain Discovery
        menu.add_action("subdomain", "🌐 Subdomain Discovery", 
                       self._action_subdomain_discovery,
                       "Enumerate subdomains using multiple sources", "d")
        
        # Port Scanning
        if self.utils.tool_manager.is_tool_available('nmap'):
            menu.add_action("portscan", "🔌 Port Scanning",
                           self._action_port_scanning,
                           "Network port scanning and service detection", "p")
        
        # Web Discovery
        if self.utils.tool_manager.is_tool_available('httpx'):
            menu.add_action("webdisco", "🌐 Web Discovery",
                           self._action_web_discovery,
                           "Web server and application discovery", "w")
        
        # DNS Enumeration
        if self.utils.tool_manager.is_tool_available('dnsx'):
            menu.add_action("dns", "📛 DNS Enumeration",
                           self._action_dns_enumeration,
                           "DNS record enumeration and analysis", "n")
        
        return menu
    
    def _create_vulnerability_menu(self) -> Menu:
        """Create vulnerability assessment submenu"""
        menu = create_menu("Vulnerability Assessment", "Security Scanning & Analysis")
        
        # Nuclei Scanning
        if self.utils.tool_manager.is_tool_available('nuclei'):
            menu.add_action("nuclei", "☢️  Nuclei Vulnerability Scan",
                           self._action_nuclei_scan,
                           "Template-based vulnerability scanning", "n")
        
        # Subdomain Takeover
        if self.utils.tool_manager.is_tool_available('subzy'):
            menu.add_action("takeover", "🎯 Subdomain Takeover Check",
                           self._action_takeover_check,
                           "Check for subdomain takeover vulnerabilities", "t")
        
        # Directory Bruteforce
        if self.utils.tool_manager.is_tool_available('gobuster'):
            menu.add_action("dirbrute", "📂 Directory Bruteforce",
                           self._action_directory_brute,
                           "Web directory and file discovery", "d")
        
        return menu
    
    def _create_exploitation_menu(self) -> Menu:
        """Create exploitation submenu"""
        menu = create_menu("Exploitation", "Safe Penetration Testing")
        
        # SQL Injection Testing
        if self.utils.tool_manager.is_tool_available('sqlmap'):
            menu.add_action("sqli", "💉 SQL Injection Testing",
                           self._action_sql_injection,
                           "Automated SQL injection detection and exploitation", "s",
                           requires_confirmation=True,
                           confirmation_message="SQL injection testing can be invasive. Continue?")
        
        return menu
    
    def _create_results_menu(self) -> Menu:
        """Create results and reports submenu"""
        menu = create_menu("Results & Reports", "View and Export Scan Data")
        
        menu.add_action("recent", "📋 Recent Scans",
                       self._action_recent_scans,
                       "View recent scan results", "r")
        
        menu.add_action("summary", "📈 Scan Summary",
                       self._action_scan_summary,
                       "View statistical summary of all scans", "s")
        
        menu.add_action("export", "💾 Export Results",
                       self._action_export_results,
                       "Export scan results to various formats", "e")
        
        menu.add_action("search", "🔍 Search Results",
                       self._action_search_results,
                       "Search through scan results", "h")
        
        return menu
    
    def _create_tools_menu(self) -> Menu:
        """Create tools and utilities submenu"""
        menu = create_menu("Tools & Utilities", "Tool Management & Utilities")
        
        menu.add_action("toolstatus", "🔧 Tool Status",
                       self._action_tool_status,
                       "Check availability of security tools", "t")
        
        menu.add_action("refresh", "🔄 Refresh Tools",
                       self._action_refresh_tools,
                       "Refresh tool availability scan", "r")
        
        menu.add_action("install", "📦 Install Tools",
                       self._action_install_tools,
                       "Install missing security tools", "i")
        
        menu.add_action("logs", "📋 View Logs",
                       self._action_view_logs,
                       "View application logs", "l")
        
        return menu
    
    def _create_configuration_menu(self) -> Menu:
        """Create configuration submenu"""
        menu = create_menu("Configuration", "Application Settings")
        
        menu.add_action("settings", "⚙️  General Settings",
                       self._action_general_settings,
                       "View and modify general settings", "s")
        
        menu.add_action("apikeys", "🔑 API Keys",
                       self._action_api_keys,
                       "Manage API keys for external services", "a")
        
        menu.add_action("theme", "🎨 Terminal Theme",
                       self._action_change_theme,
                       "Change terminal color theme", "t")
        
        menu.add_action("backup", "💾 Backup Configuration",
                       self._action_backup_config,
                       "Backup configuration and data", "b")
        
        menu.add_action("reset", "🔄 Reset Configuration",
                       self._action_reset_config,
                       "Reset configuration to defaults", "r",
                       requires_confirmation=True,
                       confirmation_message="This will reset all settings. Continue?")
        
        return menu
    
    # Action Methods (Placeholder implementations)
    def _action_subdomain_discovery(self, context: MenuContext) -> Optional[str]:
        """Subdomain discovery action"""
        self.display.print_header("Subdomain Discovery", "Multiple Source Enumeration")
        self.display.print_status("This feature will be implemented in the next phase", StatusType.INFO)
        return None
    
    def _action_port_scanning(self, context: MenuContext) -> Optional[str]:
        """Port scanning action"""
        self.display.print_header("Port Scanning", "Network Service Discovery")
        self.display.print_status("This feature will be implemented in the next phase", StatusType.INFO)
        return None
    
    def _action_web_discovery(self, context: MenuContext) -> Optional[str]:
        """Web discovery action"""
        self.display.print_header("Web Discovery", "HTTP Service Enumeration")
        self.display.print_status("This feature will be implemented in the next phase", StatusType.INFO)
        return None
    
    def _action_dns_enumeration(self, context: MenuContext) -> Optional[str]:
        """DNS enumeration action"""
        self.display.print_header("DNS Enumeration", "DNS Record Analysis")
        self.display.print_status("This feature will be implemented in the next phase", StatusType.INFO)
        return None
    
    def _action_nuclei_scan(self, context: MenuContext) -> Optional[str]:
        """Nuclei vulnerability scan action"""
        self.display.print_header("Nuclei Vulnerability Scan", "Template-based Security Scanning")
        self.display.print_status("This feature will be implemented in the next phase", StatusType.INFO)
        return None
    
    def _action_takeover_check(self, context: MenuContext) -> Optional[str]:
        """Subdomain takeover check action"""
        self.display.print_header("Subdomain Takeover Check", "Takeover Vulnerability Detection")
        self.display.print_status("This feature will be implemented in the next phase", StatusType.INFO)
        return None
    
    def _action_directory_brute(self, context: MenuContext) -> Optional[str]:
        """Directory bruteforce action"""
        self.display.print_header("Directory Bruteforce", "Web Directory Discovery")
        self.display.print_status("This feature will be implemented in the next phase", StatusType.INFO)
        return None
    
    def _action_sql_injection(self, context: MenuContext) -> Optional[str]:
        """SQL injection testing action"""
        self.display.print_header("SQL Injection Testing", "Automated SQLi Detection")
        self.display.print_status("This feature will be implemented in the next phase", StatusType.INFO)
        return None
    
    def _action_recent_scans(self, context: MenuContext) -> Optional[str]:
        """Recent scans action"""
        self.display.print_header("Recent Scans", "Latest Scan Results")
        
        # Get recent scans from database
        recent_scans = context.database.get_recent_scans(limit=10)
        
        if not recent_scans:
            self.display.print_status("No scans found", StatusType.INFO)
            return None
        
        # Display scans in table format
        from .display import TableColumn
        columns = [
            TableColumn("ID", "id", width=8),
            TableColumn("Target", "target", width=25),
            TableColumn("Type", "scan_type", width=15),
            TableColumn("Status", "status", width=12),
            TableColumn("Date", "created_at", width=20)
        ]
        
        self.display.print_table(columns, recent_scans, "Recent Scans", max_rows=10)
        return None
    
    def _action_scan_summary(self, context: MenuContext) -> Optional[str]:
        """Scan summary action"""
        self.display.print_header("Scan Summary", "Statistical Overview")
        
        # Get scan statistics
        stats = context.database.get_scan_statistics()
        
        if stats:
            self.display.print_key_value_pairs(stats, "Scan Statistics", columns=2)
        else:
            self.display.print_status("No scan data available", StatusType.INFO)
        
        return None
    
    def _action_export_results(self, context: MenuContext) -> Optional[str]:
        """Export results action"""
        self.display.print_header("Export Results", "Data Export Options")
        self.display.print_status("This feature will be implemented in the next phase", StatusType.INFO)
        return None
    
    def _action_search_results(self, context: MenuContext) -> Optional[str]:
        """Search results action"""
        self.display.print_header("Search Results", "Query Scan Database")
        self.display.print_status("This feature will be implemented in the next phase", StatusType.INFO)
        return None
    
    def _action_tool_status(self, context: MenuContext) -> Optional[str]:
        """Tool status action"""
        self.display.print_header("Tool Status", "Security Tool Availability")
        
        available_tools = context.utils.tool_manager.get_available_tools()
        missing_tools = context.utils.tool_manager.get_missing_tools()
        
        # Show available tools
        if available_tools:
            self.display.console.print(f"[{self.display.colors['success']}]✅ Available Tools ({len(available_tools)}):[/]")
            for tool in available_tools:
                version_info = f" ({tool.version})" if tool.version else ""
                self.display.console.print(f"  • {tool.name}{version_info} - {tool.description}")
            self.display.print_empty_lines()
        
        # Show missing tools
        if missing_tools:
            self.display.console.print(f"[{self.display.colors['error']}]❌ Missing Tools ({len(missing_tools)}):[/]")
            for tool in missing_tools:
                self.display.console.print(f"  • {tool.name} - {tool.description}")
            self.display.print_empty_lines()
        
        return None
    
    def _action_refresh_tools(self, context: MenuContext) -> Optional[str]:
        """Refresh tools action"""
        self.display.print_header("Refresh Tools", "Rescanning Tool Availability")
        
        self.display.print_status("Refreshing tool availability...", StatusType.INFO)
        context.utils.tool_manager.refresh_tool_availability()
        
        available_count = len(context.utils.tool_manager.get_available_tools())
        total_count = len(context.utils.tool_manager.tools)
        
        self.display.print_status(f"Scan complete: {available_count}/{total_count} tools available", StatusType.SUCCESS)
        return None
    
    def _action_install_tools(self, context: MenuContext) -> Optional[str]:
        """Install tools action"""
        self.display.print_header("Install Tools", "Security Tool Installation")
        self.display.print_status("This feature will be implemented in the next phase", StatusType.INFO)
        self.display.print_status("For now, install tools manually using your package manager", StatusType.INFO)
        return None
    
    def _action_view_logs(self, context: MenuContext) -> Optional[str]:
        """View logs action"""
        self.display.print_header("View Logs", "Application Log Files")
        self.display.print_status("This feature will be implemented in the next phase", StatusType.INFO)
        return None
    
    def _action_general_settings(self, context: MenuContext) -> Optional[str]:
        """General settings action"""
        self.display.print_header("General Settings", "Application Configuration")
        
        settings = context.config.get_all_settings()
        for section, values in settings.items():
            self.display.console.print(f"\n[{self.display.colors['accent']}]{section}:[/]")
            for key, value in values.items():
                # Hide sensitive values
                if any(sensitive in key.lower() for sensitive in ['key', 'token', 'password']):
                    value = "***HIDDEN***"
                self.display.console.print(f"  {key}: {value}")
        
        return None
    
    def _action_api_keys(self, context: MenuContext) -> Optional[str]:
        """API keys action"""
        self.display.print_header("API Keys Management", "External Service Configuration")
        
        if self.display.prompt_confirm("Configure API keys?", default=True):
            self._setup_api_keys()
        
        return None
    
    def _action_change_theme(self, context: MenuContext) -> Optional[str]:
        """Change theme action"""
        self.display.print_header("Terminal Theme", "Visual Appearance Settings")
        
        themes = ["default", "dark", "hacker", "light"]
        current_theme = context.config.get('TERMINAL', 'theme', 'default')
        
        new_theme = self.display.prompt_choice("Select theme", themes, current_theme)
        
        if new_theme != current_theme:
            context.config.set_setting('TERMINAL', 'theme', new_theme)
            context.config.save_config()
            self.display.print_status(f"Theme changed to '{new_theme}' - restart to apply", StatusType.SUCCESS)
        else:
            self.display.print_status("Theme unchanged", StatusType.INFO)
        
        return None
    
    def _action_backup_config(self, context: MenuContext) -> Optional[str]:
        """Backup configuration action"""
        self.display.print_header("Backup Configuration", "Data Protection")
        self.display.print_status("This feature will be implemented in the next phase", StatusType.INFO)
        return None
    
    def _action_reset_config(self, context: MenuContext) -> Optional[str]:
        """Reset configuration action"""
        self.display.print_header("Reset Configuration", "Restore Default Settings")
        self.display.print_status("This feature will be implemented in the next phase", StatusType.INFO)
        return None
    
    def shutdown(self):
        """Shutdown terminal interface"""
        self.logger.log_system("Terminal UI shutting down")
        self.running = False
        
        if self.navigator:
            self.navigator.running = False
        
        if self.display:
            self.display.cleanup()