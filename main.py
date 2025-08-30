#!/usr/bin/env python3
"""
ReconForge - Terminal-First Professional Reconnaissance Platform
Main Entry Point

A comprehensive reconnaissance platform designed for security professionals
with a focus on terminal-based interaction and comprehensive logging.

Usage:
    python3 main.py [options]
    
Options:
    --config PATH       Use custom configuration file
    --log-level LEVEL   Set logging level (DEBUG, INFO, WARNING, ERROR)
    --session-id ID     Resume existing session
    --help              Show help information
    --version           Show version information
"""

import os
import sys
import signal
import argparse
from pathlib import Path
from typing import Optional, Dict, Any
from datetime import datetime, timezone

# Add the current directory to Python path for imports
sys.path.insert(0, str(Path(__file__).parent))

from core.logger import ReconForgeLogger, LogLevel
from core.config import ReconForgeConfig
from core.database import ReconForgeDatabase
from core.utils import ReconForgeUtils


class ReconForgeApp:
    """Main ReconForge application class"""
    
    VERSION = "2.0.1"
    BUILD_DATE = "2025-08-28"
    DESCRIPTION = "Terminal-First Professional Reconnaissance Platform"
    
    def __init__(self, config_path: Optional[str] = None, log_level: Optional[str] = None):
        """Initialize ReconForge application"""
        self.config_path = config_path
        self.log_level = log_level
        self.session_id: Optional[str] = None
        self.startup_time = datetime.now(timezone.utc)
        
        # Core components (initialized in startup)
        self.logger: Optional[ReconForgeLogger] = None
        self.config: Optional[ReconForgeConfig] = None
        self.database: Optional[ReconForgeDatabase] = None
        self.utils: Optional[ReconForgeUtils] = None
        
        # Application state
        self.running = False
        self.initialized = False
        self.terminal_ui = None
        
        # Signal handlers
        self._setup_signal_handlers()
    
    def _setup_signal_handlers(self):
        """Setup signal handlers for graceful shutdown"""
        def signal_handler(signum, frame):
            print(f"\n[INFO] Received signal {signum}, initiating graceful shutdown...")
            self.shutdown()
            sys.exit(0)
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
    
    def startup(self) -> bool:
        """Initialize all application components"""
        try:
            print(f"[INFO] Starting {self.DESCRIPTION} v{self.VERSION}")
            print(f"[INFO] Build Date: {self.BUILD_DATE}")
            print(f"[INFO] Python Version: {sys.version.split()[0]}")
            print(f"[INFO] Working Directory: {os.getcwd()}")
            print()
            
            # Phase 1: Initialize Logger
            print("[INIT] Initializing logging system...")
            self.logger = ReconForgeLogger()
            
            # Set custom log level if provided
            if self.log_level:
                try:
                    level = LogLevel[self.log_level.upper()]
                    self.logger.set_log_level(level)
                except KeyError:
                    print(f"[WARNING] Invalid log level '{self.log_level}', using default")
            
            self.logger.log_system("=== ReconForge Application Startup ===")
            self.logger.log_system(f"Version: {self.VERSION}")
            self.logger.log_system(f"Build Date: {self.BUILD_DATE}")
            self.logger.log_system(f"Startup Time: {self.startup_time.isoformat()}")
            self.logger.log_system(f"Python Version: {sys.version}")
            self.logger.log_system(f"Working Directory: {os.getcwd()}")
            
            # Phase 2: Initialize Configuration
            print("[INIT] Loading configuration...")
            self.config = ReconForgeConfig(config_file=self.config_path or "config.json")
            
            if not self.config.load_config():
                self.logger.log_error("Failed to load configuration")
                return False
            
            self.logger.log_system("Configuration loaded successfully")
            
            # Phase 3: Initialize Database
            print("[INIT] Initializing database...")
            self.database = ReconForgeDatabase(
                db_path='data/reconforge.db'
            )
            
            self.logger.log_system("Database initialized successfully")
            
            # Phase 4: Initialize Utilities
            print("[INIT] Initializing utilities...")
            self.utils = ReconForgeUtils(self.logger)
            self.logger.log_system("Utilities initialized successfully")
            
            # Phase 5: Generate Session ID
            self.session_id = self.utils.generate_session_id()
            self.logger.log_system(f"Session ID: {self.session_id}")
            
            # Phase 6: Log System Information
            system_info = self.utils.get_system_info()
            self.logger.log_system(f"System Information: {system_info}")
            
            # Phase 7: Tool Availability Check
            print("[INIT] Checking tool availability...")
            available_tools = self.utils.tool_manager.get_available_tools()
            missing_tools = self.utils.tool_manager.get_missing_tools()
            
            self.logger.log_system(f"Available tools: {len(available_tools)}")
            self.logger.log_system(f"Missing tools: {len(missing_tools)}")
            
            for tool in available_tools:
                self.logger.log_tool_execution(f"Available: {tool.name} - {tool.description}")
            
            for tool in missing_tools:
                self.logger.log_tool_execution(f"Missing: {tool.name} - {tool.description}")
            
            # Phase 8: Database Session Setup
            session_data = {
                'session_id': self.session_id,
                'start_time': self.startup_time.isoformat(),
                'version': self.VERSION,
                'available_tools': len(available_tools),
                'missing_tools': len(missing_tools)
            }
            
            if not self.database.create_session(self.session_id, session_data):
                self.logger.log_error("Failed to create database session")
                return False
            
            # Phase 9: Initialize Terminal Interface (if available)
            try:
                from interface.terminal_ui import TerminalUI
                print("[INIT] Initializing terminal interface...")
                self.terminal_ui = TerminalUI(
                    logger=self.logger,
                    config=self.config,
                    database=self.database,
                    utils=self.utils
                )
                self.logger.log_system("Terminal interface initialized successfully")
                print("[INIT] Terminal interface ready")
            except ImportError:
                print("[WARNING] Terminal interface not available (will be created in next phase)")
                self.logger.log_system("Terminal interface not available - will use basic mode")
            
            # Startup Complete
            startup_duration = (datetime.now(timezone.utc) - self.startup_time).total_seconds()
            self.logger.log_system(f"Application startup completed in {startup_duration:.2f}s")
            
            print(f"[SUCCESS] ReconForge initialized successfully in {startup_duration:.2f}s")
            print(f"[INFO] Session ID: {self.session_id}")
            print(f"[INFO] Available Tools: {len(available_tools)}/{len(available_tools + missing_tools)}")
            
            if missing_tools:
                print(f"[WARNING] Missing {len(missing_tools)} tools - some features may be limited")
                print("[WARNING] Run 'sudo apt update && sudo apt install -y <tool-names>' to install missing tools")
            
            print()
            
            self.initialized = True
            return True
        
        except Exception as e:
            error_msg = f"Application startup failed: {str(e)}"
            print(f"[ERROR] {error_msg}")
            if self.logger:
                self.logger.log_error(error_msg)
                import traceback
                self.logger.log_error(f"Startup traceback: {traceback.format_exc()}")
            return False
    
    def run(self) -> int:
        """Main application run loop"""
        if not self.initialized:
            print("[ERROR] Application not initialized")
            return 1
        
        try:
            self.running = True
            self.logger.log_system("Starting main application run loop")
            
            # Check if terminal interface is available
            if self.terminal_ui:
                print("[INFO] Starting interactive terminal interface...")
                print("[INFO] Use Ctrl+C to exit gracefully")
                print("=" * 60)
                
                # Start terminal interface
                return self.terminal_ui.run()
            else:
                # Basic mode without terminal interface
                print("[INFO] Running in basic mode - terminal interface not available")
                print("[INFO] This is a placeholder until terminal interface is implemented")
                print("=" * 60)
                print()
                print("ReconForge Basic Mode")
                print("====================")
                print()
                print("Available Commands:")
                print("  status    - Show application status")
                print("  tools     - List available tools") 
                print("  config    - Show configuration")
                print("  help      - Show this help")
                print("  exit      - Exit application")
                print()
                
                return self._run_basic_mode()
        
        except KeyboardInterrupt:
            print("\n[INFO] Received keyboard interrupt")
            self.logger.log_system("Application interrupted by user")
            return 0
        
        except Exception as e:
            error_msg = f"Application run failed: {str(e)}"
            print(f"[ERROR] {error_msg}")
            self.logger.log_error(error_msg)
            import traceback
            self.logger.log_error(f"Run traceback: {traceback.format_exc()}")
            return 1
        
        finally:
            self.running = False
    
    def _run_basic_mode(self) -> int:
        """Run basic command mode until terminal interface is available"""
        while self.running:
            try:
                command = input("reconforge> ").strip().lower()
                
                if not command:
                    continue
                
                self.logger.log_user_action(f"Basic mode command: {command}")
                
                if command in ('exit', 'quit', 'q'):
                    print("Exiting ReconForge...")
                    break
                
                elif command == 'status':
                    self._show_status()
                
                elif command == 'tools':
                    self._show_tools()
                
                elif command == 'config':
                    self._show_config()
                
                elif command in ('help', 'h', '?'):
                    self._show_help()
                
                else:
                    print(f"Unknown command: {command}")
                    print("Type 'help' for available commands")
            
            except EOFError:
                print("\nGoodbye!")
                break
            except KeyboardInterrupt:
                print("\nGoodbye!")
                break
        
        return 0
    
    def _show_status(self):
        """Show application status"""
        uptime = (datetime.now(timezone.utc) - self.startup_time).total_seconds()
        
        print()
        print("ReconForge Status")
        print("================")
        print(f"Version: {self.VERSION}")
        print(f"Session ID: {self.session_id}")
        print(f"Uptime: {self.utils.format_duration(uptime)}")
        print(f"Database: Connected")
        print(f"Configuration: Loaded")
        print(f"Logging: Active")
        print()
    
    def _show_tools(self):
        """Show available tools"""
        available = self.utils.tool_manager.get_available_tools()
        missing = self.utils.tool_manager.get_missing_tools()
        
        print()
        print("Tool Status")
        print("===========")
        print(f"Available: {len(available)}")
        print(f"Missing: {len(missing)}")
        print()
        
        if available:
            print("Available Tools:")
            for tool in available:
                version = f" ({tool.version})" if tool.version else ""
                print(f"  ✓ {tool.name}{version} - {tool.description}")
            print()
        
        if missing:
            print("Missing Tools:")
            for tool in missing:
                print(f"  ✗ {tool.name} - {tool.description}")
            print()
    
    def _show_config(self):
        """Show configuration summary"""
        print()
        print("Configuration Summary")
        print("====================")
        
        config_data = self.config.get_all_settings()
        for section, settings in config_data.items():
            print(f"{section}:")
            for key, value in settings.items():
                # Hide sensitive values
                if 'key' in key.lower() or 'token' in key.lower() or 'password' in key.lower():
                    value = "***HIDDEN***"
                print(f"  {key}: {value}")
            print()
    
    def _show_help(self):
        """Show help information"""
        print()
        print("ReconForge Help")
        print("===============")
        print("Available Commands:")
        print("  status    - Show application status")
        print("  tools     - List available tools") 
        print("  config    - Show configuration")
        print("  help      - Show this help")
        print("  exit      - Exit application")
        print()
        print("Note: Full terminal interface will be available in the next phase")
        print()
    
    def shutdown(self):
        """Graceful application shutdown"""
        if not self.initialized:
            return
        
        shutdown_time = datetime.now(timezone.utc)
        self.logger.log_system("=== ReconForge Application Shutdown ===")
        
        try:
            # Stop terminal interface if running
            if self.terminal_ui and self.running:
                self.logger.log_system("Stopping terminal interface...")
                self.terminal_ui.shutdown()
            
            # Close database session
            if self.database:
                self.logger.log_system("Closing database session...")
                if self.session_id:
                    self.database.end_session(self.session_id)
                
                self.database.close()
            
            # Log shutdown
            total_runtime = (shutdown_time - self.startup_time).total_seconds()
            self.logger.log_system(f"Total runtime: {total_runtime:.2f}s")
            self.logger.log_system("Application shutdown completed")
            
            print(f"[INFO] ReconForge shutdown completed (runtime: {total_runtime:.2f}s)")
        
        except Exception as e:
            print(f"[ERROR] Error during shutdown: {str(e)}")
            if self.logger:
                self.logger.log_error(f"Shutdown error: {str(e)}")
        
        finally:
            self.running = False
            self.initialized = False


def create_argument_parser() -> argparse.ArgumentParser:
    """Create command line argument parser"""
    parser = argparse.ArgumentParser(
        description="ReconForge - Terminal-First Professional Reconnaissance Platform",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python3 main.py                     # Start with default settings
    python3 main.py --log-level DEBUG   # Enable debug logging
    python3 main.py --config custom.json # Use custom configuration
    
For more information, visit: https://github.com/reconforge/reconforge
        """
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version=f"ReconForge {ReconForgeApp.VERSION} ({ReconForgeApp.BUILD_DATE})"
    )
    
    parser.add_argument(
        '--config',
        type=str,
        help='Path to custom configuration file'
    )
    
    parser.add_argument(
        '--log-level',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
        help='Set logging level'
    )
    
    parser.add_argument(
        '--session-id',
        type=str,
        help='Resume existing session (not implemented yet)'
    )
    
    return parser


def main() -> int:
    """Main entry point"""
    try:
        # Parse command line arguments
        parser = create_argument_parser()
        args = parser.parse_args()
        
        # Create and initialize application
        app = ReconForgeApp(
            config_path=args.config,
            log_level=args.log_level
        )
        
        # Startup application
        if not app.startup():
            print("[ERROR] Failed to start ReconForge")
            return 1
        
        # Run application
        return app.run()
    
    except KeyboardInterrupt:
        print("\n[INFO] Interrupted by user")
        return 0
    
    except Exception as e:
        print(f"[FATAL] Unhandled exception: {str(e)}")
        import traceback
        traceback.print_exc()
        return 1
    
    finally:
        # Ensure cleanup
        try:
            if 'app' in locals():
                app.shutdown()
        except:
            pass


if __name__ == '__main__':
    sys.exit(main())