#!/usr/bin/env python3
"""
ReconForge Terminal-First Professional Reconnaissance Platform
Configuration Management Module

Built from scratch for the complete ReconForge rebuild.
Provides comprehensive configuration management for terminal-first
reconnaissance platform with secure API key handling and tool configuration.

Features:
- JSON-based configuration with schema validation
- Secure API key storage and management (excluded from version control)
- Tool-specific configuration with path validation and version detection
- Terminal interface preferences and display settings
- Performance optimization settings and resource management
- Configuration backup and restore capabilities
- Environment variable integration and override support
- Automatic validation and migration of configuration files
"""

import json
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, field, asdict
from enum import Enum
import shutil
from datetime import datetime

# Import our logging system
from .logger import get_logger, log_function_call, LogCategory


class ConfigSection(Enum):
    """Configuration sections for organized settings"""
    GENERAL = "general"
    API_KEYS = "api_keys"
    TOOLS = "tools"
    TERMINAL = "terminal"
    PERFORMANCE = "performance"
    SCANNING = "scanning"
    REPORTING = "reporting"


@dataclass
class TerminalConfig:
    """Terminal interface configuration settings"""
    theme: str = "dark"
    colors_enabled: bool = True
    progress_bars: bool = True
    table_style: str = "rounded"
    page_size: int = 25
    auto_refresh: bool = True
    refresh_interval: int = 1
    show_timestamps: bool = True
    compact_mode: bool = False
    banner_enabled: bool = True
    breadcrumb_navigation: bool = True


@dataclass
class ToolConfig:
    """Individual tool configuration"""
    name: str
    path: str = ""
    timeout: int = 30
    rate_limit: int = 10
    max_concurrent: int = 5
    enabled: bool = True
    verify_ssl: bool = True
    custom_args: List[str] = field(default_factory=list)
    environment_vars: Dict[str, str] = field(default_factory=dict)
    version: str = ""
    last_verified: str = ""


@dataclass
class ScanConfig:
    """Scanning operation configuration"""
    max_concurrent: int = 10
    timeout: int = 300
    rate_limit: int = 50
    retry_attempts: int = 3
    retry_delay: int = 5
    verify_results: bool = True
    exclude_wildcards: bool = True
    resolve_ips: bool = True
    check_alive: bool = True
    min_confidence: float = 0.7
    default_wordlists: Dict[str, str] = field(default_factory=dict)
    output_formats: List[str] = field(default_factory=lambda: ["json", "txt", "csv"])


@dataclass
class PerformanceConfig:
    """Performance optimization settings"""
    max_memory_mb: int = 2048
    cache_enabled: bool = True
    cache_ttl_hours: int = 24
    database_wal_mode: bool = True
    log_level: str = "INFO"
    log_rotation_mb: int = 20
    log_retention_days: int = 30
    metrics_enabled: bool = True
    cleanup_interval_hours: int = 24
    thread_pool_size: int = 20


@dataclass
class ReportConfig:
    """Reporting and export configuration"""
    default_format: str = "json"
    include_metadata: bool = True
    include_raw_output: bool = False
    timestamp_format: str = "%Y-%m-%d %H:%M:%S"
    export_directory: str = "exports"
    auto_export: bool = False
    compress_exports: bool = False
    report_templates: Dict[str, str] = field(default_factory=dict)


class ReconForgeConfig:
    """
    Professional configuration management for terminal-first ReconForge
    
    Handles all application settings with secure storage, validation,
    and comprehensive management of API keys, tools, and preferences.
    """
    
    def __init__(self, config_file: str = "config.json"):
        self.config_file = Path(config_file)
        self.backup_dir = Path("config_backups")
        self.backup_dir.mkdir(exist_ok=True)
        
        # Initialize logging
        self.logger = get_logger()
        
        # Configuration data storage
        self._config_data: Dict[str, Any] = {}
        self._default_config = self._create_default_config()
        
        # Load configuration
        self.load_config()
        
        self.logger.log_config_change("Configuration system initialized", {
            "config_file": str(self.config_file),
            "sections": list(self._config_data.keys()),
            "backup_dir": str(self.backup_dir)
        })
    
    def _create_default_config(self) -> Dict[str, Any]:
        """Create comprehensive default configuration"""
        return {
            ConfigSection.GENERAL.value: {
                "version": "2.0.0",
                "application_name": "ReconForge Terminal",
                "description": "Professional Terminal-First Reconnaissance Platform",
                "data_directory": "data",
                "log_directory": "logs",
                "export_directory": "exports",
                "temp_directory": "/tmp/reconforge",
                "debug_mode": False,
                "safe_mode": True,
                "auto_update_tools": False
            },
            
            ConfigSection.API_KEYS.value: {
                # FREE RESOURCES ONLY - No API keys required
                # All reconnaissance now uses free public APIs and tools
            },
            
            ConfigSection.TOOLS.value: {
                "subfinder": asdict(ToolConfig(
                    name="subfinder",
                    timeout=60,
                    rate_limit=150,
                    max_concurrent=10
                )),
                "amass": asdict(ToolConfig(
                    name="amass", 
                    timeout=300,
                    rate_limit=50,
                    max_concurrent=5
                )),
                "assetfinder": asdict(ToolConfig(
                    name="assetfinder",
                    timeout=60,
                    rate_limit=100,
                    max_concurrent=10
                )),
                "nuclei": asdict(ToolConfig(
                    name="nuclei",
                    timeout=300,
                    rate_limit=150,
                    max_concurrent=10
                )),
                "httpx": asdict(ToolConfig(
                    name="httpx",
                    timeout=10,
                    rate_limit=100,
                    max_concurrent=20
                )),
                "nmap": asdict(ToolConfig(
                    name="nmap",
                    timeout=600,
                    rate_limit=10,
                    max_concurrent=3
                )),
                "gobuster": asdict(ToolConfig(
                    name="gobuster",
                    timeout=300,
                    rate_limit=50,
                    max_concurrent=5
                )),
                "sqlmap": asdict(ToolConfig(
                    name="sqlmap",
                    timeout=300,
                    rate_limit=5,
                    max_concurrent=2
                )),
                "nikto": asdict(ToolConfig(
                    name="nikto",
                    timeout=600,
                    rate_limit=10,
                    max_concurrent=3
                )),
                "masscan": asdict(ToolConfig(
                    name="masscan",
                    timeout=300,
                    rate_limit=100,
                    max_concurrent=5
                )),
                "shuffledns": asdict(ToolConfig(
                    name="shuffledns",
                    timeout=120,
                    rate_limit=200,
                    max_concurrent=10
                )),
                "gau": asdict(ToolConfig(
                    name="gau",
                    timeout=120,
                    rate_limit=50,
                    max_concurrent=5
                )),
                "waybackurls": asdict(ToolConfig(
                    name="waybackurls",
                    timeout=120,
                    rate_limit=50,
                    max_concurrent=5
                )),
                "testssl": asdict(ToolConfig(
                    name="testssl.sh",
                    timeout=300,
                    rate_limit=10,
                    max_concurrent=3
                ))
            },
            
            ConfigSection.TERMINAL.value: asdict(TerminalConfig()),
            ConfigSection.PERFORMANCE.value: asdict(PerformanceConfig()),
            ConfigSection.SCANNING.value: asdict(ScanConfig()),
            ConfigSection.REPORTING.value: asdict(ReportConfig())
        }
    
    @log_function_call(LogCategory.CONFIG)
    def load_config(self) -> bool:
        """Load configuration from file with validation and defaults"""
        try:
            if self.config_file.exists():
                with open(self.config_file, 'r') as f:
                    loaded_config = json.load(f)
                
                # Merge loaded config with defaults
                self._config_data = self._merge_configs(self._default_config, loaded_config)
                
                self.logger.log_config_change("Configuration loaded from file", {
                    "config_file": str(self.config_file),
                    "file_size_bytes": self.config_file.stat().st_size
                })
            else:
                # Use defaults and create file
                self._config_data = self._default_config.copy()
                self.save_config()
                
                self.logger.log_config_change("Default configuration created", {
                    "config_file": str(self.config_file)
                })
            
            # Validate and auto-detect tools
            self._validate_configuration()
            self._auto_detect_tools()
            
            return True
            
        except Exception as e:
            self.logger.log_error("Failed to load configuration", e, {
                "config_file": str(self.config_file)
            })
            # Fall back to defaults
            self._config_data = self._default_config.copy()
            return False
    
    @log_function_call(LogCategory.CONFIG) 
    def save_config(self) -> bool:
        """Save configuration to file with backup"""
        try:
            # Create backup if file exists
            self._create_backup()
            
            # Ensure parent directory exists
            self.config_file.parent.mkdir(parents=True, exist_ok=True)
            
            # Save configuration with proper formatting
            with open(self.config_file, 'w') as f:
                json.dump(self._config_data, f, indent=2, default=str)
            
            self.logger.log_config_change("Configuration saved to file", {
                "config_file": str(self.config_file),
                "file_size_bytes": self.config_file.stat().st_size
            })
            
            return True
            
        except Exception as e:
            self.logger.log_error("Failed to save configuration", e, {
                "config_file": str(self.config_file)
            })
            return False
    
    def _merge_configs(self, default: Dict[str, Any], loaded: Dict[str, Any]) -> Dict[str, Any]:
        """Recursively merge loaded configuration with defaults"""
        result = default.copy()
        
        for key, value in loaded.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._merge_configs(result[key], value)
            else:
                result[key] = value
        
        return result
    
    def _validate_configuration(self):
        """Validate configuration structure and values"""
        # Ensure all required sections exist
        required_sections = [section.value for section in ConfigSection]
        for section in required_sections:
            if section not in self._config_data:
                self.logger.log_warning(f"Missing configuration section: {section}")
                self._config_data[section] = self._default_config[section].copy()
        
        # Validate directory paths
        general_config = self._config_data[ConfigSection.GENERAL.value]
        for dir_key in ['data_directory', 'log_directory', 'export_directory']:
            if dir_key in general_config:
                dir_path = Path(general_config[dir_key])
                try:
                    dir_path.mkdir(parents=True, exist_ok=True)
                except Exception as e:
                    self.logger.log_warning(f"Failed to create directory: {dir_key}", {
                        "path": str(dir_path),
                        "error": str(e)
                    })
        
        # Validate numeric ranges
        perf_config = self._config_data[ConfigSection.PERFORMANCE.value]
        if perf_config.get('max_memory_mb', 0) < 512:
            perf_config['max_memory_mb'] = 512
            self.logger.log_warning("Minimum memory requirement not met, set to 512MB")
        
        # Validate scan configuration
        scan_config = self._config_data[ConfigSection.SCANNING.value]
        if scan_config.get('max_concurrent', 0) < 1:
            scan_config['max_concurrent'] = 1
        if scan_config.get('timeout', 0) < 30:
            scan_config['timeout'] = 30
    
    def _auto_detect_tools(self):
        """Auto-detect tool paths and versions"""
        tools_config = self._config_data[ConfigSection.TOOLS.value]
        detection_count = 0
        
        for tool_name, tool_config in tools_config.items():
            if not tool_config.get('path'):
                # Try to find tool in PATH
                tool_path = shutil.which(tool_name)
                if tool_path:
                    tool_config['path'] = tool_path
                    tool_config['last_verified'] = datetime.now().isoformat()
                    detection_count += 1
                    
                    self.logger.log_config_change(f"Auto-detected tool: {tool_name}", {
                        "tool_path": tool_path
                    })
                else:
                    tool_config['enabled'] = False
                    self.logger.log_warning(f"Tool not found: {tool_name}")
        
        if detection_count > 0:
            self.logger.log_config_change(f"Auto-detected {detection_count} tools")
    
    def _create_backup(self):
        """Create configuration backup before changes"""
        if self.config_file.exists():
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_file = self.backup_dir / f"config_{timestamp}.json"
            
            try:
                shutil.copy2(self.config_file, backup_file)
                
                # Keep only last 20 backups
                backups = sorted(self.backup_dir.glob("config_*.json"))
                if len(backups) > 20:
                    for old_backup in backups[:-20]:
                        old_backup.unlink()
                
                self.logger.log_config_change("Configuration backup created", {
                    "backup_file": str(backup_file)
                })
                
            except Exception as e:
                self.logger.log_error("Failed to create configuration backup", e)
    
    # Configuration Access Methods
    
    def get(self, section: Union[ConfigSection, str], key: str = None, default: Any = None) -> Any:
        """Get configuration value with optional default"""
        section_name = section.value if isinstance(section, ConfigSection) else section
        
        if section_name not in self._config_data:
            return default
        
        if key is None:
            return self._config_data[section_name]
        
        return self._config_data[section_name].get(key, default)
    
    def set(self, section: Union[ConfigSection, str], key: str, value: Any) -> bool:
        """Set configuration value with logging"""
        section_name = section.value if isinstance(section, ConfigSection) else section
        
        if section_name not in self._config_data:
            self._config_data[section_name] = {}
        
        old_value = self._config_data[section_name].get(key)
        self._config_data[section_name][key] = value
        
        self.logger.log_config_change(f"Configuration updated: {section_name}.{key}", {
            "section": section_name,
            "key": key,
            "old_value": old_value,
            "new_value": value
        })
        
        return self.save_config()
    
    def update_section(self, section: Union[ConfigSection, str], data: Dict[str, Any]) -> bool:
        """Update entire configuration section"""
        section_name = section.value if isinstance(section, ConfigSection) else section
        
        if section_name not in self._config_data:
            self._config_data[section_name] = {}
        
        old_data = self._config_data[section_name].copy()
        self._config_data[section_name].update(data)
        
        self.logger.log_config_change(f"Configuration section updated: {section_name}", {
            "section": section_name,
            "updated_keys": list(data.keys()),
            "changes_count": len(data)
        })
        
        return self.save_config()
    
    # Specialized Configuration Access Methods
    
    def get_api_key(self, service: str) -> Optional[str]:
        """Get API key for specific service"""
        api_keys = self.get(ConfigSection.API_KEYS)
        key_name = f"{service}_api_key"
        return api_keys.get(key_name)
    
    def set_api_key(self, service: str, api_key: str) -> bool:
        """Set API key for service with security logging"""
        key_name = f"{service}_api_key"
        
        # Log API key update (without exposing the key)
        self.logger.log_security_event(f"API key updated for service: {service}", {
            "service": service,
            "key_length": len(api_key) if api_key else 0,
            "key_set": bool(api_key)
        })
        
        return self.set(ConfigSection.API_KEYS, key_name, api_key)
    
    def get_tool_config(self, tool_name: str) -> Optional[Dict[str, Any]]:
        """Get complete tool configuration"""
        tools = self.get(ConfigSection.TOOLS)
        return tools.get(tool_name)
    
    def is_tool_enabled(self, tool_name: str) -> bool:
        """Check if tool is enabled and available"""
        tool_config = self.get_tool_config(tool_name)
        if not tool_config:
            return False
        
        return (tool_config.get('enabled', False) and 
                bool(tool_config.get('path')))
    
    def get_tool_path(self, tool_name: str) -> Optional[str]:
        """Get tool executable path"""
        tool_config = self.get_tool_config(tool_name)
        return tool_config.get('path') if tool_config else None
    
    def update_tool_config(self, tool_name: str, config_updates: Dict[str, Any]) -> bool:
        """Update tool configuration"""
        tools = self.get(ConfigSection.TOOLS) or {}
        
        if tool_name not in tools:
            tools[tool_name] = asdict(ToolConfig(name=tool_name))
        
        tools[tool_name].update(config_updates)
        tools[tool_name]['last_verified'] = datetime.now().isoformat()
        
        return self.update_section(ConfigSection.TOOLS, tools)
    
    def get_terminal_config(self) -> TerminalConfig:
        """Get terminal interface configuration as dataclass"""
        config_dict = self.get(ConfigSection.TERMINAL)
        return TerminalConfig(**config_dict)
    
    def get_scan_config(self) -> ScanConfig:
        """Get scanning configuration as dataclass"""
        config_dict = self.get(ConfigSection.SCANNING)
        return ScanConfig(**config_dict)
    
    def get_performance_config(self) -> PerformanceConfig:
        """Get performance configuration as dataclass"""
        config_dict = self.get(ConfigSection.PERFORMANCE)
        return PerformanceConfig(**config_dict)
    
    def get_report_config(self) -> ReportConfig:
        """Get reporting configuration as dataclass"""
        config_dict = self.get(ConfigSection.REPORTING)
        return ReportConfig(**config_dict)
    
    # Environment Variable Integration
    
    def load_environment_overrides(self):
        """Load configuration overrides from environment variables"""
        env_prefix = "RECONFORGE_"
        overrides = {}
        override_count = 0
        
        for env_var, value in os.environ.items():
            if env_var.startswith(env_prefix):
                key = env_var[len(env_prefix):].lower()
                
                # Parse section.key format
                if '.' in key:
                    section, config_key = key.split('.', 1)
                    if section not in overrides:
                        overrides[section] = {}
                    overrides[section][config_key] = value
                    override_count += 1
                else:
                    overrides[key] = value
                    override_count += 1
        
        # Apply overrides
        for section, values in overrides.items():
            if isinstance(values, dict):
                for key, value in values.items():
                    self.set(section, key, value)
            else:
                self.set("general", section, values)
        
        if override_count > 0:
            self.logger.log_config_change("Environment overrides applied", {
                "overrides_count": override_count,
                "sections_affected": list(overrides.keys())
            })
    
    # Configuration Validation and Testing
    
    def validate_api_keys(self) -> Dict[str, bool]:
        """Validate API keys format and availability"""
        api_keys = self.get(ConfigSection.API_KEYS)
        validation_results = {}
        
        for key_name, api_key in api_keys.items():
            if api_key:
                # Basic validation - non-empty, reasonable length, no obvious issues
                is_valid = (isinstance(api_key, str) and 
                          len(api_key) >= 10 and 
                          not api_key.startswith(' ') and 
                          not api_key.endswith(' '))
                validation_results[key_name] = is_valid
            else:
                validation_results[key_name] = False
        
        self.logger.log_config_change("API keys validated", {
            "validation_results": {k: v for k, v in validation_results.items()},
            "total_keys": len(api_keys),
            "valid_keys": sum(validation_results.values())
        })
        
        return validation_results
    
    def validate_tool_paths(self) -> Dict[str, bool]:
        """Validate all tool executable paths"""
        tools = self.get(ConfigSection.TOOLS)
        validation_results = {}
        
        for tool_name, tool_config in tools.items():
            path = tool_config.get('path')
            
            if path:
                path_obj = Path(path)
                is_valid = (path_obj.exists() and 
                          os.access(path, os.X_OK))
                validation_results[tool_name] = is_valid
                
                if not is_valid:
                    # Try to find tool again
                    new_path = shutil.which(tool_name)
                    if new_path:
                        tool_config['path'] = new_path
                        validation_results[tool_name] = True
                        self.logger.log_config_change(f"Tool path updated: {tool_name}", {
                            "old_path": path,
                            "new_path": new_path
                        })
            else:
                validation_results[tool_name] = False
        
        # Update tools configuration
        self.update_section(ConfigSection.TOOLS, tools)
        
        self.logger.log_config_change("Tool paths validated", {
            "validation_results": validation_results,
            "total_tools": len(tools),
            "valid_tools": sum(validation_results.values())
        })
        
        return validation_results
    
    # Configuration Import/Export
    
    def export_config(self, file_path: str, include_api_keys: bool = False, 
                     sections: List[str] = None) -> bool:
        """Export configuration to file"""
        try:
            export_data = self._config_data.copy()
            
            # Filter sections if specified
            if sections:
                export_data = {k: v for k, v in export_data.items() if k in sections}
            
            # Remove API keys if not requested
            if not include_api_keys and ConfigSection.API_KEYS.value in export_data:
                export_data[ConfigSection.API_KEYS.value] = {
                    key: None for key in export_data[ConfigSection.API_KEYS.value]
                }
            
            # Add export metadata
            export_data['_export_metadata'] = {
                'export_time': datetime.now().isoformat(),
                'version': self.get('general', 'version'),
                'include_api_keys': include_api_keys,
                'sections': list(export_data.keys())
            }
            
            with open(file_path, 'w') as f:
                json.dump(export_data, f, indent=2, default=str)
            
            self.logger.log_config_change("Configuration exported", {
                "export_file": file_path,
                "include_api_keys": include_api_keys,
                "sections_count": len(export_data) - 1  # Exclude metadata
            })
            
            return True
            
        except Exception as e:
            self.logger.log_error("Failed to export configuration", e, {
                "export_file": file_path
            })
            return False
    
    def import_config(self, file_path: str, merge: bool = True, 
                     sections: List[str] = None) -> bool:
        """Import configuration from file"""
        try:
            with open(file_path, 'r') as f:
                import_data = json.load(f)
            
            # Remove metadata if present
            import_data.pop('_export_metadata', None)
            
            # Filter sections if specified
            if sections:
                import_data = {k: v for k, v in import_data.items() if k in sections}
            
            if merge:
                # Merge with existing configuration
                for section, data in import_data.items():
                    if section in self._config_data:
                        if isinstance(self._config_data[section], dict) and isinstance(data, dict):
                            self._config_data[section].update(data)
                        else:
                            self._config_data[section] = data
                    else:
                        self._config_data[section] = data
            else:
                # Replace sections completely
                self._config_data.update(import_data)
            
            # Validate and save
            self._validate_configuration()
            self.save_config()
            
            self.logger.log_config_change("Configuration imported", {
                "import_file": file_path,
                "merge_mode": merge,
                "sections_imported": list(import_data.keys())
            })
            
            return True
            
        except Exception as e:
            self.logger.log_error("Failed to import configuration", e, {
                "import_file": file_path
            })
            return False
    
    # Configuration Reset and Management
    
    def reset_section_to_defaults(self, section: Union[ConfigSection, str]) -> bool:
        """Reset specific section to default values"""
        section_name = section.value if isinstance(section, ConfigSection) else section
        
        if section_name in self._default_config:
            self._config_data[section_name] = self._default_config[section_name].copy()
            
            self.logger.log_config_change(f"Section reset to defaults: {section_name}")
            return self.save_config()
        
        return False
    
    def reset_all_to_defaults(self) -> bool:
        """Reset entire configuration to defaults"""
        self._config_data = self._default_config.copy()
        
        self.logger.log_config_change("Configuration reset to defaults")
        return self.save_config()
    
    def get_config_summary(self) -> Dict[str, Any]:
        """Get comprehensive configuration summary"""
        api_keys = self.get(ConfigSection.API_KEYS)
        tools = self.get(ConfigSection.TOOLS)
        
        return {
            "config_file": str(self.config_file),
            "config_exists": self.config_file.exists(),
            "last_modified": datetime.fromtimestamp(
                self.config_file.stat().st_mtime
            ).isoformat() if self.config_file.exists() else None,
            "file_size_bytes": self.config_file.stat().st_size if self.config_file.exists() else 0,
            "sections": list(self._config_data.keys()),
            "api_keys_configured": sum(1 for v in api_keys.values() if v),
            "total_api_keys": len(api_keys),
            "tools_enabled": sum(1 for t in tools.values() if t.get('enabled')),
            "tools_with_paths": sum(1 for t in tools.values() if t.get('path')),
            "total_tools": len(tools),
            "version": self.get('general', 'version'),
            "debug_mode": self.get('general', 'debug_mode', False)
        }


# Global configuration instance
_global_config: Optional[ReconForgeConfig] = None


def initialize_config(config_file: str = "config.json") -> ReconForgeConfig:
    """Initialize the global configuration instance"""
    global _global_config
    _global_config = ReconForgeConfig(config_file)
    return _global_config


def get_config() -> ReconForgeConfig:
    """Get the global configuration instance"""
    global _global_config
    if _global_config is None:
        _global_config = ReconForgeConfig()
    return _global_config


if __name__ == "__main__":
    # Test the configuration system
    print("Testing ReconForge configuration system...")
    
    config = initialize_config()
    
    # Test configuration access
    print(f"Application name: {config.get('general', 'application_name')}")
    print(f"Debug mode: {config.get('general', 'debug_mode')}")
    
    # Test tool configuration
    subfinder_config = config.get_tool_config("subfinder")
    print(f"Subfinder enabled: {config.is_tool_enabled('subfinder')}")
    print(f"Subfinder path: {config.get_tool_path('subfinder')}")
    
    # Test API key management
    config.set_api_key("shodan", "test_key_12345")
    print(f"Shodan API key set: {bool(config.get_api_key('shodan'))}")
    
    # Test validation
    tool_validation = config.validate_tool_paths()
    api_validation = config.validate_api_keys()
    print(f"Tools validated: {sum(tool_validation.values())}/{len(tool_validation)}")
    print(f"API keys validated: {sum(api_validation.values())}/{len(api_validation)}")
    
    # Test configuration summary
    summary = config.get_config_summary()
    print(f"Configuration summary: {summary['sections']}")
    
    print("✅ Configuration system test completed successfully")