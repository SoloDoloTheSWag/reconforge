#!/usr/bin/env python3
"""
ReconForge Terminal-First Professional Reconnaissance Platform
Comprehensive Logging System

Built from scratch for the complete ReconForge rebuild.
Provides enterprise-grade logging capabilities with comprehensive tracking
of every action, decision, and operation in the terminal-first platform.

Features:
- Multi-level categorized logging (SYSTEM, USER, TOOL, SCAN, DATABASE, etc.)
- Daily rotation with automatic cleanup
- Performance metrics tracking with operation timing
- User interaction logging for all menu selections and inputs
- External tool execution logging with full command details
- Error tracking with complete stack traces and context
- Session state logging and management
- JSON structured logs for analysis and monitoring
"""

import logging
import os
import sys
import threading
import time
import json
import traceback
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, asdict
from enum import Enum
from logging.handlers import RotatingFileHandler, TimedRotatingFileHandler


class LogLevel(Enum):
    """Log severity levels"""
    DEBUG = "DEBUG"
    INFO = "INFO" 
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class LogCategory(Enum):
    """Categorized logging for organized tracking"""
    SYSTEM = "SYSTEM"           # System startup, shutdown, initialization
    USER = "USER"              # User interactions, menu selections, input
    TOOL = "TOOL"              # External tool execution, commands, results
    SCAN = "SCAN"              # Scanning operations, discovery, enumeration
    DATABASE = "DATABASE"       # Database operations, queries, storage
    CONFIG = "CONFIG"          # Configuration changes, settings
    PERFORMANCE = "PERFORMANCE" # Performance metrics, timing, resource usage
    ERROR = "ERROR"            # Error handling, exceptions, failures
    SECURITY = "SECURITY"      # Security events, validation, authentication


@dataclass
class LogEntry:
    """Structured log entry for consistent formatting"""
    timestamp: str
    session_id: str
    level: LogLevel
    category: LogCategory
    module: str
    function: str
    message: str
    data: Optional[Dict[str, Any]] = None
    duration_ms: Optional[float] = None
    thread_id: Optional[str] = None


class PerformanceTracker:
    """Performance tracking for operations and timing"""
    
    def __init__(self, logger_instance):
        self.logger = logger_instance
        self.active_operations = {}
        self.lock = threading.Lock()
    
    def start_operation(self, operation_name: str) -> str:
        """Start tracking a timed operation"""
        operation_id = f"{operation_name}_{int(time.time() * 1000)}"
        
        with self.lock:
            self.active_operations[operation_id] = {
                'name': operation_name,
                'start_time': time.time(),
                'thread_id': threading.current_thread().name
            }
        
        return operation_id
    
    def end_operation(self, operation_id: str, success: bool = True, 
                     result_data: Optional[Dict[str, Any]] = None):
        """Complete operation tracking and log performance"""
        with self.lock:
            if operation_id in self.active_operations:
                operation = self.active_operations.pop(operation_id)
                duration_ms = (time.time() - operation['start_time']) * 1000
                
                log_data = {
                    "operation_id": operation_id,
                    "operation_name": operation['name'],
                    "duration_ms": round(duration_ms, 2),
                    "success": success,
                    "thread_id": operation['thread_id']
                }
                
                if result_data:
                    log_data.update(result_data)
                
                self.logger.log_performance(
                    f"Operation '{operation['name']}' completed in {duration_ms:.2f}ms",
                    log_data
                )


class ReconForgeLogger:
    """
    Professional logging system for terminal-first ReconForge platform
    
    Comprehensive logging with categorization, rotation, performance tracking,
    and detailed audit trails for all reconnaissance activities.
    """
    
    def __init__(self, log_dir: str = "logs", session_id: Optional[str] = None):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(exist_ok=True)
        
        # Session management
        self.session_id = session_id or self._generate_session_id()
        self.session_start = datetime.now()
        
        # Performance tracking
        self.performance_tracker = PerformanceTracker(self)
        
        # Thread safety
        self._lock = threading.RLock()
        
        # Initialize all loggers
        self._setup_loggers()
        
        # Log system initialization
        self.log_system("ReconForge logging system initialized", {
            "session_id": self.session_id,
            "log_directory": str(self.log_dir),
            "session_start": self.session_start.isoformat(),
            "python_version": sys.version,
            "platform": sys.platform
        })
    
    def _generate_session_id(self) -> str:
        """Generate unique session identifier"""
        return f"reconforge_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
    def _setup_loggers(self):
        """Initialize all logging handlers with proper configuration"""
        
        # Formatters for different log types
        detailed_formatter = logging.Formatter(
            '%(asctime)s | %(name)-20s | %(levelname)-8s | %(funcName)-25s | %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        json_formatter = logging.Formatter('%(message)s')
        
        # Main application logger
        self.main_logger = logging.getLogger('reconforge.main')
        self.main_logger.setLevel(logging.DEBUG)
        
        # Main log file with rotation (20MB, keep 15 files)
        main_handler = RotatingFileHandler(
            self.log_dir / 'reconforge_main.log',
            maxBytes=20 * 1024 * 1024,
            backupCount=15
        )
        main_handler.setFormatter(detailed_formatter)
        main_handler.setLevel(logging.DEBUG)
        self.main_logger.addHandler(main_handler)
        
        # Session-specific log file
        session_handler = RotatingFileHandler(
            self.log_dir / f'session_{self.session_id}.log',
            maxBytes=10 * 1024 * 1024,
            backupCount=5
        )
        session_handler.setFormatter(detailed_formatter)
        session_handler.setLevel(logging.INFO)
        self.main_logger.addHandler(session_handler)
        
        # User interaction logger
        self.user_logger = logging.getLogger('reconforge.user')
        self.user_logger.setLevel(logging.INFO)
        user_handler = RotatingFileHandler(
            self.log_dir / 'user_interactions.log',
            maxBytes=5 * 1024 * 1024,
            backupCount=10
        )
        user_handler.setFormatter(detailed_formatter)
        self.user_logger.addHandler(user_handler)
        
        # Tool execution logger
        self.tool_logger = logging.getLogger('reconforge.tools')
        self.tool_logger.setLevel(logging.DEBUG)
        tool_handler = RotatingFileHandler(
            self.log_dir / 'tool_execution.log',
            maxBytes=15 * 1024 * 1024,
            backupCount=10
        )
        tool_handler.setFormatter(detailed_formatter)
        self.tool_logger.addHandler(tool_handler)
        
        # Scan operations logger
        self.scan_logger = logging.getLogger('reconforge.scans')
        self.scan_logger.setLevel(logging.INFO)
        scan_handler = RotatingFileHandler(
            self.log_dir / 'scan_operations.log',
            maxBytes=15 * 1024 * 1024,
            backupCount=15
        )
        scan_handler.setFormatter(detailed_formatter)
        self.scan_logger.addHandler(scan_handler)
        
        # Database operations logger
        self.database_logger = logging.getLogger('reconforge.database')
        self.database_logger.setLevel(logging.DEBUG)
        db_handler = RotatingFileHandler(
            self.log_dir / 'database_operations.log',
            maxBytes=10 * 1024 * 1024,
            backupCount=10
        )
        db_handler.setFormatter(detailed_formatter)
        self.database_logger.addHandler(db_handler)
        
        # Performance metrics logger
        self.performance_logger = logging.getLogger('reconforge.performance')
        self.performance_logger.setLevel(logging.INFO)
        perf_handler = RotatingFileHandler(
            self.log_dir / 'performance_metrics.log',
            maxBytes=10 * 1024 * 1024,
            backupCount=10
        )
        perf_handler.setFormatter(detailed_formatter)
        self.performance_logger.addHandler(perf_handler)
        
        # Structured error logger (JSON format)
        self.error_logger = logging.getLogger('reconforge.errors')
        self.error_logger.setLevel(logging.WARNING)
        error_handler = RotatingFileHandler(
            self.log_dir / 'errors_structured.jsonl',
            maxBytes=10 * 1024 * 1024,
            backupCount=15
        )
        error_handler.setFormatter(json_formatter)
        self.error_logger.addHandler(error_handler)
        
        # Security events logger
        self.security_logger = logging.getLogger('reconforge.security')
        self.security_logger.setLevel(logging.INFO)
        security_handler = RotatingFileHandler(
            self.log_dir / 'security_events.log',
            maxBytes=5 * 1024 * 1024,
            backupCount=10
        )
        security_handler.setFormatter(detailed_formatter)
        self.security_logger.addHandler(security_handler)
    
    def _get_caller_context(self):
        """Get detailed caller information for comprehensive logging"""
        frame = sys._getframe(3)  # Go up the call stack
        return {
            "module": frame.f_globals.get('__name__', 'unknown'),
            "function": frame.f_code.co_name,
            "line_number": frame.f_lineno,
            "filename": frame.f_code.co_filename,
            "thread_id": threading.current_thread().name
        }
    
    def _create_log_entry(self, level: LogLevel, category: LogCategory, 
                         message: str, data: Optional[Dict[str, Any]] = None,
                         duration_ms: Optional[float] = None) -> LogEntry:
        """Create structured log entry with complete context"""
        caller_info = self._get_caller_context()
        
        return LogEntry(
            timestamp=datetime.now().isoformat(),
            session_id=self.session_id,
            level=level,
            category=category,
            module=caller_info['module'],
            function=caller_info['function'],
            message=message,
            data=data,
            duration_ms=duration_ms,
            thread_id=caller_info['thread_id']
        )
    
    def _log_to_appropriate_logger(self, entry: LogEntry):
        """Route log entry to appropriate logger based on category"""
        
        # Format message with comprehensive context
        log_message = f"[{entry.category.value}] {entry.message}"
        
        if entry.data:
            log_message += f" | Data: {json.dumps(entry.data, default=str)}"
        
        if entry.duration_ms:
            log_message += f" | Duration: {entry.duration_ms:.2f}ms"
        
        # Route to appropriate logger
        if entry.category == LogCategory.USER:
            getattr(self.user_logger, entry.level.value.lower())(log_message)
            
        elif entry.category == LogCategory.TOOL:
            getattr(self.tool_logger, entry.level.value.lower())(log_message)
            
        elif entry.category == LogCategory.SCAN:
            getattr(self.scan_logger, entry.level.value.lower())(log_message)
            
        elif entry.category == LogCategory.DATABASE:
            getattr(self.database_logger, entry.level.value.lower())(log_message)
            
        elif entry.category == LogCategory.PERFORMANCE:
            getattr(self.performance_logger, entry.level.value.lower())(log_message)
            
        elif entry.category == LogCategory.SECURITY:
            getattr(self.security_logger, entry.level.value.lower())(log_message)
            
        elif entry.category == LogCategory.ERROR:
            # Log structured errors as JSON
            error_entry = asdict(entry)
            self.error_logger.error(json.dumps(error_entry, default=str))
        
        # Always log to main logger as well
        getattr(self.main_logger, entry.level.value.lower())(log_message)
    
    # Public logging methods for different categories
    
    def log_system(self, message: str, data: Optional[Dict[str, Any]] = None):
        """Log system-level operations and events"""
        with self._lock:
            entry = self._create_log_entry(LogLevel.INFO, LogCategory.SYSTEM, message, data)
            self._log_to_appropriate_logger(entry)
    
    def log_user_action(self, message: str, data: Optional[Dict[str, Any]] = None):
        """Log user interactions, menu selections, and input"""
        with self._lock:
            entry = self._create_log_entry(LogLevel.INFO, LogCategory.USER, message, data)
            self._log_to_appropriate_logger(entry)
    
    def log_tool_execution(self, message: str, data: Optional[Dict[str, Any]] = None):
        """Log external tool execution with full context"""
        with self._lock:
            entry = self._create_log_entry(LogLevel.INFO, LogCategory.TOOL, message, data)
            self._log_to_appropriate_logger(entry)
    
    def log_scan_operation(self, message: str, data: Optional[Dict[str, Any]] = None):
        """Log reconnaissance and scanning operations"""
        with self._lock:
            entry = self._create_log_entry(LogLevel.INFO, LogCategory.SCAN, message, data)
            self._log_to_appropriate_logger(entry)
    
    def log_database_operation(self, message: str, data: Optional[Dict[str, Any]] = None):
        """Log database operations and queries"""
        with self._lock:
            entry = self._create_log_entry(LogLevel.DEBUG, LogCategory.DATABASE, message, data)
            self._log_to_appropriate_logger(entry)
    
    def log_config_change(self, message: str, data: Optional[Dict[str, Any]] = None):
        """Log configuration changes and updates"""
        with self._lock:
            entry = self._create_log_entry(LogLevel.INFO, LogCategory.CONFIG, message, data)
            self._log_to_appropriate_logger(entry)
    
    def log_performance(self, message: str, data: Optional[Dict[str, Any]] = None):
        """Log performance metrics and timing"""
        duration_ms = data.get('duration_ms') if data else None
        with self._lock:
            entry = self._create_log_entry(LogLevel.INFO, LogCategory.PERFORMANCE, message, data, duration_ms)
            self._log_to_appropriate_logger(entry)
    
    def log_security_event(self, message: str, data: Optional[Dict[str, Any]] = None):
        """Log security-related events and validations"""
        with self._lock:
            entry = self._create_log_entry(LogLevel.WARNING, LogCategory.SECURITY, message, data)
            self._log_to_appropriate_logger(entry)
    
    def log_error(self, message: str, exception: Optional[Exception] = None, 
                  data: Optional[Dict[str, Any]] = None):
        """Log errors with comprehensive context and stack traces"""
        error_data = data.copy() if data else {}
        
        if exception:
            error_data.update({
                "exception_type": type(exception).__name__,
                "exception_message": str(exception),
                "stack_trace": traceback.format_exc(),
                "exception_args": getattr(exception, 'args', None)
            })
        
        with self._lock:
            entry = self._create_log_entry(LogLevel.ERROR, LogCategory.ERROR, message, error_data)
            self._log_to_appropriate_logger(entry)
    
    def log_warning(self, message: str, data: Optional[Dict[str, Any]] = None):
        """Log warnings and potential issues"""
        with self._lock:
            entry = self._create_log_entry(LogLevel.WARNING, LogCategory.SYSTEM, message, data)
            self._log_to_appropriate_logger(entry)
    
    def log_debug(self, message: str, data: Optional[Dict[str, Any]] = None):
        """Log detailed debug information"""
        with self._lock:
            entry = self._create_log_entry(LogLevel.DEBUG, LogCategory.SYSTEM, message, data)
            self._log_to_appropriate_logger(entry)
    
    def log_critical(self, message: str, data: Optional[Dict[str, Any]] = None):
        """Log critical system issues"""
        with self._lock:
            entry = self._create_log_entry(LogLevel.CRITICAL, LogCategory.SYSTEM, message, data)
            self._log_to_appropriate_logger(entry)
    
    # Performance tracking methods
    
    def start_performance_tracking(self, operation_name: str) -> str:
        """Start tracking performance for an operation"""
        return self.performance_tracker.start_operation(operation_name)
    
    def end_performance_tracking(self, operation_id: str, success: bool = True, 
                                result_data: Optional[Dict[str, Any]] = None):
        """End performance tracking for an operation"""
        self.performance_tracker.end_operation(operation_id, success, result_data)
    
    # Context managers for automatic operation tracking
    
    def track_operation(self, operation_name: str):
        """Context manager for automatic performance tracking"""
        class OperationTracker:
            def __init__(self, logger, name):
                self.logger = logger
                self.operation_name = name
                self.operation_id = None
                self.success = True
                self.result_data = {}
            
            def __enter__(self):
                self.operation_id = self.logger.start_performance_tracking(self.operation_name)
                return self
            
            def __exit__(self, exc_type, exc_val, exc_tb):
                if exc_type is not None:
                    self.success = False
                    self.logger.log_error(
                        f"Operation '{self.operation_name}' failed with exception",
                        exc_val,
                        {"operation_id": self.operation_id}
                    )
                
                self.logger.end_performance_tracking(
                    self.operation_id, 
                    self.success, 
                    self.result_data
                )
            
            def add_result_data(self, key: str, value: Any):
                """Add result data to be logged with operation completion"""
                self.result_data[key] = value
        
        return OperationTracker(self, operation_name)
    
    # Utility and management methods
    
    def get_session_stats(self) -> Dict[str, Any]:
        """Get comprehensive session statistics"""
        uptime = datetime.now() - self.session_start
        
        return {
            "session_id": self.session_id,
            "session_start": self.session_start.isoformat(),
            "uptime_seconds": uptime.total_seconds(),
            "uptime_formatted": str(uptime),
            "log_directory": str(self.log_dir),
            "active_operations": len(self.performance_tracker.active_operations),
            "thread_count": threading.active_count()
        }
    
    def cleanup_old_logs(self, days_to_keep: int = 30):
        """Clean up old log files beyond retention period"""
        cutoff_date = datetime.now() - timedelta(days=days_to_keep)
        cleanup_count = 0
        
        try:
            for log_file in self.log_dir.glob("*.log*"):
                if log_file.stat().st_mtime < cutoff_date.timestamp():
                    log_file.unlink()
                    cleanup_count += 1
            
            if cleanup_count > 0:
                self.log_system(f"Cleaned up {cleanup_count} old log files", {
                    "cutoff_date": cutoff_date.isoformat(),
                    "retention_days": days_to_keep
                })
                
        except Exception as e:
            self.log_error("Failed to cleanup old logs", e)
    
    def set_log_level(self, level: LogLevel):
        """Set logging level for all loggers"""
        python_level = getattr(logging, level.value)
        
        # Update all loggers
        loggers = [
            self.main_logger, self.user_logger, self.tool_logger,
            self.scan_logger, self.database_logger,
            self.performance_logger, self.security_logger, self.error_logger
        ]
        
        for logger in loggers:
            logger.setLevel(python_level)
        
        self.log_system(f"Log level changed to {level.value}")
    
    def shutdown(self):
        """Graceful logging system shutdown"""
        session_stats = self.get_session_stats()
        
        self.log_system("ReconForge logging system shutdown initiated", session_stats)
        
        # Close all handlers
        for logger in [self.main_logger, self.user_logger, self.tool_logger, 
                      self.scan_logger, self.database_logger, self.performance_logger,
                      self.error_logger, self.security_logger]:
            
            for handler in logger.handlers[:]:
                handler.close()
                logger.removeHandler(handler)


# Global logger instance
_global_logger: Optional[ReconForgeLogger] = None


def initialize_logging(log_dir: str = "logs", session_id: Optional[str] = None) -> ReconForgeLogger:
    """Initialize the global logging system"""
    global _global_logger
    _global_logger = ReconForgeLogger(log_dir, session_id)
    return _global_logger


def get_logger() -> ReconForgeLogger:
    """Get the global logger instance"""
    global _global_logger
    if _global_logger is None:
        _global_logger = ReconForgeLogger()
    return _global_logger


def shutdown_logging():
    """Shutdown the global logging system"""
    global _global_logger
    if _global_logger:
        _global_logger.shutdown()
        _global_logger = None


# Decorator for automatic function call logging
def log_function_call(category: LogCategory = LogCategory.SYSTEM):
    """Decorator for automatic function call logging with performance tracking"""
    def decorator(func):
        def wrapper(*args, **kwargs):
            logger = get_logger()
            func_name = f"{func.__module__}.{func.__name__}"
            
            # Start performance tracking
            with logger.track_operation(func_name) as tracker:
                # Log function entry
                logger._log_to_appropriate_logger(
                    logger._create_log_entry(
                        LogLevel.DEBUG,
                        category,
                        f"Entering function: {func_name}",
                        {
                            "args_count": len(args),
                            "kwargs_keys": list(kwargs.keys())
                        }
                    )
                )
                
                try:
                    result = func(*args, **kwargs)
                    tracker.add_result_data("function_result", "success")
                    return result
                    
                except Exception as e:
                    tracker.add_result_data("function_result", "exception")
                    tracker.add_result_data("exception_type", type(e).__name__)
                    raise
        
        return wrapper
    return decorator


if __name__ == "__main__":
    # Test the logging system
    print("Testing ReconForge logging system...")
    
    logger = initialize_logging()
    
    # Test various logging categories
    logger.log_system("ReconForge logging system test initiated")
    logger.log_user_action("User selected main menu option", {"option": 1, "menu": "main"})
    logger.log_tool_execution("Executing subfinder", {"command": "subfinder -d example.com", "timeout": 30})
    logger.log_scan_operation("Starting subdomain discovery", {"target": "example.com", "sources": 5})
    logger.log_database_operation("Storing scan results", {"scan_id": "test_123", "results_count": 25})
    
    # Test performance tracking
    with logger.track_operation("test_operation") as tracker:
        time.sleep(0.1)  # Simulate work
        tracker.add_result_data("items_processed", 100)
    
    # Test error logging
    try:
        raise ValueError("Test error for logging")
    except ValueError as e:
        logger.log_error("Test error occurred during logging test", e)
    
    # Test session stats
    stats = logger.get_session_stats()
    logger.log_system("Logging system test completed", stats)
    
    print("✅ Logging system test completed successfully")
    print(f"📁 Logs available in: {logger.log_dir}")
    
    # Shutdown
    shutdown_logging()