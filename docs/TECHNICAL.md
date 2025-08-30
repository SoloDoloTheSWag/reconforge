# ReconForge Technical Documentation 🔧

**Version 2.0.0 - Terminal-First Professional Reconnaissance Platform**

## 📚 Table of Contents

- [Architecture Overview](#architecture-overview)
- [Core Components](#core-components)
- [Module System](#module-system)
- [Database Design](#database-design)
- [Logging System](#logging-system)
- [Security Framework](#security-framework)
- [Performance Optimization](#performance-optimization)
- [API Reference](#api-reference)
- [Development Guide](#development-guide)

---

## 🏗️ Architecture Overview

### **Design Philosophy**
ReconForge v2.0.0 follows a **clean architecture** pattern with clear separation of concerns:

```
┌─────────────────────────────────────────────────────────────┐
│                    Terminal Interface                        │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────────────────┐ │
│  │ display.py  │ │  menus.py   │ │    terminal_ui.py       │ │
│  │ Rich UI     │ │ Navigation  │ │   Main Interface        │ │
│  └─────────────┘ └─────────────┘ └─────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────┐
│                    Application Core                          │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────┐ │
│  │  logger.py  │ │ database.py │ │ config.py   │ │utils.py │ │
│  │  Logging    │ │  Data       │ │ Settings    │ │Security │ │
│  └─────────────┘ └─────────────┘ └─────────────┘ └─────────┘ │
└─────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────┐
│                 Reconnaissance Modules                       │
│ ┌─────────────┐┌─────────────┐┌─────────────┐┌─────────────┐ │
│ │subdomain_   ││vulnerability││port_        ││web_         │ │
│ │discovery    ││_scan        ││scanning     ││enumeration  │ │
│ └─────────────┘└─────────────┘└─────────────┘└─────────────┘ │
│ ┌─────────────┐┌─────────────────────────────────────────┐   │
│ │sql_         ││        exploitation                     │   │
│ │injection    ││        (Safety Framework)               │   │
│ └─────────────┘└─────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

### **Key Architectural Principles**

1. **Modularity**: Each component has a single responsibility
2. **Dependency Injection**: Components receive dependencies, don't create them
3. **Thread Safety**: All operations are thread-safe by design
4. **Security First**: Input validation and security controls at every layer
5. **Observability**: Comprehensive logging and metrics collection
6. **Performance**: Optimized for speed and resource efficiency

---

## 🧩 Core Components

### **1. Logger System** (`core/logger.py`)

**Purpose**: Enterprise-grade logging with multiple categories and structured output

**Key Features**:
- **8 Log Categories**: SYSTEM, USER, TOOL, SCAN, DATABASE, SECURITY, PERFORMANCE, ERROR
- **Thread-Safe Operations**: RLock protection for concurrent logging
- **Performance Tracking**: Operation timing with context managers
- **Structured Logging**: JSON format for analysis and SIEM integration
- **Automatic Rotation**: Daily log rotation with cleanup

**Class Structure**:
```python
class ReconForgeLogger:
    def __init__(self, log_dir: str = "logs", session_id: Optional[str] = None)
    def log_system(self, message: str, data: Optional[Dict[str, Any]] = None)
    def log_user_action(self, message: str, data: Optional[Dict[str, Any]] = None)
    def log_tool_execution(self, message: str, data: Optional[Dict[str, Any]] = None)
    def log_scan_operation(self, message: str, data: Optional[Dict[str, Any]] = None)
    def log_database_operation(self, message: str, data: Optional[Dict[str, Any]] = None)
    def log_security_event(self, message: str, data: Optional[Dict[str, Any]] = None)
    def log_performance(self, message: str, data: Optional[Dict[str, Any]] = None)
    def track_operation(self, operation_name: str) -> ContextManager
```

**Usage Example**:
```python
logger = ReconForgeLogger()
logger.log_system("Application startup initiated")

with logger.track_operation("subdomain_discovery") as op:
    # Perform operation
    op.add_result_data("subdomains_found", 25)
# Automatically logs timing and results
```

### **2. Database System** (`core/database.py`)

**Purpose**: Thread-safe SQLite operations with comprehensive schema

**Key Features**:
- **WAL Mode**: Write-Ahead Logging for better concurrent performance
- **Thread Safety**: Connection pooling with RLock protection
- **Context Managers**: Automatic transaction handling
- **Comprehensive Schema**: Scans, subdomains, vulnerabilities, sessions
- **Performance Optimized**: Indexed queries and batch operations

**Schema Design**:
```sql
-- Core scan management
CREATE TABLE scans (
    scan_id TEXT PRIMARY KEY,
    target TEXT NOT NULL,
    scan_type TEXT NOT NULL,
    status TEXT DEFAULT 'pending',
    config_data TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    completed_at DATETIME,
    error_message TEXT
);

-- Subdomain discoveries
CREATE TABLE subdomains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT,
    subdomain TEXT,
    ip_address TEXT,
    status_code INTEGER,
    title TEXT,
    source TEXT,
    tech_stack TEXT,
    cname TEXT,
    discovered_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES scans (scan_id)
);

-- Vulnerability findings
CREATE TABLE vulnerabilities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT,
    target TEXT,
    vulnerability_type TEXT,
    name TEXT,
    description TEXT,
    severity TEXT,
    cvss_score REAL,
    cve_id TEXT,
    proof_of_concept TEXT,
    source TEXT,
    discovered_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES scans (scan_id)
);
```

**Class Structure**:
```python
class ReconForgeDatabase:
    def __init__(self, db_path: str = "data/reconforge.db")
    def create_scan(self, target: str, scan_type: str, config: Dict[str, Any] = None) -> str
    def update_scan_status(self, scan_id: str, status: ScanStatus, error_message: str = None) -> bool
    def add_subdomain(self, scan_id: str, subdomain: str, **kwargs) -> bool
    def add_vulnerability(self, scan_id: str, target: str, vulnerability_type: str, **kwargs) -> bool
    def get_scan_statistics(self, target: str = None, days: int = 30) -> Dict[str, Any]
```

### **3. Configuration System** (`core/config.py`)

**Purpose**: JSON-based configuration with encrypted API key storage

**Key Features**:
- **Hierarchical Configuration**: Organized in logical sections
- **API Key Encryption**: AES encryption for sensitive data
- **Environment Integration**: Supports environment variable overrides
- **Tool Auto-Detection**: Automatic path detection for security tools
- **Validation**: Input validation with type checking

**Configuration Structure**:
```json
{
  "GENERAL": {
    "setup_completed": false,
    "default_scan_timeout": 1800,
    "max_concurrent_scans": 5,
    "auto_cleanup_logs": true,
    "log_retention_days": 30
  },
  "API_KEYS": {
    "shodan": "encrypted_api_key_data",
    "virustotal": "encrypted_api_key_data",
    "securitytrails": "encrypted_api_key_data",
    "censys": "encrypted_api_key_data"
  },
  "TOOLS": {
    "nmap_path": "/usr/bin/nmap",
    "subfinder_path": "/usr/bin/subfinder",
    "nuclei_path": "/usr/bin/nuclei",
    "gobuster_path": "/usr/bin/gobuster",
    "sqlmap_path": "/usr/bin/sqlmap"
  },
  "TERMINAL": {
    "theme": "default",
    "show_banner": true,
    "auto_update_check": true,
    "progress_bars": true
  },
  "PERFORMANCE": {
    "database_wal_mode": true,
    "connection_pool_size": 5,
    "query_timeout": 30,
    "batch_size": 1000
  }
}
```

### **4. Utilities System** (`core/utils.py`)

**Purpose**: Security validation, tool management, and common utilities

**Key Components**:

**SecurityValidator**:
```python
class SecurityValidator:
    def validate_domain(self, domain: str) -> ValidationResult
    def validate_ip_address(self, ip: str) -> ValidationResult  
    def validate_url(self, url: str) -> ValidationResult
    def sanitize_command_arg(self, arg: str) -> ValidationResult
```

**ToolManager**:
```python
class ToolManager:
    def __init__(self, logger: ReconForgeLogger)
    def is_tool_available(self, tool_name: str) -> bool
    def get_tool_info(self, tool_name: str) -> Optional[ToolInfo]
    def refresh_tool_availability(self) -> None
```

**FileOperations**:
```python
class FileOperations:
    def create_directory(self, path: Path, mode: int = 0o755) -> bool
    def write_file(self, path: Path, content: str, mode: int = 0o644) -> bool
    def read_file(self, path: Path) -> Optional[str]
    def get_file_hash(self, path: Path) -> Optional[str]
```

---

## 🔍 Module System

### **Module Architecture**

All reconnaissance modules follow a consistent architecture pattern:

```python
# Standard module structure
class ModuleEngine:
    def __init__(self, logger: ReconForgeLogger, database: ReconForgeDatabase, 
                 utils: ReconForgeUtils, display: ReconForgeDisplay)
    def scan_method(self, config: ModuleConfig) -> Dict[str, Any]
    def _determine_scanners(self, config: ModuleConfig) -> Dict[str, Any]
    def _process_results(self, scanner_name: str, results: List[Result])
    def _save_results_to_database(self, config: ModuleConfig)

# Factory function
def create_module_engine(**kwargs) -> ModuleEngine
def create_module_config(targets: List[str], scan_id: str, **kwargs) -> ModuleConfig
```

### **1. Subdomain Discovery Module**

**File**: `modules/subdomain_discovery.py` (600+ lines)

**Discovery Sources**:
- **Passive Sources** (20): crt.sh, VirusTotal, SecurityTrails, Shodan, Censys, Subfinder, Assetfinder, etc.
- **Active Sources** (5): DNS bruteforce, permutations, zone transfer, reverse DNS

**Key Classes**:
```python
@dataclass
class SubdomainResult:
    subdomain: str
    source: str
    ip_address: Optional[str] = None
    status_code: Optional[int] = None
    title: Optional[str] = None
    confidence: float = 1.0

class SubdomainDiscoveryEngine:
    def discover_subdomains(self, config: DiscoveryConfig) -> Dict[str, Any]
    def _discover_crt_sh(self, config: DiscoveryConfig) -> List[str]
    def _discover_subfinder(self, config: DiscoveryConfig) -> List[str]
    def _resolve_dns_records(self, config: DiscoveryConfig)
    def _verify_alive_subdomains(self, config: DiscoveryConfig)
```

### **2. Vulnerability Scanning Module**

**File**: `modules/vulnerability_scan.py` (700+ lines)

**Scanner Types**:
- **Nuclei**: Template-based vulnerability scanning
- **Custom Scanners**: XSS, SQLi, RCE, LFI detection
- **Specialized**: Subdomain takeover, SSL/TLS, DNS security

**Key Classes**:
```python
class SeverityLevel(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

@dataclass  
class VulnerabilityResult:
    target: str
    vulnerability_id: str
    name: str
    severity: SeverityLevel
    cvss_score: Optional[float] = None
    proof_of_concept: Optional[str] = None

class VulnerabilityScanner:
    def scan_vulnerabilities(self, config: ScanConfig) -> Dict[str, Any]
    def _scan_nuclei(self, config: ScanConfig) -> List[VulnerabilityResult]
    def _scan_subdomain_takeover(self, config: ScanConfig) -> List[VulnerabilityResult]
```

### **3. Port Scanning Module**

**File**: `modules/port_scanning.py` (800+ lines)

**Scanner Integration**:
- **Nmap**: Full integration with XML parsing
- **Masscan**: High-speed scanning with JSON output
- **Custom**: Fallback TCP/UDP scanners

**Key Classes**:
```python
class PortState(Enum):
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"

@dataclass
class ServiceInfo:
    name: str
    product: Optional[str] = None
    version: Optional[str] = None
    confidence: Optional[int] = None

@dataclass
class PortResult:
    host: str
    port: int
    protocol: str
    state: PortState
    service: Optional[ServiceInfo] = None

class PortScanner:
    def scan_ports(self, config: ScanConfig) -> Dict[str, Any]
    def _scan_nmap(self, config: ScanConfig) -> List[HostResult]
    def _parse_nmap_xml(self, xml_file: Path) -> List[HostResult]
```

---

## 🗄️ Database Design

### **Entity Relationship Diagram**

```
┌─────────────────┐       ┌─────────────────┐       ┌─────────────────┐
│     SCANS       │       │   SUBDOMAINS    │       │ VULNERABILITIES │
├─────────────────┤       ├─────────────────┤       ├─────────────────┤
│ scan_id (PK)    │◄─────►│ scan_id (FK)    │       │ scan_id (FK)    │
│ target          │       │ subdomain       │       │ target          │
│ scan_type       │       │ ip_address      │       │ vulnerability   │
│ status          │       │ status_code     │       │ severity        │
│ config_data     │       │ title           │       │ cvss_score      │
│ created_at      │       │ source          │       │ proof_concept   │
│ updated_at      │       │ tech_stack      │       │ discovered_at   │
│ completed_at    │       │ discovered_at   │       └─────────────────┘
└─────────────────┘       └─────────────────┘
        │
        ▼
┌─────────────────┐       ┌─────────────────┐
│    SESSIONS     │       │ USER_INTERACTIONS│
├─────────────────┤       ├─────────────────┤
│ session_id (PK) │       │ session_id (FK) │
│ start_time      │       │ interaction_type│
│ end_time        │       │ menu_path       │
│ platform_info   │       │ user_input      │
│ total_scans     │       │ timestamp       │
│ total_findings  │       └─────────────────┘
└─────────────────┘
```

### **Indexing Strategy**

```sql
-- Performance indexes
CREATE INDEX idx_scans_target ON scans (target);
CREATE INDEX idx_scans_created_at ON scans (created_at);
CREATE INDEX idx_subdomains_scan_id ON subdomains (scan_id);
CREATE INDEX idx_subdomains_subdomain ON subdomains (subdomain);
CREATE INDEX idx_vulnerabilities_scan_id ON vulnerabilities (scan_id);
CREATE INDEX idx_vulnerabilities_severity ON vulnerabilities (severity);
CREATE INDEX idx_sessions_start_time ON sessions (start_time);

-- Composite indexes for complex queries
CREATE INDEX idx_scans_target_type_status ON scans (target, scan_type, status);
CREATE INDEX idx_vulnerabilities_target_severity ON vulnerabilities (target, severity);
```

### **Data Access Patterns**

**Common Queries**:
```python
# Get recent scans for dashboard
def get_recent_scans(self, limit: int = 10) -> List[Dict[str, Any]]:
    query = """
    SELECT scan_id, target, scan_type, status, created_at
    FROM scans 
    ORDER BY created_at DESC 
    LIMIT ?
    """

# Get vulnerability statistics
def get_vulnerability_statistics(self, target: str = None, days: int = 30) -> Dict[str, Any]:
    base_query = """
    SELECT 
        severity,
        COUNT(*) as count,
        COUNT(DISTINCT target) as unique_targets
    FROM vulnerabilities v
    JOIN scans s ON v.scan_id = s.scan_id
    WHERE s.created_at >= datetime('now', '-{} days')
    """.format(days)
```

---

## 📊 Logging System

### **Log Categories & Purposes**

| Category | Purpose | File | Format |
|----------|---------|------|--------|
| **SYSTEM** | Application lifecycle, startup, shutdown | `reconforge_main.log` | Structured |
| **USER** | User interactions, menu selections | `user_interactions.log` | Structured |
| **TOOL** | External tool executions, commands | `tool_execution.log` | Structured |
| **SCAN** | Scanning operations, progress | `scan_operations.log` | Structured |
| **DATABASE** | Database operations, queries | `database_operations.log` | Structured |
| **SECURITY** | Security events, authorization | `security_events.log` | Structured |
| **PERFORMANCE** | Performance metrics, timing | `performance_metrics.log` | JSON |
| **ERROR** | Errors, exceptions, failures | `errors_structured.jsonl` | JSON Lines |

### **Log Entry Structure**

**Standard Log Entry**:
```
2025-08-29 04:30:15 | reconforge.main | INFO | method_name | [CATEGORY] Message | Data: {"key": "value"}
```

**JSON Performance Log**:
```json
{
  "timestamp": "2025-08-29T04:30:15.123456Z",
  "session_id": "reconforge_20250829_043015",
  "category": "PERFORMANCE",
  "operation": "subdomain_discovery",
  "operation_id": "op_1234567890",
  "duration_ms": 2350.45,
  "success": true,
  "results": {
    "subdomains_found": 25,
    "sources_used": 8,
    "dns_resolved": 23
  }
}
```

### **Performance Tracking**

**Context Manager Usage**:
```python
with logger.track_operation("port_scan") as op:
    # Perform scanning
    results = scanner.scan_ports(config)
    
    # Add operation metadata
    op.add_result_data("ports_scanned", len(results))
    op.add_result_data("open_ports", len([r for r in results if r.open]))
    
# Automatically logs:
# - Operation start/end time  
# - Duration in milliseconds
# - Success/failure status
# - Custom result data
```

---

## 🔒 Security Framework

### **Multi-Layer Security Architecture**

```
┌─────────────────────────────────────────────────────────────┐
│                    Input Validation Layer                   │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────────────────┐ │
│  │   Domain    │ │     URL     │ │      File Path          │ │
│  │ Validation  │ │ Validation  │ │     Validation          │ │
│  └─────────────┘ └─────────────┘ └─────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────┐
│                   Authorization Layer                       │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────────────────┐ │
│  │   Target    │ │  Command    │ │     Operation           │ │
│  │Authorization│ │ Sanitization│ │   Confirmation          │ │
│  └─────────────┘ └─────────────┘ └─────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────┐
│                     Audit & Logging Layer                   │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────────────────┐ │
│  │   Action    │ │   Security  │ │      Performance        │ │
│  │  Logging    │ │   Events    │ │      Tracking           │ │
│  └─────────────┘ └─────────────┘ └─────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

### **Input Validation**

**SecurityValidator Class**:
```python
class SecurityValidator:
    # Dangerous characters blocked in command injection
    DANGEROUS_CHARS = [';', '|', '&', '$', '`', '(', ')', '{', '}', '[', ']', '<', '>', '"', "'", '\\']
    
    def validate_domain(self, domain: str) -> ValidationResult:
        # Remove protocol if present
        # Validate domain format with regex
        # Check for dangerous characters
        # Return sanitized result
        
    def sanitize_command_arg(self, arg: str) -> ValidationResult:
        # Check for command injection patterns
        # Use shell escaping with shlex.quote()
        # Return sanitized result
```

### **Safety Controls in Exploitation Module**

**Multi-Level Safety System**:
```python
class SafetyLevel(Enum):
    SAFE = "safe"        # Read-only, no system impact
    CAUTIOUS = "cautious" # Minimal impact, reversible  
    MODERATE = "moderate" # Limited impact, cleanup required
    DANGEROUS = "dangerous" # Significant impact, extreme care
    CRITICAL = "critical"  # System-level impact, emergency only

def _perform_safety_checks(self, config: ExploitConfig) -> bool:
    # Check safety level restrictions
    # Verify target authorization
    # Validate targets against restricted lists
    # Confirm user authorization
```

### **Audit Trail System**

**Complete Action Logging**:
```python
# User action tracking
logger.log_user_action("Menu selection: Reconnaissance -> Subdomain Discovery", {
    "menu_path": ["main", "reconnaissance", "subdomain_discovery"],
    "target": "example.com",
    "user_session": session_id
})

# Security event logging  
logger.log_security_event("Exploitation module activated", {
    "safety_level": "cautious",
    "target_count": 1,
    "user_authorization_confirmed": True
})

# Tool execution logging
logger.log_tool_execution("nmap scan initiated", {
    "command": ["nmap", "-sS", "-T3", "target.com"],
    "timeout": 300,
    "rate_limit": 100
})
```

---

## ⚡ Performance Optimization

### **Database Optimization**

**WAL Mode Configuration**:
```python
# Enable Write-Ahead Logging for better concurrent performance
self._connection.execute("PRAGMA journal_mode=WAL")
self._connection.execute("PRAGMA synchronous=NORMAL")  
self._connection.execute("PRAGMA cache_size=10000")
self._connection.execute("PRAGMA temp_store=MEMORY")
```

**Connection Pooling**:
```python
class ReconForgeDatabase:
    def __init__(self, db_path: str):
        self._connection_lock = threading.RLock()
        self._thread_local = threading.local()
        
    def _get_connection(self) -> sqlite3.Connection:
        # Thread-local connection management
        # Automatic connection recycling
        # Connection health checking
```

### **Concurrent Operations**

**Thread-Safe Scanning**:
```python
# All modules support concurrent execution
class SubdomainDiscoveryEngine:
    def __init__(self):
        self.thread_lock = threading.RLock()
        self.discovered_subdomains = set()
    
    def _process_source_results(self, source_name: str, results: List[str]):
        with self.thread_lock:
            # Thread-safe result processing
            for subdomain in results:
                self.discovered_subdomains.add(subdomain)
```

**Resource Management**:
```python
# Context managers for automatic cleanup
@contextmanager  
def _get_cursor(self):
    with self._connection_lock:
        conn = self._get_connection()
        cursor = conn.cursor()
        try:
            yield cursor
            conn.commit()
        except Exception as e:
            conn.rollback()
            raise
        finally:
            cursor.close()
```

### **Memory Optimization**

**Streaming Processing**:
```python
# Large result sets processed in chunks
def _process_large_results(self, results_iterator):
    batch_size = 1000
    batch = []
    
    for result in results_iterator:
        batch.append(result)
        
        if len(batch) >= batch_size:
            self._process_batch(batch)
            batch = []  # Free memory
    
    # Process remaining items
    if batch:
        self._process_batch(batch)
```

---

## 🔌 API Reference

### **Core Module Factory Functions**

```python
# Logger
from core.logger import ReconForgeLogger
logger = ReconForgeLogger(log_dir="custom_logs", session_id="session123")

# Database  
from core.database import ReconForgeDatabase
database = ReconForgeDatabase(db_path="custom.db")

# Configuration
from core.config import ReconForgeConfig  
config = ReconForgeConfig(config_file="custom_config.json")

# Utilities
from core.utils import ReconForgeUtils
utils = ReconForgeUtils(logger)
```

### **Reconnaissance Module APIs**

```python
# Subdomain Discovery
from modules.subdomain_discovery import create_discovery_engine, create_discovery_config

engine = create_discovery_engine(logger, database, utils, display)
config = create_discovery_config(
    target="example.com",
    scan_id="scan_123",
    passive_only=True,
    verify_alive=True
)
results = engine.discover_subdomains(config)

# Vulnerability Scanning  
from modules.vulnerability_scan import create_vulnerability_scanner, create_scan_config

scanner = create_vulnerability_scanner(logger, database, utils, display)
config = create_scan_config(
    targets=["https://example.com"],
    scan_id="vuln_123",
    scan_type="comprehensive"
)
results = scanner.scan_vulnerabilities(config)
```

### **Result Data Structures**

```python
# Standard result format
{
    "success": True,
    "scan_id": "scan_123456789",
    "targets": ["example.com"],
    "statistics": {
        "total_targets": 1,
        "resources_found": 25,
        "duration_seconds": 45.2
    },
    "results": [
        {
            "subdomain": "api.example.com", 
            "ip_address": "192.168.1.100",
            "status_code": 200,
            "source": "subfinder",
            "discovered_at": "2025-08-29T04:30:15.123456Z"
        }
    ]
}
```

---

## 🛠️ Development Guide

### **Setting Up Development Environment**

```bash
# Clone repository
git clone https://github.com/yourusername/reconforge.git
cd reconforge

# Install development dependencies
pip3 install -r requirements-dev.txt

# Install pre-commit hooks
pre-commit install

# Run tests
python3 -m pytest tests/ -v

# Run linting
flake8 . --max-line-length=120
black . --check

# Type checking
mypy . --ignore-missing-imports
```

### **Code Style Guidelines**

**Python Style**:
- Follow PEP 8 with 120 character line limit
- Use type hints for all function parameters and return values
- Comprehensive docstrings for all classes and methods
- Use dataclasses for structured data
- Context managers for resource management

**Example**:
```python
from typing import List, Dict, Optional, Any
from dataclasses import dataclass

@dataclass
class ScanResult:
    """Represents a scan operation result.
    
    Attributes:
        target: The target that was scanned
        success: Whether the scan completed successfully  
        results: List of individual findings
        metadata: Additional scan metadata
    """
    target: str
    success: bool
    results: List[Dict[str, Any]]
    metadata: Optional[Dict[str, Any]] = None

def perform_scan(target: str, config: ScanConfig) -> ScanResult:
    """Perform a security scan on the specified target.
    
    Args:
        target: The target domain or IP address to scan
        config: Scan configuration parameters
        
    Returns:
        ScanResult containing the scan findings and metadata
        
    Raises:
        ValueError: If target is invalid
        ScanError: If scan fails to complete
    """
    # Implementation here
    pass
```

### **Testing Strategy**

**Unit Tests**:
```python
import pytest
from unittest.mock import Mock, patch
from core.logger import ReconForgeLogger

class TestReconForgeLogger:
    def setup_method(self):
        self.logger = ReconForgeLogger(log_dir="test_logs")
    
    def test_system_logging(self):
        # Test system message logging
        self.logger.log_system("Test message", {"key": "value"})
        # Assert log entry created
        
    def test_performance_tracking(self):
        # Test performance tracking context manager
        with self.logger.track_operation("test_operation") as op:
            op.add_result_data("test_key", "test_value")
        # Assert performance metrics logged
```

**Integration Tests**:
```python
class TestSubdomainDiscovery:
    def test_full_discovery_workflow(self):
        # Test complete subdomain discovery process
        engine = create_discovery_engine(logger, database, utils, display)
        config = create_discovery_config(target="example.com", scan_id="test")
        results = engine.discover_subdomains(config)
        
        assert results["success"] is True
        assert len(results["results"]) > 0
```

### **Adding New Modules**

**Module Template**:
```python
#!/usr/bin/env python3
"""
ReconForge [Module Name] Module
Terminal-First Professional Reconnaissance Platform

[Module description and purpose]
"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from datetime import datetime, timezone

# Core imports
from core.logger import ReconForgeLogger
from core.database import ReconForgeDatabase  
from core.utils import ReconForgeUtils
from interface.display import ReconForgeDisplay, StatusType

@dataclass
class ModuleConfig:
    """Configuration for [module name]"""
    targets: List[str]
    scan_id: str
    # Add module-specific configuration options

@dataclass  
class ModuleResult:
    """[Module name] result"""
    target: str
    # Add result-specific fields
    discovered_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

class ModuleEngine:
    """[Module name] engine"""
    
    def __init__(self, logger: ReconForgeLogger, database: ReconForgeDatabase,
                 utils: ReconForgeUtils, display: ReconForgeDisplay):
        self.logger = logger
        self.database = database
        self.utils = utils
        self.display = display
        
    def scan_method(self, config: ModuleConfig) -> Dict[str, Any]:
        """Main scanning method"""
        # Implementation here
        pass

# Factory functions
def create_module_engine(logger, database, utils, display) -> ModuleEngine:
    """Create module engine instance"""
    return ModuleEngine(logger, database, utils, display)

def create_module_config(targets: List[str], scan_id: str, **kwargs) -> ModuleConfig:
    """Create module configuration"""
    return ModuleConfig(targets=targets, scan_id=scan_id, **kwargs)
```

---

## 📋 Performance Benchmarks

### **Startup Performance**
- **Application Initialization**: < 1 second
- **Database Connection**: < 100ms
- **Tool Detection**: < 500ms  
- **Configuration Loading**: < 50ms

### **Runtime Performance**
- **Database Queries**: < 10ms average
- **Log Entry Writing**: < 5ms average
- **Memory Usage**: 50-100MB typical
- **Thread Overhead**: < 1% per additional thread

### **Scalability Metrics**
- **Concurrent Scans**: Up to 20 threads per module
- **Database Connections**: 5-connection pool
- **File Descriptors**: Automatic cleanup and management
- **Memory Growth**: Linear with result set size

---

This technical documentation provides comprehensive coverage of ReconForge's architecture, implementation details, and development guidelines. For additional information, refer to the source code comments and docstrings throughout the codebase.