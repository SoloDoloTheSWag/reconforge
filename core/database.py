#!/usr/bin/env python3
"""
ReconForge Terminal-First Professional Reconnaissance Platform
Database Operations Module

Built from scratch for the complete ReconForge rebuild.
Provides comprehensive SQLite database operations optimized for
terminal-based reconnaissance platform with full audit trails.

Features:
- Thread-safe SQLite operations with WAL mode for performance
- Complete scan lifecycle management (pending -> running -> completed/failed)
- Subdomain discovery results storage with metadata and validation
- Vulnerability tracking with severity classification and CVSS scoring
- Session management and user interaction tracking
- Performance metrics storage and analysis
- Comprehensive audit trails and data integrity
- Export capabilities for terminal-based reporting
- Automatic cleanup and database maintenance
"""

import sqlite3
import json
import os
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple, Union
from dataclasses import dataclass, asdict
from enum import Enum
import uuid
from contextlib import contextmanager

# Import our logging system
from .logger import get_logger, log_function_call, LogCategory


class ScanStatus(Enum):
    """Enumeration for scan status tracking"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class VulnerabilitySeverity(Enum):
    """Vulnerability severity classification"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class ScanRecord:
    """Data structure for scan records"""
    id: Optional[int] = None
    scan_id: Optional[str] = None
    target: Optional[str] = None
    scan_type: Optional[str] = None
    config: Optional[Dict[str, Any]] = None
    status: ScanStatus = ScanStatus.PENDING
    created_at: Optional[datetime] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    results_count: int = 0
    error_message: Optional[str] = None
    session_id: Optional[str] = None
    duration_ms: Optional[float] = None


@dataclass
class SubdomainRecord:
    """Data structure for subdomain discovery results"""
    id: Optional[int] = None
    scan_id: Optional[str] = None
    subdomain: Optional[str] = None
    ip_address: Optional[str] = None
    discovery_source: Optional[str] = None
    discovered_at: Optional[datetime] = None
    is_alive: Optional[bool] = None
    http_status: Optional[int] = None
    technologies: Optional[List[str]] = None
    confidence: Optional[float] = None
    response_time_ms: Optional[float] = None


@dataclass
class VulnerabilityRecord:
    """Data structure for vulnerability findings"""
    id: Optional[int] = None
    scan_id: Optional[str] = None
    target: Optional[str] = None
    vulnerability_type: Optional[str] = None
    severity: VulnerabilitySeverity = VulnerabilitySeverity.INFO
    title: Optional[str] = None
    description: Optional[str] = None
    scanner: Optional[str] = None
    discovered_at: Optional[datetime] = None
    cvss_score: Optional[float] = None
    cve_ids: Optional[List[str]] = None
    remediation: Optional[str] = None
    evidence: Optional[Dict[str, Any]] = None
    verified: bool = False


@dataclass
class SessionRecord:
    """Data structure for session tracking"""
    id: Optional[int] = None
    session_id: Optional[str] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    user_actions: int = 0
    scans_started: int = 0
    scans_completed: int = 0
    last_activity: Optional[datetime] = None
    platform_info: Optional[Dict[str, Any]] = None


class ReconForgeDatabase:
    """
    Professional SQLite database operations for terminal-first reconnaissance
    
    Provides thread-safe, high-performance database operations with comprehensive
    logging and audit trails for all reconnaissance activities.
    """
    
    def __init__(self, db_path: str = "data/reconforge.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Initialize logging
        self.logger = get_logger()
        
        # Thread safety
        self._connection_lock = threading.RLock()
        self._thread_local = threading.local()
        
        # Initialize database schema
        self._initialize_database()
        
        # Log database initialization
        self.logger.log_database_operation("ReconForge database initialized", {
            "database_path": str(self.db_path),
            "database_size_bytes": self.db_path.stat().st_size if self.db_path.exists() else 0,
            "wal_mode_enabled": True
        })
    
    def _get_connection(self) -> sqlite3.Connection:
        """Get thread-local database connection with optimized settings"""
        if not hasattr(self._thread_local, 'connection'):
            self._thread_local.connection = sqlite3.connect(
                str(self.db_path),
                timeout=30.0,
                check_same_thread=False
            )
            
            # Configure for performance and reliability
            conn = self._thread_local.connection
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("PRAGMA cache_size=10000")
            conn.execute("PRAGMA temp_store=MEMORY")
            conn.execute("PRAGMA foreign_keys=ON")
            
            # Row factory for dict-like access
            conn.row_factory = sqlite3.Row
        
        return self._thread_local.connection
    
    @contextmanager
    def _get_cursor(self):
        """Context manager for database operations with automatic transaction handling"""
        with self._connection_lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            try:
                yield cursor
                conn.commit()
            except Exception as e:
                conn.rollback()
                self.logger.log_error("Database transaction failed", e, {
                    "operation": "database_transaction"
                })
                raise
            finally:
                cursor.close()
    
    @log_function_call(LogCategory.DATABASE)
    def _initialize_database(self):
        """Initialize database schema with comprehensive tables"""
        
        schema_sql = """
        -- Scans table for tracking all reconnaissance operations
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT UNIQUE NOT NULL,
            target TEXT NOT NULL,
            scan_type TEXT NOT NULL,
            config TEXT,  -- JSON configuration
            status TEXT DEFAULT 'pending',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            started_at DATETIME,
            completed_at DATETIME,
            results_count INTEGER DEFAULT 0,
            error_message TEXT,
            session_id TEXT,
            duration_ms REAL
        );
        
        -- Subdomains table for discovery results
        CREATE TABLE IF NOT EXISTS subdomains (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT NOT NULL,
            subdomain TEXT NOT NULL,
            ip_address TEXT,
            discovery_source TEXT,
            discovered_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            is_alive BOOLEAN,
            http_status INTEGER,
            technologies TEXT,  -- JSON array
            confidence REAL,
            response_time_ms REAL,
            FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
        );
        
        -- Vulnerabilities table for security findings
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT NOT NULL,
            target TEXT NOT NULL,
            vulnerability_type TEXT,
            severity TEXT,
            title TEXT,
            description TEXT,
            scanner TEXT,
            discovered_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            cvss_score REAL,
            cve_ids TEXT,  -- JSON array
            remediation TEXT,
            evidence TEXT,  -- JSON object
            verified BOOLEAN DEFAULT 0,
            FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
        );
        
        -- Sessions table for user session tracking
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT UNIQUE NOT NULL,
            start_time DATETIME DEFAULT CURRENT_TIMESTAMP,
            end_time DATETIME,
            user_actions INTEGER DEFAULT 0,
            scans_started INTEGER DEFAULT 0,
            scans_completed INTEGER DEFAULT 0,
            last_activity DATETIME DEFAULT CURRENT_TIMESTAMP,
            platform_info TEXT  -- JSON object
        );
        
        -- User interactions table for detailed activity tracking
        CREATE TABLE IF NOT EXISTS user_interactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL,
            interaction_type TEXT NOT NULL,  -- menu_selection, input, command, etc.
            interaction_data TEXT,  -- JSON object with details
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
        );
        
        -- Performance metrics table for operation timing
        CREATE TABLE IF NOT EXISTS performance_metrics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            operation_type TEXT NOT NULL,
            operation_id TEXT,
            duration_ms REAL NOT NULL,
            success BOOLEAN NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            session_id TEXT,
            additional_data TEXT,  -- JSON object
            FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE SET NULL
        );
        
        -- Create indexes for optimal query performance
        CREATE INDEX IF NOT EXISTS idx_scans_scan_id ON scans(scan_id);
        CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target);
        CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
        CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at);
        CREATE INDEX IF NOT EXISTS idx_scans_session_id ON scans(session_id);
        
        CREATE INDEX IF NOT EXISTS idx_subdomains_scan_id ON subdomains(scan_id);
        CREATE INDEX IF NOT EXISTS idx_subdomains_subdomain ON subdomains(subdomain);
        CREATE INDEX IF NOT EXISTS idx_subdomains_source ON subdomains(discovery_source);
        
        CREATE INDEX IF NOT EXISTS idx_vulnerabilities_scan_id ON vulnerabilities(scan_id);
        CREATE INDEX IF NOT EXISTS idx_vulnerabilities_target ON vulnerabilities(target);
        CREATE INDEX IF NOT EXISTS idx_vulnerabilities_severity ON vulnerabilities(severity);
        CREATE INDEX IF NOT EXISTS idx_vulnerabilities_scanner ON vulnerabilities(scanner);
        
        CREATE INDEX IF NOT EXISTS idx_sessions_session_id ON sessions(session_id);
        CREATE INDEX IF NOT EXISTS idx_sessions_start_time ON sessions(start_time);
        
        CREATE INDEX IF NOT EXISTS idx_user_interactions_session_id ON user_interactions(session_id);
        CREATE INDEX IF NOT EXISTS idx_user_interactions_timestamp ON user_interactions(timestamp);
        
        CREATE INDEX IF NOT EXISTS idx_performance_metrics_session_id ON performance_metrics(session_id);
        CREATE INDEX IF NOT EXISTS idx_performance_metrics_timestamp ON performance_metrics(timestamp);
        CREATE INDEX IF NOT EXISTS idx_performance_metrics_operation_type ON performance_metrics(operation_type);
        """
        
        with self._get_cursor() as cursor:
            cursor.executescript(schema_sql)
    
    # Scan Management Methods
    
    @log_function_call(LogCategory.DATABASE)
    def create_scan(self, target: str, scan_type: str, config: Dict[str, Any] = None,
                   session_id: str = None) -> str:
        """Create new scan record and return scan_id"""
        scan_id = str(uuid.uuid4())
        
        with self._get_cursor() as cursor:
            cursor.execute("""
                INSERT INTO scans (scan_id, target, scan_type, config, session_id, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                scan_id, 
                target, 
                scan_type, 
                json.dumps(config or {}),
                session_id,
                datetime.now()
            ))
        
        self.logger.log_database_operation("Scan record created", {
            "scan_id": scan_id,
            "target": target,
            "scan_type": scan_type,
            "session_id": session_id
        })
        
        return scan_id
    
    @log_function_call(LogCategory.DATABASE)
    def update_scan_status(self, scan_id: str, status: ScanStatus, 
                          error_message: str = None, results_count: int = None):
        """Update scan status with timing information"""
        now = datetime.now()
        update_fields = ["status = ?", "last_activity = ?"]
        params = [status.value, now]
        
        # Add timing fields based on status
        if status == ScanStatus.RUNNING:
            update_fields.append("started_at = ?")
            params.append(now)
        elif status in [ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED]:
            update_fields.append("completed_at = ?")
            params.append(now)
            
            # Calculate duration if scan was started
            with self._get_cursor() as cursor:
                cursor.execute("SELECT started_at FROM scans WHERE scan_id = ?", (scan_id,))
                row = cursor.fetchone()
                if row and row['started_at']:
                    started = datetime.fromisoformat(row['started_at'])
                    duration_ms = (now - started).total_seconds() * 1000
                    update_fields.append("duration_ms = ?")
                    params.append(duration_ms)
        
        if error_message:
            update_fields.append("error_message = ?")
            params.append(error_message)
        
        if results_count is not None:
            update_fields.append("results_count = ?")
            params.append(results_count)
        
        params.append(scan_id)
        
        with self._get_cursor() as cursor:
            cursor.execute(f"""
                UPDATE scans SET {', '.join(update_fields)} WHERE scan_id = ?
            """, params)
        
        self.logger.log_database_operation("Scan status updated", {
            "scan_id": scan_id,
            "new_status": status.value,
            "error_message": error_message,
            "results_count": results_count
        })
    
    @log_function_call(LogCategory.DATABASE)
    def get_scan(self, scan_id: str) -> Optional[ScanRecord]:
        """Retrieve scan record by scan_id"""
        with self._get_cursor() as cursor:
            cursor.execute("SELECT * FROM scans WHERE scan_id = ?", (scan_id,))
            row = cursor.fetchone()
            
            if row:
                return self._row_to_scan_record(row)
        
        return None
    
    @log_function_call(LogCategory.DATABASE)
    def get_scans(self, target: str = None, scan_type: str = None, 
                 status: ScanStatus = None, session_id: str = None, 
                 limit: int = 100) -> List[ScanRecord]:
        """Get scans with optional filtering"""
        query = "SELECT * FROM scans WHERE 1=1"
        params = []
        
        if target:
            query += " AND target LIKE ?"
            params.append(f"%{target}%")
        
        if scan_type:
            query += " AND scan_type = ?"
            params.append(scan_type)
        
        if status:
            query += " AND status = ?"
            params.append(status.value)
        
        if session_id:
            query += " AND session_id = ?"
            params.append(session_id)
        
        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        
        with self._get_cursor() as cursor:
            cursor.execute(query, params)
            return [self._row_to_scan_record(row) for row in cursor.fetchall()]
    
    # Subdomain Management Methods
    
    @log_function_call(LogCategory.DATABASE)
    def add_subdomain(self, scan_id: str, subdomain: str, ip_address: str = None,
                     discovery_source: str = None, is_alive: bool = None,
                     http_status: int = None, technologies: List[str] = None,
                     confidence: float = None, response_time_ms: float = None):
        """Add discovered subdomain with metadata"""
        with self._get_cursor() as cursor:
            cursor.execute("""
                INSERT OR REPLACE INTO subdomains 
                (scan_id, subdomain, ip_address, discovery_source, is_alive, 
                 http_status, technologies, confidence, response_time_ms)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                scan_id, subdomain, ip_address, discovery_source, is_alive,
                http_status, json.dumps(technologies or []), confidence, response_time_ms
            ))
        
        self.logger.log_database_operation("Subdomain record added", {
            "scan_id": scan_id,
            "subdomain": subdomain,
            "source": discovery_source,
            "is_alive": is_alive
        })
    
    @log_function_call(LogCategory.DATABASE) 
    def get_subdomains(self, scan_id: str = None, target: str = None,
                      limit: int = 1000) -> List[SubdomainRecord]:
        """Get subdomain records with optional filtering"""
        if scan_id:
            query = "SELECT * FROM subdomains WHERE scan_id = ? ORDER BY discovered_at DESC LIMIT ?"
            params = [scan_id, limit]
        elif target:
            query = """
                SELECT s.* FROM subdomains s 
                JOIN scans sc ON s.scan_id = sc.scan_id 
                WHERE sc.target LIKE ? ORDER BY s.discovered_at DESC LIMIT ?
            """
            params = [f"%{target}%", limit]
        else:
            query = "SELECT * FROM subdomains ORDER BY discovered_at DESC LIMIT ?"
            params = [limit]
        
        with self._get_cursor() as cursor:
            cursor.execute(query, params)
            return [self._row_to_subdomain_record(row) for row in cursor.fetchall()]
    
    # Vulnerability Management Methods
    
    @log_function_call(LogCategory.DATABASE)
    def add_vulnerability(self, scan_id: str, target: str, vulnerability_type: str,
                         severity: VulnerabilitySeverity, title: str, 
                         description: str = None, scanner: str = None,
                         cvss_score: float = None, cve_ids: List[str] = None,
                         remediation: str = None, evidence: Dict[str, Any] = None,
                         verified: bool = False):
        """Add discovered vulnerability"""
        with self._get_cursor() as cursor:
            cursor.execute("""
                INSERT INTO vulnerabilities 
                (scan_id, target, vulnerability_type, severity, title, description,
                 scanner, cvss_score, cve_ids, remediation, evidence, verified)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                scan_id, target, vulnerability_type, severity.value, title, description,
                scanner, cvss_score, json.dumps(cve_ids or []), remediation,
                json.dumps(evidence or {}), verified
            ))
        
        self.logger.log_database_operation("Vulnerability record added", {
            "scan_id": scan_id,
            "target": target,
            "severity": severity.value,
            "vulnerability_type": vulnerability_type,
            "scanner": scanner
        })
    
    @log_function_call(LogCategory.DATABASE)
    def get_vulnerabilities(self, scan_id: str = None, target: str = None,
                           severity: VulnerabilitySeverity = None,
                           limit: int = 1000) -> List[VulnerabilityRecord]:
        """Get vulnerability records with optional filtering"""
        query = "SELECT * FROM vulnerabilities WHERE 1=1"
        params = []
        
        if scan_id:
            query += " AND scan_id = ?"
            params.append(scan_id)
        
        if target:
            query += " AND target LIKE ?"
            params.append(f"%{target}%")
        
        if severity:
            query += " AND severity = ?"
            params.append(severity.value)
        
        query += " ORDER BY discovered_at DESC LIMIT ?"
        params.append(limit)
        
        with self._get_cursor() as cursor:
            cursor.execute(query, params)
            return [self._row_to_vulnerability_record(row) for row in cursor.fetchall()]
    
    # Session Management Methods
    
    @log_function_call(LogCategory.DATABASE)
    def create_session(self, session_id: str, platform_info: Dict[str, Any] = None) -> bool:
        """Create new user session record"""
        try:
            with self._get_cursor() as cursor:
                cursor.execute("""
                    INSERT INTO sessions (session_id, start_time, platform_info)
                    VALUES (?, ?, ?)
                """, (session_id, datetime.now(), json.dumps(platform_info or {})))
            
            self.logger.log_database_operation("Session created", {
                "session_id": session_id,
                "platform_info": platform_info
            })
            return True
            
        except sqlite3.IntegrityError:
            return False  # Session already exists
    
    @log_function_call(LogCategory.DATABASE)
    def update_session_activity(self, session_id: str, action_type: str = None):
        """Update session activity and increment counters"""
        updates = ["last_activity = ?", "user_actions = user_actions + 1"]
        params = [datetime.now()]
        
        if action_type == "scan_started":
            updates.append("scans_started = scans_started + 1")
        elif action_type == "scan_completed":
            updates.append("scans_completed = scans_completed + 1")
        
        params.append(session_id)
        
        with self._get_cursor() as cursor:
            cursor.execute(f"""
                UPDATE sessions SET {', '.join(updates)} WHERE session_id = ?
            """, params)
    
    @log_function_call(LogCategory.DATABASE)
    def end_session(self, session_id: str):
        """End user session"""
        with self._get_cursor() as cursor:
            cursor.execute("""
                UPDATE sessions SET end_time = ? WHERE session_id = ?
            """, (datetime.now(), session_id))
        
        self.logger.log_database_operation("Session ended", {"session_id": session_id})
    
    # User Interaction Tracking
    
    @log_function_call(LogCategory.DATABASE)
    def log_user_interaction(self, session_id: str, interaction_type: str, 
                            interaction_data: Dict[str, Any]):
        """Log detailed user interaction for analytics"""
        with self._get_cursor() as cursor:
            cursor.execute("""
                INSERT INTO user_interactions (session_id, interaction_type, interaction_data)
                VALUES (?, ?, ?)
            """, (session_id, interaction_type, json.dumps(interaction_data)))
    
    # Performance Metrics
    
    @log_function_call(LogCategory.DATABASE)
    def log_performance_metric(self, operation_type: str, operation_id: str,
                              duration_ms: float, success: bool, 
                              session_id: str = None,
                              additional_data: Dict[str, Any] = None):
        """Log performance metrics for analysis"""
        with self._get_cursor() as cursor:
            cursor.execute("""
                INSERT INTO performance_metrics 
                (operation_type, operation_id, duration_ms, success, session_id, additional_data)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (operation_type, operation_id, duration_ms, success, session_id,
                 json.dumps(additional_data or {})))
    
    # Statistics and Analysis Methods
    
    @log_function_call(LogCategory.DATABASE)
    def get_scan_statistics(self, target: str = None, days: int = 30) -> Dict[str, Any]:
        """Get comprehensive scan statistics"""
        cutoff_date = datetime.now() - timedelta(days=days)
        base_conditions = "WHERE created_at >= ?"
        params = [cutoff_date]
        
        if target:
            base_conditions += " AND target LIKE ?"
            params.append(f"%{target}%")
        
        with self._get_cursor() as cursor:
            # Total scans
            cursor.execute(f"SELECT COUNT(*) FROM scans {base_conditions}", params)
            total_scans = cursor.fetchone()[0]
            
            # Scans by status
            cursor.execute(f"SELECT status, COUNT(*) FROM scans {base_conditions} GROUP BY status", params)
            status_counts = {row[0]: row[1] for row in cursor.fetchall()}
            
            # Scans by type
            cursor.execute(f"SELECT scan_type, COUNT(*) FROM scans {base_conditions} GROUP BY scan_type", params)
            type_counts = {row[0]: row[1] for row in cursor.fetchall()}
            
            # Recent activity (last 24 hours)
            recent_cutoff = datetime.now() - timedelta(hours=24)
            recent_params = params + [recent_cutoff]
            cursor.execute(f"SELECT COUNT(*) FROM scans {base_conditions} AND created_at >= ?", recent_params)
            last_24h = cursor.fetchone()[0]
        
        return {
            "total_scans": total_scans,
            "status_counts": status_counts,
            "type_counts": type_counts,
            "last_24h": last_24h,
            "period_days": days
        }
    
    @log_function_call(LogCategory.DATABASE)
    def get_vulnerability_statistics(self, target: str = None, days: int = 30) -> Dict[str, Any]:
        """Get comprehensive vulnerability statistics"""
        cutoff_date = datetime.now() - timedelta(days=days)
        base_conditions = "WHERE discovered_at >= ?"
        params = [cutoff_date]
        
        if target:
            base_conditions += " AND target LIKE ?"
            params.append(f"%{target}%")
        
        with self._get_cursor() as cursor:
            # Total vulnerabilities
            cursor.execute(f"SELECT COUNT(*) FROM vulnerabilities {base_conditions}", params)
            total_vulns = cursor.fetchone()[0]
            
            # By severity
            cursor.execute(f"SELECT severity, COUNT(*) FROM vulnerabilities {base_conditions} GROUP BY severity", params)
            severity_counts = {row[0]: row[1] for row in cursor.fetchall()}
            
            # By scanner
            cursor.execute(f"SELECT scanner, COUNT(*) FROM vulnerabilities {base_conditions} GROUP BY scanner", params)
            scanner_counts = {row[0]: row[1] for row in cursor.fetchall()}
            
            # By vulnerability type
            cursor.execute(f"SELECT vulnerability_type, COUNT(*) FROM vulnerabilities {base_conditions} GROUP BY vulnerability_type", params)
            type_counts = {row[0]: row[1] for row in cursor.fetchall()}
        
        return {
            "total_vulnerabilities": total_vulns,
            "severity_counts": severity_counts,
            "scanner_counts": scanner_counts,
            "type_counts": type_counts,
            "period_days": days
        }
    
    # Data Export Methods
    
    @log_function_call(LogCategory.DATABASE)
    def export_scan_data(self, scan_id: str) -> Dict[str, Any]:
        """Export complete scan data for reporting"""
        scan = self.get_scan(scan_id)
        if not scan:
            return {}
        
        subdomains = self.get_subdomains(scan_id=scan_id)
        vulnerabilities = self.get_vulnerabilities(scan_id=scan_id)
        
        return {
            "scan": asdict(scan),
            "subdomains": [asdict(sub) for sub in subdomains],
            "vulnerabilities": [asdict(vuln) for vuln in vulnerabilities],
            "export_timestamp": datetime.now().isoformat(),
            "summary": {
                "total_subdomains": len(subdomains),
                "total_vulnerabilities": len(vulnerabilities),
                "vulnerability_breakdown": self._count_by_severity(vulnerabilities)
            }
        }
    
    def _count_by_severity(self, vulnerabilities: List[VulnerabilityRecord]) -> Dict[str, int]:
        """Count vulnerabilities by severity"""
        counts = {}
        for vuln in vulnerabilities:
            severity = vuln.severity.value
            counts[severity] = counts.get(severity, 0) + 1
        return counts
    
    # Helper Methods for Data Conversion
    
    def _row_to_scan_record(self, row) -> ScanRecord:
        """Convert database row to ScanRecord"""
        return ScanRecord(
            id=row['id'],
            scan_id=row['scan_id'],
            target=row['target'],
            scan_type=row['scan_type'],
            config=json.loads(row['config']) if row['config'] else {},
            status=ScanStatus(row['status']),
            created_at=datetime.fromisoformat(row['created_at']) if row['created_at'] else None,
            started_at=datetime.fromisoformat(row['started_at']) if row['started_at'] else None,
            completed_at=datetime.fromisoformat(row['completed_at']) if row['completed_at'] else None,
            results_count=row['results_count'],
            error_message=row['error_message'],
            session_id=row['session_id'],
            duration_ms=row['duration_ms']
        )
    
    def _row_to_subdomain_record(self, row) -> SubdomainRecord:
        """Convert database row to SubdomainRecord"""
        return SubdomainRecord(
            id=row['id'],
            scan_id=row['scan_id'],
            subdomain=row['subdomain'],
            ip_address=row['ip_address'],
            discovery_source=row['discovery_source'],
            discovered_at=datetime.fromisoformat(row['discovered_at']) if row['discovered_at'] else None,
            is_alive=row['is_alive'],
            http_status=row['http_status'],
            technologies=json.loads(row['technologies']) if row['technologies'] else [],
            confidence=row['confidence'],
            response_time_ms=row['response_time_ms']
        )
    
    def _row_to_vulnerability_record(self, row) -> VulnerabilityRecord:
        """Convert database row to VulnerabilityRecord"""
        return VulnerabilityRecord(
            id=row['id'],
            scan_id=row['scan_id'],
            target=row['target'],
            vulnerability_type=row['vulnerability_type'],
            severity=VulnerabilitySeverity(row['severity']),
            title=row['title'],
            description=row['description'],
            scanner=row['scanner'],
            discovered_at=datetime.fromisoformat(row['discovered_at']) if row['discovered_at'] else None,
            cvss_score=row['cvss_score'],
            cve_ids=json.loads(row['cve_ids']) if row['cve_ids'] else [],
            remediation=row['remediation'],
            evidence=json.loads(row['evidence']) if row['evidence'] else {},
            verified=bool(row['verified'])
        )
    
    # Database Maintenance Methods
    
    @log_function_call(LogCategory.DATABASE)
    def optimize_database(self):
        """Optimize database performance"""
        with self._get_cursor() as cursor:
            cursor.execute("VACUUM")
            cursor.execute("ANALYZE")
        
        self.logger.log_database_operation("Database optimized")
    
    @log_function_call(LogCategory.DATABASE)
    def cleanup_old_data(self, days_to_keep: int = 90):
        """Clean up old scan data beyond retention period"""
        cutoff_date = datetime.now() - timedelta(days=days_to_keep)
        
        with self._get_cursor() as cursor:
            # Delete old scans (CASCADE will handle related data)
            cursor.execute("DELETE FROM scans WHERE created_at < ?", (cutoff_date,))
            deleted_scans = cursor.rowcount
            
            # Delete old sessions
            cursor.execute("DELETE FROM sessions WHERE start_time < ?", (cutoff_date,))
            deleted_sessions = cursor.rowcount
            
            # Delete old performance metrics
            cursor.execute("DELETE FROM performance_metrics WHERE timestamp < ?", (cutoff_date,))
            deleted_metrics = cursor.rowcount
        
        self.logger.log_database_operation("Old data cleaned up", {
            "cutoff_date": cutoff_date.isoformat(),
            "deleted_scans": deleted_scans,
            "deleted_sessions": deleted_sessions,
            "deleted_metrics": deleted_metrics
        })
    
    def close(self):
        """Close database connections"""
        if hasattr(self._thread_local, 'connection'):
            self._thread_local.connection.close()
        
        self.logger.log_database_operation("Database connections closed")


# Global database instance
_global_database: Optional[ReconForgeDatabase] = None


def initialize_database(db_path: str = "data/reconforge.db") -> ReconForgeDatabase:
    """Initialize the global database instance"""
    global _global_database
    _global_database = ReconForgeDatabase(db_path)
    return _global_database


def get_database() -> ReconForgeDatabase:
    """Get the global database instance"""
    global _global_database
    if _global_database is None:
        _global_database = ReconForgeDatabase()
    return _global_database


if __name__ == "__main__":
    # Test the database system
    print("Testing ReconForge database system...")
    
    # Initialize database
    db = initialize_database()
    
    # Test scan creation
    scan_id = db.create_scan("example.com", "subdomain_discovery", 
                            {"sources": ["subfinder", "amass"]})
    print(f"Created test scan: {scan_id}")
    
    # Test subdomain addition
    db.add_subdomain(scan_id, "www.example.com", "93.184.216.34", "subfinder", 
                    is_alive=True, http_status=200)
    db.add_subdomain(scan_id, "mail.example.com", "93.184.216.35", "amass",
                    is_alive=True, http_status=200)
    
    # Test vulnerability addition
    db.add_vulnerability(scan_id, "www.example.com", "xss", 
                        VulnerabilitySeverity.HIGH, "Cross-Site Scripting",
                        "Reflected XSS found in search parameter", "nuclei")
    
    # Update scan completion
    db.update_scan_status(scan_id, ScanStatus.COMPLETED, results_count=3)
    
    # Test statistics
    stats = db.get_scan_statistics()
    print(f"Database statistics: {stats}")
    
    # Test data export
    export_data = db.export_scan_data(scan_id)
    print(f"Export data keys: {list(export_data.keys())}")
    
    print("✅ Database system test completed successfully")
    
    # Close database
    db.close()