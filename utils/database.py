import sqlite3
import json
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional, Any
import logging

logger = logging.getLogger(__name__)

class ReconForgeDB:
    """SQLite database manager for ReconForge"""
    
    def __init__(self, db_path: str = "data/reconforge.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.init_database()
    
    def get_connection(self):
        """Get database connection with proper configuration"""
        conn = sqlite3.connect(str(self.db_path), timeout=30.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA temp_store=MEMORY")
        conn.execute("PRAGMA mmap_size=268435456")  # 256MB
        return conn
    
    def init_database(self):
        """Initialize database with all required tables"""
        with self.get_connection() as conn:
            # Scans table - main scan tracking
            conn.execute('''
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT NOT NULL,
                    scan_type TEXT NOT NULL,
                    status TEXT DEFAULT 'running',
                    start_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    end_time TIMESTAMP,
                    duration INTEGER,
                    total_subdomains INTEGER DEFAULT 0,
                    total_vulns INTEGER DEFAULT 0,
                    total_services INTEGER DEFAULT 0,
                    config TEXT,
                    notes TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Subdomains table - discovered subdomains
            conn.execute('''
                CREATE TABLE IF NOT EXISTS subdomains (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER NOT NULL,
                    subdomain TEXT NOT NULL,
                    ip_address TEXT,
                    status_code INTEGER,
                    title TEXT,
                    server TEXT,
                    technology_stack TEXT,
                    ssl_info TEXT,
                    discovery_source TEXT,
                    screenshot_path TEXT,
                    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE,
                    UNIQUE(scan_id, subdomain)
                )
            ''')
            
            # Vulnerabilities table - discovered vulnerabilities
            conn.execute('''
                CREATE TABLE IF NOT EXISTS vulnerabilities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER NOT NULL,
                    subdomain TEXT,
                    vulnerability_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT,
                    url TEXT,
                    method TEXT,
                    payload TEXT,
                    response TEXT,
                    template_id TEXT,
                    cvss_score REAL,
                    cve_id TEXT,
                    reference_urls TEXT,
                    verified BOOLEAN DEFAULT FALSE,
                    false_positive BOOLEAN DEFAULT FALSE,
                    exploitation_data TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE
                )
            ''')
            
            # Services table - discovered services and ports
            conn.execute('''
                CREATE TABLE IF NOT EXISTS services (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER NOT NULL,
                    subdomain TEXT NOT NULL,
                    port INTEGER NOT NULL,
                    protocol TEXT DEFAULT 'tcp',
                    service_name TEXT,
                    service_version TEXT,
                    banner TEXT,
                    state TEXT DEFAULT 'open',
                    fingerprint TEXT,
                    ssl_enabled BOOLEAN DEFAULT FALSE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE,
                    UNIQUE(scan_id, subdomain, port, protocol)
                )
            ''')
            
            # Pentests table - penetration testing activities
            conn.execute('''
                CREATE TABLE IF NOT EXISTS pentests (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER NOT NULL,
                    target TEXT NOT NULL,
                    test_type TEXT NOT NULL,
                    command TEXT,
                    output TEXT,
                    success BOOLEAN DEFAULT FALSE,
                    severity TEXT,
                    impact TEXT,
                    recommendations TEXT,
                    artifacts TEXT,
                    start_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    end_time TIMESTAMP,
                    duration INTEGER,
                    FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE
                )
            ''')
            
            # Exports table - track report exports
            conn.execute('''
                CREATE TABLE IF NOT EXISTS exports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER NOT NULL,
                    export_type TEXT NOT NULL,
                    file_path TEXT NOT NULL,
                    file_size INTEGER,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE
                )
            ''')
            
            # API Keys table - store encrypted API keys
            conn.execute('''
                CREATE TABLE IF NOT EXISTS api_keys (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    service_name TEXT UNIQUE NOT NULL,
                    api_key TEXT NOT NULL,
                    encrypted BOOLEAN DEFAULT TRUE,
                    active BOOLEAN DEFAULT TRUE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Create indexes for better performance
            indexes = [
                "CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target)",
                "CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status)",
                "CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created_at)",
                "CREATE INDEX IF NOT EXISTS idx_subdomains_scan_id ON subdomains(scan_id)",
                "CREATE INDEX IF NOT EXISTS idx_subdomains_subdomain ON subdomains(subdomain)",
                "CREATE INDEX IF NOT EXISTS idx_vulns_scan_id ON vulnerabilities(scan_id)",
                "CREATE INDEX IF NOT EXISTS idx_vulns_severity ON vulnerabilities(severity)",
                "CREATE INDEX IF NOT EXISTS idx_vulns_type ON vulnerabilities(vulnerability_type)",
                "CREATE INDEX IF NOT EXISTS idx_services_scan_id ON services(scan_id)",
                "CREATE INDEX IF NOT EXISTS idx_pentests_scan_id ON pentests(scan_id)"
            ]
            
            for index in indexes:
                conn.execute(index)
            
            conn.commit()
    
    # Scan management methods
    def create_scan(self, target: str, scan_type: str, config: Dict = None) -> int:
        """Create a new scan entry"""
        with self.get_connection() as conn:
            cursor = conn.execute('''
                INSERT INTO scans (target, scan_type, config)
                VALUES (?, ?, ?)
            ''', (target, scan_type, json.dumps(config) if config else None))
            return cursor.lastrowid
    
    def update_scan_status(self, scan_id: int, status: str, **kwargs):
        """Update scan status and optional fields"""
        fields = []
        values = []
        
        if status:
            fields.append("status = ?")
            values.append(status)
        
        if status in ['completed', 'failed']:
            fields.append("end_time = ?")
            values.append(datetime.now())
        
        for field, value in kwargs.items():
            if field in ['total_subdomains', 'total_vulns', 'total_services', 'duration', 'notes']:
                fields.append(f"{field} = ?")
                values.append(value)
        
        if fields:
            values.append(scan_id)
            with self.get_connection() as conn:
                conn.execute(f'''
                    UPDATE scans SET {', '.join(fields)} WHERE id = ?
                ''', values)
    
    def get_scan(self, scan_id: int) -> Optional[Dict]:
        """Get scan details by ID"""
        with self.get_connection() as conn:
            row = conn.execute('SELECT * FROM scans WHERE id = ?', (scan_id,)).fetchone()
            return dict(row) if row else None
    
    def get_scans(self, target: str = None, status: str = None, limit: int = 50) -> List[Dict]:
        """Get list of scans with optional filtering"""
        query = "SELECT * FROM scans"
        params = []
        conditions = []
        
        if target:
            conditions.append("target LIKE ?")
            params.append(f"%{target}%")
        
        if status:
            conditions.append("status = ?")
            params.append(status)
        
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
        
        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        
        with self.get_connection() as conn:
            rows = conn.execute(query, params).fetchall()
            return [dict(row) for row in rows]
    
    # Subdomain management methods
    def add_subdomain(self, scan_id: int, subdomain: str, **kwargs):
        """Add or update subdomain information"""
        fields = ['scan_id', 'subdomain']
        values = [scan_id, subdomain]
        placeholders = ['?', '?']
        
        update_fields = []
        for field, value in kwargs.items():
            if field in ['ip_address', 'status_code', 'title', 'server', 'technology_stack', 
                        'ssl_info', 'discovery_source', 'screenshot_path']:
                fields.append(field)
                values.append(value)
                placeholders.append('?')
                update_fields.append(f"{field} = excluded.{field}")
        
        update_fields.append("last_seen = CURRENT_TIMESTAMP")
        
        with self.get_connection() as conn:
            conn.execute(f'''
                INSERT INTO subdomains ({', '.join(fields)})
                VALUES ({', '.join(placeholders)})
                ON CONFLICT(scan_id, subdomain) DO UPDATE SET
                {', '.join(update_fields)}
            ''', values)
    
    def get_subdomains(self, scan_id: int) -> List[Dict]:
        """Get all subdomains for a scan"""
        with self.get_connection() as conn:
            rows = conn.execute('''
                SELECT * FROM subdomains WHERE scan_id = ? ORDER BY subdomain
            ''', (scan_id,)).fetchall()
            return [dict(row) for row in rows]
    
    # Vulnerability management methods
    def add_vulnerability(self, scan_id: int, vuln_data: Dict):
        """Add vulnerability finding"""
        fields = ['scan_id']
        values = [scan_id]
        placeholders = ['?']
        
        for field in ['subdomain', 'vulnerability_type', 'severity', 'title', 'description',
                     'url', 'method', 'payload', 'response', 'template_id', 'cvss_score',
                     'cve_id', 'reference_urls']:
            if field in vuln_data:
                fields.append(field)
                if field == 'reference_urls' and isinstance(vuln_data[field], list):
                    values.append(json.dumps(vuln_data[field]))
                else:
                    values.append(vuln_data[field])
                placeholders.append('?')
        
        with self.get_connection() as conn:
            cursor = conn.execute(f'''
                INSERT INTO vulnerabilities ({', '.join(fields)})
                VALUES ({', '.join(placeholders)})
            ''', values)
            return cursor.lastrowid
    
    def get_vulnerabilities(self, scan_id: int, severity: str = None) -> List[Dict]:
        """Get vulnerabilities for a scan"""
        query = "SELECT * FROM vulnerabilities WHERE scan_id = ?"
        params = [scan_id]
        
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        
        query += " ORDER BY CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END"
        
        with self.get_connection() as conn:
            rows = conn.execute(query, params).fetchall()
            return [dict(row) for row in rows]
    
    # Service management methods
    def add_service(self, scan_id: int, subdomain: str, port: int, **kwargs):
        """Add or update service information"""
        fields = ['scan_id', 'subdomain', 'port']
        values = [scan_id, subdomain, port]
        placeholders = ['?', '?', '?']
        
        update_fields = []
        for field, value in kwargs.items():
            if field in ['protocol', 'service_name', 'service_version', 'banner', 
                        'state', 'fingerprint', 'ssl_enabled']:
                fields.append(field)
                values.append(value)
                placeholders.append('?')
                update_fields.append(f"{field} = excluded.{field}")
        
        with self.get_connection() as conn:
            conn.execute(f'''
                INSERT INTO services ({', '.join(fields)})
                VALUES ({', '.join(placeholders)})
                ON CONFLICT(scan_id, subdomain, port, protocol) DO UPDATE SET
                {', '.join(update_fields) if update_fields else 'created_at = created_at'}
            ''', values)
    
    def get_services(self, scan_id: int) -> List[Dict]:
        """Get all services for a scan"""
        with self.get_connection() as conn:
            rows = conn.execute('''
                SELECT * FROM services WHERE scan_id = ? ORDER BY subdomain, port
            ''', (scan_id,)).fetchall()
            return [dict(row) for row in rows]
    
    # Pentest management methods
    def add_pentest_result(self, scan_id: int, test_data: Dict) -> int:
        """Add penetration test result"""
        fields = ['scan_id']
        values = [scan_id]
        placeholders = ['?']
        
        for field in ['target', 'test_type', 'command', 'output', 'success', 
                     'severity', 'impact', 'recommendations', 'artifacts']:
            if field in test_data:
                fields.append(field)
                if field == 'artifacts' and isinstance(test_data[field], (dict, list)):
                    values.append(json.dumps(test_data[field]))
                else:
                    values.append(test_data[field])
                placeholders.append('?')
        
        with self.get_connection() as conn:
            cursor = conn.execute(f'''
                INSERT INTO pentests ({', '.join(fields)})
                VALUES ({', '.join(placeholders)})
            ''', values)
            return cursor.lastrowid
    
    def get_pentest_results(self, scan_id: int) -> List[Dict]:
        """Get penetration test results for a scan"""
        with self.get_connection() as conn:
            rows = conn.execute('''
                SELECT * FROM pentests WHERE scan_id = ? ORDER BY start_time DESC
            ''', (scan_id,)).fetchall()
            return [dict(row) for row in rows]
    
    # Statistics methods
    def get_scan_stats(self, scan_id: int) -> Dict:
        """Get comprehensive scan statistics"""
        with self.get_connection() as conn:
            # Basic counts
            subdomains_count = conn.execute(
                'SELECT COUNT(*) as count FROM subdomains WHERE scan_id = ?', 
                (scan_id,)
            ).fetchone()['count']
            
            vulns_count = conn.execute(
                'SELECT COUNT(*) as count FROM vulnerabilities WHERE scan_id = ?', 
                (scan_id,)
            ).fetchone()['count']
            
            services_count = conn.execute(
                'SELECT COUNT(*) as count FROM services WHERE scan_id = ?', 
                (scan_id,)
            ).fetchone()['count']
            
            # Vulnerability breakdown by severity
            vuln_breakdown = conn.execute('''
                SELECT severity, COUNT(*) as count 
                FROM vulnerabilities 
                WHERE scan_id = ? 
                GROUP BY severity
            ''', (scan_id,)).fetchall()
            
            vuln_by_severity = {row['severity']: row['count'] for row in vuln_breakdown}
            
            # Top ports
            top_ports = conn.execute('''
                SELECT port, COUNT(*) as count 
                FROM services 
                WHERE scan_id = ? 
                GROUP BY port 
                ORDER BY count DESC 
                LIMIT 10
            ''', (scan_id,)).fetchall()
            
            return {
                'total_subdomains': subdomains_count,
                'total_vulnerabilities': vulns_count,
                'total_services': services_count,
                'vulnerabilities_by_severity': vuln_by_severity,
                'top_ports': [dict(row) for row in top_ports]
            }
    
    # Export tracking
    def add_export_record(self, scan_id: int, export_type: str, file_path: str, file_size: int = None):
        """Record export activity"""
        with self.get_connection() as conn:
            conn.execute('''
                INSERT INTO exports (scan_id, export_type, file_path, file_size)
                VALUES (?, ?, ?, ?)
            ''', (scan_id, export_type, file_path, file_size))
    
    def delete_scan(self, scan_id: int):
        """Delete a scan and all associated data"""
        with self.get_connection() as conn:
            # Delete associated data first
            conn.execute('DELETE FROM vulnerabilities WHERE scan_id = ?', (scan_id,))
            conn.execute('DELETE FROM subdomains WHERE scan_id = ?', (scan_id,))
            conn.execute('DELETE FROM services WHERE scan_id = ?', (scan_id,))
            conn.execute('DELETE FROM pentest_results WHERE scan_id = ?', (scan_id,))
            conn.execute('DELETE FROM exports WHERE scan_id = ?', (scan_id,))
            # Delete the scan itself
            conn.execute('DELETE FROM scans WHERE id = ?', (scan_id,))
    
    def cleanup_old_scans(self, days_old: int = 30):
        """Clean up old scan data"""
        with self.get_connection() as conn:
            conn.execute('''
                DELETE FROM scans 
                WHERE created_at < datetime('now', '-{} days')
            '''.format(days_old))
            conn.execute('VACUUM')