"""
Advanced Analytics and Reporting Module for ReconForge
Provides comprehensive analytics, trending, and executive reporting capabilities
"""

import sqlite3
import json
import statistics
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path
from dataclasses import dataclass
import pandas as pd
import numpy as np
from collections import defaultdict, Counter

from .database import ReconForgeDB
from .logging import main_logger

@dataclass
class MetricTrend:
    """Represents a metric with trend analysis"""
    current_value: float
    previous_value: float
    change_percent: float
    change_type: str  # 'positive', 'negative', 'stable'
    trend_direction: str  # 'up', 'down', 'stable'

@dataclass
class VulnerabilityTrend:
    """Vulnerability trend data over time"""
    timestamp: datetime
    critical: int
    high: int
    medium: int
    low: int
    info: int

@dataclass
class ScanMetrics:
    """Comprehensive scan metrics"""
    total_scans: int
    completed_scans: int
    failed_scans: int
    avg_scan_duration: float
    total_targets: int
    unique_domains: int

@dataclass
class ComplianceScore:
    """Security compliance scoring"""
    framework: str
    current_score: float
    target_score: float
    gap: float
    recommendations: List[str]

class SecurityAnalytics:
    """Advanced security analytics and reporting system"""
    
    def __init__(self, db_path: str = "data/reconforge.db"):
        self.db = ReconForgeDB(db_path)
        self.severity_weights = {
            'critical': 10,
            'high': 7,
            'medium': 4,
            'low': 2,
            'info': 1
        }
    
    def calculate_risk_score(self, vulnerabilities: List[Dict]) -> Tuple[float, str]:
        """Calculate overall risk score based on vulnerabilities"""
        if not vulnerabilities:
            return 0.0, 'low'
        
        total_score = 0
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'info').lower()
            weight = self.severity_weights.get(severity, 1)
            total_score += weight
        
        # Normalize score to 0-100 range
        max_possible = len(vulnerabilities) * 10  # If all were critical
        normalized_score = (total_score / max_possible) * 100 if max_possible > 0 else 0
        
        # Determine risk level
        if normalized_score >= 80:
            risk_level = 'critical'
        elif normalized_score >= 60:
            risk_level = 'high'
        elif normalized_score >= 40:
            risk_level = 'medium'
        else:
            risk_level = 'low'
        
        return normalized_score, risk_level
    
    def get_vulnerability_trends(self, days: int = 30) -> Dict[str, Any]:
        """Get vulnerability trends over specified days"""
        try:
            end_date = datetime.now()
            start_date = end_date - timedelta(days=days)
            
            with self.db.get_connection() as conn:
                # Get daily vulnerability counts by severity
                query = """
                SELECT 
                    DATE(created_at) as date,
                    severity,
                    COUNT(*) as count
                FROM vulnerabilities 
                WHERE created_at >= ? AND created_at <= ?
                GROUP BY DATE(created_at), severity
                ORDER BY date
                """
                
                cursor = conn.execute(query, (start_date.isoformat(), end_date.isoformat()))
                results = cursor.fetchall()
                
                # Process data for charting
                dates = []
                current_date = start_date.date()
                while current_date <= end_date.date():
                    dates.append(current_date.strftime('%Y-%m-%d'))
                    current_date += timedelta(days=1)
                
                # Initialize data structure
                trend_data = {
                    'labels': dates,
                    'critical': [0] * len(dates),
                    'high': [0] * len(dates),
                    'medium': [0] * len(dates),
                    'low': [0] * len(dates),
                    'info': [0] * len(dates)
                }
                
                # Fill in actual data
                for row in results:
                    date_str = row['date']
                    severity = row['severity'].lower()
                    count = row['count']
                    
                    if date_str in dates and severity in trend_data:
                        date_index = dates.index(date_str)
                        trend_data[severity][date_index] = count
                
                return trend_data
                
        except Exception as e:
            main_logger.error(f"Error getting vulnerability trends: {e}")
            return self._empty_trend_data()
    
    def get_scan_volume_trends(self, days: int = 30) -> Dict[str, Any]:
        """Get scan volume trends"""
        try:
            end_date = datetime.now()
            start_date = end_date - timedelta(days=days)
            
            with self.db.get_connection() as conn:
                query = """
                SELECT 
                    DATE(created_at) as date,
                    COUNT(*) as scan_count
                FROM scans 
                WHERE created_at >= ? AND created_at <= ?
                GROUP BY DATE(created_at)
                ORDER BY date
                """
                
                cursor = conn.execute(query, (start_date.isoformat(), end_date.isoformat()))
                results = cursor.fetchall()
                
                # Generate date labels
                dates = []
                current_date = start_date.date()
                while current_date <= end_date.date():
                    dates.append(current_date.strftime('%m/%d'))
                    current_date += timedelta(days=1)
                
                # Initialize volumes with zeros
                volumes = [0] * len(dates)
                
                # Fill in actual data
                for row in results:
                    date_obj = datetime.strptime(row['date'], '%Y-%m-%d').date()
                    date_str = date_obj.strftime('%m/%d')
                    if date_str in dates:
                        date_index = dates.index(date_str)
                        volumes[date_index] = row['scan_count']
                
                return {
                    'labels': dates,
                    'volumes': volumes
                }
                
        except Exception as e:
            main_logger.error(f"Error getting scan volume trends: {e}")
            return {'labels': [], 'volumes': []}
    
    def get_threat_distribution(self) -> Dict[str, Any]:
        """Get current threat type distribution"""
        try:
            with self.db.get_connection() as conn:
                query = """
                SELECT 
                    vulnerability_type,
                    COUNT(*) as count
                FROM vulnerabilities 
                WHERE created_at >= datetime('now', '-30 days')
                GROUP BY vulnerability_type
                ORDER BY count DESC
                LIMIT 10
                """
                
                cursor = conn.execute(query)
                results = cursor.fetchall()
                
                labels = []
                values = []
                
                for row in results:
                    labels.append(row['vulnerability_type'] or 'Unknown')
                    values.append(row['count'])
                
                return {
                    'labels': labels,
                    'values': values
                }
                
        except Exception as e:
            main_logger.error(f"Error getting threat distribution: {e}")
            return {'labels': [], 'values': []}
    
    def get_compliance_scores(self) -> Dict[str, Any]:
        """Calculate compliance scores for various frameworks"""
        try:
            with self.db.get_connection() as conn:
                # Get total vulnerabilities by severity
                query = """
                SELECT severity, COUNT(*) as count
                FROM vulnerabilities 
                WHERE created_at >= datetime('now', '-30 days')
                GROUP BY severity
                """
                
                cursor = conn.execute(query)
                results = cursor.fetchall()
                
                severity_counts = {row['severity']: row['count'] for row in results}
                
                # Calculate compliance scores based on vulnerability counts
                frameworks = ['OWASP Top 10', 'NIST', 'ISO 27001', 'CIS Controls', 'GDPR', 'SOX']
                current_scores = []
                target_scores = [95, 90, 85, 92, 88, 85]  # Target scores for each framework
                
                # Simple scoring algorithm based on vulnerability severity
                critical_count = severity_counts.get('critical', 0)
                high_count = severity_counts.get('high', 0)
                medium_count = severity_counts.get('medium', 0)
                
                base_score = 100
                for framework in frameworks:
                    # Deduct points based on vulnerabilities
                    score = base_score
                    score -= critical_count * 15  # Critical: -15 points each
                    score -= high_count * 8       # High: -8 points each
                    score -= medium_count * 3     # Medium: -3 points each
                    
                    # Ensure score doesn't go below 0
                    score = max(0, score)
                    current_scores.append(score)
                
                return {
                    'frameworks': frameworks,
                    'current_scores': current_scores,
                    'target_scores': target_scores
                }
                
        except Exception as e:
            main_logger.error(f"Error calculating compliance scores: {e}")
            return {
                'frameworks': [],
                'current_scores': [],
                'target_scores': []
            }
    
    def get_dashboard_metrics(self, days: int = 7) -> Dict[str, Dict[str, Any]]:
        """Get key dashboard metrics with trends"""
        try:
            current_period = datetime.now() - timedelta(days=days)
            previous_period = current_period - timedelta(days=days)
            
            with self.db.get_connection() as conn:
                # Total scans
                current_scans = conn.execute(
                    "SELECT COUNT(*) as count FROM scans WHERE created_at >= ?",
                    (current_period.isoformat(),)
                ).fetchone()['count']
                
                previous_scans = conn.execute(
                    "SELECT COUNT(*) as count FROM scans WHERE created_at >= ? AND created_at < ?",
                    (previous_period.isoformat(), current_period.isoformat())
                ).fetchone()['count']
                
                # Total vulnerabilities
                current_vulns = conn.execute(
                    "SELECT COUNT(*) as count FROM vulnerabilities WHERE created_at >= ?",
                    (current_period.isoformat(),)
                ).fetchone()['count']
                
                previous_vulns = conn.execute(
                    "SELECT COUNT(*) as count FROM vulnerabilities WHERE created_at >= ? AND created_at < ?",
                    (previous_period.isoformat(), current_period.isoformat())
                ).fetchone()['count']
                
                # Critical vulnerabilities
                current_critical = conn.execute(
                    "SELECT COUNT(*) as count FROM vulnerabilities WHERE severity = 'critical' AND created_at >= ?",
                    (current_period.isoformat(),)
                ).fetchone()['count']
                
                previous_critical = conn.execute(
                    "SELECT COUNT(*) as count FROM vulnerabilities WHERE severity = 'critical' AND created_at >= ? AND created_at < ?",
                    (previous_period.isoformat(), current_period.isoformat())
                ).fetchone()['count']
                
                # Average scan time
                avg_duration = conn.execute(
                    """SELECT AVG(duration) as avg_duration 
                       FROM scans 
                       WHERE duration IS NOT NULL AND created_at >= ?""",
                    (current_period.isoformat(),)
                ).fetchone()['avg_duration'] or 0
                
                prev_avg_duration = conn.execute(
                    """SELECT AVG(duration) as avg_duration 
                       FROM scans 
                       WHERE duration IS NOT NULL AND created_at >= ? AND created_at < ?""",
                    (previous_period.isoformat(), current_period.isoformat())
                ).fetchone()['avg_duration'] or 0
                
                def calculate_change(current, previous):
                    if previous == 0:
                        return "+100%" if current > 0 else "No change", "positive" if current > 0 else "stable"
                    
                    change_pct = ((current - previous) / previous) * 100
                    change_type = "positive" if change_pct > 0 else "negative" if change_pct < 0 else "stable"
                    return f"{change_pct:+.1f}%", change_type
                
                # Format duration
                def format_duration(seconds):
                    if seconds < 60:
                        return f"{seconds:.0f}s"
                    elif seconds < 3600:
                        return f"{seconds/60:.1f}m"
                    else:
                        return f"{seconds/3600:.1f}h"
                
                scan_change, scan_change_type = calculate_change(current_scans, previous_scans)
                vuln_change, vuln_change_type = calculate_change(current_vulns, previous_vulns)
                critical_change, critical_change_type = calculate_change(current_critical, previous_critical)
                duration_change, duration_change_type = calculate_change(avg_duration, prev_avg_duration)
                
                return {
                    'totalScans': {
                        'value': str(current_scans),
                        'change': scan_change,
                        'change_type': scan_change_type
                    },
                    'totalVulnerabilities': {
                        'value': str(current_vulns),
                        'change': vuln_change,
                        'change_type': vuln_change_type
                    },
                    'criticalVulns': {
                        'value': str(current_critical),
                        'change': critical_change,
                        'change_type': critical_change_type
                    },
                    'avgScanTime': {
                        'value': format_duration(avg_duration),
                        'change': duration_change,
                        'change_type': duration_change_type
                    }
                }
                
        except Exception as e:
            main_logger.error(f"Error getting dashboard metrics: {e}")
            return self._empty_metrics()
    
    def get_executive_summary(self) -> Dict[str, Any]:
        """Generate executive summary with risk assessment"""
        try:
            with self.db.get_connection() as conn:
                # Get recent vulnerabilities
                recent_vulns = conn.execute(
                    """SELECT * FROM vulnerabilities 
                       WHERE created_at >= datetime('now', '-30 days')
                       ORDER BY created_at DESC"""
                ).fetchall()
                
                # Calculate risk score
                vuln_dicts = [dict(row) for row in recent_vulns]
                risk_score, risk_level = self.calculate_risk_score(vuln_dicts)
                
                # Get scan statistics
                total_scans = conn.execute(
                    "SELECT COUNT(*) as count FROM scans WHERE created_at >= datetime('now', '-30 days')"
                ).fetchone()['count']
                
                total_targets = conn.execute(
                    "SELECT COUNT(DISTINCT target) as count FROM scans WHERE created_at >= datetime('now', '-30 days')"
                ).fetchone()['count']
                
                # Generate summary text
                critical_count = len([v for v in vuln_dicts if v.get('severity') == 'critical'])
                high_count = len([v for v in vuln_dicts if v.get('severity') == 'high'])
                
                summary_parts = [
                    f"<strong>Security Assessment Overview:</strong> In the past 30 days, {total_scans} scans were conducted across {total_targets} unique targets.",
                    f"<strong>Vulnerability Summary:</strong> {len(vuln_dicts)} total vulnerabilities identified, including {critical_count} critical and {high_count} high-severity issues.",
                ]
                
                if critical_count > 0:
                    summary_parts.append(f"<strong>⚠️ Immediate Action Required:</strong> {critical_count} critical vulnerabilities require immediate remediation to prevent potential security breaches.")
                elif high_count > 0:
                    summary_parts.append(f"<strong>Priority Action:</strong> {high_count} high-severity vulnerabilities should be addressed within the next 7-14 days.")
                else:
                    summary_parts.append("<strong>✅ Good Security Posture:</strong> No critical or high-severity vulnerabilities detected in recent scans.")
                
                summary_text = " ".join(summary_parts)
                
                return {
                    'risk_score': f"{risk_score:.0f}",
                    'risk_level': risk_level,
                    'summary_text': summary_text
                }
                
        except Exception as e:
            main_logger.error(f"Error generating executive summary: {e}")
            return {
                'risk_score': '0',
                'risk_level': 'low',
                'summary_text': 'Unable to generate executive summary due to data access issues.'
            }
    
    def get_recent_activities(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent security activities for timeline"""
        try:
            with self.db.get_connection() as conn:
                activities = []
                
                # Get recent scans
                recent_scans = conn.execute(
                    """SELECT target, scan_type, status, created_at 
                       FROM scans 
                       ORDER BY created_at DESC 
                       LIMIT ?""",
                    (limit,)
                ).fetchall()
                
                for scan in recent_scans:
                    status_map = {
                        'completed': 'success',
                        'failed': 'error',
                        'running': 'warning'
                    }
                    
                    activities.append({
                        'title': f"{scan['scan_type'].title()} Scan",
                        'description': f"Target: {scan['target']}",
                        'timestamp': self._format_timestamp(scan['created_at']),
                        'status': status_map.get(scan['status'], 'warning')
                    })
                
                return activities[:limit]
                
        except Exception as e:
            main_logger.error(f"Error getting recent activities: {e}")
            return []
    
    def export_analytics_data(self, format_type: str, date_range: int = 30) -> Dict[str, Any]:
        """Export analytics data in various formats"""
        try:
            end_date = datetime.now()
            start_date = end_date - timedelta(days=date_range)
            
            with self.db.get_connection() as conn:
                # Get comprehensive data
                scans_data = conn.execute(
                    """SELECT * FROM scans 
                       WHERE created_at >= ? AND created_at <= ?
                       ORDER BY created_at DESC""",
                    (start_date.isoformat(), end_date.isoformat())
                ).fetchall()
                
                vulns_data = conn.execute(
                    """SELECT * FROM vulnerabilities 
                       WHERE created_at >= ? AND created_at <= ?
                       ORDER BY created_at DESC""",
                    (start_date.isoformat(), end_date.isoformat())
                ).fetchall()
                
                # Convert to dictionaries
                scans = [dict(row) for row in scans_data]
                vulns = [dict(row) for row in vulns_data]
                
                # Calculate summary statistics
                summary = {
                    'date_range': f"{start_date.strftime('%Y-%m-%d')} to {end_date.strftime('%Y-%m-%d')}",
                    'total_scans': len(scans),
                    'total_vulnerabilities': len(vulns),
                    'severity_breakdown': Counter(v.get('severity', 'unknown') for v in vulns),
                    'scan_type_breakdown': Counter(s.get('scan_type', 'unknown') for s in scans),
                    'risk_score': self.calculate_risk_score(vulns)[0]
                }
                
                return {
                    'summary': summary,
                    'scans': scans,
                    'vulnerabilities': vulns,
                    'export_timestamp': datetime.now().isoformat(),
                    'format': format_type
                }
                
        except Exception as e:
            main_logger.error(f"Error exporting analytics data: {e}")
            return {}
    
    def _empty_trend_data(self) -> Dict[str, List]:
        """Return empty trend data structure"""
        return {
            'labels': [],
            'critical': [],
            'high': [],
            'medium': [],
            'low': [],
            'info': []
        }
    
    def _empty_metrics(self) -> Dict[str, Dict[str, str]]:
        """Return empty metrics structure"""
        return {
            'totalScans': {'value': '0', 'change': 'No data', 'change_type': 'stable'},
            'totalVulnerabilities': {'value': '0', 'change': 'No data', 'change_type': 'stable'},
            'criticalVulns': {'value': '0', 'change': 'No data', 'change_type': 'stable'},
            'avgScanTime': {'value': '0s', 'change': 'No data', 'change_type': 'stable'}
        }
    
    def _format_timestamp(self, timestamp_str: str) -> str:
        """Format timestamp for display"""
        try:
            dt = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
            now = datetime.now()
            diff = now - dt
            
            if diff.days > 0:
                return f"{diff.days} day{'s' if diff.days != 1 else ''} ago"
            elif diff.seconds > 3600:
                hours = diff.seconds // 3600
                return f"{hours} hour{'s' if hours != 1 else ''} ago"
            elif diff.seconds > 60:
                minutes = diff.seconds // 60
                return f"{minutes} minute{'s' if minutes != 1 else ''} ago"
            else:
                return "Just now"
        except:
            return timestamp_str

# Initialize global analytics instance
analytics = SecurityAnalytics()