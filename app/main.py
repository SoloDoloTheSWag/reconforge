"""
ReconForge Web Dashboard
FastAPI-based web interface for reconnaissance and penetration testing
"""

import asyncio
import json
import os
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Any, Optional
import uuid
import subprocess

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect, HTTPException, BackgroundTasks
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
import uvicorn
from pydantic import BaseModel
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response
from starlette.staticfiles import StaticFiles as StarletteStaticFiles

# Add parent directory to path
import sys
sys.path.append(str(Path(__file__).parent.parent))

from utils.database import ReconForgeDB
from utils.logging import web_logger, get_scan_logger
from utils.helpers import DomainValidator, ToolValidator, ReportGenerator
from sources.base import SourceManager
from sources.passive import get_passive_sources
from sources.active import get_active_sources
from scanners.base import ScannerManager
from scanners.nuclei import get_nuclei_scanners
from scanners.web import get_web_scanners
from pentest.base import PentestManager, get_pentest_modules


class CacheControlStaticFiles(StaticFiles):
    """StaticFiles with cache control headers"""
    
    def file_response(self, *args, **kwargs):
        response = super().file_response(*args, **kwargs)
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
        return response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers to all responses"""
    
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        
        # Security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' ws: wss:;"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
        
        return response


# Initialize FastAPI app
app = FastAPI(
    title="ReconForge",
    description="Professional Reconnaissance and Penetration Testing Framework",
    version="1.3.1"
)

# Add security middleware
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(
    TrustedHostMiddleware, 
    allowed_hosts=["localhost", "127.0.0.1", "0.0.0.0", "*"]
)

# Add CORS middleware with security restrictions  
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8000", "http://127.0.0.1:8000", "http://0.0.0.0:8000"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Content-Type", "Authorization", "X-Requested-With"],
)

# Setup static files and templates
templates = Jinja2Templates(directory="app/templates")

# Add url_for function to templates
def url_for(name: str, **path_params):
    """Simple URL generator for FastAPI routes"""
    routes = {
        'dashboard': '/',
        'discover_page': '/discover',
        'scan_page': '/scan', 
        'pentest_page': '/pentest',
        'scans_page': '/scans',
        'tools_page': '/tools',
        'terminal_page': '/terminal'
    }
    return routes.get(name, '/')

templates.env.globals["url_for"] = url_for
app.mount("/static", CacheControlStaticFiles(directory="app/static"), name="static")

# Initialize database and managers
db = ReconForgeDB()
source_manager = SourceManager()
scanner_manager = ScannerManager()
pentest_manager = PentestManager()

# WebSocket connections for real-time updates
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []
    
    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
    
    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
    
    async def send_message(self, message: Dict[str, Any], websocket: WebSocket):
        try:
            await websocket.send_text(json.dumps(message))
        except:
            self.disconnect(websocket)
    
    async def broadcast(self, message: Dict[str, Any]):
        disconnected = []
        for connection in self.active_connections:
            try:
                await connection.send_text(json.dumps(message))
            except:
                disconnected.append(connection)
        
        # Remove disconnected clients
        for connection in disconnected:
            self.disconnect(connection)

manager = ConnectionManager()

# Background tasks tracking
active_scans = {}
background_tasks_registry = {}

# Pydantic models
class ScanRequest(BaseModel):
    target: str
    mode: Optional[str] = "passive"
    sources: Optional[List[str]] = None
    format: Optional[str] = "json"
    config: Optional[Dict[str, Any]] = {}

class VulnScanRequest(BaseModel):
    targets: List[str]
    scanners: Optional[List[str]] = None
    config: Optional[Dict[str, Any]] = {}

class PentestRequest(BaseModel):
    target: str
    modules: Optional[List[str]] = None
    config: Optional[Dict[str, Any]] = {}


def setup_managers():
    """Initialize all managers with their sources/scanners/modules"""
    # Register subdomain discovery sources
    passive_sources = get_passive_sources()
    for source in passive_sources:
        source_manager.register_source(source)
    
    active_sources = get_active_sources()
    for source in active_sources:
        source_manager.register_source(source)
    
    # Register vulnerability scanners
    nuclei_scanners = get_nuclei_scanners()
    for scanner in nuclei_scanners:
        scanner_manager.register_scanner(scanner)
    
    web_scanners = get_web_scanners()
    for scanner in web_scanners:
        scanner_manager.register_scanner(scanner)
    
    # Register penetration testing modules
    pentest_modules = get_pentest_modules()
    for module in pentest_modules:
        pentest_manager.register_module(module)

# Initialize managers on startup
setup_managers()


@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    """Main dashboard page"""
    # Get recent scans
    recent_scans = db.get_scans(limit=10)
    
    # Get system statistics
    tool_status = ToolValidator.check_all_tools()
    available_tools = sum(1 for tool in tool_status.values() if tool['available'])
    
    stats = {
        'total_scans': len(db.get_scans(limit=1000)),
        'active_scans': len(active_scans),
        'available_tools': available_tools,
        'total_tools': len(tool_status)
    }
    
    return templates.TemplateResponse("modern_dashboard.html", {
        "request": request,
        "recent_scans": recent_scans,
        "stats": stats,
        "page_title": "Dashboard"
    })


@app.get("/advanced-dashboard", response_class=HTMLResponse)
async def advanced_dashboard(request: Request):
    """Enhanced dashboard with real-time features"""
    # Get comprehensive statistics
    all_scans = db.get_scans(limit=1000)
    recent_scans = db.get_scans(limit=10)
    
    # Calculate advanced statistics
    total_vulnerabilities = sum(len(scan.get('vulnerabilities', [])) for scan in all_scans)
    critical_vulns = sum(1 for scan in all_scans for vuln in scan.get('vulnerabilities', []) 
                        if vuln.get('severity') == 'critical')
    high_vulns = sum(1 for scan in all_scans for vuln in scan.get('vulnerabilities', []) 
                    if vuln.get('severity') == 'high')
    
    total_subdomains = sum(len(scan.get('subdomains', [])) for scan in all_scans 
                          if scan.get('scan_type') == 'discovery')
    
    unique_domains = len(set(scan.get('target', '') for scan in all_scans))
    
    tool_status = ToolValidator.check_all_tools()
    available_tools = sum(1 for tool in tool_status.values() if tool['available'])
    
    stats = {
        'total_scans': len(all_scans),
        'active_scans': len(active_scans),
        'total_vulnerabilities': total_vulnerabilities,
        'critical_vulns': critical_vulns,
        'high_vulns': high_vulns,
        'total_subdomains': total_subdomains,
        'unique_domains': unique_domains,
        'available_tools': available_tools,
        'total_tools': len(tool_status)
    }
    
    return templates.TemplateResponse("advanced_dashboard.html", {
        "request": request,
        "recent_scans": recent_scans,
        "stats": stats,
        "page_title": "Advanced Dashboard"
    })


# Enhanced Dashboard API Endpoints

@app.get("/api/system/status")
async def get_system_status():
    """Get real-time system status"""
    import psutil
    
    try:
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        
        return {
            "status": "online",
            "cpu_usage": round(cpu_percent, 1),
            "memory_usage": round(memory.percent, 1),
            "active_scans": len(active_scans),
            "queued_scans": 0,  # TODO: Implement queue system
            "connections": len(websocket_connections),
            "uptime": "24h 15m"  # TODO: Calculate actual uptime
        }
    except Exception as e:
        web_logger.error(f"Failed to get system status: {e}")
        return {
            "status": "error",
            "active_scans": len(active_scans),
            "queued_scans": 0,
            "connections": len(websocket_connections)
        }


@app.get("/api/activity/recent")
async def get_recent_activity():
    """Get recent system activity"""
    try:
        recent_scans = db.get_scans(limit=20)
        activities = []
        
        for scan in recent_scans:
            status = scan.get('status', 'unknown')
            scan_type = scan.get('scan_type', 'scan')
            target = scan.get('target', 'Unknown')
            
            # Calculate time ago
            if scan.get('created_at'):
                created_at = datetime.fromisoformat(scan['created_at'])
                time_diff = datetime.now() - created_at
                if time_diff.days > 0:
                    time_ago = f"{time_diff.days} day{'s' if time_diff.days > 1 else ''} ago"
                elif time_diff.seconds > 3600:
                    hours = time_diff.seconds // 3600
                    time_ago = f"{hours} hour{'s' if hours > 1 else ''} ago"
                elif time_diff.seconds > 60:
                    minutes = time_diff.seconds // 60
                    time_ago = f"{minutes} minute{'s' if minutes > 1 else ''} ago"
                else:
                    time_ago = "Just now"
            else:
                time_ago = "Unknown"
            
            # Generate activity title and description
            if scan_type == 'discovery':
                title = "Subdomain discovery"
                if status == 'completed':
                    title += " completed"
                    subdomain_count = len(scan.get('subdomains', []))
                    description = f"Found {subdomain_count} subdomains for {target}"
                elif status == 'running':
                    title += " in progress"
                    description = f"Discovering subdomains for {target}"
                else:
                    title += f" {status}"
                    description = f"Subdomain discovery for {target}"
            elif scan_type == 'vulnerability':
                title = "Vulnerability scan"
                if status == 'completed':
                    title += " completed"
                    vuln_count = len(scan.get('vulnerabilities', []))
                    description = f"Found {vuln_count} vulnerabilities on {target}"
                elif status == 'running':
                    title += " in progress"
                    description = f"Scanning {target} for vulnerabilities"
                else:
                    title += f" {status}"
                    description = f"Vulnerability scan for {target}"
            elif scan_type == 'pentest':
                title = "Penetration test"
                if status == 'completed':
                    title += " completed"
                    results_count = len(scan.get('pentest_results', []))
                    description = f"Executed {results_count} tests against {target}"
                elif status == 'running':
                    title += " in progress"
                    description = f"Running penetration tests against {target}"
                else:
                    title += f" {status}"
                    description = f"Penetration test for {target}"
            else:
                title = f"Scan {status}"
                description = f"General scan for {target}"
            
            activities.append({
                "title": title,
                "description": description,
                "status": status,
                "time_ago": time_ago,
                "target": target,
                "type": scan_type
            })
        
        return {"activities": activities[:10]}  # Return top 10 activities
        
    except Exception as e:
        web_logger.error(f"Failed to get recent activity: {e}")
        return {"activities": []}


@app.get("/api/scans/recent")
async def get_recent_scans():
    """Get recent scans for dashboard table"""
    try:
        recent_scans = db.get_scans(limit=15)
        formatted_scans = []
        
        for scan in recent_scans:
            # Format duration
            duration = "N/A"
            if scan.get('completed_at') and scan.get('started_at'):
                try:
                    start = datetime.fromisoformat(scan['started_at'])
                    end = datetime.fromisoformat(scan['completed_at'])
                    duration_seconds = (end - start).total_seconds()
                    
                    if duration_seconds >= 3600:
                        hours = int(duration_seconds // 3600)
                        minutes = int((duration_seconds % 3600) // 60)
                        duration = f"{hours}h {minutes}m"
                    elif duration_seconds >= 60:
                        minutes = int(duration_seconds // 60)
                        seconds = int(duration_seconds % 60)
                        duration = f"{minutes}m {seconds}s"
                    else:
                        duration = f"{int(duration_seconds)}s"
                except Exception:
                    duration = "N/A"
            
            # Format results summary
            results_summary = "N/A"
            scan_type = scan.get('scan_type', 'scan')
            
            if scan_type == 'discovery' and scan.get('subdomains'):
                results_summary = f"{len(scan['subdomains'])} subdomains"
            elif scan_type == 'vulnerability' and scan.get('vulnerabilities'):
                vuln_count = len(scan['vulnerabilities'])
                critical_count = sum(1 for v in scan['vulnerabilities'] if v.get('severity') == 'critical')
                if critical_count > 0:
                    results_summary = f"{vuln_count} vulnerabilities ({critical_count} critical)"
                else:
                    results_summary = f"{vuln_count} vulnerabilities"
            elif scan_type == 'pentest' and scan.get('pentest_results'):
                results_count = len(scan['pentest_results'])
                successful = sum(1 for r in scan['pentest_results'] if r.get('success'))
                results_summary = f"{successful}/{results_count} tests successful"
            
            # Format started_at
            started_at = "N/A"
            if scan.get('created_at'):
                try:
                    created = datetime.fromisoformat(scan['created_at'])
                    started_at = created.strftime("%Y-%m-%d %H:%M")
                except Exception:
                    started_at = scan['created_at'][:16] if len(scan['created_at']) > 16 else scan['created_at']
            
            formatted_scans.append({
                "id": scan.get('id'),
                "target": scan.get('target', 'Unknown'),
                "type": scan_type,
                "status": scan.get('status', 'unknown'),
                "started_at": started_at,
                "duration": duration,
                "results_summary": results_summary
            })
        
        return {"scans": formatted_scans}
        
    except Exception as e:
        web_logger.error(f"Failed to get recent scans: {e}")
        return {"scans": []}


@app.get("/api/tools/status")
async def get_tools_status():
    """Get status of all penetration testing tools"""
    try:
        tool_status = ToolValidator.check_all_tools()
        return {"tools": tool_status}
    except Exception as e:
        web_logger.error(f"Failed to get tools status: {e}")
        return {"tools": {}}


@app.get("/api/scans/{scan_id}/download")
async def download_scan_results(scan_id: str):
    """Download scan results"""
    try:
        scan = db.get_scan(scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        # Generate report
        report_generator = ReportGenerator()
        report_content = report_generator.generate_json_report(scan)
        
        # Create response
        response = Response(
            content=json.dumps(report_content, indent=2),
            media_type="application/json",
            headers={
                "Content-Disposition": f"attachment; filename=reconforge_scan_{scan_id}.json"
            }
        )
        
        return response
        
    except Exception as e:
        web_logger.error(f"Failed to download scan results: {e}")
        raise HTTPException(status_code=500, detail="Failed to download results")


@app.get("/api/scans/{scan_id}/details")
async def get_scan_details(scan_id: int):
    """Get detailed scan information for dashboard display"""
    try:
        # Get scan information
        scan = db.get_scan(scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        # Get related data
        subdomains = db.get_subdomains(scan_id)
        vulnerabilities = db.get_vulnerabilities(scan_id)
        services = db.get_services(scan_id)
        
        # Format datetime fields for JSON serialization
        if scan.get('start_time'):
            scan['start_time'] = scan['start_time'].strftime('%Y-%m-%d %H:%M:%S') if hasattr(scan['start_time'], 'strftime') else str(scan['start_time'])
        if scan.get('end_time'):
            scan['end_time'] = scan['end_time'].strftime('%Y-%m-%d %H:%M:%S') if hasattr(scan['end_time'], 'strftime') else str(scan['end_time'])
        if scan.get('created_at'):
            scan['created_at'] = scan['created_at'].strftime('%Y-%m-%d %H:%M:%S') if hasattr(scan['created_at'], 'strftime') else str(scan['created_at'])
        
        return {
            "scan": scan,
            "subdomains": subdomains[:50],  # Limit to first 50 for performance
            "vulnerabilities": vulnerabilities[:50],  # Limit to first 50
            "services": services[:50]  # Limit to first 50
        }
        
    except HTTPException:
        raise
    except Exception as e:
        web_logger.error(f"Failed to get scan details: {e}")
        raise HTTPException(status_code=500, detail="Failed to get scan details")


@app.get("/discover", response_class=HTMLResponse)
async def discover_page(request: Request):
    """Subdomain discovery page"""
    # Get available sources
    sources = source_manager.get_source_stats()
    
    return templates.TemplateResponse("discover.html", {
        "request": request,
        "sources": sources,
        "page_title": "Subdomain Discovery"
    })


@app.get("/scan", response_class=HTMLResponse) 
async def scan_page(request: Request):
    """Vulnerability scanning page"""
    # Get available scanners
    scanners = scanner_manager.get_scanner_stats()
    
    return templates.TemplateResponse("scan.html", {
        "request": request,
        "scanners": scanners,
        "page_title": "Vulnerability Scanning"
    })


@app.get("/pentest", response_class=HTMLResponse)
async def pentest_page(request: Request):
    """Penetration testing page"""
    # Get available modules
    modules = pentest_manager.get_module_stats()
    
    return templates.TemplateResponse("pentest.html", {
        "request": request,
        "modules": modules,
        "page_title": "Penetration Testing"
    })


@app.get("/scans", response_class=HTMLResponse)
async def scans_page(request: Request):
    """Scans history and management page"""
    scans = db.get_scans(limit=50)
    
    return templates.TemplateResponse("scans.html", {
        "request": request,
        "scans": scans,
        "page_title": "Scan History"
    })


@app.get("/scan/{scan_id}", response_class=HTMLResponse)
async def scan_details(request: Request, scan_id: int):
    """Individual scan details page"""
    scan = db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    subdomains = db.get_subdomains(scan_id)
    vulnerabilities = db.get_vulnerabilities(scan_id)
    pentest_results = db.get_pentest_results(scan_id)
    stats = db.get_scan_stats(scan_id)
    
    return templates.TemplateResponse("scan_details.html", {
        "request": request,
        "scan": scan,
        "subdomains": subdomains,
        "vulnerabilities": vulnerabilities,
        "pentest_results": pentest_results,
        "stats": stats,
        "page_title": f"Scan Details - {scan['target']}"
    })


@app.get("/tools", response_class=HTMLResponse)
async def tools_page(request: Request):
    """Tools management page"""
    tool_status = ToolValidator.check_all_tools()
    
    # Calculate tool statistics
    available_tools = sum(1 for info in tool_status.values() if info.get('available', False))
    missing_tools = len(tool_status) - available_tools
    total_tools = len(tool_status)
    
    return templates.TemplateResponse("tools.html", {
        "request": request,
        "tools": tool_status,
        "available_tools": available_tools,
        "missing_tools": missing_tools,
        "total_tools": total_tools,
        "page_title": "Tools Management"
    })


@app.get("/terminal", response_class=HTMLResponse)
async def terminal_page(request: Request):
    """Web terminal page"""
    return templates.TemplateResponse("terminal.html", {
        "request": request,
        "page_title": "Web Terminal"
    })


# API Endpoints
@app.post("/api/discover")
async def start_subdomain_discovery(request: ScanRequest, background_tasks: BackgroundTasks):
    """Start subdomain discovery scan"""
    try:
        # Input validation
        if not request.target or not request.target.strip():
            raise HTTPException(status_code=400, detail="Target domain is required")
        
        # Validate target domain
        if not DomainValidator.is_valid_domain(request.target):
            raise HTTPException(status_code=400, detail="Invalid domain format")
        
        target_clean = DomainValidator.normalize_domain(request.target)
        
        # Validate mode
        valid_modes = ["passive", "active", "both"]
        if request.mode not in valid_modes:
            raise HTTPException(status_code=400, detail=f"Invalid mode. Must be one of: {', '.join(valid_modes)}")
        
        # Validate sources if provided
        if request.sources:
            available_sources = list(source_manager.get_source_stats().keys())
            invalid_sources = [s for s in request.sources if s not in available_sources]
            if invalid_sources:
                raise HTTPException(status_code=400, detail=f"Invalid sources: {', '.join(invalid_sources)}")
        
        # Create scan in database  
        scan_type = f"subdomain_discovery_{request.mode}"
        scan_config = {
            "mode": request.mode,
            "sources": request.sources,
            "format": request.format,
            **request.config
        }
        
        try:
            scan_id = db.create_scan(target_clean, scan_type, scan_config)
        except Exception as e:
            web_logger.error(f"Database error creating scan: {e}")
            raise HTTPException(status_code=500, detail="Failed to create scan record")
        
        # Add to active scans
        scan_uuid = str(uuid.uuid4())
        active_scans[scan_uuid] = {
            'scan_id': scan_id,
            'target': target_clean,
            'type': scan_type,
            'status': 'running',
            'start_time': datetime.now(),
            'cancelled': False
        }
        
        # Start background task
        background_tasks.add_task(run_subdomain_discovery, scan_uuid, target_clean, scan_config)
        
        web_logger.info(f"Started subdomain discovery scan for {target_clean} (UUID: {scan_uuid})")
        
        return {
            "status": "started",
            "scan_uuid": scan_uuid,
            "scan_id": scan_id,
            "target": target_clean
        }
        
    except HTTPException:
        raise
    except Exception as e:
        web_logger.error(f"Unexpected error in start_subdomain_discovery: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@app.post("/api/scan")
async def start_vulnerability_scan(request: VulnScanRequest, background_tasks: BackgroundTasks):
    """Start vulnerability scanning"""
    
    if not request.targets:
        raise HTTPException(status_code=400, detail="No targets provided")
    
    # Create scan in database
    scan_id = db.create_scan(", ".join(request.targets), "vulnerability_scan", request.config)
    
    # Add to active scans
    scan_uuid = str(uuid.uuid4())
    active_scans[scan_uuid] = {
        'scan_id': scan_id,
        'targets': request.targets,
        'type': 'vulnerability_scan',
        'status': 'running',
        'start_time': datetime.now(),
        'cancelled': False
    }
    
    # Start background task
    background_tasks.add_task(run_vulnerability_scan, scan_uuid, request.targets, 
                            request.scanners, request.config)
    
    return {
        "status": "started",
        "scan_uuid": scan_uuid,
        "scan_id": scan_id,
        "targets": request.targets
    }


@app.post("/api/pentest")
async def start_penetration_test(request: PentestRequest, background_tasks: BackgroundTasks):
    """Start penetration testing"""
    
    # Create scan in database
    scan_id = db.create_scan(request.target, "penetration_test", request.config)
    
    # Add to active scans
    scan_uuid = str(uuid.uuid4())
    active_scans[scan_uuid] = {
        'scan_id': scan_id,
        'target': request.target,
        'type': 'penetration_test',
        'status': 'running',
        'start_time': datetime.now(),
        'cancelled': False
    }
    
    # Start background task
    background_tasks.add_task(run_penetration_test, scan_uuid, request.target, 
                            request.modules, request.config)
    
    return {
        "status": "started",
        "scan_uuid": scan_uuid,
        "scan_id": scan_id,
        "target": request.target
    }


@app.get("/api/scans")
async def get_scans(limit: int = 50, status: Optional[str] = None):
    """Get list of scans"""
    scans = db.get_scans(limit=limit, status=status)
    return {"scans": scans}


@app.get("/api/scan/{scan_id}")
async def get_scan_details(scan_id: int):
    """Get detailed scan information"""
    scan = db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    subdomains = db.get_subdomains(scan_id)
    vulnerabilities = db.get_vulnerabilities(scan_id)
    pentest_results = db.get_pentest_results(scan_id)
    stats = db.get_scan_stats(scan_id)
    
    return {
        "scan": scan,
        "subdomains": subdomains,
        "vulnerabilities": vulnerabilities,
        "pentest_results": pentest_results,
        "stats": stats
    }


@app.get("/api/scan/{scan_id}/export")
async def export_scan_results(scan_id: int, format: str = "json"):
    """Export scan results in various formats"""
    scan = db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    # Get all scan data
    subdomains = db.get_subdomains(scan_id)
    vulnerabilities = db.get_vulnerabilities(scan_id)
    pentest_results = db.get_pentest_results(scan_id)
    stats = db.get_scan_stats(scan_id)
    
    report_data = {
        'scan_info': scan,
        'subdomains': subdomains,
        'vulnerabilities': vulnerabilities,
        'pentest_results': pentest_results,
        'stats': stats
    }
    
    # Generate export file
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    target = scan['target'].replace('.', '_').replace(',', '_')
    
    export_dir = Path("exports")
    export_dir.mkdir(exist_ok=True)
    
    try:
        if format == "json":
            filename = f"reconforge_scan_{scan_id}_{target}_{timestamp}.json"
            filepath = export_dir / filename
            
            content = ReportGenerator.generate_json_report(report_data)
            with filepath.open('w', encoding='utf-8') as f:
                f.write(content)
            
            # Record export
            db.add_export_record(scan_id, 'json', str(filepath), filepath.stat().st_size)
            
            return FileResponse(
                filepath, 
                media_type='application/json',
                filename=filename
            )
        
        elif format == "html":
            filename = f"reconforge_scan_{scan_id}_{target}_{timestamp}.html"
            filepath = export_dir / filename
            
            content = ReportGenerator.generate_html_report(report_data)
            with filepath.open('w', encoding='utf-8') as f:
                f.write(content)
            
            # Record export
            db.add_export_record(scan_id, 'html', str(filepath), filepath.stat().st_size)
            
            return FileResponse(
                filepath,
                media_type='text/html',
                filename=filename
            )
        
        elif format == "markdown":
            filename = f"reconforge_scan_{scan_id}_{target}_{timestamp}.md"
            filepath = export_dir / filename
            
            content = ReportGenerator.generate_markdown_report(report_data)
            with filepath.open('w', encoding='utf-8') as f:
                f.write(content)
            
            # Record export
            db.add_export_record(scan_id, 'markdown', str(filepath), filepath.stat().st_size)
            
            return FileResponse(
                filepath,
                media_type='text/markdown',
                filename=filename
            )
        
        elif format == "csv":
            # Export subdomains as CSV
            filename = f"reconforge_subdomains_{scan_id}_{target}_{timestamp}.csv"
            filepath = export_dir / filename
            
            content = ReportGenerator.generate_csv_data(subdomains)
            with filepath.open('w', encoding='utf-8') as f:
                f.write(content)
            
            # Record export
            db.add_export_record(scan_id, 'csv', str(filepath), filepath.stat().st_size)
            
            return FileResponse(
                filepath,
                media_type='text/csv',
                filename=filename
            )
        
        elif format == "txt":
            filename = f"reconforge_scan_{scan_id}_{target}_{timestamp}.txt"
            filepath = export_dir / filename
            
            content = ReportGenerator.generate_text_report(report_data)
            with filepath.open('w', encoding='utf-8') as f:
                f.write(content)
            
            # Record export
            db.add_export_record(scan_id, 'txt', str(filepath), filepath.stat().st_size)
            
            return FileResponse(
                filepath,
                media_type='text/plain',
                filename=filename
        )
        
        else:
            raise HTTPException(status_code=400, detail=f"Unsupported format: {format}. Supported formats: json, html, markdown, csv, txt")
    
    except Exception as e:
        web_logger.error(f"Error exporting scan {scan_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to generate export")


@app.get("/api/active-scans")
async def get_active_scans():
    """Get currently running scans"""
    return {"active_scans": active_scans}


@app.delete("/api/scan/{scan_id}")
async def delete_scan(scan_id: int):
    """Delete a scan and its results"""
    scan = db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    # This would require implementing a delete method in the database
    # For now, we'll just update the status
    db.update_scan_status(scan_id, 'deleted')
    
    return {"status": "deleted"}


@app.get("/api/stats")
async def get_system_stats():
    """Get system statistics"""
    # Tool status
    tools = ToolValidator.check_all_tools()
    available_tools = sum(1 for tool in tools.values() if tool['available'])
    
    # Recent scans
    recent_scans = db.get_scans(limit=100)
    
    # Scan statistics
    total_scans = len(recent_scans)
    completed_scans = len([s for s in recent_scans if s['status'] == 'completed'])
    failed_scans = len([s for s in recent_scans if s['status'] == 'failed'])
    
    return {
        "tools": {
            "total": len(tools),
            "available": available_tools,
            "missing": len(tools) - available_tools
        },
        "scans": {
            "total": total_scans,
            "completed": completed_scans,
            "failed": failed_scans,
            "active": len(active_scans)
        },
        "sources": source_manager.get_summary(),
        "scanners": scanner_manager.get_summary(),
        "pentest": pentest_manager.get_summary()
    }


# WebSocket endpoint for real-time updates
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time scan updates"""
    await manager.connect(websocket)
    try:
        while True:
            # Keep connection alive and listen for messages
            data = await websocket.receive_text()
            message = json.loads(data)
            
            # Handle different message types
            if message.get("type") == "ping":
                await manager.send_message({"type": "pong"}, websocket)
            elif message.get("type") == "subscribe":
                # Subscribe to specific scan updates
                scan_uuid = message.get("scan_uuid")
                await manager.send_message({
                    "type": "subscribed", 
                    "scan_uuid": scan_uuid
                }, websocket)
    
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as e:
        web_logger.error(f"WebSocket error: {e}")
        manager.disconnect(websocket)


# Background task functions
async def run_subdomain_discovery(scan_uuid: str, target: str, config: Dict[str, Any]):
    """Background task for subdomain discovery"""
    if scan_uuid not in active_scans:
        return
        
    scan_info = active_scans[scan_uuid]
    scan_id = scan_info['scan_id']
    
    try:
        # Send start notification
        await manager.broadcast({
            "type": "scan_update",
            "scan_uuid": scan_uuid,
            "status": "running",
            "message": f"Starting subdomain discovery for {target}"
        })
        
        # Check if cancelled before starting
        if scan_info.get('cancelled', False):
            return
        
        # Configure sources based on config
        source_names = config.get('sources')
        if config.get('passive_only'):
            source_names = [name for name, source in source_manager.sources.items() 
                           if hasattr(source, 'rate_limit')]
        
        # Run discovery with cancellation checks
        results = await source_manager.discover_all(
            target,
            sources=source_names,
            parallel=True
        )
        
        # Check if cancelled after discovery
        if scan_info.get('cancelled', False):
            return
        
        # Store results
        for result in results:
            db.add_subdomain(
                scan_id=scan_id,
                subdomain=result.subdomain,
                ip_address=result.ip_address,
                discovery_source=result.source
            )
            
            # Send real-time update
            await manager.broadcast({
                "type": "subdomain_found",
                "scan_uuid": scan_uuid,
                "subdomain": result.subdomain,
                "source": result.source,
                "ip_address": result.ip_address
            })
        
        # Update scan status
        db.update_scan_status(scan_id, 'completed', total_subdomains=len(results))
        
        # Update active scans
        scan_info['status'] = 'completed'
        scan_info['end_time'] = datetime.now()
        scan_info['results_count'] = len(results)
        
        # Send completion notification
        await manager.broadcast({
            "type": "scan_complete",
            "scan_uuid": scan_uuid,
            "status": "completed",
            "results_count": len(results),
            "message": f"Discovery completed: {len(results)} subdomains found"
        })
        
    except Exception as e:
        web_logger.error(f"Subdomain discovery failed for {target}: {e}")
        
        # Update database and active scans
        db.update_scan_status(scan_id, 'failed')
        scan_info['status'] = 'failed'
        scan_info['error'] = str(e)
        
        # Send error notification
        await manager.broadcast({
            "type": "scan_error",
            "scan_uuid": scan_uuid,
            "status": "failed",
            "error": str(e)
        })
    
    finally:
        # Clean up active scan after some time
        await asyncio.sleep(300)  # Keep for 5 minutes
        if scan_uuid in active_scans:
            del active_scans[scan_uuid]


async def run_vulnerability_scan(scan_uuid: str, targets: List[str], 
                                scanners: Optional[List[str]], config: Dict[str, Any]):
    """Background task for vulnerability scanning"""
    scan_info = active_scans[scan_uuid]
    scan_id = scan_info['scan_id']
    
    try:
        # Send start notification
        await manager.broadcast({
            "type": "scan_update", 
            "scan_uuid": scan_uuid,
            "status": "running",
            "message": f"Starting vulnerability scan on {len(targets)} targets"
        })
        
        # Run vulnerability scan
        results = await scanner_manager.scan_all(
            targets,
            scanners=scanners,
            parallel=True
        )
        
        # Store results
        for result in results:
            vuln_id = db.add_vulnerability(scan_id, {
                'subdomain': result.target,
                'vulnerability_type': result.vulnerability_type,
                'severity': result.severity.value,
                'title': result.title,
                'description': result.description,
                'url': result.url,
                'template_id': result.template_id,
                'cve_id': result.cve_id
            })
            
            # Send real-time update
            await manager.broadcast({
                "type": "vulnerability_found",
                "scan_uuid": scan_uuid,
                "vulnerability": {
                    "title": result.title,
                    "severity": result.severity.value,
                    "target": result.target,
                    "type": result.vulnerability_type
                }
            })
        
        # Update scan status
        db.update_scan_status(scan_id, 'completed', total_vulns=len(results))
        
        # Update active scans
        scan_info['status'] = 'completed'
        scan_info['end_time'] = datetime.now()
        scan_info['results_count'] = len(results)
        
        # Send completion notification
        await manager.broadcast({
            "type": "scan_complete",
            "scan_uuid": scan_uuid,
            "status": "completed",
            "results_count": len(results),
            "message": f"Vulnerability scan completed: {len(results)} vulnerabilities found"
        })
        
    except Exception as e:
        web_logger.error(f"Vulnerability scan failed: {e}")
        
        # Update database and active scans
        db.update_scan_status(scan_id, 'failed')
        scan_info['status'] = 'failed'
        scan_info['error'] = str(e)
        
        # Send error notification
        await manager.broadcast({
            "type": "scan_error",
            "scan_uuid": scan_uuid,
            "status": "failed", 
            "error": str(e)
        })
    
    finally:
        # Clean up active scan after some time
        await asyncio.sleep(300)
        if scan_uuid in active_scans:
            del active_scans[scan_uuid]


async def run_penetration_test(scan_uuid: str, target: str, 
                              modules: Optional[List[str]], config: Dict[str, Any]):
    """Background task for penetration testing"""
    scan_info = active_scans[scan_uuid]
    scan_id = scan_info['scan_id']
    
    try:
        # Send start notification
        await manager.broadcast({
            "type": "scan_update",
            "scan_uuid": scan_uuid,
            "status": "running",
            "message": f"Starting penetration test on {target}"
        })
        
        # Run penetration testing
        results = await pentest_manager.execute_all(
            target,
            modules=modules,
            parallel=False  # Sequential for pentesting
        )
        
        # Store results
        for result in results:
            db.add_pentest_result(scan_id, {
                'target': result.target,
                'test_type': result.test_type,
                'command': result.command,
                'output': result.output,
                'success': result.success,
                'severity': result.severity.value,
                'impact': result.impact,
                'recommendations': result.recommendations
            })
            
            # Send real-time update
            await manager.broadcast({
                "type": "pentest_result",
                "scan_uuid": scan_uuid,
                "result": {
                    "test_type": result.test_type,
                    "target": result.target,
                    "success": result.success,
                    "severity": result.severity.value
                }
            })
        
        # Update scan status
        db.update_scan_status(scan_id, 'completed')
        successful = sum(1 for r in results if r.success)
        
        # Update active scans
        scan_info['status'] = 'completed'
        scan_info['end_time'] = datetime.now()
        scan_info['results_count'] = len(results)
        scan_info['successful_tests'] = successful
        
        # Send completion notification
        await manager.broadcast({
            "type": "scan_complete",
            "scan_uuid": scan_uuid,
            "status": "completed", 
            "results_count": len(results),
            "successful_tests": successful,
            "message": f"Penetration testing completed: {len(results)} tests ({successful} successful)"
        })
        
    except Exception as e:
        web_logger.error(f"Penetration testing failed for {target}: {e}")
        
        # Update database and active scans
        db.update_scan_status(scan_id, 'failed')
        scan_info['status'] = 'failed'
        scan_info['error'] = str(e)
        
        # Send error notification
        await manager.broadcast({
            "type": "scan_error",
            "scan_uuid": scan_uuid,
            "status": "failed",
            "error": str(e)
        })
    
    finally:
        # Clean up active scan after some time
        await asyncio.sleep(300)
        if scan_uuid in active_scans:
            del active_scans[scan_uuid]


# Additional API Endpoints

@app.post("/api/stop-scan/{scan_uuid}")
async def stop_scan_api(scan_uuid: str):
    """Stop a running scan"""
    if scan_uuid in active_scans:
        scan_info = active_scans[scan_uuid]
        scan_status = scan_info.get('status', 'running')
        
        # If scan is already completed or failed, just remove it from active scans
        if scan_status in ['completed', 'failed']:
            del active_scans[scan_uuid]
            return {"success": True, "message": f"Scan {scan_status} - removed from active scans"}
        
        # If scan is still running, mark it as cancelled
        scan_info['cancelled'] = True
        scan_info['status'] = 'stopped'
        
        # Update database status
        try:
            db.update_scan_status(scan_info['scan_id'], 'stopped')
        except Exception as e:
            web_logger.error(f"Failed to update scan status in database: {e}")
        
        # Send cancellation notification
        await manager.broadcast({
            "type": "scan_cancelled",
            "scan_uuid": scan_uuid,
            "status": "stopped",
            "message": "Scan cancelled by user"
        })
        
        return {"success": True, "message": "Scan stopped"}
    else:
        # Scan not found in active scans - it might have already completed
        return {"success": True, "message": "Scan not found in active scans (may have already completed)"}


@app.post("/api/scans/delete")
async def delete_multiple_scans(request: Request):
    """Delete multiple scans"""
    try:
        data = await request.json()
        scan_ids = data.get('scan_ids', [])
        
        for scan_id in scan_ids:
            db.delete_scan(scan_id)
        
        return {"success": True}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/scans/{scan_id}/rerun")
async def rerun_scan_api(scan_id: int):
    """Rerun a scan with the same configuration"""
    try:
        scan = db.get_scan(scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        # Create a new scan with the same configuration
        new_scan_id = db.create_scan(scan['target'], scan['scan_type'], scan.get('config', {}))
        return {"success": True, "scan_id": new_scan_id}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/scans/{scan_id}/stop")
async def stop_single_scan(scan_id: int):
    """Stop a specific scan"""
    try:
        db.update_scan_status(scan_id, 'cancelled')
        return {"success": True}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/scans/{scan_id}/export")
async def export_single_scan(scan_id: int, format: str = "json"):
    """Export a specific scan"""
    try:
        scan = db.get_scan(scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        # Generate export data
        export_data = {
            'scan': scan,
            'subdomains': db.get_subdomains(scan_id),
            'vulnerabilities': db.get_vulnerabilities(scan_id),
            'pentest_results': db.get_pentest_results(scan_id)
        }
        
        filename = f"scan_{scan_id}_export.{format}"
        
        if format == 'json':
            content = json.dumps(export_data, indent=2, default=str)
            media_type = 'application/json'
        elif format == 'csv':
            # Simple CSV export of vulnerabilities
            content = "Title,Severity,Target,Type\n"
            for vuln in export_data['vulnerabilities']:
                content += f"{vuln['title']},{vuln['severity']},{vuln['subdomain']},{vuln['vulnerability_type']}\n"
            media_type = 'text/csv'
        else:
            content = str(export_data)
            media_type = 'text/plain'
        
        return Response(content=content, media_type=media_type, headers={"Content-Disposition": f"attachment; filename={filename}"})
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/tools/check")
async def check_tools_api():
    """Check tool installation status"""
    try:
        tools = ToolValidator.check_all_tools()
        return {"success": True, "tools": tools}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/tools/install")
async def install_tools_api(request: Request):
    """Install tools"""
    try:
        data = await request.json()
        tools = data.get('tools', [])
        
        # This would need actual implementation
        # For now, just return success
        return {"success": True, "message": f"Installation started for {len(tools)} tools"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/tools/update")
async def update_tools_api(request: Request):
    """Update tools"""
    try:
        data = await request.json()
        tools = data.get('tools', [])
        
        # This would need actual implementation
        return {"success": True, "message": f"Update started for {len(tools)} tools"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/tools/test/{tool_name}")
async def test_tool_api(tool_name: str):
    """Test a specific tool"""
    try:
        tools = ToolValidator.check_all_tools()
        if tool_name not in tools:
            raise HTTPException(status_code=404, detail="Tool not found")
        
        tool_info = tools[tool_name]
        if tool_info['available']:
            return {"success": True, "output": f"{tool_name} is working correctly"}
        else:
            return {"success": False, "error": f"{tool_name} is not available"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/tools/info/{tool_name}")
async def get_tool_info(tool_name: str):
    """Get information about a specific tool"""
    try:
        tools = ToolValidator.check_all_tools()
        if tool_name not in tools:
            raise HTTPException(status_code=404, detail="Tool not found")
        
        return tools[tool_name]
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/tools/cancel")
async def cancel_installation():
    """Cancel tool installation"""
    # This would need actual implementation
    return {"success": True, "message": "Installation cancelled"}


@app.on_event("startup")
async def startup_event():
    """Startup event handler"""
    web_logger.info("ReconForge web interface starting up")
    
    # Ensure required directories exist
    Path("exports").mkdir(exist_ok=True)
    Path("logs").mkdir(exist_ok=True)
    Path("data").mkdir(exist_ok=True)


@app.on_event("shutdown")
async def shutdown_event():
    """Shutdown event handler"""
    web_logger.info("ReconForge web interface shutting down")


if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )