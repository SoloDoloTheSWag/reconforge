# Claude Code Context - ReconForge Framework

> **Critical: This file contains context for Claude Code interactions. It should be read at the start of any Claude Code session working on ReconForge to understand the framework's current state, architecture, and development guidelines.**

## 📋 Framework Overview

**ReconForge** is a professional penetration testing framework combining reconnaissance, vulnerability scanning, and penetration testing in a unified platform.

**Current Version**: v1.4.0
**Primary Language**: Python 3.8+
**Framework Type**: Web-based (FastAPI) + CLI
**License**: MIT
**Repository**: [SoloDoloTheSWag/reconforge](https://github.com/SoloDoloTheSWag/reconforge)

## 🏗️ Project Architecture

### Core Components
```
/home/kali/reconforge/
├── reconforge.py              # Main CLI entry point (32KB)
├── app/                       # FastAPI web application
│   ├── main.py               # Web server & API endpoints
│   ├── templates/            # Jinja2 HTML templates (8 files)
│   └── static/               # CSS, JavaScript assets
├── sources/                   # Subdomain discovery modules
│   ├── base.py               # Base classes and managers
│   ├── passive.py            # 14 passive discovery sources
│   └── active.py             # 8 active discovery methods
├── scanners/                  # Vulnerability scanning modules
│   ├── base.py               # Scanner framework
│   ├── nuclei.py             # Nuclei integration
│   ├── nikto.py              # Nikto web scanner
│   ├── wapiti.py             # Wapiti vulnerability scanner
│   ├── testssl.py            # SSL/TLS testing
│   ├── zap.py                # OWASP ZAP integration
│   └── web.py                # Web application scanners
├── pentest/                   # Penetration testing modules
│   ├── base.py               # Pentest framework
│   ├── metasploit.py         # Metasploit Framework integration
│   ├── ssrf.py               # SSRF testing module
│   ├── xxe.py                # XXE vulnerability testing
│   ├── rce.py                # Remote code execution testing
│   └── directory_traversal.py # Path traversal testing
├── utils/                     # Core utilities
│   ├── database.py           # SQLite database management
│   ├── logging.py            # Advanced logging system
│   ├── helpers.py            # Utility functions
│   └── performance.py        # Performance monitoring
├── data/                      # SQLite database (EXCLUDED from git)
├── exports/                   # Scan results (EXCLUDED from git)
├── logs/                      # Application logs (EXCLUDED from git)
├── config.json               # Configuration file (EXCLUDED from git)
└── requirements.txt          # Python dependencies
```

## 🔧 Current Capabilities

### 1. Subdomain Discovery (sources/)
**Passive Sources (14 total):**
- subfinder (Project Discovery)
- assetfinder (Tom Hudson)
- amass (OWASP)
- crt.sh (Certificate Transparency)
- Shodan API (IoT/device discovery)
- Censys (Certificate transparency)
- Facebook CT (Certificate logs)
- RapidDNS (DNS resolution data)
- DNSDB (Historical DNS data)
- GAU (Get All URLs from archives)
- SecurityTrails API
- VirusTotal API
- Wayback Machine
- DNSDumpster

**Active Sources (8 total):**
- DNS brute force (custom wordlists)
- shuffledns (DNS resolution validation)
- gobuster (directory/subdomain brute force)
- puredns (mass DNS resolution)
- massdns (high-performance DNS stub resolver)
- FFuF (virtual host fuzzing)
- Alteration patterns (DNS variations)
- Domain permutation generation

### 2. Vulnerability Scanning (scanners/)
**Professional Scanners (10 total):**
- **Nuclei**: Template-based vulnerability scanner with community templates
- **Nikto**: Web vulnerability scanner with XML output parsing
- **OWASP ZAP**: Both proxy mode and headless baseline scanning
- **Wapiti**: Web application vulnerability assessment
- **TestSSL**: SSL/TLS security configuration testing
- **Custom Web Scanner**: Technology detection and basic checks
- **Directory Brute Force**: Content discovery
- **Subdomain Takeover**: Detection of vulnerable subdomains
- **Port Scanning**: Integration with nmap/masscan
- **Technology Stack Detection**: Framework and CMS identification

### 3. Penetration Testing (pentest/)
**Automated Modules (8 total):**
- **SQL Injection**: SQLMap integration + custom payloads
- **XSS Testing**: Reflected, stored, and DOM-based XSS
- **Directory Traversal**: Path traversal with 15+ payloads
- **Brute Force**: Hydra integration for authentication attacks
- **SSRF Testing**: Server-Side Request Forgery with cloud metadata detection
- **XXE Testing**: XML External Entity vulnerability assessment
- **RCE Testing**: Remote Code Execution with multiple payload types
- **Metasploit Integration**: Full MSF framework integration with safe exploitation

### 4. Web Dashboard (app/)
**Modern Interface Features:**
- **Real-time Dashboard**: System metrics, activity timeline, performance monitoring
- **Discovery Page**: Interactive subdomain enumeration interface
- **Scanning Page**: Vulnerability assessment with real-time progress
- **Pentest Page**: Automated penetration testing modules
- **Scan History**: Professional scan management with filtering
- **Tools Management**: Visual tool status and installation
- **Web Terminal**: Browser-based command line
- **Report Generation**: Multi-format exports (JSON, HTML, Markdown, CSV, TXT, XML)

## 🛠️ Technical Stack

### Backend
- **FastAPI**: Modern async web framework
- **SQLite**: Database with WAL mode for performance
- **WebSockets**: Real-time updates and monitoring
- **Jinja2**: Template engine for HTML rendering
- **Pydantic**: Data validation and settings management

### Frontend
- **Bootstrap 5.3.2**: Professional responsive UI framework
- **CSS Grid**: Modern layout system
- **JavaScript**: Real-time updates and interactions
- **Chart.js**: Data visualization and metrics
- **Dark Theme**: Professional security-focused design

### Integration Tools
- **Go Tools**: subfinder, nuclei, httpx, shuffledns, assetfinder
- **Python Tools**: amass integration, custom scanners
- **System Tools**: nmap, sqlmap, hydra, nikto, gobuster
- **Metasploit**: MSF framework integration for exploitation

## 🔒 Security & Data Protection

### Critical Security Measures
**⚠️ IMPORTANT: All actual reconnaissance data MUST be excluded from git/GitHub**

### Protected Data Types
- **Scan Results**: All scan_*, pentest_*, recon_* files
- **Database Files**: SQLite databases with actual target data
- **Export Directories**: exports/, results/, reports/, output/
- **Subdomain Lists**: All *_subdomains*.txt and domain enumeration results
- **Target Information**: Actual domain/IP reconnaissance data
- **Configuration**: API keys, tokens, credentials

### .gitignore Patterns
```gitignore
# Critical exclusions for reconnaissance data
data/                          # SQLite database with scan results
exports/                       # All scan output and results
logs/                          # Application and scan logs
config.json                    # API keys and configuration
*_subdomains*.txt             # Subdomain enumeration results
scan_*                        # All scan result files
pentest_*                     # All penetration test results
recon_*                       # All reconnaissance results
-                             # Accidental output files
*winbornholding*              # Specific target exclusions (example)
```

### Security Best Practices
- **Input Validation**: All user inputs sanitized and validated
- **Rate Limiting**: Prevents abuse and target overwhelming
- **Security Headers**: CSRF, XSS, CSP, HSTS protection
- **CORS Restrictions**: Secure cross-origin resource sharing
- **Error Handling**: No information leakage in error responses
- **Safe Exploitation**: Default "check" mode for pentesting modules

## 📊 Database Schema

### SQLite Database Structure (data/reconforge.db)
```sql
-- Scans table
CREATE TABLE scans (
    id INTEGER PRIMARY KEY,
    target TEXT NOT NULL,
    scan_type TEXT NOT NULL,
    config TEXT,              -- JSON configuration
    status TEXT DEFAULT 'pending',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    completed_at DATETIME,
    results_count INTEGER DEFAULT 0
);

-- Subdomains table
CREATE TABLE subdomains (
    id INTEGER PRIMARY KEY,
    scan_id INTEGER,
    subdomain TEXT NOT NULL,
    ip_address TEXT,
    discovery_source TEXT,
    discovered_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);

-- Vulnerabilities table
CREATE TABLE vulnerabilities (
    id INTEGER PRIMARY KEY,
    scan_id INTEGER,
    target TEXT NOT NULL,
    vulnerability_type TEXT,
    severity TEXT,
    title TEXT,
    description TEXT,
    scanner TEXT,
    discovered_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);
```

## 🔄 Development Workflow

### Starting Development
1. **Activate Environment**: `cd /home/kali/reconforge && source venv/bin/activate`
2. **Verify Tools**: `python reconforge.py tools --check`
3. **Start Web Interface**: `./start_web.sh` or `python reconforge.py web`
4. **Run Tests**: `python test_reconforge.py`

### Making Changes
1. **Read this file first** to understand current state
2. **Follow existing patterns** - check similar functionality
3. **Test thoroughly** - verify with actual scans (use example.com for docs)
4. **Update documentation** - README.md, CHANGELOG.md, and this file
5. **Never commit reconnaissance data** - check .gitignore before commits

### Code Conventions
- **Python Style**: Follow PEP 8
- **Type Hints**: Use Python type annotations
- **Error Handling**: Comprehensive exception handling
- **Logging**: Use existing logging framework (utils/logging.py)
- **Security**: Input validation, no hardcoded secrets
- **Comments**: Minimal unless complex logic requires explanation

## 🚨 Critical Reminders for Claude Code

### Data Protection
1. **NEVER commit actual reconnaissance data to git**
2. **Always verify .gitignore patterns** before suggesting commits
3. **Use example.com for documentation/examples** - never real targets
4. **Check exports/ and data/ directories** for sensitive data before changes
5. **🔥 CRITICAL: Repository was cleaned with git filter-branch and force push** - reconnaissance data completely removed from GitHub

### 📋 Logging & Testing Guidelines (Added v1.3.1)
1. **ALWAYS check logs before starting work** - `logs/terminal_test.log` contains recent testing results
2. **Clean old logs after reviewing** - Don't let old issues confuse future debugging
3. **Document ALL major fixes** - Update CLAUDE.md, CHANGELOG.md, and commit messages
4. **Test fixes thoroughly** - Use analyze_logs.py to verify no errors remain
5. **Log analysis workflow**: Review → Fix → Test → Clean → Document → Commit
6. **Never ignore testing feedback** - User testing reveals critical issues that need immediate fixing

### Framework Understanding
1. **This is a DEFENSIVE security tool** - for authorized testing only
2. **All modules have safety features** - rate limiting, check modes, timeouts
3. **Web interface is production-ready** - comprehensive error handling
4. **Database contains actual scan data** - must remain local only

### Development Guidelines
1. **Read existing code patterns** before implementing new features
2. **Use the modular architecture** - don't break separation of concerns
3. **Test with the web interface** - CLI and web should work together
4. **Update version numbers** when making significant changes
5. **Document security implications** of any new features

### Common Tasks
- **Adding new discovery sources**: Extend sources/passive.py or active.py
- **Adding new scanners**: Create new module in scanners/ following base.py pattern
- **Adding new pentest modules**: Extend pentest/ with safety considerations
- **UI improvements**: Modify app/templates/ and app/static/
- **Database changes**: Update utils/database.py and provide migrations

## 📈 Performance Considerations

### System Requirements
- **RAM**: Minimum 4GB, recommended 8GB+ for large scans
- **CPU**: Multi-core recommended for concurrent operations
- **Disk**: 3GB+ for tools, results can be large
- **Network**: Consider rate limiting and target impact

### Optimization Features
- **Caching**: TTL-based caching system for repeated queries
- **Rate Limiting**: Configurable per-source and per-scanner limits
- **Concurrency Control**: Adaptive task scheduling based on resources
- **Memory Management**: Efficient data structures and garbage collection
- **Database Optimization**: WAL mode, proper indexing

## 🔧 Configuration Management

### Key Configuration Files
- **config.json**: Main configuration (API keys, timeouts, limits)
- **config/performance.yaml**: Performance and resource settings
- **requirements.txt**: Python dependencies
- **.gitignore**: Critical for data protection

### Environment Variables
- API keys should be in config.json (excluded from git)
- No environment variables required for basic operation
- Virtual environment: `/home/kali/reconforge/venv/`

## 📋 Current Status & Potential Improvements

### Framework Analysis (August 27, 2025)
**✅ Current Status:**
- **Architecture**: 28 Python files, 12,767+ lines of professional security code
- **Database**: SQLite with comprehensive schema for scan management
- **Security**: Repository completely cleaned and secured for public deployment
- **Web Interface**: Modern Bootstrap 5.3.2 with responsive dark theme design
- **Git Status**: Clean working tree, synchronized with GitHub repository

### Identified Areas for Enhancement

#### 🔧 Infrastructure & Setup
- **Tool Installation**: Fix missing Go tools and security tools (14 tools currently missing)
- **Configuration**: Enhance config management and API key handling
- **Dependencies**: Update and optimize requirements.txt for latest versions

#### 🚀 Feature Enhancements
- **User Authentication**: Add multi-user support and role-based access control
- **Scheduled Scans**: Implement cron-like functionality for automated scanning
- **Cloud Integration**: Add cloud deployment templates (Docker, Kubernetes)
- **Custom Wordlists**: Enhanced wordlist management system
- **Advanced Reporting**: Enhanced report templates and analytics dashboards

#### ⚡ Performance & Optimization
- **Caching Expansion**: More intelligent caching strategies for scan results
- **Database Optimization**: Better indexing and query performance for large datasets
- **Memory Management**: Enhanced large-scale scan handling capabilities
- **API Rate Limiting**: More sophisticated rate limiting algorithms

#### 🛡️ Security & Compliance
- **Audit Logging**: Enhanced security audit trails and compliance reporting
- **Compliance Reports**: OWASP, NIST framework compliance reporting
- **Vulnerability Database**: Local CVE database integration
- **Certificate Management**: Enhanced SSL/TLS certificate handling

### Maintenance Tasks
- **Dependency Updates**: Regular updates of requirements.txt
- **Tool Updates**: Keep Go tools and system tools updated (currently missing)
- **Template Updates**: Nuclei templates should be updated regularly
- **Documentation**: Keep examples and guides current (✅ completed)

---

## 🎯 Quick Reference for Claude Code Sessions

### Before Making Changes
1. ✅ Read this entire CLAUDE.md file
2. ✅ Check current git status
3. ✅ Verify no reconnaissance data in working directory
4. ✅ Understand the specific request and scope

### During Development
1. ✅ Follow existing code patterns
2. ✅ Test changes with web interface
3. ✅ Verify security implications
4. ✅ Document significant changes

### Before Committing
1. ✅ Check .gitignore effectiveness
2. ✅ Verify no sensitive data in changes
3. ✅ Update documentation if needed
4. ✅ Test critical functionality

### Version History
- **v1.4.0** (Current): PRODUCTION-READY - All critical terminal errors resolved, database methods fixed, exploitation modules complete
- **v1.3.1**: STABLE - All terminal interface issues fixed and tested
- **v1.3.0**: Interactive Terminal Interface - Major terminal-first redesign
- **v1.2.2**: Final release - Complete framework documentation & analysis
- **v1.2.1**: GitHub repository cleanup - reconnaissance data completely removed  
- **v1.2.0**: Enhanced security and data protection
- **v1.1.0**: Metasploit integration and UI redesign
- **v1.0.x**: Major feature expansion and initial stable releases

---

*This document should be updated with each significant change to maintain context for future Claude Code interactions.*