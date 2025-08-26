# ReconForge

**Professional Reconnaissance and Penetration Testing Framework**

ReconForge is a comprehensive, production-ready penetration testing platform that automates the entire reconnaissance-to-exploitation pipeline. It combines passive and active subdomain discovery, vulnerability scanning, and penetration testing in a unified framework with both CLI and web interfaces.

## 🚀 Features

### 🔍 Subdomain Discovery
- **Passive Sources**: subfinder, assetfinder, amass, crt.sh, SecurityTrails, VirusTotal, Wayback Machine
- **Active Sources**: DNS brute force, shuffledns, gobuster, puredns, massdns
- **Intelligent Deduplication**: Advanced filtering and result aggregation
- **Multi-source Correlation**: Combine results from multiple tools

### 🛡️ Vulnerability Scanning
- **Nuclei Integration**: Latest community templates with custom template support
- **Nikto Scanner**: Comprehensive web vulnerability scanning with XML parsing
- **Web Application Testing**: HTTPX integration, subdomain takeover detection
- **Directory Enumeration**: Built-in directory and file brute forcing
- **Technology Detection**: Comprehensive stack fingerprinting
- **CVE Matching**: Automatic CVE identification and scoring

### 🎯 Penetration Testing
- **SQL Injection**: Manual payload testing and SQLMap integration
- **Cross-Site Scripting**: XSS detection and exploitation
- **Directory Traversal**: Path traversal vulnerability testing with multiple payloads
- **Authentication Testing**: Brute force attacks with Hydra integration
- **Real-time Terminal**: Execute pentests directly from web interface
- **Exploit Verification**: Manual confirmation for critical findings

### 🌐 Web Dashboard
- **Modern UI Design**: Professional Bootstrap 5.3.2 interface with gradient themes
- **Real-time Updates**: WebSocket-based live scan monitoring with visual status indicators
- **Interactive Interface**: Clean, responsive web UI optimized for all devices
- **Comprehensive Reporting**: JSON, HTML, Markdown, CSV, and TXT export capabilities
- **Scan Management**: History, comparison, and progress tracking with visual feedback
- **Terminal Access**: Built-in web terminal for manual testing
- **Mobile Responsive**: Fully optimized for desktop, tablet, and mobile devices

### 📊 Professional Reporting
- **Multiple Formats**: JSON, HTML, Markdown, CSV, and TXT reports
- **Interactive HTML Reports**: Professional styling with vulnerability breakdown
- **Markdown Documentation**: GitHub-compatible format with emojis and tables
- **Executive Summaries**: High-level findings and recommendations  
- **Technical Details**: Complete scan data with evidence
- **Trend Analysis**: Historical comparison and metrics
- **Export Integration**: Automated report generation with multiple output options

## 🏗️ Architecture

```
reconforge/
├── reconforge.py              # Main CLI interface
├── app/                       # FastAPI web application
│   ├── main.py               # Web server and API endpoints
│   ├── templates/            # Jinja2 HTML templates
│   └── static/               # CSS, JavaScript, assets
├── sources/                   # Subdomain discovery modules
│   ├── base.py               # Base classes and managers
│   ├── passive.py            # Passive discovery sources
│   └── active.py             # Active discovery sources
├── scanners/                  # Vulnerability scanning modules
│   ├── base.py               # Scanner framework
│   ├── nuclei.py             # Nuclei integration
│   └── web.py                # Web application scanners
├── pentest/                   # Penetration testing modules
│   └── base.py               # Pentest framework and modules
├── utils/                     # Core utilities
│   ├── database.py           # SQLite database management
│   ├── logging.py            # Advanced logging system
│   └── helpers.py            # Utility functions
├── install.sh                # Tool installation script
├── requirements.txt          # Python dependencies
└── config.json              # Configuration file
```

## 🔧 Installation

### Prerequisites
- Kali Linux (recommended) or similar penetration testing distribution
- Python 3.8+ with pip
- Go 1.19+ (for tool installation)
- Sufficient disk space (2GB+ recommended)

### Quick Installation

1. **Clone the repository:**
```bash
git clone https://github.com/your-repo/reconforge.git
cd reconforge
```

2. **Run the installation script:**
```bash
chmod +x install.sh
./install.sh
```

3. **Set up Python environment:**
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

4. **Verify tool installation:**
```bash
python reconforge.py tools --check
```

### Manual Tool Installation

If the automated installation fails, install tools manually:

```bash
# Go-based tools
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/tomnomnom/assetfinder@latest
go install github.com/owasp-amass/amass/v4/cmd/amass@latest
go install github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest

# System packages
sudo apt install -y nmap sqlmap gobuster masscan nikto hydra john hashcat
```

## 🚀 Quick Start

### ⚡ Essential First Steps

**1. Navigate to project directory and activate virtual environment:**
```bash
cd /home/kali/reconforge
source venv/bin/activate
```

**2. Verify activation:**
You should see `(venv)` at the beginning of your command prompt like:
```
(venv) kali@kali:~/reconforge$
```

**3. You're ready to use ReconForge!**

### CLI Usage

**Subdomain Discovery:**
```bash
# Basic discovery
python reconforge.py discover example.com

# Passive only
python reconforge.py discover example.com --passive-only

# Custom wordlist
python reconforge.py discover example.com --wordlist /path/to/wordlist.txt

# Export results
python reconforge.py discover example.com --output results.json --format json
```

**Vulnerability Scanning:**
```bash
# Scan discovered subdomains
python reconforge.py scan example.com

# Scan specific targets
python reconforge.py scan https://target1.com https://target2.com

# Custom Nuclei templates
python reconforge.py scan example.com --nuclei-templates /path/to/templates
```

**Penetration Testing:**
```bash
# Run all pentest modules
python reconforge.py pentest example.com

# Specific modules only
python reconforge.py pentest example.com --modules sql_injection,xss_injection

# Sequential execution
python reconforge.py pentest example.com --sequential
```

**Complete Assessment:**
```bash
# Full automated assessment
python reconforge.py full example.com

# Skip penetration testing
python reconforge.py full example.com --skip-pentest

# Custom output directory
python reconforge.py full example.com --output-dir /path/to/reports
```

### Web Interface

**IMPORTANT: Activate Virtual Environment First**
```bash
# Navigate to project directory
cd /home/kali/reconforge

# Activate the virtual environment
source venv/bin/activate

# Verify activation (you should see (venv) in your prompt)
```

**Start the web dashboard:**

**Option 1: Use the convenient startup script**
```bash
./start_web.sh
```

**Option 2: Manual activation and startup**
```bash
# Activate virtual environment
source venv/bin/activate

# Start web interface
python reconforge.py web --host 0.0.0.0 --port 8000
```

**Access the interface:**
- Open browser to `http://localhost:8000`
- Dashboard provides real-time scan monitoring
- Interactive forms for starting scans
- Results visualization and export
- Web-based terminal for manual testing
- Comprehensive scan history and management

**Web Interface Features:**
- **Dashboard**: Modern responsive dashboard with real-time system status and statistics
- **Discovery Page**: Interactive subdomain enumeration with multiple sources and progress tracking
- **Scanning Page**: Vulnerability assessment with Nuclei, Nikto, and custom scanners  
- **Pentest Page**: Automated penetration testing modules including Directory Traversal
- **Scan History**: Professional scan management with advanced filtering and export options
- **Tools Management**: Visual tool status checker with installation capabilities
- **Web Terminal**: Browser-based command line for manual testing and debugging
- **Report Generation**: Multi-format exports with HTML, Markdown, JSON, CSV, and TXT support

**Latest Updates (v1.1.0):**
- 🔒 **Enhanced Security**: Added comprehensive security headers, CORS restrictions, and input validation
- 🛡️ **New Scanner Integration**: Added Nikto web vulnerability scanner for comprehensive web app testing
- 📊 **Enhanced Reporting**: Added HTML, Markdown, and improved CSV/TXT export formats
- 🎯 **New Pentest Module**: Added Directory Traversal vulnerability testing module
- ⚡ **Performance Improvements**: Enhanced error handling, logging, and database operations
- 🔧 **API Enhancements**: Improved validation, error responses, and security middleware
- 🎨 **UI System Overhaul**: Complete rebuild of web interface with modern Bootstrap 5.3.2, responsive design, and professional styling
- 🌐 **WebSocket Improvements**: Enhanced real-time connection management with visual status indicators
- 📱 **Mobile Responsive**: Fully responsive design optimized for all device sizes

**Previous Fixes (v1.0.2):**
- ✅ Fixed subdomain discovery API validation error (422 Unprocessable Content)
- ✅ Updated ScanRequest model to match frontend data structure
- ✅ Fixed scan type mapping and configuration handling

**Previous Fixes (v1.0.1):**
- ✅ Fixed missing template files (discover.html, scan.html, pentest.html, scans.html, tools.html, terminal.html)
- ✅ Added comprehensive API endpoints for all web interface functionality
- ✅ Fixed database operations and scan management
- ✅ Enhanced error handling and user experience
- ✅ Added professional UI/UX with Bootstrap integration
- ✅ Implemented real-time WebSocket updates

### Advanced Configuration

**API Keys Setup:**
```bash
# Create configuration file
cp config.json.example config.json

# Add your API keys
{
  "api_keys": {
    "securitytrails_api_key": "your-key-here",
    "virustotal_api_key": "your-key-here",
    "shodan_api_key": "your-key-here"
  }
}
```

**Custom Wordlists:**
```bash
# Use custom wordlist
python reconforge.py discover example.com --wordlist /opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
```

## 📊 Example Output

### Subdomain Discovery
```
🎯 Subdomain Discovery Summary
Target: example.com
Subdomains found: 247
Sources used: 8

📋 Discovered Subdomains:
  • www.example.com [93.184.216.34]
  • mail.example.com [93.184.216.35]
  • api.example.com [93.184.216.36]
  • blog.example.com [93.184.216.37]
  ... and 243 more
```

### Vulnerability Scanning
```
🔍 Vulnerability Scan Summary
Target: example.com
Vulnerabilities found: 23
Scanners used: 4

🚨 Vulnerabilities by Severity:
  CRITICAL: 2
  HIGH: 5
  MEDIUM: 12
  LOW: 4

⚠️  Critical/High Vulnerabilities:
  • [CRITICAL] SQL Injection in login form - api.example.com
  • [CRITICAL] Remote Code Execution - admin.example.com
  • [HIGH] Cross-Site Scripting - blog.example.com
```

### Penetration Testing
```
🎯 Penetration Test Summary
Target: example.com
Tests executed: 15
Successful exploits: 3
Modules used: 3

✅ Successful Exploits:
  • [CRITICAL] SQL Injection - api.example.com/login
    Impact: Database access and potential data extraction
  • [HIGH] Authentication Bypass - admin.example.com
    Impact: Administrative access to control panel
```

## 🔒 Security Considerations

### Ethical Usage
- **Authorization Required**: Only test systems you own or have explicit permission to test
- **Legal Compliance**: Ensure compliance with local laws and regulations
- **Responsible Disclosure**: Report vulnerabilities through proper channels
- **Documentation**: Maintain detailed records of all testing activities

### Tool Safety
- **Rate Limiting**: Built-in rate limiting to avoid overwhelming targets
- **Input Validation**: Comprehensive input sanitization and validation
- **Security Headers**: CSRF protection, XSS prevention, and content security policies
- **CORS Restrictions**: Secure cross-origin resource sharing configuration
- **Error Handling**: Graceful error handling to prevent information leakage
- **Logging**: Detailed audit trails for all activities
- **Secure Middleware**: Multiple layers of security validation and protection

### Best Practices
- **Scope Definition**: Clearly define testing scope before starting
- **Impact Assessment**: Understand potential impact of testing activities
- **Backup Verification**: Ensure target systems have recent backups
- **Communication**: Maintain clear communication with system owners

## 🛠️ Configuration

### Database Configuration
```json
{
  "database_path": "data/reconforge.db",
  "max_connections": 10,
  "timeout": 30
}
```

### Scanner Configuration
```json
{
  "scanner_config": {
    "nuclei": {
      "rate_limit": 150,
      "timeout": 10,
      "severity_filter": ["critical", "high", "medium"]
    },
    "httpx": {
      "timeout": 10,
      "follow_redirects": true,
      "check_tech": true
    }
  }
}
```

### API Keys
```json
{
  "api_keys": {
    "securitytrails_api_key": null,
    "virustotal_api_key": null,
    "shodan_api_key": null
  }
}
```

## 📈 Performance Optimization

### Concurrency Settings
- **DNS Threads**: Adjust based on system capabilities
- **Rate Limiting**: Balance speed vs. target impact
- **Memory Management**: Monitor resource usage during large scans

### Network Optimization
- **Connection Pooling**: Efficient HTTP connection management
- **Request Batching**: Group requests for better performance
- **Retry Logic**: Intelligent retry mechanisms for failed requests

### Storage Optimization
- **Database Indexing**: Optimized database schema for fast queries
- **Result Compression**: Efficient storage of scan results
- **Cleanup Policies**: Automatic cleanup of old scan data

## 🤝 Contributing

We welcome contributions to ReconForge! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

### Development Setup
1. Fork the repository
2. Create a feature branch
3. Set up development environment
4. Make your changes
5. Add tests for new functionality
6. Submit a pull request

### Code Standards
- Follow PEP 8 for Python code
- Include comprehensive docstrings
- Add unit tests for new features
- Update documentation as needed

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🛠️ Troubleshooting

### Common Issues

**UI/Web Interface Issues:**
- **Broken Layout**: Clear browser cache and hard reload (Ctrl+F5)
- **WebSocket Connection Failed**: Check firewall settings and ensure port 8000 is accessible
- **422 Validation Errors**: Updated in v1.1.0 - ensure you're using the latest version

**Scanner Issues:**
- **Tools Not Found**: Run `python reconforge.py tools --check` to verify tool installation
- **Permission Denied**: Ensure tools have executable permissions: `chmod +x /usr/local/bin/nuclei`
- **Rate Limiting**: Adjust rate limits in `config.json` if scans are too aggressive

**Performance Issues:**
- **Slow Scans**: Reduce concurrent threads in configuration
- **Memory Usage**: Monitor system resources during large scans
- **Database Locks**: Restart application if database becomes unresponsive

### Getting Help
```bash
# Check system status
python reconforge.py tools --check

# Verify virtual environment
which python  # Should show: /home/kali/reconforge/venv/bin/python

# Check logs
tail -f logs/reconforge.log
tail -f logs/web.log
```

## 🆘 Support

### Documentation
- [User Guide](docs/user-guide.md)
- [API Reference](docs/api-reference.md)
- [Developer Documentation](docs/developer-guide.md)
- [FAQ](docs/faq.md)

### Community
- [GitHub Issues](https://github.com/your-repo/reconforge/issues)
- [Discord Community](https://discord.gg/your-discord)
- [Twitter Updates](https://twitter.com/reconforge)

### Professional Support
For enterprise support and custom development, contact us at support@reconforge.com

## 🔄 Updates and Maintenance

ReconForge is actively maintained with regular updates:

- **Security Updates**: Regular security patches and improvements
- **Tool Integration**: New tool integrations and updates
- **Feature Enhancements**: Community-requested features
- **Bug Fixes**: Prompt resolution of reported issues

### Update Instructions
```bash
# Update ReconForge
git pull origin main
pip install -r requirements.txt --upgrade

# Update tools
python reconforge.py tools --install --force

# Update Nuclei templates
nuclei -update-templates
```

---

## 📋 Complete Feature Summary (v1.1.0)

### 🆕 **New Features Added:**
- **Nikto Scanner Integration**: Professional web vulnerability scanning with XML parsing
- **Directory Traversal Module**: Comprehensive path traversal testing with 15+ payloads
- **HTML Report Generation**: Professional interactive reports with styling and charts
- **Markdown Report Export**: GitHub-compatible documentation format
- **Enhanced WebSocket Management**: Real-time connection status with visual indicators

### 🔧 **Major Improvements:**
- **Complete UI Rebuild**: Modern Bootstrap 5.3.2 interface with responsive design
- **Security Enhancements**: CORS restrictions, security headers, and input validation
- **API Validation Fixes**: Resolved 422 errors and improved error handling
- **Performance Optimizations**: Enhanced database operations and connection management
- **Mobile Responsive Design**: Optimized for all device sizes and screen resolutions

### 🛡️ **Security & Reliability:**
- **Enhanced Input Validation**: Comprehensive sanitization and error handling
- **Security Headers**: CSP, HSTS, X-Frame-Options, and more security middleware
- **Rate Limiting**: Built-in protection against overwhelming targets
- **Error Recovery**: Graceful error handling with detailed logging

---

**⚠️ Disclaimer**: ReconForge is intended for authorized security testing only. Users are responsible for ensuring they have proper authorization before testing any systems. The developers are not responsible for any misuse of this tool.

**🛡️ Security**: If you discover a security vulnerability in ReconForge itself, please report it responsibly to security@reconforge.com.