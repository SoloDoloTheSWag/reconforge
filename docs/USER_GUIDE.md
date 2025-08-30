# ReconForge User Guide 📖

**Version 2.0.0 - Terminal-First Professional Reconnaissance Platform**

## 🎯 Welcome to ReconForge

This comprehensive user guide will help you master ReconForge's powerful reconnaissance capabilities. Whether you're a security professional, penetration tester, or researcher, this guide provides everything you need to effectively use ReconForge for authorized security testing.

---

## 📚 Table of Contents

1. [Getting Started](#getting-started)
2. [First-Time Setup](#first-time-setup)
3. [Interface Overview](#interface-overview)
4. [Core Workflows](#core-workflows)
5. [Module Deep Dives](#module-deep-dives)
6. [Configuration Guide](#configuration-guide)
7. [Results Management](#results-management)
8. [Best Practices](#best-practices)
9. [Troubleshooting](#troubleshooting)
10. [Advanced Usage](#advanced-usage)

---

## 🚀 Getting Started

### **Prerequisites**

Before using ReconForge, ensure you have:

- ✅ **Python 3.8+** installed
- ✅ **Terminal access** with appropriate permissions
- ✅ **Written authorization** for all target systems
- ✅ **Understanding** of applicable laws and regulations

### **Quick Installation**

```bash
# Clone ReconForge
git clone https://github.com/yourusername/reconforge.git
cd reconforge

# Install Python dependencies
pip3 install rich requests

# Run ReconForge
python3 main.py
```

### **Your First Scan**

1. **Launch ReconForge**: `python3 main.py`
2. **Complete first-time setup** (if prompted)
3. **Navigate to**: Reconnaissance → Subdomain Discovery
4. **Enter target**: `example.com` (replace with authorized target)
5. **Run scan** and review results

---

## ⚙️ First-Time Setup

### **Setup Wizard**

When you first run ReconForge, you'll be guided through a setup wizard:

```
Welcome to ReconForge! Let's get you set up.

Choose your terminal theme:
  1. default
  2. dark  
  3. hacker
  4. light

Would you like to configure API keys now? [y/N]
```

### **Theme Selection**

Choose a theme that works best with your terminal:

- **Default**: Blue/white color scheme, good for most terminals
- **Dark**: Optimized for dark terminal backgrounds
- **Hacker**: Green/black matrix-style theme
- **Light**: Designed for light terminal backgrounds

### **API Keys (Optional)**

For enhanced reconnaissance capabilities, configure API keys:

- **Shodan**: Enhanced network reconnaissance
- **VirusTotal**: Malware and reputation checking  
- **SecurityTrails**: DNS and domain intelligence
- **Censys**: Internet-wide scanning data

**Note**: API keys are encrypted and stored locally.

---

## 🖥️ Interface Overview

### **Main Menu Structure**

```
ReconForge Main Menu
===================

1. 🔍 Reconnaissance
   └── Passive and active discovery modules

2. 🛡️  Vulnerability Assessment  
   └── Security scanning and vulnerability detection

3. ⚡ Exploitation
   └── Safe exploitation and penetration testing

4. 📊 Results & Reports
   └── View scan results and generate reports

5. 🔧 Tools & Utilities
   └── Tool management and utility functions

6. ⚙️  Configuration
   └── Application settings and configuration
```

### **Navigation Controls**

- **Numbers**: Select menu items by number (1, 2, 3...)
- **Shortcuts**: Use keyboard shortcuts shown in parentheses (r, v, e...)
- **'b'**: Go back to previous menu
- **'?'**: Show help for current menu
- **'x'**: Exit ReconForge (from main menu)

### **Status Indicators**

- ✅ **Success**: Operation completed successfully
- ❌ **Error**: Operation failed or encountered errors
- ⚠️ **Warning**: Important information or potential issues
- ℹ️ **Info**: General information messages
- 🔄 **Running**: Operation in progress
- ⏳ **Pending**: Operation queued or waiting

---

## 🔄 Core Workflows

### **Workflow 1: Basic Reconnaissance**

**Objective**: Discover subdomains and basic information about a target

```
1. Launch ReconForge
   python3 main.py

2. Navigate to Reconnaissance
   Main Menu → 1 (Reconnaissance)

3. Select Subdomain Discovery  
   Reconnaissance → 1 (Subdomain Discovery)

4. Enter target domain
   Target: example.com

5. Choose discovery options
   - Passive sources: Yes
   - DNS resolution: Yes  
   - Alive verification: Yes

6. Review results
   - View discovered subdomains
   - Check alive status
   - Note technologies detected
```

### **Workflow 2: Vulnerability Assessment**

**Objective**: Perform comprehensive security scanning

```
1. Start from Main Menu
   Main Menu → 2 (Vulnerability Assessment)

2. Select Nuclei Scanning
   Vulnerability Assessment → 1 (Nuclei Vulnerability Scan)

3. Configure scan parameters
   - Target: https://example.com
   - Severity filter: Medium, High, Critical
   - Template categories: vulnerabilities, exposures

4. Execute scan
   - Monitor progress bar
   - Review findings in real-time

5. Analyze results
   - Check CVSS scores
   - Review proof-of-concept
   - Plan remediation
```

### **Workflow 3: Port and Service Discovery**

**Objective**: Map network services and open ports

```
1. Navigate to Port Scanning
   Main Menu → 1 (Reconnaissance) → 2 (Port Scanning)

2. Configure scan settings
   - Target: 192.168.1.100
   - Ports: top_1000
   - Service detection: Yes
   - Timing: Normal (T3)

3. Execute scan
   - Monitor scanning progress
   - Review discovered services

4. Analyze services
   - Check service versions
   - Note potential vulnerabilities
   - Document findings
```

---

## 🔍 Module Deep Dives

### **1. Subdomain Discovery Module**

**Purpose**: Discover subdomains using multiple passive and active techniques

#### **Available Sources**

**Passive Sources (20+)**:
- **Certificate Transparency**: crt.sh, Censys, Certspotter
- **Search Engines**: Google, Bing, DuckDuckGo
- **APIs**: VirusTotal, SecurityTrails, Shodan, Spyse
- **Tools**: Subfinder, Assetfinder, Findomain, Chaos
- **Archives**: Wayback Machine, CommonCrawl, Alien Vault

**Active Sources (5+)**:
- **DNS Bruteforce**: Common subdomain wordlists
- **Permutations**: Generate subdomain variations
- **Zone Transfer**: Attempt DNS zone transfers
- **Reverse DNS**: PTR record enumeration
- **Certificate Probing**: Active certificate discovery

#### **Configuration Options**

```
Subdomain Discovery Configuration
================================

Target Domain: example.com

Discovery Options:
□ Passive only (recommended for stealth)
□ Active discovery (may be detected)
☑ Verify alive (HTTP probing)
☑ Resolve DNS records
☑ Detect technologies

Rate Limiting:
• Requests per second: [100]
• Delay between requests: [1.0] seconds

Output Options:
☑ Save to database
☑ Export to file
□ Generate screenshots
```

#### **Interpreting Results**

```
Subdomain Discovery Results
==========================

Total Subdomains Found: 47
Alive Subdomains: 23
Technologies Detected: 12

┌──────────────────────┬─────────────┬──────┬─────────────┐
│ Subdomain            │ IP Address  │ Code │ Technology  │
├──────────────────────┼─────────────┼──────┼─────────────┤
│ api.example.com      │ 192.168.1.5 │ 200  │ Express.js  │
│ admin.example.com    │ 192.168.1.6 │ 401  │ Apache      │
│ dev.example.com      │ 192.168.1.7 │ 403  │ Nginx       │
│ mail.example.com     │ 192.168.1.8 │ 443  │ Postfix     │
└──────────────────────┴─────────────┴──────┴─────────────┘

⚠️  Interesting Findings:
• admin.example.com - Administrative interface (401 Unauthorized)
• dev.example.com - Development environment (403 Forbidden)  
• api.example.com - API endpoint with Express.js
```

### **2. Vulnerability Scanning Module**

**Purpose**: Identify security vulnerabilities using professional scanners

#### **Scanner Types**

**Nuclei Integration**:
- **Template Categories**: Vulnerabilities, exposures, misconfigurations
- **Severity Levels**: Critical, High, Medium, Low, Info
- **Custom Templates**: Support for custom vulnerability templates
- **Update System**: Automatic template updates

**Custom Scanners**:
- **XSS Detection**: Reflected, stored, DOM-based XSS
- **SQL Injection**: Error-based, blind, time-based testing  
- **Security Headers**: Missing security headers detection
- **SSL/TLS Testing**: Certificate and configuration analysis
- **Directory Traversal**: Path traversal vulnerability detection

#### **Risk Assessment**

ReconForge automatically calculates risk scores based on:

- **CVSS Score**: Industry-standard vulnerability scoring
- **Exploitability**: How easily the vulnerability can be exploited
- **Impact**: Potential damage from successful exploitation
- **Context**: Target environment and configuration

```
Vulnerability Risk Matrix
========================

       │ Low Impact │ Medium Impact │ High Impact
───────┼────────────┼───────────────┼─────────────
Low    │ Info       │ Low           │ Medium
Medium │ Low        │ Medium        │ High  
High   │ Medium     │ High          │ Critical
```

### **3. Port Scanning Module**

**Purpose**: Discover network services and analyze attack surface

#### **Scanning Techniques**

**TCP Scans**:
- **SYN Scan (-sS)**: Stealthy half-open scanning (default)
- **Connect Scan (-sT)**: Full TCP connection
- **ACK Scan (-sA)**: Firewall and filtering detection
- **Window Scan (-sW)**: Advanced TCP window detection

**UDP Scans**:
- **UDP Scan (-sU)**: UDP service discovery
- **Combined TCP/UDP**: Comprehensive service mapping

#### **Service Detection**

```
Service Detection Results
========================

Host: 192.168.1.100 (example.com)
Status: Up

PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 8.9p1
80/tcp   open  http       Apache httpd 2.4.41
443/tcp  open  https      Apache httpd 2.4.41 (SSL)
3306/tcp open  mysql      MySQL 8.0.28
8080/tcp open  http-proxy Squid 4.13

⚠️  Security Notes:
• SSH version may be outdated
• MySQL exposed to network
• HTTP proxy running on non-standard port
```

### **4. Web Enumeration Module**

**Purpose**: Discover web application content and structure

#### **Discovery Methods**

**Directory Discovery**:
- **Gobuster**: Fast directory/file enumeration
- **FFUF**: High-performance web fuzzing
- **Custom Wordlists**: Tailored discovery lists
- **Recursive Discovery**: Multi-level directory traversal

**Content Analysis**:
- **Technology Detection**: Web frameworks, CMS, libraries
- **Response Analysis**: Content type, size, timing analysis
- **Error Page Detection**: Custom error pages and information leakage
- **Redirect Following**: Automatic redirect chain analysis

#### **Common Findings**

```
Web Enumeration Results
======================

Target: https://example.com
Directories Found: 15
Files Found: 23
Interesting Items: 7

┌─────────────────────────┬──────┬────────┬──────────────┐
│ Path                    │ Code │ Size   │ Content-Type │
├─────────────────────────┼──────┼────────┼──────────────┤
│ /admin/                 │ 401  │ 1.2KB  │ text/html    │
│ /api/v1/                │ 200  │ 345B   │ application/ │
│ /backup.zip             │ 200  │ 2.1MB  │ application/ │
│ /robots.txt             │ 200  │ 156B   │ text/plain   │
│ /.git/config            │ 200  │ 89B    │ text/plain   │
└─────────────────────────┴──────┴────────┴──────────────┘

⚠️  Critical Findings:
• /backup.zip - Potentially sensitive backup file
• /.git/config - Git configuration exposed
• /admin/ - Administrative interface
```

### **5. SQL Injection Testing Module**

**Purpose**: Test for SQL injection vulnerabilities with safety controls

#### **Testing Types**

**Injection Techniques**:
- **Boolean-based**: True/false condition testing
- **Time-based**: Blind injection with delays
- **Error-based**: Database error message extraction
- **UNION-based**: Data extraction via UNION queries
- **Stacked queries**: Multiple query execution

#### **Safety Features**

```
SQL Injection Safety Controls
============================

Safety Level: CAUTIOUS
Target Authorization: ✅ Confirmed
Rate Limiting: 1 request/second
Confirmation Required: Yes

Safety Checks:
• Input validation and sanitization
• Restricted target validation  
• Payload safety classification
• Automatic cleanup procedures
• Comprehensive audit logging

⚠️  Ethical Use Warning:
SQL injection testing can potentially damage databases.
Only proceed with explicit written authorization.
```

### **6. Exploitation Module**

**Purpose**: Safe proof-of-concept testing with comprehensive controls

#### **Safety Framework**

**Safety Levels**:
- **SAFE**: Read-only operations, no system impact
- **CAUTIOUS**: Minimal impact, fully reversible
- **MODERATE**: Limited impact, cleanup required
- **DANGEROUS**: Significant impact, use with extreme care
- **CRITICAL**: System-level impact, emergency use only

#### **Exploit Categories**

```
Available Exploit Categories
===========================

Cross-Site Scripting (XSS):
• Reflected XSS testing
• Stored XSS detection  
• DOM-based XSS analysis

Command Injection:
• OS command execution testing
• Safe payload generation
• System information gathering

File Inclusion:
• Local file inclusion (LFI)
• Remote file inclusion (RFI)  
• Path traversal testing

Server-Side Request Forgery (SSRF):
• Internal network probing
• Service enumeration
• Cloud metadata access
```

---

## ⚙️ Configuration Guide

### **Configuration File Structure**

ReconForge uses a JSON configuration file (`config.json`) with hierarchical sections:

```json
{
  "GENERAL": {
    "setup_completed": true,
    "default_scan_timeout": 1800,
    "max_concurrent_scans": 5,
    "auto_cleanup_logs": true,
    "log_retention_days": 30
  },
  "API_KEYS": {
    "shodan": "encrypted_api_key_data",
    "virustotal": "encrypted_api_key_data"
  },
  "TERMINAL": {
    "theme": "hacker",
    "show_banner": true,
    "progress_bars": true
  },
  "PERFORMANCE": {
    "database_wal_mode": true,
    "connection_pool_size": 5,
    "query_timeout": 30
  }
}
```

### **API Key Management**

#### **Configuring API Keys**

```bash
# Method 1: Through ReconForge interface
Main Menu → Configuration → API Keys

# Method 2: Direct configuration editing  
vim config.json

# Method 3: Environment variables
export SHODAN_API_KEY="your_api_key_here"
```

#### **Supported Services**

| Service | Purpose | Free Tier | Rate Limit |
|---------|---------|-----------|------------|
| **Shodan** | Network reconnaissance | 100 queries/month | 1 query/second |
| **VirusTotal** | Malware/reputation checking | 1000 queries/day | 4 queries/minute |
| **SecurityTrails** | DNS intelligence | 50 queries/month | 1 query/second |
| **Censys** | Internet scanning data | 1000 queries/month | 120 queries/hour |

### **Performance Tuning**

#### **Database Optimization**

```json
{
  "PERFORMANCE": {
    "database_wal_mode": true,        // Enable WAL mode for better concurrency
    "connection_pool_size": 5,        // Number of database connections
    "query_timeout": 30,              // Query timeout in seconds
    "batch_size": 1000,              // Batch insert size
    "vacuum_interval": 7              // Days between VACUUM operations
  }
}
```

#### **Scanning Performance**

```json
{
  "SCANNING": {
    "default_threads": 10,            // Default thread count
    "max_threads": 20,               // Maximum threads per module
    "request_timeout": 30,           // HTTP request timeout
    "rate_limit": 100,               // Requests per second
    "retry_attempts": 3,             // Failed request retries
    "backoff_factor": 2.0            // Exponential backoff multiplier
  }
}
```

---

## 📊 Results Management

### **Viewing Results**

#### **Recent Scans**

```
Recent Scans
============

┌──────────────┬─────────────────┬──────────────┬──────────┬─────────────────────┐
│ Scan ID      │ Target          │ Type         │ Status   │ Date                │
├──────────────┼─────────────────┼──────────────┼──────────┼─────────────────────┤
│ scan_001     │ example.com     │ subdomain    │ complete │ 2025-08-29 04:30:15 │
│ scan_002     │ test.com        │ vulnerability│ complete │ 2025-08-29 03:15:42 │
│ scan_003     │ 192.168.1.0/24  │ port_scan    │ running  │ 2025-08-29 04:45:20 │
└──────────────┴─────────────────┴──────────────┴──────────┴─────────────────────┘

Select scan to view details: [1-3]
```

#### **Detailed Results**

```
Scan Details: scan_001
=====================

Target: example.com
Type: Subdomain Discovery  
Status: Completed
Duration: 2m 15s
Started: 2025-08-29 04:30:15
Completed: 2025-08-29 04:32:30

Statistics:
• Total subdomains: 47
• Alive subdomains: 23  
• Sources used: 8
• Technologies detected: 12

Top Findings:
• admin.example.com (401 Unauthorized)
• api.example.com (200 OK - Express.js)
• dev.example.com (403 Forbidden)
```

### **Exporting Results**

#### **Export Formats**

```bash
Export Options
=============

1. JSON          - Machine-readable structured data
2. CSV           - Spreadsheet-compatible format
3. HTML Report   - Formatted web report
4. Text Report   - Simple text format  
5. XML           - Structured markup format

Select format: [1-5]
```

#### **Sample JSON Export**

```json
{
  "scan_metadata": {
    "scan_id": "scan_001",
    "target": "example.com",
    "scan_type": "subdomain_discovery",
    "started_at": "2025-08-29T04:30:15Z",
    "completed_at": "2025-08-29T04:32:30Z",
    "duration_seconds": 135
  },
  "statistics": {
    "total_subdomains": 47,
    "alive_subdomains": 23,
    "sources_used": 8
  },
  "results": [
    {
      "subdomain": "api.example.com",
      "ip_address": "192.168.1.5", 
      "status_code": 200,
      "title": "API Gateway",
      "technologies": ["Express.js", "Node.js"],
      "source": "subfinder"
    }
  ]
}
```

### **Search and Filtering**

#### **Search Interface**

```
Search Results
=============

Search criteria:
□ Target contains: [example.com]
□ Scan type: [subdomain_discovery]  
□ Status: [completed]
□ Date range: [Last 30 days]
□ Severity: [High, Critical]

Advanced filters:
□ Has vulnerabilities
□ Technology detected
□ Specific ports open
□ Response code range

Apply filters: [Enter]
```

---

## ✅ Best Practices

### **Pre-Engagement**

#### **Authorization Checklist**

- ✅ **Written Authorization**: Obtain explicit written permission
- ✅ **Scope Definition**: Clearly define target scope and boundaries
- ✅ **Timeline Agreement**: Establish testing timeframes
- ✅ **Contact Information**: Emergency contacts for all parties
- ✅ **Legal Review**: Ensure compliance with applicable laws
- ✅ **Insurance Coverage**: Verify professional liability coverage

#### **Technical Preparation**

```bash
# Pre-engagement checklist
□ Update ReconForge to latest version
□ Verify tool availability: python3 main.py → tools
□ Configure API keys for enhanced reconnaissance  
□ Test database connectivity and logging
□ Verify network connectivity to targets
□ Prepare secure storage for results
```

### **During Engagement**

#### **Reconnaissance Best Practices**

1. **Start Passive**: Begin with passive reconnaissance to minimize footprint
2. **Gradual Escalation**: Progressively move to more active techniques
3. **Rate Limiting**: Respect target systems with appropriate delays
4. **Documentation**: Maintain detailed logs of all activities
5. **Regular Backups**: Backup results and configurations regularly

#### **Safety Guidelines**

```
Safety Guidelines
================

Rate Limiting:
• Never exceed 100 requests/second without explicit approval
• Use 1-2 second delays for web application testing
• Monitor target system performance during scans

Target Validation:
• Double-check target scope before each scan
• Avoid testing production systems during business hours
• Stop immediately if unauthorized targets detected

Error Handling:
• Stop testing if errors suggest system instability
• Document all errors and unexpected responses  
• Contact target organization if systems appear compromised
```

### **Post-Engagement**

#### **Results Analysis**

1. **Vulnerability Prioritization**: Focus on critical and high-severity findings
2. **False Positive Verification**: Manually verify automated findings
3. **Business Impact Assessment**: Evaluate real-world impact of vulnerabilities
4. **Remediation Planning**: Develop actionable remediation recommendations

#### **Report Generation**

```
Report Structure
===============

Executive Summary:
• High-level findings overview
• Business risk assessment  
• Key recommendations

Technical Findings:
• Detailed vulnerability descriptions
• Proof-of-concept demonstrations
• CVSS scores and risk ratings

Remediation Guidance:
• Specific fixing instructions
• Priority recommendations
• Timeline suggestions

Appendices:
• Scan outputs and raw data
• Tool configurations used
• Methodology documentation
```

---

## 🔧 Troubleshooting

### **Common Issues**

#### **Application Won't Start**

```bash
# Check Python version
python3 --version  # Should be 3.8+

# Verify dependencies
pip3 list | grep rich

# Check file permissions
ls -la main.py  # Should be readable

# Clear configuration
rm config.json && python3 main.py
```

#### **Tools Not Found**

```bash
# Check tool availability
python3 main.py
reconforge> tools

# Install missing tools
sudo apt update && sudo apt install nmap gobuster

# Update PATH
export PATH=$PATH:/usr/local/go/bin

# Verify installation
which nmap subfinder nuclei
```

#### **Database Issues**

```bash
# Check database file
ls -la data/reconforge.db

# Check permissions
chmod 644 data/reconforge.db

# Reset database (WARNING: Deletes all data)
rm data/reconforge.db && python3 main.py
```

#### **Performance Issues**

```bash
# Check system resources
htop  # Monitor CPU and memory usage

# Reduce thread count
vim config.json
# Set "max_threads": 5

# Clear old logs
rm -rf logs/*.log
```

### **Debug Mode**

#### **Enable Verbose Logging**

```bash
# Start with debug logging
python3 main.py --log-level DEBUG

# Monitor logs in real-time
tail -f logs/reconforge_main.log

# Check specific log categories
tail -f logs/tool_execution.log
tail -f logs/database_operations.log
```

### **Getting Help**

#### **Support Resources**

- 📖 **Documentation**: `/docs` directory contains comprehensive guides
- 🐛 **Bug Reports**: GitHub Issues for bug reports and feature requests
- 💬 **Community**: GitHub Discussions for questions and support
- 📧 **Security Issues**: Report security vulnerabilities privately

#### **Diagnostic Information**

```bash
# Generate diagnostic report
python3 main.py --log-level DEBUG > diagnostic.log 2>&1

# System information
python3 -c "
import sys, platform
print(f'Python: {sys.version}')
print(f'Platform: {platform.platform()}')
print(f'Architecture: {platform.architecture()}')
"

# Tool versions
nmap --version
subfinder -version
nuclei -version
```

---

## 🚀 Advanced Usage

### **Custom Wordlists**

#### **Creating Custom Wordlists**

```bash
# Create custom subdomain wordlist
echo "admin
api  
dev
staging
test
backup" > custom_subdomains.txt

# Configure in ReconForge
Configuration → Custom Wordlists → Add Wordlist
```

### **Automation and Scripting**

#### **Batch Scanning**

```bash
# Create target list
echo "target1.com
target2.com
target3.com" > targets.txt

# Batch processing (pseudo-code)
for target in $(cat targets.txt); do
    # ReconForge doesn't have CLI mode yet
    # This would be implemented in future versions
    echo "Scanning $target..."
done
```

### **Integration with Other Tools**

#### **SIEM Integration**

ReconForge logs can be integrated with SIEM systems:

```bash
# Structured JSON logs for SIEM ingestion
tail -f logs/errors_structured.jsonl | logstash -f siem_config.conf

# Splunk Universal Forwarder configuration
# Monitor logs/ directory for automatic ingestion
```

### **Custom Modules Development**

#### **Module Template**

See the [Technical Documentation](TECHNICAL.md) for detailed information on creating custom reconnaissance modules.

---

## 🔒 Security Considerations

### **Ethical Use**

⚠️ **CRITICAL**: ReconForge is designed for **authorized security testing only**

**Legal Requirements**:
- Explicit written authorization for all targets
- Compliance with applicable laws and regulations
- Respect for system owners and users
- Responsible disclosure of vulnerabilities

**Prohibited Uses**:
- Testing systems without permission
- Malicious exploitation of vulnerabilities  
- Denial of service attacks
- Data exfiltration or system compromise

### **Operational Security**

#### **Protecting Your Infrastructure**

- **VPN Usage**: Route traffic through VPN when appropriate
- **Source IP Management**: Rotate source IPs for large engagements
- **Log Security**: Protect reconnaissance logs and results
- **Credential Management**: Secure storage of API keys and credentials

#### **Target System Protection**

- **Rate Limiting**: Avoid overwhelming target systems
- **Business Hours**: Respect target organization schedules
- **Graceful Degradation**: Stop testing if systems show instability
- **Communication**: Maintain open communication with target contacts

---

This user guide provides comprehensive coverage of ReconForge's capabilities and best practices. For technical implementation details, refer to the [Technical Documentation](TECHNICAL.md). For the latest updates and features, check the project's GitHub repository.