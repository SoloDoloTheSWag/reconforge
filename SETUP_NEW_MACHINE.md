# Quick Setup - New Machine

> **Quick reference for setting up ReconForge on a new local machine**

## 🚀 Quick Setup Steps

### 1. Clone Repository
```bash
git clone https://github.com/SoloDoloTheSWag/reconforge.git
cd reconforge
```

### 2. Set Up Python Environment
```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate

# Install Python dependencies
pip install -r requirements.txt
```

### 3. Install Security Tools
```bash
# Make installation script executable
chmod +x install.sh

# Run tool installation (requires sudo)
./install.sh

# Verify tool installation
python reconforge.py tools --check
```

### 4. Configuration Setup
```bash
# Copy example config (if it exists)
# cp config.json.example config.json

# Or create basic config.json:
# Add your API keys for enhanced discovery sources
```

### 5. Start ReconForge
```bash
# CLI Usage
python reconforge.py --help

# Web Interface (recommended)
./start_web.sh
# Then open http://localhost:8000
```

## 📋 Prerequisites

**System Requirements:**
- Kali Linux (recommended) or similar pentesting distro
- Python 3.8+
- Go 1.19+ (for Go-based tools)
- 4GB+ RAM, 3GB+ disk space
- Root/sudo access for tool installation

**Manual Tool Installation (if install.sh fails):**
```bash
# Go tools
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/tomnomnom/assetfinder@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest

# System packages
sudo apt install -y nmap sqlmap gobuster nikto hydra
```

## ⚠️ Important Notes

**Security:**
- **Never commit reconnaissance data** - all scan results stay local
- Check `.gitignore` patterns before any commits
- Use `example.com` for testing/documentation only

**Development:**
- Read `CLAUDE.md` for complete framework context
- Follow existing code patterns and security practices
- Test with web interface after making changes

**Troubleshooting:**
```bash
# Verify virtual environment is active
which python  # Should show: /path/to/reconforge/venv/bin/python

# Check tool installation
python reconforge.py tools --check

# View logs if issues occur
tail -f logs/reconforge.log
```

## 🔧 Configuration Files

**Created Automatically:**
- `data/reconforge.db` - SQLite database (excluded from git)
- `logs/` - Application logs (excluded from git)
- `exports/` - Scan results directory (excluded from git)

**Optional Configuration:**
- `config.json` - API keys and advanced settings (excluded from git)
- Custom wordlists and templates

---

**Ready to hack! 🔐** The framework is now set up and ready for authorized penetration testing.