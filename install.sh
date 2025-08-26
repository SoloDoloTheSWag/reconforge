#!/bin/bash

# ReconForge Tool Installation Script
# This script installs all required penetration testing tools for Kali Linux

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}[INFO]${NC} Starting ReconForge tool installation..."

# Update package list
echo -e "${BLUE}[INFO]${NC} Updating package repositories..."
sudo apt update

# Install Go (required for several tools)
if ! command -v go &> /dev/null; then
    echo -e "${YELLOW}[INSTALL]${NC} Installing Go..."
    wget -q https://go.dev/dl/go1.21.6.linux-amd64.tar.gz -O /tmp/go.tar.gz
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf /tmp/go.tar.gz
    echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.bashrc
    export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
    rm /tmp/go.tar.gz
else
    echo -e "${GREEN}[OK]${NC} Go is already installed"
fi

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to install Go-based tools
install_go_tool() {
    local tool_name="$1"
    local install_path="$2"
    
    if ! command_exists "$tool_name"; then
        echo -e "${YELLOW}[INSTALL]${NC} Installing $tool_name..."
        go install -v "$install_path@latest"
    else
        echo -e "${GREEN}[OK]${NC} $tool_name is already installed"
    fi
}

# Install subfinder
install_go_tool "subfinder" "github.com/projectdiscovery/subfinder/v2/cmd/subfinder"

# Install assetfinder
install_go_tool "assetfinder" "github.com/tomnomnom/assetfinder"

# Install amass
install_go_tool "amass" "github.com/owasp-amass/amass/v4/cmd/amass"

# Install shuffledns
install_go_tool "shuffledns" "github.com/projectdiscovery/shuffledns/cmd/shuffledns"

# Install nuclei
install_go_tool "nuclei" "github.com/projectdiscovery/nuclei/v3/cmd/nuclei"

# Install subzy
install_go_tool "subzy" "github.com/lukasikic/subzy"

# Install httpx
install_go_tool "httpx" "github.com/projectdiscovery/httpx/cmd/httpx"

# Update nuclei templates
if command_exists nuclei; then
    echo -e "${BLUE}[INFO]${NC} Updating nuclei templates..."
    nuclei -update-templates -silent || true
fi

# Install system packages
echo -e "${BLUE}[INFO]${NC} Installing system packages..."
sudo apt install -y \
    nmap \
    sqlmap \
    wkhtmltopdf \
    dig \
    whois \
    curl \
    wget \
    git \
    python3-pip \
    python3-venv \
    dnsutils \
    masscan \
    nikto \
    gobuster \
    dirb \
    wfuzz \
    hydra \
    john \
    hashcat \
    metasploit-framework \
    exploitdb \
    searchsploit

# Install additional reconnaissance tools
echo -e "${BLUE}[INFO]${NC} Installing additional tools..."

# Install waybackurls
install_go_tool "waybackurls" "github.com/tomnomnom/waybackurls"

# Install gau (GetAllUrls)
install_go_tool "gau" "github.com/lc/gau/v2/cmd/gau"

# Install subjack
install_go_tool "subjack" "github.com/haccer/subjack"

# Install aquatone (if not already installed)
if ! command_exists aquatone; then
    echo -e "${YELLOW}[INSTALL]${NC} Installing aquatone..."
    wget -q https://github.com/michenriksen/aquatone/releases/download/v1.7.0/aquatone_linux_amd64_1.7.0.zip -O /tmp/aquatone.zip
    cd /tmp && unzip -q aquatone.zip
    sudo mv aquatone /usr/local/bin/
    sudo chmod +x /usr/local/bin/aquatone
    rm /tmp/aquatone.zip
else
    echo -e "${GREEN}[OK]${NC} Aquatone is already installed"
fi

# Install dirsearch
if [ ! -d "/opt/dirsearch" ]; then
    echo -e "${YELLOW}[INSTALL]${NC} Installing dirsearch..."
    sudo git clone https://github.com/maurosoria/dirsearch.git /opt/dirsearch
    sudo chmod +x /opt/dirsearch/dirsearch.py
    sudo ln -sf /opt/dirsearch/dirsearch.py /usr/local/bin/dirsearch
else
    echo -e "${GREEN}[OK]${NC} Dirsearch is already installed"
fi

# Install SecLists wordlists
if [ ! -d "/opt/SecLists" ]; then
    echo -e "${YELLOW}[INSTALL]${NC} Installing SecLists wordlists..."
    sudo git clone https://github.com/danielmiessler/SecLists.git /opt/SecLists
else
    echo -e "${GREEN}[OK]${NC} SecLists is already installed"
fi

# Create tool configuration directories
mkdir -p ~/.config/subfinder
mkdir -p ~/.config/amass
mkdir -p ~/.config/nuclei

# Create basic subfinder config with API keys placeholder
cat > ~/.config/subfinder/config.yaml << EOF
# Subfinder Configuration
# Add your API keys here for better results

# API Keys (uncomment and add your keys)
# virustotal: []
# passivetotal: []
# securitytrails: []
# censys: []
# binaryedge: []
# shodan: []
# github: []
# intelx: []
EOF

# Create basic amass config
cat > ~/.config/amass/config.ini << EOF
# Amass Configuration
# Add your API keys and data sources here

[scope]
# Example: google.com,example.com

[graphdbs]
# local_database = amass.sqlite

[data_sources]
# Add data source configurations here
EOF

echo -e "${GREEN}[SUCCESS]${NC} Tool installation completed!"
echo -e "${BLUE}[INFO]${NC} Installed tools:"
echo "  - subfinder (subdomain enumeration)"
echo "  - assetfinder (subdomain enumeration)"
echo "  - amass (subdomain enumeration)"
echo "  - shuffledns (DNS resolution)"
echo "  - nuclei (vulnerability scanner)"
echo "  - subzy (subdomain takeover)"
echo "  - httpx (HTTP toolkit)"
echo "  - nmap (network scanner)"
echo "  - sqlmap (SQL injection)"
echo "  - waybackurls (URL discovery)"
echo "  - gau (URL discovery)"
echo "  - subjack (subdomain takeover)"
echo "  - aquatone (HTTP screenshot)"
echo "  - dirsearch (directory brute force)"
echo "  - And many more..."

echo -e "${YELLOW}[NOTE]${NC} Please add API keys to ~/.config/subfinder/config.yaml for better results"
echo -e "${YELLOW}[NOTE]${NC} Restart your terminal or run 'source ~/.bashrc' to update PATH"
echo -e "${GREEN}[READY]${NC} ReconForge is ready to use!"