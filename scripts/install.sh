#!/bin/bash
#
# HackTheWeb Installation Script
# Supports Kali Linux, Ubuntu, Debian, and other Linux distributions
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Print functions
print_info() {
    echo -e "${BLUE}[*]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[+]${NC} $1"
}

print_error() {
    echo -e "${RED}[!]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

# Banner
echo -e "${BLUE}"
cat << "EOF"
██╗  ██╗ █████╗  ██████╗██╗  ██╗████████╗██╗  ██╗███████╗██╗    ██╗███████╗██████╗ 
██║  ██║██╔══██╗██╔════╝██║ ██╔╝╚══██╔══╝██║  ██║██╔════╝██║    ██║██╔════╝██╔══██╗
███████║███████║██║     █████╔╝    ██║   ███████║█████╗  ██║ █╗ ██║█████╗  ██████╔╝
██╔══██║██╔══██║██║     ██╔═██╗    ██║   ██╔══██║██╔══╝  ██║███╗██║██╔══╝  ██╔══██╗
██║  ██║██║  ██║╚██████╗██║  ██╗   ██║   ██║  ██║███████╗╚███╔███╔╝███████╗██████╔╝
╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚══════╝ ╚══╝╚══╝ ╚══════╝╚═════╝ 

                    Installation Script v1.0
EOF
echo -e "${NC}"

# Check if running as root
if [ "$EUID" -eq 0 ]; then 
    print_warning "Running as root. This is not recommended for installation."
    read -p "Continue anyway? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Detect OS
print_info "Detecting operating system..."
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$NAME
    VER=$VERSION_ID
    print_success "Detected: $OS $VER"
else
    print_error "Cannot detect OS. Please install manually."
    exit 1
fi

# Check Python version
print_info "Checking Python version..."
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
    PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d. -f1)
    PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d. -f2)
    
    if [ "$PYTHON_MAJOR" -ge 3 ] && [ "$PYTHON_MINOR" -ge 8 ]; then
        print_success "Python $PYTHON_VERSION found"
    else
        print_error "Python 3.8+ required. Found: $PYTHON_VERSION"
        exit 1
    fi
else
    print_error "Python 3 not found. Please install Python 3.8+"
    exit 1
fi

# Install system dependencies
print_info "Installing system dependencies..."
case $OS in
    *"Kali"*|*"Ubuntu"*|*"Debian"*)
        sudo apt-get update -qq
        sudo apt-get install -y -qq \
            python3-pip \
            python3-venv \
            python3-dev \
            build-essential \
            libssl-dev \
            libffi-dev \
            libxml2-dev \
            libxslt1-dev \
            zlib1g-dev \
            nmap \
            git \
            curl \
            wget
        print_success "System dependencies installed"
        ;;
    *"Arch"*)
        sudo pacman -Sy --noconfirm \
            python-pip \
            python-virtualenv \
            base-devel \
            openssl \
            libffi \
            libxml2 \
            libxslt \
            nmap \
            git \
            curl \
            wget
        print_success "System dependencies installed"
        ;;
    *"Fedora"*|*"CentOS"*|*"Red Hat"*)
        sudo dnf install -y \
            python3-pip \
            python3-devel \
            gcc \
            openssl-devel \
            libffi-devel \
            libxml2-devel \
            libxslt-devel \
            nmap \
            git \
            curl \
            wget
        print_success "System dependencies installed"
        ;;
    *)
        print_warning "Unknown OS. Please install dependencies manually."
        ;;
esac

# Create virtual environment (optional)
read -p "Create virtual environment? (recommended) (Y/n) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Nn]$ ]]; then
    print_info "Creating virtual environment..."
    python3 -m venv venv
    source venv/bin/activate
    print_success "Virtual environment created and activated"
    VENV_CREATED=1
else
    VENV_CREATED=0
fi

# Upgrade pip
print_info "Upgrading pip..."
pip install --upgrade pip setuptools wheel

# Install HackTheWeb
print_info "Installing HackTheWeb..."
if [ -f "setup.py" ]; then
    pip install -e .
    print_success "HackTheWeb installed in development mode"
else
    print_error "setup.py not found. Are you in the correct directory?"
    exit 1
fi

# Create necessary directories
print_info "Creating directories..."
mkdir -p config data reports
print_success "Directories created"

# Download wordlists (optional)
read -p "Download common wordlists? (Y/n) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Nn]$ ]]; then
    print_info "Downloading wordlists..."
    
    # Create data directory if it doesn't exist
    mkdir -p data
    
    # Download common wordlists
    if command -v wget &> /dev/null; then
        # XSS payloads
        wget -q -O data/xss_payloads.txt "https://raw.githubusercontent.com/payloadbox/xss-payload-list/master/Intruder/xss-payload-list.txt" || true
        
        # SQL injection payloads
        wget -q -O data/sqli_payloads.txt "https://raw.githubusercontent.com/payloadbox/sql-injection-payload-list/master/Intruder/detect/Generic_SQLI.txt" || true
        
        # Directory wordlist
        wget -q -O data/directories.txt "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt" || true
        
        print_success "Wordlists downloaded"
    else
        print_warning "wget not found. Skipping wordlist download."
    fi
fi

# Create default configuration
print_info "Creating default configuration..."
hacktheweb init-config || python3 -m hacktheweb.cli init-config
print_success "Default configuration created"

# Verify installation
print_info "Verifying installation..."
if hacktheweb --version &> /dev/null || python3 -m hacktheweb.cli --version &> /dev/null; then
    print_success "Installation verified"
else
    print_error "Installation verification failed"
    exit 1
fi

# Print completion message
echo -e "\n${GREEN}"
cat << "EOF"
╔══════════════════════════════════════════════════════════════════════╗
║                   Installation Complete! ✅                           ║
╚══════════════════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

print_info "Quick Start Guide:"
echo ""
echo "  1. Activate virtual environment (if created):"
if [ $VENV_CREATED -eq 1 ]; then
    echo -e "     ${YELLOW}source venv/bin/activate${NC}"
fi
echo ""
echo "  2. Run a basic scan:"
echo -e "     ${YELLOW}hacktheweb scan https://example.com${NC}"
echo ""
echo "  3. Run with custom options:"
echo -e "     ${YELLOW}hacktheweb scan https://example.com --scan-mode thorough --format html${NC}"
echo ""
echo "  4. List available techniques:"
echo -e "     ${YELLOW}hacktheweb list-techniques${NC}"
echo ""
echo "  5. View help:"
echo -e "     ${YELLOW}hacktheweb --help${NC}"
echo ""

print_warning "Important Notes:"
echo "  • Always get permission before scanning"
echo "  • Use responsibly and ethically"
echo "  • Review the documentation for advanced usage"
echo ""

print_info "For more information, visit: https://github.com/yashab-cyber/hacktheweb"
echo ""
