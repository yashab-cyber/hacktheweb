#!/bin/bash
#
# Quick Start Script for HackTheWeb
# Run your first scan easily
#

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${BLUE}"
cat << "EOF"
╔══════════════════════════════════════════════════════════════════════╗
║                   HackTheWeb Quick Start                              ║
╚══════════════════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

# Check if hacktheweb is installed
if ! command -v hacktheweb &> /dev/null; then
    echo -e "${YELLOW}[!] HackTheWeb not found. Installing...${NC}"
    ./scripts/install.sh
fi

# Activate venv if it exists
if [ -d "venv" ]; then
    source venv/bin/activate
fi

# Example target
echo -e "${GREEN}[+] Running example scan...${NC}"
echo -e "${BLUE}[*] Target: http://testphp.vulnweb.com${NC}"
echo ""

# Run scan
hacktheweb scan http://testphp.vulnweb.com --scan-mode fast --format html

echo ""
echo -e "${GREEN}[+] Scan complete! Check the reports directory.${NC}"
