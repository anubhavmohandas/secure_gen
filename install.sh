#!/bin/bash

# Enhanced Payload Generator Installation Script
# Created by Anubhav Mohandas
# https://github.com/anubhavmohandas

# Color codes for terminal output
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Print banner
echo -e "${BLUE}"
echo "=========================================================="
echo "    Enhanced Secure Payload Generation Framework Setup    "
echo "    Developed by Anubhav Mohandas                        "
echo "=========================================================="
echo -e "${NC}"

# Check if script is run as root
if [ "$EUID" -eq 0 ]; then
  echo -e "${YELLOW}Warning: Running as root. It's recommended to install Python packages as a normal user.${NC}"
  read -p "Continue as root? (y/n): " root_choice
  if [[ ! $root_choice =~ ^[Yy]$ ]]; then
    echo -e "${RED}Installation aborted.${NC}"
    exit 1
  fi
fi

# Check Python version
echo -e "${BLUE}[*] Checking Python version...${NC}"
if command -v python3 &>/dev/null; then
    python_version=$(python3 --version | cut -d " " -f 2)
    echo -e "${GREEN}[+] Python $python_version detected${NC}"
    PYTHON="python3"
elif command -v python &>/dev/null; then
    python_version=$(python --version | cut -d " " -f 2)
    echo -e "${GREEN}[+] Python $python_version detected${NC}"
    PYTHON="python"
else
    echo -e "${RED}[!] Python 3.6+ is required but was not found${NC}"
    echo -e "${YELLOW}[*] Installing Python 3...${NC}"
    
    # Detect OS and install Python accordingly
    if [ -f /etc/debian_version ]; then
        # Debian/Ubuntu
        apt-get update
        apt-get install -y python3 python3-pip python3-venv
    elif [ -f /etc/redhat-release ]; then
        # CentOS/RHEL/Fedora
        yum install -y python3 python3-pip
    elif [ -f /etc/arch-release ]; then
        # Arch Linux
        pacman -Sy python python-pip
    elif [ -f /etc/alpine-release ]; then
        # Alpine
        apk add python3 py3-pip
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS
        if command -v brew &>/dev/null; then
            brew install python3
        else
            echo -e "${RED}[!] Homebrew not found. Please install Python 3 manually.${NC}"
            exit 1
        fi
    else
        echo -e "${RED}[!] Unsupported OS. Please install Python 3.6+ manually.${NC}"
        exit 1
    fi
    
    PYTHON="python3"
fi

# Create virtual environment
echo -e "${BLUE}[*] Creating virtual environment...${NC}"
$PYTHON -m venv env
if [ $? -ne 0 ]; then
    echo -e "${YELLOW}[!] Virtual environment creation failed, trying pip installation...${NC}"
    $PYTHON -m pip install virtualenv
    $PYTHON -m virtualenv env
    if [ $? -ne 0 ]; then
        echo -e "${RED}[!] Failed to create virtual environment. Installing globally...${NC}"
        ENV_ACTIVE=false
    else
        ENV_ACTIVE=true
    fi
else
    ENV_ACTIVE=true
fi

# Activate virtual environment if created
if [ "$ENV_ACTIVE" = true ]; then
    echo -e "${GREEN}[+] Virtual environment created${NC}"
    if [[ "$OSTYPE" == "win32" || "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" ]]; then
        source env/Scripts/activate
    else
        source env/bin/activate
    fi
    echo -e "${GREEN}[+] Virtual environment activated${NC}"
    PIP="pip"
else
    echo -e "${YELLOW}[!] Using global Python installation${NC}"
    PIP="$PYTHON -m pip"
fi

# Upgrade pip
echo -e "${BLUE}[*] Upgrading pip...${NC}"
$PIP install --upgrade pip
echo -e "${GREEN}[+] Pip upgraded${NC}"

# Install requirements
echo -e "${BLUE}[*] Installing required packages...${NC}"
$PIP install -r requirements.txt

# Check installation status
if [ $? -ne 0 ]; then
    echo -e "${RED}[!] Failed to install some dependencies${NC}"
    echo -e "${YELLOW}[*] Trying to install core dependencies individually...${NC}"
    
    # Install core dependencies one by one
    $PIP install prettytable
    $PIP install requests
    $PIP install pycryptodome
    $PIP install click  # For CLI commands
    
    # Check if at least core dependencies were installed
    if [ $? -ne 0 ]; then
        echo -e "${RED}[!] Critical error: Failed to install core dependencies${NC}"
        exit 1
    else
        echo -e "${YELLOW}[!] Core dependencies installed, but some optional dependencies may be missing${NC}"
    fi
else
    echo -e "${GREEN}[+] All dependencies installed successfully${NC}"
fi

# Create payload directory structure
echo -e "${BLUE}[*] Creating payload directories...${NC}"
mkdir -p payloads/{xss,sqli,csrf,ssrf,xxe,rce,lfi,path_traversal,open_redirect,command_injection,ssti,nosql,ldap,xml,deserialization,jwt,oauth,headers,special_chars,file_upload}

echo -e "${GREEN}[+] Payload directories created${NC}"

# Download payload collections from various sources
echo -e "${BLUE}[*] Downloading payload collections...${NC}"

# Function to download payloads
download_payloads() {
    local url=$1
    local destination=$2
    local description=$3
    
    echo -e "${BLUE}[*] Downloading $description...${NC}"
    
    if command -v curl &>/dev/null; then
        curl -s "$url" -o "$destination"
    elif command -v wget &>/dev/null; then
        wget -q "$url" -O "$destination"
    else
        echo -e "${YELLOW}[!] Neither curl nor wget found. Skipping download of $description.${NC}"
        return 1
    fi
    
    if [ -f "$destination" ]; then
        echo -e "${GREEN}[+] $description downloaded successfully${NC}"
        return 0
    else
        echo -e "${YELLOW}[!] Download of $description failed${NC}"
        return 1
    fi
}

# Download various payload collections
download_payloads "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/XSS/XSS-Jhaddix.txt" "payloads/xss/jhaddix.txt" "XSS payloads (Jhaddix)"
download_payloads "https://raw.githubusercontent.com/payloadbox/xss-payload-list/master/Intruder/xss-payload-list.txt" "payloads/xss/payloadbox.txt" "XSS payloads (PayloadBox)"

download_payloads "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/SQLi/Generic-SQLi.txt" "payloads/sqli/generic.txt" "SQL Injection payloads"
download_payloads "https://raw.githubusercontent.com/payloadbox/sql-injection-payload-list/master/Intruder/detect/Generic_ErrorBased.txt" "payloads/sqli/error_based.txt" "SQL Error-based payloads"

download_payloads "https://raw.githubusercontent.com/payloadbox/command-injection-payload-list/master/command-injection-payload-list.txt" "payloads/command_injection/payloads.txt" "Command Injection payloads"

download_payloads "https://raw.githubusercontent.com/payloadbox/rce-payload-list/master/command-execution-payload-list.txt" "payloads/rce/payloads.txt" "RCE payloads"

download_payloads "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/LFI/LFI-Jhaddix.txt" "payloads/lfi/jhaddix.txt" "LFI payloads"

download_payloads "https://raw.githubusercontent.com/payloadbox/xxe-injection-payload-list/master/XXE/XXE-FTP-NETDOC.txt" "payloads/xxe/payloads.txt" "XXE payloads"

download_payloads "https://raw.githubusercontent.com/payloadbox/open-redirect-payload-list/master/Open-Redirect-payloads.txt" "payloads/open_redirect/payloads.txt" "Open Redirect payloads"

download_payloads "https://raw.githubusercontent.com/payloadbox/ssrf-payload-list/master/Intruder/SSRF_Payloads.txt" "payloads/ssrf/payloads.txt" "SSRF payloads"

download_payloads "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Server%20Side%20Template%20Injection/Intruder/ssti.txt" "payloads/ssti/payloads.txt" "SSTI payloads"

download_payloads "https://raw.githubusercontent.com/payloadbox/csv-injection-payload-list/master/CSV-Injection-Payload-List.txt" "payloads/special_chars/csv_injection.txt" "CSV Injection payloads"

download_payloads "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/special-chars.txt" "payloads/special_chars/special_chars.txt" "Special characters"

# Create the payloadfor command utility
echo -e "${BLUE}[*] Creating payloadfor command utility...${NC}"

cat > payloadfor << 'EOF'
#!/bin/bash

# payloadfor - A utility to quickly find payloads for specific vulnerabilities
# Part of Enhanced Secure Payload Generation Framework

# Text colors
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Directory where payloads are stored
PAYLOAD_DIR=$(dirname "$(readlink -f "$0")")/payloads

# Function to display usage
function show_usage {
    echo -e "${BLUE}Usage:${NC} payloadfor <vulnerability_type> [options]"
    echo ""
    echo -e "${BLUE}Available vulnerability types:${NC}"
    
    # Get list of available payload directories
    payload_types=$(ls -1 "$PAYLOAD_DIR" 2>/dev/null | sort)
    
    if [ -z "$payload_types" ]; then
        echo -e "${RED}No payload collections found!${NC}"
    else
        for type in $payload_types; do
            echo -e "  ${GREEN}$type${NC}"
        done
    fi
    
    echo ""
    echo -e "${BLUE}Options:${NC}"
    echo "  -c, --count       Show the count of available payloads"
    echo "  -r, --random      Show a random payload"
    echo "  -l, --limit N     Limit output to N payloads (default: all)"
    echo "  -f, --filter STR  Filter payloads containing STR"
    echo ""
    echo -e "${BLUE}Examples:${NC}"
    echo "  payloadfor xss              # List all XSS payloads"
    echo "  payloadfor sqli --random    # Show a random SQL injection payload"
    echo "  payloadfor rce --limit 5    # Show 5 RCE payloads"
    echo "  payloadfor lfi --filter php # Show LFI payloads containing 'php'"
}

# Check if no arguments provided
if [ $# -eq 0 ]; then
    show_usage
    exit 0
fi

VULNERABILITY_TYPE=$1
shift

# Check if the vulnerability type exists
if [ ! -d "$PAYLOAD_DIR/$VULNERABILITY_TYPE" ]; then
    echo -e "${RED}Error:${NC} Payload collection for '$VULNERABILITY_TYPE' not found."
    echo ""
    show_usage
    exit 1
fi

# Default values
COUNT_ONLY=false
RANDOM_PAYLOAD=false
LIMIT=0
FILTER=""

# Parse options
while [[ $# -gt 0 ]]; do
    case "$1" in
        -c|--count)
            COUNT_ONLY=true
            shift
            ;;
        -r|--random)
            RANDOM_PAYLOAD=true
            shift
            ;;
        -l|--limit)
            LIMIT=$2
            shift 2
            ;;
        -f|--filter)
            FILTER=$2
            shift 2
            ;;
        -h|--help)
            show_usage
            exit 0
            ;;
        *)
            echo -e "${RED}Error:${NC} Unknown option: $1"
            show_usage
            exit 1
            ;;
    esac
done

# Find all payload files for the specified vulnerability type
PAYLOAD_FILES=$(find "$PAYLOAD_DIR/$VULNERABILITY_TYPE" -type f | sort)

if [ -z "$PAYLOAD_FILES" ]; then
    echo -e "${RED}Error:${NC} No payload files found for '$VULNERABILITY_TYPE'."
    exit 1
fi

# Collect all payloads
ALL_PAYLOADS=""
for file in $PAYLOAD_FILES; do
    if [ -f "$file" ]; then
        if [ -z "$ALL_PAYLOADS" ]; then
            ALL_PAYLOADS=$(cat "$file")
        else
            ALL_PAYLOADS="$ALL_PAYLOADS"$'\n'"$(cat "$file")"
        fi
    fi
done

# Apply filter if specified
if [ -n "$FILTER" ]; then
    ALL_PAYLOADS=$(echo "$ALL_PAYLOADS" | grep -i "$FILTER")
fi

# Count payloads
PAYLOAD_COUNT=$(echo "$ALL_PAYLOADS" | grep -v "^$" | wc -l)

# Show count if requested
if [ "$COUNT_ONLY" = true ]; then
    echo -e "${BLUE}Payloads for ${GREEN}$VULNERABILITY_TYPE${NC} (Total: ${GREEN}$PAYLOAD_COUNT${NC})"
    exit 0
fi

# Show random payload if requested
if [ "$RANDOM_PAYLOAD" = true ]; then
    echo -e "${BLUE}Random payload for ${GREEN}$VULNERABILITY_TYPE${NC}:${YELLOW}"
    echo "$ALL_PAYLOADS" | grep -v "^$" | shuf -n 1
    echo -e "${NC}"
    exit 0
fi

# Apply limit if specified
if [ "$LIMIT" -gt 0 ]; then
    echo -e "${BLUE}Payloads for ${GREEN}$VULNERABILITY_TYPE${NC} (Showing ${GREEN}$LIMIT${NC} of ${GREEN}$PAYLOAD_COUNT${NC}):${YELLOW}"
    echo "$ALL_PAYLOADS" | grep -v "^$" | head -n "$LIMIT"
    echo -e "${NC}"
else
    echo -e "${BLUE}Payloads for ${GREEN}$VULNERABILITY_TYPE${NC} (Total: ${GREEN}$PAYLOAD_COUNT${NC}):${YELLOW}"
    echo "$ALL_PAYLOADS" | grep -v "^$"
    echo -e "${NC}"
fi

exit 0
EOF

chmod +x payloadfor

# Create a launcher script
echo -e "${BLUE}[*] Creating launcher scripts...${NC}"
cat > run.sh << 'EOF'
#!/bin/bash
# Launcher for Enhanced Payload Generator

# Activate virtual environment if it exists
if [ -d "env" ]; then
    if [[ "$OSTYPE" == "win32" || "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" ]]; then
        source env/Scripts/activate
    else
        source env/bin/activate
    fi
fi

# Run the payload generator
python payload_generator.py "$@"
EOF

chmod +x run.sh

# Create a symlink to make payloadfor globally accessible
echo -e "${BLUE}[*] Making payloadfor command globally accessible...${NC}"
if [ "$EUID" -eq 0 ]; then
    # If running as root, link to /usr/local/bin
    ln -sf "$(pwd)/payloadfor" /usr/local/bin/payloadfor
    echo -e "${GREEN}[+] payloadfor command linked to /usr/local/bin/payloadfor${NC}"
else
    # If not root, suggest methods to make it accessible
    echo -e "${YELLOW}[!] To make payloadfor globally accessible, do one of the following:${NC}"
    echo -e "   1. Run: ${BLUE}sudo ln -sf $(pwd)/payloadfor /usr/local/bin/payloadfor${NC}"
    echo -e "   2. Add this directory to your PATH: ${BLUE}export PATH=\$PATH:$(pwd)${NC}"
    echo -e "      (Add this to your .bashrc or .zshrc for permanent access)"
fi

# Verify installation
echo -e "${BLUE}[*] Verifying installation...${NC}"
if [ -f requirements.txt ] && [ -d env ] && [ -f run.sh ] && [ -f payloadfor ]; then
    echo -e "${GREEN}[+] Installation verified${NC}"
    echo -e "${GREEN}[+] Enhanced Payload Generator has been successfully installed!${NC}"
    echo ""
    echo -e "${BLUE}To run the generator, use: ${YELLOW}./run.sh${NC}"
    echo -e "${BLUE}To access payloads, use: ${YELLOW}./payloadfor <vulnerability_type>${NC}"
    echo ""
else
    echo -e "${RED}[!] Installation verification failed${NC}"
    echo -e "${YELLOW}[*] Please check for errors and try again${NC}"
fi

# Additional notes
echo -e "${BLUE}Additional Notes:${NC}"
echo -e " - A ${YELLOW}payloads${NC} directory has been created with various vulnerability categories"
echo -e " - Use ${YELLOW}./payloadfor --help${NC} to see all available options"
echo -e " - Run with ${YELLOW}./run.sh --help${NC} for generator command line options"
echo ""
echo -e "${BLUE}Thank you for installing the Enhanced Payload Generator${NC}"
echo -e "${BLUE}Developed by Anubhav Mohandas${NC}"
echo -e "${BLUE}https://github.com/anubhavmohandas${NC}"
