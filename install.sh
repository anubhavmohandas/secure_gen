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

# Create dictionaries directory
echo -e "${BLUE}[*] Creating dictionaries directory...${NC}"
mkdir -p dictionaries
echo -e "${GREEN}[+] Dictionaries directory created${NC}"

# Download common wordlists
echo -e "${BLUE}[*] Downloading common wordlists...${NC}"
if command -v curl &>/dev/null; then
    curl -s https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-1000.txt -o dictionaries/common_passwords.txt
    curl -s https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/SQLi/Generic-SQLi.txt -o dictionaries/sql_payloads.txt
    curl -s https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/XSS/XSS-Jhaddix.txt -o dictionaries/xss_payloads.txt
elif command -v wget &>/dev/null; then
    wget -q https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-1000.txt -O dictionaries/common_passwords.txt
    wget -q https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/SQLi/Generic-SQLi.txt -O dictionaries/sql_payloads.txt
    wget -q https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/XSS/XSS-Jhaddix.txt -O dictionaries/xss_payloads.txt
else
    echo -e "${YELLOW}[!] Neither curl nor wget found. Skipping wordlist download.${NC}"
fi

if [ -f dictionaries/common_passwords.txt ]; then
    echo -e "${GREEN}[+] Wordlists downloaded successfully${NC}"
else
    echo -e "${YELLOW}[!] Wordlist download failed or skipped. The tool will use built-in wordlists.${NC}"
fi

# Create a launcher script
echo -e "${BLUE}[*] Creating launcher script...${NC}"
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
echo -e "${GREEN}[+] Launcher script created${NC}"

# Verify installation
echo -e "${BLUE}[*] Verifying installation...${NC}"
if [ -f requirements.txt ] && [ -d env ] && [ -f run.sh ]; then
    echo -e "${GREEN}[+] Installation verified${NC}"
    echo -e "${GREEN}[+] Enhanced Payload Generator has been successfully installed!${NC}"
    echo ""
    echo -e "${BLUE}To run the generator, use: ${YELLOW}./run.sh${NC}"
    echo ""
else
    echo -e "${RED}[!] Installation verification failed${NC}"
    echo -e "${YELLOW}[*] Please check for errors and try again${NC}"
fi

# Additional notes
echo -e "${BLUE}Additional Notes:${NC}"
echo -e " - A ${YELLOW}dictionaries${NC} folder has been created for custom wordlists"
echo -e " - The tool will use built-in wordlists if custom ones are not found"
echo -e " - Run with ${YELLOW}./run.sh --help${NC} for command line options"
echo ""
echo -e "${BLUE}Thank you for installing the Enhanced Payload Generator${NC}"
echo -e "${BLUE}Developed by Anubhav Mohandas${NC}"
echo -e "${BLUE}https://github.com/anubhavmohandas${NC}"
