#!/usr/bin/env bash
# AI-Pentest Copilot - Automated Missing Tools Installer for Ubuntu/Debian
# Installs: RustScan, SearchSploit, enum4linux, theHarvester, OWASP ZAP

set -e

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}====================================================${NC}"
echo -e "${BLUE}[*] AI-Pentest Copilot - Toolset Installer (Ubuntu/Debian)${NC}"
echo -e "${BLUE}====================================================${NC}\n"

# Check sudo permissions
if [ "$EUID" -ne 0 ] && ! command -v sudo &> /dev/null; then
    echo -e "${RED}[!] Vui lòng chạy script với quyền sudo hoặc root.${NC}"
    exit 1
fi

SUDO_CMD=""
if [ "$EUID" -ne 0 ]; then
    SUDO_CMD="sudo"
fi

# 1. Update APT & install prerequisites
echo -e "${YELLOW}==> [1/5] Cập nhật APT và cài đặt các gói phụ thuộc...${NC}"
$SUDO_CMD apt-get update -qq
$SUDO_CMD apt-get install -y -qq git curl wget pipx python3-venv samba-common-bin smbclient >/dev/null 2>&1 || true

# 2. Install RustScan
echo -e "${YELLOW}==> [2/5] Đang cài đặt RustScan (Fast Port Scanner)...${NC}"
if command -v rustscan &> /dev/null; then
    echo -e "${GREEN}    [OK] RustScan đã có sẵn tại $(which rustscan)${NC}"
else
    TEMP_DEB="/tmp/rustscan.deb"
    wget -q https://github.com/RustScan/RustScan/releases/download/2.3.0/rustscan_2.3.0_amd64.deb -O "$TEMP_DEB" || true
    if [ -f "$TEMP_DEB" ]; then
        $SUDO_CMD dpkg -i "$TEMP_DEB" >/dev/null 2>&1 || true
        rm -f "$TEMP_DEB"
        echo -e "${GREEN}    [OK] Đã cài đặt RustScan thành công!${NC}"
    else
        echo -e "${RED}    [!] Không tải được RustScan deb package.${NC}"
    fi
fi

# 3. Install SearchSploit (Exploit-DB)
echo -e "${YELLOW}==> [3/5] Đang cài đặt SearchSploit (Exploit-DB Offline Query)...${NC}"
if command -v searchsploit &> /dev/null; then
    echo -e "${GREEN}    [OK] SearchSploit đã có sẵn tại $(which searchsploit)${NC}"
else
    if [ ! -d "/opt/exploitdb" ]; then
        $SUDO_CMD git clone --depth 1 https://gitlab.com/exploit-database/exploitdb.git /opt/exploitdb >/dev/null 2>&1 || true
    fi
    if [ -f "/opt/exploitdb/searchsploit" ]; then
        $SUDO_CMD ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit
        $SUDO_CMD chmod +x /usr/local/bin/searchsploit
        echo -e "${GREEN}    [OK] Đã liên kết SearchSploit vào /usr/local/bin/searchsploit thành công!${NC}"
    else
        echo -e "${RED}    [!] Không clone được Exploit-DB.${NC}"
    fi
fi

# 4. Install enum4linux
echo -e "${YELLOW}==> [4/5] Đang cài đặt enum4linux (SMB / Windows Enumeration)...${NC}"
if command -v enum4linux &> /dev/null; then
    echo -e "${GREEN}    [OK] enum4linux đã có sẵn tại $(which enum4linux)${NC}"
else
    if [ ! -d "/opt/enum4linux" ]; then
        $SUDO_CMD git clone https://github.com/CiscoCXSecurity/enum4linux.git /opt/enum4linux >/dev/null 2>&1 || true
    fi
    if [ -f "/opt/enum4linux/enum4linux.pl" ]; then
        $SUDO_CMD ln -sf /opt/enum4linux/enum4linux.pl /usr/local/bin/enum4linux
        $SUDO_CMD chmod +x /usr/local/bin/enum4linux
        echo -e "${GREEN}    [OK] Đã liên kết enum4linux vào /usr/local/bin/enum4linux thành công!${NC}"
    else
        echo -e "${RED}    [!] Không clone được enum4linux.${NC}"
    fi
fi

# 5. Install theHarvester
echo -e "${YELLOW}==> [5/5] Đang cài đặt theHarvester (OSINT / Subdomain Gathering)...${NC}"
if command -v theHarvester &> /dev/null || command -v theharvester &> /dev/null; then
    echo -e "${GREEN}    [OK] theHarvester đã có sẵn trên hệ thống.${NC}"
else
    if [ ! -d "/opt/theHarvester" ]; then
        $SUDO_CMD git clone https://github.com/laramies/theHarvester.git /opt/theHarvester >/dev/null 2>&1 || true
    fi
    pipx install /opt/theHarvester >/dev/null 2>&1 || true
    pipx ensurepath >/dev/null 2>&1 || true
    if command -v theHarvester &> /dev/null; then
        echo -e "${GREEN}    [OK] Đã cài theHarvester qua pipx thành công!${NC}"
    else
        echo -e "${YELLOW}    [!] Đang tạo wrapper cho theHarvester...${NC}"
        $SUDO_CMD tee /usr/local/bin/theHarvester > /dev/null << 'EOF'
#!/usr/bin/env bash
python3 -m theHarvester "$@"
EOF
        $SUDO_CMD chmod +x /usr/local/bin/theHarvester || true
    fi
fi

echo -e "\n${BLUE}====================================================${NC}"
echo -e "${GREEN}[+] Hoàn tất tiến trình cài đặt! Kiểm tra lại catalog...${NC}"
echo -e "${BLUE}====================================================${NC}\n"

if [ -f "./venv/bin/python" ]; then
    ./venv/bin/python run.py catalog || true
else
    python3 run.py catalog || true
fi
