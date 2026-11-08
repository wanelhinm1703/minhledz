#!/usr/bin/env bash
# ==============================================================================
# AI-Pentest Copilot - One-Click Launcher for Kali Linux
# ==============================================================================
set -e

GREEN="\033[1;32m"
CYAN="\033[1;36m"
YELLOW="\033[1;33m"
RED="\033[1;31m"
RESET="\033[0m"

echo -e "${CYAN}"
echo "  ___   ___      ____            _            _        ____                 _ _       _   "
echo " / _ \ |_ _|    |  _ \ ___ _ __ | |_ ___  ___| |_     / ___|___  _ __  ___ | (_) ___ | |_ "
echo "| |_| | | |_____| |_) / _ \ '_ \| __/ _ \/ __| __|   | |   / _ \| '_ \|_  \| | |/ _ \| __|"
echo "|  _  | | |_____|  __/  __/ | | | ||  __/\__ \ |_    | |__| (_) | |_) | |/ / | | (_) | |_ "
echo "|_| |_|___|     |_|   \___|_| |_|\__\___||___/\__|    \____\___/| .__/ |___/|_|_|\___/ \__|"
echo "                                                                |_|                        "
echo -e "${RESET}"
echo -e "${GREEN}[*] Starting AI-Pentest Copilot on Kali Linux...${RESET}"

# 1. Check & Install Essential Kali Packages
echo -e "${CYAN}[1/4] Checking system dependencies...${RESET}"
MISSING_PKGS=()

for pkg in python3 python3-pip python3-venv nodejs npm git curl nmap; do
    if ! command -v "$pkg" &>/dev/null; then
        MISSING_PKGS+=("$pkg")
    fi
done

if [ ${#MISSING_PKGS[@]} -gt 0 ]; then
    echo -e "${YELLOW}[!] Missing packages: ${MISSING_PKGS[*]}. Installing with apt...${RESET}"
    sudo apt update
    sudo apt install -y "${MISSING_PKGS[@]}"
else
    echo -e "${GREEN}[+] System dependencies verified.${RESET}"
fi

# Kill any dangling background uvicorn/vite processes on ports 8000/5173
echo -e "${CYAN}[*] Checking and freeing ports 8000 & 5173...${RESET}"
fuser -k 8000/tcp 2>/dev/null || true
fuser -k 5173/tcp 2>/dev/null || true
pkill -f "uvicorn backend.app.main:app" 2>/dev/null || true

# 2. Setup Python Virtual Environment
echo -e "${CYAN}[2/4] Setting up Python virtual environment...${RESET}"
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$PROJECT_ROOT/venv"
PYTHON_BIN="$VENV_DIR/bin/python3"
PIP_BIN="$VENV_DIR/bin/pip"

# Detect if venv was moved from another directory (e.g. Desktop or Windows)
if [ -d "$VENV_DIR" ] && [ -f "$VENV_DIR/bin/activate" ]; then
    if ! grep -q "$PROJECT_ROOT" "$VENV_DIR/bin/activate" 2>/dev/null; then
        echo -e "${YELLOW}[!] Detected venv moved from another directory. Rebuilding venv...${RESET}"
        rm -rf "$VENV_DIR"
    fi
fi

if [ ! -d "$VENV_DIR" ]; then
    python3 -m venv "$VENV_DIR"
    echo -e "${GREEN}[+] Created virtual environment in ./venv${RESET}"
fi

"$PIP_BIN" install --upgrade pip -q
"$PIP_BIN" install -r "$PROJECT_ROOT/backend/requirements.txt" -q
"$PYTHON_BIN" "$PROJECT_ROOT/run.py" setup

# 3. Setup Frontend Dependencies & Fix Execution Permissions
echo -e "${CYAN}[3/4] Preparing Frontend Web IDE (Linux native)...${RESET}"
cd frontend

# Detect if node_modules was copied from Windows (contains node.exe references)
if grep -q "node.exe" node_modules/.bin/vite 2>/dev/null; then
    echo -e "${YELLOW}[!] Detected Windows-formatted node_modules (node.exe). Purging for Linux...${RESET}"
    rm -rf node_modules package-lock.json
fi

# Fix permissions if files were copied from Windows
chmod -R 755 node_modules/.bin 2>/dev/null || true

# Check if vite can run; if not or missing, install cleanly on Kali
if [ ! -d "node_modules" ] || ! node node_modules/vite/bin/vite.js --version &>/dev/null; then
    echo -e "${YELLOW}[*] Installing Linux-native npm packages for Kali (takes ~30s)...${RESET}"
    rm -rf node_modules package-lock.json
    npm install
    chmod -R 755 node_modules/.bin 2>/dev/null || true
fi

cd ..

# 4. Get Kali Linux IP Address
KALI_IP=$(hostname -I | awk '{print $1}')
if [ -z "$KALI_IP" ]; then
    KALI_IP="127.0.0.1"
fi

# Cleanup on exit (Ctrl+C)
cleanup() {
    echo -e "\n${YELLOW}[*] Shutting down AI-Pentest Copilot services...${RESET}"
    kill $(jobs -p) 2>/dev/null || true
    echo -e "${GREEN}[+] All services stopped.${RESET}"
    exit 0
}
trap cleanup SIGINT SIGTERM

# 5. Launch Backend & Frontend
echo -e "${CYAN}[4/4] Launching Backend & Frontend services...${RESET}"

# Launch FastAPI Backend
"$PYTHON_BIN" -m uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --reload &
BACKEND_PID=$!

# Launch React Vite Frontend directly via node to prevent 'vite: Permission denied'
cd frontend
chmod -R 755 node_modules/.bin 2>/dev/null || true
if [ -f "node_modules/vite/bin/vite.js" ]; then
    node node_modules/vite/bin/vite.js --host 0.0.0.0 --port 5173 &
else
    npx vite --host 0.0.0.0 --port 5173 &
fi
FRONTEND_PID=$!
cd ..

sleep 3

echo -e "\n${GREEN}================================================================${RESET}"
echo -e "${GREEN}✨ AI-Pentest Copilot is LIVE on Kali Linux!${RESET}"
echo -e "${GREEN}================================================================${RESET}"
echo -e "  🌐 Web IDE (Trong Kali):     ${CYAN}http://localhost:5173${RESET}"
echo -e "  🌐 Web IDE (Từ máy Windows): ${CYAN}http://${KALI_IP}:5173${RESET}"
echo -e "  📘 Backend API & Swagger:   ${CYAN}http://${KALI_IP}:8000/docs${RESET}"
echo -e "  🛡️ Kali Native Tools:       ${CYAN}Active & Directly Available (Local Execution)${RESET}"
echo -e "${GREEN}================================================================${RESET}"
echo -e "${YELLOW}[*] Press Ctrl + C to stop both services.${RESET}\n"

wait
