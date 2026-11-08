#!/bin/bash
set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

echo "=========================================================="
echo "  AI-Pentest Copilot - Automated Native Setup Script"
echo "=========================================================="

echo "[1/4] Kiểm tra các gói hệ thống (cần quyền sudo)..."
if ! command -v npm &> /dev/null || ! python3 -c "import venv" &> /dev/null; then
    echo "[*] Cần cài đặt python3-venv, python3-pip, nodejs, npm, nmap..."
    echo "[*] Vui lòng nhập mật khẩu sudo khi được hỏi:"
    sudo apt update
    sudo apt install -y python3.12-venv python3-pip nodejs npm nmap
else
    echo "[+] Các công cụ hệ thống (python3, node, npm) đã có sẵn."
fi

echo ""
echo "[2/4] Khởi tạo môi trường ảo Python venv mới..."
rm -rf venv
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip setuptools wheel
pip install -r backend/requirements.txt

echo ""
echo "[3/4] Cài đặt dependencies cho Frontend (React + Vite)..."
cd frontend
npm install
cd "$PROJECT_ROOT"

echo ""
echo "=========================================================="
echo " [OK] Cài đặt hoàn tất thành công!"
echo " Để khởi chạy hệ thống, hãy mở 2 Terminal riêng biệt:"
echo ""
echo " Terminal 1 (Backend FastAPI):"
echo "   source venv/bin/activate"
echo "   python run.py dev"
echo ""
echo " Terminal 2 (Frontend Vite):"
echo "   npm --prefix frontend run dev"
echo ""
echo " Sau đó mở trình duyệt tại: http://localhost:5173"
echo "=========================================================="
