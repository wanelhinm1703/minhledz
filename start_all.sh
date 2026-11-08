#!/bin/bash
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_ROOT"

if [ ! -d "venv" ] || [ ! -d "frontend/node_modules" ]; then
    echo "[!] Hệ thống chưa được cài đặt. Vui lòng chạy lệnh sau trước:"
    echo "    bash scripts/setup_native.sh"
    exit 1
fi

echo "=========================================================="
echo "  Khởi chạy AI-Pentest Copilot (Backend FastAPI + Frontend Vite)"
echo "=========================================================="

# Trap để tắt cả 2 tiến trình khi bấm Ctrl+C
trap 'echo ""; echo "[*] Đang dừng hệ thống..."; kill $(jobs -p) 2>/dev/null; exit' SIGINT SIGTERM EXIT

source venv/bin/activate

# 1. Bật Backend cổng 8000
echo "[*] Khởi động Backend FastAPI tại http://127.0.0.1:8000 ..."
python run.py dev &
BACKEND_PID=$!

sleep 2

# 2. Bật Frontend Vite cổng 5173
echo "[*] Khởi động Frontend Vite tại http://localhost:5173 ..."
npm --prefix frontend run dev

wait
