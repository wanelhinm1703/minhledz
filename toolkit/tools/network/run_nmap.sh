#!/usr/bin/env bash
set -euo pipefail

TARGET="${1:-}"
if [ -z "$TARGET" ]; then
    echo "Usage: $0 <target> [ports]"
    exit 1
fi

python toolkit/scripts/run_nmap.py --target "$TARGET" "${@:2}"
