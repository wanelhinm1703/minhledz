#!/usr/bin/env bash
# toolkit/scripts/run_pipeline.sh - Multi-tool recon pipeline execution script
set -euo pipefail

TARGET="${1:-}"
if [ -z "$TARGET" ]; then
    echo "Usage: $0 <target> [campaign]"
    echo "Example: $0 http://192.168.56.101:3000"
    exit 1
fi

CAMPAIGN="${2:-lab-local}"
python toolkit/scripts/pipeline_runner.py "$TARGET" --campaign "$CAMPAIGN"
