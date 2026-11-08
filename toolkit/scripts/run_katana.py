#!/usr/bin/env python3
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
import pathlib
import shutil
import subprocess
import sys
import time

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from toolkit.scripts.run_nmap import append_command_log


def generate_mock_katana_jsonl(target_url: str) -> str:
    endpoints = [
        {"request": {"endpoint": target_url, "method": "GET", "tag": "a", "attribute": "href"}, "source": "crawler"},
        {"request": {"endpoint": f"{target_url.rstrip('/')}/login", "method": "GET", "tag": "form", "attribute": "action"}, "source": "crawler"},
        {"request": {"endpoint": f"{target_url.rstrip('/')}/api/v1/status", "method": "GET", "tag": "script", "attribute": "src"}, "source": "crawler"},
        {"request": {"endpoint": f"{target_url.rstrip('/')}/assets/main.js", "method": "GET", "tag": "script", "attribute": "src"}, "source": "crawler"},
    ]
    return "\n".join(json.dumps(e) for e in endpoints) + "\n"


def run_katana_scan(
    target_id: str,
    target_url: str,
    depth: int = 2,
    output_dir: pathlib.Path | None = None,
    simulate: bool = False,
) -> dict:
    root = REPO_ROOT
    if output_dir is None:
        scan_dir = root / "toolkit" / "04-web" / "scans" / target_id / "katana"
    else:
        scan_dir = output_dir

    raw_dir = scan_dir / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)
    raw_jsonl_path = raw_dir / "katana_raw.jsonl"
    commands_log = scan_dir / "commands.md"

    cmd_args = f"-u {target_url} -d {depth} -rate-limit 50 -jsonl -o {raw_jsonl_path}"
    command_str = f"katana {cmd_args}"

    katana_bin = shutil.which("katana")
    force_sim = simulate or (os.getenv("SIMULATE_SCANS", "false").lower() == "true")

    start_time = time.time()
    exit_code = 0
    error_msg = None

    if katana_bin and not force_sim:
        try:
            cmd = [
                katana_bin,
                "-u", target_url,
                "-d", str(depth),
                "-rate-limit", "50",
                "-jsonl",
                "-o", str(raw_jsonl_path),
            ]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
            exit_code = res.returncode
            if exit_code != 0:
                error_msg = res.stderr
        except Exception as e:
            exit_code = 1
            error_msg = str(e)
    elif force_sim:
        raw_jsonl_path.write_text(generate_mock_katana_jsonl(target_url), encoding="utf-8")
    else:
        exit_code = 127
        error_msg = "Katana binary is not installed in the current environment. Please install katana or use HTTPx/Gobuster."
        raw_jsonl_path.write_text("", encoding="utf-8")

    duration = time.time() - start_time

    append_command_log(
        log_path=commands_log,
        target=target_url,
        tool="katana",
        command=command_str,
        arguments=cmd_args,
        exit_code=exit_code,
        duration=duration,
        output_path=str(raw_jsonl_path),
        error=error_msg,
    )

    return {
        "tool": "katana",
        "command": command_str,
        "arguments": cmd_args,
        "exit_code": exit_code,
        "duration": duration,
        "raw_path": str(raw_jsonl_path),
        "commands_log": str(commands_log),
        "error": error_msg,
    }


def main():
    parser = argparse.ArgumentParser(description="AI-Pentest Copilot Katana Runner")
    parser.add_argument("--target-id", default="target-web", help="Target ID")
    parser.add_argument("--url", required=True, help="Target URL")
    parser.add_argument("--depth", type=int, default=2, help="Crawling depth")
    parser.add_argument("--simulate", action="store_true", help="Force test simulation")
    args = parser.parse_args()

    res = run_katana_scan(
        target_id=args.target_id,
        target_url=args.url,
        depth=args.depth,
        simulate=args.simulate,
    )
    print(f"Katana finished in {res['duration']:.2f}s with exit code {res['exit_code']}")
    print(f"Raw Evidence: {res['raw_path']}")


if __name__ == "__main__":
    main()
