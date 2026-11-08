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


def generate_mock_gobuster_output() -> str:
    return """/login                (Status: 200) [Size: 1420]
/admin                (Status: 403) [Size: 284]
/robots.txt           (Status: 200) [Size: 64]
/api                  (Status: 301) [Size: 0] [--> /api/]
"""


def run_gobuster_scan(
    target_id: str,
    target_url: str,
    wordlist: str | None = None,
    mode: str = "dir",
    output_dir: pathlib.Path | None = None,
    simulate: bool = False,
) -> dict:
    root = REPO_ROOT
    if output_dir is None:
        scan_dir = root / "toolkit" / "04-web" / "scans" / target_id / "gobuster"
    else:
        scan_dir = output_dir

    raw_dir = scan_dir / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)
    raw_txt_path = raw_dir / "gobuster_raw.txt"
    commands_log = scan_dir / "commands.md"

    # Default fallback small wordlist if none provided
    wl_path = wordlist or str(root / "toolkit" / "00-meta" / "templates" / "common.txt")
    if not os.path.exists(wl_path):
        # Create a basic safe fallback wordlist
        temp_wl = raw_dir / "temp_wordlist.txt"
        temp_wl.write_text("login\nadmin\nrobots.txt\napi\nimages\nstatic\n", encoding="utf-8")
        wl_path = str(temp_wl)

    cmd_args = f"{mode} -u {target_url} -w {wl_path} -o {raw_txt_path} --no-error"
    command_str = f"gobuster {cmd_args}"

    gobuster_bin = shutil.which("gobuster")
    force_sim = simulate or (os.getenv("SIMULATE_SCANS", "false").lower() == "true")

    start_time = time.time()
    exit_code = 0
    error_msg = None

    if gobuster_bin and not force_sim:
        try:
            cmd = [
                gobuster_bin,
                mode,
                "-u", target_url,
                "-w", wl_path,
                "-o", str(raw_txt_path),
                "--no-error",
            ]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            exit_code = res.returncode
            if exit_code != 0:
                error_msg = res.stderr
        except Exception as e:
            exit_code = 1
            error_msg = str(e)
    elif force_sim:
        raw_txt_path.write_text(generate_mock_gobuster_output(), encoding="utf-8")
    else:
        exit_code = 127
        error_msg = "Gobuster binary is not installed in the current environment. Please install gobuster or use Katana/FFUF."
        raw_txt_path.write_text(error_msg, encoding="utf-8")

    duration = time.time() - start_time

    append_command_log(
        log_path=commands_log,
        target=target_url,
        tool="gobuster",
        command=command_str,
        arguments=cmd_args,
        exit_code=exit_code,
        duration=duration,
        output_path=str(raw_txt_path),
        error=error_msg,
    )

    return {
        "tool": "gobuster",
        "command": command_str,
        "arguments": cmd_args,
        "exit_code": exit_code,
        "duration": duration,
        "raw_path": str(raw_txt_path),
        "commands_log": str(commands_log),
        "error": error_msg,
    }


def main():
    parser = argparse.ArgumentParser(description="AI-Pentest Copilot Gobuster Runner")
    parser.add_argument("--target-id", default="target-web", help="Target ID")
    parser.add_argument("--url", required=True, help="Target URL")
    parser.add_argument("--mode", default="dir", help="Gobuster mode (dir, dns)")
    parser.add_argument("--wordlist", default=None, help="Wordlist path")
    parser.add_argument("--simulate", action="store_true", help="Force test simulation")
    args = parser.parse_args()

    res = run_gobuster_scan(
        target_id=args.target_id,
        target_url=args.url,
        wordlist=args.wordlist,
        mode=args.mode,
        simulate=args.simulate,
    )
    print(f"Gobuster finished in {res['duration']:.2f}s with exit code {res['exit_code']}")
    print(f"Raw Evidence: {res['raw_path']}")


if __name__ == "__main__":
    main()
