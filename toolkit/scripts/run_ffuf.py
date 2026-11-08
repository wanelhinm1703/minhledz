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


def generate_mock_ffuf_json(target_url: str) -> str:
    mock_data = {
        "commandline": f"ffuf -u {target_url}/FUZZ -w wordlist.txt -of json",
        "time": datetime.now(timezone.utc).isoformat(),
        "results": [
            {
                "input": {"FUZZ": "robots.txt"},
                "position": 1,
                "status": 200,
                "length": 64,
                "words": 5,
                "lines": 3,
                "url": f"{target_url.rstrip('/')}/robots.txt",
                "redirectlocation": ""
            },
            {
                "input": {"FUZZ": "login"},
                "position": 2,
                "status": 200,
                "length": 1420,
                "words": 150,
                "lines": 45,
                "url": f"{target_url.rstrip('/')}/login",
                "redirectlocation": ""
            },
            {
                "input": {"FUZZ": "api"},
                "position": 3,
                "status": 301,
                "length": 0,
                "words": 0,
                "lines": 1,
                "url": f"{target_url.rstrip('/')}/api",
                "redirectlocation": f"{target_url.rstrip('/')}/api/"
            }
        ]
    }
    return json.dumps(mock_data, indent=2)


def run_ffuf_scan(
    target_id: str,
    target_url: str,
    wordlist: str | None = None,
    output_dir: pathlib.Path | None = None,
    simulate: bool = False,
) -> dict:
    root = REPO_ROOT
    if output_dir is None:
        scan_dir = root / "toolkit" / "04-web" / "scans" / target_id / "ffuf"
    else:
        scan_dir = output_dir

    raw_dir = scan_dir / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)
    raw_json_path = raw_dir / "ffuf_raw.json"
    commands_log = scan_dir / "commands.md"

    fuzz_url = target_url.rstrip("/") + "/FUZZ"
    wl_path = wordlist or str(root / "toolkit" / "00-meta" / "templates" / "common.txt")
    if not os.path.exists(wl_path):
        temp_wl = raw_dir / "temp_wordlist.txt"
        temp_wl.write_text("login\nadmin\nrobots.txt\napi\nimages\n", encoding="utf-8")
        wl_path = str(temp_wl)

    cmd_args = f"-u {fuzz_url} -w {wl_path} -of json -o {raw_json_path} -s -rate 50"
    command_str = f"ffuf {cmd_args}"

    ffuf_bin = shutil.which("ffuf")
    force_sim = simulate or (os.getenv("SIMULATE_SCANS", "false").lower() == "true")

    start_time = time.time()
    exit_code = 0
    error_msg = None

    if ffuf_bin and not force_sim:
        try:
            cmd = [
                ffuf_bin,
                "-u", fuzz_url,
                "-w", wl_path,
                "-of", "json",
                "-o", str(raw_json_path),
                "-s",
                "-rate", "50",
            ]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            exit_code = res.returncode
            if exit_code != 0:
                error_msg = res.stderr
        except Exception as e:
            exit_code = 1
            error_msg = str(e)
    elif force_sim:
        raw_json_path.write_text(generate_mock_ffuf_json(target_url), encoding="utf-8")
    else:
        exit_code = 127
        error_msg = "FFUF binary is not installed in the current environment. Please install ffuf or use Gobuster/Katana."
        raw_json_path.write_text("{}", encoding="utf-8")

    duration = time.time() - start_time

    append_command_log(
        log_path=commands_log,
        target=target_url,
        tool="ffuf",
        command=command_str,
        arguments=cmd_args,
        exit_code=exit_code,
        duration=duration,
        output_path=str(raw_json_path),
        error=error_msg,
    )

    return {
        "tool": "ffuf",
        "command": command_str,
        "arguments": cmd_args,
        "exit_code": exit_code,
        "duration": duration,
        "raw_path": str(raw_json_path),
        "commands_log": str(commands_log),
        "error": error_msg,
    }


def main():
    parser = argparse.ArgumentParser(description="AI-Pentest Copilot FFUF Runner")
    parser.add_argument("--target-id", default="target-web", help="Target ID")
    parser.add_argument("--url", required=True, help="Target URL")
    parser.add_argument("--wordlist", default=None, help="Wordlist path")
    parser.add_argument("--simulate", action="store_true", help="Force test simulation")
    args = parser.parse_args()

    res = run_ffuf_scan(
        target_id=args.target_id,
        target_url=args.url,
        wordlist=args.wordlist,
        simulate=args.simulate,
    )
    print(f"FFUF finished in {res['duration']:.2f}s with exit code {res['exit_code']}")
    print(f"Raw Evidence: {res['raw_path']}")


if __name__ == "__main__":
    main()
