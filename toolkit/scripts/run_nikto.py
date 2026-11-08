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


def generate_mock_nikto_json(target_host: str, target_port: int = 80) -> str:
    mock_data = {
        "host": target_host,
        "ip": target_host,
        "port": target_port,
        "banner": "Apache/2.4.49 (Unix)",
        "items": [
            {
                "id": "000001",
                "osvdb": "0",
                "method": "GET",
                "uri": "/",
                "description": "Server leaks version information via 'Server' HTTP header: Apache/2.4.49",
                "severity": "info"
            },
            {
                "id": "000002",
                "osvdb": "0",
                "method": "GET",
                "uri": "/",
                "description": "The anti-clickjacking X-Frame-Options header is not present.",
                "severity": "low"
            },
            {
                "id": "000003",
                "osvdb": "0",
                "method": "GET",
                "uri": "/",
                "description": "The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type.",
                "severity": "low"
            }
        ]
    }
    return json.dumps(mock_data, indent=2)


def run_nikto_scan(
    target_id: str,
    target_url: str,
    target_host: str,
    port: int | None = None,
    output_dir: pathlib.Path | None = None,
    simulate: bool = False,
) -> dict:
    root = REPO_ROOT
    if output_dir is None:
        scan_dir = root / "toolkit" / "04-web" / "scans" / target_id / "nikto"
    else:
        scan_dir = output_dir

    raw_dir = scan_dir / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)
    raw_json_path = raw_dir / "nikto_raw.json"
    commands_log = scan_dir / "commands.md"

    p_val = port or (443 if target_url.startswith("https") else 80)
    cmd_args = f"-host {target_url} -Format json -output {raw_json_path} -Tuning 123b"
    command_str = f"nikto {cmd_args}"

    nikto_bin = shutil.which("nikto")
    if not nikto_bin:
        candidates = [
            r"C:\ProgramData\chocolatey\bin\nikto.bat",
            r"C:\nikto\program\nikto.pl",
        ]
        for c in candidates:
            if os.path.exists(c):
                nikto_bin = c
                break

    force_sim = simulate or (os.getenv("SIMULATE_SCANS", "false").lower() == "true")

    start_time = time.time()
    exit_code = 0
    error_msg = None

    if nikto_bin and not force_sim:
        try:
            cmd = [
                nikto_bin,
                "-host", target_url,
                "-Format", "json",
                "-output", str(raw_json_path),
                "-Tuning", "123b",
            ]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
            exit_code = res.returncode
            if exit_code != 0:
                error_msg = res.stderr
        except Exception as e:
            exit_code = 1
            error_msg = str(e)
    elif force_sim:
        raw_json_path.write_text(generate_mock_nikto_json(target_host, p_val), encoding="utf-8")
    else:
        exit_code = 127
        error_msg = "Nikto binary is not installed in the current environment. Please install nikto or use HTTPx/Nuclei."
        raw_json_path.write_text("{}", encoding="utf-8")

    duration = time.time() - start_time

    append_command_log(
        log_path=commands_log,
        target=target_url,
        tool="nikto",
        command=command_str,
        arguments=cmd_args,
        exit_code=exit_code,
        duration=duration,
        output_path=str(raw_json_path),
        error=error_msg,
    )

    return {
        "tool": "nikto",
        "command": command_str,
        "arguments": cmd_args,
        "exit_code": exit_code,
        "duration": duration,
        "raw_path": str(raw_json_path),
        "commands_log": str(commands_log),
        "error": error_msg,
    }


def main():
    parser = argparse.ArgumentParser(description="AI-Pentest Copilot Nikto Runner")
    parser.add_argument("--target-id", default="target-web", help="Target ID")
    parser.add_argument("--url", required=True, help="Target URL")
    parser.add_argument("--host", default="localhost", help="Host header")
    parser.add_argument("--port", type=int, default=None, help="Port")
    parser.add_argument("--simulate", action="store_true", help="Force test simulation")
    args = parser.parse_args()

    res = run_nikto_scan(
        target_id=args.target_id,
        target_url=args.url,
        target_host=args.host,
        port=args.port,
        simulate=args.simulate,
    )
    print(f"Nikto finished in {res['duration']:.2f}s with exit code {res['exit_code']}")
    print(f"Raw Evidence: {res['raw_path']}")


if __name__ == "__main__":
    main()
