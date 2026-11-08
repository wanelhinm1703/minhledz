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


def generate_mock_masscan_json(host: str, ports: list[int] | None = None) -> str:
    target_ports = ports or [80, 443, 8080]
    records = []
    for p in target_ports:
        records.append({
            "ip": host,
            "timestamp": str(int(time.time())),
            "ports": [
                {"port": p, "proto": "tcp", "status": "open", "reason": "syn-ack", "ttl": 64}
            ]
        })
    return json.dumps(records, indent=2)


def run_masscan_scan(
    target_id: str,
    target_host: str,
    ports: str = "1-1000",
    rate: int = 1000,
    output_dir: pathlib.Path | None = None,
    simulate: bool = False,
) -> dict:
    root = REPO_ROOT
    if output_dir is None:
        scan_dir = root / "toolkit" / "03-network" / "scans" / target_id / "masscan"
    else:
        scan_dir = output_dir

    raw_dir = scan_dir / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)
    raw_json_path = raw_dir / "masscan_raw.json"
    commands_log = scan_dir / "commands.md"

    cmd_args = f"-p{ports} {target_host} --rate {rate} -oJ {raw_json_path}"
    command_str = f"masscan {cmd_args}"

    masscan_bin = shutil.which("masscan")
    if not masscan_bin:
        candidates = [
            r"C:\masscan\masscan.exe",
            r"C:\ProgramData\chocolatey\bin\masscan.exe",
        ]
        for c in candidates:
            if os.path.exists(c):
                masscan_bin = c
                break

    force_sim = simulate or (os.getenv("SIMULATE_SCANS", "false").lower() == "true")

    start_time = time.time()
    exit_code = 0
    error_msg = None

    if masscan_bin and not force_sim:
        try:
            cmd = [
                masscan_bin,
                f"-p{ports}",
                target_host,
                "--rate", str(rate),
                "-oJ", str(raw_json_path),
            ]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
            exit_code = res.returncode
            if exit_code != 0:
                error_msg = res.stderr
        except Exception as e:
            exit_code = 1
            error_msg = str(e)
    elif force_sim:
        parsed_ports = [int(p) for p in ports.split(",") if p.isdigit()] if "," in ports else None
        raw_json_path.write_text(generate_mock_masscan_json(target_host, parsed_ports), encoding="utf-8")
    else:
        exit_code = 127
        error_msg = "Masscan binary is not installed in the current environment. Please install masscan or use Nmap fallback."
        raw_json_path.write_text("[]", encoding="utf-8")

    duration = time.time() - start_time

    append_command_log(
        log_path=commands_log,
        target=target_host,
        tool="masscan",
        command=command_str,
        arguments=cmd_args,
        exit_code=exit_code,
        duration=duration,
        output_path=str(raw_json_path),
        error=error_msg,
    )

    return {
        "tool": "masscan",
        "command": command_str,
        "arguments": cmd_args,
        "exit_code": exit_code,
        "duration": duration,
        "raw_path": str(raw_json_path),
        "commands_log": str(commands_log),
        "error": error_msg,
    }


def main():
    parser = argparse.ArgumentParser(description="AI-Pentest Copilot Masscan Runner")
    parser.add_argument("--target-id", default="target-local", help="Target ID")
    parser.add_argument("--host", required=True, help="Target Host/IP/CIDR")
    parser.add_argument("--ports", default="1-1000", help="Port range (e.g. 1-1000, 80,443)")
    parser.add_argument("--rate", type=int, default=1000, help="Packet rate limit")
    parser.add_argument("--simulate", action="store_true", help="Force test fixture simulation")
    args = parser.parse_args()

    res = run_masscan_scan(
        target_id=args.target_id,
        target_host=args.host,
        ports=args.ports,
        rate=args.rate,
        simulate=args.simulate,
    )
    print(f"Masscan finished in {res['duration']:.2f}s with exit code {res['exit_code']}")
    print(f"Raw Evidence: {res['raw_path']}")


if __name__ == "__main__":
    main()
