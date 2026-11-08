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


def generate_mock_rustscan_output(host: str, ports: list[int] | None = None) -> str:
    target_ports = ports or [80, 443, 8080]
    ports_str = ",".join(str(p) for p in target_ports)
    return f"""[~] RustScan - The Modern Day Port Scanner.
Real test fixture simulation.

Open {host}:80
Open {host}:443
Open {host}:8080
[~] The ports {ports_str} are open!
"""


def run_rustscan_scan(
    target_id: str,
    target_host: str,
    ports: str | None = None,
    output_dir: pathlib.Path | None = None,
    simulate: bool = False,
) -> dict:
    root = REPO_ROOT
    if output_dir is None:
        scan_dir = root / "toolkit" / "03-network" / "scans" / target_id / "rustscan"
    else:
        scan_dir = output_dir

    raw_dir = scan_dir / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)
    raw_txt_path = raw_dir / "rustscan_raw.txt"
    commands_log = scan_dir / "commands.md"

    port_arg = f"-p {ports}" if ports else "--top"
    cmd_args = f"-a {target_host} {port_arg} --accessible"
    command_str = f"rustscan {cmd_args}"

    rustscan_bin = shutil.which("rustscan")
    if not rustscan_bin:
        candidates = [
            r"C:\rustscan\rustscan.exe",
            os.path.expanduser(r"~\.cargo\bin\rustscan.exe"),
        ]
        for c in candidates:
            if os.path.exists(c):
                rustscan_bin = c
                break

    force_sim = simulate or (os.getenv("SIMULATE_SCANS", "false").lower() == "true")

    start_time = time.time()
    exit_code = 0
    error_msg = None

    if rustscan_bin and not force_sim:
        try:
            cmd = [rustscan_bin, "-a", target_host, "--accessible"]
            if ports:
                cmd.extend(["-p", ports])
            else:
                cmd.append("--top")

            res = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            exit_code = res.returncode
            raw_txt_path.write_text(res.stdout + "\n" + res.stderr, encoding="utf-8")
            if exit_code != 0:
                error_msg = res.stderr
        except Exception as e:
            exit_code = 1
            error_msg = str(e)
            raw_txt_path.write_text(f"Error: {e}", encoding="utf-8")
    elif force_sim:
        parsed_ports = [int(p) for p in ports.split(",") if p.isdigit()] if ports else None
        raw_txt_path.write_text(generate_mock_rustscan_output(target_host, parsed_ports), encoding="utf-8")
    else:
        exit_code = 127
        error_msg = "RustScan binary is not installed in the current environment. Please install rustscan or use Nmap fallback."
        raw_txt_path.write_text(error_msg, encoding="utf-8")

    duration = time.time() - start_time

    append_command_log(
        log_path=commands_log,
        target=target_host,
        tool="rustscan",
        command=command_str,
        arguments=cmd_args,
        exit_code=exit_code,
        duration=duration,
        output_path=str(raw_txt_path),
        error=error_msg,
    )

    return {
        "tool": "rustscan",
        "command": command_str,
        "arguments": cmd_args,
        "exit_code": exit_code,
        "duration": duration,
        "raw_path": str(raw_txt_path),
        "commands_log": str(commands_log),
        "error": error_msg,
    }


def main():
    parser = argparse.ArgumentParser(description="AI-Pentest Copilot RustScan Runner")
    parser.add_argument("--target-id", default="target-local", help="Target ID")
    parser.add_argument("--host", required=True, help="Target Host/IP")
    parser.add_argument("--ports", default=None, help="Ports to scan (e.g. 80,443)")
    parser.add_argument("--simulate", action="store_true", help="Force simulation fixture")
    args = parser.parse_args()

    res = run_rustscan_scan(
        target_id=args.target_id,
        target_host=args.host,
        ports=args.ports,
        simulate=args.simulate,
    )
    print(f"RustScan finished in {res['duration']:.2f}s with exit code {res['exit_code']}")
    print(f"Raw Evidence: {res['raw_path']}")


if __name__ == "__main__":
    main()
