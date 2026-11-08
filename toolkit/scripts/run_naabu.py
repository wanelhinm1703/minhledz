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


def generate_mock_naabu_output(host: str, port: int | None = None) -> str:
    ports = [port] if port else [80, 443, 3000, 22]
    lines = [f"{host}:{p}" for p in ports]
    return "\n".join(lines) + "\n"


def run_naabu_scan(
    target_id: str,
    target_host: str,
    port: int | None = None,
    output_dir: pathlib.Path | None = None,
    simulate: bool = False,
) -> dict:
    root = pathlib.Path(__file__).resolve().parent.parent.parent
    if output_dir is None:
        scan_dir = root / "toolkit" / "03-network" / "scans" / target_id / "naabu"
    else:
        scan_dir = output_dir

    raw_dir = scan_dir / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)
    raw_output_path = raw_dir / "naabu_raw.txt"
    commands_log = scan_dir / "commands.md"

    port_arg = f"-p {port}" if port else "-top-ports 100"
    cmd_args = f"-host {target_host} {port_arg} -o {raw_output_path}"
    command_str = f"naabu {cmd_args}"

    naabu_bin = shutil.which("naabu")
    force_sim = simulate or (os.getenv("SIMULATE_SCANS", "false").lower() == "true")

    start_time = time.time()
    exit_code = 0
    error_msg = None

    if naabu_bin and not force_sim:
        try:
            cmd = [naabu_bin, "-host", target_host]
            if port:
                cmd.extend(["-p", str(port)])
            else:
                cmd.extend(["-top-ports", "100"])
            cmd.extend(["-o", str(raw_output_path)])
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            exit_code = res.returncode
            if exit_code != 0:
                error_msg = res.stderr
        except Exception as e:
            exit_code = 1
            error_msg = str(e)
            raw_output_path.write_text(generate_mock_naabu_output(target_host, port), encoding="utf-8")
    elif not force_sim:
        # Probe real TCP ports using sockets
        import socket
        import concurrent.futures
        test_ports = [port] if port else [80, 443, 8080, 8000, 3000, 22, 21, 25, 135, 139, 445, 3389, 3306, 5432, 8443]
        open_found = []

        def check_port(p):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.3)
                    if s.connect_ex((target_host, p)) == 0:
                        return p
            except Exception:
                pass
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            results = executor.map(check_port, test_ports)
            for p in results:
                if p is not None:
                    open_found.append(p)

        if open_found:
            lines = [f"{target_host}:{p}" for p in sorted(open_found)]
            raw_output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        else:
            raw_output_path.write_text("", encoding="utf-8")
    else:
        raw_output_path.write_text(generate_mock_naabu_output(target_host, port), encoding="utf-8")

    duration = time.time() - start_time

    append_command_log(
        log_path=commands_log,
        target=target_host,
        tool="naabu",
        command=command_str,
        arguments=cmd_args,
        exit_code=exit_code,
        duration=duration,
        output_path=str(raw_output_path),
        error=error_msg,
    )

    return {
        "tool": "naabu",
        "command": command_str,
        "arguments": cmd_args,
        "exit_code": exit_code,
        "duration": duration,
        "raw_path": str(raw_output_path),
        "commands_log": str(commands_log),
    }


def main():
    parser = argparse.ArgumentParser(description="AI-Pentest Copilot Naabu Runner")
    parser.add_argument("--target-id", default="target-local", help="Target ID")
    parser.add_argument("--host", required=True, help="Target Host/IP")
    parser.add_argument("--port", type=int, default=None, help="Target Port")
    parser.add_argument("--simulate", action="store_true", help="Force simulation")
    args = parser.parse_args()

    res = run_naabu_scan(
        target_id=args.target_id,
        target_host=args.host,
        port=args.port,
        simulate=args.simulate,
    )
    print(f"Naabu completed in {res['duration']:.2f}s with exit code {res['exit_code']}")
    print(f"Raw Evidence: {res['raw_path']}")


if __name__ == "__main__":
    main()
