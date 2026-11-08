#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import pathlib
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from toolkit.scripts.run_nmap import append_command_log
from toolkit.scripts.scan_status import create_scan_status, save_scan_status


def generate_mock_masscan_json(host: str, ports: list[int] | None = None) -> str:
    target_ports = ports or [80, 443, 8080]
    records = []
    for p in target_ports:
        records.append(
            {
                "ip": host,
                "timestamp": str(int(time.time())),
                "ports": [
                    {
                        "port": p,
                        "proto": "tcp",
                        "status": "open",
                        "reason": "syn-ack",
                        "ttl": 64,
                    }
                ],
            }
        )
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
    simulated_dir = scan_dir / "simulated"
    commands_log = scan_dir / "commands.md"

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

    started_at = datetime.now(timezone.utc).isoformat()
    start_time = time.time()
    exit_code = 0
    error_msg = None
    reason = None
    warnings = []
    errors = []
    mode = "real"
    actual_file_path: pathlib.Path | None = None
    rel_raw_path: str | None = None
    finding_count = 0

    if masscan_bin and not force_sim:
        raw_dir.mkdir(parents=True, exist_ok=True)
        raw_json_path = raw_dir / "masscan_raw.json"
        actual_file_path = raw_json_path
        rel_raw_path = "raw/masscan_raw.json"
        cmd_args = f"-p{ports} {target_host} --rate {rate} -oJ {raw_json_path}"
        command_str = f"masscan {cmd_args}"

        try:
            cmd = [
                masscan_bin,
                f"-p{ports}",
                target_host,
                "--rate",
                str(rate),
                "-oJ",
                str(raw_json_path),
            ]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
            exit_code = res.returncode
            if exit_code != 0:
                mode = "failed"
                error_msg = res.stderr or f"Exit code {exit_code}"
                errors.append(error_msg)
                reason = "execution_error"
            else:
                mode = "real"
                if raw_json_path.exists():
                    try:
                        data = json.loads(raw_json_path.read_text(encoding="utf-8"))
                        finding_count = len(data) if isinstance(data, list) else 0
                    except Exception:
                        pass
        except subprocess.TimeoutExpired:
            mode = "failed"
            exit_code = 124
            reason = "timeout"
            error_msg = "Masscan timed out after 180 seconds."
            errors.append(error_msg)
        except Exception as e:
            mode = "failed"
            exit_code = 1
            reason = "execution_error"
            error_msg = str(e)
            errors.append(error_msg)
    elif force_sim:
        simulated_dir.mkdir(parents=True, exist_ok=True)
        sim_json_path = simulated_dir / "masscan_raw.json"
        parsed_ports = (
            [int(p) for p in ports.split(",") if p.isdigit()] if "," in ports else None
        )
        sim_json_path.write_text(
            generate_mock_masscan_json(target_host, parsed_ports), encoding="utf-8"
        )
        actual_file_path = sim_json_path
        rel_raw_path = "simulated/masscan_raw.json"
        mode = "simulated"
        reason = "binary_not_found" if not masscan_bin else None
        exit_code = 0
        finding_count = len(parsed_ports) if parsed_ports else 3
        warnings.append("Simulated scan results. Not genuine evidence.")
        cmd_args = f"-p{ports} {target_host} [SIMULATED]"
        command_str = f"masscan {cmd_args}"
    else:
        mode = "failed"
        reason = "binary_not_found"
        exit_code = 127
        error_msg = "Masscan binary is not installed in the current environment. Please install masscan or use Nmap."
        errors.append(error_msg)
        actual_file_path = None
        rel_raw_path = None
        cmd_args = f"-p{ports} {target_host} [BINARY NOT FOUND]"
        command_str = f"masscan {cmd_args}"

    duration = time.time() - start_time
    finished_at = datetime.now(timezone.utc).isoformat()

    status = create_scan_status(
        tool="masscan",
        target_id=target_id,
        target_url=f"http://{target_host}",
        started_at=started_at,
        finished_at=finished_at,
        duration_sec=duration,
        mode=mode,
        exit_code=exit_code,
        binary_available=bool(masscan_bin),
        reason=reason,
        raw_file_path=actual_file_path,
        finding_count=finding_count,
        warnings=warnings,
        errors=errors,
        relative_raw_path=rel_raw_path,
    )
    save_scan_status(scan_dir, status)

    append_command_log(
        log_path=commands_log,
        target=target_host,
        tool="masscan",
        command=command_str,
        arguments=cmd_args,
        exit_code=exit_code,
        duration=duration,
        output_path=str(actual_file_path) if actual_file_path else "None",
        error=error_msg,
    )

    return {
        "tool": "masscan",
        "command": command_str,
        "arguments": cmd_args,
        "exit_code": exit_code,
        "duration": duration,
        "raw_path": str(actual_file_path) if actual_file_path else "",
        "commands_log": str(commands_log),
        "error": error_msg,
        "status": status.model_dump(),
    }


def main():
    parser = argparse.ArgumentParser(description="AI-Pentest Copilot Masscan Runner")
    parser.add_argument("--target-id", default="target-local", help="Target ID")
    parser.add_argument("--host", required=True, help="Target Host/IP/CIDR")
    parser.add_argument(
        "--ports", default="1-1000", help="Port range (e.g. 1-1000, 80,443)"
    )
    parser.add_argument("--rate", type=int, default=1000, help="Packet rate limit")
    parser.add_argument(
        "--simulate", action="store_true", help="Force test fixture simulation"
    )
    args = parser.parse_args()

    res = run_masscan_scan(
        target_id=args.target_id,
        target_host=args.host,
        ports=args.ports,
        rate=args.rate,
        simulate=args.simulate,
    )
    print(
        f"Masscan finished in {res['duration']:.2f}s with exit code {res['exit_code']} (mode: {res['status']['mode']})"
    )
    print(f"Raw Evidence: {res['raw_path']}")


if __name__ == "__main__":
    main()
