#!/usr/bin/env python3
from __future__ import annotations

import argparse
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


def generate_mock_rustscan_output(host: str, ports: list[int] | None = None) -> str:
    target_ports = ports or [80, 443, 8080]
    ports_str = ",".join(str(p) for p in target_ports)
    return f"""Starting RustScan 2.1.1 ( https://rustscan.github.io/RustScan/ )
[~] The config file is not found. Using default config.
[~] Automatically increasing ulimit value to 5000.
Open {host}:80
Open {host}:443
Open {host}:8080
[~] Starting Script(s)
[~] Starting Nmap 7.94 ( https://nmap.org ) at {datetime.now().ctime()}
Initiating Service scan against {host} with ports {ports_str}
Discovered open port 80/tcp on {host}
Discovered open port 443/tcp on {host}
Discovered open port 8080/tcp on {host}
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
    simulated_dir = scan_dir / "simulated"
    commands_log = scan_dir / "commands.md"

    port_arg = f"-p {ports}" if ports else "--top"
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

    if rustscan_bin and not force_sim:
        raw_dir.mkdir(parents=True, exist_ok=True)
        raw_txt_path = raw_dir / "rustscan_raw.txt"
        actual_file_path = raw_txt_path
        rel_raw_path = "raw/rustscan_raw.txt"
        cmd_args = f"-a {target_host} {port_arg} --accessible"
        command_str = f"rustscan {cmd_args}"

        try:
            cmd = [rustscan_bin, "-a", target_host, "--accessible"]
            if ports:
                cmd.extend(["-p", ports])
            else:
                cmd.append("--top")

            res = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            exit_code = res.returncode
            raw_txt_path.write_text(
                (res.stdout or "") + "\n" + (res.stderr or ""), encoding="utf-8"
            )
            if exit_code != 0:
                mode = "failed"
                error_msg = res.stderr or f"Exit code {exit_code}"
                errors.append(error_msg)
                reason = "execution_error"
            else:
                mode = "real"
                lines = [l for l in (res.stdout or "").splitlines() if "Open " in l]
                finding_count = len(lines)
        except subprocess.TimeoutExpired:
            mode = "failed"
            exit_code = 124
            reason = "timeout"
            error_msg = "RustScan timed out after 120 seconds."
            errors.append(error_msg)
        except Exception as e:
            mode = "failed"
            exit_code = 1
            reason = "execution_error"
            error_msg = str(e)
            errors.append(error_msg)
    elif force_sim:
        simulated_dir.mkdir(parents=True, exist_ok=True)
        sim_txt_path = simulated_dir / "rustscan_raw.txt"
        parsed_ports = (
            [int(p) for p in ports.split(",") if p.isdigit()] if ports else None
        )
        sim_txt_path.write_text(
            generate_mock_rustscan_output(target_host, parsed_ports), encoding="utf-8"
        )
        actual_file_path = sim_txt_path
        rel_raw_path = "simulated/rustscan_raw.txt"
        mode = "simulated"
        reason = "binary_not_found" if not rustscan_bin else None
        exit_code = 0
        finding_count = len(parsed_ports) if parsed_ports else 3
        warnings.append("Simulated scan results. Not genuine evidence.")
        cmd_args = f"-a {target_host} {port_arg} [SIMULATED]"
        command_str = f"rustscan {cmd_args}"
    else:
        mode = "failed"
        reason = "binary_not_found"
        exit_code = 127
        error_msg = "RustScan binary is not installed in the current environment. Please install rustscan or use Nmap."
        errors.append(error_msg)
        actual_file_path = None
        rel_raw_path = None
        cmd_args = f"-a {target_host} {port_arg} [BINARY NOT FOUND]"
        command_str = f"rustscan {cmd_args}"

    duration = time.time() - start_time
    finished_at = datetime.now(timezone.utc).isoformat()

    status = create_scan_status(
        tool="rustscan",
        target_id=target_id,
        target_url=f"http://{target_host}",
        started_at=started_at,
        finished_at=finished_at,
        duration_sec=duration,
        mode=mode,
        exit_code=exit_code,
        binary_available=bool(rustscan_bin),
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
        tool="rustscan",
        command=command_str,
        arguments=cmd_args,
        exit_code=exit_code,
        duration=duration,
        output_path=str(actual_file_path) if actual_file_path else "None",
        error=error_msg,
    )

    return {
        "tool": "rustscan",
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
    parser = argparse.ArgumentParser(description="AI-Pentest Copilot RustScan Runner")
    parser.add_argument("--target-id", default="target-local", help="Target ID")
    parser.add_argument("--host", required=True, help="Target Host/IP")
    parser.add_argument("--ports", default=None, help="Ports to scan (e.g. 80,443)")
    parser.add_argument(
        "--simulate", action="store_true", help="Force simulation fixture"
    )
    args = parser.parse_args()

    res = run_rustscan_scan(
        target_id=args.target_id,
        target_host=args.host,
        ports=args.ports,
        simulate=args.simulate,
    )
    print(
        f"RustScan finished in {res['duration']:.2f}s with exit code {res['exit_code']} (mode: {res['status']['mode']})"
    )
    print(f"Raw Evidence: {res['raw_path']}")


if __name__ == "__main__":
    main()
