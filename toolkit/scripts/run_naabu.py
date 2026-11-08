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
    simulated_dir = scan_dir / "simulated"
    commands_log = scan_dir / "commands.md"

    port_arg = f"-p {port}" if port else "-top-ports 100"
    naabu_bin = shutil.which("naabu")
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

    if naabu_bin and not force_sim:
        raw_dir.mkdir(parents=True, exist_ok=True)
        raw_output_path = raw_dir / "naabu_raw.txt"
        actual_file_path = raw_output_path
        rel_raw_path = "raw/naabu_raw.txt"
        cmd_args = f"-host {target_host} {port_arg} -o {raw_output_path}"
        command_str = f"naabu {cmd_args}"

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
                mode = "failed"
                error_msg = res.stderr or f"Exit code {exit_code}"
                errors.append(error_msg)
                reason = "execution_error"
            else:
                mode = "real"
                if raw_output_path.exists():
                    lines = [
                        l
                        for l in raw_output_path.read_text(
                            encoding="utf-8", errors="replace"
                        ).splitlines()
                        if l.strip()
                    ]
                    finding_count = len(lines)
        except subprocess.TimeoutExpired:
            mode = "failed"
            exit_code = 124
            reason = "timeout"
            error_msg = "Naabu scan timed out after 120 seconds."
            errors.append(error_msg)
        except Exception as e:
            mode = "failed"
            exit_code = 1
            reason = "execution_error"
            error_msg = str(e)
            errors.append(error_msg)

    elif not force_sim:
        # Probe real TCP ports using standard socket
        import concurrent.futures
        import socket

        test_ports = (
            [port]
            if port
            else [
                80,
                443,
                8080,
                8000,
                3000,
                22,
                21,
                25,
                135,
                139,
                445,
                3389,
                3306,
                5432,
                8443,
            ]
        )
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
            raw_dir.mkdir(parents=True, exist_ok=True)
            raw_output_path = raw_dir / "naabu_raw.txt"
            lines = [f"{target_host}:{p}" for p in sorted(open_found)]
            raw_output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            actual_file_path = raw_output_path
            rel_raw_path = "raw/naabu_raw.txt"
            mode = "real"
            exit_code = 0
            finding_count = len(open_found)
            cmd_args = f"-host {target_host} [Socket TCP Probe]"
            command_str = f"naabu-probe {cmd_args}"
        else:
            mode = "failed"
            reason = "binary_not_found" if not naabu_bin else "host_unreachable"
            exit_code = 127 if not naabu_bin else 1
            error_msg = (
                "Naabu binary not installed and no open ports answered socket probe."
            )
            errors.append(error_msg)
            actual_file_path = None
            rel_raw_path = None
            cmd_args = f"-host {target_host} [FAILED]"
            command_str = f"naabu {cmd_args}"

    else:
        # force_sim == True
        simulated_dir.mkdir(parents=True, exist_ok=True)
        sim_output_path = simulated_dir / "naabu_raw.txt"
        sim_output_path.write_text(
            generate_mock_naabu_output(target_host, port), encoding="utf-8"
        )
        actual_file_path = sim_output_path
        rel_raw_path = "simulated/naabu_raw.txt"
        mode = "simulated"
        reason = "binary_not_found" if not naabu_bin else None
        exit_code = 0
        finding_count = 4
        warnings.append("Simulated scan results. Not genuine evidence.")
        cmd_args = f"-host {target_host} [SIMULATED]"
        command_str = f"naabu {cmd_args}"

    duration = time.time() - start_time
    finished_at = datetime.now(timezone.utc).isoformat()

    status = create_scan_status(
        tool="naabu",
        target_id=target_id,
        target_url=f"http://{target_host}:{port}" if port else f"http://{target_host}",
        started_at=started_at,
        finished_at=finished_at,
        duration_sec=duration,
        mode=mode,
        exit_code=exit_code,
        binary_available=bool(naabu_bin),
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
        tool="naabu",
        command=command_str,
        arguments=cmd_args,
        exit_code=exit_code,
        duration=duration,
        output_path=str(actual_file_path) if actual_file_path else "None",
        error=error_msg,
    )

    return {
        "tool": "naabu",
        "command": command_str,
        "arguments": cmd_args,
        "exit_code": exit_code,
        "duration": duration,
        "raw_path": str(actual_file_path) if actual_file_path else "",
        "commands_log": str(commands_log),
        "status": status.model_dump(),
    }


def main():
    parser = argparse.ArgumentParser(description="AI-Pentest Copilot Naabu Runner")
    parser.add_argument("--target-id", default="target-local", help="Target ID")
    parser.add_argument("--host", required=True, help="Target Host")
    parser.add_argument("--port", type=int, default=None, help="Port")
    parser.add_argument("--simulate", action="store_true", help="Force simulation")
    args = parser.parse_args()

    res = run_naabu_scan(
        target_id=args.target_id,
        target_host=args.host,
        port=args.port,
        simulate=args.simulate,
    )
    print(
        f"Naabu completed in {res['duration']:.2f}s with exit code {res['exit_code']} (mode: {res['status']['mode']})"
    )
    print(f"Raw Evidence: {res['raw_path']}")


if __name__ == "__main__":
    main()
