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


def generate_mock_nikto_json(target_host: str, port: int) -> str:
    mock_data = {
        "host": target_host,
        "ip": target_host,
        "port": port,
        "banner": "Apache/2.4.49 (Unix)",
        "items": [
            {
                "id": "999100",
                "OSVDB": "0",
                "method": "GET",
                "url": "/",
                "description": "The anti-clickjacking X-Frame-Options header is not present.",
                "severity": "low",
            },
            {
                "id": "999101",
                "OSVDB": "0",
                "method": "GET",
                "url": "/",
                "description": "The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type.",
                "severity": "low",
            },
            {
                "id": "999102",
                "OSVDB": "3092",
                "method": "GET",
                "url": "/icons/README",
                "description": "Apache default file found.",
                "severity": "low",
            },
        ],
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
    simulated_dir = scan_dir / "simulated"
    commands_log = scan_dir / "commands.md"

    p_val = port or (443 if target_url.startswith("https") else 80)
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

    if nikto_bin and not force_sim:
        raw_dir.mkdir(parents=True, exist_ok=True)
        raw_json_path = raw_dir / "nikto_raw.json"
        actual_file_path = raw_json_path
        rel_raw_path = "raw/nikto_raw.json"
        cmd_args = (
            f"-host {target_url} -Format json -output {raw_json_path} -Tuning 123b"
        )
        command_str = f"nikto {cmd_args}"

        try:
            cmd = [
                nikto_bin,
                "-host",
                target_url,
                "-Format",
                "json",
                "-output",
                str(raw_json_path),
                "-Tuning",
                "123b",
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
                        finding_count = len(data.get("items", []))
                    except Exception:
                        pass
        except subprocess.TimeoutExpired:
            mode = "failed"
            exit_code = 124
            reason = "timeout"
            error_msg = "Nikto scan timed out after 180 seconds."
            errors.append(error_msg)
        except Exception as e:
            mode = "failed"
            exit_code = 1
            reason = "execution_error"
            error_msg = str(e)
            errors.append(error_msg)
    elif force_sim:
        simulated_dir.mkdir(parents=True, exist_ok=True)
        sim_json_path = simulated_dir / "nikto_raw.json"
        sim_json_path.write_text(
            generate_mock_nikto_json(target_host, p_val), encoding="utf-8"
        )
        actual_file_path = sim_json_path
        rel_raw_path = "simulated/nikto_raw.json"
        mode = "simulated"
        reason = "binary_not_found" if not nikto_bin else None
        exit_code = 0
        finding_count = 3
        warnings.append("Simulated scan results. Not genuine evidence.")
        cmd_args = f"-host {target_url} [SIMULATED]"
        command_str = f"nikto {cmd_args}"
    else:
        mode = "failed"
        reason = "binary_not_found"
        exit_code = 127
        error_msg = "Nikto binary is not installed in the current environment. Please install nikto or use HTTPx/Nuclei."
        errors.append(error_msg)
        actual_file_path = None
        rel_raw_path = None
        cmd_args = f"-host {target_url} [BINARY NOT FOUND]"
        command_str = f"nikto {cmd_args}"

    duration = time.time() - start_time
    finished_at = datetime.now(timezone.utc).isoformat()

    status = create_scan_status(
        tool="nikto",
        target_id=target_id,
        target_url=target_url,
        started_at=started_at,
        finished_at=finished_at,
        duration_sec=duration,
        mode=mode,
        exit_code=exit_code,
        binary_available=bool(nikto_bin),
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
        target=target_url,
        tool="nikto",
        command=command_str,
        arguments=cmd_args,
        exit_code=exit_code,
        duration=duration,
        output_path=str(actual_file_path) if actual_file_path else "None",
        error=error_msg,
    )

    return {
        "tool": "nikto",
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
    parser = argparse.ArgumentParser(description="AI-Pentest Copilot Nikto Runner")
    parser.add_argument("--target-id", default="target-web", help="Target ID")
    parser.add_argument("--url", required=True, help="Target URL")
    parser.add_argument("--host", default="localhost", help="Host name")
    parser.add_argument("--port", type=int, default=None, help="Port")
    parser.add_argument(
        "--simulate", action="store_true", help="Force test fixture simulation"
    )
    args = parser.parse_args()

    res = run_nikto_scan(
        target_id=args.target_id,
        target_url=args.url,
        target_host=args.host,
        port=args.port,
        simulate=args.simulate,
    )
    print(
        f"Nikto finished in {res['duration']:.2f}s with exit code {res['exit_code']} (mode: {res['status']['mode']})"
    )
    print(f"Raw Evidence: {res['raw_path']}")


if __name__ == "__main__":
    main()
