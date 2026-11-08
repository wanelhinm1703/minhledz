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


def generate_mock_katana_jsonl(target_url: str) -> str:
    base = target_url.rstrip("/")
    endpoints = [
        {
            "request": {"method": "GET", "endpoint": f"{base}/"},
            "response": {"status_code": 200},
        },
        {
            "request": {"method": "GET", "endpoint": f"{base}/login"},
            "response": {"status_code": 200},
        },
        {
            "request": {"method": "GET", "endpoint": f"{base}/api/v1/health"},
            "response": {"status_code": 200},
        },
        {
            "request": {"method": "GET", "endpoint": f"{base}/robots.txt"},
            "response": {"status_code": 200},
        },
    ]
    lines = [json.dumps(ep) for ep in endpoints]
    return "\n".join(lines) + "\n"


def run_katana_scan(
    target_id: str,
    target_url: str,
    depth: int = 2,
    output_dir: pathlib.Path | None = None,
    simulate: bool = False,
) -> dict:
    root = REPO_ROOT
    if output_dir is None:
        scan_dir = root / "toolkit" / "04-web" / "scans" / target_id / "katana"
    else:
        scan_dir = output_dir

    raw_dir = scan_dir / "raw"
    simulated_dir = scan_dir / "simulated"
    commands_log = scan_dir / "commands.md"

    katana_bin = shutil.which("katana")
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

    if katana_bin and not force_sim:
        raw_dir.mkdir(parents=True, exist_ok=True)
        raw_jsonl_path = raw_dir / "katana_raw.jsonl"
        actual_file_path = raw_jsonl_path
        rel_raw_path = "raw/katana_raw.jsonl"
        cmd_args = (
            f"-u {target_url} -d {depth} -rate-limit 50 -jsonl -o {raw_jsonl_path}"
        )
        command_str = f"katana {cmd_args}"

        try:
            cmd = [
                katana_bin,
                "-u",
                target_url,
                "-d",
                str(depth),
                "-rate-limit",
                "50",
                "-jsonl",
                "-o",
                str(raw_jsonl_path),
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
                if raw_jsonl_path.exists():
                    lines = [
                        l
                        for l in raw_jsonl_path.read_text(
                            encoding="utf-8", errors="replace"
                        ).splitlines()
                        if l.strip()
                    ]
                    finding_count = len(lines)
        except subprocess.TimeoutExpired:
            mode = "failed"
            exit_code = 124
            reason = "timeout"
            error_msg = "Katana scan timed out after 180 seconds."
            errors.append(error_msg)
        except Exception as e:
            mode = "failed"
            exit_code = 1
            reason = "execution_error"
            error_msg = str(e)
            errors.append(error_msg)
    elif force_sim:
        simulated_dir.mkdir(parents=True, exist_ok=True)
        sim_jsonl_path = simulated_dir / "katana_raw.jsonl"
        sim_jsonl_path.write_text(
            generate_mock_katana_jsonl(target_url), encoding="utf-8"
        )
        actual_file_path = sim_jsonl_path
        rel_raw_path = "simulated/katana_raw.jsonl"
        mode = "simulated"
        reason = "binary_not_found" if not katana_bin else None
        exit_code = 0
        finding_count = 4
        warnings.append("Simulated scan results. Not genuine evidence.")
        cmd_args = f"-u {target_url} -d {depth} [SIMULATED]"
        command_str = f"katana {cmd_args}"
    else:
        mode = "failed"
        reason = "binary_not_found"
        exit_code = 127
        error_msg = "Katana binary is not installed in the current environment. Please install katana or use HTTPx/Gobuster."
        errors.append(error_msg)
        actual_file_path = None
        rel_raw_path = None
        cmd_args = f"-u {target_url} [BINARY NOT FOUND]"
        command_str = f"katana {cmd_args}"

    duration = time.time() - start_time
    finished_at = datetime.now(timezone.utc).isoformat()

    status = create_scan_status(
        tool="katana",
        target_id=target_id,
        target_url=target_url,
        started_at=started_at,
        finished_at=finished_at,
        duration_sec=duration,
        mode=mode,
        exit_code=exit_code,
        binary_available=bool(katana_bin),
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
        tool="katana",
        command=command_str,
        arguments=cmd_args,
        exit_code=exit_code,
        duration=duration,
        output_path=str(actual_file_path) if actual_file_path else "None",
        error=error_msg,
    )

    return {
        "tool": "katana",
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
    parser = argparse.ArgumentParser(description="AI-Pentest Copilot Katana Runner")
    parser.add_argument("--target-id", default="target-web", help="Target ID")
    parser.add_argument("--url", required=True, help="Target URL")
    parser.add_argument("--depth", type=int, default=2, help="Crawl depth")
    parser.add_argument(
        "--simulate", action="store_true", help="Force test fixture simulation"
    )
    args = parser.parse_args()

    res = run_katana_scan(
        target_id=args.target_id,
        target_url=args.url,
        depth=args.depth,
        simulate=args.simulate,
    )
    print(
        f"Katana finished in {res['duration']:.2f}s with exit code {res['exit_code']} (mode: {res['status']['mode']})"
    )
    print(f"Raw Evidence: {res['raw_path']}")


if __name__ == "__main__":
    main()
