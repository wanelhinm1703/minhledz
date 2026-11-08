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


def generate_mock_ffuf_json(target_url: str) -> str:
    mock_data = {
        "commandline": f"ffuf -u {target_url}/FUZZ -w common.txt -of json",
        "time": datetime.now(timezone.utc).isoformat(),
        "results": [
            {
                "input": {"FUZZ": "robots.txt"},
                "position": 1,
                "status": 200,
                "length": 45,
                "words": 6,
                "lines": 3,
                "url": f"{target_url.rstrip('/')}/robots.txt",
                "redirectlocation": "",
            },
            {
                "input": {"FUZZ": "login"},
                "position": 2,
                "status": 200,
                "length": 1420,
                "words": 150,
                "lines": 45,
                "url": f"{target_url.rstrip('/')}/login",
                "redirectlocation": "",
            },
            {
                "input": {"FUZZ": "api"},
                "position": 3,
                "status": 301,
                "length": 0,
                "words": 0,
                "lines": 1,
                "url": f"{target_url.rstrip('/')}/api",
                "redirectlocation": f"{target_url.rstrip('/')}/api/",
            },
        ],
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
    simulated_dir = scan_dir / "simulated"
    commands_log = scan_dir / "commands.md"

    fuzz_url = target_url.rstrip("/") + "/FUZZ"
    wl_path = wordlist or str(root / "toolkit" / "00-meta" / "templates" / "common.txt")
    if not os.path.exists(wl_path):
        temp_wl = scan_dir / "temp_wordlist.txt"
        temp_wl.parent.mkdir(parents=True, exist_ok=True)
        temp_wl.write_text("login\nadmin\nrobots.txt\napi\nimages\n", encoding="utf-8")
        wl_path = str(temp_wl)

    ffuf_bin = shutil.which("ffuf")
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

    if ffuf_bin and not force_sim:
        raw_dir.mkdir(parents=True, exist_ok=True)
        raw_json_path = raw_dir / "ffuf_raw.json"
        actual_file_path = raw_json_path
        rel_raw_path = "raw/ffuf_raw.json"
        cmd_args = f"-u {fuzz_url} -w {wl_path} -of json -o {raw_json_path} -s -rate 50"
        command_str = f"ffuf {cmd_args}"

        try:
            cmd = [
                ffuf_bin,
                "-u",
                fuzz_url,
                "-w",
                wl_path,
                "-of",
                "json",
                "-o",
                str(raw_json_path),
                "-s",
                "-rate",
                "50",
            ]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
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
                        finding_count = len(data.get("results", []))
                    except Exception:
                        pass
        except subprocess.TimeoutExpired:
            mode = "failed"
            exit_code = 124
            reason = "timeout"
            error_msg = "FFUF scan timed out after 120 seconds."
            errors.append(error_msg)
        except Exception as e:
            mode = "failed"
            exit_code = 1
            reason = "execution_error"
            error_msg = str(e)
            errors.append(error_msg)
    elif force_sim:
        simulated_dir.mkdir(parents=True, exist_ok=True)
        sim_json_path = simulated_dir / "ffuf_raw.json"
        sim_json_path.write_text(generate_mock_ffuf_json(target_url), encoding="utf-8")
        actual_file_path = sim_json_path
        rel_raw_path = "simulated/ffuf_raw.json"
        mode = "simulated"
        reason = "binary_not_found" if not ffuf_bin else None
        exit_code = 0
        finding_count = 3
        warnings.append("Simulated scan results. Not genuine evidence.")
        cmd_args = f"-u {fuzz_url} -w {wl_path} [SIMULATED]"
        command_str = f"ffuf {cmd_args}"
    else:
        mode = "failed"
        reason = "binary_not_found"
        exit_code = 127
        error_msg = "FFUF binary is not installed in the current environment. Please install ffuf or use Gobuster/Katana."
        errors.append(error_msg)
        actual_file_path = None
        rel_raw_path = None
        cmd_args = f"-u {fuzz_url} [BINARY NOT FOUND]"
        command_str = f"ffuf {cmd_args}"

    duration = time.time() - start_time
    finished_at = datetime.now(timezone.utc).isoformat()

    status = create_scan_status(
        tool="ffuf",
        target_id=target_id,
        target_url=target_url,
        started_at=started_at,
        finished_at=finished_at,
        duration_sec=duration,
        mode=mode,
        exit_code=exit_code,
        binary_available=bool(ffuf_bin),
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
        tool="ffuf",
        command=command_str,
        arguments=cmd_args,
        exit_code=exit_code,
        duration=duration,
        output_path=str(actual_file_path) if actual_file_path else "None",
        error=error_msg,
    )

    return {
        "tool": "ffuf",
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
    parser = argparse.ArgumentParser(description="AI-Pentest Copilot FFUF Runner")
    parser.add_argument("--target-id", default="target-web", help="Target ID")
    parser.add_argument("--url", required=True, help="Target URL")
    parser.add_argument("--wordlist", default=None, help="Wordlist path")
    parser.add_argument(
        "--simulate", action="store_true", help="Force test fixture simulation"
    )
    args = parser.parse_args()

    res = run_ffuf_scan(
        target_id=args.target_id,
        target_url=args.url,
        wordlist=args.wordlist,
        simulate=args.simulate,
    )
    print(
        f"FFUF finished in {res['duration']:.2f}s with exit code {res['exit_code']} (mode: {res['status']['mode']})"
    )
    print(f"Raw Evidence: {res['raw_path']}")


if __name__ == "__main__":
    main()
