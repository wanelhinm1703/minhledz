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


def generate_mock_whatweb_json(target_url: str) -> str:
    mock_data = [
        {
            "target": target_url,
            "http_status": 200,
            "plugins": {
                "Apache": {"version": ["2.4.49"]},
                "HTTPServer": {"string": ["Apache/2.4.49 (Unix)"]},
                "PHP": {"version": ["7.4.21"]},
                "Title": {"string": ["Test Target Service"]},
                "X-Powered-By": {"string": ["PHP/7.4.21"]}
            }
        }
    ]
    return json.dumps(mock_data, indent=2)


def run_whatweb_scan(
    target_id: str,
    target_url: str,
    output_dir: pathlib.Path | None = None,
    simulate: bool = False,
) -> dict:
    root = REPO_ROOT
    if output_dir is None:
        scan_dir = root / "toolkit" / "04-web" / "scans" / target_id / "whatweb"
    else:
        scan_dir = output_dir

    raw_dir = scan_dir / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)
    raw_json_path = raw_dir / "whatweb_raw.json"
    commands_log = scan_dir / "commands.md"

    cmd_args = f"-a 1 --log-json {raw_json_path} {target_url}"
    command_str = f"whatweb {cmd_args}"

    whatweb_bin = shutil.which("whatweb")
    force_sim = simulate or (os.getenv("SIMULATE_SCANS", "false").lower() == "true")

    start_time = time.time()
    exit_code = 0
    error_msg = None

    if whatweb_bin and not force_sim:
        try:
            cmd = [
                whatweb_bin,
                "-a", "1",
                f"--log-json={raw_json_path}",
                target_url,
            ]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            exit_code = res.returncode
            if exit_code != 0:
                error_msg = res.stderr
        except Exception as e:
            exit_code = 1
            error_msg = str(e)
    elif force_sim:
        raw_json_path.write_text(generate_mock_whatweb_json(target_url), encoding="utf-8")
    else:
        exit_code = 127
        error_msg = "WhatWeb binary is not installed in the current environment. Please install whatweb or use HTTPx tech-detect fallback."
        raw_json_path.write_text("[]", encoding="utf-8")

    duration = time.time() - start_time

    append_command_log(
        log_path=commands_log,
        target=target_url,
        tool="whatweb",
        command=command_str,
        arguments=cmd_args,
        exit_code=exit_code,
        duration=duration,
        output_path=str(raw_json_path),
        error=error_msg,
    )

    return {
        "tool": "whatweb",
        "command": command_str,
        "arguments": cmd_args,
        "exit_code": exit_code,
        "duration": duration,
        "raw_path": str(raw_json_path),
        "commands_log": str(commands_log),
        "error": error_msg,
    }


def main():
    parser = argparse.ArgumentParser(description="AI-Pentest Copilot WhatWeb Runner")
    parser.add_argument("--target-id", default="target-web", help="Target ID")
    parser.add_argument("--url", required=True, help="Target URL")
    parser.add_argument("--simulate", action="store_true", help="Force test fixture simulation")
    args = parser.parse_args()

    res = run_whatweb_scan(
        target_id=args.target_id,
        target_url=args.url,
        simulate=args.simulate,
    )
    print(f"WhatWeb finished in {res['duration']:.2f}s with exit code {res['exit_code']}")
    print(f"Raw Evidence: {res['raw_path']}")


if __name__ == "__main__":
    main()
