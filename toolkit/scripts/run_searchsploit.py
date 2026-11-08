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


def generate_mock_searchsploit_json(query: str) -> str:
    mock_data = {
        "SEARCH": query,
        "RESULTS_EXPLOIT": [
            {
                "Title": "Apache 2.4.49 - Path Traversal & Remote Code Execution (CVE-2021-41773)",
                "EDB-ID": "50383",
                "Date": "2021-10-06",
                "Author": "Ash Daulton",
                "Type": "remote",
                "Platform": "multiple",
                "Path": "exploits/multiple/remote/50383.sh",
                "Codes": "CVE-2021-41773"
            },
            {
                "Title": "Apache 2.4.49 / 2.4.50 - Remote Code Execution (RCE)",
                "EDB-ID": "50406",
                "Date": "2021-10-12",
                "Author": "Lucas",
                "Type": "remote",
                "Platform": "multiple",
                "Path": "exploits/multiple/remote/50406.py",
                "Codes": "CVE-2021-41773;CVE-2021-42013"
            }
        ],
        "RESULTS_PAPER": []
    }
    return json.dumps(mock_data, indent=2)


def run_searchsploit_lookup(
    target_id: str,
    query: str,
    output_dir: pathlib.Path | None = None,
    simulate: bool = False,
) -> dict:
    root = REPO_ROOT
    if output_dir is None:
        scan_dir = root / "toolkit" / "05-vulnerability" / "scans" / target_id / "searchsploit"
    else:
        scan_dir = output_dir

    raw_dir = scan_dir / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)
    raw_json_path = raw_dir / "searchsploit_raw.json"
    commands_log = scan_dir / "commands.md"

    cmd_args = f"--json \"{query}\""
    command_str = f"searchsploit {cmd_args}"

    searchsploit_bin = shutil.which("searchsploit")
    if not searchsploit_bin:
        candidates = [
            r"C:\ProgramData\chocolatey\bin\searchsploit.bat",
            r"C:\tools\searchsploit\searchsploit.bat",
        ]
        for c in candidates:
            if os.path.exists(c):
                searchsploit_bin = c
                break

    force_sim = simulate or (os.getenv("SIMULATE_SCANS", "false").lower() == "true")

    start_time = time.time()
    exit_code = 0
    error_msg = None

    if searchsploit_bin and not force_sim:
        try:
            cmd = [searchsploit_bin, "--json", query]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            exit_code = res.returncode
            raw_json_path.write_text(res.stdout, encoding="utf-8")
            if exit_code != 0:
                error_msg = res.stderr
        except Exception as e:
            exit_code = 1
            error_msg = str(e)
            raw_json_path.write_text("{}", encoding="utf-8")
    elif force_sim:
        raw_json_path.write_text(generate_mock_searchsploit_json(query), encoding="utf-8")
    else:
        exit_code = 127
        error_msg = "SearchSploit binary is not installed in the current environment. Please install exploitdb/searchsploit or use KB/RAG."
        raw_json_path.write_text("{}", encoding="utf-8")

    duration = time.time() - start_time

    append_command_log(
        log_path=commands_log,
        target=query,
        tool="searchsploit",
        command=command_str,
        arguments=cmd_args,
        exit_code=exit_code,
        duration=duration,
        output_path=str(raw_json_path),
        error=error_msg,
    )

    return {
        "tool": "searchsploit",
        "command": command_str,
        "arguments": cmd_args,
        "exit_code": exit_code,
        "duration": duration,
        "raw_path": str(raw_json_path),
        "commands_log": str(commands_log),
        "error": error_msg,
    }


def main():
    parser = argparse.ArgumentParser(description="AI-Pentest Copilot SearchSploit Runner")
    parser.add_argument("--target-id", default="target-ref", help="Target ID")
    parser.add_argument("--query", required=True, help="Search query (e.g. Apache 2.4.49)")
    parser.add_argument("--simulate", action="store_true", help="Force test simulation")
    args = parser.parse_args()

    res = run_searchsploit_lookup(
        target_id=args.target_id,
        query=args.query,
        simulate=args.simulate,
    )
    print(f"SearchSploit finished in {res['duration']:.2f}s with exit code {res['exit_code']}")
    print(f"Raw Evidence: {res['raw_path']}")


if __name__ == "__main__":
    main()
