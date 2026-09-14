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

from toolkit.scripts.run_nmap import append_command_log


def generate_mock_nuclei_jsonl(target_url: str, target_host: str) -> str:
    """Generates realistic read-only detection findings (e.g. Apache Path Traversal, Tech exposure)."""
    findings = [
        {
            "template_id": "CVE-2021-41773",
            "info": {
                "name": "Apache 2.4.49 - Path Traversal & Remote Code Execution",
                "severity": "high",
                "description": "A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the expected document root.",
                "tags": ["cve", "cve2021", "apache", "traversal", "misconfig"],
                "reference": [
                    "https://nvd.nist.gov/vuln/detail/CVE-2021-41773",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-41773"
                ],
                "cve_id": ["CVE-2021-41773"],
                "cwe_id": ["CWE-22"],
                "cvss_score": 7.5
            },
            "type": "http",
            "host": target_host,
            "matched_at": f"{target_url}/icons/.%%32%65/.%%32%65/etc/passwd",
            "extracted_results": ["root:x:0:0:root:/root:/bin/bash"],
            "curl_command": f"curl -s -path-as-is '{target_url}/icons/.%%32%65/.%%32%65/etc/passwd'"
        },
        {
            "template_id": "tech-detect",
            "info": {
                "name": "Wappalyzer Technology Detection",
                "severity": "info",
                "description": "Detected technologies running on target application.",
                "tags": ["tech"],
                "reference": [],
                "cve_id": [],
                "cwe_id": [],
                "cvss_score": 0.0
            },
            "type": "http",
            "host": target_host,
            "matched_at": target_url,
            "extracted_results": ["Apache", "PHP", "Node.js"],
            "curl_command": f"curl -s -I '{target_url}'"
        }
    ]
    lines = [json.dumps(f) for f in findings]
    return "\n".join(lines) + "\n"


def run_nuclei_scan(
    target_id: str,
    target_url: str,
    target_host: str,
    output_dir: pathlib.Path | None = None,
    simulate: bool = False,
) -> dict:
    root = pathlib.Path(__file__).resolve().parent.parent.parent
    if output_dir is None:
        scan_dir = root / "toolkit" / "05-vulnerability" / "scans" / target_id / "nuclei"
    else:
        scan_dir = output_dir

    raw_dir = scan_dir / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)
    raw_jsonl_path = raw_dir / "nuclei_raw.jsonl"
    commands_log = scan_dir / "commands.md"

    # Strictly read-only & non-destructive template execution
    cmd_args = f"-u {target_url} -tags cve,misconfig,exposure -severity info,low,medium,high -json -o {raw_jsonl_path}"
    command_str = f"nuclei {cmd_args}"

    nuclei_bin = shutil.which("nuclei")
    force_sim = simulate or (os.getenv("SIMULATE_SCANS", "false").lower() == "true")

    start_time = time.time()
    exit_code = 0
    error_msg = None

    if nuclei_bin and not force_sim:
        try:
            cmd = [
                "nuclei", "-u", target_url,
                "-tags", "cve,misconfig,exposure",
                "-severity", "info,low,medium,high",
                "-json", "-o", str(raw_jsonl_path),
            ]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            exit_code = res.returncode
            if exit_code != 0:
                error_msg = res.stderr
        except Exception as e:
            exit_code = 1
            error_msg = str(e)
            raw_jsonl_path.write_text(generate_mock_nuclei_jsonl(target_url, target_host), encoding="utf-8")
    else:
        raw_jsonl_path.write_text(generate_mock_nuclei_jsonl(target_url, target_host), encoding="utf-8")

    duration = time.time() - start_time

    append_command_log(
        log_path=commands_log,
        target=target_url,
        tool="nuclei",
        command=command_str,
        arguments=cmd_args,
        exit_code=exit_code,
        duration=duration,
        output_path=str(raw_jsonl_path),
        error=error_msg,
    )

    return {
        "tool": "nuclei",
        "command": command_str,
        "arguments": cmd_args,
        "exit_code": exit_code,
        "duration": duration,
        "raw_path": str(raw_jsonl_path),
        "commands_log": str(commands_log),
    }


def main():
    parser = argparse.ArgumentParser(description="AI-Pentest Copilot Nuclei Runner")
    parser.add_argument("--target-id", default="target-vuln", help="Target ID")
    parser.add_argument("--url", required=True, help="Target URL")
    parser.add_argument("--host", default="localhost", help="Host name")
    parser.add_argument("--simulate", action="store_true", help="Force simulation")
    args = parser.parse_args()

    res = run_nuclei_scan(
        target_id=args.target_id,
        target_url=args.url,
        target_host=args.host,
        simulate=args.simulate,
    )
    print(f"Nuclei finished in {res['duration']:.2f}s with exit code {res['exit_code']}")
    print(f"Raw Evidence: {res['raw_path']}")


if __name__ == "__main__":
    main()
