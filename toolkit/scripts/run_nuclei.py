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


def generate_mock_nuclei_jsonl(target_url: str, target_host: str) -> str:
    """Generates read-only detection findings for simulation testing only."""
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
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-41773",
                ],
                "cve_id": ["CVE-2021-41773"],
                "cwe_id": ["CWE-22"],
                "cvss_score": 7.5,
            },
            "type": "http",
            "host": target_host,
            "matched_at": f"{target_url}/icons/.%%32%65/.%%32%65/etc/passwd",
            "extracted_results": ["root:x:0:0:root:/root:/bin/bash"],
            "curl_command": f"curl -s -path-as-is '{target_url}/icons/.%%32%65/.%%32%65/etc/passwd'",
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
                "cvss_score": 0.0,
            },
            "type": "http",
            "host": target_host,
            "matched_at": target_url,
            "extracted_results": ["Apache", "PHP", "Node.js"],
            "curl_command": f"curl -s -I '{target_url}'",
        },
    ]
    lines = [json.dumps(f) for f in findings]
    return "\n".join(lines) + "\n"


def run_nuclei_scan(
    target_id: str,
    target_url: str,
    target_host: str,
    output_dir: pathlib.Path | None = None,
    simulate: bool = False,
    intel_mode: str | None = None,
) -> dict:
    root = pathlib.Path(__file__).resolve().parent.parent.parent
    if output_dir is None:
        scan_dir = (
            root / "toolkit" / "05-vulnerability" / "scans" / target_id / "nuclei"
        )
    else:
        scan_dir = output_dir

    raw_dir = scan_dir / "raw"
    simulated_dir = scan_dir / "simulated"
    commands_log = scan_dir / "commands.md"

    nuclei_bin = shutil.which("nuclei")
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

    if nuclei_bin and not force_sim:
        raw_dir.mkdir(parents=True, exist_ok=True)
        raw_jsonl_path = raw_dir / "nuclei_raw.jsonl"
        actual_file_path = raw_jsonl_path
        rel_raw_path = "raw/nuclei_raw.jsonl"
        active_intel = (intel_mode or os.getenv("VULN_INTEL_MODE", "dual")).lower()

        cmd = [
            nuclei_bin,
            "-u",
            target_url,
            "-tags",
            "cve,misconfig,exposure",
            "-severity",
            "info,low,medium,high",
            "-json",
            "-o",
            str(raw_jsonl_path),
        ]
        if active_intel == "offline":
            cmd.append("-offline")

        cmd_args = f"-u {target_url} -tags cve,misconfig,exposure -severity info,low,medium,high -json -o {raw_jsonl_path} [mode={active_intel}]"
        command_str = f"nuclei {cmd_args}"
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            exit_code = res.returncode
            if exit_code != 0:
                mode = "failed"
                error_msg = res.stderr or f"Exit code {exit_code}"
                errors.append(error_msg)
                if "connection refused" in (res.stderr or "").lower():
                    reason = "connection_refused"
                else:
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
            error_msg = "Nuclei scan timed out after 300 seconds."
            errors.append(error_msg)
        except Exception as e:
            mode = "failed"
            exit_code = 1
            reason = "execution_error"
            error_msg = str(e)
            errors.append(error_msg)
    elif force_sim:
        simulated_dir.mkdir(parents=True, exist_ok=True)
        sim_jsonl_path = simulated_dir / "nuclei_raw.jsonl"
        actual_file_path = sim_jsonl_path
        rel_raw_path = "simulated/nuclei_raw.jsonl"
        sim_data = generate_mock_nuclei_jsonl(target_url, target_host)
        sim_jsonl_path.write_text(sim_data, encoding="utf-8")
        mode = "simulated"
        reason = "binary_not_found" if not nuclei_bin else None
        exit_code = 0
        finding_count = 2
        warnings.append("Simulated scan results. Not genuine evidence.")
        cmd_args = f"-u {target_url} -tags cve,misconfig,exposure [SIMULATED]"
        command_str = f"nuclei {cmd_args}"
    else:
        # Binary not found and not simulating -> FAIL HONESTLY
        mode = "failed"
        reason = "binary_not_found"
        exit_code = 127
        error_msg = "Nuclei binary is not installed in the environment."
        errors.append(error_msg)
        actual_file_path = None
        rel_raw_path = None
        cmd_args = f"-u {target_url} [BINARY NOT FOUND]"
        command_str = f"nuclei {cmd_args}"

    duration = time.time() - start_time
    finished_at = datetime.now(timezone.utc).isoformat()

    status = create_scan_status(
        tool="nuclei",
        target_id=target_id,
        target_url=target_url,
        started_at=started_at,
        finished_at=finished_at,
        duration_sec=duration,
        mode=mode,
        exit_code=exit_code,
        binary_available=bool(nuclei_bin),
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
        tool="nuclei",
        command=command_str,
        arguments=cmd_args,
        exit_code=exit_code,
        duration=duration,
        output_path=str(actual_file_path) if actual_file_path else "None",
        error=error_msg,
    )

    return {
        "tool": "nuclei",
        "command": command_str,
        "arguments": cmd_args,
        "exit_code": exit_code,
        "duration": duration,
        "raw_path": str(actual_file_path) if actual_file_path else "",
        "commands_log": str(commands_log),
        "status": status.model_dump(),
    }


def main():
    parser.add_argument(
        "--target-id",
        default="intel_cache",
        help="Target ID (default: intel_cache)",
    )
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
    print(
        f"Nuclei finished in {res['duration']:.2f}s with exit code {res['exit_code']} (mode: {res['status']['mode']})"
    )
    print(f"Raw Evidence: {res['raw_path']}")


if __name__ == "__main__":
    main()
