#!/usr/bin/env python3
"""
AI-Pentest Copilot - SearchSploit Runner with Dual-Mode Support.
Executes Exploit-DB searches locally and/or queries Online Threat Intel (OSV.dev, NVD) concurrently.
Supports modes:
  - offline: only local SearchSploit CLI
  - online: only Online Threat Intel
  - dual: executes both concurrently, merging and deduplicating matches
Strictly read-only: never compiles, downloads, or executes exploit binaries.
"""

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

from backend.app.config import settings
from backend.app.services.online_intel import online_intel
from toolkit.scripts.run_nmap import append_command_log
from toolkit.scripts.scan_status import create_scan_status, save_scan_status


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
                "Codes": "CVE-2021-41773",
                "Origin": "mock_fixture",
            },
            {
                "Title": "Apache 2.4.49 / 2.4.50 - Remote Code Execution (RCE)",
                "EDB-ID": "50406",
                "Date": "2021-10-12",
                "Author": "Lucas",
                "Type": "remote",
                "Platform": "multiple",
                "Path": "exploits/multiple/remote/50406.py",
                "Codes": "CVE-2021-41773;CVE-2021-42013",
                "Origin": "mock_fixture",
            },
        ],
        "RESULTS_PAPER": [],
    }
    return json.dumps(mock_data, indent=2)


def extract_product_and_version(query: str) -> tuple[str, str | None]:
    """Simple parser to extract product and version from query (e.g. 'Apache 2.4.49')."""
    parts = query.strip().split()
    if len(parts) >= 2 and any(c.isdigit() for c in parts[-1]):
        return " ".join(parts[:-1]), parts[-1]
    return query.strip(), None


def merge_searchsploit_data(
    local_data: dict,
    online_candidates: list,
    query: str,
    active_mode: str,
) -> dict:
    """Consolidates local SearchSploit and online threat intel results."""
    merged_exploits = list(local_data.get("RESULTS_EXPLOIT", []))
    for exp in merged_exploits:
        if "Origin" not in exp:
            exp["Origin"] = "local_exploitdb"

    seen_cves: set[str] = set()
    for exp in merged_exploits:
        codes = exp.get("Codes", "")
        for c in codes.split(";"):
            c_clean = c.strip().upper()
            if c_clean.startswith("CVE-"):
                seen_cves.add(c_clean)

    for cand in online_candidates:
        cve_key = cand.cve_id.upper()
        if cve_key not in seen_cves:
            seen_cves.add(cve_key)
            merged_exploits.append(
                {
                    "Title": f"[{cand.cve_id}] {cand.description[:120]}",
                    "EDB-ID": "N/A (Online)",
                    "Date": "2024-2026",
                    "Author": cand.source_name,
                    "Type": "remote",
                    "Platform": "multiple",
                    "Path": cand.source_url,
                    "Codes": cand.cve_id,
                    "Origin": cand.origin,
                }
            )

    return {
        "SEARCH": query,
        "RESULTS_EXPLOIT": merged_exploits,
        "RESULTS_PAPER": local_data.get("RESULTS_PAPER", []),
        "METADATA": {
            "mode": active_mode,
            "total_exploits": len(merged_exploits),
            "online_added": len(online_candidates),
        },
    }


def run_searchsploit_lookup(
    target_id: str,
    query: str,
    output_dir: pathlib.Path | None = None,
    simulate: bool = False,
    intel_mode: str | None = None,
) -> dict:
    root = REPO_ROOT
    if output_dir is None:
        scan_dir = (
            root / "toolkit" / "05-vulnerability" / "scans" / target_id / "searchsploit"
        )
    else:
        scan_dir = output_dir

    raw_dir = scan_dir / "raw"
    simulated_dir = scan_dir / "simulated"
    commands_log = scan_dir / "commands.md"

    active_mode = (
        intel_mode
        or getattr(settings, "VULN_INTEL_MODE", "dual")
    ).lower()

    cmd_args = f'--json "{query}" [mode={active_mode}]'
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

    local_data: dict = {"RESULTS_EXPLOIT": [], "RESULTS_PAPER": []}
    local_success = False

    if force_sim:
        simulated_dir.mkdir(parents=True, exist_ok=True)
        sim_json_path = simulated_dir / "searchsploit_raw.json"
        sim_json_path.write_text(
            generate_mock_searchsploit_json(query), encoding="utf-8"
        )
        actual_file_path = sim_json_path
        rel_raw_path = "simulated/searchsploit_raw.json"
        mode = "simulated"
        reason = "binary_not_found" if not searchsploit_bin else None
        exit_code = 0
        finding_count = 2
        warnings.append("Simulated scan results. Not genuine evidence.")
        cmd_args = f'--json "{query}" [SIMULATED]'
        command_str = f"searchsploit {cmd_args}"
    else:
        raw_dir.mkdir(parents=True, exist_ok=True)
        raw_json_path = raw_dir / "searchsploit_raw.json"
        actual_file_path = raw_json_path
        rel_raw_path = "raw/searchsploit_raw.json"

        # 1. Run local searchsploit if available and not online-only
        if searchsploit_bin and active_mode in ("offline", "dual"):
            try:
                cmd = [searchsploit_bin, "--json", query]
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                if res.returncode == 0:
                    local_success = True
                    try:
                        local_data = json.loads(res.stdout)
                    except Exception:
                        local_data = {"RESULTS_EXPLOIT": [], "RESULTS_PAPER": []}
                else:
                    warnings.append(f"Local searchsploit returned code {res.returncode}")
            except Exception as e:
                warnings.append(f"Local searchsploit execution error: {e}")

        # 2. Run online intel if in dual or online mode
        online_candidates = []
        if active_mode in ("dual", "online"):
            prod, ver = extract_product_and_version(query)
            try:
                online_candidates = online_intel.query_sync(prod, ver, limit=10)
            except Exception as e:
                warnings.append(f"Online intel lookup error: {e}")

        # 3. Consolidate results based on execution outcome
        if local_success or online_candidates:
            merged = merge_searchsploit_data(
                local_data, online_candidates, query, active_mode
            )
            raw_json_path.write_text(json.dumps(merged, indent=2), encoding="utf-8")
            finding_count = len(merged["RESULTS_EXPLOIT"])
            mode = "real"
            exit_code = 0
        elif not searchsploit_bin and active_mode == "offline":
            mode = "failed"
            reason = "binary_not_found"
            exit_code = 127
            error_msg = "SearchSploit binary is not installed in current environment and online mode is disabled."
            errors.append(error_msg)
            actual_file_path = None
            rel_raw_path = None
        else:
            # Both had zero results without error
            empty_data = {"SEARCH": query, "RESULTS_EXPLOIT": [], "RESULTS_PAPER": []}
            raw_json_path.write_text(json.dumps(empty_data, indent=2), encoding="utf-8")
            finding_count = 0
            mode = "real"
            exit_code = 0

    duration = time.time() - start_time
    finished_at = datetime.now(timezone.utc).isoformat()

    status = create_scan_status(
        tool="searchsploit",
        target_id=target_id,
        target_url=query,
        started_at=started_at,
        finished_at=finished_at,
        duration_sec=duration,
        mode=mode,
        exit_code=exit_code,
        binary_available=bool(searchsploit_bin),
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
        target=query,
        tool="searchsploit",
        command=command_str,
        arguments=cmd_args,
        exit_code=exit_code,
        duration=duration,
        output_path=str(actual_file_path) if actual_file_path else "None",
        error=error_msg,
    )

    return {
        "tool": "searchsploit",
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
    parser = argparse.ArgumentParser(
        description="AI-Pentest Copilot SearchSploit Runner with Dual-Mode Support"
    )
    parser.add_argument(
        "--target-id",
        default="intel_cache",
        help="Target ID (default: intel_cache)",
    )
    parser.add_argument(
        "--query", required=True, help="Search query (product name or CVE)"
    )
    parser.add_argument(
        "--mode",
        choices=["dual", "offline", "online"],
        default=None,
        help="Threat Intel Mode (default: dual)",
    )
    parser.add_argument(
        "--simulate", action="store_true", help="Force test fixture simulation"
    )
    args = parser.parse_args()

    res = run_searchsploit_lookup(
        target_id=args.target_id,
        query=args.query,
        simulate=args.simulate,
        intel_mode=args.mode,
    )
    print(
        f"SearchSploit finished in {res['duration']:.2f}s with exit code {res['exit_code']} (mode: {res['status']['mode']})"
    )
    print(f"Raw Evidence: {res['raw_path']}")


if __name__ == "__main__":
    main()
