#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
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


def generate_mock_httpx_jsonl(url: str, host: str, port: int | None = None) -> str:
    target_port = port if port else (443 if url.startswith("https") else 80)
    scheme = "https" if url.startswith("https") else "http"

    if target_port == 3000 or "juice" in url or "3000" in str(target_port):
        webserver = "Express"
        title = "OWASP Juice Shop"
        techs = ["Node.js", "Express", "Angular", "Socket.io"]
    else:
        webserver = "Apache/2.4.49 (Unix)"
        title = "Test Lab Service"
        techs = ["Apache", "PHP/7.4.21"]

    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "url": url,
        "input": host,
        "host": host,
        "port": target_port,
        "scheme": scheme,
        "status_code": 200,
        "title": title,
        "webserver": webserver,
        "content_type": "text/html; charset=utf-8",
        "content_length": 1420,
        "technologies": techs,
        "response_headers": {
            "server": webserver,
            "content-type": "text/html; charset=utf-8",
            "connection": "close",
        },
    }
    return json.dumps(record) + "\n"


def run_httpx_scan(
    target_id: str,
    target_url: str,
    target_host: str,
    port: int | None = None,
    output_dir: pathlib.Path | None = None,
    simulate: bool = False,
) -> dict:
    root = pathlib.Path(__file__).resolve().parent.parent.parent
    if output_dir is None:
        scan_dir = root / "toolkit" / "04-web" / "scans" / target_id / "httpx"
    else:
        scan_dir = output_dir

    raw_dir = scan_dir / "raw"
    simulated_dir = scan_dir / "simulated"
    commands_log = scan_dir / "commands.md"

    httpx_bin = shutil.which("httpx")
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

    if httpx_bin and not force_sim:
        raw_dir.mkdir(parents=True, exist_ok=True)
        raw_jsonl_path = raw_dir / "httpx_raw.jsonl"
        actual_file_path = raw_jsonl_path
        rel_raw_path = "raw/httpx_raw.jsonl"
        cmd_args = f"-u {target_url} -status-code -title -tech-detect -web-server -json -o {raw_jsonl_path}"
        command_str = f"httpx {cmd_args}"

        try:
            cmd = [
                httpx_bin,
                "-u",
                target_url,
                "-status-code",
                "-title",
                "-tech-detect",
                "-web-server",
                "-json",
                "-o",
                str(raw_jsonl_path),
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
            error_msg = "HTTPx scan timed out after 120 seconds."
            errors.append(error_msg)
        except Exception as e:
            mode = "failed"
            exit_code = 1
            reason = "execution_error"
            error_msg = str(e)
            errors.append(error_msg)

    elif not force_sim:
        # Check if python httpx is available for genuine probe fallback
        real_records = []
        schemes_and_ports = [("http", port or 80), ("https", port or 443)]
        if port:
            schemes_and_ports = [("http", port), ("https", port)]

        try:
            import httpx as python_httpx

            for scheme, p in schemes_and_ports:
                try:
                    probe_url = f"{scheme}://{target_host}:{p}"
                    resp = python_httpx.get(probe_url, timeout=3.0, verify=False)
                    title_match = re.search(
                        r"<title>(.*?)</title>", resp.text, re.IGNORECASE | re.DOTALL
                    )
                    title = title_match.group(1).strip() if title_match else ""
                    server = resp.headers.get("server", "")
                    real_records.append(
                        {
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                            "url": probe_url,
                            "input": target_host,
                            "host": target_host,
                            "port": p,
                            "scheme": scheme,
                            "status_code": resp.status_code,
                            "title": title,
                            "webserver": server,
                            "content_type": resp.headers.get("content-type", ""),
                            "content_length": len(resp.content),
                            "technologies": [server] if server else [],
                            "response_headers": dict(resp.headers),
                        }
                    )
                except Exception:
                    pass
        except ImportError:
            pass

        if real_records:
            raw_dir.mkdir(parents=True, exist_ok=True)
            raw_jsonl_path = raw_dir / "httpx_raw.jsonl"
            raw_jsonl_path.write_text(
                "\n".join(json.dumps(r) for r in real_records) + "\n", encoding="utf-8"
            )
            actual_file_path = raw_jsonl_path
            rel_raw_path = "raw/httpx_raw.jsonl"
            mode = "real"
            exit_code = 0
            finding_count = len(real_records)
            cmd_args = f"-u {target_url} [Python HTTP Probe]"
            command_str = f"httpx-probe {cmd_args}"
        else:
            mode = "failed"
            reason = "binary_not_found" if not httpx_bin else "connection_refused"
            exit_code = 127 if not httpx_bin else 1
            error_msg = (
                "HTTPx binary not installed and target did not respond to HTTP probe."
            )
            errors.append(error_msg)
            actual_file_path = None
            rel_raw_path = None
            cmd_args = f"-u {target_url} [FAILED]"
            command_str = f"httpx {cmd_args}"

    else:
        # force_sim == True
        simulated_dir.mkdir(parents=True, exist_ok=True)
        sim_jsonl_path = simulated_dir / "httpx_raw.jsonl"
        sim_jsonl_path.write_text(
            generate_mock_httpx_jsonl(target_url, target_host, port), encoding="utf-8"
        )
        actual_file_path = sim_jsonl_path
        rel_raw_path = "simulated/httpx_raw.jsonl"
        mode = "simulated"
        reason = "binary_not_found" if not httpx_bin else None
        exit_code = 0
        finding_count = 1
        warnings.append("Simulated scan results. Not genuine evidence.")
        cmd_args = f"-u {target_url} [SIMULATED]"
        command_str = f"httpx {cmd_args}"

    duration = time.time() - start_time
    finished_at = datetime.now(timezone.utc).isoformat()

    status = create_scan_status(
        tool="httpx",
        target_id=target_id,
        target_url=target_url,
        started_at=started_at,
        finished_at=finished_at,
        duration_sec=duration,
        mode=mode,
        exit_code=exit_code,
        binary_available=bool(httpx_bin),
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
        tool="httpx",
        command=command_str,
        arguments=cmd_args,
        exit_code=exit_code,
        duration=duration,
        output_path=str(actual_file_path) if actual_file_path else "None",
        error=error_msg,
    )

    return {
        "tool": "httpx",
        "command": command_str,
        "arguments": cmd_args,
        "exit_code": exit_code,
        "duration": duration,
        "raw_path": str(actual_file_path) if actual_file_path else "",
        "commands_log": str(commands_log),
        "status": status.model_dump(),
    }


def main():
    parser = argparse.ArgumentParser(description="AI-Pentest Copilot HTTPx Runner")
    parser.add_argument("--target-id", default="target-web", help="Target ID")
    parser.add_argument("--url", required=True, help="Target URL")
    parser.add_argument("--host", default="localhost", help="Host name")
    parser.add_argument("--port", type=int, default=None, help="Port")
    parser.add_argument("--simulate", action="store_true", help="Force simulation")
    args = parser.parse_args()

    res = run_httpx_scan(
        target_id=args.target_id,
        target_url=args.url,
        target_host=args.host,
        port=args.port,
        simulate=args.simulate,
    )
    print(
        f"HTTPx finished in {res['duration']:.2f}s with exit code {res['exit_code']} (mode: {res['status']['mode']})"
    )
    print(f"Raw Evidence: {res['raw_path']}")


if __name__ == "__main__":
    main()
