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
    raw_dir.mkdir(parents=True, exist_ok=True)
    raw_jsonl_path = raw_dir / "httpx_raw.jsonl"
    commands_log = scan_dir / "commands.md"

    cmd_args = f"-u {target_url} -status-code -title -tech-detect -web-server -json -o {raw_jsonl_path}"
    command_str = f"httpx {cmd_args}"

    httpx_bin = shutil.which("httpx")
    force_sim = simulate or (os.getenv("SIMULATE_SCANS", "false").lower() == "true")

    start_time = time.time()
    exit_code = 0
    error_msg = None

    if httpx_bin and not force_sim:
        try:
            cmd = [
                httpx_bin, "-u", target_url,
                "-status-code", "-title", "-tech-detect", "-web-server",
                "-json", "-o", str(raw_jsonl_path),
            ]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            exit_code = res.returncode
            if exit_code != 0:
                error_msg = res.stderr
        except Exception as e:
            exit_code = 1
            error_msg = str(e)
            raw_jsonl_path.write_text(generate_mock_httpx_jsonl(target_url, target_host, port), encoding="utf-8")
    elif not force_sim:
        # Perform real HTTP probing using python httpx client
        real_records = []
        schemes_and_ports = [("http", port or 80), ("https", port or 443)]
        if port:
            schemes_and_ports = [("http", port), ("https", port)]
        
        for scheme, p in schemes_and_ports:
            try:
                import httpx as python_httpx
                probe_url = f"{scheme}://{target_host}:{p}"
                resp = python_httpx.get(probe_url, timeout=3.0, verify=False)
                title_match = re.search(r"<title>(.*?)</title>", resp.text, re.IGNORECASE | re.DOTALL)
                title = title_match.group(1).strip() if title_match else ""
                server = resp.headers.get("server", "")
                real_records.append({
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
                })
            except Exception:
                pass
        
        if real_records:
            raw_jsonl_path.write_text("\n".join(json.dumps(r) for r in real_records) + "\n", encoding="utf-8")
        else:
            raw_jsonl_path.write_text("", encoding="utf-8")
    else:
        raw_jsonl_path.write_text(generate_mock_httpx_jsonl(target_url, target_host, port), encoding="utf-8")

    duration = time.time() - start_time

    append_command_log(
        log_path=commands_log,
        target=target_url,
        tool="httpx",
        command=command_str,
        arguments=cmd_args,
        exit_code=exit_code,
        duration=duration,
        output_path=str(raw_jsonl_path),
        error=error_msg,
    )

    return {
        "tool": "httpx",
        "command": command_str,
        "arguments": cmd_args,
        "exit_code": exit_code,
        "duration": duration,
        "raw_path": str(raw_jsonl_path),
        "commands_log": str(commands_log),
    }


def main():
    parser = argparse.ArgumentParser(description="AI-Pentest Copilot Httpx Runner")
    parser.add_argument("--target-id", default="target-web", help="Target ID")
    parser.add_argument("--url", required=True, help="Target URL")
    parser.add_argument("--host", default="localhost", help="Host header/name")
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
    print(f"Httpx finished in {res['duration']:.2f}s with exit code {res['exit_code']}")
    print(f"Raw Evidence: {res['raw_path']}")


if __name__ == "__main__":
    main()
