#!/usr/bin/env python3
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
import pathlib
import shutil
import sys
import time

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from toolkit.scripts.run_nmap import append_command_log


def run_proxy_manual_workflow(
    target_id: str,
    target_url: str,
    tool_name: str = "burpsuite",
    proxy_port: int = 8080,
    output_dir: pathlib.Path | None = None,
    simulate: bool = False,
) -> dict:
    """Configures and records manual proxy workflow for Burp Suite or OWASP ZAP."""
    root = REPO_ROOT
    if output_dir is None:
        scan_dir = root / "toolkit" / "08-manual" / "scans" / target_id / tool_name
    else:
        scan_dir = output_dir

    raw_dir = scan_dir / "raw"
    struct_dir = scan_dir / "structured"
    raw_dir.mkdir(parents=True, exist_ok=True)
    struct_dir.mkdir(parents=True, exist_ok=True)

    raw_config_path = raw_dir / f"{tool_name}_config.json"
    structured_path = struct_dir / f"{tool_name}_result.json"
    commands_log = scan_dir / "commands.md"

    proxy_endpoint = f"127.0.0.1:{proxy_port}"
    scope_rule = f"^{target_url.replace('.', r'\.')}.*"

    # Detect binary
    bin_name = "burpsuite" if tool_name == "burpsuite" else "zap.bat"
    bin_path = shutil.which(bin_name)
    if not bin_path and tool_name == "burpsuite":
        for p in [
            r"C:\Program Files\BurpSuiteCommunity\BurpSuiteCommunity.exe",
            r"C:\Program Files\BurpSuitePro\BurpSuitePro.exe",
        ]:
            if os.path.exists(p):
                bin_path = p
                break
    elif not bin_path and tool_name == "zap":
        for p in [
            r"C:\Program Files\OWASP\Zed Attack Proxy\zap.bat",
            r"C:\Program Files (x86)\OWASP\Zed Attack Proxy\zap.bat",
        ]:
            if os.path.exists(p):
                bin_path = p
                break

    installed = bin_path is not None or simulate
    status_text = "READY_FOR_MANUAL_TESTING" if installed else "PROXY_CONFIGURED_MANUAL_LAUNCH_REQUIRED"

    config_data = {
        "tool": tool_name,
        "target": target_url,
        "proxy_endpoint": proxy_endpoint,
        "scope": {
            "include": [scope_rule],
            "exclude": [],
        },
        "binary_installed": installed,
        "binary_path": bin_path,
        "instructions": (
            f"1. Set browser proxy to {proxy_endpoint}\n"
            f"2. Ensure Target Scope includes: {target_url}\n"
            f"3. Perform controlled manual navigation and validation\n"
            f"4. Export captured traffic/issues to toolkit/08-manual/scans/{target_id}/{tool_name}/"
        ),
    }
    raw_config_path.write_text(json.dumps(config_data, indent=2), encoding="utf-8")

    structured_result = {
        "scan_metadata": {
            "tool": tool_name,
            "target": target_url,
            "command": f"{tool_name} --proxy {proxy_endpoint} --target {target_url}",
            "arguments": f"--proxy {proxy_endpoint}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "duration_seconds": 0.05,
            "exit_code": 0 if installed else 127,
        },
        "tool": tool_name,
        "target": target_url,
        "proxy_endpoint": proxy_endpoint,
        "scope_rules": [scope_rule],
        "status": status_text,
        "manual_notes": config_data["instructions"],
    }
    structured_path.write_text(json.dumps(structured_result, indent=2), encoding="utf-8")

    append_command_log(
        log_path=commands_log,
        target=target_url,
        tool=tool_name,
        command=f"{tool_name} manual workflow",
        arguments=f"proxy={proxy_endpoint}",
        exit_code=0 if installed else 127,
        duration=0.05,
        output_path=str(raw_config_path),
        error=None if installed else f"{tool_name} binary not found in standard paths",
    )

    return {
        "tool": tool_name,
        "status": status_text,
        "raw_path": str(raw_config_path),
        "structured_path": str(structured_path),
        "commands_log": str(commands_log),
        "installed": installed,
    }


def main():
    parser = argparse.ArgumentParser(description="AI-Pentest Copilot Manual Proxy Workflow Helper")
    parser.add_argument("--target-id", default="target-web", help="Target ID")
    parser.add_argument("--url", required=True, help="Target URL")
    parser.add_argument("--tool", default="burpsuite", choices=["burpsuite", "zap"], help="Tool name")
    parser.add_argument("--port", type=int, default=8080, help="Proxy port")
    parser.add_argument("--simulate", action="store_true", help="Force simulation")
    args = parser.parse_args()

    res = run_proxy_manual_workflow(
        target_id=args.target_id,
        target_url=args.url,
        tool_name=args.tool,
        proxy_port=args.port,
        simulate=args.simulate,
    )
    print(f"Proxy workflow prepared: status={res['status']}")
    print(f"Config: {res['raw_path']}")


if __name__ == "__main__":
    main()
