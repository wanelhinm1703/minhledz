#!/usr/bin/env python3
from __future__ import annotations

import argparse
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

from toolkit.scripts.scan_status import create_scan_status, save_scan_status


def generate_mock_nmap_xml(target_host: str, port: int | None = None) -> str:
    target_port = port if port else 80
    service_name = "http"
    product = "Apache httpd"
    version = "2.4.49"
    cpe = "cpe:/a:apache:http_server:2.4.49"

    if target_port == 3000:
        service_name = "http"
        product = "Node.js (Express)"
        version = "14.17.0"
        cpe = "cpe:/a:nodejs:node.js:14.17.0"
    elif target_port == 22:
        service_name = "ssh"
        product = "OpenSSH"
        version = "8.2p1 Ubuntu 4ubuntu0.3"
        cpe = "cpe:/a:openbsd:openssh:8.2p1"

    curr_ts = int(time.time())
    now_str = datetime.now().ctime()
    return f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sV -sC -Pn -T4 -p {target_port} {target_host}" start="{curr_ts}" version="7.94">
<scaninfo type="syn" protocol="tcp" numservices="1" services="{target_port}"/>
<verbose level="0"/>
<debugging level="0"/>
<host starttime="{curr_ts}" endtime="{curr_ts + 2}">
<status state="up" reason="user-set"/>
<address addr="{target_host}" addrtype="ipv4"/>
<hostnames>
  <hostname name="{target_host}" type="user"/>
</hostnames>
<ports>
  <port protocol="tcp" portid="{target_port}">
    <state state="open" reason="syn-ack" reason_ttl="64"/>
    <service name="{service_name}" product="{product}" version="{version}" method="probed" conf="10">
      <cpe>{cpe}</cpe>
    </service>
    <script id="http-title" output="Vulnerable Service Playground"/>
  </port>
</ports>
<times srtt="1500" rttvar="5000" to="100000"/>
</host>
<runstats>
  <finished time="{curr_ts + 2}" timestr="{now_str}" summary="Nmap done at {now_str}; 1 IP address (1 host up) scanned in 2.15 seconds" elapsed="2.15" exit="success"/>
  <hosts up="1" down="0" total="1"/>
</runstats>
</nmaprun>
'''


def generate_mock_nmap_normal(target_host: str, port: int | None = None) -> str:
    target_port = port if port else 80
    product = "Apache httpd 2.4.49"
    if target_port == 3000:
        product = "Node.js (Express)"
    elif target_port == 22:
        product = "OpenSSH 8.2p1"

    now_str = datetime.now().ctime()
    return f"""# Nmap 7.94 scan initiated {now_str} as: nmap -sV -sC -Pn -T4 -p {target_port} {target_host}
Nmap scan report for {target_host}
Host is up (0.0015s latency).

PORT     STATE SERVICE VERSION
{target_port}/tcp open  http    {product}
|_http-title: Vulnerable Service Playground

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at {now_str} -- 1 IP address (1 host up) scanned in 2.15 seconds
"""


def append_command_log(
    log_path: pathlib.Path,
    target: str,
    tool: str,
    command: str,
    arguments: str,
    exit_code: int,
    duration: float,
    output_path: str,
    error: str | None = None,
):
    timestamp = datetime.now(timezone.utc).isoformat()
    entry = f"""
## Scan Execution - {timestamp}
- **Target**: `{target}`
- **Tool**: `{tool}`
- **Command**: `{command}`
- **Arguments**: `{arguments}`
- **Exit Code**: `{exit_code}`
- **Duration**: `{duration:.2f}s`
- **Output Path**: `{output_path}`
- **Error**: `{error or "None"}`

---
"""
    if not log_path.exists():
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text("# Command Execution Audit Log\n\n", encoding="utf-8")

    with open(log_path, "a", encoding="utf-8") as f:
        f.write(entry)


def find_nmap_binary() -> str | None:
    bin_path = shutil.which("nmap")
    if bin_path:
        return bin_path
    windows_paths = [
        r"C:\Program Files (x86)\Nmap\nmap.exe",
        r"C:\Program Files\Nmap\nmap.exe",
        r"C:\ProgramData\chocolatey\bin\nmap.exe",
        r"C:\tools\nmap\nmap.exe",
    ]
    for p in windows_paths:
        if os.path.exists(p):
            return p
    return None


def run_nmap_scan(
    target_id: str,
    target_host: str,
    port: int | None = None,
    scripts: str | None = None,
    output_dir: pathlib.Path | None = None,
    simulate: bool = False,
) -> dict:
    root = pathlib.Path(__file__).resolve().parent.parent.parent
    if output_dir is None:
        scan_dir = root / "toolkit" / "03-network" / "scans" / target_id / "nmap"
    else:
        scan_dir = output_dir

    raw_dir = scan_dir / "raw"
    normal_dir = scan_dir / "normal"
    simulated_dir = scan_dir / "simulated"
    commands_log = scan_dir / "commands.md"

    port_arg = f"-p {port}" if port else "-F"
    script_arg = f" --script={scripts}" if scripts else ""

    nmap_binary = find_nmap_binary()
    force_sim = simulate or (os.getenv("SIMULATE_SCANS", "false").lower() == "true")

    started_at = datetime.now(timezone.utc).isoformat()
    start_time = time.time()
    exit_code = 0
    error_msg = None
    reason = None
    warnings = []
    errors = []
    mode = "real"
    raw_xml_path: pathlib.Path | None = None
    normal_txt_path: pathlib.Path | None = None
    rel_raw_path: str | None = None
    finding_count = 0

    if nmap_binary and not force_sim:
        raw_dir.mkdir(parents=True, exist_ok=True)
        normal_dir.mkdir(parents=True, exist_ok=True)
        raw_xml_path = raw_dir / "nmap_raw.xml"
        normal_txt_path = normal_dir / "nmap_normal.txt"
        rel_raw_path = "raw/nmap_raw.xml"

        nmap_args = f"-sV -Pn -T4 {port_arg}{script_arg} {target_host} -oX {raw_xml_path} -oN {normal_txt_path}"
        command_str = f"nmap {nmap_args}"

        try:
            cmd = [nmap_binary, "-sV", "-Pn", "-T4"]
            if port:
                cmd.extend(["-p", str(port)])
            else:
                cmd.append("-F")
            if scripts:
                cmd.append(f"--script={scripts}")
            cmd.extend(
                [target_host, "-oX", str(raw_xml_path), "-oN", str(normal_txt_path)]
            )

            res = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
            exit_code = res.returncode
            if exit_code != 0:
                mode = "failed"
                error_msg = res.stderr or f"Exit code {exit_code}"
                errors.append(error_msg)
                if "host seems down" in (res.stdout or "").lower():
                    reason = "host_down"
                else:
                    reason = "execution_error"
            else:
                mode = "real"
                finding_count = 1
        except subprocess.TimeoutExpired:
            mode = "failed"
            exit_code = 124
            reason = "timeout"
            error_msg = "Nmap scan timed out after 180 seconds."
            errors.append(error_msg)
        except Exception as e:
            mode = "failed"
            exit_code = 1
            reason = "execution_error"
            error_msg = str(e)
            errors.append(error_msg)
    elif force_sim:
        simulated_dir.mkdir(parents=True, exist_ok=True)
        raw_xml_path = simulated_dir / "nmap_raw.xml"
        normal_txt_path = simulated_dir / "nmap_normal.txt"
        rel_raw_path = "simulated/nmap_raw.xml"

        raw_xml_path.write_text(
            generate_mock_nmap_xml(target_host, port), encoding="utf-8"
        )
        normal_txt_path.write_text(
            generate_mock_nmap_normal(target_host, port), encoding="utf-8"
        )
        mode = "simulated"
        reason = "binary_not_found" if not nmap_binary else None
        exit_code = 0
        finding_count = 1
        warnings.append("Simulated scan results. Not genuine evidence.")
        nmap_args = f"-sV -Pn -T4 {port_arg}{script_arg} {target_host} [SIMULATED]"
        command_str = f"nmap {nmap_args}"
    else:
        # Binary not found and not simulating -> FAIL HONESTLY
        mode = "failed"
        reason = "binary_not_found"
        exit_code = 127
        error_msg = "Nmap binary is not installed in the environment."
        errors.append(error_msg)
        raw_xml_path = None
        normal_txt_path = None
        rel_raw_path = None
        nmap_args = (
            f"-sV -Pn -T4 {port_arg}{script_arg} {target_host} [BINARY NOT FOUND]"
        )
        command_str = f"nmap {nmap_args}"

    duration = time.time() - start_time
    finished_at = datetime.now(timezone.utc).isoformat()

    status = create_scan_status(
        tool="nmap",
        target_id=target_id,
        target_url=f"http://{target_host}:{port}" if port else f"http://{target_host}",
        started_at=started_at,
        finished_at=finished_at,
        duration_sec=duration,
        mode=mode,
        exit_code=exit_code,
        binary_available=bool(nmap_binary),
        reason=reason,
        raw_file_path=raw_xml_path,
        finding_count=finding_count,
        warnings=warnings,
        errors=errors,
        relative_raw_path=rel_raw_path,
    )
    save_scan_status(scan_dir, status)

    append_command_log(
        log_path=commands_log,
        target=target_host,
        tool="nmap",
        command=command_str,
        arguments=nmap_args,
        exit_code=exit_code,
        duration=duration,
        output_path=str(raw_xml_path) if raw_xml_path else "None",
        error=error_msg,
    )

    return {
        "command": command_str,
        "arguments": nmap_args,
        "exit_code": exit_code,
        "duration": duration,
        "raw_xml_path": str(raw_xml_path) if raw_xml_path else "",
        "normal_txt_path": str(normal_txt_path) if normal_txt_path else "",
        "commands_log": str(commands_log),
        "status": status.model_dump(),
    }


def main():
    parser = argparse.ArgumentParser(description="AI-Pentest Copilot Nmap Runner")
    parser.add_argument("--target-id", default="target-local", help="Target ID")
    parser.add_argument("--host", required=True, help="Target Host/IP")
    parser.add_argument("--port", type=int, default=None, help="Target Port")
    parser.add_argument("--simulate", action="store_true", help="Force simulated scan")
    args = parser.parse_args()

    res = run_nmap_scan(
        target_id=args.target_id,
        target_host=args.host,
        port=args.port,
        simulate=args.simulate,
    )
    print(
        f"Scan completed with exit code {res['exit_code']} in {res['duration']:.2f}s (mode: {res['status']['mode']})"
    )
    print(f"Raw Evidence XML: {res['raw_xml_path']}")
    print(f"Commands Log: {res['commands_log']}")


if __name__ == "__main__":
    main()
