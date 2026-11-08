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


def generate_mock_service_output(tool: str, host: str, port: int | None = None) -> str:
    if tool == "enum4linux":
        return f"""Starting enum4linux v0.9.1 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on {datetime.now().ctime()}

 ========================================= 
|    Target Information                   |
 ========================================= 
Target ........... {host}
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''

 ========================================= 
|    Share Enumeration on {host}          |
 ========================================= 
Sharename       Type      Comment
---------       ----      -------
print$          Disk      Printer Drivers
IPC$            IPC       IPC Service (Samba 4.9.5-Debian)
public          Disk      Anonymous File Share

 ========================================= 
|    Users on {host}                      |
 ========================================= 
user:[nobody] rid:[0x1f5]
user:[guest] rid:[0x1f8]
user:[admin] rid:[0x3e8]
"""
    elif tool == "smbclient":
        return f"""
        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        IPC$            IPC       IPC Service
        public          Disk      Public Share
Reconnecting with SMB1 for workgroup listing.
        Server               Comment
        ---------            -------
        {host}               Samba 4.9.5
"""
    elif tool == "snmpwalk":
        return f"""SNMPv2-MIB::sysDescr.0 = STRING: Linux {host} 5.10.0-8-amd64 #1 SMP Debian
SNMPv2-MIB::sysObjectID.0 = OID: NET-SNMP-MIB::netSnmpAgentOIDs.10
DISMAN-EVENT-MIB::sysUpTimeInstance = Timeticks: (1234567) 3:25:45.67
SNMPv2-MIB::sysContact.0 = STRING: Root <root@{host}>
SNMPv2-MIB::sysName.0 = STRING: lab-target-{host}
"""
    elif tool == "ldapsearch":
        return f"""# extended LDIF
# LDAPv3
# base <> with scope subtree
# filter: (objectclass=*)
# requesting: namingContexts

dn:
namingContexts: dc=lab,dc=local
supportedLDAPVersion: 3
"""
    elif tool == "database":
        db_type = "MySQL" if port == 3306 else ("PostgreSQL" if port == 5432 else "Redis")
        return f"""Database banner check on {host}:{port or 3306}
Connected successfully.
Server banner: {db_type} 8.0.28-community
Protocol version: 10
SSL enabled: yes
"""
    return f"Service enumeration completed for {tool} on {host}"


def run_service_enum_scan(
    target_id: str,
    target_host: str,
    tool_name: str,
    port: int | None = None,
    output_dir: pathlib.Path | None = None,
    simulate: bool = False,
) -> dict:
    root = REPO_ROOT
    if output_dir is None:
        scan_dir = root / "toolkit" / "06-service-enum" / "scans" / target_id / tool_name
    else:
        scan_dir = output_dir

    raw_dir = scan_dir / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)
    raw_txt_path = raw_dir / f"{tool_name}_raw.txt"
    commands_log = scan_dir / "commands.md"

    # Command construction per tool
    if tool_name == "enum4linux":
        bin_name = "enum4linux"
        cmd_args = f"-a {target_host}"
        cmd_list = [bin_name, "-a", target_host]
    elif tool_name == "smbclient":
        bin_name = "smbclient"
        cmd_args = f"-L //{target_host} -N"
        cmd_list = [bin_name, "-L", f"//{target_host}", "-N"]
    elif tool_name == "snmpwalk":
        bin_name = "snmpwalk"
        cmd_args = f"-v2c -c public {target_host}"
        cmd_list = [bin_name, "-v2c", "-c", "public", target_host]
    elif tool_name == "ldapsearch":
        bin_name = "ldapsearch"
        p_str = f":{port}" if port else ""
        cmd_args = f"-x -H ldap://{target_host}{p_str} -b \"\""
        cmd_list = [bin_name, "-x", "-H", f"ldap://{target_host}{p_str}", "-b", ""]
    elif tool_name == "database":
        # Check specific DB client according to port
        p_val = port or 3306
        if p_val == 3306:
            bin_name = "mysql"
            cmd_args = f"-h {target_host} -P 3306 -u root -e \"status;\""
            cmd_list = [bin_name, "-h", target_host, "-P", "3306", "-u", "root", "-e", "status;"]
        elif p_val == 5432:
            bin_name = "psql"
            cmd_args = f"-h {target_host} -p 5432 -U postgres -l"
            cmd_list = [bin_name, "-h", target_host, "-p", "5432", "-U", "postgres", "-l"]
        elif p_val == 6379:
            bin_name = "redis-cli"
            cmd_args = f"-h {target_host} -p 6379 ping"
            cmd_list = [bin_name, "-h", target_host, "-p", "6379", "ping"]
        elif p_val == 27017:
            bin_name = "mongosh"
            cmd_args = f"mongodb://{target_host}:27017 --eval \"db.version()\""
            cmd_list = [bin_name, f"mongodb://{target_host}:27017", "--eval", "db.version()"]
        else:
            bin_name = "mysql"
            cmd_args = f"-h {target_host} -P {p_val}"
            cmd_list = [bin_name, "-h", target_host, "-P", str(p_val)]
    else:
        raise ValueError(f"Unsupported service enumeration tool: {tool_name}")

    command_str = f"{bin_name} {cmd_args}"
    real_bin = shutil.which(bin_name)

    force_sim = simulate or (os.getenv("SIMULATE_SCANS", "false").lower() == "true")

    start_time = time.time()
    exit_code = 0
    error_msg = None

    if real_bin and not force_sim:
        try:
            res = subprocess.run([real_bin] + cmd_list[1:], capture_output=True, text=True, timeout=90)
            exit_code = res.returncode
            raw_txt_path.write_text(res.stdout + "\n" + res.stderr, encoding="utf-8")
            if exit_code != 0:
                error_msg = res.stderr
        except Exception as e:
            exit_code = 1
            error_msg = str(e)
            raw_txt_path.write_text(f"Error: {e}", encoding="utf-8")
    elif force_sim:
        raw_txt_path.write_text(generate_mock_service_output(tool_name, target_host, port), encoding="utf-8")
    else:
        exit_code = 127
        error_msg = f"{bin_name} binary is not installed in the current environment. Please install {bin_name}."
        raw_txt_path.write_text(error_msg, encoding="utf-8")

    duration = time.time() - start_time

    append_command_log(
        log_path=commands_log,
        target=f"{target_host}:{port or ''}",
        tool=tool_name,
        command=command_str,
        arguments=cmd_args,
        exit_code=exit_code,
        duration=duration,
        output_path=str(raw_txt_path),
        error=error_msg,
    )

    return {
        "tool": tool_name,
        "command": command_str,
        "arguments": cmd_args,
        "exit_code": exit_code,
        "duration": duration,
        "raw_path": str(raw_txt_path),
        "commands_log": str(commands_log),
        "error": error_msg,
    }


def main():
    parser = argparse.ArgumentParser(description="AI-Pentest Copilot Service Enumeration Runner")
    parser.add_argument("--target-id", default="target-local", help="Target ID")
    parser.add_argument("--host", required=True, help="Target Host/IP")
    parser.add_argument("--tool", required=True, choices=["enum4linux", "smbclient", "snmpwalk", "ldapsearch", "database"], help="Tool name")
    parser.add_argument("--port", type=int, default=None, help="Target Port")
    parser.add_argument("--simulate", action="store_true", help="Force test simulation")
    args = parser.parse_args()

    res = run_service_enum_scan(
        target_id=args.target_id,
        target_host=args.host,
        tool_name=args.tool,
        port=args.port,
        simulate=args.simulate,
    )
    print(f"{args.tool} finished in {res['duration']:.2f}s with exit code {res['exit_code']}")
    print(f"Raw Evidence: {res['raw_path']}")


if __name__ == "__main__":
    main()
