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

from toolkit.scripts.run_nmap import append_command_log
from toolkit.scripts.scan_status import create_scan_status, save_scan_status


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
        return f"""SNMPv2-MIB::sysDescr.0 = STRING: Linux {host} 5.4.0-42-generic #46-Ubuntu SMP Fri Jul 10 00:24:02 UTC 2020 x86_64
SNMPv2-MIB::sysObjectID.0 = OID: NET-SNMP-MIB::netSnmpAgentOIDs.10
DISMAN-EVENT-MIB::sysUpTimeInstance = Timeticks: (452103) 1:15:21.03
SNMPv2-MIB::sysContact.0 = STRING: Sysadmin <admin@{host}>
SNMPv2-MIB::sysName.0 = STRING: lab-target-srv01
SNMPv2-MIB::sysLocation.0 = STRING: Primary Datacenter
"""
    elif tool == "ldapsearch":
        return """# extended LDIF
# LDAPv3
# base <> with scope subtree
# filter: (objectclass=*)
# requesting: ALL
#

# lab.local
dn: dc=lab,dc=local
objectClass: top
objectClass: dcObject
objectClass: organization
o: Lab Local Organization
dc: lab

# admin, lab.local
dn: cn=admin,dc=lab,dc=local
objectClass: simpleSecurityObject
objectClass: organizationalRole
cn: admin
description: LDAP Administrator

# search result
search: 2
result: 0 Success
numResponses: 3
numEntries: 2
"""
    elif tool == "database":
        db_type = (
            "MySQL" if port == 3306 else ("PostgreSQL" if port == 5432 else "Redis")
        )
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
        scan_dir = (
            root / "toolkit" / "06-service-enum" / "scans" / target_id / tool_name
        )
    else:
        scan_dir = output_dir

    raw_dir = scan_dir / "raw"
    simulated_dir = scan_dir / "simulated"
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
        cmd_args = f'-x -H ldap://{target_host}{p_str} -b ""'
        cmd_list = [bin_name, "-x", "-H", f"ldap://{target_host}{p_str}", "-b", ""]
    elif tool_name == "database":
        p_val = port or 3306
        if p_val == 3306:
            bin_name = "mysql"
            cmd_args = f'-h {target_host} -P 3306 -u root -e "status;"'
            cmd_list = [
                bin_name,
                "-h",
                target_host,
                "-P",
                "3306",
                "-u",
                "root",
                "-e",
                "status;",
            ]
        elif p_val == 5432:
            bin_name = "psql"
            cmd_args = f"-h {target_host} -p 5432 -U postgres -l"
            cmd_list = [
                bin_name,
                "-h",
                target_host,
                "-p",
                "5432",
                "-U",
                "postgres",
                "-l",
            ]
        elif p_val == 6379:
            bin_name = "redis-cli"
            cmd_args = f"-h {target_host} -p 6379 ping"
            cmd_list = [bin_name, "-h", target_host, "-p", "6379", "ping"]
        elif p_val == 27017:
            bin_name = "mongosh"
            cmd_args = f'mongodb://{target_host}:27017 --eval "db.version()"'
            cmd_list = [
                bin_name,
                f"mongodb://{target_host}:27017",
                "--eval",
                "db.version()",
            ]
        else:
            bin_name = "mysql"
            cmd_args = f"-h {target_host} -P {p_val}"
            cmd_list = [bin_name, "-h", target_host, "-P", str(p_val)]
    else:
        raise ValueError(f"Unsupported service enumeration tool: {tool_name}")

    command_str = f"{bin_name} {cmd_args}"
    real_bin = shutil.which(bin_name)
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

    if real_bin and not force_sim:
        raw_dir.mkdir(parents=True, exist_ok=True)
        raw_txt_path = raw_dir / f"{tool_name}_raw.txt"
        actual_file_path = raw_txt_path
        rel_raw_path = f"raw/{tool_name}_raw.txt"

        try:
            res = subprocess.run(
                [real_bin] + cmd_list[1:], capture_output=True, text=True, timeout=90
            )
            exit_code = res.returncode
            raw_txt_path.write_text(
                (res.stdout or "") + "\n" + (res.stderr or ""), encoding="utf-8"
            )
            if exit_code != 0:
                mode = "failed"
                error_msg = res.stderr or f"Exit code {exit_code}"
                errors.append(error_msg)
                reason = "execution_error"
            else:
                mode = "real"
                finding_count = 1
        except subprocess.TimeoutExpired:
            mode = "failed"
            exit_code = 124
            reason = "timeout"
            error_msg = f"{tool_name} scan timed out after 90 seconds."
            errors.append(error_msg)
        except Exception as e:
            mode = "failed"
            exit_code = 1
            reason = "execution_error"
            error_msg = str(e)
            errors.append(error_msg)
    elif force_sim:
        simulated_dir.mkdir(parents=True, exist_ok=True)
        sim_txt_path = simulated_dir / f"{tool_name}_raw.txt"
        sim_txt_path.write_text(
            generate_mock_service_output(tool_name, target_host, port), encoding="utf-8"
        )
        actual_file_path = sim_txt_path
        rel_raw_path = f"simulated/{tool_name}_raw.txt"
        mode = "simulated"
        reason = "binary_not_found" if not real_bin else None
        exit_code = 0
        finding_count = 1
        warnings.append("Simulated scan results. Not genuine evidence.")
        cmd_args = f"{cmd_args} [SIMULATED]"
        command_str = f"{bin_name} {cmd_args}"
    else:
        mode = "failed"
        reason = "binary_not_found"
        exit_code = 127
        error_msg = f"{bin_name} binary is not installed in the current environment. Please install {bin_name}."
        errors.append(error_msg)
        actual_file_path = None
        rel_raw_path = None
        cmd_args = f"{cmd_args} [BINARY NOT FOUND]"
        command_str = f"{bin_name} {cmd_args}"

    duration = time.time() - start_time
    finished_at = datetime.now(timezone.utc).isoformat()

    status = create_scan_status(
        tool=tool_name,
        target_id=target_id,
        target_url=f"http://{target_host}:{port or ''}",
        started_at=started_at,
        finished_at=finished_at,
        duration_sec=duration,
        mode=mode,
        exit_code=exit_code,
        binary_available=bool(real_bin),
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
        target=f"{target_host}:{port or ''}",
        tool=tool_name,
        command=command_str,
        arguments=cmd_args,
        exit_code=exit_code,
        duration=duration,
        output_path=str(actual_file_path) if actual_file_path else "None",
        error=error_msg,
    )

    return {
        "tool": tool_name,
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
        description="AI-Pentest Copilot Service Enumeration Runner"
    )
    parser.add_argument("--target-id", default="target-local", help="Target ID")
    parser.add_argument("--host", required=True, help="Target Host/IP")
    parser.add_argument(
        "--tool",
        required=True,
        choices=["enum4linux", "smbclient", "snmpwalk", "ldapsearch", "database"],
        help="Tool name",
    )
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
    print(
        f"{args.tool} finished in {res['duration']:.2f}s with exit code {res['exit_code']} (mode: {res['status']['mode']})"
    )
    print(f"Raw Evidence: {res['raw_path']}")


if __name__ == "__main__":
    main()
