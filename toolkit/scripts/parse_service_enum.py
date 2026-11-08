#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import pathlib
import re
from datetime import datetime, timezone

import jsonschema


class ServiceEnumParser:
    @classmethod
    def parse_raw_output(
        cls,
        raw_path: pathlib.Path,
        service_name: str,
        scan_metadata: dict | None = None,
        schema_path: pathlib.Path | None = None,
    ) -> dict:
        if not raw_path.exists():
            raise FileNotFoundError(f"Raw service enum file not found at: {raw_path}")

        meta = scan_metadata or {}
        structured_meta = {
            "tool": meta.get("tool", service_name),
            "target": meta.get("target", "unknown"),
            "command": meta.get("command", service_name),
            "arguments": meta.get("arguments", ""),
            "timestamp": meta.get("timestamp", datetime.now(timezone.utc).isoformat()),
            "duration_seconds": float(meta.get("duration", 0.0)),
            "exit_code": int(meta.get("exit_code", 0)),
        }

        content = raw_path.read_text(encoding="utf-8", errors="replace")
        findings = []
        shares = []
        users = []

        if service_name in ("enum4linux", "smbclient"):
            # Extract SMB shares
            # Sharename Type Comment
            for line in content.splitlines():
                line = line.strip()
                match = re.match(
                    r"^([a-zA-Z0-9_$-]+)\s+(Disk|IPC|Printer|Special)\s*(.*)?", line
                )
                if match and not match.group(1).lower().startswith("sharename"):
                    s_name = match.group(1)
                    s_type = match.group(2)
                    s_comment = match.group(3) or ""
                    shares.append(
                        {"name": s_name, "type": s_type, "comment": s_comment.strip()}
                    )

            # Extract users
            for match in re.finditer(r"user:\[([^\]]+)\]", content):
                users.append(match.group(1))

            if shares:
                findings.append(
                    {
                        "category": "smb_shares",
                        "description": f"Discovered {len(shares)} SMB shares on target: {', '.join(s['name'] for s in shares)}",
                        "details": {"shares": shares},
                        "severity": "info",
                    }
                )
            if users:
                findings.append(
                    {
                        "category": "smb_users",
                        "description": f"Enumerated {len(users)} local/domain user accounts via SMB",
                        "details": {"users": users},
                        "severity": "medium",
                    }
                )

        elif service_name == "snmpwalk":
            sys_descr = ""
            for line in content.splitlines():
                if "sysDescr" in line:
                    sys_descr = line.split("=", 1)[-1].strip()
                    break
            if sys_descr:
                findings.append(
                    {
                        "category": "snmp_system_info",
                        "description": f"SNMP public community string accepted. System info: {sys_descr}",
                        "details": {"sysDescr": sys_descr},
                        "severity": "medium",
                    }
                )

        elif service_name == "ldapsearch":
            contexts = []
            for line in content.splitlines():
                if "namingContexts:" in line:
                    contexts.append(line.split(":", 1)[-1].strip())
            if contexts:
                findings.append(
                    {
                        "category": "ldap_naming_contexts",
                        "description": f"Discovered LDAP base naming contexts: {', '.join(contexts)}",
                        "details": {"namingContexts": contexts},
                        "severity": "info",
                    }
                )

        elif service_name == "database":
            if "Connected successfully" in content or "Server banner" in content:
                banner_match = re.search(r"Server banner:\s*(.+)", content)
                banner = banner_match.group(1) if banner_match else "Database response"
                findings.append(
                    {
                        "category": "database_connection",
                        "description": f"Database service accessible. Banner: {banner}",
                        "details": {"banner": banner},
                        "severity": "info",
                    }
                )

        if not findings:
            findings.append(
                {
                    "category": "service_enumeration",
                    "description": f"Service enumeration completed for {service_name}.",
                    "details": {},
                    "severity": "info",
                }
            )

        structured = {
            "scan_metadata": structured_meta,
            "service": service_name,
            "findings": findings,
            "shares": shares,
            "users": users,
        }

        if schema_path and schema_path.exists():
            schema_data = json.loads(schema_path.read_text(encoding="utf-8"))
            jsonschema.validate(instance=structured, schema=schema_data)

        return structured


def main():
    parser = argparse.ArgumentParser(
        description="Parse Service Enumeration output to Structured JSON"
    )
    parser.add_argument("--input", required=True, help="Path to raw service output")
    parser.add_argument(
        "--service", required=True, help="Service name (enum4linux, smbclient, etc.)"
    )
    parser.add_argument(
        "--output", required=True, help="Path to output structured json"
    )
    parser.add_argument("--schema", help="Path to service_enum_result.schema.json")
    args = parser.parse_args()

    in_p = pathlib.Path(args.input)
    out_p = pathlib.Path(args.output)
    schema_p = pathlib.Path(args.schema) if args.schema else None

    structured = ServiceEnumParser.parse_raw_output(
        in_p, service_name=args.service, schema_path=schema_p
    )
    out_p.parent.mkdir(parents=True, exist_ok=True)
    out_p.write_text(json.dumps(structured, indent=2), encoding="utf-8")
    print(f"Structured Service Enum JSON written to: {out_p}")


if __name__ == "__main__":
    main()
