#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import pathlib
from datetime import datetime, timezone

import jsonschema


class MasscanParser:
    @classmethod
    def parse_raw_json(
        cls,
        json_path: pathlib.Path,
        scan_metadata: dict | None = None,
        schema_path: pathlib.Path | None = None,
    ) -> dict:
        if not json_path.exists():
            raise FileNotFoundError(f"Raw Masscan JSON file not found at: {json_path}")

        meta = scan_metadata or {}
        structured_meta = {
            "tool": "masscan",
            "target": meta.get("target", "unknown"),
            "command": meta.get("command", "masscan"),
            "arguments": meta.get("arguments", ""),
            "timestamp": meta.get("timestamp", datetime.now(timezone.utc).isoformat()),
            "duration_seconds": float(meta.get("duration", 0.0)),
            "exit_code": int(meta.get("exit_code", 0)),
            "rate": int(meta.get("rate", 1000)),
        }

        hosts_dict = {}
        try:
            raw_text = json_path.read_text(encoding="utf-8").strip()
            if raw_text:
                entries = json.loads(raw_text)
                for entry in entries:
                    ip = entry.get("ip")
                    if not ip:
                        continue
                    if ip not in hosts_dict:
                        hosts_dict[ip] = []
                    for port_info in entry.get("ports", []):
                        hosts_dict[ip].append(
                            {
                                "port": int(port_info.get("port", 0)),
                                "proto": port_info.get("proto", "tcp"),
                                "status": port_info.get("status", "open"),
                                "reason": port_info.get("reason", "syn-ack"),
                                "ttl": int(port_info.get("ttl", 64)),
                            }
                        )
        except Exception:
            pass

        hosts_list = [{"ip": ip, "ports": ports} for ip, ports in hosts_dict.items()]

        structured = {
            "scan_metadata": structured_meta,
            "hosts": hosts_list,
        }

        if schema_path and schema_path.exists():
            schema_data = json.loads(schema_path.read_text(encoding="utf-8"))
            jsonschema.validate(instance=structured, schema=schema_data)

        return structured


def main():
    parser = argparse.ArgumentParser(
        description="Parse Masscan JSON to Structured JSON"
    )
    parser.add_argument("--json", required=True, help="Path to raw masscan_raw.json")
    parser.add_argument(
        "--output", required=True, help="Path to output structured json"
    )
    parser.add_argument("--schema", help="Path to masscan_result.schema.json")
    args = parser.parse_args()

    j_path = pathlib.Path(args.json)
    out_path = pathlib.Path(args.output)
    schema_p = pathlib.Path(args.schema) if args.schema else None

    structured = MasscanParser.parse_raw_json(j_path, schema_path=schema_p)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(structured, indent=2), encoding="utf-8")
    print(f"Structured Masscan JSON written to: {out_path}")


if __name__ == "__main__":
    main()
