#!/usr/bin/env python3
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import pathlib
import re
import sys
import jsonschema


class RustscanParser:
    @classmethod
    def parse_raw_output(
        cls,
        raw_path: pathlib.Path,
        scan_metadata: dict | None = None,
        schema_path: pathlib.Path | None = None,
    ) -> dict:
        if not raw_path.exists():
            raise FileNotFoundError(f"Raw RustScan file not found at: {raw_path}")

        meta = scan_metadata or {}
        structured_meta = {
            "tool": "rustscan",
            "target": meta.get("target", "unknown"),
            "command": meta.get("command", "rustscan"),
            "arguments": meta.get("arguments", ""),
            "timestamp": meta.get("timestamp", datetime.now(timezone.utc).isoformat()),
            "duration_seconds": float(meta.get("duration", 0.0)),
            "exit_code": int(meta.get("exit_code", 0)),
        }

        content = raw_path.read_text(encoding="utf-8", errors="replace")
        open_ports = set()

        # Match pattern: Open <host>:<port>
        for match in re.finditer(r"Open\s+[^:]+:(\d+)", content):
            open_ports.add(int(match.group(1)))

        # Match pattern: The ports [...] are open! or [80, 443]
        for match in re.finditer(r"ports\s+([0-9, ]+)\s+are\s+open", content, re.IGNORECASE):
            port_items = match.group(1).split(",")
            for item in port_items:
                clean_p = item.strip()
                if clean_p.isdigit():
                    open_ports.add(int(clean_p))

        ports_list = sorted(list(open_ports))

        structured = {
            "scan_metadata": structured_meta,
            "target": meta.get("target", "unknown"),
            "open_ports": ports_list,
        }

        if schema_path and schema_path.exists():
            schema_data = json.loads(schema_path.read_text(encoding="utf-8"))
            jsonschema.validate(instance=structured, schema=schema_data)

        return structured


def main():
    parser = argparse.ArgumentParser(description="Parse RustScan output to Structured JSON")
    parser.add_argument("--input", required=True, help="Path to raw rustscan_raw.txt")
    parser.add_argument("--output", required=True, help="Path to output structured json")
    parser.add_argument("--schema", help="Path to rustscan_result.schema.json")
    args = parser.parse_args()

    in_path = pathlib.Path(args.input)
    out_path = pathlib.Path(args.output)
    schema_p = pathlib.Path(args.schema) if args.schema else None

    structured = RustscanParser.parse_raw_output(in_path, schema_path=schema_p)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(structured, indent=2), encoding="utf-8")
    print(f"Structured RustScan JSON written to: {out_path}")


if __name__ == "__main__":
    main()
