#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import pathlib
import re
from datetime import datetime, timezone

import jsonschema


class GobusterParser:
    @classmethod
    def parse_raw_output(
        cls,
        raw_path: pathlib.Path,
        scan_metadata: dict | None = None,
        schema_path: pathlib.Path | None = None,
    ) -> dict:
        if not raw_path.exists():
            raise FileNotFoundError(f"Raw Gobuster output not found at: {raw_path}")

        meta = scan_metadata or {}
        structured_meta = {
            "tool": "gobuster",
            "target": meta.get("target", "unknown"),
            "command": meta.get("command", "gobuster"),
            "arguments": meta.get("arguments", ""),
            "timestamp": meta.get("timestamp", datetime.now(timezone.utc).isoformat()),
            "duration_seconds": float(meta.get("duration", 0.0)),
            "exit_code": int(meta.get("exit_code", 0)),
            "mode": meta.get("mode", "dir"),
        }

        entries = []
        try:
            content = raw_path.read_text(encoding="utf-8", errors="replace")
            # Pattern: /path (Status: 200) [Size: 1234] [--> /redirect]
            line_pattern = re.compile(
                r"^(\S+)\s+\(Status:\s*(\d+)\)(?:\s+\[Size:\s*(\d+)\])?(?:\s+\[-->\s*(\S+)\])?",
                re.MULTILINE,
            )
            for match in line_pattern.finditer(content):
                path_val = match.group(1)
                status_code = int(match.group(2))
                size_val = int(match.group(3)) if match.group(3) else 0
                redirect_to = match.group(4) if match.group(4) else ""

                entry = {
                    "path": path_val,
                    "status": status_code,
                    "size": size_val,
                }
                if redirect_to:
                    entry["redirect_to"] = redirect_to
                entries.append(entry)
        except Exception:
            pass

        structured = {
            "scan_metadata": structured_meta,
            "entries": entries,
        }

        if schema_path and schema_path.exists():
            schema_data = json.loads(schema_path.read_text(encoding="utf-8"))
            jsonschema.validate(instance=structured, schema=schema_data)

        return structured


def main():
    parser = argparse.ArgumentParser(
        description="Parse Gobuster text to Structured JSON"
    )
    parser.add_argument("--input", required=True, help="Path to raw gobuster_raw.txt")
    parser.add_argument(
        "--output", required=True, help="Path to output structured json"
    )
    parser.add_argument("--schema", help="Path to gobuster_result.schema.json")
    args = parser.parse_args()

    in_p = pathlib.Path(args.input)
    out_p = pathlib.Path(args.output)
    schema_p = pathlib.Path(args.schema) if args.schema else None

    structured = GobusterParser.parse_raw_output(in_p, schema_path=schema_p)
    out_p.parent.mkdir(parents=True, exist_ok=True)
    out_p.write_text(json.dumps(structured, indent=2), encoding="utf-8")
    print(f"Structured Gobuster JSON written to: {out_p}")


if __name__ == "__main__":
    main()
