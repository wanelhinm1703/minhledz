#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import pathlib
from datetime import datetime, timezone

import jsonschema


class NiktoParser:
    @classmethod
    def parse_raw_json(
        cls,
        json_path: pathlib.Path,
        scan_metadata: dict | None = None,
        schema_path: pathlib.Path | None = None,
    ) -> dict:
        if not json_path.exists():
            raise FileNotFoundError(f"Raw Nikto output not found at: {json_path}")

        meta = scan_metadata or {}
        structured_meta = {
            "tool": "nikto",
            "target": meta.get("target", "unknown"),
            "command": meta.get("command", "nikto"),
            "arguments": meta.get("arguments", ""),
            "timestamp": meta.get("timestamp", datetime.now(timezone.utc).isoformat()),
            "duration_seconds": float(meta.get("duration", 0.0)),
            "exit_code": int(meta.get("exit_code", 0)),
        }

        host = meta.get("target", "unknown")
        ip = meta.get("target", "unknown")
        port = 80
        banner = ""
        items = []

        try:
            content = json_path.read_text(encoding="utf-8").strip()
            if content:
                raw_data = json.loads(content)
                host = raw_data.get("host", host)
                ip = raw_data.get("ip", ip)
                port = int(raw_data.get("port", port))
                banner = raw_data.get("banner", "")

                for item in raw_data.get("items", []):
                    items.append(
                        {
                            "id": str(item.get("id", "0")),
                            "osvdb": str(item.get("osvdb", "0")),
                            "method": item.get("method", "GET"),
                            "uri": item.get("uri", "/"),
                            "description": item.get("description", ""),
                            "severity": item.get("severity", "low"),
                        }
                    )
        except Exception:
            pass

        structured = {
            "scan_metadata": structured_meta,
            "host": host,
            "ip": ip,
            "port": port,
            "banner": banner,
            "items": items,
        }

        if schema_path and schema_path.exists():
            schema_data = json.loads(schema_path.read_text(encoding="utf-8"))
            jsonschema.validate(instance=structured, schema=schema_data)

        return structured


def main():
    parser = argparse.ArgumentParser(description="Parse Nikto JSON to Structured JSON")
    parser.add_argument("--json", required=True, help="Path to raw nikto_raw.json")
    parser.add_argument(
        "--output", required=True, help="Path to output structured json"
    )
    parser.add_argument("--schema", help="Path to nikto_result.schema.json")
    args = parser.parse_args()

    j_path = pathlib.Path(args.json)
    out_path = pathlib.Path(args.output)
    schema_p = pathlib.Path(args.schema) if args.schema else None

    structured = NiktoParser.parse_raw_json(j_path, schema_path=schema_p)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(structured, indent=2), encoding="utf-8")
    print(f"Structured Nikto JSON written to: {out_path}")


if __name__ == "__main__":
    main()
