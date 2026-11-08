#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import pathlib
from datetime import datetime, timezone

import jsonschema


class HttpxParser:
    @classmethod
    def parse_raw_jsonl(
        cls,
        jsonl_path: pathlib.Path,
        scan_metadata: dict | None = None,
        schema_path: pathlib.Path | None = None,
    ) -> dict:
        if not jsonl_path.exists():
            raise FileNotFoundError(f"Raw Httpx output file not found at: {jsonl_path}")

        meta = scan_metadata or {}
        structured_meta = {
            "tool": "httpx",
            "target": meta.get("target", "unknown"),
            "command": meta.get("command", "httpx"),
            "arguments": meta.get("arguments", ""),
            "timestamp": meta.get("timestamp", datetime.now(timezone.utc).isoformat()),
            "duration_seconds": float(meta.get("duration", 0.0)),
            "exit_code": int(meta.get("exit_code", 0)),
        }

        results = []
        with open(jsonl_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                    results.append(
                        {
                            "url": record.get("url", ""),
                            "input": record.get("input", ""),
                            "host": record.get("host", ""),
                            "port": int(record.get("port", 80)),
                            "scheme": record.get("scheme", "http"),
                            "status_code": int(record.get("status_code", 200)),
                            "title": record.get("title", ""),
                            "webserver": record.get("webserver", ""),
                            "content_type": record.get("content_type", ""),
                            "content_length": int(record.get("content_length", 0)),
                            "technologies": record.get("technologies", []),
                            "response_headers": record.get("response_headers", {}),
                        }
                    )
                except Exception:
                    pass

        structured = {
            "scan_metadata": structured_meta,
            "results": results,
        }

        if schema_path and schema_path.exists():
            schema_data = json.loads(schema_path.read_text(encoding="utf-8"))
            jsonschema.validate(instance=structured, schema=schema_data)

        return structured


def main():
    parser = argparse.ArgumentParser(description="Parse Httpx JSONL to Structured JSON")
    parser.add_argument("--jsonl", required=True, help="Path to raw httpx_raw.jsonl")
    parser.add_argument(
        "--output", required=True, help="Path to output structured json"
    )
    parser.add_argument("--schema", help="Path to httpx_result.schema.json")
    args = parser.parse_args()

    j_path = pathlib.Path(args.jsonl)
    out_path = pathlib.Path(args.output)
    schema_p = pathlib.Path(args.schema) if args.schema else None

    structured = HttpxParser.parse_raw_jsonl(j_path, schema_path=schema_p)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(structured, indent=2), encoding="utf-8")
    print(f"Structured Httpx JSON written to: {out_path}")


if __name__ == "__main__":
    main()
