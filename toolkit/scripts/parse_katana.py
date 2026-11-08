#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import pathlib
from datetime import datetime, timezone

import jsonschema


class KatanaParser:
    @classmethod
    def parse_raw_jsonl(
        cls,
        jsonl_path: pathlib.Path,
        scan_metadata: dict | None = None,
        schema_path: pathlib.Path | None = None,
    ) -> dict:
        if not jsonl_path.exists():
            raise FileNotFoundError(f"Raw Katana output not found at: {jsonl_path}")

        meta = scan_metadata or {}
        structured_meta = {
            "tool": "katana",
            "target": meta.get("target", "unknown"),
            "command": meta.get("command", "katana"),
            "arguments": meta.get("arguments", ""),
            "timestamp": meta.get("timestamp", datetime.now(timezone.utc).isoformat()),
            "duration_seconds": float(meta.get("duration", 0.0)),
            "exit_code": int(meta.get("exit_code", 0)),
        }

        endpoints = []
        try:
            with open(jsonl_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        record = json.loads(line)
                        req = record.get("request", {})
                        ep = (
                            req.get("endpoint")
                            or record.get("endpoint")
                            or record.get("url")
                        )
                        if ep:
                            endpoints.append(
                                {
                                    "endpoint": str(ep),
                                    "method": str(req.get("method", "GET")),
                                    "source": str(record.get("source", "crawler")),
                                    "tag": str(req.get("tag", "a")),
                                    "attribute": str(req.get("attribute", "href")),
                                }
                            )
                    except Exception:
                        pass
        except Exception:
            pass

        structured = {
            "scan_metadata": structured_meta,
            "endpoints": endpoints,
        }

        if schema_path and schema_path.exists():
            schema_data = json.loads(schema_path.read_text(encoding="utf-8"))
            jsonschema.validate(instance=structured, schema=schema_data)

        return structured


def main():
    parser = argparse.ArgumentParser(
        description="Parse Katana JSONL to Structured JSON"
    )
    parser.add_argument("--jsonl", required=True, help="Path to raw katana_raw.jsonl")
    parser.add_argument(
        "--output", required=True, help="Path to output structured json"
    )
    parser.add_argument("--schema", help="Path to katana_result.schema.json")
    args = parser.parse_args()

    j_p = pathlib.Path(args.jsonl)
    out_p = pathlib.Path(args.output)
    schema_p = pathlib.Path(args.schema) if args.schema else None

    structured = KatanaParser.parse_raw_jsonl(j_p, schema_path=schema_p)
    out_p.parent.mkdir(parents=True, exist_ok=True)
    out_p.write_text(json.dumps(structured, indent=2), encoding="utf-8")
    print(f"Structured Katana JSON written to: {out_p}")


if __name__ == "__main__":
    main()
