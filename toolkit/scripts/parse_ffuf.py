#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import pathlib
from datetime import datetime, timezone

import jsonschema


class FfufParser:
    @classmethod
    def parse_raw_json(
        cls,
        json_path: pathlib.Path,
        scan_metadata: dict | None = None,
        schema_path: pathlib.Path | None = None,
    ) -> dict:
        if not json_path.exists():
            raise FileNotFoundError(f"Raw FFUF output not found at: {json_path}")

        meta = scan_metadata or {}
        structured_meta = {
            "tool": "ffuf",
            "target": meta.get("target", "unknown"),
            "command": meta.get("command", "ffuf"),
            "arguments": meta.get("arguments", ""),
            "timestamp": meta.get("timestamp", datetime.now(timezone.utc).isoformat()),
            "duration_seconds": float(meta.get("duration", 0.0)),
            "exit_code": int(meta.get("exit_code", 0)),
        }

        results = []
        try:
            content = json_path.read_text(encoding="utf-8").strip()
            if content:
                data = json.loads(content)
                raw_results = data.get("results", [])
                for r in raw_results:
                    inp = r.get("input", {})
                    # If input is dict like {"FUZZ": "login"}, extract first value
                    input_str = (
                        next(iter(inp.values()))
                        if isinstance(inp, dict) and inp
                        else str(inp)
                    )
                    results.append(
                        {
                            "input": str(input_str),
                            "position": int(r.get("position", 0)),
                            "status": int(r.get("status", 200)),
                            "length": int(r.get("length", 0)),
                            "words": int(r.get("words", 0)),
                            "lines": int(r.get("lines", 0)),
                            "url": r.get("url", ""),
                            "redirectlocation": r.get("redirectlocation", ""),
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
    parser = argparse.ArgumentParser(description="Parse FFUF JSON to Structured JSON")
    parser.add_argument("--json", required=True, help="Path to raw ffuf_raw.json")
    parser.add_argument(
        "--output", required=True, help="Path to output structured json"
    )
    parser.add_argument("--schema", help="Path to ffuf_result.schema.json")
    args = parser.parse_args()

    j_p = pathlib.Path(args.json)
    out_p = pathlib.Path(args.output)
    schema_p = pathlib.Path(args.schema) if args.schema else None

    structured = FfufParser.parse_raw_json(j_p, schema_path=schema_p)
    out_p.parent.mkdir(parents=True, exist_ok=True)
    out_p.write_text(json.dumps(structured, indent=2), encoding="utf-8")
    print(f"Structured FFUF JSON written to: {out_p}")


if __name__ == "__main__":
    main()
