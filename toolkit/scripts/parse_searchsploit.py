#!/usr/bin/env python3
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import pathlib
import sys
import jsonschema


class SearchsploitParser:
    @classmethod
    def parse_raw_json(
        cls,
        json_path: pathlib.Path,
        scan_metadata: dict | None = None,
        schema_path: pathlib.Path | None = None,
    ) -> dict:
        if not json_path.exists():
            raise FileNotFoundError(f"Raw SearchSploit output not found at: {json_path}")

        meta = scan_metadata or {}
        structured_meta = {
            "tool": "searchsploit",
            "target": meta.get("target", "unknown"),
            "command": meta.get("command", "searchsploit"),
            "arguments": meta.get("arguments", ""),
            "timestamp": meta.get("timestamp", datetime.now(timezone.utc).isoformat()),
            "duration_seconds": float(meta.get("duration", 0.0)),
            "exit_code": int(meta.get("exit_code", 0)),
        }

        query = meta.get("target", "")
        results = []
        try:
            content = json_path.read_text(encoding="utf-8").strip()
            if content:
                data = json.loads(content)
                query = data.get("SEARCH", query)
                exploits = data.get("RESULTS_EXPLOIT", [])
                for exp in exploits:
                    cve_list = []
                    codes = exp.get("Codes", "")
                    if codes:
                        cve_list = [c.strip() for c in codes.split(";") if c.strip().upper().startswith("CVE-")]

                    results.append({
                        "title": exp.get("Title", ""),
                        "edb_id": str(exp.get("EDB-ID", "")),
                        "date": exp.get("Date", ""),
                        "author": exp.get("Author", ""),
                        "type": exp.get("Type", "remote"),
                        "platform": exp.get("Platform", "unknown"),
                        "path": exp.get("Path", ""),
                        "cve_ids": cve_list,
                    })
        except Exception:
            pass

        structured = {
            "scan_metadata": structured_meta,
            "query": query,
            "results": results,
        }

        if schema_path and schema_path.exists():
            schema_data = json.loads(schema_path.read_text(encoding="utf-8"))
            jsonschema.validate(instance=structured, schema=schema_data)

        return structured


def main():
    parser = argparse.ArgumentParser(description="Parse SearchSploit JSON to Structured JSON")
    parser.add_argument("--json", required=True, help="Path to raw searchsploit_raw.json")
    parser.add_argument("--output", required=True, help="Path to output structured json")
    parser.add_argument("--schema", help="Path to searchsploit_result.schema.json")
    args = parser.parse_args()

    j_p = pathlib.Path(args.json)
    out_p = pathlib.Path(args.output)
    schema_p = pathlib.Path(args.schema) if args.schema else None

    structured = SearchsploitParser.parse_raw_json(j_p, schema_path=schema_p)
    out_p.parent.mkdir(parents=True, exist_ok=True)
    out_p.write_text(json.dumps(structured, indent=2), encoding="utf-8")
    print(f"Structured SearchSploit JSON written to: {out_p}")


if __name__ == "__main__":
    main()
