#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import pathlib
from datetime import datetime, timezone

import jsonschema


class NucleiParser:
    @classmethod
    def parse_raw_jsonl(
        cls,
        jsonl_path: pathlib.Path,
        scan_metadata: dict | None = None,
        schema_path: pathlib.Path | None = None,
    ) -> dict:
        if not jsonl_path.exists():
            raise FileNotFoundError(
                f"Raw Nuclei output file not found at: {jsonl_path}"
            )

        meta = scan_metadata or {}
        structured_meta = {
            "tool": "nuclei",
            "target": meta.get("target", "unknown"),
            "command": meta.get("command", "nuclei"),
            "arguments": meta.get("arguments", ""),
            "timestamp": meta.get("timestamp", datetime.now(timezone.utc).isoformat()),
            "duration_seconds": float(meta.get("duration", 0.0)),
            "exit_code": int(meta.get("exit_code", 0)),
        }

        findings = []
        with open(jsonl_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                    info = record.get("info", {})
                    findings.append(
                        {
                            "template_id": record.get(
                                "template_id", record.get("template-id", "unknown")
                            ),
                            "info": {
                                "name": info.get("name", "Unknown Finding"),
                                "severity": info.get("severity", "info"),
                                "description": info.get("description", ""),
                                "tags": info.get("tags", []),
                                "reference": info.get("reference", []),
                                "cve_id": info.get("cve_id", info.get("cve-id", [])),
                                "cwe_id": info.get("cwe_id", info.get("cwe-id", [])),
                                "cvss_score": float(
                                    info.get("cvss_score", info.get("cvss-score", 0.0))
                                ),
                            },
                            "type": record.get("type", "http"),
                            "host": record.get("host", ""),
                            "matched_at": record.get(
                                "matched_at", record.get("matched-at", "")
                            ),
                            "extracted_results": record.get(
                                "extracted_results", record.get("extracted-results", [])
                            ),
                            "curl_command": record.get(
                                "curl_command", record.get("curl-command", "")
                            ),
                        }
                    )
                except Exception:
                    pass

        structured = {
            "scan_metadata": structured_meta,
            "findings": findings,
        }

        if schema_path and schema_path.exists():
            schema_data = json.loads(schema_path.read_text(encoding="utf-8"))
            jsonschema.validate(instance=structured, schema=schema_data)

        return structured


def main():
    parser = argparse.ArgumentParser(
        description="Parse Nuclei JSONL to Structured JSON"
    )
    parser.add_argument("--jsonl", required=True, help="Path to raw nuclei_raw.jsonl")
    parser.add_argument(
        "--output", required=True, help="Path to output structured json"
    )
    parser.add_argument("--schema", help="Path to nuclei_finding.schema.json")
    args = parser.parse_args()

    j_path = pathlib.Path(args.jsonl)
    out_path = pathlib.Path(args.output)
    schema_p = pathlib.Path(args.schema) if args.schema else None

    structured = NucleiParser.parse_raw_jsonl(j_path, schema_path=schema_p)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(structured, indent=2), encoding="utf-8")
    print(f"Structured Nuclei JSON written to: {out_path}")


if __name__ == "__main__":
    main()
