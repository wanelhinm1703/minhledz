#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import pathlib
from datetime import datetime, timezone

import jsonschema


class WhatwebParser:
    @classmethod
    def parse_raw_json(
        cls,
        json_path: pathlib.Path,
        scan_metadata: dict | None = None,
        schema_path: pathlib.Path | None = None,
    ) -> dict:
        if not json_path.exists():
            raise FileNotFoundError(f"Raw WhatWeb output not found at: {json_path}")

        meta = scan_metadata or {}
        structured_meta = {
            "tool": "whatweb",
            "target": meta.get("target", "unknown"),
            "command": meta.get("command", "whatweb"),
            "arguments": meta.get("arguments", ""),
            "timestamp": meta.get("timestamp", datetime.now(timezone.utc).isoformat()),
            "duration_seconds": float(meta.get("duration", 0.0)),
            "exit_code": int(meta.get("exit_code", 0)),
        }

        targets = []
        try:
            content = json_path.read_text(encoding="utf-8").strip()
            if content:
                raw_entries = json.loads(content)
                if isinstance(raw_entries, dict):
                    raw_entries = [raw_entries]

                for item in raw_entries:
                    target_str = item.get("target", meta.get("target", "unknown"))
                    http_status = int(item.get("http_status", 200))
                    plugins_dict = item.get("plugins", {})

                    technologies = []
                    for p_name, p_data in plugins_dict.items():
                        ver_list = p_data.get("version", [])
                        ver = ver_list[0] if ver_list else ""
                        technologies.append(
                            {
                                "name": p_name,
                                "version": str(ver) if ver else "",
                                "categories": [],
                            }
                        )

                    targets.append(
                        {
                            "target": target_str,
                            "http_status": http_status,
                            "plugins": plugins_dict,
                            "technologies": technologies,
                        }
                    )
        except Exception:
            pass

        structured = {
            "scan_metadata": structured_meta,
            "targets": targets,
        }

        if schema_path and schema_path.exists():
            schema_data = json.loads(schema_path.read_text(encoding="utf-8"))
            jsonschema.validate(instance=structured, schema=schema_data)

        return structured


def main():
    parser = argparse.ArgumentParser(
        description="Parse WhatWeb JSON to Structured JSON"
    )
    parser.add_argument("--json", required=True, help="Path to raw whatweb_raw.json")
    parser.add_argument(
        "--output", required=True, help="Path to output structured json"
    )
    parser.add_argument("--schema", help="Path to whatweb_result.schema.json")
    args = parser.parse_args()

    j_path = pathlib.Path(args.json)
    out_path = pathlib.Path(args.output)
    schema_p = pathlib.Path(args.schema) if args.schema else None

    structured = WhatwebParser.parse_raw_json(j_path, schema_path=schema_p)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(structured, indent=2), encoding="utf-8")
    print(f"Structured WhatWeb JSON written to: {out_path}")


if __name__ == "__main__":
    main()
