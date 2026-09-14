from __future__ import annotations

import json
import os
import pathlib
from typing import List
from fastapi import APIRouter, HTTPException, Query

router = APIRouter(prefix="/scans", tags=["scans"])

root_dir = pathlib.Path(__file__).resolve().parent.parent.parent.parent
scans_net_dir = root_dir / "toolkit" / "03-network" / "scans"
scans_web_dir = root_dir / "toolkit" / "04-web" / "scans"
scans_vuln_dir = root_dir / "toolkit" / "05-vulnerability" / "scans"


@router.get("")
def list_scans():
    results = []
    # Collect all targets with scan artifacts
    targets_seen = set()
    for base in [scans_net_dir, scans_web_dir, scans_vuln_dir]:
        if base.exists():
            for t_dir in base.iterdir():
                if t_dir.is_dir():
                    targets_seen.add(t_dir.name)

    for tid in sorted(targets_seen):
        tools = []
        files = []

        # Nmap
        nmap_dir = scans_net_dir / tid / "nmap"
        if nmap_dir.exists():
            tools.append("nmap")
            if (nmap_dir / "structured" / "nmap_result.json").exists():
                files.append({"name": "nmap_result.json", "tool": "nmap", "type": "structured", "rel_path": f"03-network/scans/{tid}/nmap/structured/nmap_result.json"})
            if (nmap_dir / "raw" / "nmap_raw.xml").exists():
                files.append({"name": "nmap_raw.xml", "tool": "nmap", "type": "raw", "rel_path": f"03-network/scans/{tid}/nmap/raw/nmap_raw.xml"})
            if (nmap_dir / "commands.md").exists():
                files.append({"name": "commands.md", "tool": "nmap", "type": "log", "rel_path": f"03-network/scans/{tid}/nmap/commands.md"})

        # Naabu
        naabu_dir = scans_net_dir / tid / "naabu"
        if naabu_dir.exists():
            tools.append("naabu")
            if (naabu_dir / "raw" / "naabu_raw.txt").exists():
                files.append({"name": "naabu_raw.txt", "tool": "naabu", "type": "raw", "rel_path": f"03-network/scans/{tid}/naabu/raw/naabu_raw.txt"})

        # Httpx
        httpx_dir = scans_web_dir / tid / "httpx"
        if httpx_dir.exists():
            tools.append("httpx")
            if (httpx_dir / "structured" / "httpx_result.json").exists():
                files.append({"name": "httpx_result.json", "tool": "httpx", "type": "structured", "rel_path": f"04-web/scans/{tid}/httpx/structured/httpx_result.json"})
            if (httpx_dir / "raw" / "httpx_raw.jsonl").exists():
                files.append({"name": "httpx_raw.jsonl", "tool": "httpx", "type": "raw", "rel_path": f"04-web/scans/{tid}/httpx/raw/httpx_raw.jsonl"})

        # Nuclei
        nuclei_dir = scans_vuln_dir / tid / "nuclei"
        if nuclei_dir.exists():
            tools.append("nuclei")
            if (nuclei_dir / "structured" / "nuclei_result.json").exists():
                files.append({"name": "nuclei_result.json", "tool": "nuclei", "type": "structured", "rel_path": f"05-vulnerability/scans/{tid}/nuclei/structured/nuclei_result.json"})

        results.append({
            "target_id": tid,
            "tools": list(set(tools)),
            "evidence_files": files,
        })

    return results


@router.get("/file")
def get_evidence_file(path: str = Query(..., description="Relative path within toolkit")):
    clean_path = path.lstrip("/\\")
    full_path = root_dir / "toolkit" / clean_path

    # Security check: Prevent path traversal outside toolkit
    try:
        full_path.resolve().relative_to((root_dir / "toolkit").resolve())
    except ValueError:
        raise HTTPException(status_code=403, detail="Access denied: Invalid file path.")

    if not full_path.exists() or not full_path.is_file():
        raise HTTPException(status_code=404, detail=f"File not found: {path}")

    content = full_path.read_text(encoding="utf-8", errors="replace")
    is_json = full_path.suffix.lower() in [".json", ".jsonl"]
    return {
        "path": path,
        "filename": full_path.name,
        "is_json": is_json,
        "content": content,
    }
