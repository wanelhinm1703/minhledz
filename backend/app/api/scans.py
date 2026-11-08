from __future__ import annotations

import json
import pathlib
import shutil

from fastapi import APIRouter, HTTPException, Query

from backend.app.services.tool_registry import tool_registry

router = APIRouter(prefix="/scans", tags=["scans"])

root_dir = pathlib.Path(__file__).resolve().parent.parent.parent.parent
scans_net_dir = root_dir / "toolkit" / "03-network" / "scans"
scans_web_dir = root_dir / "toolkit" / "04-web" / "scans"
scans_vuln_dir = root_dir / "toolkit" / "05-vulnerability" / "scans"
scans_enum_dir = root_dir / "toolkit" / "06-service-enum" / "scans"
scans_manual_dir = root_dir / "toolkit" / "08-manual" / "scans"

ALL_SCAN_DIRS = [
    ("03-network", scans_net_dir),
    ("04-web", scans_web_dir),
    ("05-vulnerability", scans_vuln_dir),
    ("06-service-enum", scans_enum_dir),
    ("08-manual", scans_manual_dir),
]


EXCLUDED_SCAN_TARGETS = {
    "target-vuln",
    "intel_cache",
    "temp",
    "scratch",
    "general",
    ".git",
}


@router.get("/tools")
def get_tools_availability():
    """Return live availability and version status for all tools in the pentest toolset."""
    return tool_registry.get_all_availability()


@router.get("")
def list_scans():
    """Dynamically discover all scan artifacts across all original tool categories."""
    results = []
    targets_seen = set()

    for _, base in ALL_SCAN_DIRS:
        if base.exists():
            for t_dir in base.iterdir():
                if t_dir.is_dir() and t_dir.name not in EXCLUDED_SCAN_TARGETS:
                    targets_seen.add(t_dir.name)

    for tid in sorted(targets_seen):
        tools = []
        files = []
        tool_statuses = {}

        for category_name, base_dir in ALL_SCAN_DIRS:
            target_tool_root = base_dir / tid
            if not target_tool_root.exists() or not target_tool_root.is_dir():
                continue

            for tool_dir in target_tool_root.iterdir():
                if not tool_dir.is_dir():
                    continue

                tool_name = tool_dir.name
                tools.append(tool_name)

                # 0. Scan Status (status.json)
                status_file = tool_dir / "status.json"
                if status_file.exists():
                    rel_p = f"{category_name}/scans/{tid}/{tool_name}/status.json"
                    files.append(
                        {
                            "name": "status.json",
                            "tool": tool_name,
                            "type": "status",
                            "rel_path": rel_p,
                        }
                    )
                    try:
                        tool_statuses[tool_name] = json.loads(
                            status_file.read_text(encoding="utf-8", errors="replace")
                        )
                    except Exception:
                        pass

                # 1. Structured files
                struct_dir = tool_dir / "structured"
                if struct_dir.exists():
                    for f in struct_dir.iterdir():
                        if f.is_file() and f.suffix.lower() == ".json":
                            rel_p = f"{category_name}/scans/{tid}/{tool_name}/structured/{f.name}"
                            files.append(
                                {
                                    "name": f.name,
                                    "tool": tool_name,
                                    "type": "structured",
                                    "rel_path": rel_p,
                                }
                            )

                # 2. Raw files
                raw_dir = tool_dir / "raw"
                if raw_dir.exists():
                    for f in raw_dir.iterdir():
                        if f.is_file():
                            rel_p = (
                                f"{category_name}/scans/{tid}/{tool_name}/raw/{f.name}"
                            )
                            files.append(
                                {
                                    "name": f.name,
                                    "tool": tool_name,
                                    "type": "raw",
                                    "rel_path": rel_p,
                                }
                            )

                # 3. Simulated files
                sim_dir = tool_dir / "simulated"
                if sim_dir.exists():
                    for f in sim_dir.iterdir():
                        if f.is_file():
                            rel_p = f"{category_name}/scans/{tid}/{tool_name}/simulated/{f.name}"
                            files.append(
                                {
                                    "name": f.name,
                                    "tool": tool_name,
                                    "type": "simulated",
                                    "rel_path": rel_p,
                                }
                            )

                # 4. Normal / stdout files
                norm_dir = tool_dir / "normal"
                if norm_dir.exists():
                    for f in norm_dir.iterdir():
                        if f.is_file():
                            rel_p = f"{category_name}/scans/{tid}/{tool_name}/normal/{f.name}"
                            files.append(
                                {
                                    "name": f.name,
                                    "tool": tool_name,
                                    "type": "normal",
                                    "rel_path": rel_p,
                                }
                            )

                # 5. Command audit log
                cmd_file = tool_dir / "commands.md"
                if cmd_file.exists():
                    rel_p = f"{category_name}/scans/{tid}/{tool_name}/commands.md"
                    files.append(
                        {
                            "name": "commands.md",
                            "tool": tool_name,
                            "type": "log",
                            "rel_path": rel_p,
                        }
                    )

        results.append(
            {
                "target_id": tid,
                "tools": sorted(list(set(tools))),
                "evidence_files": files,
                "tool_statuses": tool_statuses,
            }
        )

    return results


@router.get("/file")
def get_evidence_file(
    path: str = Query(..., description="Relative path within toolkit"),
):
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


@router.delete("/{target_id}")
def delete_target_scans(target_id: str):
    """Delete all scan evidence artifacts for a specific target across all scan directories."""
    keys_to_clean = {target_id}
    if target_id.startswith("target-"):
        keys_to_clean.add(target_id[7:])
    else:
        keys_to_clean.add(f"target-{target_id}")

    deleted_count = 0
    for key in keys_to_clean:
        # Check network, web, vuln, service-enum, manual scan directories
        for _, base in ALL_SCAN_DIRS:
            target_dir = base / key
            if target_dir.exists() and target_dir.is_dir():
                shutil.rmtree(target_dir, ignore_errors=True)
                deleted_count += 1

        # Check analysis artifacts
        manifest_file = (
            root_dir / "toolkit" / "09-analysis" / "manifests" / f"{key}_manifest.json"
        )
        if manifest_file.exists():
            manifest_file.unlink(missing_ok=True)
            deleted_count += 1

        findings_file = (
            root_dir / "toolkit" / "09-analysis" / "findings" / f"{key}_findings.json"
        )
        if findings_file.exists():
            findings_file.unlink(missing_ok=True)
            deleted_count += 1

    return {
        "status": "deleted",
        "target_id": target_id,
        "artifacts_cleaned": deleted_count,
    }
