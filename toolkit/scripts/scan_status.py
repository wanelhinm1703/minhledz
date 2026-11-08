"""
AI-Pentest Copilot - Scan Result & Evidence Status Taxonomy Manager.
Enforces strict distinction between REAL, SIMULATED, and FAILED scans across all tools.
Preserves raw evidence integrity (MASTER PROMPT v5.0 §17, §29, §53, §75).
"""

from __future__ import annotations

import hashlib
import json
import pathlib
from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, Field

ScanMode = Literal["real", "simulated", "failed"]
FailureReason = Literal[
    "binary_not_found",
    "timeout",
    "connection_refused",
    "scope_blocked",
    None,
]


class ScanStatus(BaseModel):
    tool: str
    target_id: str
    target_url: str | None = None
    started_at: str
    finished_at: str
    duration_sec: float
    mode: ScanMode
    reason: str | None = None
    exit_code: int
    binary_available: bool
    evidence_trustworthy: bool
    raw_path: str | None = None
    raw_sha256: str | None = None
    raw_size_bytes: int = 0
    finding_count: int = 0
    warnings: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)


def compute_file_sha256(filepath: pathlib.Path) -> str | None:
    """Compute SHA256 hex digest of a raw output file. Returns None if file does not exist."""
    if not filepath.exists() or not filepath.is_file():
        return None
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()


def create_scan_status(
    tool: str,
    target_id: str,
    target_url: str | None = None,
    started_at: str | None = None,
    finished_at: str | None = None,
    duration_sec: float = 0.0,
    mode: ScanMode = "real",
    exit_code: int = 0,
    binary_available: bool = True,
    reason: str | None = None,
    raw_file_path: pathlib.Path | None = None,
    finding_count: int = 0,
    warnings: list[str] | None = None,
    errors: list[str] | None = None,
    relative_raw_path: str | None = None,
    evidence_trustworthy: bool | None = None,
) -> ScanStatus:
    """Factory helper to construct a strictly compliant ScanStatus instance."""
    now_iso = datetime.now(timezone.utc).isoformat()
    started_at = started_at or now_iso
    finished_at = finished_at or now_iso

    raw_sha256 = None
    raw_size_bytes = 0

    if raw_file_path and raw_file_path.exists() and raw_file_path.is_file():
        raw_sha256 = compute_file_sha256(raw_file_path)
        raw_size_bytes = raw_file_path.stat().st_size

    # evidence_trustworthy is TRUE strictly when mode is 'real' and exit_code is 0
    if evidence_trustworthy is None:
        evidence_trustworthy = (mode == "real") and (exit_code == 0)

    # Clean warnings & errors
    warn_list = list(warnings or [])
    err_list = list(errors or [])

    if (
        mode == "simulated"
        and "Simulated scan results. Not genuine evidence." not in warn_list
    ):
        warn_list.append("Simulated scan results. Not genuine evidence.")

    return ScanStatus(
        tool=tool,
        target_id=target_id,
        target_url=target_url,
        started_at=started_at,
        finished_at=finished_at,
        duration_sec=round(duration_sec, 2),
        mode=mode,
        reason=reason,
        exit_code=exit_code,
        binary_available=binary_available,
        evidence_trustworthy=evidence_trustworthy,
        raw_path=relative_raw_path,
        raw_sha256=raw_sha256,
        raw_size_bytes=raw_size_bytes,
        finding_count=finding_count,
        warnings=warn_list,
        errors=err_list,
    )


def save_scan_status(
    tool_dir: pathlib.Path, status: ScanStatus | dict[str, Any]
) -> pathlib.Path:
    """Save status.json directly in the tool scan directory (next to raw/ or simulated/)."""
    tool_dir.mkdir(parents=True, exist_ok=True)
    status_file = tool_dir / "status.json"
    if isinstance(status, ScanStatus):
        data = status.model_dump()
    else:
        data = dict(status)
    status_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return status_file


class ScanStatusDict(dict):
    """Dictionary supporting both item access (d['mode']) and attribute access (d.mode)."""

    def __getattr__(self, name: str) -> Any:
        try:
            return self[name]
        except KeyError:
            return None


def load_scan_status(tool_dir: pathlib.Path) -> ScanStatusDict | None:
    """Load status.json from the tool scan directory if it exists."""
    status_file = tool_dir / "status.json"
    if not status_file.exists() or not status_file.is_file():
        return None
    try:
        raw = json.loads(status_file.read_text(encoding="utf-8", errors="replace"))
        return ScanStatusDict(raw)
    except Exception:
        return None


def is_scan_trustworthy(tool_dir: pathlib.Path) -> bool:
    """Returns True if and only if status.json exists and confirms evidence_trustworthy is True."""
    status = load_scan_status(tool_dir)
    if not status:
        return False
    return bool(
        status.get("evidence_trustworthy") is True and status.get("mode") == "real"
    )
