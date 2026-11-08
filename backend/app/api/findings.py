"""REST API endpoints for Findings management, aggregation, and export."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, HTTPException, Query

from backend.app.schemas.finding import (
    Finding,
    FindingCreate,
    FindingsSummary,
    FindingUpdate,
)
from backend.app.services.findings_builder import findings_builder
from backend.app.storage.findings_db import findings_db

router = APIRouter(prefix="/findings", tags=["findings"])


@router.get("", response_model=list[Finding])
def list_findings(
    target_id: str | None = Query(None, description="Filter by target ID"),
    severity: str | None = Query(
        None, description="Filter by severity: CRITICAL, HIGH, MEDIUM, LOW, INFO"
    ),
    status: str | None = Query(
        None, description="Filter by status: CANDIDATE, UNVERIFIED, VERIFIED, etc."
    ),
):
    return findings_db.list_findings(
        target_id=target_id, severity=severity, status=status
    )


@router.get("/summary", response_model=FindingsSummary)
def get_findings_summary(
    target_id: str | None = Query(None, description="Filter by target ID"),
):
    return findings_db.get_summary(target_id=target_id)


@router.get("/{finding_id}", response_model=Finding)
def get_finding(finding_id: str):
    finding = findings_db.get_finding(finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail=f"Finding '{finding_id}' not found")
    return finding


@router.post("", response_model=Finding, status_code=201)
def create_manual_finding(item: FindingCreate):
    clean_target = item.target_id.replace(":", "-")
    fid = f"FIND-{clean_target}-{str(uuid.uuid4())[:8].upper()}"
    return findings_db.create_finding(fid, item)


@router.put("/{finding_id}", response_model=Finding)
def update_finding(finding_id: str, update: FindingUpdate):
    updated = findings_db.update_finding(finding_id, update)
    if not updated:
        raise HTTPException(status_code=404, detail=f"Finding '{finding_id}' not found")
    return updated


@router.delete("/{finding_id}")
def delete_finding(finding_id: str):
    success = findings_db.delete_finding(finding_id)
    if not success:
        raise HTTPException(status_code=404, detail=f"Finding '{finding_id}' not found")
    return {"status": "deleted", "id": finding_id}


@router.post("/generate/{target_id}")
def generate_findings_for_target(target_id: str):
    findings = findings_builder.generate_findings_for_target(target_id)
    return {
        "status": "success",
        "target_id": target_id,
        "count": len(findings),
        "findings": [f.model_dump() for f in findings],
    }


@router.post("/deduplicate")
def deduplicate_findings(
    target_id: str | None = Query(
        None, description="Target ID to deduplicate (optional)"
    ),
):
    stats = findings_db.deduplicate_all(target_id=target_id)
    if target_id:
        findings_builder._export_target_findings(target_id)
    return {
        "status": "success",
        "message": f"Deduplication completed: {stats['removed_duplicates']} duplicates merged across {stats['merged_groups']} groups.",
        "stats": stats,
    }
