"""REST endpoints for Generating and Viewing Pentest Reports."""

from __future__ import annotations

from typing import Optional, List
from fastapi import APIRouter, HTTPException, Query
from backend.app.services.report_generator import report_generator

router = APIRouter(prefix="/reports", tags=["reports"])


@router.post("/generate/{target_id}")
def generate_report(
    target_id: str,
    campaign_name: Optional[str] = Query("Automated Lab Assessment"),
):
    result = report_generator.generate_report(target_id=target_id, campaign_name=campaign_name)
    return result


@router.get("")
def list_reports():
    return {"reports": report_generator.list_reports()}


@router.get("/{target_id}")
def get_report(target_id: str):
    report = report_generator.get_report(target_id)
    if not report:
        raise HTTPException(status_code=404, detail=f"No report found for target '{target_id}'")
    return report
