"""REST endpoints for Safe Verification Plans."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from backend.app.storage.findings_db import findings_db
from backend.app.services.verification_planner import verification_planner
from backend.app.schemas.verification import VerificationPlan, VerificationResult

router = APIRouter(prefix="/verification", tags=["verification"])


class ExecuteCheckRequest(BaseModel):
    command: str


@router.get("/plan/{finding_id}", response_model=VerificationPlan)
def get_verification_plan(finding_id: str):
    finding = findings_db.get_finding(finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail=f"Finding '{finding_id}' not found")
    return verification_planner.generate_plan(finding)


@router.post("/execute", response_model=VerificationResult)
def execute_verification_check(req: ExecuteCheckRequest):
    return verification_planner.execute_safe_check(req.command)
