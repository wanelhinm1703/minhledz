"""Schemas for Safe Read-Only Verification Plans and Execution Records."""

from __future__ import annotations

from typing import List, Optional
from pydantic import BaseModel, Field


class VerificationStep(BaseModel):
    step_number: int
    name: str
    description: str
    command: str
    is_safe_readonly: bool = True
    expected_evidence: str
    remediation_check: Optional[str] = None


class VerificationPlan(BaseModel):
    finding_id: str
    target_id: str
    title: str
    cve_id: Optional[str] = None
    affected_asset: str
    rationale: str
    safety_guarantee: str = "Strictly non-destructive, read-only passive probing."
    steps: List[VerificationStep] = Field(default_factory=list)
    created_at: str


class VerificationResult(BaseModel):
    finding_id: str
    step_number: int
    command: str
    output: str
    status: str  # "SUCCESS", "FAILED", "BLOCKED"
    is_vulnerable_indicated: bool
    timestamp: str
