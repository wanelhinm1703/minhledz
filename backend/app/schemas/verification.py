"""Schemas for Safe Read-Only Verification Plans and Execution Records."""

from __future__ import annotations

from pydantic import BaseModel, Field


class VerificationStep(BaseModel):
    step_number: int
    name: str
    description: str
    command: str
    is_safe_readonly: bool = True
    expected_evidence: str
    remediation_check: str | None = None


class VerificationPlan(BaseModel):
    finding_id: str
    target_id: str
    title: str
    cve_id: str | None = None
    affected_asset: str
    rationale: str
    safety_guarantee: str = "Strictly non-destructive, read-only passive probing."
    steps: list[VerificationStep] = Field(default_factory=list)
    created_at: str


class VerificationResult(BaseModel):
    finding_id: str
    step_number: int
    command: str
    output: str
    status: str  # "SUCCESS", "FAILED", "BLOCKED"
    is_vulnerable_indicated: bool
    timestamp: str


class ChainVerificationStep(BaseModel):
    step_number: int
    phase: str = Field(..., description="Reconnaissance | Initial Access | Exploitation | Impact Check | Lateral Movement")
    node_id: str
    node_label: str
    name: str
    description: str
    command: str
    is_safe_readonly: bool = True
    expected_evidence: str
    remediation_check: str | None = None
    break_point_candidate: bool = False  # Choke point to break the chain


class ChainVerificationPlan(BaseModel):
    chain_id: str
    target_id: str
    chain_title: str
    severity: str = "HIGH"
    attacker_goal: str = ""
    rationale: str
    safety_guarantee: str = "100% Read-Only, không gửi payload phá hoại, không gián đoạn dịch vụ."
    steps: list[ChainVerificationStep] = Field(default_factory=list)
    break_point_recommendation: str = ""
    recommended_mitigations: list[str] = Field(default_factory=list)
    created_at: str


class ChainExecutionResult(BaseModel):
    chain_id: str
    step_number: int
    command: str
    output: str
    status: str  # "SUCCESS", "FAILED", "BLOCKED"
    is_vulnerable_indicated: bool
    is_chain_broken: bool = False
    evidence_found: str = ""
    ai_assessment: str = ""
    ai_deduction: str = ""
    timestamp: str

