"""Pydantic schemas for Findings, Evidence Chains, and Severity ratings."""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class FindingSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class FindingStatus(str, Enum):
    CANDIDATE = "CANDIDATE"
    APPLICABLE = "APPLICABLE"
    VERIFIED = "VERIFIED"
    EXPLOITED = "EXPLOITED"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    UNVERIFIED = "UNVERIFIED"
    RESOLVED = "RESOLVED"


class EvidenceItem(BaseModel):
    tool: str = Field(
        ..., description="Tool producing evidence: nmap, httpx, nuclei, nikto, manual, verification_probe"
    )
    file_path: str = Field(
        default="", description="Relative path to immutable raw evidence file"
    )
    matched_text: str = Field(
        default="", description="Excerpt or matched banner/vulnerability snippet"
    )
    target: str | None = None
    command: str | None = None
    raw_result: str | None = None
    parsed_result: dict | None = None
    timestamp: str | None = None
    trustworthy: bool = Field(
        default=True, description="Whether this evidence is genuine and confirmed"
    )
    is_simulated: bool = Field(
        default=False,
        description="Whether this evidence was generated in simulation mode",
    )


class FindingBase(BaseModel):
    target_id: str
    title: str
    cve_id: str | None = None
    cwe_id: str | None = None
    cvss_score: float = Field(default=0.0, ge=0.0, le=10.0)
    cvss_severity: FindingSeverity = FindingSeverity.INFO
    cvss_v4_score: float | None = None
    cvss_v4_vector: str | None = None
    cvss_v4_severity: str | None = None
    is_cisa_kev: bool = False
    epss_score: float | None = None
    epss_percentile: float | None = None
    status: FindingStatus = FindingStatus.CANDIDATE
    affected_asset: str
    description: str
    remediation: str | None = None
    evidence_chain: list[EvidenceItem] = Field(default_factory=list)
    trustworthy: bool = Field(
        default=True,
        description="Whether all evidence in chain is genuine and confirmed",
    )
    is_simulated: bool = Field(
        default=False, description="Whether finding was derived from simulated scans"
    )


class FindingCreate(FindingBase):
    pass


class FindingUpdate(BaseModel):
    title: str | None = None
    cwe_id: str | None = None
    status: FindingStatus | None = None
    cvss_score: float | None = None
    cvss_severity: FindingSeverity | None = None
    remediation: str | None = None
    description: str | None = None
    trustworthy: bool | None = None
    is_simulated: bool | None = None


class Finding(FindingBase):
    id: str
    created_at: str
    updated_at: str


class FindingsSummary(BaseModel):
    total: int
    by_severity: dict[str, int]
    by_status: dict[str, int]
    trustworthy_count: int = 0
    simulated_count: int = 0
    has_insufficient_evidence: bool = False
