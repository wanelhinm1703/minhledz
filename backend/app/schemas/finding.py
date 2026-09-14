"""Pydantic schemas for Findings, Evidence Chains, and Severity ratings."""

from __future__ import annotations

from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class FindingSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class FindingStatus(str, Enum):
    CANDIDATE = "CANDIDATE"
    UNVERIFIED = "UNVERIFIED"
    VERIFIED = "VERIFIED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    RESOLVED = "RESOLVED"


class EvidenceItem(BaseModel):
    tool: str = Field(..., description="Tool producing evidence: nmap, httpx, nuclei, manual")
    file_path: str = Field(..., description="Relative path to immutable raw evidence file")
    matched_text: str = Field(..., description="Excerpt or matched banner/vulnerability snippet")
    timestamp: Optional[str] = None


class FindingBase(BaseModel):
    target_id: str
    title: str
    cve_id: Optional[str] = None
    cwe_id: Optional[str] = None
    cvss_score: float = Field(default=0.0, ge=0.0, le=10.0)
    cvss_severity: FindingSeverity = FindingSeverity.INFO
    status: FindingStatus = FindingStatus.CANDIDATE
    affected_asset: str
    description: str
    remediation: Optional[str] = None
    evidence_chain: List[EvidenceItem] = Field(default_factory=list)


class FindingCreate(FindingBase):
    pass


class FindingUpdate(BaseModel):
    title: Optional[str] = None
    status: Optional[FindingStatus] = None
    cvss_score: Optional[float] = None
    cvss_severity: Optional[FindingSeverity] = None
    remediation: Optional[str] = None
    description: Optional[str] = None


class Finding(FindingBase):
    id: str
    created_at: str
    updated_at: str


class FindingsSummary(BaseModel):
    total: int
    by_severity: Dict[str, int]
    by_status: Dict[str, int]
