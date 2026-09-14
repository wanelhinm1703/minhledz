from __future__ import annotations

from typing import List, Optional
from pydantic import BaseModel, Field


class CVECandidate(BaseModel):
    cve_id: str
    description: str
    cvss_score: Optional[float] = None
    cvss_severity: Optional[str] = None
    cwe_ids: List[str] = Field(default_factory=list)
    source_url: str
    source_name: str = "National Vulnerability Database (NVD)"
    confidence: float = Field(..., description="Match confidence (0.95 exact, 0.85 range, 0.50 product)")
    match_reason: str


class CorrelateResponse(BaseModel):
    query: dict
    count: int
    candidates: List[CVECandidate]
