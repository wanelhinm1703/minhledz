from __future__ import annotations

from pydantic import BaseModel, Field


class CVECandidate(BaseModel):
    cve_id: str
    description: str
    cvss_score: float | None = None
    cvss_severity: str | None = None
    cvss_v4_score: float | None = None
    cvss_v4_vector: str | None = None
    cvss_v4_severity: str | None = None
    is_cisa_kev: bool = False
    epss_score: float | None = None
    epss_percentile: float | None = None
    cwe_ids: list[str] = Field(default_factory=list)
    source_url: str
    source_name: str = "National Vulnerability Database (NVD)"
    confidence: float = Field(
        ..., description="Match confidence (0.95 exact, 0.85 range, 0.50 product)"
    )
    match_reason: str
    origin: str = "offline_kb"  # 'offline_kb', 'online_intel', 'dual'


class CorrelateResponse(BaseModel):
    query: dict
    count: int
    candidates: list[CVECandidate]
