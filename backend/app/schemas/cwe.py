from __future__ import annotations

from pydantic import BaseModel


class CWEDetail(BaseModel):
    cwe_id: str
    name: str
    description: str
    extended_description: str | None = None
    likelihood: str | None = None
    mitigations: str | None = None
    parent_cwe: str | None = None
    source_url: str
    source_name: str = "MITRE CWE"
