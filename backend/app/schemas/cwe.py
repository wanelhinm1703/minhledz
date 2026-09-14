from __future__ import annotations

from typing import Optional
from pydantic import BaseModel


class CWEDetail(BaseModel):
    cwe_id: str
    name: str
    description: str
    extended_description: Optional[str] = None
    likelihood: Optional[str] = None
    mitigations: Optional[str] = None
    parent_cwe: Optional[str] = None
    source_url: str
    source_name: str = "MITRE CWE"
