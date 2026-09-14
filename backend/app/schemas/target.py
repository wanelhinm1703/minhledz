from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class TargetType(str, Enum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    CIDR = "cidr"
    DOMAIN = "domain"
    HOSTNAME = "hostname"
    URL = "url"
    HOST_PORT = "host_port"
    CUSTOM = "custom"


class TargetStatus(str, Enum):
    ACTIVE = "active"
    ARCHIVED = "archived"
    BLOCKED = "blocked"


class TargetScope(BaseModel):
    allowed_ports: List[int] = Field(default_factory=list, description="Explicitly allowed ports")
    forbidden_ports: List[int] = Field(default_factory=list, description="Explicitly forbidden ports")
    allowed_attacks: List[str] = Field(default_factory=lambda: ["recon", "web", "network"], description="Allowed attack modes")
    forbidden_attacks: List[str] = Field(default_factory=lambda: ["dos", "brute-force", "exploit"], description="Strictly forbidden attacks")
    is_in_scope: bool = Field(default=True, description="Whether target is authorized by scope rules")
    scope_rule: Optional[str] = Field(default=None, description="Matched authorization rule or violation reason")


class TargetMetadata(BaseModel):
    os: Optional[str] = None
    technologies: List[str] = Field(default_factory=list)
    notes: Optional[str] = None
    extra: Dict[str, Any] = Field(default_factory=dict)


class Target(BaseModel):
    target_id: str = Field(..., description="Unique identifier for target")
    campaign_id: str = Field(default="lab-local", description="Associated campaign ID")
    name: str = Field(..., description="Human-readable target name")
    type: TargetType = Field(..., description="Detected target type")
    raw_input: str = Field(..., description="Exact raw input string provided by user")
    normalized_value: str = Field(..., description="Normalized target representation")
    host: str = Field(..., description="Host IP, domain, or hostname")
    port: Optional[int] = Field(default=None, description="Port number if specified or applicable")
    scheme: Optional[str] = Field(default=None, description="Protocol scheme (http, https, etc.)")
    path: Optional[str] = Field(default=None, description="URL path if applicable")
    environment: str = Field(default="lab", description="Target environment: lab, staging, prod")
    scope: TargetScope = Field(default_factory=TargetScope, description="Scope definition")
    tags: List[str] = Field(default_factory=list, description="Tags for categorization")
    metadata: TargetMetadata = Field(default_factory=TargetMetadata, description="Extensible metadata")
    status: TargetStatus = Field(default=TargetStatus.ACTIVE, description="Current lifecycle status")
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class ValidationResult(BaseModel):
    is_valid: bool
    target_type: Optional[TargetType] = None
    errors: List[str] = Field(default_factory=list)
    details: Dict[str, Any] = Field(default_factory=dict)


class ScopeDecision(BaseModel):
    allowed: bool
    reason: str
    matched_rule: Optional[str] = None
    target_host: str
    target_port: Optional[int] = None
