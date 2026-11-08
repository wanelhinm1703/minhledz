"""Pydantic schemas for Attack Surface Topology Graph (Knowledge Graph & Attack Path Visualizer)."""

from __future__ import annotations

from enum import Enum
from typing import Any
from pydantic import BaseModel, Field


class NodeType(str, Enum):
    TARGET = "target"
    PORT = "port"
    SERVICE = "service"
    TECHNOLOGY = "technology"
    VULNERABILITY = "vulnerability"
    FINDING = "finding"
    IMPACT = "impact"                           # Hậu quả khai thác / Lộ dữ liệu
    LATERAL_MOVEMENT = "lateral_movement"       # Nguy cơ leo thang / di chuyển nội bộ


class RelationType(str, Enum):
    EXPOSES = "EXPOSES"                        # Target -> Port
    RUNS_SERVICE = "RUNS_SERVICE"              # Port -> Service
    USES_TECH = "USES_TECH"                    # Service -> Technology
    VULNERABLE_TO = "VULNERABLE_TO"            # Service/Port -> Vulnerability (CVE)
    HAS_EVIDENCE = "HAS_EVIDENCE"              # Vulnerability -> Finding
    LEADS_TO = "LEADS_TO"                      # Vulnerability -> Impact
    ENABLES_PIVOT = "ENABLES_PIVOT"            # Impact -> Lateral Movement
    RESOLVES_TO = "RESOLVES_TO"                # Subdomain/Domain -> IP


class NodeRiskLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    SAFE = "SAFE"


class GraphNode(BaseModel):
    id: str = Field(..., description="Unique node identifier, e.g. 'port:target-1:tcp-80'")
    target_id: str = Field(..., description="Target identifier to which this node belongs")
    type: NodeType = Field(..., description="Classification of the entity node")
    label: str = Field(..., description="Display label for UI, e.g. '80/tcp (HTTP)'")
    risk_level: NodeRiskLevel = Field(default=NodeRiskLevel.INFO, description="Propagated risk level")
    properties: dict[str, Any] = Field(default_factory=dict, description="Metadata dictionary (e.g. port, protocol, cpe, cvss, cisa_kev, epss)")
    created_at: str
    updated_at: str


class GraphEdge(BaseModel):
    id: str = Field(..., description="Unique edge identifier, e.g. 'edge:target-1:p80'")
    target_id: str = Field(..., description="Target identifier")
    source: str = Field(..., description="Source node id")
    target: str = Field(..., description="Destination node id")
    relation: RelationType = Field(..., description="Relationship semantic type")
    label: str | None = Field(default=None, description="Optional textual relationship label")
    properties: dict[str, Any] = Field(default_factory=dict, description="Edge metadata")
    created_at: str


class AttackPathStep(BaseModel):
    step_number: int
    phase: str = Field(..., description="Reconnaissance | Exploitation | Impact & Exposure | Lateral Movement")
    node_id: str
    title: str
    description: str
    technical_detail: str | None = None
    node_label: str | None = None
    node_type: str | None = None
    mitre_tactic: str | None = None
    mitre_technique: str | None = None
    annotation: str | None = Field(default=None, description="Chú thích nguồn gốc hoặc gộp các bước tương đồng")
    related_cves: list[str] = Field(default_factory=list, description="Danh sách CVE liên đới trong bước này")


class AttackPath(BaseModel):
    id: str
    title: str
    severity: NodeRiskLevel
    attacker_goal: str = ""
    remediation_summary: str = ""
    node_ids: list[str] = Field(default_factory=list)
    edge_ids: list[str] = Field(default_factory=list)
    steps: list[AttackPathStep] = Field(default_factory=list)
    cvss_score: float = 0.0
    cve_id: str | None = None
    is_cisa_kev: bool = False
    epss_score: float | None = None
    mitigation_steps: list[str] = Field(default_factory=list)
    verification_plan_id: str | None = None
    is_severed: bool = False
    severed_by_node: str | None = None
    verification_status: str = "PENDING"
    explainability: dict[str, Any] | None = None
    related_cves: list[str] = Field(default_factory=list, description="Danh sách các CVE/Finding thuộc đường dẫn này")
    findings_count: int = Field(default=1, description="Số lượng Findings được gộp trong đường dẫn")
    annotation: str = Field(default="", description="Chú thích nguồn gốc và lý do gộp các bước tương đồng")
    service_name: str | None = Field(default=None, description="Tên dịch vụ đích của đường dẫn")
    port_name: str | None = Field(default=None, description="Cổng dịch vụ đích của đường dẫn")


class GraphStats(BaseModel):
    total_nodes: int = 0
    total_edges: int = 0
    by_type: dict[str, int] = Field(default_factory=dict)
    by_risk: dict[str, int] = Field(default_factory=dict)
    critical_path_count: int = 0


class GraphDataResponse(BaseModel):
    target_id: str
    nodes: list[GraphNode] = Field(default_factory=list)
    edges: list[GraphEdge] = Field(default_factory=list)
    stats: GraphStats = Field(default_factory=GraphStats)
    attack_paths: list[AttackPath] = Field(default_factory=list)
