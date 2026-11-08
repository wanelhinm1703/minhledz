"""Pydantic schemas for Evidence-Driven Attack Plan, Decision Points, Choke Points, and Verification."""

from __future__ import annotations

from enum import Enum
from typing import Any
from pydantic import BaseModel, Field

from backend.app.schemas.finding import EvidenceItem, Finding, FindingStatus
from backend.app.schemas.graph import AttackPath, AttackPathStep, NodeRiskLevel


class DecisionResult(str, Enum):
    PASSED = "PASSED"
    FAILED = "FAILED"
    NEEDS_EVIDENCE = "NEEDS_EVIDENCE"
    BLOCKED = "BLOCKED"


class DecisionPoint(BaseModel):
    id: str = Field(..., description="Unique decision point identifier, e.g. 'dp-port-80'")
    step_name: str = Field(..., description="Tên bước kiểm thử logic")
    condition: str = Field(..., description="Biểu thức / Điều kiện đánh giá (VD: Version == 2.4.49)")
    evaluation: str = Field(..., description="Kết quả đánh giá điều kiện")
    result: DecisionResult = Field(default=DecisionResult.NEEDS_EVIDENCE, description="Trạng thái quyết định")
    branch_action: str = Field(..., description="Hành vi rẽ nhánh (VD: Mark APPLICABLE -> Tiếp tục chuỗi)")
    rationale: str = Field(..., description="Lý do khoa học / bằng chứng biện giải")


class ChokePoint(BaseModel):
    node_id: str = Field(..., description="ID của nút đồ thị, e.g. 'port:192.168.100.153:tcp-80'")
    node_label: str = Field(..., description="Nhãn hiển thị của nút")
    node_type: str = Field(..., description="Loại nút (port, service, vulnerability)")
    affected_paths_count: int = Field(default=0, description="Số lượng Attack Paths đi qua nút này")
    affected_path_ids: list[str] = Field(default_factory=list, description="Danh sách ID các Attack Path bị ảnh hưởng")
    dependent_findings: list[str] = Field(default_factory=list, description="Các finding / lỗ hổng phụ thuộc vào nút này")
    recommended_remediation: str = Field(..., description="Biện pháp khắc phục tối ưu")
    reason: str = Field(..., description="Lý giải định lượng vì sao đây là điểm chốt chặn (Choke Point)")
    is_severed: bool = Field(default=False, description="Trạng thái đã bị cắt đứt/khắc phục hay chưa")


class VerificationConfidence(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNVERIFIED = "UNVERIFIED"


class NextDecision(str, Enum):
    CONTINUE_PATH = "CONTINUE_PATH"
    BLOCK_PATH = "BLOCK_PATH"
    NEEDS_EVIDENCE = "NEEDS_EVIDENCE"


class VerificationProbe(BaseModel):
    step_number: int
    phase: str = Field(..., description="Reconnaissance | Service Enum | Vulnerability Verification | Impact Check")
    node_id: str
    node_label: str = ""
    purpose: str = Field(..., description="Mục đích kiểm chứng an toàn")
    expected_result: str = Field(..., description="Kết quả kỳ vọng nếu dính lỗ hổng hoặc nếu đã được phòng vệ")
    actual_result: str = Field(default="", description="Kết quả thực tế từ lệnh probe")
    command: str = Field(..., description="Lệnh thực thi kiểm chứng (100% read-only)")
    evidence_found: str = Field(default="", description="Bằng chứng cụ thể trích xuất được")
    confidence: VerificationConfidence = VerificationConfidence.UNVERIFIED
    next_decision: NextDecision = NextDecision.NEEDS_EVIDENCE
    status: str = Field(default="PENDING", description="PENDING | SUCCESS | FAILED | BLOCKED")
    is_safe_readonly: bool = True
    can_execute: bool = True
    ai_assessment: str = Field(default="", description="Đánh giá kỹ thuật của AI dựa trên đầu ra thực tế")
    ai_deduction: str = Field(default="", description="Suy diễn AI về khả năng tiếp diễn và mắt xích tiếp theo của chuỗi tấn công")
    timestamp: str | None = None


class ExplainabilityReport(BaseModel):
    target_reachable: bool = True
    target_evidence: str = ""
    port_discovered: str = ""
    service_identified: str = ""
    version_confirmed: str = ""
    vuln_correlation: str = ""
    evidence_available: list[str] = Field(default_factory=list)
    verification_status: str = "Chưa kiểm chứng"
    missing_evidence: list[str] = Field(default_factory=list)
    next_step_rationale: str = ""


class AttackPlanState(str, Enum):
    PLANNED = "PLANNED"
    IN_PROGRESS = "IN_PROGRESS"
    VERIFIED = "VERIFIED"
    SEVERED = "SEVERED"
    BLOCKED = "BLOCKED"


class PreconditionItem(BaseModel):
    id: str
    description: str
    is_met: bool = True
    evidence_ref: str = ""


class AttackPlan(BaseModel):
    id: str = Field(..., description="plan:<target_id>")
    target_id: str
    target_name: str
    objective: str = Field(..., description="Mục tiêu tổng thể của kế hoạch kiểm thử")
    preconditions: list[PreconditionItem] = Field(default_factory=list)
    recon_evidence: list[EvidenceItem] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    verification_steps: list[VerificationProbe] = Field(default_factory=list)
    attack_paths: list[AttackPath] = Field(default_factory=list)
    decision_points: list[DecisionPoint] = Field(default_factory=list)
    choke_points: list[ChokePoint] = Field(default_factory=list)
    remediation_summary: str = ""
    state: AttackPlanState = AttackPlanState.PLANNED
    severed_paths_count: int = 0
    active_paths_count: int = 0
    created_at: str
    updated_at: str


class RemediationImpact(BaseModel):
    target_id: str
    remediated_node_id: str
    severed_path_ids: list[str] = Field(default_factory=list)
    remaining_path_ids: list[str] = Field(default_factory=list)
    risk_reduction_percent: float = 0.0
    updated_plan: AttackPlan | None = None
