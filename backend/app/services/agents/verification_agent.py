"""AI-Pentest Copilot - Safe Verification Planner Sub-Agent.
Specializes in generating non-destructive validation plans, benign probe commands,
and remediation guidance while strictly enforcing anti-exploitation guardrails.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from backend.app.schemas.finding import Finding
from backend.app.services.agents.threat_intel_agent import VulnerabilityMatch
from backend.app.services.verification_planner import VerificationPlanner, VerificationPlan


class VerificationStepItem(BaseModel):
    step_number: int
    name: str
    command: str
    description: str
    is_safe_readonly: bool = True
    expected_evidence: str = ""


class SafePlanResult(BaseModel):
    target_id: str
    cve_id: str
    steps: list[VerificationStepItem] = Field(default_factory=list)
    remediation_roadmap: list[str] = Field(default_factory=list)
    safety_summary: str = "Tất cả các bước kiểm chứng đều chỉ đọc (Read-only), an toàn tuyệt đối và không phá hủy."
    guardrails_enforced: bool = True


class SafeVerificationPlannerAgent:
    """Specialist sub-agent dedicated to designing safe, non-destructive verification plans."""

    def __init__(self):
        self._planner = VerificationPlanner()

    def generate_plan_for_match(
        self,
        target_id: str,
        match: VulnerabilityMatch,
        target_host: str = "127.0.0.1",
        port: int = 80,
    ) -> SafePlanResult:
        """Generate a safe verification plan for a specific threat intelligence match."""
        from datetime import datetime, timezone

        now_str = datetime.now(timezone.utc).isoformat()
        finding_mock = Finding(
            id=f"plan-{match.cve_id}",
            target_id=target_id,
            affected_asset=f"{target_host}:{port}",
            cve_id=match.cve_id,
            cwe_id=match.cwe_ids[0] if match.cwe_ids else "CWE-200",
            title=f"{match.product} {match.version} — {match.cve_id}",
            description=match.description,
            cvss_score=match.cvss_score,
            remediation=match.remediation,
            created_at=now_str,
            updated_at=now_str,
        )

        plan = self._planner.generate_plan(finding_mock)

        steps: list[VerificationStepItem] = []
        for s in plan.steps:
            steps.append(
                VerificationStepItem(
                    step_number=s.step_number,
                    name=s.name,
                    command=s.command,
                    description=s.description,
                    is_safe_readonly=s.is_safe_readonly,
                    expected_evidence=s.expected_evidence,
                )
            )

        roadmap = [
            f"1. Xác nhận phiên bản dịch vụ thực tế qua lệnh probe an toàn: '{steps[0].command if steps else 'curl -I'}'",
            f"2. Đánh giá phạm vi ảnh hưởng của {match.cve_id} đối với tài sản {target_id}.",
            f"3. Áp dụng bản vá bảo mật chính thức hoặc nâng cấp {match.product} lên phiên bản mới nhất.",
            f"4. Cấu hình hạn chế truy cập cổng dịch vụ đối với các dải mạng không tin cậy.",
        ]

        return SafePlanResult(
            target_id=target_id,
            cve_id=match.cve_id,
            steps=steps,
            remediation_roadmap=roadmap,
            safety_summary="Kế hoạch kiểm chứng an toàn không phá hủy, được thực thi nghiêm ngặt bởi Hàng rào Bảo vệ (Security Guardrails).",
            guardrails_enforced=True,
        )

    def generate_chain_plan(self, attack_path: Any, target_id: str = "") -> Any:
        """Generate a chain-level safe verification plan from an attack path."""
        return self._planner.generate_chain_plan(attack_path, target_id=target_id)


safe_verification_agent = SafeVerificationPlannerAgent()

