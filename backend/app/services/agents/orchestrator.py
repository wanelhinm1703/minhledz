"""AI-Pentest Copilot - Specialist Agent Orchestrator & Natural Language Command Translator.
Coordinates Recon Analyst, Threat Intel, and Safe Verification Planner agents.
Translates natural language operator requests into safe, verified CLI commands with preview.
"""

from __future__ import annotations

import re
from typing import Any

from pydantic import BaseModel, Field

from backend.app.core.guardrails import check_exploit_intent, format_guardrail_refusal
from backend.app.core.observability import observability
from backend.app.services.agents.compliance_agent import (
    ComplianceReporterAgent,
    ComplianceReportResult,
    compliance_reporter_agent,
)
from backend.app.services.agents.recon_analyst_agent import (
    ReconAnalystAgent,
    ReconAnalystResult,
    recon_analyst_agent,
)
from backend.app.services.agents.threat_intel_agent import (
    ThreatIntelAgent,
    ThreatIntelResult,
    threat_intel_agent,
)
from backend.app.services.agents.verification_agent import (
    SafePlanResult,
    SafeVerificationPlannerAgent,
    safe_verification_agent,
)
from backend.app.services.scope_validator import ScopeValidator
from backend.app.services.target_parser import TargetParser
from backend.app.services.tool_registry import tool_registry


class CommandPreview(BaseModel):
    raw_prompt: str
    target: str = ""
    tool: str = ""
    proposed_command: str = ""
    safe_flags_applied: list[str] = Field(default_factory=list)
    risk_level: str = "safe"  # safe, controlled, refused
    is_safe: bool = True
    requires_approval: bool = True
    scope_allowed: bool = True
    explanation: str = ""
    error: str | None = None


class CollaborativeAssessmentResult(BaseModel):
    target_id: str
    recon_analysis: ReconAnalystResult
    threat_intel: ThreatIntelResult
    verification_plans: list[SafePlanResult] = Field(default_factory=list)
    compliance_report: ComplianceReportResult | None = None
    executive_summary: str = ""


class SpecialistAgentOrchestrator:
    """Orchestrates specialized sub-agents and provides natural language command translation."""

    def __init__(
        self,
        recon_agent: ReconAnalystAgent | None = None,
        intel_agent: ThreatIntelAgent | None = None,
        verify_agent: SafeVerificationPlannerAgent | None = None,
        compliance_agent: ComplianceReporterAgent | None = None,
    ):
        self.recon_agent = recon_agent or recon_analyst_agent
        self.intel_agent = intel_agent or threat_intel_agent
        self.verify_agent = verify_agent or safe_verification_agent
        self.compliance_agent = compliance_agent or compliance_reporter_agent

    def run_collaborative_assessment(
        self,
        target_id: str,
        target_host: str = "127.0.0.1",
        port: int = 80,
    ) -> CollaborativeAssessmentResult:
        """Run a full multi-agent collaborative cycle for a target."""
        span = observability.start_span(
            "collaborative_assessment",
            metadata={"target_id": target_id, "target_host": target_host},
        )

        # 1. Recon Analyst Sub-Agent
        recon_res = self.recon_agent.analyze(target_id)

        # 2. Threat Intel Sub-Agent
        intel_res = self.intel_agent.correlate_services(
            target_id, recon_res.discovered_services
        )

        # 3. Safe Verification Planner Sub-Agent
        plans: list[SafePlanResult] = []
        for match in intel_res.matches[:3]:  # Top 3 most critical matches
            plan = self.verify_agent.generate_plan_for_match(
                target_id=target_id,
                match=match,
                target_host=target_host,
                port=port,
            )
            plans.append(plan)

        # 4. Compliance & Reporting Sub-Agent
        findings_payload = [
            {
                "title": f"Vulnerability {m.cve_id} on {m.product}",
                "cve_id": m.cve_id,
                "cwe_id": m.cwe_ids[0] if m.cwe_ids else "CWE-20",
                "cvss_score": m.cvss_score,
                "cvss_severity": "CRITICAL" if m.cvss_score >= 9.0 else "HIGH" if m.cvss_score >= 7.0 else "MEDIUM",
                "remediation": m.remediation,
            }
            for m in intel_res.matches
        ]
        comp_res = self.compliance_agent.evaluate_compliance(target_id, findings_payload)

        observability.end_span(span.span_id, status="SUCCESS")

        exec_summary = (
            f"Báo cáo Đa Tác tử (Multi-Agent Assessment) cho mục tiêu {target_id}:\n"
            f"- Recon Analyst: {recon_res.summary}\n"
            f"- Threat Intel: {intel_res.summary}\n"
            f"- Verification Planner: Đã lập {len(plans)} kịch bản xác thực an toàn (chỉ đọc).\n"
            f"- Compliance & Reporting: Điểm tuân thủ chung {comp_res.overall_compliance_score}% "
            f"({comp_res.overall_status}) với {len(comp_res.violations)} điểm vi phạm kiểm soát an ninh."
        )

        return CollaborativeAssessmentResult(
            target_id=target_id,
            recon_analysis=recon_res,
            threat_intel=intel_res,
            verification_plans=plans,
            compliance_report=comp_res,
            executive_summary=exec_summary,
        )

    def extract_target_from_prompt(self, text: str) -> str | None:
        """Extract IP, CIDR, or URL from natural language text."""
        # 1. URL pattern
        url_match = re.search(r"https?://[^\s,]+", text, re.IGNORECASE)
        if url_match:
            return url_match.group(0).rstrip(".,;")

        # 2. IP:Port or IP pattern
        ip_match = re.search(
            r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?::[0-9]{1,5})?\b", text
        )
        if ip_match:
            return ip_match.group(0)

        # 3. Domain pattern (e.g. target.local, test.corp)
        domain_match = re.search(r"\b(?:[a-zA-Z0-9-]+\.)+(?:local|internal|corp|lan|test)\b", text)
        if domain_match:
            return domain_match.group(0)

        return None

    def translate_natural_language_command(
        self,
        prompt: str,
        target_override: str | None = None,
    ) -> CommandPreview:
        """
        Translates natural language operator requests into safe, verified CLI commands.
        Enforces RFC 1918 scope validation and anti-exploitation guardrails.
        """
        trimmed = prompt.strip()
        if trimmed.startswith("@copilot"):
            trimmed = trimmed[8:].strip()

        # Step 1: Guardrail check on prompt
        is_exploit, refusal_reason = check_exploit_intent(trimmed)
        if is_exploit:
            refusal_text = format_guardrail_refusal(refusal_reason)
            return CommandPreview(
                raw_prompt=prompt,
                target="",
                tool="guardrail",
                proposed_command="",
                risk_level="refused",
                is_safe=False,
                requires_approval=True,
                scope_allowed=False,
                explanation=refusal_text,
                error=f"GUARDRAIL REFUSAL: {refusal_reason}",
            )

        # Step 2: Target extraction & Scope Validation
        found_target = target_override or self.extract_target_from_prompt(trimmed) or "127.0.0.1"
        from backend.app.services.target_registry import TargetRegistry
        from backend.app.schemas.target import Target, TargetType, TargetScope

        t_reg = TargetRegistry()
        try:
            target_obj = t_reg.create_from_input(found_target)
        except Exception:
            host_part = found_target.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]
            target_obj = Target(
                target_id="temp-target",
                name="temp-target",
                type=TargetType.IPV4,
                raw_input=found_target,
                normalized_value=found_target if found_target.startswith("http") else f"http://{found_target}",
                host=host_part,
                scope=TargetScope(allowed=True),
            )

        scope_res = ScopeValidator().validate(target_obj)

        if not scope_res.allowed:
            return CommandPreview(
                raw_prompt=prompt,
                target=found_target,
                tool="scope_validator",
                proposed_command="",
                risk_level="refused",
                is_safe=False,
                requires_approval=True,
                scope_allowed=False,
                explanation=f"SCOPE BLOCKED: Mục tiêu '{found_target}' nằm ngoài phạm vi được phép ({scope_res.reason}).",
                error=f"ScopeViolation: {scope_res.reason}",
            )

        target_host = target_obj.host
        target_port = target_obj.port or 80
        norm_url = target_obj.normalized_value

        # Step 3: Intent Classification & Tool Mapping
        p_lower = trimmed.lower()

        # Web Endpoints / Crawling / API discovery
        if any(w in p_lower for w in ["endpoint", "api", "crawl", "đường dẫn", "route", "ẩn", "kiterunner", "katana"]):
            tool_id = "katana"
            safe_flags = ["-depth", "2", "-rate-limit", "20", "-silent"]
            cmd = f"katana -u {norm_url} -depth 2 -rate-limit 20 -silent"
            explanation = (
                f"Sử dụng công cụ Katana để thu thập đường dẫn và endpoint API an toàn trên '{norm_url}', "
                f"giới hạn độ sâu 2 và tốc độ 20 req/s để tránh gây tải cho dịch vụ."
            )

        # SSL / TLS inspection
        elif any(w in p_lower for w in ["ssl", "tls", "chứng chỉ", "certificate", "cipher", "testssl"]):
            tool_id = "testssl"
            safe_flags = ["--quiet", "--fast"]
            cmd = f"testssl.sh --quiet --fast {target_host}:{target_port}"
            explanation = (
                f"Sử dụng TestSSL.sh để kiểm tra cấu hình TLS/ciphersuites trên cổng {target_port} của '{target_host}' "
                f"ở chế độ chỉ-đọc (read-only audit)."
            )

        # Subdomain / OSINT
        elif any(w in p_lower for w in ["subdomain", "osint", "tên miền phụ", "theharvester"]):
            tool_id = "theharvester"
            safe_flags = ["-l", "100", "-b", "duckduckgo"]
            cmd = f"theHarvester -d {target_host} -l 100 -b duckduckgo"
            explanation = (
                f"Sử dụng theHarvester để trinh sát tên miền phụ và siêu dữ liệu công khai của '{target_host}' "
                f"qua nguồn tìm kiếm DuckDuckGo hoàn toàn hợp pháp."
            )

        # Web Vulnerability Scan (Nuclei)
        elif any(w in p_lower for w in ["nuclei", "lỗ hổng web", "cve web", "template"]):
            tool_id = "nuclei"
            safe_flags = ["-tags", "cve", "-severity", "low,medium,high,critical", "-rate-limit", "50"]
            cmd = f"nuclei -u {norm_url} -tags cve -severity low,medium,high,critical -rate-limit 50"
            explanation = (
                f"Sử dụng Nuclei chạy các template kiểm tra CVE an toàn trên '{norm_url}', "
                f"giới hạn tốc độ 50 req/s."
            )

        # Web Fingerprinting (WhatWeb / HTTPx)
        elif any(w in p_lower for w in ["whatweb", "công nghệ", "tech", "cms", "fingerprint"]):
            tool_id = "whatweb"
            safe_flags = ["-a", "1"]
            cmd = f"whatweb -a 1 {norm_url}"
            explanation = (
                f"Sử dụng WhatWeb để nhận diện công nghệ web và CMS máy chủ '{norm_url}' qua request GET thụ động."
            )

        # Default / Network Port Scanning (Nmap)
        else:
            tool_id = "nmap"
            safe_flags = ["-sV", "-Pn", "-T4", "-F", "--script=safe"]
            cmd = f"nmap -sV -Pn -T4 -F --script=safe {target_host}"
            explanation = (
                f"Sử dụng Nmap quét nhanh các cổng phổ biến (-F), nhận diện phiên bản (-sV) "
                f"kèm script NSE an toàn (--script=safe) đối với mục tiêu '{target_host}'."
            )

        # Look up tool in YAML catalog to ensure consistency
        tool_def = tool_registry.get_tool(tool_id)
        risk = tool_def.risk_level if tool_def else "safe"

        return CommandPreview(
            raw_prompt=prompt,
            target=found_target,
            tool=tool_id,
            proposed_command=cmd,
            safe_flags_applied=safe_flags,
            risk_level=risk,
            is_safe=True,
            requires_approval=True,
            scope_allowed=True,
            explanation=explanation,
        )

    def translate_intent(
        self,
        prompt: str,
        target: str | None = None,
        target_override: str | None = None,
    ) -> CommandPreview:
        """Alias for translate_natural_language_command."""
        return self.translate_natural_language_command(
            prompt=prompt,
            target_override=target or target_override,
        )


orchestrator = SpecialistAgentOrchestrator()
agent_orchestrator = orchestrator
