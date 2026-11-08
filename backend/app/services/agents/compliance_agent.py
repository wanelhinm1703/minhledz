"""
AI-Pentest Copilot - Compliance & Reporting Specialist Sub-Agent.
Specializes in evaluating assessment findings against international cybersecurity standards:
- OWASP Top 10 (2021)
- PCI-DSS v4.0 (Requirements 6.4 & 11.3)
- ISO/IEC 27001:2022 (Control A.8.8 Management of technical vulnerabilities)
- NIST CSF v2.0 (Identify, Protect, Detect)
Generates audit-ready compliance scorecards and executive risk summaries.
"""

from __future__ import annotations

import logging
from typing import Any

from pydantic import BaseModel, Field

from backend.app.services.compliance_engine import ComplianceEngine, OWASP_2021_MAPPING

logger = logging.getLogger("ai_pentest.compliance_agent")


class StandardViolation(BaseModel):
    standard: str
    control_id: str
    control_name: str
    finding_title: str
    severity: str
    remediation_recommendation: str


class ComplianceScorecard(BaseModel):
    standard_name: str
    compliance_score: float = 100.0  # Percentage 0.0 - 100.0
    status: str = "COMPLIANT"  # COMPLIANT, PARTIALLY_COMPLIANT, NON_COMPLIANT
    violations_count: int = 0
    passed_controls: int = 0
    total_evaluated_controls: int = 0


class ComplianceReportResult(BaseModel):
    target_id: str
    overall_compliance_score: float = 100.0
    overall_status: str = "COMPLIANT"
    scorecards: dict[str, ComplianceScorecard] = Field(default_factory=dict)
    violations: list[StandardViolation] = Field(default_factory=list)
    executive_summary: str = ""
    remediation_roadmap: list[str] = Field(default_factory=list)


class ComplianceReporterAgent:
    """Specialist sub-agent dedicated to regulatory compliance mapping and audit reporting."""

    PCI_DSS_MAPPING = {
        "CWE-89": {"control": "Req 6.4.1", "name": "Protection Against SQL Injection"},
        "CWE-79": {"control": "Req 6.4.2", "name": "Protection Against Cross-Site Scripting (XSS)"},
        "CWE-22": {"control": "Req 6.4.3", "name": "Protection Against Path Traversal & Unauthorized Access"},
        "CWE-287": {"control": "Req 8.2", "name": "Multi-Factor Authentication & Access Control"},
        "CWE-319": {"control": "Req 4.2", "name": "Strong Cryptography in Transmission"},
    }

    ISO_27001_MAPPING = {
        "A01": {"control": "A.8.8", "name": "Management of technical vulnerabilities"},
        "A02": {"control": "A.8.24", "name": "Use of cryptography"},
        "A03": {"control": "A.8.28", "name": "Secure coding principles"},
        "A05": {"control": "A.8.9", "name": "Configuration management"},
        "A07": {"control": "A.5.15", "name": "Access control policy"},
    }

    def evaluate_compliance(
        self,
        target_id: str,
        findings: list[dict[str, Any]],
    ) -> ComplianceReportResult:
        """
        Evaluates a list of findings against OWASP, PCI-DSS, and ISO 27001.
        Computes weighted scorecards and actionable remediation steps.
        """
        violations: list[StandardViolation] = []
        owasp_violations = 0
        pci_violations = 0
        iso_violations = 0

        remediation_items: set[str] = set()

        for f in findings:
            cwe_id = (f.get("cwe_id") or "").upper()
            title = f.get("title", "Security Weakness")
            severity = (f.get("cvss_severity") or f.get("severity") or "MEDIUM").upper()
            remediation = f.get("remediation") or "Apply vendor security patch immediately."

            # 1. Evaluate OWASP Top 10
            owasp_info = OWASP_2021_MAPPING.get(cwe_id)
            if owasp_info:
                owasp_violations += 1
                violations.append(
                    StandardViolation(
                        standard="OWASP Top 10 (2021)",
                        control_id=owasp_info["id"],
                        control_name=owasp_info["name"],
                        finding_title=title,
                        severity=severity,
                        remediation_recommendation=remediation,
                    )
                )
                remediation_items.add(f"[{owasp_info['id']}]: {remediation}")

            # 2. Evaluate PCI-DSS
            if cwe_id in self.PCI_DSS_MAPPING:
                pci_violations += 1
                pci_rule = self.PCI_DSS_MAPPING[cwe_id]
                violations.append(
                    StandardViolation(
                        standard="PCI-DSS v4.0",
                        control_id=pci_rule["control"],
                        control_name=pci_rule["name"],
                        finding_title=title,
                        severity=severity,
                        remediation_recommendation=remediation,
                    )
                )
                remediation_items.add(f"[PCI-DSS {pci_rule['control']}]: Validate input and enforce strict access boundaries.")

            # 3. Evaluate ISO 27001
            if owasp_info:
                owasp_prefix = owasp_info["id"][:3]
                if owasp_prefix in self.ISO_27001_MAPPING:
                    iso_violations += 1
                    iso_rule = self.ISO_27001_MAPPING[owasp_prefix]
                    violations.append(
                        StandardViolation(
                            standard="ISO/IEC 27001:2022",
                            control_id=iso_rule["control"],
                            control_name=iso_rule["name"],
                            finding_title=title,
                            severity=severity,
                            remediation_recommendation=remediation,
                        )
                    )

        # Compute Scorecards
        def calc_score(viol_count: int, base_controls: int = 10) -> tuple[float, str]:
            penalty = min(100.0, viol_count * 20.0)
            score = max(0.0, 100.0 - penalty)
            if score >= 90.0:
                status = "COMPLIANT"
            elif score >= 60.0:
                status = "PARTIALLY_COMPLIANT"
            else:
                status = "NON_COMPLIANT"
            return round(score, 1), status

        owasp_score, owasp_status = calc_score(owasp_violations, 10)
        pci_score, pci_status = calc_score(pci_violations, 6)
        iso_score, iso_status = calc_score(iso_violations, 8)

        overall_score = round((owasp_score * 0.4 + pci_score * 0.3 + iso_score * 0.3), 1)
        if overall_score >= 85.0:
            overall_status = "COMPLIANT"
        elif overall_score >= 55.0:
            overall_status = "PARTIALLY_COMPLIANT"
        else:
            overall_status = "NON_COMPLIANT"

        scorecards = {
            "OWASP_Top_10": ComplianceScorecard(
                standard_name="OWASP Top 10 (2021)",
                compliance_score=owasp_score,
                status=owasp_status,
                violations_count=owasp_violations,
                passed_controls=max(0, 10 - owasp_violations),
                total_evaluated_controls=10,
            ),
            "PCI_DSS": ComplianceScorecard(
                standard_name="PCI-DSS v4.0",
                compliance_score=pci_score,
                status=pci_status,
                violations_count=pci_violations,
                passed_controls=max(0, 6 - pci_violations),
                total_evaluated_controls=6,
            ),
            "ISO_27001": ComplianceScorecard(
                standard_name="ISO/IEC 27001:2022",
                compliance_score=iso_score,
                status=iso_status,
                violations_count=iso_violations,
                passed_controls=max(0, 8 - iso_violations),
                total_evaluated_controls=8,
            ),
        }

        exec_summary = (
            f"Target '{target_id}' assessed with an overall compliance score of {overall_score}% ({overall_status}). "
            f"Identified {len(violations)} standard control violations across OWASP Top 10 ({owasp_violations}), "
            f"PCI-DSS v4.0 ({pci_violations}), and ISO 27001:2022 ({iso_violations}). "
            f"{'Immediate remediation required before production deployment.' if overall_score < 70 else 'System maintains acceptable baseline security.'}"
        )

        return ComplianceReportResult(
            target_id=target_id,
            overall_compliance_score=overall_score,
            overall_status=overall_status,
            scorecards=scorecards,
            violations=violations,
            executive_summary=exec_summary,
            remediation_roadmap=sorted(list(remediation_items)),
        )


# Global singleton instance
compliance_reporter_agent = ComplianceReporterAgent()
