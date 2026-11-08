import pytest
from backend.app.services.agents.recon_analyst_agent import (
    ReconAnalystAgent,
    DiscoveredService,
    recon_analyst_agent,
)
from backend.app.services.agents.threat_intel_agent import (
    ThreatIntelAgent,
    VulnerabilityMatch,
    threat_intel_agent,
)
from backend.app.services.agents.verification_agent import (
    SafeVerificationPlannerAgent,
    safe_verification_agent,
)
from backend.app.services.agents.orchestrator import (
    SpecialistAgentOrchestrator,
    orchestrator,
)


def test_recon_analyst_conflict_detection():
    """Verify Recon Analyst identifies services and detects version discrepancies across tools."""
    mock_scans = [
        {
            "tool": "nmap",
            "ports": [
                {
                    "port": 80,
                    "protocol": "tcp",
                    "service": "http",
                    "product": "Apache httpd",
                    "version": "2.4.49",
                }
            ],
        },
        {
            "tool": "whatweb",
            "technologies": [
                {
                    "name": "Apache",
                    "version": "2.4.51",
                }
            ],
        },
    ]

    agent = ReconAnalystAgent()
    res = agent.analyze("target-test-recon", scans_data=mock_scans)
    assert len(res.discovered_services) == 2
    assert len(res.conflicts) >= 1
    assert any("Nmap" in c and "WhatWeb" in c for c in res.conflicts)
    assert res.confidence < 0.90  # Conflicted results lower confidence


def test_threat_intel_agent_correlation():
    """Verify Threat Intel agent accurately correlates discovered services with KB."""
    agent = ThreatIntelAgent()
    services = [
        DiscoveredService(
            tool="nmap",
            port=80,
            service_name="http",
            product="Apache",
            version="2.4.49",
        )
    ]

    res = agent.correlate_services("target-test-intel", services)
    assert len(res.matches) >= 1
    top = res.matches[0]
    assert "CVE-2021-41773" in top.cve_id
    assert top.cvss_score >= 7.0
    assert top.remediation != ""
    assert res.high_count >= 1 or res.critical_count >= 1


def test_safe_verification_planner_agent():
    """Verify Safe Verification agent produces non-destructive, strictly read-only plans."""
    agent = SafeVerificationPlannerAgent()
    match = VulnerabilityMatch(
        cve_id="CVE-2021-41773",
        product="Apache",
        version="2.4.49",
        cvss_score=7.5,
        cwe_ids=["CWE-22"],
        description="Path traversal flaw in Apache 2.4.49",
        remediation="Upgrade to 2.4.50+",
    )

    plan = agent.generate_plan_for_match(
        target_id="target-test-verify",
        match=match,
        target_host="192.168.1.100",
        port=80,
    )
    assert len(plan.steps) >= 2
    assert all(s.is_safe_readonly for s in plan.steps)
    assert plan.guardrails_enforced is True
    assert len(plan.remediation_roadmap) >= 3


def test_specialist_agent_orchestrator():
    """Verify the Orchestrator successfully executes collaborative multi-agent cycle."""
    res = orchestrator.run_collaborative_assessment("192.168.100.153")
    assert res.target_id == "192.168.100.153"
    assert res.recon_analysis is not None
    assert res.threat_intel is not None
    assert "Multi-Agent Assessment" in res.executive_summary
