"""End-to-End full lifecycle integration test for Milestone M7."""

import pathlib
import pytest
from fastapi.testclient import TestClient
from backend.app.main import app
from backend.app.services.target_parser import TargetParser
from backend.app.services.scope_validator import ScopeValidator
from backend.app.services.correlator import Correlator
from backend.app.core.context import context_engine
from backend.app.core.guardrails import check_exploit_intent
from backend.app.services.findings_builder import findings_builder
from backend.app.storage.findings_db import findings_db
from backend.app.services.verification_planner import verification_planner
from backend.app.services.report_generator import report_generator

client = TestClient(app)


def test_full_lifecycle_e2e():
    """Verify the entire end-to-end pentest workflow from target ingestion to final report."""
    root_dir = pathlib.Path(__file__).resolve().parent.parent.parent

    # Step 1: Target Ingestion & Scope Validation
    raw_target = "http://192.168.100.153:8080"
    target_info = TargetParser.parse(raw_target)
    assert target_info.host == "192.168.100.153"
    assert target_info.port == 8080

    res_detect = client.post("/api/targets/detect", json={"input": raw_target})
    assert res_detect.status_code == 200
    detect_data = res_detect.json()
    assert detect_data["scope"]["allowed"] is True

    # Verify public IPs are rejected by scope validator
    res_pub = client.post("/api/targets/detect", json={"input": "8.8.8.8"})
    assert res_pub.status_code == 200
    assert res_pub.json()["scope"]["allowed"] is False

    # Step 2: Correlate Detected Service with Vulnerability KB
    cands = Correlator.correlate(product="Apache", version="2.4.49", limit=5)
    assert len(cands) > 0
    top_cve = cands[0]
    assert "CVE-2021-41773" in top_cve.cve_id
    assert top_cve.confidence >= 0.85

    # Step 3: ContextEngine Assembly & Guardrails
    # 3a. Exploit command blocked
    is_exploit, _ = check_exploit_intent("exploit target này ngay lập tức")
    assert is_exploit is True

    # 3b. Safe query contextualized with evidence
    ctx = context_engine.build_context(
        message="Apache 2.4.49 có CVE gì?",
        active_target="192.168.100.153:8080",
    )
    assert len(ctx["sources"]) > 0
    assert any("CVE-2021-41773" in s["title"] for s in ctx["sources"])

    # Step 4: Findings Generation & Deduplication
    findings = findings_builder.generate_findings_for_target("192.168.100.153")
    assert len(findings) >= 1
    target_finding = next((f for f in findings if "CVE-2021-41773" in (f.cve_id or "")), findings[0])
    assert target_finding.cvss_score >= 7.0

    # Step 5: Safe Read-Only Verification Plan
    plan = verification_planner.generate_plan(target_finding)
    assert len(plan.steps) >= 3
    assert all(s.is_safe_readonly for s in plan.steps)

    # Step 6: Execute Safe Verification Probe
    safe_cmd = plan.steps[1].command
    check_res = verification_planner.execute_safe_check(safe_cmd)
    assert check_res.status == "SUCCESS"
    assert check_res.is_vulnerable_indicated is True

    # Step 7: Promote Finding to VERIFIED
    res_update = client.put(
        f"/api/findings/{target_finding.id}",
        json={"status": "VERIFIED"},
    )
    assert res_update.status_code == 200
    assert res_update.json()["status"] == "VERIFIED"

    # Step 8: Generate Final Comprehensive Pentest Report
    report_res = report_generator.generate_report("192.168.100.153", campaign_name="E2E Demonstration")
    assert report_res["findings_count"] >= 1
    assert "EXECUTIVE SUMMARY" in report_res["markdown_content"]
    assert "REMEDIATION ROADMAP" in report_res["markdown_content"]

    # Verify report files written to toolkit/10-reports/
    md_path = root_dir / report_res["markdown_path"]
    html_path = root_dir / report_res["html_path"]
    assert md_path.exists()
    assert html_path.exists()

    # Step 9: Report APIs verification
    res_get_md = client.get("/api/reports/192.168.100.153")
    assert res_get_md.status_code == 200
    assert len(res_get_md.json()["markdown_content"]) > 100

    res_get_html = client.get("/api/reports/192.168.100.153/html")
    assert res_get_html.status_code == 200
    assert "text/html" in res_get_html.headers["content-type"]
