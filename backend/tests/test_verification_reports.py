"""Comprehensive unit and integration tests for Milestone M6 (Verification & Reports)."""

import pathlib

import pytest
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.schemas.finding import (
    EvidenceItem,
    FindingCreate,
    FindingSeverity,
    FindingStatus,
)
from backend.app.services.report_generator import report_generator
from backend.app.services.verification_planner import verification_planner
from backend.app.storage.findings_db import findings_db

client = TestClient(app)


@pytest.fixture(scope="module", autouse=True)
def setup_test_finding():
    item = FindingCreate(
        target_id="test-report-mock-target",
        title="Apache 2.4.49 Path Traversal Test",
        cve_id="CVE-2021-41773",
        cwe_id="CWE-22",
        cvss_score=7.5,
        cvss_severity=FindingSeverity.HIGH,
        status=FindingStatus.CANDIDATE,
        affected_asset="test-report-mock-target:80",
        description="Path traversal vulnerability test",
        remediation="Upgrade to 2.4.51+",
        evidence_chain=[
            EvidenceItem(
                tool="nmap",
                file_path="03-network/scans/nmap.xml",
                matched_text="Apache 2.4.49 on port 80",
            )
        ],
    )
    findings_db.create_finding("FIND-REPORT-TEST", item)
    yield
    findings_db.delete_finding("FIND-REPORT-TEST")


def test_verification_plan_generation():
    finding = findings_db.get_finding("FIND-REPORT-TEST")
    assert finding is not None
    plan = verification_planner.generate_plan(finding)
    assert plan.finding_id == "FIND-REPORT-TEST"
    assert len(plan.steps) >= 3
    for s in plan.steps:
        assert s.is_safe_readonly is True
        assert "curl" in s.command or "nc" in s.command
        assert s.expected_evidence != ""


def test_verification_safety_enforcement():
    # Attempting to execute an unsafe / exploit command must be BLOCKED
    res_bad = verification_planner.execute_safe_check(
        "sqlmap -u http://target --os-shell"
    )
    assert res_bad.status == "BLOCKED"
    assert "aborted" in res_bad.output.lower()

    # Safe echo banner command succeeds
    res_good = verification_planner.execute_safe_check(
        "echo 'HTTP/1.1 200 OK\nServer: Apache/2.4.49'"
    )
    assert res_good.status == "SUCCESS"
    assert "Apache" in res_good.output


def test_report_generation_markdown_and_html():
    res = report_generator.generate_report(
        "test-report-mock-target", campaign_name="Integration Test Campaign"
    )
    assert res["target_id"] == "test-report-mock-target"
    assert res["findings_count"] >= 1
    assert "EXECUTIVE SUMMARY" in res["markdown_content"]
    assert "CVE-2021-41773" in res["markdown_content"]

    root_dir = pathlib.Path(__file__).resolve().parent.parent.parent
    md_file = root_dir / res["markdown_path"]
    html_file = root_dir / res["html_path"]
    assert md_file.exists()
    assert html_file.exists()
    assert "<!DOCTYPE html>" in html_file.read_text(encoding="utf-8")


def test_verification_and_report_rest_api():
    # 1. GET verification plan
    res_plan = client.get("/api/verification/plan/FIND-REPORT-TEST")
    assert res_plan.status_code == 200
    plan_data = res_plan.json()
    assert len(plan_data["steps"]) >= 3

    # 2. POST execute verification check
    res_exec = client.post(
        "/api/verification/execute",
        json={"command": "echo 'HTTP/1.1 200 OK\nServer: Apache/2.4.49'"},
    )
    assert res_exec.status_code == 200
    assert res_exec.json()["status"] == "SUCCESS"

    # 3. POST generate report
    res_gen = client.post("/api/reports/generate/test-report-mock-target")
    assert res_gen.status_code == 200
    assert "markdown_path" in res_gen.json()

    # 4. GET report detail
    res_rep = client.get("/api/reports/test-report-mock-target")
    assert res_rep.status_code == 200
    assert "markdown_content" in res_rep.json()

    # 5. GET list reports
    res_list = client.get("/api/reports")
    assert res_list.status_code == 200
    assert len(res_list.json()["reports"]) >= 1
    assert res_list.status_code == 200
    assert len(res_list.json()["reports"]) >= 1
