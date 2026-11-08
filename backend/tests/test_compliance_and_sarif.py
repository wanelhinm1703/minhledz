"""Tests for Pillar 4: Compliance 2.0 & DevSecOps SARIF Integration."""

from __future__ import annotations

import json
import pytest
from starlette.testclient import TestClient

from backend.app.main import app
from backend.app.schemas.finding import FindingCreate, FindingSeverity, FindingStatus
from backend.app.services.compliance_engine import compliance_engine
from backend.app.services.report_generator import report_generator
from backend.app.services.sarif_exporter import sarif_exporter
from backend.app.storage.findings_db import findings_db


@pytest.fixture
def client():
    return TestClient(app)


def test_compliance_engine_owasp_and_top25_mapping():
    """Verify CWE mappings to OWASP Top 10, CWE Top 25, NIST SP 800-115, and CIS Controls."""
    # Test CWE-22 (Path Traversal) -> A01:2021 Broken Access Control & CWE Top 25 Rank 8
    dummy_finding_path_traversal = FindingCreate(
        target_id="test-target",
        title="Apache Path Traversal",
        cve_id="CVE-2021-41773",
        cwe_id="CWE-22",
        cvss_score=7.5,
        cvss_severity=FindingSeverity.HIGH,
        status=FindingStatus.VERIFIED,
        affected_asset="test-target:80",
        description="Path traversal flaw",
        remediation="Upgrade Apache",
        evidence_chain=[],
    )

    mapping = compliance_engine.map_finding(dummy_finding_path_traversal)
    assert mapping["owasp"]["id"] == "A01:2021"
    assert "Broken Access Control" in mapping["owasp"]["name"]
    assert mapping["cwe_top_25"]["is_top_25"] is True
    assert mapping["cwe_top_25"]["rank"] == 8
    assert "NIST SP 800-115" in mapping["nist_sp_800_115"]["section"]
    assert "CIS Control" in mapping["cis_controls"]["control"]

    # Test CWE-89 (SQL Injection) -> A03:2021 Injection & CWE Top 25 Rank 3
    dummy_sqli = FindingCreate(
        target_id="test-target",
        title="SQL Injection Vulnerability",
        cve_id=None,
        cwe_id="CWE-89",
        cvss_score=9.8,
        cvss_severity=FindingSeverity.CRITICAL,
        status=FindingStatus.VERIFIED,
        affected_asset="test-target:443",
        description="SQL injection in login",
        remediation="Use prepared statements",
        evidence_chain=[],
    )
    mapping_sqli = compliance_engine.map_finding(dummy_sqli)
    assert mapping_sqli["owasp"]["id"] == "A03:2021"
    assert mapping_sqli["cwe_top_25"]["rank"] == 3


def test_compliance_summary_score_and_deductions():
    """Verify overall compliance score calculation and posture status."""
    findings = [
        FindingCreate(
            target_id="test-target",
            title="Critical SQL Injection",
            cwe_id="CWE-89",
            cvss_score=9.8,
            cvss_severity=FindingSeverity.CRITICAL,
            status=FindingStatus.VERIFIED,
            affected_asset="test-target:443",
            description="Severe SQL flaw",
            evidence_chain=[],
        )
    ]
    summary = compliance_engine.evaluate_compliance_summary(findings)
    assert summary["compliance_score"] < 100
    assert "NON-COMPLIANT" in summary["status"]
    assert summary["critical_high_count"] == 1
    assert "A03:2021" in summary["owasp_top_10_breakdown"]


def test_sarif_exporter_oasis_schema():
    """Verify SARIF 2.1.0 output complies with OASIS standard schema."""
    target_id = "test-sarif-target"
    f_create = FindingCreate(
        target_id=target_id,
        title="Apache httpd 2.4.49 Path Traversal",
        cve_id="CVE-2021-41773",
        cwe_id="CWE-22",
        cvss_score=7.5,
        cvss_severity=FindingSeverity.HIGH,
        status=FindingStatus.VERIFIED,
        affected_asset="192.168.56.101:80",
        description="Path traversal attack outside document root",
        remediation="Upgrade to 2.4.51",
        evidence_chain=[],
    )
    sarif_doc = sarif_exporter.export_sarif(target_id, [f_create])

    assert sarif_doc["version"] == "2.1.0"
    assert "sarif-spec" in sarif_doc["$schema"]
    assert len(sarif_doc["runs"]) == 1

    driver = sarif_doc["runs"][0]["tool"]["driver"]
    assert driver["name"] == "AI-Pentest Copilot"
    assert len(driver["rules"]) == 1

    rule = driver["rules"][0]
    assert rule["id"] == "CVE-2021-41773"
    assert rule["defaultConfiguration"]["level"] == "error"
    assert rule["properties"]["security-severity"] == "7.5"
    assert "A01:2021" in rule["properties"]["owasp"]

    results = sarif_doc["runs"][0]["results"]
    assert len(results) == 1
    assert results[0]["ruleId"] == "CVE-2021-41773"
    assert results[0]["level"] == "error"
    assert "target://192.168.56.101:80" in results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]


def test_report_generator_generates_all_formats():
    """Verify ReportGenerator generates Markdown, HTML, SARIF, and JSON."""
    target_id = "192.168.56.101"
    result = report_generator.generate_report(target_id, campaign_name="DevSecOps Audit Test")

    assert "markdown_path" in result
    assert "html_path" in result
    assert "sarif_path" in result
    assert "json_path" in result
    assert "compliance_summary" in result

    # Check Markdown contains Compliance Matrix
    md = result["markdown_content"]
    assert "REGULATORY & COMPLIANCE POSTURE" in md
    assert "OWASP Top 10" in md
    assert "MITRE CWE Top 25" in md

    # Check report files physically exist
    clean_target = target_id.replace(":", "-").replace("/", "-")
    rep_dir = report_generator.reports_dir
    assert (rep_dir / f"{clean_target}_report.md").exists()
    assert (rep_dir / f"{clean_target}_report.html").exists()
    assert (rep_dir / f"{clean_target}_report.sarif").exists()
    assert (rep_dir / f"{clean_target}_report.json").exists()


def test_reports_api_sarif_and_compliance_endpoints(client):
    """Verify REST API endpoints for SARIF download and Compliance Matrix."""
    target_id = "192.168.56.101"

    # GET /api/reports/{target_id}/sarif
    res = client.get(f"/api/reports/{target_id}/sarif")
    assert res.status_code == 200
    assert "application/sarif+json" in res.headers.get("content-type", "")
    data = res.json()
    assert data["version"] == "2.1.0"

    # GET /api/reports/{target_id}/sarif?download=true
    res_dl = client.get(f"/api/reports/{target_id}/sarif?download=true")
    assert res_dl.status_code == 200
    assert "attachment" in res_dl.headers.get("content-disposition", "")
    assert ".sarif" in res_dl.headers.get("content-disposition", "")

    # GET /api/reports/{target_id}/compliance
    res_comp = client.get(f"/api/reports/{target_id}/compliance")
    assert res_comp.status_code == 200
    comp_data = res_comp.json()
    assert "summary" in comp_data
    assert "compliance_score" in comp_data["summary"]
    assert "detailed_mappings" in comp_data
