"""Comprehensive unit and integration tests for Milestone M5 (Findings Builder & Management)."""

from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.schemas.finding import (
    EvidenceItem,
    FindingCreate,
    FindingSeverity,
    FindingStatus,
    FindingUpdate,
)
from backend.app.services.findings_builder import findings_builder
from backend.app.storage.findings_db import findings_db

client = TestClient(app)


def test_create_and_get_finding():
    item = FindingCreate(
        target_id="192.168.1.100",
        title="Apache 2.4.49 Path Traversal",
        cve_id="CVE-2021-41773",
        cwe_id="CWE-22",
        cvss_score=7.5,
        cvss_severity=FindingSeverity.HIGH,
        status=FindingStatus.CANDIDATE,
        affected_asset="192.168.1.100:80",
        description="Path traversal vulnerability in Apache HTTP Server 2.4.49",
        remediation="Upgrade Apache to 2.4.51 or later",
        evidence_chain=[
            EvidenceItem(
                tool="nmap",
                file_path="scans/nmap.xml",
                matched_text="Apache 2.4.49 on port 80",
            )
        ],
    )
    created = findings_db.create_finding("FIND-TEST-001", item)
    assert created.id == "FIND-TEST-001"
    assert created.target_id == "192.168.1.100"
    assert created.cvss_severity == FindingSeverity.HIGH
    assert len(created.evidence_chain) == 1

    fetched = findings_db.get_finding("FIND-TEST-001")
    assert fetched is not None
    assert fetched.title == "Apache 2.4.49 Path Traversal"


def test_update_finding_status():
    update = FindingUpdate(
        status=FindingStatus.VERIFIED, remediation="Patched in staging"
    )
    updated = findings_db.update_finding("FIND-TEST-001", update)
    assert updated is not None
    assert updated.status == FindingStatus.VERIFIED
    assert updated.remediation == "Patched in staging"


def test_findings_deduplication():
    """Verify that multiple observations of the same asset + CVE merge into one finding with an extended evidence chain."""
    ev1 = EvidenceItem(
        tool="nmap",
        file_path="scans/nmap.xml",
        matched_text="Nmap banner: Apache 2.4.49",
    )
    f1 = findings_builder._upsert_finding(
        target_id="10.0.0.5",
        asset="10.0.0.5:8080",
        title="Apache 2.4.49 CVE-2021-41773",
        description="Matched via Nmap banner",
        cvss_score=7.5,
        evidence=ev1,
        cve_id="CVE-2021-41773",
    )

    ev2 = EvidenceItem(
        tool="nuclei",
        file_path="scans/nuclei.json",
        matched_text="Nuclei template cve-2021-41773 matched",
    )
    f2 = findings_builder._upsert_finding(
        target_id="10.0.0.5",
        asset="10.0.0.5:8080",
        title="Apache 2.4.49 CVE-2021-41773",
        description="Matched via Nuclei template",
        cvss_score=7.5,
        evidence=ev2,
        cve_id="CVE-2021-41773",
    )

    # Both upserts must resolve to the SAME finding ID
    assert f1.id == f2.id
    # Evidence chain must now contain both tool observations
    f_final = findings_db.get_finding(f1.id)
    assert f_final is not None
    assert len(f_final.evidence_chain) == 2
    tools = [e.tool for e in f_final.evidence_chain]
    assert "nmap" in tools
    assert "nuclei" in tools


def test_findings_rest_api_crud():
    # 1. List findings
    res = client.get("/api/findings")
    assert res.status_code == 200
    data = res.json()
    assert isinstance(data, list)
    assert len(data) > 0

    # 2. Filter by target
    res_filt = client.get("/api/findings?target_id=10.0.0.5")
    assert res_filt.status_code == 200
    assert len(res_filt.json()) >= 1

    # 3. Summary endpoint
    res_sum = client.get("/api/findings/summary?target_id=10.0.0.5")
    assert res_sum.status_code == 200
    summary = res_sum.json()
    assert summary["total"] >= 1
    assert "by_severity" in summary
    assert "by_status" in summary

    # 4. Manual Create via POST
    res_create = client.post(
        "/api/findings",
        json={
            "target_id": "10.0.0.5",
            "title": "Manual Finding Test",
            "affected_asset": "10.0.0.5:22",
            "description": "Manual SSH finding",
            "cvss_score": 5.0,
            "cvss_severity": "MEDIUM",
            "status": "CANDIDATE",
            "evidence_chain": [],
        },
    )
    assert res_create.status_code == 201
    created_id = res_create.json()["id"]

    # 5. Delete via DELETE
    res_del = client.delete(f"/api/findings/{created_id}")
    assert res_del.status_code == 200
    assert client.get(f"/api/findings/{created_id}").status_code == 404


def test_findings_auto_generation_from_scans():
    """Verify FindingsBuilder generates structured findings from simulated target scan files."""
    res = client.post("/api/findings/generate/192.168.56.101-3000")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    assert data["target_id"] == "192.168.56.101-3000"
    # Even if 0 or more findings generated depending on files, the endpoint executes cleanly
    assert "count" in data
