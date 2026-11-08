"""Comprehensive unit and integration tests for Findings Deduplication & Merging Engine."""

import pytest
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.schemas.finding import (
    EvidenceItem,
    FindingCreate,
    FindingSeverity,
    FindingStatus,
)
from backend.app.services.findings_builder import findings_builder
from backend.app.storage.findings_db import (
    are_assets_compatible,
    clean_finding_title,
    findings_db,
    normalize_asset,
    normalize_target_id,
    normalize_title,
)

client = TestClient(app)


def test_asset_and_target_normalization():
    """Verify target and asset normalization across different tool formats."""
    # Target normalization
    assert normalize_target_id("target-192.168.100.153") == "192.168.100.153"
    assert normalize_target_id("192.168.100.153") == "192.168.100.153"
    assert normalize_target_id("  target-10.0.0.1  ") == "10.0.0.1"

    # Asset normalization
    assert normalize_asset("http://192.168.100.153") == ("192.168.100.153", 80)
    assert normalize_asset("https://192.168.100.153") == ("192.168.100.153", 443)
    assert normalize_asset("http://192.168.100.153:8080/app") == ("192.168.100.153", 8080)
    assert normalize_asset("192.168.100.153:80") == ("192.168.100.153", 80)
    assert normalize_asset("192.168.100.153") == ("192.168.100.153", None)

    # Asset compatibility
    assert are_assets_compatible("http://192.168.100.153", "192.168.100.153:80") is True
    assert are_assets_compatible("http://192.168.100.153/", "192.168.100.153") is True
    assert are_assets_compatible("192.168.100.153:80", "192.168.100.153:8080") is True
    assert are_assets_compatible("192.168.100.153:22", "192.168.100.153:80") is False


def test_title_cleaning_and_normalization():
    """Verify tool prefixes are cleanly stripped."""
    t1 = "[SIMULATED] WhatWeb: Apache 2.4.49 — CVE-2021-42013"
    assert clean_finding_title(t1) == "Apache 2.4.49 — CVE-2021-42013"

    t2 = "HTTPx Web Banner: Apache 2.4.49 — CVE-2021-42013"
    assert clean_finding_title(t2) == "Apache 2.4.49 — CVE-2021-42013"

    t3 = "Nuclei: Apache 2.4.49 - Path Traversal (CVE-2021-41773)"
    assert clean_finding_title(t3) == "Apache 2.4.49 - Path Traversal (CVE-2021-41773)"

    norm1 = normalize_title("Nikto: The anti-clickjacking X-Frame-Options header is not present.")
    norm2 = normalize_title("The anti-clickjacking X-Frame-Options header is not present.")
    assert norm1 == norm2


def test_cve_deduplication_across_multiple_tools():
    """Verify 5 tools reporting the same CVE on a target merge into 1 finding with 5 evidence items."""
    target = "192.168.99.50"
    cve = "CVE-2021-41773"

    # Tool 1: Nmap
    ev1 = EvidenceItem(
        tool="nmap",
        file_path="scans/nmap.xml",
        matched_text="Nmap port 80 Apache 2.4.49",
        trustworthy=False,
        is_simulated=True,
    )
    f1 = findings_builder._upsert_finding(
        target_id=target,
        asset=f"{target}:80",
        title=f"Apache 2.4.49 — {cve}",
        description="Apache Path Traversal via Nmap banner",
        cvss_score=7.5,
        evidence=ev1,
        cve_id=cve,
        cwe_id="CWE-20",
        trustworthy=False,
        is_simulated=True,
    )

    # Tool 2: Nuclei (Real & Higher CVSS)
    ev2 = EvidenceItem(
        tool="nuclei",
        file_path="scans/nuclei.json",
        matched_text=f"Template {cve} matched at http://{target}/",
        trustworthy=True,
        is_simulated=False,
    )
    f2 = findings_builder._upsert_finding(
        target_id=target,
        asset=f"http://{target}/",
        title=f"Nuclei: Apache 2.4.49 - Path Traversal ({cve})",
        description="Path traversal validated by Nuclei scanner probe",
        cvss_score=9.8,
        evidence=ev2,
        cve_id=cve,
        cwe_id="CWE-22",
        trustworthy=True,
        is_simulated=False,
    )

    # Tool 3: WhatWeb
    ev3 = EvidenceItem(
        tool="whatweb",
        file_path="scans/whatweb.json",
        matched_text="WhatWeb detected: Apache 2.4.49",
        trustworthy=True,
        is_simulated=False,
    )
    f3 = findings_builder._upsert_finding(
        target_id=target,
        asset=f"http://{target}",
        title=f"WhatWeb: Apache 2.4.49 — {cve}",
        description="WhatWeb technology fingerprint",
        cvss_score=7.5,
        evidence=ev3,
        cve_id=cve,
        trustworthy=True,
        is_simulated=False,
    )

    # Tool 4: HTTPx
    ev4 = EvidenceItem(
        tool="httpx",
        file_path="scans/httpx.json",
        matched_text="HTTPx Server: Apache/2.4.49",
        trustworthy=True,
        is_simulated=False,
    )
    f4 = findings_builder._upsert_finding(
        target_id=f"target-{target}",  # Test with target- prefix
        asset=target,
        title=f"HTTPx Web Banner: Apache 2.4.49 — {cve}",
        description="HTTPx server banner match",
        cvss_score=7.5,
        evidence=ev4,
        cve_id=cve,
        trustworthy=True,
        is_simulated=False,
    )

    # Tool 5: SearchSploit
    ev5 = EvidenceItem(
        tool="searchsploit",
        file_path="scans/searchsploit.json",
        matched_text="SearchSploit match: EDB-50383",
        trustworthy=True,
        is_simulated=False,
    )
    f5 = findings_builder._upsert_finding(
        target_id=target,
        asset=target,
        title=f"SearchSploit Reference: Apache 2.4.49 — {cve}",
        description="Exploit-DB reference lookup",
        cvss_score=5.0,
        evidence=ev5,
        cve_id=cve,
        trustworthy=True,
        is_simulated=False,
    )

    # All 5 tool upserts must resolve to the exact same Master finding ID
    assert f1.id == f2.id == f3.id == f4.id == f5.id

    # Fetch consolidated finding from database
    final_f = findings_db.get_finding(f1.id)
    assert final_f is not None

    # Check evidence chain length: all 5 tools must be represented
    assert len(final_f.evidence_chain) == 5
    tools_in_chain = {e.tool for e in final_f.evidence_chain}
    assert tools_in_chain == {"nmap", "nuclei", "whatweb", "httpx", "searchsploit"}

    # Must upgrade to highest CVSS score (9.8 from Nuclei)
    assert final_f.cvss_score == 9.8
    assert final_f.cvss_severity == FindingSeverity.CRITICAL

    # Must retain specific CWE-22 from Nuclei instead of generic CWE-20
    assert final_f.cwe_id == "CWE-22"

    # Because Nuclei and HTTPx were real, finding must be marked trustworthy and not simulated
    assert final_f.trustworthy is True
    assert final_f.is_simulated is False


def test_batch_deduplicate_all():
    """Verify deduplicate_all correctly detects and merges separately inserted duplicates."""
    target_id = "test-dedup-target"

    # Create 3 duplicate findings directly in database
    f_create1 = FindingCreate(
        target_id=target_id,
        title="Apache 2.4.49 — CVE-2021-42013",
        cve_id="CVE-2021-42013",
        cvss_score=7.5,
        cvss_severity=FindingSeverity.HIGH,
        status=FindingStatus.CANDIDATE,
        affected_asset=f"{target_id}:80",
        description="Nmap observation",
        evidence_chain=[EvidenceItem(tool="nmap", file_path="nmap.xml", matched_text="nmap 80")],
    )
    f_create2 = FindingCreate(
        target_id=target_id,
        title="WhatWeb: Apache 2.4.49 — CVE-2021-42013",
        cve_id="CVE-2021-42013",
        cvss_score=7.5,
        cvss_severity=FindingSeverity.HIGH,
        status=FindingStatus.CANDIDATE,
        affected_asset=f"http://{target_id}",
        description="WhatWeb observation",
        evidence_chain=[EvidenceItem(tool="whatweb", file_path="whatweb.json", matched_text="whatweb 80")],
    )
    f_create3 = FindingCreate(
        target_id=target_id,
        title="HTTPx Web Banner: Apache 2.4.49 — CVE-2021-42013",
        cve_id="CVE-2021-42013",
        cvss_score=9.8,
        cvss_severity=FindingSeverity.CRITICAL,
        status=FindingStatus.CANDIDATE,
        affected_asset=target_id,
        description="HTTPx observation",
        evidence_chain=[EvidenceItem(tool="httpx", file_path="httpx.json", matched_text="httpx banner")],
    )

    findings_db.create_finding("FIND-TEST-DEDUP-1", f_create1)
    findings_db.create_finding("FIND-TEST-DEDUP-2", f_create2)
    findings_db.create_finding("FIND-TEST-DEDUP-3", f_create3)

    # Verify initially 3 findings exist
    initial_findings = findings_db.list_findings(target_id=target_id)
    assert len(initial_findings) == 3

    # Run batch deduplicate
    stats = findings_db.deduplicate_all(target_id=target_id)
    assert stats["merged_groups"] == 1
    assert stats["removed_duplicates"] == 2
    assert stats["remaining_findings"] == 1

    # Verify only 1 finding remains in the database
    remaining = findings_db.list_findings(target_id=target_id)
    assert len(remaining) == 1

    master = remaining[0]
    assert master.cve_id == "CVE-2021-42013"
    assert master.cvss_score == 9.8
    assert len(master.evidence_chain) == 3
    tools = {e.tool for e in master.evidence_chain}
    assert tools == {"nmap", "whatweb", "httpx"}


def test_rest_api_deduplicate_endpoint():
    """Verify POST /api/findings/deduplicate executes and returns success status."""
    res = client.post("/api/findings/deduplicate")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    assert "stats" in data
    assert "remaining_findings" in data["stats"]
