import json

from backend.app.core.context import ContextData, ContextEngine
from backend.app.schemas.finding import FindingStatus
from backend.app.services.findings_builder import FindingsBuilder
from backend.app.services.report_generator import ReportGenerator
from toolkit.scripts.scan_status import (
    compute_file_sha256,
    create_scan_status,
    is_scan_trustworthy,
    load_scan_status,
    save_scan_status,
)


def test_scan_status_lifecycle(tmp_path):
    tool_dir = tmp_path / "nmap"
    tool_dir.mkdir(parents=True)
    raw_file = tool_dir / "raw" / "nmap_raw.xml"
    raw_file.parent.mkdir(parents=True)
    raw_file.write_text("<nmaprun>open port 80</nmaprun>", encoding="utf-8")

    st = create_scan_status(
        tool="nmap",
        target_id="target-10.0.0.1",
        target_url="http://10.0.0.1",
        mode="real",
        reason=None,
        exit_code=0,
        binary_available=True,
        raw_file_path=raw_file,
        relative_raw_path=str(raw_file),
        finding_count=1,
    )
    assert st.mode == "real"
    assert st.evidence_trustworthy is True
    assert st.raw_sha256 is not None
    assert st.raw_size_bytes > 0

    save_path = save_scan_status(tool_dir, st)
    assert save_path.exists()

    loaded = load_scan_status(tool_dir)
    assert loaded is not None
    assert loaded["tool"] == "nmap"
    assert loaded["mode"] == "real"
    assert loaded["evidence_trustworthy"] is True
    assert is_scan_trustworthy(tool_dir) is True


def test_scan_status_failed_mode(tmp_path):
    tool_dir = tmp_path / "nuclei"
    tool_dir.mkdir(parents=True)

    st = create_scan_status(
        tool="nuclei",
        target_id="target-10.0.0.1",
        target_url="http://10.0.0.1",
        mode="failed",
        reason="binary_not_found",
        exit_code=127,
        binary_available=False,
        evidence_trustworthy=False,
        errors=["Nuclei not found in PATH"],
    )
    assert st.mode == "failed"
    assert st.evidence_trustworthy is False
    assert st.exit_code == 127
    assert st.reason == "binary_not_found"

    save_scan_status(tool_dir, st)
    assert is_scan_trustworthy(tool_dir) is False


def test_scan_status_simulated_mode(tmp_path):
    tool_dir = tmp_path / "httpx"
    tool_dir.mkdir(parents=True)

    st = create_scan_status(
        tool="httpx",
        target_id="target-10.0.0.1",
        mode="simulated",
        reason=None,
        exit_code=0,
        binary_available=True,
        evidence_trustworthy=False,
    )
    assert st.mode == "simulated"
    assert st.evidence_trustworthy is False

    save_scan_status(tool_dir, st)
    assert is_scan_trustworthy(tool_dir) is False


def test_compute_file_sha256(tmp_path):
    non_existent = tmp_path / "does_not_exist.txt"
    assert compute_file_sha256(non_existent) is None

    test_file = tmp_path / "evidence.txt"
    test_file.write_text("secure evidence data", encoding="utf-8")
    sha1 = compute_file_sha256(test_file)
    assert sha1 is not None and len(sha1) == 64

    # Identical content produces identical hash
    test_file2 = tmp_path / "evidence2.txt"
    test_file2.write_text("secure evidence data", encoding="utf-8")
    assert compute_file_sha256(test_file2) == sha1


def test_findings_builder_skips_failed_tool(tmp_path):
    from backend.app.storage.findings_db import findings_db

    builder = FindingsBuilder(root_dir=tmp_path)
    tid = "test-target-failed"
    findings_db.delete_by_target(tid)
    vuln_scans = tmp_path / "toolkit" / "05-vulnerability" / "scans" / tid / "nuclei"
    vuln_scans.mkdir(parents=True)

    # Save failed scan_status
    st = create_scan_status(
        tool="nuclei",
        target_id=tid,
        mode="failed",
        reason="binary_not_found",
        exit_code=127,
        binary_available=False,
    )
    save_scan_status(vuln_scans, st)

    # Even if an old/stale structured json exists, it must be ignored because mode=failed
    struct_dir = vuln_scans / "structured"
    struct_dir.mkdir(parents=True)
    fake_payload = {
        "matches": [
            {
                "template_id": "CVE-2021-41773",
                "info": {
                    "name": "Apache RCE",
                    "severity": "critical",
                    "cvss_score": 9.8,
                },
                "matched_at": "http://test-target-failed/icons/",
            }
        ]
    }
    (struct_dir / "nuclei_result.json").write_text(
        json.dumps(fake_payload), encoding="utf-8"
    )

    findings = builder.generate_findings_for_target(tid)
    # Failed tool scan must NOT produce any findings
    assert len(findings) == 0


def test_findings_builder_flags_simulated_findings(tmp_path):
    from backend.app.storage.findings_db import findings_db

    builder = FindingsBuilder(root_dir=tmp_path)
    tid = "test-target-sim"
    findings_db.delete_by_target(tid)
    vuln_scans = tmp_path / "toolkit" / "05-vulnerability" / "scans" / tid / "nuclei"
    vuln_scans.mkdir(parents=True)

    # Save simulated scan_status
    st = create_scan_status(
        tool="nuclei",
        target_id=tid,
        mode="simulated",
        reason="binary_not_found",
        exit_code=127,
        binary_available=False,
        evidence_trustworthy=False,
    )
    save_scan_status(vuln_scans, st)

    sim_dir = vuln_scans / "simulated"
    sim_dir.mkdir(parents=True)
    sim_payload = {
        "matches": [
            {
                "template_id": "CVE-2021-41773",
                "info": {
                    "name": "Apache Path Traversal",
                    "severity": "high",
                    "cvss_score": 7.5,
                },
                "matched_at": "http://test-target-sim//icons/.%%32%65/",
            }
        ]
    }
    (sim_dir / "nuclei_result.json").write_text(
        json.dumps(sim_payload), encoding="utf-8"
    )

    findings = builder.generate_findings_for_target(tid)
    assert len(findings) == 1
    f = findings[0]
    # Finding must be explicitly tagged as simulated and untrustworthy
    assert "[SIMULATED]" in f.title
    assert f.trustworthy is False
    assert f.is_simulated is True
    assert f.status in (FindingStatus.CANDIDATE, FindingStatus.UNVERIFIED, FindingStatus.INSUFFICIENT_EVIDENCE)
    assert len(f.evidence_chain) == 1
    assert f.evidence_chain[0].trustworthy is False
    assert f.evidence_chain[0].is_simulated is True


def test_report_generator_audit_table_and_insufficient_evidence(tmp_path):
    generator = ReportGenerator(root_dir=tmp_path)

    tid = "target-unverified-only"
    # Create tool directory with failed scan
    tool_dir = tmp_path / "toolkit" / "05-vulnerability" / "scans" / tid / "nuclei"
    tool_dir.mkdir(parents=True)
    st = create_scan_status(
        tool="nuclei",
        target_id=tid,
        mode="failed",
        reason="binary_not_found",
        exit_code=127,
        binary_available=False,
    )
    save_scan_status(tool_dir, st)

    report = generator.generate_report(tid)
    md = report["markdown_content"]

    # Must include Tool Execution & Reliability Audit table
    assert "Tool Execution & Reliability Audit" in md
    assert "FAILED" in md or "binary_not_found" in md
    # Must flag insufficient evidence when 0 trustworthy findings exist
    assert "INSUFFICIENT EVIDENCE" in md


def test_context_engine_injects_anti_hallucination_directive(tmp_path):
    # Test that ContextEngine includes warning notices when scans failed/simulated
    ctx_data = ContextData(
        user_message="Are there any CVEs?",
        active_target={"name": "test-box", "host": "192.168.1.50", "type": "ip"},
        recent_scans=[
            {
                "tool": "nuclei",
                "type": "vulnerabilities",
                "mode": "failed",
                "trustworthy": False,
                "reason": "binary_not_found",
                "summary": "Nuclei scan failed: binary not found.",
            }
        ],
    )

    messages = ContextEngine.to_prompt_messages(ctx_data)
    assert len(messages) >= 2
    prompt_str = "\n".join([m["content"] for m in messages])

    assert "FAILED" in prompt_str
    assert "KHÔNG ĐƯỢC" in prompt_str or "bịa đặt" in prompt_str
