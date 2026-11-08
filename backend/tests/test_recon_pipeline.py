import pathlib

import pytest

from backend.app.services.scope_validator import ScopeViolation
from toolkit.scripts.parse_httpx import HttpxParser
from toolkit.scripts.parse_nuclei import NucleiParser
from toolkit.scripts.pipeline_runner import run_pipeline
from toolkit.scripts.run_httpx import run_httpx_scan
from toolkit.scripts.run_naabu import run_naabu_scan
from toolkit.scripts.run_nuclei import run_nuclei_scan


def test_naabu_scan_simulation(tmp_path):
    scan_dir = tmp_path / "naabu_scan"
    res = run_naabu_scan(
        target_id="test-naabu",
        target_host="192.168.56.101",
        port=80,
        output_dir=scan_dir,
        simulate=True,
    )
    assert res["exit_code"] == 0
    assert pathlib.Path(res["raw_path"]).exists()
    assert pathlib.Path(res["commands_log"]).exists()
    content = pathlib.Path(res["raw_path"]).read_text(encoding="utf-8")
    assert "192.168.56.101:80" in content


def test_httpx_scan_and_parse(tmp_path):
    scan_dir = tmp_path / "httpx_scan"
    res = run_httpx_scan(
        target_id="test-httpx",
        target_url="http://192.168.56.101:3000",
        target_host="192.168.56.101",
        port=3000,
        output_dir=scan_dir,
        simulate=True,
    )
    assert res["exit_code"] == 0
    assert pathlib.Path(res["raw_path"]).exists()

    schema_file = (
        pathlib.Path(__file__).resolve().parent.parent.parent
        / "security"
        / "schemas"
        / "httpx_result.schema.json"
    )
    parsed = HttpxParser.parse_raw_jsonl(
        jsonl_path=pathlib.Path(res["raw_path"]),
        scan_metadata=res,
        schema_path=schema_file,
    )
    assert parsed["scan_metadata"]["tool"] == "httpx"
    assert len(parsed["results"]) == 1
    assert parsed["results"][0]["status_code"] == 200
    assert "Juice Shop" in parsed["results"][0]["title"]
    assert "Node.js" in parsed["results"][0]["technologies"]


def test_nuclei_scan_and_parse(tmp_path):
    scan_dir = tmp_path / "nuclei_scan"
    res = run_nuclei_scan(
        target_id="test-nuclei",
        target_url="http://192.168.56.101:3000",
        target_host="192.168.56.101",
        output_dir=scan_dir,
        simulate=True,
    )
    assert res["exit_code"] == 0
    assert pathlib.Path(res["raw_path"]).exists()

    schema_file = (
        pathlib.Path(__file__).resolve().parent.parent.parent
        / "security"
        / "schemas"
        / "nuclei_finding.schema.json"
    )
    parsed = NucleiParser.parse_raw_jsonl(
        jsonl_path=pathlib.Path(res["raw_path"]),
        scan_metadata=res,
        schema_path=schema_file,
    )
    assert parsed["scan_metadata"]["tool"] == "nuclei"
    assert len(parsed["findings"]) >= 1
    cve_finding = next(
        f for f in parsed["findings"] if f["template_id"] == "CVE-2021-41773"
    )
    assert cve_finding["info"]["severity"] == "high"
    assert "CWE-22" in cve_finding["info"]["cwe_id"]


def test_pipeline_web_target():
    manifest = run_pipeline("http://192.168.56.101:3000")
    assert "nmap" in manifest["tools_executed"]
    assert "httpx" in manifest["tools_executed"]
    assert "nuclei" in manifest["tools_executed"]
    assert "web" in manifest["capabilities"]
    assert pathlib.Path(manifest["evidence_files"]["nmap"]["structured"]).exists()
    assert pathlib.Path(manifest["evidence_files"]["httpx"]["structured"]).exists()
    assert pathlib.Path(manifest["evidence_files"]["nuclei"]["structured"]).exists()


def test_pipeline_network_target():
    manifest = run_pipeline("192.168.56.101")
    assert "naabu" in manifest["tools_executed"]
    assert "nmap" in manifest["tools_executed"]
    assert "network" in manifest["capabilities"]
    assert pathlib.Path(manifest["evidence_files"]["naabu"]["raw"]).exists()
    assert pathlib.Path(manifest["evidence_files"]["nmap"]["structured"]).exists()


def test_pipeline_scope_violation():
    with pytest.raises(ScopeViolation):
        run_pipeline("8.8.8.8")
