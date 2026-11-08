import pathlib

from toolkit.scripts.parse_ffuf import FfufParser
from toolkit.scripts.parse_gobuster import GobusterParser
from toolkit.scripts.parse_katana import KatanaParser
from toolkit.scripts.parse_masscan import MasscanParser
from toolkit.scripts.parse_nikto import NiktoParser
from toolkit.scripts.parse_rustscan import RustscanParser
from toolkit.scripts.parse_searchsploit import SearchsploitParser
from toolkit.scripts.parse_service_enum import ServiceEnumParser
from toolkit.scripts.parse_whatweb import WhatwebParser
from toolkit.scripts.run_ffuf import run_ffuf_scan
from toolkit.scripts.run_gobuster import run_gobuster_scan
from toolkit.scripts.run_katana import run_katana_scan
from toolkit.scripts.run_masscan import run_masscan_scan
from toolkit.scripts.run_nikto import run_nikto_scan
from toolkit.scripts.run_proxy_manual import run_proxy_manual_workflow
from toolkit.scripts.run_rustscan import run_rustscan_scan
from toolkit.scripts.run_searchsploit import run_searchsploit_lookup
from toolkit.scripts.run_service_enum import run_service_enum_scan
from toolkit.scripts.run_whatweb import run_whatweb_scan

ROOT_DIR = pathlib.Path(__file__).resolve().parent.parent.parent
SCHEMAS_DIR = ROOT_DIR / "security" / "schemas"


def test_masscan_runner_and_parser(tmp_path):
    res = run_masscan_scan(
        target_id="test-masscan",
        target_host="192.168.1.10",
        ports="80,443",
        output_dir=tmp_path / "masscan",
        simulate=True,
    )
    assert res["exit_code"] == 0
    assert pathlib.Path(res["raw_path"]).exists()

    schema = SCHEMAS_DIR / "masscan_result.schema.json"
    parsed = MasscanParser.parse_raw_json(
        json_path=pathlib.Path(res["raw_path"]),
        scan_metadata=res,
        schema_path=schema,
    )
    assert parsed["scan_metadata"]["tool"] == "masscan"
    assert len(parsed["hosts"]) == 1
    assert len(parsed["hosts"][0]["ports"]) == 2


def test_rustscan_runner_and_parser(tmp_path):
    res = run_rustscan_scan(
        target_id="test-rustscan",
        target_host="192.168.1.10",
        ports="80,443,8080",
        output_dir=tmp_path / "rustscan",
        simulate=True,
    )
    assert res["exit_code"] == 0
    assert pathlib.Path(res["raw_path"]).exists()

    schema = SCHEMAS_DIR / "rustscan_result.schema.json"
    parsed = RustscanParser.parse_raw_output(
        raw_path=pathlib.Path(res["raw_path"]),
        scan_metadata=res,
        schema_path=schema,
    )
    assert parsed["scan_metadata"]["tool"] == "rustscan"
    assert 80 in parsed["open_ports"]
    assert 443 in parsed["open_ports"]


def test_whatweb_runner_and_parser(tmp_path):
    res = run_whatweb_scan(
        target_id="test-whatweb",
        target_url="http://192.168.1.10",
        output_dir=tmp_path / "whatweb",
        simulate=True,
    )
    assert res["exit_code"] == 0
    assert pathlib.Path(res["raw_path"]).exists()

    schema = SCHEMAS_DIR / "whatweb_result.schema.json"
    parsed = WhatwebParser.parse_raw_json(
        json_path=pathlib.Path(res["raw_path"]),
        scan_metadata=res,
        schema_path=schema,
    )
    assert parsed["scan_metadata"]["tool"] == "whatweb"
    assert len(parsed["targets"]) >= 1
    tech_names = [t["name"] for t in parsed["targets"][0]["technologies"]]
    assert "Apache" in tech_names


def test_nikto_runner_and_parser(tmp_path):
    res = run_nikto_scan(
        target_id="test-nikto",
        target_url="http://192.168.1.10",
        target_host="192.168.1.10",
        output_dir=tmp_path / "nikto",
        simulate=True,
    )
    assert res["exit_code"] == 0
    assert pathlib.Path(res["raw_path"]).exists()

    schema = SCHEMAS_DIR / "nikto_result.schema.json"
    parsed = NiktoParser.parse_raw_json(
        json_path=pathlib.Path(res["raw_path"]),
        scan_metadata=res,
        schema_path=schema,
    )
    assert parsed["scan_metadata"]["tool"] == "nikto"
    assert len(parsed["items"]) >= 1
    assert "Apache" in parsed["banner"]


def test_gobuster_runner_and_parser(tmp_path):
    res = run_gobuster_scan(
        target_id="test-gobuster",
        target_url="http://192.168.1.10",
        output_dir=tmp_path / "gobuster",
        simulate=True,
    )
    assert res["exit_code"] == 0
    assert pathlib.Path(res["raw_path"]).exists()

    schema = SCHEMAS_DIR / "gobuster_result.schema.json"
    parsed = GobusterParser.parse_raw_output(
        raw_path=pathlib.Path(res["raw_path"]),
        scan_metadata=res,
        schema_path=schema,
    )
    assert parsed["scan_metadata"]["tool"] == "gobuster"
    assert len(parsed["entries"]) >= 1
    paths = [e["path"] for e in parsed["entries"]]
    assert "/login" in paths


def test_ffuf_runner_and_parser(tmp_path):
    res = run_ffuf_scan(
        target_id="test-ffuf",
        target_url="http://192.168.1.10",
        output_dir=tmp_path / "ffuf",
        simulate=True,
    )
    assert res["exit_code"] == 0
    assert pathlib.Path(res["raw_path"]).exists()

    schema = SCHEMAS_DIR / "ffuf_result.schema.json"
    parsed = FfufParser.parse_raw_json(
        json_path=pathlib.Path(res["raw_path"]),
        scan_metadata=res,
        schema_path=schema,
    )
    assert parsed["scan_metadata"]["tool"] == "ffuf"
    assert len(parsed["results"]) >= 1


def test_katana_runner_and_parser(tmp_path):
    res = run_katana_scan(
        target_id="test-katana",
        target_url="http://192.168.1.10",
        output_dir=tmp_path / "katana",
        simulate=True,
    )
    assert res["exit_code"] == 0
    assert pathlib.Path(res["raw_path"]).exists()

    schema = SCHEMAS_DIR / "katana_result.schema.json"
    parsed = KatanaParser.parse_raw_jsonl(
        jsonl_path=pathlib.Path(res["raw_path"]),
        scan_metadata=res,
        schema_path=schema,
    )
    assert parsed["scan_metadata"]["tool"] == "katana"
    assert len(parsed["endpoints"]) >= 1


def test_searchsploit_runner_and_parser(tmp_path):
    res = run_searchsploit_lookup(
        target_id="test-searchsploit",
        query="Apache 2.4.49",
        output_dir=tmp_path / "searchsploit",
        simulate=True,
    )
    assert res["exit_code"] == 0
    assert pathlib.Path(res["raw_path"]).exists()

    schema = SCHEMAS_DIR / "searchsploit_result.schema.json"
    parsed = SearchsploitParser.parse_raw_json(
        json_path=pathlib.Path(res["raw_path"]),
        scan_metadata=res,
        schema_path=schema,
    )
    assert parsed["scan_metadata"]["tool"] == "searchsploit"
    assert len(parsed["results"]) >= 1
    assert any("CVE-2021-41773" in r["cve_ids"] for r in parsed["results"])


def test_service_enum_runners_and_parser(tmp_path):
    for tool_name in ["enum4linux", "smbclient", "snmpwalk", "ldapsearch", "database"]:
        res = run_service_enum_scan(
            target_id="test-enum",
            target_host="192.168.1.10",
            tool_name=tool_name,
            port=445 if "smb" in tool_name or "enum4" in tool_name else 3306,
            output_dir=tmp_path / tool_name,
            simulate=True,
        )
        assert res["exit_code"] == 0
        assert pathlib.Path(res["raw_path"]).exists()

        schema = SCHEMAS_DIR / "service_enum_result.schema.json"
        parsed = ServiceEnumParser.parse_raw_output(
            raw_path=pathlib.Path(res["raw_path"]),
            service_name=tool_name,
            scan_metadata=res,
            schema_path=schema,
        )
        assert parsed["service"] == tool_name
        assert len(parsed["findings"]) >= 1


def test_proxy_manual_workflow(tmp_path):
    res = run_proxy_manual_workflow(
        target_id="test-proxy",
        target_url="http://192.168.1.10:8080",
        tool_name="burpsuite",
        output_dir=tmp_path / "burp",
        simulate=True,
    )
    assert pathlib.Path(res["raw_path"]).exists()
    assert pathlib.Path(res["structured_path"]).exists()
    assert "READY" in res["status"] or "PROXY" in res["status"]


def test_missing_binary_safe_failure(tmp_path, monkeypatch):
    """Section 37 requirement: when a tool is not installed, no fake output is produced in production execution."""
    import shutil
    monkeypatch.delenv("SIMULATE_SCANS", raising=False)
    monkeypatch.setattr(shutil, "which", lambda cmd: None)
    res = run_masscan_scan(
        target_id="test-no-fake",
        target_host="127.0.0.1",
        output_dir=tmp_path / "masscan_fail",
        simulate=False,
    )
    # When binary is missing, returns non-zero and error
    assert res["exit_code"] != 0
    assert "not installed" in (res.get("error") or "")
