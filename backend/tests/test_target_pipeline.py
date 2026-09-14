import pathlib
import pytest
from backend.app.schemas.target import TargetType
from backend.app.services.target_parser import TargetParser
from backend.app.services.target_normalizer import TargetNormalizer
from backend.app.services.target_validator import TargetValidator
from backend.app.services.scope_validator import ScopeValidator, ScopeViolation
from backend.app.services.recon_planner import ReconPlanner
from backend.app.services.target_registry import TargetRegistry
from toolkit.scripts.parse_nmap import NmapParser
from toolkit.scripts.run_nmap import run_nmap_scan


def test_target_parser_ipv4():
    p = TargetParser.parse("192.168.56.101")
    assert p.target_type == TargetType.IPV4
    assert p.host == "192.168.56.101"
    assert p.port is None


def test_target_parser_ipv6():
    p = TargetParser.parse("::1")
    assert p.target_type == TargetType.IPV6
    assert p.host == "::1"


def test_target_parser_cidr():
    p = TargetParser.parse("192.168.56.0/24")
    assert p.target_type == TargetType.CIDR
    assert p.host == "192.168.56.0/24"


def test_target_parser_url():
    p = TargetParser.parse("http://192.168.56.101:3000/rest/admin")
    assert p.target_type == TargetType.URL
    assert p.host == "192.168.56.101"
    assert p.port == 3000
    assert p.scheme == "http"
    assert p.path == "/rest/admin"


def test_target_parser_host_port():
    p = TargetParser.parse("10.10.10.20:8080")
    assert p.target_type == TargetType.HOST_PORT
    assert p.host == "10.10.10.20"
    assert p.port == 8080


def test_target_parser_domain():
    p = TargetParser.parse("juice-shop.local")
    assert p.target_type in (TargetType.DOMAIN, TargetType.HOSTNAME)
    assert p.host == "juice-shop.local"


def test_target_normalizer():
    parsed = TargetParser.parse("  http://Example.LOCAL:80/  ")
    norm = TargetNormalizer.normalize(parsed)
    assert norm["host"] == "example.local"
    assert norm["port"] == 80
    assert norm["normalized_value"] == "http://example.local/"


def test_target_validator_invalid_port():
    parsed = TargetParser.parse("10.10.10.10:70000")
    norm = TargetNormalizer.normalize(parsed)
    res = TargetValidator.validate(parsed, norm)
    assert not res.is_valid
    assert any("70000" in e for e in res.errors)


def test_scope_validator_allowed(tmp_path):
    registry = TargetRegistry(storage_dir=tmp_path)
    target = registry.create_from_input("192.168.56.101")
    validator = ScopeValidator()
    decision = validator.validate(target)
    assert decision.allowed is True
    assert "authorized" in decision.reason.lower()


def test_scope_validator_blocked(tmp_path):
    registry = TargetRegistry(storage_dir=tmp_path)
    target = registry.create_from_input("8.8.8.8")
    validator = ScopeValidator()
    decision = validator.validate(target)
    assert decision.allowed is False
    assert "OUT OF SCOPE" in decision.reason


def test_recon_planner_capabilities(tmp_path):
    registry = TargetRegistry(storage_dir=tmp_path)
    url_target = registry.create_from_input("http://192.168.56.101:3000")
    plan = ReconPlanner.plan(url_target)
    assert "web" in plan.capabilities
    assert any(step.tool == "nmap" for step in plan.steps)
    assert any(step.tool == "httpx" for step in plan.steps)


def test_nmap_scan_and_parse(tmp_path):
    scan_dir = tmp_path / "nmap_scan"
    res = run_nmap_scan(
        target_id="test-target",
        target_host="192.168.56.101",
        port=3000,
        output_dir=scan_dir,
        simulate=True,
    )
    assert pathlib.Path(res["raw_xml_path"]).exists()
    assert pathlib.Path(res["normal_txt_path"]).exists()
    assert pathlib.Path(res["commands_log"]).exists()

    schema_file = pathlib.Path(__file__).resolve().parent.parent.parent / "security" / "schemas" / "nmap_result.schema.json"
    parsed = NmapParser.parse_xml_file(
        xml_path=pathlib.Path(res["raw_xml_path"]),
        scan_metadata=res,
        schema_path=schema_file,
    )
    assert parsed["scan_metadata"]["tool"] == "nmap"
    assert len(parsed["hosts"]) == 1
    assert parsed["hosts"][0]["ports"][0]["portid"] == 3000
    assert parsed["hosts"][0]["ports"][0]["service"]["name"] == "http"
