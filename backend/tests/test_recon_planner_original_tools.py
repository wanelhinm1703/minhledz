import pytest
import pathlib
from backend.app.schemas.target import Target, TargetType
from backend.app.services.recon_planner import ReconPlanner
from backend.app.services.target_registry import TargetRegistry
from backend.app.core.context import ContextEngine
from backend.app.services.findings_builder import findings_builder


def test_service_driven_recon_planning(tmp_path):
    """Verify ReconPlanner suggests SMB, SNMP, LDAP, and DB tools based on detected services."""
    registry = TargetRegistry(storage_dir=tmp_path)
    target = registry.create_from_input("192.168.1.50")

    # 1. SMB detection (port 445)
    detected_smb = [{"port": 445, "service": "microsoft-ds", "product": "Samba", "version": "4.9.5"}]
    plan_smb = ReconPlanner.plan(target, detected_services=detected_smb)
    tools = [s.tool for s in plan_smb.steps]
    assert "enum4linux" in tools
    assert "smbclient" in tools
    assert "searchsploit" in tools  # product and version detected

    # 2. SNMP detection (port 161)
    detected_snmp = [{"port": 161, "service": "snmp"}]
    plan_snmp = ReconPlanner.plan(target, detected_services=detected_snmp)
    tools_snmp = [s.tool for s in plan_snmp.steps]
    assert "snmpwalk" in tools_snmp

    # 3. LDAP detection (port 389)
    detected_ldap = [{"port": 389, "service": "ldap"}]
    plan_ldap = ReconPlanner.plan(target, detected_services=detected_ldap)
    tools_ldap = [s.tool for s in plan_ldap.steps]
    assert "ldapsearch" in tools_ldap

    # 4. Database detection (MySQL on 3306)
    detected_db = [{"port": 3306, "service": "mysql", "product": "MySQL", "version": "8.0"}]
    plan_db = ReconPlanner.plan(target, detected_services=detected_db)
    tools_db = [s.tool for s in plan_db.steps]
    assert "database" in tools_db


def test_explicit_user_tool_selection(tmp_path):
    """Verify that when a user specifically requests a tool, ReconPlanner honors it."""
    registry = TargetRegistry(storage_dir=tmp_path)
    target_net = registry.create_from_input("192.168.1.100")

    plan_masscan = ReconPlanner.plan(target_net, requested_tools=["masscan"])
    assert any(s.tool == "masscan" for s in plan_masscan.steps)

    plan_rustscan = ReconPlanner.plan(target_net, requested_tools=["rustscan"])
    assert any(s.tool == "rustscan" for s in plan_rustscan.steps)

    target_web = registry.create_from_input("http://192.168.1.100:8080")
    plan_web = ReconPlanner.plan(target_web, requested_tools=["whatweb", "nikto", "katana", "ffuf", "gobuster"])
    tools = [s.tool for s in plan_web.steps]
    assert "whatweb" in tools
    assert "nikto" in tools
    assert "katana" in tools
    assert "ffuf" in tools
    assert "gobuster" in tools


def test_tool_conflict_detection():
    """Verify Section 30: detect conflicting versions between Nmap and WhatWeb."""
    scans_with_conflict = [
        {
            "tool": "nmap",
            "ports": [{"port": 80, "service": "http", "product": "Apache httpd", "version": "2.4.49"}],
        },
        {
            "tool": "whatweb",
            "technologies": [{"name": "Apache", "version": "2.4.51"}],
        }
    ]

    conflicts = ContextEngine.detect_conflicts(scans_with_conflict)
    assert len(conflicts) >= 1
    assert "2.4.49" in conflicts[0]
    assert "2.4.51" in conflicts[0]
    assert "discrepancy" in conflicts[0].lower()


def test_findings_builder_extended_tools(tmp_path):
    """Verify FindingsBuilder processes WhatWeb, Nikto, and SearchSploit evidence files."""
    root_dir = tmp_path
    fb = findings_builder
    fb.root_dir = root_dir

    target_id = "192.168.1.200"
    target_dir = root_dir / "toolkit" / "04-web" / "scans" / f"target-{target_id}"
    (target_dir / "whatweb" / "structured").mkdir(parents=True, exist_ok=True)
    (target_dir / "nikto" / "structured").mkdir(parents=True, exist_ok=True)

    # Mock structured WhatWeb file
    whatweb_content = {
        "scan_metadata": {"tool": "whatweb", "target": f"http://{target_id}", "command": "whatweb", "timestamp": "2026-09-15T00:00:00Z", "exit_code": 0},
        "targets": [{"target": f"http://{target_id}", "http_status": 200, "technologies": [{"name": "Apache", "version": "2.4.49"}]}],
    }
    import json
    (target_dir / "whatweb" / "structured" / "whatweb_result.json").write_text(json.dumps(whatweb_content), encoding="utf-8")

    # Mock structured Nikto file
    nikto_content = {
        "scan_metadata": {"tool": "nikto", "target": f"http://{target_id}", "command": "nikto", "timestamp": "2026-09-15T00:00:00Z", "exit_code": 0},
        "host": target_id,
        "port": 80,
        "banner": "Apache/2.4.49",
        "items": [{"id": "001", "osvdb": "0", "method": "GET", "uri": "/", "description": "X-Frame-Options header missing", "severity": "low"}],
    }
    (target_dir / "nikto" / "structured" / "nikto_result.json").write_text(json.dumps(nikto_content), encoding="utf-8")

    findings = fb.generate_findings_for_target(target_id)
    assert len(findings) >= 1
    assert any("WhatWeb" in f.title or "Nikto" in f.title for f in findings)
