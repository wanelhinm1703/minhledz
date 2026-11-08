from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.services.tool_registry import tool_registry

client = TestClient(app)


def test_tool_registry_definitions():
    """Verify all 18 tools of the original toolset exist in the registry."""
    required_tools = [
        # Network
        "nmap",
        "masscan",
        "rustscan",
        "naabu",
        # Web
        "httpx",
        "whatweb",
        "nikto",
        "gobuster",
        "ffuf",
        "katana",
        # Vulnerability
        "nuclei",
        "nmap-nse",
        "searchsploit",
        # Service Enum
        "enum4linux",
        "smbclient",
        "snmpwalk",
        "ldapsearch",
        "database",
        # Proxy / Manual
        "burpsuite",
        "zap",
    ]
    for tid in required_tools:
        tool_def = tool_registry.get_tool(tid)
        assert tool_def is not None, f"Tool '{tid}' must be registered"
        assert len(tool_def.capabilities) >= 1
        assert tool_def.category in (
            "network",
            "web",
            "vulnerability",
            "service_enum",
            "proxy_manual",
        )


def test_tool_availability_check():
    """Verify availability check correctly identifies Nmap and missing binaries."""
    # Nmap is installed on the testing environment
    nmap_status = tool_registry.check_availability("nmap")
    assert nmap_status.installed is True
    assert nmap_status.binary_path is not None

    # Unknown tool
    unknown_status = tool_registry.check_availability("nonexistent_tool_12345")
    assert unknown_status.installed is False
    assert "not defined" in (unknown_status.error or "")

    # Check that all tools can be queried without crashing
    all_status = tool_registry.get_all_availability()
    assert len(all_status) >= 20
    assert "nmap" in all_status
    assert "masscan" in all_status
    assert "whatweb" in all_status


def test_api_tools_availability_endpoint():
    """Verify /api/scans/tools endpoint returns availability dictionary."""
    res = client.get("/api/scans/tools")
    assert res.status_code == 200
    data = res.json()
    assert "nmap" in data
    assert data["nmap"]["installed"] is True
    assert "masscan" in data
    assert "category" in data["masscan"]
