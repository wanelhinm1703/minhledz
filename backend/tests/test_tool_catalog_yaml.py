import pytest
from backend.app.services.tool_registry import tool_registry, ToolDefinition, ToolAvailability


def test_yaml_catalog_loading():
    """Verify that the YAML catalog successfully loads all tool definition files."""
    tools = tool_registry.list_tools()
    assert len(tools) >= 22, f"Expected at least 22 tools from YAML catalog, found {len(tools)}"

    # Check key original tools exist
    tool_ids = [t.tool_id for t in tools]
    assert "nmap" in tool_ids
    assert "masscan" in tool_ids
    assert "rustscan" in tool_ids
    assert "httpx" in tool_ids
    assert "nuclei" in tool_ids
    assert "whatweb" in tool_ids
    assert "zap" in tool_ids


def test_new_tools_testssl_and_theharvester():
    """Verify the new tools testssl and theharvester are present and valid in catalog."""
    testssl = tool_registry.get_tool("testssl")
    assert testssl is not None
    assert testssl.name == "TestSSL.sh"
    assert testssl.category == "network"
    assert "ssl_tls_audit" in testssl.capabilities
    assert "ssl" in testssl.tags
    assert testssl.docker is not None
    assert "testssl" in testssl.docker.image

    theharvester = tool_registry.get_tool("theharvester")
    assert theharvester is not None
    assert theharvester.name == "theHarvester"
    assert "osint_recon" in theharvester.capabilities
    assert "osint" in theharvester.tags


def test_tool_filtering_by_category_and_tag():
    """Verify tools can be queried by category and by individual tags."""
    # By category
    web_tools = tool_registry.list_tools(category="web")
    assert len(web_tools) >= 6
    web_ids = [t.tool_id for t in web_tools]
    assert "httpx" in web_ids
    assert "whatweb" in web_ids
    assert "nikto" in web_ids

    # By tag
    crypto_tools = tool_registry.list_tools(tag="crypto")
    assert len(crypto_tools) >= 1
    assert any(t.tool_id == "testssl" for t in crypto_tools)

    port_scan_tools = tool_registry.list_tools(tag="port-scan")
    assert len(port_scan_tools) >= 3
    scan_ids = [t.tool_id for t in port_scan_tools]
    assert "nmap" in scan_ids
    assert "masscan" in scan_ids
    assert "rustscan" in scan_ids


def test_list_tags():
    """Verify list_tags returns comprehensive deduplicated tags."""
    tags = tool_registry.list_tags()
    assert len(tags) >= 20
    assert "network" in tags
    assert "web" in tags
    assert "cve" in tags
    assert "ssl" in tags
    assert "osint" in tags


def test_availability_includes_docker_info():
    """Verify availability status includes docker configuration info."""
    avail = tool_registry.check_availability("nmap")
    assert avail.tool_id == "nmap"
    assert avail.docker_image == "ai-pentest-tools:latest"
    assert len(avail.tags) > 0
