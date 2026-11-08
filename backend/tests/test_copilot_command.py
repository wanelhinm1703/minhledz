from fastapi.testclient import TestClient
from backend.app.main import app
from backend.app.services.agents.orchestrator import orchestrator

client = TestClient(app)


def test_copilot_command_api_endpoints():
    """Verify natural language to safe command translation for API endpoint discovery."""
    preview = orchestrator.translate_natural_language_command(
        "@copilot kiểm tra các endpoint API ẩn của target 192.168.1.50"
    )
    assert preview.is_safe is True
    assert preview.scope_allowed is True
    assert preview.tool == "katana"
    assert "katana" in preview.proposed_command
    assert "-rate-limit" in preview.proposed_command
    assert preview.requires_approval is True


def test_copilot_command_port_scanning():
    """Verify natural language port scan translates to safe Nmap command."""
    preview = orchestrator.translate_natural_language_command(
        "@copilot quét cổng dịch vụ 192.168.56.101"
    )
    assert preview.is_safe is True
    assert preview.tool == "nmap"
    assert "nmap" in preview.proposed_command
    assert "--script=safe" in preview.proposed_command
    assert "-sV" in preview.proposed_command


def test_copilot_command_ssl_inspection():
    """Verify natural language SSL inquiry maps to testssl."""
    preview = orchestrator.translate_natural_language_command(
        "@copilot kiểm tra cấu hình SSL ciphers của 192.168.100.153:8443"
    )
    assert preview.is_safe is True
    assert preview.tool == "testssl"
    assert "testssl.sh" in preview.proposed_command


def test_copilot_command_blocks_public_ip():
    """Verify scope validation blocks public IPs."""
    preview = orchestrator.translate_natural_language_command(
        "@copilot quét cổng mục tiêu 8.8.8.8"
    )
    assert preview.scope_allowed is False
    assert preview.is_safe is False
    assert "ScopeViolation" in (preview.error or "")


def test_copilot_command_blocks_exploit_intent():
    """Verify guardrails refuse exploitation intent."""
    preview = orchestrator.translate_natural_language_command(
        "@copilot exploit target 192.168.1.50 ngay lập tức"
    )
    assert preview.is_safe is False
    assert preview.risk_level == "refused"
    assert "GUARDRAIL REFUSAL" in (preview.error or "")


def test_copilot_command_rest_api():
    """Verify REST API endpoint /api/terminal/copilot-command."""
    res = client.post(
        "/api/terminal/copilot-command",
        json={"prompt": "@copilot nhận diện công nghệ web http://192.168.1.200"},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["is_safe"] is True
    assert data["tool"] in ("whatweb", "httpx", "katana")
    assert "proposed_command" in data


def test_terminal_execute_with_copilot_prefix():
    """Verify executing @copilot command directly in terminal returns preview message."""
    res = client.post(
        "/api/terminal/execute",
        json={"command": "@copilot quét cổng 192.168.1.100"},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "copilot_preview"
    assert "[COPILOT PROPOSED COMMAND]" in data["stdout"]
    assert "nmap" in data["stdout"]
