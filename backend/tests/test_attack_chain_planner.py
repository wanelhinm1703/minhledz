"""Comprehensive tests for Attack Chain Verification Planning & Execution."""

import pytest
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.schemas.graph import (
    AttackPath,
    AttackPathStep,
    NodeRiskLevel,
)
from backend.app.schemas.verification import (
    ChainExecutionResult,
    ChainVerificationPlan,
    ChainVerificationStep,
)
from backend.app.services.verification_planner import verification_planner

client = TestClient(app)


@pytest.fixture
def sample_attack_path():
    return AttackPath(
        id="path:192.168.100.153:vuln:apache-cve",
        title="Khai thác CVE-2021-41773 -> Remote Access",
        severity=NodeRiskLevel.HIGH,
        attacker_goal="Kẻ tấn công truy cập tệp tin nhạy cảm và leo thang quyền kiểm soát hệ thống.",
        remediation_summary="Nâng cấp Apache HTTP Server lên phiên bản 2.4.51 trở lên.",
        node_ids=["target:192.168.100.153", "port:192.168.100.153:tcp-80", "vuln:apache-cve", "impact:data-leak"],
        edge_ids=["e1", "e2", "e3"],
        steps=[
            AttackPathStep(
                step_number=1,
                phase="Reconnaissance",
                node_id="port:192.168.100.153:tcp-80",
                title="80/tcp (HTTP)",
                description="Cổng web mở chạy Apache 2.4.49",
            ),
            AttackPathStep(
                step_number=2,
                phase="Exploitation",
                node_id="vuln:apache-cve",
                title="Apache 2.4.49 Path Traversal (CVE-2021-41773)",
                description="Bỏ qua cơ chế chuẩn hóa đường dẫn để đọc tệp tùy ý",
            ),
            AttackPathStep(
                step_number=3,
                phase="Impact & Exposure",
                node_id="impact:data-leak",
                title="Sensitive File Exposure",
                description="Truy cập trái phép tệp cấu hình và mật khẩu",
            ),
        ],
        cvss_score=7.5,
        cve_id="CVE-2021-41773",
        is_cisa_kev=True,
        epss_score=0.92,
        mitigation_steps=[
            "Nâng cấp Apache lên 2.4.51+",
            "Bật WAF rule chặn chuỗi percent-encoded",
        ],
    )


def test_generate_chain_verification_plan(sample_attack_path):
    """Test generating a multi-step safe read-only plan from an attack path."""
    plan = verification_planner.generate_chain_plan(
        sample_attack_path, target_id="192.168.100.153"
    )

    assert isinstance(plan, ChainVerificationPlan)
    assert plan.chain_id == sample_attack_path.id
    assert plan.target_id == "192.168.100.153"
    assert len(plan.steps) == 3

    # Verify each step is strictly safe read-only
    for step in plan.steps:
        assert isinstance(step, ChainVerificationStep)
        assert step.is_safe_readonly is True
        assert "curl" in step.command or "nc" in step.command or "ping" in step.command
        assert step.expected_evidence != ""
        assert step.remediation_check is not None

    # Step 2 should be identified as the choke point
    choke_steps = [s for s in plan.steps if s.break_point_candidate]
    assert len(choke_steps) >= 1
    assert "cắt đứt chuỗi" in plan.break_point_recommendation


def test_execute_chain_step_safe_probe():
    """Test executing benign probe for path traversal with real execution."""
    cmd = "python3 -c \"print('HTTP/1.1 200 OK\\nServer: Apache/2.4.49 (Unix)\\n\\nroot:x:0:0:root:/root:/bin/bash')\""
    result = verification_planner.execute_chain_step(
        chain_id="test-chain",
        step_number=2,
        command=cmd,
    )

    assert isinstance(result, ChainExecutionResult)
    assert result.status == "SUCCESS"
    assert result.is_vulnerable_indicated is True
    assert result.is_chain_broken is False
    assert "tệp nhạy cảm" in result.evidence_found


def test_execute_chain_step_chain_broken():
    """Test executing probe where defense is active and breaks the chain."""
    cmd = "python3 -c \"print('HTTP/1.1 403 Forbidden\\nServer: Apache\\nAccess Denied.')\""
    result = verification_planner.execute_chain_step(
        chain_id="test-chain",
        step_number=2,
        command=cmd,
    )

    assert result.status == "SUCCESS"
    assert result.is_vulnerable_indicated is False
    assert result.is_chain_broken is True
    assert "403 Forbidden" in result.evidence_found


def test_execute_chain_step_real_curl_unreachable():
    """Test real curl execution against non-listening IP breaks chain gracefully."""
    result = verification_planner.execute_chain_step(
        chain_id="test-chain",
        step_number=1,
        command="curl -s -I --connect-timeout 2 http://192.0.2.1:9999/",
    )
    assert result.status == "FAILED"
    assert result.is_chain_broken is True


def test_execute_chain_step_blocked_on_unsafe_command():
    """Test safety guardrails block harmful exploit commands."""
    bad_commands = [
        "curl http://192.168.100.153/ --os-shell",
        "rm -rf /",
        "upload exploit.php",
        "drop table users",
    ]

    for bad_cmd in bad_commands:
        result = verification_planner.execute_chain_step(
            chain_id="test-chain", step_number=1, command=bad_cmd
        )
        assert result.status == "BLOCKED"
        assert "[BLOCKED]" in result.output


def test_api_chain_plan_and_execute(sample_attack_path):
    """Test FastAPI REST endpoints for chain plan retrieval and execution."""
    # 1. Test POST /api/verification/chain-execute
    exec_payload = {
        "chain_id": "test-chain-api",
        "step_number": 1,
        "command": "python3 -c \"print('HTTP/1.1 200 OK\\nServer: Apache/2.4.49')\"",
    }
    resp = client.post("/api/verification/chain-execute", json=exec_payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "SUCCESS"
    assert data["step_number"] == 1
    assert data["is_vulnerable_indicated"] is True

    # 2. Test blocked execution via API
    bad_payload = {
        "chain_id": "test-chain-api",
        "step_number": 2,
        "command": "curl http://test.local/ --os-shell",
    }
    resp_bad = client.post("/api/verification/chain-execute", json=bad_payload)
    assert resp_bad.status_code == 200
    assert resp_bad.json()["status"] == "BLOCKED"


def test_websocket_terminal_real_bash_execution():
    """Test WebSocket terminal executes native bash commands and streams real output."""
    with client.websocket_connect("/ws/terminal") as ws:
        ready = ws.receive_json()
        assert ready["type"] == "ready"
        assert "Kali Linux" in ready["message"] or "PowerShell" in ready["message"] or "Bash" in ready["message"]

        ws.send_json({"type": "execute", "command": "echo 'KALI_TERMINAL_READY'"})
        collected = []
        while True:
            msg = ws.receive_json()
            if msg.get("type") == "stdout":
                collected.append(msg.get("data"))
            if msg.get("type") == "exit":
                assert msg.get("code") == 0
                break
        assert any("KALI_TERMINAL_READY" in line for line in collected)


def test_api_get_chain_plan_prefix_variations():
    """Test chain plan retrieval works with various prefix combinations and doesn't 404."""
    import urllib.parse
    from datetime import datetime, timezone
    from backend.app.schemas.graph import GraphEdge, GraphNode, NodeType, RelationType
    from backend.app.storage.graph_db import graph_db

    now = datetime.now(timezone.utc).isoformat()
    t_id = "test-target-prefix-100"
    n1 = GraphNode(id="target:test", target_id=t_id, type=NodeType.TARGET, label="Target", created_at=now, updated_at=now)
    n2 = GraphNode(id="port:test:80", target_id=t_id, type=NodeType.PORT, label="Port 80", created_at=now, updated_at=now)
    n3 = GraphNode(
        id=f"vuln:target-{t_id}:CVE-9999-0001",
        target_id=t_id,
        type=NodeType.VULNERABILITY,
        label="CVE-9999-0001",
        properties={"cve_id": "CVE-9999-0001"},
        created_at=now,
        updated_at=now,
    )
    n4 = GraphNode(id="impact:test:rce", target_id=t_id, type=NodeType.IMPACT, label="Impact RCE", created_at=now, updated_at=now)
    e1 = GraphEdge(id="e1", target_id=t_id, source=n1.id, target=n2.id, relation=RelationType.EXPOSES, created_at=now)
    e2 = GraphEdge(id="e2", target_id=t_id, source=n2.id, target=n3.id, relation=RelationType.VULNERABLE_TO, created_at=now)
    e3 = GraphEdge(id="e3", target_id=t_id, source=n3.id, target=n4.id, relation=RelationType.LEADS_TO, created_at=now)
    graph_db.bulk_save(t_id, [n1, n2, n3, n4], [e1, e2, e3])

    chain_id = f"path:target-{t_id}:vuln:target-{t_id}:CVE-9999-0001"
    quoted = urllib.parse.quote(chain_id, safe="")

    # 1. Raw target_id
    resp1 = client.get(f"/api/verification/chain-plan/{t_id}/{quoted}")
    assert resp1.status_code == 200
    plan1 = resp1.json()
    assert len(plan1["steps"]) >= 2

    # 2. Prefixed target_id (target-...)
    resp2 = client.get(f"/api/verification/chain-plan/target-{t_id}/{quoted}")
    assert resp2.status_code == 200
    plan2 = resp2.json()
    assert len(plan2["steps"]) >= 2

