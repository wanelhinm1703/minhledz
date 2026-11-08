"""Comprehensive tests for Evidence-Driven Attack Plan, Decision Points, Choke Points & Remediation."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.schemas.attack_plan import (
    AttackPlan,
    AttackPlanState,
    DecisionResult,
    NextDecision,
)
from backend.app.schemas.finding import FindingCreate, FindingSeverity, FindingStatus
from backend.app.schemas.graph import GraphEdge, GraphNode, NodeRiskLevel, NodeType, RelationType
from backend.app.services.attack_plan_service import attack_plan_service
from backend.app.storage.findings_db import findings_db
from backend.app.storage.graph_db import graph_db

client = TestClient(app)


@pytest.fixture
def sample_test_target():
    t_id = "192.168.100.153"
    graph_db.clear_target_graph(t_id)

    # Nodes: Target -> Port 80 -> Service Apache -> Vuln Apache -> Impact Data Leak
    n1 = GraphNode(
        id=f"target:{t_id}",
        target_id=t_id,
        type=NodeType.TARGET,
        label=t_id,
        risk_level=NodeRiskLevel.SAFE,
        properties={"target_id": t_id},
        created_at="2026-09-20T00:00:00Z",
        updated_at="2026-09-20T00:00:00Z",
    )
    n2 = GraphNode(
        id=f"port:{t_id}:tcp-80",
        target_id=t_id,
        type=NodeType.PORT,
        label="80/tcp",
        risk_level=NodeRiskLevel.HIGH,
        properties={"port": 80, "protocol": "tcp"},
        created_at="2026-09-20T00:00:00Z",
        updated_at="2026-09-20T00:00:00Z",
    )
    n3 = GraphNode(
        id=f"svc:{t_id}:tcp-80:http",
        target_id=t_id,
        type=NodeType.SERVICE,
        label="Apache 2.4.49",
        risk_level=NodeRiskLevel.HIGH,
        properties={"service": "http", "version": "2.4.49", "port": 80},
        created_at="2026-09-20T00:00:00Z",
        updated_at="2026-09-20T00:00:00Z",
    )
    n4 = GraphNode(
        id=f"vuln:{t_id}:CVE-2021-41773",
        target_id=t_id,
        type=NodeType.VULNERABILITY,
        label="Apache 2.4.49 Path Traversal (CVE-2021-41773)",
        risk_level=NodeRiskLevel.CRITICAL,
        properties={"cve_id": "CVE-2021-41773", "cvss_score": 7.5, "is_cisa_kev": True},
        created_at="2026-09-20T00:00:00Z",
        updated_at="2026-09-20T00:00:00Z",
    )
    n5 = GraphNode(
        id=f"impact:{t_id}:CVE-2021-41773",
        target_id=t_id,
        type=NodeType.IMPACT,
        label="Sensitive File Disclosure",
        risk_level=NodeRiskLevel.HIGH,
        properties={"description": "Arbitrary file reading"},
        created_at="2026-09-20T00:00:00Z",
        updated_at="2026-09-20T00:00:00Z",
    )

    e1 = GraphEdge(id="e1", target_id=t_id, source=n1.id, target=n2.id, relation=RelationType.EXPOSES, created_at="2026-09-20T00:00:00Z")
    e2 = GraphEdge(id="e2", target_id=t_id, source=n2.id, target=n3.id, relation=RelationType.RUNS_SERVICE, created_at="2026-09-20T00:00:00Z")
    e3 = GraphEdge(id="e3", target_id=t_id, source=n3.id, target=n4.id, relation=RelationType.VULNERABLE_TO, created_at="2026-09-20T00:00:00Z")
    e4 = GraphEdge(id="e4", target_id=t_id, source=n4.id, target=n5.id, relation=RelationType.LEADS_TO, created_at="2026-09-20T00:00:00Z")

    graph_db.bulk_save(t_id, [n1, n2, n3, n4, n5], [e1, e2, e3, e4])

    # Also register finding
    findings_db.create_finding(
        f"FIND-{t_id}-TEST",
        FindingCreate(
            target_id=t_id,
            title="Apache HTTP Server Path Traversal",
            cve_id="CVE-2021-41773",
            cvss_score=7.5,
            cvss_severity=FindingSeverity.HIGH,
            status=FindingStatus.APPLICABLE,
            affected_asset=f"{t_id}:80",
            description="Path traversal in Apache 2.4.49",
            evidence_chain=[],
            trustworthy=True,
        ),
    )
    return t_id


def test_generate_attack_plan(sample_test_target):
    """Test generating a structured Attack Plan with all core sections."""
    plan = attack_plan_service.generate_attack_plan(sample_test_target)

    assert isinstance(plan, AttackPlan)
    assert plan.target_id == sample_test_target
    assert "Kế hoạch kiểm thử" in plan.objective
    assert len(plan.preconditions) >= 3
    assert len(plan.decision_points) >= 4
    assert len(plan.attack_paths) >= 1

    # Check attack path properties
    path = plan.attack_paths[0]
    assert path.cve_id == "CVE-2021-41773"
    assert path.is_severed is False
    assert path.explainability is not None
    assert path.explainability["target_reachable"] is True

    # Check choke points identified
    assert len(plan.choke_points) >= 1
    top_choke = plan.choke_points[0]
    assert top_choke.affected_paths_count >= 1
    assert "cắt đứt" in top_choke.reason or "Khắc phục" in top_choke.reason


def test_decision_points_logic(sample_test_target):
    """Test decision points evaluate conditions correctly."""
    plan = attack_plan_service.generate_attack_plan(sample_test_target)
    dp_map = {dp.id: dp for dp in plan.decision_points}

    assert "dp-01-reachability" in dp_map
    assert dp_map["dp-01-reachability"].result == DecisionResult.PASSED
    assert "dp-03-cve-applicability" in dp_map
    assert dp_map["dp-03-cve-applicability"].result == DecisionResult.PASSED


def test_toggle_remediation_and_severance(sample_test_target):
    """Test remediating a choke point node cuts the attack path and updates graph state."""
    # 1. Remediate port 80
    choke_node_id = f"port:{sample_test_target}:tcp-80"
    impact = attack_plan_service.toggle_remediation_node(sample_test_target, choke_node_id)

    assert impact.remediated_node_id == choke_node_id
    assert len(impact.severed_path_ids) >= 1
    assert impact.risk_reduction_percent == 100.0

    # 2. Check updated plan reflects severed state
    updated_plan = attack_plan_service.generate_attack_plan(sample_test_target)
    assert updated_plan.severed_paths_count >= 1
    assert updated_plan.active_paths_count == 0
    assert updated_plan.state == AttackPlanState.SEVERED
    for p in updated_plan.attack_paths:
        assert p.is_severed is True
        assert p.severed_by_node == choke_node_id

    # 3. Toggle back to restore
    impact_restored = attack_plan_service.toggle_remediation_node(sample_test_target, choke_node_id)
    assert len(impact_restored.severed_path_ids) == 0
    plan_restored = attack_plan_service.generate_attack_plan(sample_test_target)
    assert plan_restored.active_paths_count >= 1
    assert plan_restored.attack_paths[0].is_severed is False


def test_execute_verification_probe_benign(sample_test_target):
    """Test executing a verification probe captures actual output and updates decision state."""
    cmd = "python3 -c \"print('HTTP/1.1 200 OK\\nServer: Apache/2.4.49\\n\\nroot:x:0:0:root:/root:/bin/bash')\""
    res = attack_plan_service.execute_verification_probe(
        target_id=sample_test_target,
        step_number=2,
        command=cmd,
    )

    assert "result" in res
    assert "updated_plan" in res
    probe_res = res["result"]
    assert probe_res["status"] == "SUCCESS"
    assert probe_res["is_vulnerable_indicated"] is True
    assert "root:x:0:0" in probe_res["output"]


def test_api_attack_plan_endpoints(sample_test_target):
    """Test REST endpoints for /api/attack-plan."""
    # 1. GET /api/attack-plan/{target_id}
    resp = client.get(f"/api/attack-plan/{sample_test_target}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["target_id"] == sample_test_target
    assert len(data["attack_paths"]) >= 1
    assert len(data["choke_points"]) >= 1

    # 2. POST /api/attack-plan/{target_id}/verify-step
    exec_payload = {
        "step_number": 1,
        "command": "python3 -c \"print('HTTP/1.1 200 OK\\nServer: Apache/2.4.49')\"",
    }
    resp_exec = client.post(f"/api/attack-plan/{sample_test_target}/verify-step", json=exec_payload)
    assert resp_exec.status_code == 200
    exec_data = resp_exec.json()
    assert exec_data["result"]["status"] == "SUCCESS"

    # 3. POST /api/attack-plan/{target_id}/remediate-node
    rem_payload = {"node_id": f"port:{sample_test_target}:tcp-80"}
    resp_rem = client.post(f"/api/attack-plan/{sample_test_target}/remediate-node", json=rem_payload)
    assert resp_rem.status_code == 200
    rem_data = resp_rem.json()
    assert rem_data["risk_reduction_percent"] == 100.0

    # 4. POST /api/attack-plan/{target_id}/rescan
    resp_rescan = client.post(f"/api/attack-plan/{sample_test_target}/rescan")
    assert resp_rescan.status_code == 200
    rescan_data = resp_rescan.json()
    assert rescan_data["target_id"] == sample_test_target
