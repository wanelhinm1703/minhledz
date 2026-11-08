"""Tests for Pillar 3: Attack Surface Topology & Knowledge Graph."""

from __future__ import annotations

import pytest
from starlette.testclient import TestClient

from backend.app.main import app
from backend.app.schemas.finding import FindingCreate, FindingSeverity, FindingStatus
from backend.app.schemas.graph import (
    GraphDataResponse,
    GraphEdge,
    GraphNode,
    NodeRiskLevel,
    NodeType,
    RelationType,
)
from backend.app.services.graph_builder import graph_builder
from backend.app.storage.findings_db import findings_db
from backend.app.storage.graph_db import graph_db


@pytest.fixture
def client():
    return TestClient(app)


def test_graph_schemas_and_models():
    """Verify GraphNode and GraphEdge schemas validation."""
    node = GraphNode(
        id="port:target-test:tcp-80",
        target_id="target-test",
        type=NodeType.PORT,
        label="80/tcp",
        risk_level=NodeRiskLevel.HIGH,
        properties={"port": 80, "protocol": "tcp"},
        created_at="2026-09-16T00:00:00Z",
        updated_at="2026-09-16T00:00:00Z",
    )
    assert node.id == "port:target-test:tcp-80"
    assert node.type == NodeType.PORT
    assert node.risk_level == NodeRiskLevel.HIGH

    edge = GraphEdge(
        id="edge:target->port",
        target_id="target-test",
        source="target:target-test",
        target=node.id,
        relation=RelationType.EXPOSES,
        label="open port",
        properties={},
        created_at="2026-09-16T00:00:00Z",
    )
    assert edge.relation == RelationType.EXPOSES
    assert edge.target == node.id


def test_graph_db_storage_and_crud():
    """Verify SQLite storage operations for graph nodes and edges."""
    test_target = "target-test-crud"
    graph_db.clear_target_graph(test_target)

    node1 = GraphNode(
        id=f"target:{test_target}",
        target_id=test_target,
        type=NodeType.TARGET,
        label="Test Target",
        risk_level=NodeRiskLevel.SAFE,
        properties={},
        created_at="2026-09-16T00:00:00Z",
        updated_at="2026-09-16T00:00:00Z",
    )
    node2 = GraphNode(
        id=f"port:{test_target}:tcp-443",
        target_id=test_target,
        type=NodeType.PORT,
        label="443/tcp",
        risk_level=NodeRiskLevel.INFO,
        properties={"port": 443},
        created_at="2026-09-16T00:00:00Z",
        updated_at="2026-09-16T00:00:00Z",
    )
    edge = GraphEdge(
        id=f"edge:{node1.id}->{node2.id}",
        target_id=test_target,
        source=node1.id,
        target=node2.id,
        relation=RelationType.EXPOSES,
        label="exposes",
        properties={},
        created_at="2026-09-16T00:00:00Z",
    )

    graph_db.upsert_node(node1)
    graph_db.upsert_node(node2)
    graph_db.upsert_edge(edge)

    graph = graph_db.get_graph_by_target(test_target)
    assert len(graph.nodes) == 2
    assert len(graph.edges) == 1
    assert graph.stats.total_nodes == 2
    assert graph.stats.by_type.get("port") == 1

    # Neighbors test
    neighbors_data = graph_db.get_node_neighbors(test_target, node1.id)
    assert len(neighbors_data["outgoing_edges"]) == 1
    assert len(neighbors_data["neighbors"]) == 1
    assert neighbors_data["neighbors"][0].id == node2.id

    # Clean up
    deleted = graph_db.clear_target_graph(test_target)
    assert deleted > 0
    empty_graph = graph_db.get_graph_by_target(test_target)
    assert len(empty_graph.nodes) == 0


def test_graph_builder_hierarchy_and_risk_propagation():
    """Verify GraphBuilder builds proper entity hierarchy and propagates risk."""
    test_target = "192.168.56.101"

    # Seed a test finding with CRITICAL severity
    f_id = "TEST-FIND-CRIT-999"
    findings_db.create_finding(
        f_id,
        FindingCreate(
            target_id=test_target,
            title="Apache Critical Remote Code Execution",
            cve_id="CVE-2021-41773",
            cwe_id="CWE-22",
            cvss_score=9.8,
            cvss_severity=FindingSeverity.CRITICAL,
            status=FindingStatus.VERIFIED,
            affected_asset=f"{test_target}:80",
            description="Severe vulnerability on port 80",
            remediation="Patch urgently",
            evidence_chain=[],
            trustworthy=True,
            is_simulated=False,
        ),
    )

    graph = graph_builder.build_graph_for_target(test_target)

    assert graph.target_id == test_target
    assert len(graph.nodes) >= 3  # Target, Port 80, Vulnerability / Finding

    node_types = {n.type for n in graph.nodes}
    assert NodeType.TARGET in node_types
    assert NodeType.PORT in node_types
    assert NodeType.VULNERABILITY in node_types

    # Find port 80 node
    port_80 = next((n for n in graph.nodes if n.type == NodeType.PORT and "80" in n.label), None)
    assert port_80 is not None

    # Risk propagation check: port 80 and target must inherit CRITICAL risk
    assert port_80.risk_level == NodeRiskLevel.CRITICAL

    target_node = next((n for n in graph.nodes if n.type == NodeType.TARGET), None)
    assert target_node is not None
    assert target_node.risk_level == NodeRiskLevel.CRITICAL

    # Check relationships exist
    relations = {e.relation for e in graph.edges}
    assert RelationType.EXPOSES in relations
    assert RelationType.VULNERABLE_TO in relations

    # Clean up test finding
    findings_db.delete_finding(f_id)


def test_topology_api_endpoints(client):
    """Test REST API endpoints for Topology Graph."""
    target_id = "192.168.56.101"

    # POST /api/topology/{target_id}/sync
    res_sync = client.post(f"/api/topology/{target_id}/sync")
    assert res_sync.status_code == 200
    data_sync = res_sync.json()
    assert len(data_sync["nodes"]) > 0
    assert len(data_sync["edges"]) > 0

    # GET /api/topology/{target_id} now matches synced nodes
    res = client.get(f"/api/topology/{target_id}")
    assert res.status_code == 200
    data = res.json()
    assert len(data["nodes"]) == len(data_sync["nodes"])

    # GET /api/topology/{target_id}/node/{node_id}
    first_node_id = data["nodes"][0]["id"]
    res_node = client.get(f"/api/topology/{target_id}/node/{first_node_id}")
    assert res_node.status_code == 200
    node_data = res_node.json()
    assert node_data["node"]["id"] == first_node_id
    assert "neighbors" in node_data


def test_attack_path_and_threat_intel_generation():
    """Verify generation of Attack Paths, Impact nodes, Lateral Movement, and Threat Intel."""
    test_target = "192.168.56.101"
    f_id = "TEST-FIND-ATTACK-PATH-1"
    findings_db.create_finding(
        f_id,
        FindingCreate(
            target_id=test_target,
            title="Apache Path Traversal Vulnerability",
            cve_id="CVE-2021-41773",
            cwe_id="CWE-22",
            cvss_score=9.8,
            cvss_severity=FindingSeverity.CRITICAL,
            status=FindingStatus.VERIFIED,
            affected_asset=f"{test_target}:80",
            description="Arbitrary file read via path traversal in Apache 2.4.49",
            remediation="Upgrade to Apache 2.4.51 or higher immediately.",
            evidence_chain=[],
            trustworthy=True,
            is_simulated=False,
        ),
    )

    try:
        graph = graph_builder.build_graph_for_target(test_target)
        node_types = {n.type for n in graph.nodes}
        assert NodeType.IMPACT in node_types
        assert NodeType.LATERAL_MOVEMENT in node_types

        # Verify Threat Intel on Vulnerability Node
        vuln_node = next((n for n in graph.nodes if "CVE-2021-41773" in n.id), None)
        assert vuln_node is not None
        assert vuln_node.properties.get("is_cisa_kev") is True
        assert vuln_node.properties.get("epss_score") is not None
        assert vuln_node.properties.get("cvss_v4_score") == 8.7

        # Verify Attack Paths
        assert len(graph.attack_paths) > 0
        path = next((p for p in graph.attack_paths if "CVE-2021-41773" in p.title or "CVE-2021-41773" in p.id), None)
        assert path is not None
        assert len(path.steps) >= 3
        assert len(path.node_ids) >= 3
    finally:
        findings_db.delete_finding(f_id)


def test_attack_path_deduplication_and_merging():
    """Verify that multiple CVEs/findings on the same service/port are consolidated into 1 Attack Path with annotations."""
    test_target = "192.168.99.200"
    f1_id = "TEST-FIND-MERGE-1"
    f2_id = "TEST-FIND-MERGE-2"
    f3_id = "TEST-FIND-MERGE-3"

    for f_id, cve, score, sev in [
        (f1_id, "CVE-2021-41773", 9.8, FindingSeverity.CRITICAL),
        (f2_id, "CVE-2021-42013", 9.8, FindingSeverity.CRITICAL),
        (f3_id, "CVE-2021-40438", 7.5, FindingSeverity.HIGH),
    ]:
        findings_db.create_finding(
            f_id,
            FindingCreate(
                target_id=test_target,
                title=f"Apache Exploit {cve}",
                cve_id=cve,
                cvss_score=score,
                cvss_severity=sev,
                status=FindingStatus.VERIFIED,
                affected_asset=f"{test_target}:80",
                description=f"Vulnerability {cve} on Apache HTTPD",
                remediation="Upgrade Apache.",
                evidence_chain=[],
                trustworthy=True,
            ),
        )

    try:
        graph = graph_builder.build_graph_for_target(test_target)
        # All 3 findings on port 80 Apache must be merged into 1 consolidated Attack Path
        assert len(graph.attack_paths) == 1
        path = graph.attack_paths[0]
        assert path.findings_count == 3
        assert "CVE-2021-41773" in path.related_cves
        assert "CVE-2021-42013" in path.related_cves
        assert "Xác minh" in path.title
        assert path.annotation != ""
        assert "3 CVEs" in path.annotation
        assert path.cvss_score == 9.8
        assert path.severity == NodeRiskLevel.CRITICAL

        # Verify Exploitation step has annotation and lists all CVEs
        vuln_step = next((s for s in path.steps if s.phase == "Khai thác lỗ hổng (Exploitation)"), None)
        assert vuln_step is not None
        assert vuln_step.annotation is not None
        assert len(vuln_step.related_cves) == 3
    finally:
        for f_id in [f1_id, f2_id, f3_id]:
            findings_db.delete_finding(f_id)


