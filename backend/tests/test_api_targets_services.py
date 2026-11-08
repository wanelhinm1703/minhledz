"""Unit tests for Target Service Discovery and GET /api/targets/{target_id}/services."""

import pytest
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.services.target_service_discovery import (
    discover_target_services,
    normalize_product_name,
)

client = TestClient(app)


def test_normalize_product_name():
    assert normalize_product_name("Apache httpd") == "Apache"
    assert normalize_product_name("OpenSSH 8.2p1") == "OpenSSH"
    assert normalize_product_name("nginx/1.18.0") == "nginx"
    assert normalize_product_name("Node.js (Express)") == "Node.js"
    assert normalize_product_name("MySQL 5.0") == "MySQL"
    assert normalize_product_name("SomethingElse") == "SomethingElse"


def test_discover_services_target_192_168_56_101():
    services = discover_target_services("192.168.56.101")
    assert len(services) > 0
    # Should find Apache on port 80
    apache_svc = next((s for s in services if s["product"] == "Apache"), None)
    assert apache_svc is not None
    assert apache_svc["port"] == 80
    assert apache_svc["version"] == "2.4.49"


def test_discover_services_target_node():
    services = discover_target_services("192.168.56.101-3000")
    assert len(services) > 0
    node_svc = next((s for s in services if s["product"] == "Node.js"), None)
    assert node_svc is not None
    assert node_svc["port"] == 3000
    assert node_svc["version"] == "14.17.0"


def test_api_targets_services_endpoint():
    resp = client.get("/api/targets/192.168.56.101/services")
    assert resp.status_code == 200
    data = resp.json()
    assert data["target_id"] == "192.168.56.101"
    assert data["total"] >= 1
    assert any(s["product"] == "Apache" for s in data["services"])


def test_api_targets_services_with_target_prefix():
    resp = client.get("/api/targets/target-192.168.56.101/services")
    assert resp.status_code == 200
    data = resp.json()
    assert any(s["product"] == "Apache" for s in data["services"])


def test_api_targets_correlate_endpoint():
    resp = client.get("/api/targets/192.168.56.101/correlate?mode=dual")
    assert resp.status_code == 200
    data = resp.json()
    assert data["target_id"] == "192.168.56.101"
    assert data["total_services"] >= 1
    assert data["total_correlated_cves"] > 0


def test_api_vulnerabilities_correlate_target_query_param():
    resp = client.get("/api/vulnerabilities/correlate-target?target_id=192.168.56.101&mode=dual")
    assert resp.status_code == 200
    data = resp.json()
    assert data["target_id"] == "192.168.56.101"
    assert data["total_services"] >= 1

