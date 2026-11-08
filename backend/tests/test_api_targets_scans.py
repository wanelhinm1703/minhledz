from fastapi.testclient import TestClient

from backend.app.main import app

client = TestClient(app)


def test_api_list_targets():
    res = client.get("/api/targets")
    assert res.status_code == 200
    targets = res.json()
    assert isinstance(targets, list)
    assert len(targets) > 0


def test_api_detect_target_allowed():
    res = client.post(
        "/api/targets/detect", json={"input": "http://192.168.56.101:3000"}
    )
    assert res.status_code == 200
    data = res.json()
    assert data["target_type"] == "url"
    assert data["host"] == "192.168.56.101"
    assert data["port"] == 3000
    assert data["scope"]["allowed"] is True
    assert "nmap" in data["recommended_tools"]
    assert "httpx" in data["recommended_tools"]


def test_api_detect_target_blocked():
    res = client.post("/api/targets/detect", json={"input": "8.8.8.8"})
    assert res.status_code == 200
    data = res.json()
    assert data["target_type"] == "ipv4"
    assert data["scope"]["allowed"] is False
    assert "OUT OF SCOPE" in data["scope"]["reason"]


def test_api_list_scans():
    res = client.get("/api/scans")
    assert res.status_code == 200
    scans = res.json()
    assert isinstance(scans, list)
    assert len(scans) > 0
    target_scan = scans[0]
    assert "target_id" in target_scan
    assert "evidence_files" in target_scan


def test_api_get_evidence_file_security():
    # Attempt directory traversal outside toolkit
    res = client.get("/api/scans/file?path=../../etc/passwd")
    assert res.status_code in [403, 404]


def test_api_get_evidence_file_success():
    # Query an existing nmap structured file
    res = client.get(
        "/api/scans/file?path=03-network/scans/target-192.168.56.101/nmap/structured/nmap_result.json"
    )
    if res.status_code == 200:
        data = res.json()
        assert data["is_json"] is True
        assert "nmap" in data["content"]
