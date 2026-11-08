from fastapi.testclient import TestClient

from backend.app.main import app

client = TestClient(app)


def test_terminal_presets():
    res = client.get("/api/terminal/presets?target=192.168.100.153")
    assert res.status_code == 200
    data = res.json()
    assert "presets" in data
    assert len(data["presets"]) >= 4
    preset_ids = [p["id"] for p in data["presets"]]
    assert "pipeline_full" in preset_ids
    assert "nmap_fast" in preset_ids


def test_terminal_execute_echo():
    res = client.post("/api/terminal/execute", json={"command": "echo pentest_ok"})
    assert res.status_code == 200
    data = res.json()
    assert data["exit_code"] == 0
    assert "pentest_ok" in data["stdout"]
    assert data["status"] == "completed"


def test_terminal_execute_ls_alias():
    res = client.post("/api/terminal/execute", json={"command": "ls -la"})
    assert res.status_code == 200
    data = res.json()
    assert data["exit_code"] == 0
    assert any(k in data["stdout"] for k in ["Mode", "Length", "total", "drwx", "toolkit", "backend"])


def test_terminal_execute_cd_pwd():
    res = client.post("/api/terminal/execute", json={"command": "cd toolkit"})
    assert res.status_code == 200
    data = res.json()
    assert data["exit_code"] == 0
    assert "toolkit" in data["cwd"]

    res_pwd = client.post("/api/terminal/execute", json={"command": "pwd"})
    assert res_pwd.status_code == 200
    assert "toolkit" in res_pwd.json()["cwd"]

    # Reset back to root
    client.post("/api/terminal/execute", json={"command": "cd .."})


def test_terminal_execute_guardrails():
    # Attempt destructive command
    res = client.post("/api/terminal/execute", json={"command": "rmdir /s /q c:"})
    assert res.status_code == 403
    assert "Guardrail Refusal" in res.json()["detail"]


def test_terminal_execute_clear():
    res = client.post("/api/terminal/execute", json={"command": "clear"})
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "clear"
