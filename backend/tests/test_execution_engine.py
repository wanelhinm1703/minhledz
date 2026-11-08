import sys
import pathlib
import pytest
from backend.app.core.executor import (
    ExecutionEngine,
    ExecutionMode,
    ExecutionBackend,
    ExecutionResult,
)


def test_execution_engine_local_run():
    """Verify local execution runs host commands successfully."""
    engine = ExecutionEngine(default_mode=ExecutionMode.LOCAL)
    res = engine.run_local([sys.executable, "-c", "print('LOCAL_RUN_OK')"])
    assert res.exit_code == 0
    assert "LOCAL_RUN_OK" in res.stdout
    assert res.backend_used == ExecutionBackend.LOCAL
    assert res.duration_seconds >= 0.0


def test_execution_engine_local_missing_binary():
    """Verify missing binary fails cleanly with 127 in LOCAL mode."""
    engine = ExecutionEngine(default_mode=ExecutionMode.LOCAL)
    res = engine.execute(["non_existent_binary_xyz_12345", "--version"])
    assert res.exit_code == 127
    assert res.backend_used == ExecutionBackend.FAILED
    assert "not installed" in (res.error or "").lower() or "not found" in (res.error or "").lower()


def test_container_path_translation():
    """Verify host path is translated to /workspace/ path inside container."""
    engine = ExecutionEngine()
    test_path = engine.project_root / "toolkit" / "03-network" / "scans" / "test.xml"
    container_path = engine.host_to_container_path(str(test_path))
    assert container_path == "/workspace/toolkit/03-network/scans/test.xml"

    cmd = ["nmap", "-oX", str(test_path), "192.168.1.1"]
    translated = engine.translate_cmd_for_container(cmd)
    assert translated[0] == "nmap"
    assert translated[2] == "/workspace/toolkit/03-network/scans/test.xml"
    assert translated[3] == "192.168.1.1"


def test_execution_engine_auto_mode():
    """Verify AUTO mode selects LOCAL when binary is present."""
    engine = ExecutionEngine(default_mode=ExecutionMode.AUTO)
    res = engine.execute([sys.executable, "-c", "print('AUTO_MODE_OK')"])
    assert res.exit_code == 0
    assert "AUTO_MODE_OK" in res.stdout
    assert res.backend_used == ExecutionBackend.LOCAL


def test_execution_engine_docker_fallback_when_unavailable():
    """Verify that when Docker daemon is not running and binary not local, fails with clean diagnostics."""
    engine = ExecutionEngine(default_mode=ExecutionMode.DOCKER)
    # Force mock docker_available to False
    engine._docker_available = False
    res = engine.execute(["testssl.sh", "--version"])
    assert res.exit_code == 127
    assert res.backend_used == ExecutionBackend.FAILED
    assert "docker" in (res.error or "").lower()
