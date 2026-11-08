import pytest
from fastapi.testclient import TestClient
from backend.app.main import app
from backend.app.core.observability import observability

client = TestClient(app)


def setup_function():
    """Clear traces before each test."""
    observability.clear()


def test_observability_record_and_stats():
    """Verify trace recording, token estimation, cost calculation, and stats aggregation."""
    trace = observability.record_trace(
        name="test_prompt",
        prompt="Hello security copilot, what are the open ports?",
        response="Based on scan results, ports 80 and 443 are open.",
        provider="gemini",
        model="gemini-flash-lite-latest",
        duration_ms=250.5,
        tags=["unit_test"],
    )

    assert trace.trace_id is not None
    assert trace.prompt_tokens > 0
    assert trace.completion_tokens > 0
    assert trace.total_tokens == trace.prompt_tokens + trace.completion_tokens
    assert trace.estimated_cost_usd >= 0.0
    assert trace.duration_ms == 250.5

    stats = observability.get_stats()
    assert stats.total_calls == 1
    assert stats.total_tokens == trace.total_tokens
    assert stats.providers_used.get("gemini") == 1
    assert stats.average_latency_ms == 250.5


def test_observability_span_lifecycle():
    """Verify span tracking lifecycle."""
    span = observability.start_span("agent_execution", metadata={"task": "recon"})
    assert span.span_id is not None
    assert span.status == "RUNNING"

    ended = observability.end_span(span.span_id, status="SUCCESS")
    assert ended is not None
    assert ended.status == "SUCCESS"
    assert ended.duration_ms >= 0.0


def test_observability_rest_apis():
    """Verify /api/observability/stats and /api/observability/traces endpoints."""
    # Seed a trace
    observability.record_trace(
        name="api_test_trace",
        prompt="Sample audit prompt",
        response="Sample audit response",
        provider="openai",
        model="gpt-4o-mini",
        duration_ms=120.0,
    )

    # 1. Stats endpoint
    res_stats = client.get("/api/observability/stats")
    assert res_stats.status_code == 200
    stats_data = res_stats.json()
    assert stats_data["total_calls"] >= 1
    assert "openai" in stats_data["providers_used"]

    # 2. Traces endpoint
    res_traces = client.get("/api/observability/traces")
    assert res_traces.status_code == 200
    traces_data = res_traces.json()
    assert len(traces_data) >= 1
    assert traces_data[0]["name"] == "api_test_trace"
    assert traces_data[0]["provider"] == "openai"

    # 3. Clear endpoint
    res_clear = client.post("/api/observability/clear")
    assert res_clear.status_code == 200
    assert client.get("/api/observability/stats").json()["total_calls"] == 0
