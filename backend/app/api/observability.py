"""API endpoints for LLM Observability, Token Counting, Latency, and Traces."""

from __future__ import annotations

from fastapi import APIRouter
from backend.app.core.observability import (
    ObservabilityStats,
    TraceRecord,
    observability,
)

router = APIRouter(prefix="/observability", tags=["observability"])


@router.get("/stats", response_model=ObservabilityStats)
def get_observability_stats():
    """Returns aggregated token usage, cost, latency, and provider statistics."""
    return observability.get_stats()


@router.get("/traces", response_model=list[TraceRecord])
def get_observability_traces(limit: int = 50):
    """Returns the most recent trace records in reverse chronological order."""
    return observability.get_recent_traces(limit=limit)


@router.post("/clear")
def clear_traces():
    """Clear recorded traces."""
    observability.clear()
    return {"status": "cleared"}
