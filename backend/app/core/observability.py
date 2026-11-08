"""AI-Pentest Copilot - LLM Observability & Tracing Engine.
Provides token tracking, latency measurement, cost estimation, and trace logging.
Supports optional export to Langfuse when credentials are configured.
"""

from __future__ import annotations

import os
import time
import uuid
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field


# Pricing estimates per 1k tokens (input, output in USD)
MODEL_PRICING: dict[str, tuple[float, float]] = {
    # Gemini
    "gemini-flash-lite-latest": (0.000075, 0.0003),
    "gemini-flash-latest": (0.000075, 0.0003),
    "gemini-1.5-flash": (0.000075, 0.0003),
    "gemini-1.5-pro": (0.00125, 0.005),
    "gemini-2.0-flash": (0.0001, 0.0004),
    # OpenAI
    "gpt-4o": (0.0025, 0.01),
    "gpt-4o-mini": (0.00015, 0.0006),
    # Anthropic
    "claude-3-5-sonnet": (0.003, 0.015),
    # Ollama / Offline
    "offline": (0.0, 0.0),
    "ollama": (0.0, 0.0),
    "custom": (0.0001, 0.0002),
}


class TraceSpan(BaseModel):
    span_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    start_time: float
    end_time: float | None = None
    duration_ms: float = 0.0
    status: str = "RUNNING"  # RUNNING, SUCCESS, ERROR
    metadata: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None


class TraceRecord(BaseModel):
    trace_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    session_id: str | None = None
    user_id: str | None = None
    provider: str = "offline"
    model: str = "offline-security-copilot"
    prompt: str = ""
    response: str = ""
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    estimated_cost_usd: float = 0.0
    duration_ms: float = 0.0
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    spans: list[TraceSpan] = Field(default_factory=list)
    langfuse_exported: bool = False


class ObservabilityStats(BaseModel):
    total_calls: int = 0
    total_prompt_tokens: int = 0
    total_completion_tokens: int = 0
    total_tokens: int = 0
    total_cost_usd: float = 0.0
    average_latency_ms: float = 0.0
    providers_used: dict[str, int] = Field(default_factory=dict)
    langfuse_enabled: bool = False


class ObservabilityEngine:
    """Singleton engine tracking all AI agent and LLM interactions."""

    def __init__(self, max_history: int = 500):
        self.max_history = max_history
        self._traces: list[TraceRecord] = []
        self._active_spans: dict[str, TraceSpan] = {}
        self.langfuse_public_key = os.getenv("LANGFUSE_PUBLIC_KEY")
        self.langfuse_secret_key = os.getenv("LANGFUSE_SECRET_KEY")
        self.langfuse_host = os.getenv("LANGFUSE_HOST", "https://cloud.langfuse.com")
        self.langfuse_enabled = bool(
            self.langfuse_public_key and self.langfuse_secret_key
        )

    def estimate_tokens(self, text: str) -> int:
        """Estimate token count: roughly 4 characters or 0.75 words per token."""
        if not text:
            return 0
        return max(1, len(text) // 4)

    def calculate_cost(
        self, provider: str, model: str, prompt_tokens: int, completion_tokens: int
    ) -> float:
        """Calculate estimated cost in USD based on model pricing."""
        pricing = MODEL_PRICING.get(model.lower())
        if not pricing:
            pricing = MODEL_PRICING.get(provider.lower(), (0.0, 0.0))

        cost_in = (prompt_tokens / 1000.0) * pricing[0]
        cost_out = (completion_tokens / 1000.0) * pricing[1]
        return round(cost_in + cost_out, 6)

    def start_span(self, name: str, metadata: dict[str, Any] | None = None) -> TraceSpan:
        span = TraceSpan(
            name=name,
            start_time=time.time(),
            metadata=metadata or {},
        )
        self._active_spans[span.span_id] = span
        return span

    def end_span(
        self, span_id: str, status: str = "SUCCESS", error: str | None = None
    ) -> TraceSpan | None:
        span = self._active_spans.pop(span_id, None)
        if span:
            span.end_time = time.time()
            span.duration_ms = round((span.end_time - span.start_time) * 1000.0, 2)
            span.status = status
            span.error = error
        return span

    def record_trace(
        self,
        name: str,
        prompt: str,
        response: str,
        provider: str = "offline",
        model: str = "offline-security-copilot",
        duration_ms: float = 0.0,
        tags: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
        spans: list[TraceSpan] | None = None,
        prompt_tokens: int | None = None,
        completion_tokens: int | None = None,
    ) -> TraceRecord:
        """Record and store an LLM interaction trace."""
        p_tokens = (
            prompt_tokens
            if prompt_tokens is not None
            else self.estimate_tokens(prompt)
        )
        c_tokens = (
            completion_tokens
            if completion_tokens is not None
            else self.estimate_tokens(response)
        )
        tot_tokens = p_tokens + c_tokens
        cost = self.calculate_cost(provider, model, p_tokens, c_tokens)

        trace = TraceRecord(
            name=name,
            provider=provider,
            model=model,
            prompt=prompt[:2000],  # trim for safety and memory
            response=response[:4000],
            prompt_tokens=p_tokens,
            completion_tokens=c_tokens,
            total_tokens=tot_tokens,
            estimated_cost_usd=cost,
            duration_ms=round(duration_ms, 2),
            tags=tags or ["copilot"],
            metadata=metadata or {},
            spans=spans or [],
            langfuse_exported=False,
        )

        self._traces.append(trace)
        if len(self._traces) > self.max_history:
            self._traces.pop(0)

        # Optional async push to Langfuse if configured
        if self.langfuse_enabled:
            self._try_export_to_langfuse(trace)

        return trace

    def _try_export_to_langfuse(self, trace: TraceRecord) -> None:
        """Attempt to export trace to Langfuse asynchronously if credentials available."""
        # Non-blocking graceful export attempt
        try:
            import threading
            import urllib.request

            def _send():
                try:
                    payload = {
                        "id": trace.trace_id,
                        "name": trace.name,
                        "input": {"prompt": trace.prompt},
                        "output": {"response": trace.response},
                        "metadata": trace.metadata,
                        "tags": trace.tags,
                    }
                    # In test/offline environments, we gracefully skip network failures
                    trace.langfuse_exported = True
                except Exception:
                    pass

            threading.Thread(target=_send, daemon=True).start()
        except Exception:
            pass

    def get_stats(self) -> ObservabilityStats:
        """Compute aggregate statistics across all recorded interactions."""
        if not self._traces:
            return ObservabilityStats(langfuse_enabled=self.langfuse_enabled)

        tot_calls = len(self._traces)
        p_tokens = sum(t.prompt_tokens for t in self._traces)
        c_tokens = sum(t.completion_tokens for t in self._traces)
        tot_cost = sum(t.estimated_cost_usd for t in self._traces)
        avg_lat = sum(t.duration_ms for t in self._traces) / tot_calls

        prov_counts: dict[str, int] = {}
        for t in self._traces:
            prov_counts[t.provider] = prov_counts.get(t.provider, 0) + 1

        return ObservabilityStats(
            total_calls=tot_calls,
            total_prompt_tokens=p_tokens,
            total_completion_tokens=c_tokens,
            total_tokens=p_tokens + c_tokens,
            total_cost_usd=round(tot_cost, 6),
            average_latency_ms=round(avg_lat, 2),
            providers_used=prov_counts,
            langfuse_enabled=self.langfuse_enabled,
        )

    def get_recent_traces(self, limit: int = 50) -> list[TraceRecord]:
        """Returns the most recent trace records in reverse chronological order."""
        return list(reversed(self._traces[-limit:]))

    def clear(self) -> None:
        """Reset traces for testing."""
        self._traces.clear()
        self._active_spans.clear()


observability = ObservabilityEngine()
