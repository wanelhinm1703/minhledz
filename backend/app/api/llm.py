"""REST endpoints for LLM provider status and switching."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from backend.app.services.llm import llm_service

router = APIRouter(tags=["llm"])


class SwitchProviderRequest(BaseModel):
    provider: str
    model: str | None = None


@router.get("/providers")
def get_providers():
    return {
        "active_provider": llm_service.active_provider,
        "active_model": llm_service.active_model,
        "providers": llm_service.get_available_providers(),
    }


@router.post("/switch")
def switch_provider(req: SwitchProviderRequest):
    success = llm_service.switch_provider(req.provider, req.model)
    if not success:
        raise HTTPException(
            status_code=400, detail=f"Invalid or unavailable provider: {req.provider}"
        )
    return {
        "status": "switched",
        "active_provider": llm_service.active_provider,
        "active_model": llm_service.active_model,
    }
