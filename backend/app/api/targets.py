from __future__ import annotations

import pathlib

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from backend.app.schemas.target import Target, TargetStatus
from backend.app.services.recon_planner import ReconPlanner
from backend.app.services.scope_validator import ScopeValidator
from backend.app.services.target_normalizer import TargetNormalizer
from backend.app.services.target_parser import TargetParser
from backend.app.services.target_registry import TargetRegistry
from backend.app.services.target_validator import TargetValidator
from backend.app.services.tool_registry import tool_registry

router = APIRouter(prefix="/targets", tags=["targets"])

root_dir = pathlib.Path(__file__).resolve().parent.parent.parent.parent
registry = TargetRegistry(root_dir / "toolkit" / "01-targets" / "registry")


class DetectRequest(BaseModel):
    input: str
    campaign_id: str = "lab-local"


class DetectResponse(BaseModel):
    raw_input: str
    target_type: str
    normalized_value: str
    host: str
    port: int | None = None
    scheme: str | None = None
    is_valid: bool
    syntax_errors: list[str] = Field(default_factory=list)
    scope: dict
    recommended_tools: list[str] = Field(default_factory=list)
    compatible_tools: list[str] = Field(default_factory=list)


class CreateTargetRequest(BaseModel):
    raw_input: str
    campaign_id: str = "lab-local"
    name: str | None = None
    environment: str = "lab"


@router.get("", response_model=list[Target])
def list_targets():
    return registry.list_all()


@router.get("/{target_id}", response_model=Target)
def get_target(target_id: str):
    target = registry.get(target_id)
    if not target:
        raise HTTPException(status_code=404, detail=f"Target '{target_id}' not found.")
    return target


from backend.app.services.target_service_discovery import discover_target_services


@router.get("/{target_id}/services")
def get_target_services(target_id: str):
    """Retrieve discovered open ports, services, and software versions for a target."""
    services = discover_target_services(target_id)
    return {
        "target_id": target_id,
        "total": len(services),
        "services": services,
    }


@router.get("/{target_id}/correlate")
def correlate_target_endpoint(
    target_id: str,
    mode: str | None = Query("dual", description="Threat intel mode: 'dual', 'offline', 'online'"),
    limit_per_service: int = Query(15, ge=1, le=50),
):
    """Retrieve correlated CVE vulnerabilities across all services for a target."""
    from backend.app.api.vulnerabilities import correlate_target_recon_services

    return correlate_target_recon_services(
        target_id=target_id, mode=mode, limit_per_service=limit_per_service
    )




@router.post("/detect", response_model=DetectResponse)
def detect_target(req: DetectRequest):
    try:
        parsed = TargetParser.parse(req.input)
        normalized = TargetNormalizer.normalize(parsed)
        val_res = TargetValidator.validate(parsed, normalized)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

    scope_validator = ScopeValidator()
    # Mock temporary target for scope check
    temp_target = registry.create_from_input(
        raw_input=req.input,
        campaign_id=req.campaign_id,
    )
    decision = scope_validator.validate(temp_target)

    plan = ReconPlanner.plan(temp_target)
    tools = [s.tool for s in plan.steps]
    compatible = tool_registry.list_compatible_tool_ids(parsed.target_type.value)

    return DetectResponse(
        raw_input=req.input,
        target_type=parsed.target_type.value,
        normalized_value=normalized["normalized_value"],
        host=normalized["host"],
        port=normalized["port"],
        scheme=normalized["scheme"],
        is_valid=val_res.is_valid,
        syntax_errors=val_res.errors,
        scope={
            "allowed": decision.allowed,
            "reason": decision.reason,
            "matched_rule": decision.matched_rule,
        },
        recommended_tools=tools,
        compatible_tools=compatible,
    )


@router.post("", response_model=Target)
def create_target(req: CreateTargetRequest):
    try:
        target = registry.create_from_input(
            raw_input=req.raw_input,
            campaign_id=req.campaign_id,
            name=req.name,
            environment=req.environment,
        )
        scope_validator = ScopeValidator()
        decision = scope_validator.validate(target)
        if not decision.allowed:
            target.status = TargetStatus.BLOCKED
            target.scope.is_in_scope = False
            target.scope.scope_rule = decision.reason
            registry._save()
        return target
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


from backend.app.storage.chat_db import chat_db


@router.delete("/{target_id}")
def delete_target(target_id: str):
    success = registry.delete(target_id)
    if not success:
        raise HTTPException(status_code=404, detail=f"Target '{target_id}' not found.")
    chat_db.delete_target_conversations(target_id)
    return {"status": "deleted", "target_id": target_id}
