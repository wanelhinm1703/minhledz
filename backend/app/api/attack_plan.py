"""REST API Router for Evidence-Driven Attack Plan & Graph Analysis."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from backend.app.schemas.attack_plan import AttackPlan, RemediationImpact
from backend.app.services.attack_plan_service import attack_plan_service

router = APIRouter(prefix="/attack-plan", tags=["attack-plan"])


class VerifyStepRequest(BaseModel):
    step_number: int
    command: str


class RemediateNodeRequest(BaseModel):
    node_id: str


@router.get("/{target_id}", response_model=AttackPlan)
def get_attack_plan(target_id: str):
    """Retrieve the Evidence-Driven Attack Plan for a target."""
    try:
        return attack_plan_service.generate_attack_plan(target_id)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate attack plan: {str(e)}")


@router.post("/{target_id}/verify-step")
def verify_step(target_id: str, req: VerifyStepRequest):
    """Execute a strictly safe, read-only verification probe and update evidence."""
    try:
        return attack_plan_service.execute_verification_probe(
            target_id=target_id,
            step_number=req.step_number,
            command=req.command,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Probe execution failed: {str(e)}")


@router.post("/{target_id}/remediate-node", response_model=RemediationImpact)
def remediate_node(target_id: str, req: RemediateNodeRequest):
    """Mark a node as remediated/isolated or restore it, calculating severed attack paths."""
    try:
        return attack_plan_service.toggle_remediation_node(
            target_id=target_id,
            node_id=req.node_id,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to toggle remediation: {str(e)}")


@router.post("/{target_id}/rescan", response_model=AttackPlan)
def rescan_target(target_id: str):
    """Re-scan and re-evaluate attack graph, updating all paths and decision points."""
    try:
        return attack_plan_service.rescan_target(target_id)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to rescan target: {str(e)}")
