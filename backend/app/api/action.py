"""
REST API Router for Human-in-the-Loop Action Execution.
Enforces the Operator Approval Lifecycle:
PROPOSED -> APPROVED -> EXECUTING -> COMPLETED (or REJECTED / BLOCKED).
"""

from __future__ import annotations

from typing import Any
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from backend.app.services.action_executor import (
    action_executor,
    ProposedAction,
    ActionStatus,
)

router = APIRouter(prefix="/action", tags=["Human-in-the-Loop Actions"])


class ProposeActionRequest(BaseModel):
    target_id: str
    name: str
    command: str
    finding_id: str | None = None
    description: str = ""
    expected_evidence: str = ""


class ApproveActionRequest(BaseModel):
    operator_notes: str | None = None


class RejectActionRequest(BaseModel):
    reason: str = "Operator declined execution."


@router.get("/pending", summary="List Pending Verification Actions")
def list_pending_actions(target_id: str | None = Query(default=None)):
    """Returns all proposed actions currently awaiting operator approval."""
    actions = action_executor.list_pending_actions(target_id=target_id)
    return {
        "count": len(actions),
        "actions": actions,
    }


@router.get("/all", summary="List All Actions")
def list_all_actions(target_id: str | None = Query(default=None)):
    """Returns the full history of proposed, approved, executed, and rejected actions."""
    actions = action_executor.list_all_actions(target_id=target_id)
    return {
        "count": len(actions),
        "actions": actions,
    }


@router.get("/{action_id}", summary="Get Action Details")
def get_action(action_id: str):
    """Retrieves specific action details by ID."""
    action = action_executor.get_action(action_id)
    if not action:
        raise HTTPException(status_code=404, detail=f"Action '{action_id}' not found.")
    return action


@router.post("/propose", summary="Propose Verification Action")
def propose_action(req: ProposeActionRequest):
    """Proposes a new verification action requiring operator approval."""
    action = action_executor.propose_action(
        target_id=req.target_id,
        name=req.name,
        command=req.command,
        finding_id=req.finding_id,
        description=req.description,
        expected_evidence=req.expected_evidence,
    )
    return action


@router.post("/approve/{action_id}", summary="Approve & Execute Action")
def approve_action(action_id: str, req: ApproveActionRequest | None = None):
    """
    Operator approves and triggers sandbox execution.
    Guardrail checks are strictly enforced before command execution.
    """
    operator_notes = req.operator_notes if req else None
    try:
        action = action_executor.approve_and_execute(action_id=action_id, operator_notes=operator_notes)
        return action
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Execution error: {str(e)}")


@router.post("/reject/{action_id}", summary="Reject Proposed Action")
def reject_action(action_id: str, req: RejectActionRequest | None = None):
    """Operator declines the execution of the action."""
    reason = req.reason if req else "Operator declined execution."
    try:
        action = action_executor.reject_action(action_id=action_id, reason=reason)
        return action
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
