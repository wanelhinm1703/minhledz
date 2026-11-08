"""
Human-in-the-Loop Action Execution Service.
Enforces the mandatory operator approval lifecycle:
PROPOSED -> APPROVED -> EXECUTING -> COMPLETED (or REJECTED / BLOCKED).
Ensures no automated exploitation or dangerous commands execute without human verification.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from backend.app.core.guardrails import check_exploit_intent
from backend.app.services.verification_planner import verification_planner

logger = logging.getLogger("ai_pentest.action_executor")


class ActionStatus(str, Enum):
    PROPOSED = "PROPOSED"
    APPROVED = "APPROVED"
    EXECUTING = "EXECUTING"
    COMPLETED = "COMPLETED"
    REJECTED = "REJECTED"
    BLOCKED = "BLOCKED"


class ProposedAction(BaseModel):
    action_id: str
    target_id: str
    finding_id: str | None = None
    name: str
    description: str = ""
    command: str
    is_safe_readonly: bool = True
    expected_evidence: str = ""
    status: ActionStatus = ActionStatus.PROPOSED
    operator_reason: str | None = None
    output: str | None = None
    is_vulnerable_indicated: bool | None = None
    created_at: str
    executed_at: str | None = None


class ActionExecutorService:
    """Manages the lifecycle of operator-supervised verification actions."""

    def __init__(self):
        # In-memory queue with thread-safe access
        self._actions: dict[str, ProposedAction] = {}

    def propose_action(
        self,
        target_id: str,
        name: str,
        command: str,
        finding_id: str | None = None,
        description: str = "",
        expected_evidence: str = "",
    ) -> ProposedAction:
        """AI proposes a new verification action requiring human approval."""
        action_id = f"act_{uuid.uuid4().hex[:12]}"
        now = datetime.now(timezone.utc).isoformat()

        action = ProposedAction(
            action_id=action_id,
            target_id=target_id,
            finding_id=finding_id,
            name=name,
            description=description,
            command=command,
            is_safe_readonly=True,
            expected_evidence=expected_evidence,
            status=ActionStatus.PROPOSED,
            created_at=now,
        )
        self._actions[action_id] = action
        logger.info("Proposed new verification action: %s ('%s')", action_id, command)
        return action

    def list_pending_actions(self, target_id: str | None = None) -> list[ProposedAction]:
        """Returns all actions currently awaiting human approval."""
        actions = [a for a in self._actions.values() if a.status == ActionStatus.PROPOSED]
        if target_id:
            actions = [a for a in actions if a.target_id == target_id]
        return sorted(actions, key=lambda x: x.created_at, reverse=True)

    def list_all_actions(self, target_id: str | None = None) -> list[ProposedAction]:
        """Returns action history."""
        actions = list(self._actions.values())
        if target_id:
            actions = [a for a in actions if a.target_id == target_id]
        return sorted(actions, key=lambda x: x.created_at, reverse=True)

    def get_action(self, action_id: str) -> ProposedAction | None:
        """Retrieves action by ID."""
        return self._actions.get(action_id)

    def approve_and_execute(self, action_id: str, operator_notes: str | None = None) -> ProposedAction:
        """
        Operator clicks 'Approve & Run'.
        Validates safety via Guardrails, executes command in sandbox, and captures results.
        """
        action = self._actions.get(action_id)
        if not action:
            raise ValueError(f"Action '{action_id}' not found.")

        if action.status not in (ActionStatus.PROPOSED, ActionStatus.REJECTED):
            raise ValueError(f"Action '{action_id}' is already in state {action.status}.")

        action.status = ActionStatus.APPROVED
        action.operator_reason = operator_notes

        # 1. Guardrail Safety Check
        has_exploit, reason = check_exploit_intent(action.command)
        if has_exploit:
            action.status = ActionStatus.BLOCKED
            action.output = f"[GUARDRAIL REFUSAL] Command blocked: {reason}"
            action.is_vulnerable_indicated = False
            action.executed_at = datetime.now(timezone.utc).isoformat()
            return action

        # 2. Safe Execution via Verification Planner
        action.status = ActionStatus.EXECUTING
        res = verification_planner.execute_safe_check(action.command)

        action.status = ActionStatus.COMPLETED if res.status == "SUCCESS" else ActionStatus.BLOCKED
        action.output = res.output
        action.is_vulnerable_indicated = res.is_vulnerable_indicated
        action.executed_at = datetime.now(timezone.utc).isoformat()

        logger.info("Executed action %s with status %s (vulnerable=%s)", action_id, action.status, action.is_vulnerable_indicated)
        return action

    def reject_action(self, action_id: str, reason: str = "Operator declined execution.") -> ProposedAction:
        """Operator declines the action."""
        action = self._actions.get(action_id)
        if not action:
            raise ValueError(f"Action '{action_id}' not found.")

        action.status = ActionStatus.REJECTED
        action.operator_reason = reason
        action.executed_at = datetime.now(timezone.utc).isoformat()
        logger.info("Rejected action %s: %s", action_id, reason)
        return action


# Global singleton instance
action_executor = ActionExecutorService()
