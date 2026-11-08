"""REST endpoints for Safe Verification Plans."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from backend.app.schemas.verification import (
    ChainExecutionResult,
    ChainVerificationPlan,
    VerificationPlan,
    VerificationResult,
)
from backend.app.services.graph_builder import graph_builder
from backend.app.services.verification_planner import verification_planner
from backend.app.storage.findings_db import findings_db
from backend.app.storage.graph_db import graph_db

router = APIRouter(prefix="/verification", tags=["verification"])


class ExecuteCheckRequest(BaseModel):
    command: str


class ExecuteChainStepRequest(BaseModel):
    chain_id: str
    step_number: int
    command: str


@router.get("/plan/{finding_id}", response_model=VerificationPlan)
def get_verification_plan(finding_id: str):
    finding = findings_db.get_finding(finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail=f"Finding '{finding_id}' not found")
    return verification_planner.generate_plan(finding)


@router.post("/execute", response_model=VerificationResult)
def execute_verification_check(req: ExecuteCheckRequest):
    return verification_planner.execute_safe_check(req.command)


@router.get("/chain-plan/{target_id}/{chain_id:path}", response_model=ChainVerificationPlan)
def get_chain_verification_plan(target_id: str, chain_id: str):
    clean = target_id.replace(":", "-")
    raw = target_id[7:] if target_id.startswith("target-") else target_id
    candidates = list(dict.fromkeys([
        target_id,
        clean,
        f"target-{target_id}",
        f"target-{clean}",
        raw,
        raw.replace(":", "-"),
    ]))

    graph = None
    for cand in candidates:
        g = graph_db.get_graph_by_target(cand)
        if g.nodes and g.attack_paths:
            graph = g
            break

    if not graph or not graph.attack_paths:
        for cand in candidates:
            try:
                g = graph_builder.build_graph_for_target(cand)
                if g.attack_paths:
                    graph = g
                    break
            except Exception:
                pass

    if not graph:
        graph = graph_builder.build_graph_for_target(target_id)

    def norm(s: str) -> str:
        return s.replace("target-", "").replace("path:", "").replace("vuln:", "").replace("finding:", "").strip()

    norm_target = norm(chain_id)
    matching_path = next((p for p in graph.attack_paths if p.id == chain_id), None)
    if not matching_path:
        matching_path = next((p for p in graph.attack_paths if norm(p.id) == norm_target), None)
    if not matching_path:
        matching_path = next((p for p in graph.attack_paths if norm_target in norm(p.id) or norm(p.id) in norm_target), None)
    if not matching_path:
        for p in graph.attack_paths:
            if any(norm(step.node_id) in norm_target or (step.node_label and step.node_label in chain_id) for step in p.steps):
                matching_path = p
                break

    if not matching_path and graph.attack_paths:
        matching_path = graph.attack_paths[0]

    if not matching_path:
        raise HTTPException(status_code=404, detail=f"Attack chain '{chain_id}' not found for target '{target_id}'")

    return verification_planner.generate_chain_plan(matching_path, target_id=target_id)



@router.post("/chain-execute", response_model=ChainExecutionResult)
def execute_chain_step(req: ExecuteChainStepRequest):
    return verification_planner.execute_chain_step(req.chain_id, req.step_number, req.command)

