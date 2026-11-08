"""
REST API Router for Graph RAG (Knowledge Graph & Attack Path Chaining).
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

from backend.app.services.graph_rag import graph_rag

router = APIRouter(prefix="/graph-rag", tags=["Graph RAG (Attack Chains)"])


@router.get("/chains/{target_id}", summary="Get Knowledge Graph Attack Chains")
def get_attack_chains(target_id: str):
    """
    Returns multi-hop causal attack chains for a target derived from Knowledge Graph relations:
    Asset -> Port/Service -> CVE -> CWE -> MITRE ATT&CK Techniques.
    """
    try:
        chains = graph_rag.get_attack_chains_for_target(target_id)
        return {
            "target_id": target_id,
            "total_chains": len(chains),
            "chains": chains,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate attack chains: {str(e)}")


@router.get("/context/{target_id}", summary="Get Graph RAG LLM Context")
def get_graph_context(target_id: str):
    """
    Returns structured Graph RAG prompt context formatted for LLM reasoning.
    """
    context = graph_rag.get_graph_rag_prompt_context(target_id)
    return {
        "target_id": target_id,
        "context": context,
    }
