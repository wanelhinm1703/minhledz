"""FastAPI REST API router for Attack Surface Topology Graph."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query

from backend.app.schemas.graph import GraphDataResponse
from backend.app.services.graph_builder import graph_builder
from backend.app.storage.graph_db import graph_db

router = APIRouter(prefix="/topology", tags=["topology"])


@router.get("/{target_id}", response_model=GraphDataResponse)
def get_target_topology(target_id: str, auto_build: bool = True):
    """Retrieve the Attack Surface Topology Graph for a target. Auto-builds if empty."""
    graph = graph_db.get_graph_by_target(target_id)
    if not graph.nodes and auto_build:
        graph = graph_builder.build_graph_for_target(target_id)
    return graph


@router.post("/{target_id}/sync", response_model=GraphDataResponse)
def sync_target_topology(target_id: str):
    """Force re-scan artifacts and findings to re-construct the full Topology Graph."""
    try:
        graph = graph_builder.build_graph_for_target(target_id)
        return graph
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to rebuild graph: {str(e)}")


@router.get("/{target_id}/node/{node_id:path}")
def get_node_details(target_id: str, node_id: str):
    """Retrieve deep node metadata, incoming/outgoing edges, and neighbor entities."""
    node = graph_db.get_node(node_id)
    if not node:
        raise HTTPException(status_code=404, detail=f"Node '{node_id}' not found")

    neighbors_info = graph_db.get_node_neighbors(target_id, node_id)
    return {
        "node": node,
        "incoming_edges": neighbors_info.get("incoming_edges", []),
        "outgoing_edges": neighbors_info.get("outgoing_edges", []),
        "neighbors": neighbors_info.get("neighbors", []),
    }
