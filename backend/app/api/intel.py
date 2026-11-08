"""
REST API Router for Automated Threat Intelligence Feeds.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

from backend.app.services.threat_intel_feed import threat_intel_feed

router = APIRouter(prefix="/intel", tags=["Threat Intelligence Feeds"])


@router.post("/sync", summary="Trigger Automated Threat Intel Synchronization")
def trigger_threat_intel_sync():
    """
    Triggers an on-demand incremental synchronization of CISA KEV,
    updates VectorStore embeddings, and re-indexes SQLite FTS5 BM25.
    """
    try:
        result = threat_intel_feed.run_full_sync()
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Threat intel sync failed: {str(e)}")


@router.get("/status", summary="Get Threat Intel Operational Status")
def get_threat_intel_status():
    """
    Returns threat intel feed health, catalog record counts, and last sync timestamp.
    """
    return threat_intel_feed.get_status()
