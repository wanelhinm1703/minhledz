"""
REST API Router for Vector Database (ChromaDB / Persistent Vector Engine).
Provides endpoints for semantic vector search, custom document ingestion,
and automated synchronization with SQLite KB.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from backend.app.services.fts5_search import fts5_search
from backend.app.services.vector_store import vector_store

router = APIRouter(prefix="/vector", tags=["Vector Database (ChromaDB / RAG)"])


class VectorSearchRequest(BaseModel):
    query: str = Field(..., description="Search query or security symptom description")
    collection_name: str = Field(default="cve_knowledge", description="Target collection name")
    top_k: int = Field(default=5, ge=1, le=50, description="Number of results to retrieve")
    filter_metadata: dict[str, Any] | None = Field(default=None, description="Optional metadata filter")


class VectorIngestRequest(BaseModel):
    collection_name: str = Field(default="custom_knowledge", description="Target collection")
    doc_id: str = Field(..., description="Unique document ID (e.g. writeup_01, cve_custom)")
    content: str = Field(..., description="Document text content to embed")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Metadata key-values")


@router.post("/search", summary="Perform Semantic Vector Search")
def search_vectors(payload: VectorSearchRequest):
    """
    Computes vector embedding for the query and executes Cosine Similarity search.
    Returns Top-K matching security documents with similarity scores.
    """
    try:
        results = vector_store.search(
            collection_name=payload.collection_name,
            query=payload.query,
            top_k=payload.top_k,
            filter_metadata=payload.filter_metadata,
        )
        return {
            "query": payload.query,
            "collection": payload.collection_name,
            "count": len(results),
            "results": results,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Vector search failed: {str(e)}")


@router.post("/ingest", summary="Ingest Document into Vector Database")
def ingest_document(payload: VectorIngestRequest):
    """
    Ingests a custom pentest document, writeup, or knowledge snippet.
    Embeds text into vector space and persists it to disk.
    """
    try:
        vector_store.add_document(
            collection_name=payload.collection_name,
            doc_id=payload.doc_id,
            content=payload.content,
            metadata=payload.metadata,
        )
        return {
            "status": "success",
            "message": f"Document '{payload.doc_id}' successfully ingested and embedded into '{payload.collection_name}'.",
            "doc_id": payload.doc_id,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Ingestion failed: {str(e)}")


@router.post("/sync-from-sqlite", summary="Synchronize SQLite Knowledge to Vector Store & FTS5")
def sync_knowledge_base():
    """
    Transfers all 539 CVEs and 52 CWEs from kb.sqlite into the Vector Store,
    computes embeddings, and rebuilds the SQLite FTS5 BM25 index.
    """
    try:
        vec_stats = vector_store.sync_from_sqlite()
        fts_stats = fts5_search.rebuild_index()
        return {
            "status": "success",
            "vector_store_synced": vec_stats,
            "fts5_rebuilt": fts_stats,
            "total_vectors": vector_store.get_stats()["total_vectors"],
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Sync failed: {str(e)}")


@router.get("/stats", summary="Get Vector Database Statistics")
def get_vector_stats():
    """
    Returns engine type, storage directory, and vector count per collection.
    """
    return vector_store.get_stats()


@router.delete("/clear", summary="Clear Vector Collection")
def clear_vectors(collection_name: str | None = None):
    """
    Clears specified collection or entire vector store.
    """
    vector_store.clear(collection_name=collection_name)
    return {
        "status": "cleared",
        "collection": collection_name or "ALL_COLLECTIONS",
    }
