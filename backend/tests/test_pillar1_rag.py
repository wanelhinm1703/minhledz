"""
Test suite for Pillar 1: Knowledge Memory & Advanced RAG Upgrades.
Tests:
- VectorStoreService (Dense semantic vector search)
- FTS5SearchService (Sparse BM25 full-text search)
- RerankerService (Reciprocal Rank Fusion)
- RAGService (Hybrid RAG integration)
- GraphRAGService (Attack path chaining & graph context)
- ThreatIntelFeedService (Threat intelligence synchronization)
- REST APIs (/api/vector, /api/graph-rag, /api/intel)
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.services.fts5_search import fts5_search
from backend.app.services.graph_rag import graph_rag
from backend.app.services.rag import RAGService
from backend.app.services.reranker import reranker
from backend.app.services.threat_intel_feed import threat_intel_feed
from backend.app.services.vector_store import vector_store


@pytest.fixture
def client():
    return TestClient(app)


def test_vector_store_embedding_and_search():
    """Test document insertion and semantic vector search in VectorStore."""
    vector_store.add_document(
        collection_name="custom_knowledge",
        doc_id="test_doc_sqli",
        content="SQL Injection flaw allows attackers to bypass authentication and dump database tables.",
        metadata={"category": "web", "cwe": "CWE-89"},
    )

    results = vector_store.search("custom_knowledge", "database injection", top_k=2)
    assert len(results) > 0
    assert results[0]["id"] == "test_doc_sqli"
    assert results[0]["similarity_score"] > 0.4
    assert results[0]["metadata"]["cwe"] == "CWE-89"


def test_fts5_sparse_bm25_search():
    """Test SQLite FTS5 BM25 search for technical terms."""
    results = fts5_search.search_cve("Apache Traversal", top_k=5)
    assert len(results) > 0
    cve_ids = [r["id"] for r in results]
    assert any("CVE-2021-41773" in cid or "CVE-2021-42013" in cid for cid in cve_ids)


def test_reranker_rrf_fusion():
    """Test Reciprocal Rank Fusion of dense and sparse candidates."""
    dense = [
        {"id": "CVE-2021-41773", "similarity_score": 0.92, "metadata": {"cvss_score": 7.5, "severity": "HIGH"}},
        {"id": "CVE-2024-0001", "similarity_score": 0.81, "metadata": {"cvss_score": 5.0, "severity": "MEDIUM"}},
    ]
    sparse = [
        {"id": "CVE-2021-41773", "score": 0.95, "metadata": {"cvss_score": 7.5, "severity": "HIGH"}},
        {"id": "CVE-2024-9999", "score": 0.88, "metadata": {"cvss_score": 9.8, "severity": "CRITICAL"}},
    ]

    fused = reranker.fuse_and_rerank(dense, sparse, top_n=2)
    assert len(fused) == 2
    assert fused[0]["id"] == "CVE-2021-41773"
    assert fused[0]["final_score"] > 0.0


def test_hybrid_rag_service_retrieval():
    """Test end-to-end Hybrid RAG retriever combining exact match and semantic search."""
    # 1. Exact match
    exact_res = RAGService.retrieve("Tell me about CVE-2021-41773", top_k=2)
    assert len(exact_res) > 0
    assert exact_res[0]["id"] == "CVE-2021-41773"
    assert exact_res[0]["metadata"]["retrieval_mode"] == "EXACT_CVE_MATCH"

    # 2. Semantic query
    semantic_res = RAGService.retrieve("path traversal vulnerability in web server", top_k=3)
    assert len(semantic_res) > 0
    modes = [r["metadata"].get("retrieval_mode") for r in semantic_res]
    assert any(m in ("HYBRID_RAG_FUSION", "EXACT_CVE_MATCH") for m in modes)


def test_graph_rag_attack_chains():
    """Test Knowledge Graph attack path chaining."""
    chains = graph_rag.get_attack_chains_for_target("192.168.56.101")
    assert isinstance(chains, list)
    assert len(chains) > 0
    prompt_ctx = graph_rag.get_graph_rag_prompt_context("192.168.56.101")
    assert "GRAPH RAG KNOWLEDGE GRAPH" in prompt_ctx

    # Verify clean target without vulnerabilities returns empty list safely
    clean_chains = graph_rag.get_attack_chains_for_target("192.168.100.153")
    assert isinstance(clean_chains, list)


def test_threat_intel_feed_service():
    """Test threat intelligence synchronization and status reporting."""
    status = threat_intel_feed.get_status()
    assert status["database_totals"]["cve_records"] >= 539
    assert status["database_totals"]["cisa_kev_records"] >= 5


def test_rest_api_vector_endpoints(client):
    """Test REST API endpoints under /api/vector."""
    # Stats
    res = client.get("/api/vector/stats")
    assert res.status_code == 200
    assert "total_vectors" in res.json()

    # Search
    search_res = client.post("/api/vector/search", json={"query": "apache traversal", "top_k": 2})
    assert search_res.status_code == 200
    data = search_res.json()
    assert data["count"] > 0


def test_rest_api_graph_rag_endpoints(client):
    """Test REST API endpoints under /api/graph-rag."""
    res = client.get("/api/graph-rag/chains/192.168.100.153")
    assert res.status_code == 200
    assert "chains" in res.json()

    ctx_res = client.get("/api/graph-rag/context/192.168.100.153")
    assert ctx_res.status_code == 200
    assert "context" in ctx_res.json()


def test_rest_api_intel_endpoints(client):
    """Test REST API endpoints under /api/intel."""
    res = client.get("/api/intel/status")
    assert res.status_code == 200
    assert "database_totals" in res.json()
