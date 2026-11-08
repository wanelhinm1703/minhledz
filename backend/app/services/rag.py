"""
Hybrid Knowledge Retrieval Service (Advanced Hybrid RAG).
Combines:
1. Exact Match via SQLite (CVE/CWE IDs) -> Top Priority
2. Dense Vector Search via ChromaDB / Persistent VectorStore (Semantic similarity)
3. Sparse BM25 Search via SQLite FTS5 (Keyword / Acronym match)
4. Reranker via Reciprocal Rank Fusion (RRF) -> Top-K highest quality snippets
Preserves strict source citation metadata and prevents hallucination.
"""

from __future__ import annotations

import re
from typing import Any

from backend.app.services.fts5_search import fts5_search
from backend.app.services.reranker import reranker
from backend.app.services.vector_store import vector_store
from backend.app.storage.db import db


class RAGService:
    """
    Production-grade Hybrid RAG Retriever for Defensive Security Copilot.
    """

    @classmethod
    def retrieve(cls, query: str, top_k: int = 5) -> list[dict[str, Any]]:
        clean_q = query.strip()
        if not clean_q:
            return []

        sources: list[dict[str, Any]] = []
        existing_ids: set[str] = set()

        # =========================================================================
        # 1. Exact Match Check (Highest Priority: Score >= 0.95)
        # =========================================================================
        with db.get_connection() as conn:
            cursor = conn.cursor()

            # 1.1 Explicit CVE ID match (e.g. CVE-2021-41773)
            cve_match = re.search(r"CVE-\d{4}-\d{4,7}", clean_q, re.IGNORECASE)
            if cve_match:
                cve_id = cve_match.group(0).upper()
                cursor.execute("SELECT * FROM cve WHERE cve_id = ?", (cve_id,))
                row = cursor.fetchone()
                if row:
                    sources.append(
                        {
                            "id": row["cve_id"],
                            "title": row["cve_id"],
                            "source": row["source_name"],
                            "url": row["source_url"],
                            "content": row["description"],
                            "score": 0.98,
                            "metadata": {
                                "cvss_score": row["cvss_v3_score"],
                                "severity": row["cvss_v3_severity"],
                                "cwe_ids": row["cwe_ids"],
                                "retrieval_mode": "EXACT_CVE_MATCH",
                            },
                        }
                    )
                    existing_ids.add(row["cve_id"])

            # 1.2 Explicit CWE match (e.g. CWE-22)
            cwe_match = re.search(r"CWE-\d+", clean_q, re.IGNORECASE)
            if cwe_match:
                cwe_id = cwe_match.group(0).upper()
                cursor.execute("SELECT * FROM cwe WHERE cwe_id = ?", (cwe_id,))
                row = cursor.fetchone()
                if row:
                    sources.append(
                        {
                            "id": row["cwe_id"],
                            "title": f"{row['cwe_id']}: {row['name']}",
                            "source": row["source_name"],
                            "url": row["source_url"],
                            "content": f"{row['description']} Mitigations: {row['mitigations']}",
                            "score": 0.95,
                            "metadata": {
                                "likelihood": row["likelihood"],
                                "retrieval_mode": "EXACT_CWE_MATCH",
                            },
                        }
                    )
                    existing_ids.add(row["cwe_id"])

        # =========================================================================
        # 2. Dense Vector Search (ChromaDB / VectorStore)
        # =========================================================================
        dense_results: list[dict[str, Any]] = []
        try:
            raw_dense = vector_store.search("cve_knowledge", clean_q, top_k=top_k * 2)
            for d in raw_dense:
                if d["id"] not in existing_ids:
                    dense_results.append(d)
        except Exception:
            dense_results = []

        # =========================================================================
        # 3. Sparse Keyword Search (SQLite FTS5 BM25)
        # =========================================================================
        sparse_results: list[dict[str, Any]] = []
        try:
            raw_sparse = fts5_search.search_cve(clean_q, top_k=top_k * 2)
            for s in raw_sparse:
                if s["id"] not in existing_ids:
                    sparse_results.append(s)
        except Exception:
            sparse_results = []

        # Fallback keyword match if FTS5 returns nothing
        if not sparse_results:
            tokens = [t.lower() for t in re.findall(r"\b[a-zA-Z0-9.-]+\b", clean_q) if len(t) > 2]
            if tokens:
                with db.get_connection() as conn:
                    cursor = conn.cursor()
                    like_clauses = " OR ".join(["description LIKE ?" for _ in tokens[:4]])
                    like_params = [f"%{tok}%" for tok in tokens[:4]]
                    sql = f"""
                        SELECT cve_id, description, cvss_v3_score, cvss_v3_severity, cwe_ids, source_url, source_name
                        FROM cve
                        WHERE {like_clauses}
                        ORDER BY cvss_v3_score DESC
                        LIMIT ?
                    """
                    cursor.execute(sql, (*like_params, top_k))
                    rows = cursor.fetchall()
                    for r in rows:
                        if r["cve_id"] not in existing_ids:
                            sparse_results.append({
                                "id": r["cve_id"],
                                "title": r["cve_id"],
                                "content": r["description"],
                                "score": 0.80,
                                "metadata": {
                                    "cvss_score": r["cvss_v3_score"],
                                    "severity": r["cvss_v3_severity"],
                                    "cwe_ids": r["cwe_ids"],
                                    "source": r["source_name"],
                                }
                            })

        # =========================================================================
        # 4. Cross-Encoder Reranking & Reciprocal Rank Fusion (RRF)
        # =========================================================================
        needed_slots = max(0, top_k - len(sources))
        if needed_slots > 0 and (dense_results or sparse_results):
            fused = reranker.fuse_and_rerank(dense_results, sparse_results, top_n=needed_slots)
            for f in fused:
                meta = f.get("metadata", {})
                meta["retrieval_mode"] = "HYBRID_RAG_FUSION"
                sources.append({
                    "id": f["id"],
                    "title": f.get("title", f["id"]),
                    "source": meta.get("source", "Vulnerability Knowledge Base"),
                    "url": meta.get("source_url", "https://nvd.nist.gov"),
                    "content": f["content"],
                    "score": round(f.get("final_score", 0.85), 4),
                    "metadata": meta,
                })

        return sources[:top_k]
