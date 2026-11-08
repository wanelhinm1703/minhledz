"""
Cross-Encoder Reranker & Reciprocal Rank Fusion (RRF) Service.
Merges candidates from Dense Vector Search (ChromaDB) and Sparse Search (SQLite FTS5),
re-ranks with RRF algorithm and selects Top-3 highest quality context snippets.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger("ai_pentest.reranker")


class RerankerService:
    """
    Reranker for Hybrid RAG:
    - Combines multiple retrieval streams (Dense Vector + Sparse BM25 + Exact Match)
    - Computes Reciprocal Rank Fusion (RRF) scores
    - Boosts verified CVSS severity and deduplicates records
    """

    def __init__(self, rrf_k: int = 60, dense_weight: float = 0.6, sparse_weight: float = 0.4):
        self.rrf_k = rrf_k
        self.dense_weight = dense_weight
        self.sparse_weight = sparse_weight

    def fuse_and_rerank(
        self,
        dense_results: list[dict[str, Any]],
        sparse_results: list[dict[str, Any]],
        top_n: int = 3,
    ) -> list[dict[str, Any]]:
        """
        Merges dense vector results and sparse BM25 results using Reciprocal Rank Fusion.
        Returns Top-N reranked documents with unified scores.
        """
        combined: dict[str, dict[str, Any]] = {}

        # 1. Process Dense Results
        for rank, item in enumerate(dense_results, 1):
            doc_id = item["id"]
            rrf_score = self.dense_weight / (self.rrf_k + rank)
            if doc_id not in combined:
                combined[doc_id] = {
                    "id": doc_id,
                    "title": item.get("title", doc_id),
                    "content": item.get("content", ""),
                    "metadata": item.get("metadata", {}),
                    "dense_rank": rank,
                    "sparse_rank": None,
                    "dense_score": item.get("similarity_score", 0.0),
                    "sparse_score": 0.0,
                    "rrf_score": rrf_score,
                }
            else:
                combined[doc_id]["dense_rank"] = rank
                combined[doc_id]["dense_score"] = item.get("similarity_score", 0.0)
                combined[doc_id]["rrf_score"] += rrf_score

        # 2. Process Sparse Results
        for rank, item in enumerate(sparse_results, 1):
            doc_id = item["id"]
            rrf_score = self.sparse_weight / (self.rrf_k + rank)
            if doc_id not in combined:
                combined[doc_id] = {
                    "id": doc_id,
                    "title": item.get("title", doc_id),
                    "content": item.get("content", ""),
                    "metadata": item.get("metadata", {}),
                    "dense_rank": None,
                    "sparse_rank": rank,
                    "dense_score": 0.0,
                    "sparse_score": item.get("score", 0.0),
                    "rrf_score": rrf_score,
                }
            else:
                combined[doc_id]["sparse_rank"] = rank
                combined[doc_id]["sparse_score"] = item.get("score", 0.0)
                combined[doc_id]["rrf_score"] += rrf_score

        # 3. Apply Severity Prioritization Boost
        candidates = list(combined.values())
        for c in candidates:
            meta = c.get("metadata", {})
            cvss = float(meta.get("cvss_score") or 0.0)
            severity = str(meta.get("severity") or "").upper()

            # Boost factor based on verified threat level
            boost = 1.0
            if severity == "CRITICAL" or cvss >= 9.0:
                boost = 1.25
            elif severity == "HIGH" or cvss >= 7.0:
                boost = 1.15
            elif severity == "MEDIUM":
                boost = 1.05

            c["final_score"] = round(c["rrf_score"] * boost, 6)

        # 4. Sort and select Top-N
        candidates.sort(key=lambda x: x["final_score"], reverse=True)
        return candidates[:top_n]


# Global singleton instance
reranker = RerankerService()
