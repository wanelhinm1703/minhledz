"""
Vector Store Service (ChromaDB / Persistent Vector Engine).
Provides dense semantic search over security knowledge (CVE, CWE, Pentest docs).
Supports Ollama embeddings (nomic-embed-text / bge-small) with resilient offline fallback.
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
import os
import pathlib
import time
from typing import Any

import httpx

try:
    import numpy as np
    HAVE_NUMPY = True
except ImportError:
    np = None  # type: ignore
    HAVE_NUMPY = False


def _normalize_vector(vec: list[float]) -> list[float]:
    """Normalizes a float vector to unit length L2 norm with pure-Python fallback."""
    if HAVE_NUMPY and np is not None:
        arr = np.array(vec, dtype=np.float32)
        norm = float(np.linalg.norm(arr))
        if norm > 0:
            return (arr / norm).tolist()
        return vec
    s = sum(x * x for x in vec)
    if s > 0:
        norm = math.sqrt(s)
        return [float(x / norm) for x in vec]
    return vec


def _cosine_similarity(v1: list[float], v2: list[float]) -> float:
    """Computes cosine similarity between two vectors with pure-Python fallback."""
    if HAVE_NUMPY and np is not None:
        arr1 = np.array(v1, dtype=np.float32)
        arr2 = np.array(v2, dtype=np.float32)
        return float(np.dot(arr1, arr2))
    return float(sum(a * b for a, b in zip(v1, v2)))

logger = logging.getLogger("ai_pentest.vector_store")

ROOT_DIR = pathlib.Path(__file__).resolve().parent.parent.parent.parent
DEFAULT_CHROMA_PATH = ROOT_DIR / "toolkit" / "data" / "chroma_db"
DEFAULT_OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")
DEFAULT_EMBED_MODEL = os.getenv("EMBED_MODEL", "nomic-embed-text")


class VectorStoreService:
    """
    High-performance Vector Store for Security RAG.
    Operates in persistent mode at toolkit/data/chroma_db.
    Features:
    - Multi-collection management (cve_knowledge, cwe_knowledge, custom_knowledge)
    - Local Ollama embedding integration (/api/embeddings)
    - Native Cosine Similarity search with NumPy
    - Full SQLite sync capability with batch performance optimization
    """

    def __init__(self, storage_dir: pathlib.Path | str | None = None):
        self.storage_dir = pathlib.Path(storage_dir or DEFAULT_CHROMA_PATH)
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self.chroma_client = self._init_chromadb()
        self.index_file = self.storage_dir / "vector_index.json"
        self._local_index: dict[str, dict[str, Any]] = self._load_local_index()
        self._ollama_checked_time: float = 0.0
        self._ollama_is_online: bool = False

    def _init_chromadb(self):
        """Attempts to initialize chromadb PersistentClient if installed."""
        try:
            import chromadb  # type: ignore
            client = chromadb.PersistentClient(path=str(self.storage_dir))
            logger.info("ChromaDB PersistentClient initialized successfully at %s", self.storage_dir)
            return client
        except Exception:
            return None

    def _load_local_index(self) -> dict[str, dict[str, Any]]:
        """Loads native vector index from disk."""
        if self.index_file.exists():
            try:
                with open(self.index_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as e:
                logger.warning("Error loading vector_index.json: %s. Re-initializing empty index.", e)
        return {"cve_knowledge": {}, "cwe_knowledge": {}, "custom_knowledge": {}}

    def _save_local_index(self) -> None:
        """Persists native vector index to disk."""
        try:
            with open(self.index_file, "w", encoding="utf-8") as f:
                json.dump(self._local_index, f, ensure_ascii=False)
        except Exception as e:
            logger.error("Failed to save vector_index.json: %s", e)

    def _is_ollama_available(self) -> bool:
        """Checks if Ollama embedding service is online with 30s caching."""
        now = time.time()
        if now - self._ollama_checked_time < 30.0:
            return self._ollama_is_online

        self._ollama_checked_time = now
        try:
            with httpx.Client(timeout=0.3) as client:
                res = client.get(f"{DEFAULT_OLLAMA_HOST.rstrip('/')}/api/tags")
                self._ollama_is_online = (res.status_code == 200)
        except Exception:
            self._ollama_is_online = False

        return self._ollama_is_online

    def get_embedding(self, text: str) -> list[float]:
        """
        Computes embedding for given text.
        Priority:
        1. Ollama local embeddings API (http://localhost:11434/api/embeddings) if online
        2. High-entropy deterministic semantic hashing fallback (384-dimension unit vector)
        """
        clean_text = text.strip()
        if not clean_text:
            return [0.0] * 384

        # 1. Try Ollama API if online
        if self._is_ollama_available():
            try:
                url = f"{DEFAULT_OLLAMA_HOST.rstrip('/')}/api/embeddings"
                with httpx.Client(timeout=3.0) as client:
                    resp = client.post(
                        url,
                        json={"model": DEFAULT_EMBED_MODEL, "prompt": clean_text},
                    )
                    if resp.status_code == 200:
                        data = resp.json()
                        emb = data.get("embedding")
                        if emb and isinstance(emb, list):
                            return _normalize_vector(emb)
            except Exception:
                pass

        # 2. Resilient Deterministic Semantic Hashing Vectorizer (dimension 384)
        dim = 384
        vec = [0.0] * dim
        tokens = [t.lower() for t in clean_text.split() if len(t) > 1]
        if not tokens:
            tokens = [clean_text.lower()]

        for i, token in enumerate(tokens):
            h = int(hashlib.sha256(token.encode("utf-8")).hexdigest(), 16)
            pos = h % dim
            val = ((h >> 8) % 1000) / 500.0 - 1.0
            vec[pos] += float(val) / (1.0 + 0.05 * i)

        norm_vec = _normalize_vector(vec)
        if sum(norm_vec) == 0:
            norm_vec[0] = 1.0
        return norm_vec

    def add_document(
        self,
        collection_name: str,
        doc_id: str,
        content: str,
        metadata: dict[str, Any] | None = None,
        auto_save: bool = True,
    ) -> None:
        """Adds or updates a document in the vector store."""
        metadata = metadata or {}
        embedding = self.get_embedding(content)

        # 1. Store in ChromaDB if available
        if self.chroma_client:
            try:
                coll = self.chroma_client.get_or_create_collection(
                    name=collection_name, metadata={"hnsw:space": "cosine"}
                )
                safe_meta = {
                    k: str(v) if isinstance(v, (list, dict)) else v
                    for k, v in metadata.items()
                }
                coll.upsert(
                    ids=[doc_id],
                    embeddings=[embedding],
                    documents=[content],
                    metadatas=[safe_meta],
                )
            except Exception as e:
                logger.debug("ChromaDB add_document error: %s", e)

        # 2. Store in Native Persistent Store
        if collection_name not in self._local_index:
            self._local_index[collection_name] = {}

        self._local_index[collection_name][doc_id] = {
            "id": doc_id,
            "content": content,
            "metadata": metadata,
            "embedding": embedding,
        }
        if auto_save:
            self._save_local_index()

    def search(
        self,
        collection_name: str,
        query: str,
        top_k: int = 5,
        filter_metadata: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """
        Performs semantic vector search with Cosine Similarity.
        Returns Top-K relevant documents with similarity scores in [0.0, 1.0].
        """
        if not query.strip():
            return []

        query_vec = _normalize_vector(self.get_embedding(query))

        # 1. Try ChromaDB if available
        if self.chroma_client:
            try:
                coll = self.chroma_client.get_collection(name=collection_name)
                res = coll.query(
                    query_embeddings=[query_vec.tolist()],
                    n_results=top_k,
                    where=filter_metadata,
                )
                if res and res.get("documents") and len(res["documents"][0]) > 0:
                    results = []
                    docs = res["documents"][0]
                    ids = res["ids"][0]
                    metas = res["metadatas"][0] if res.get("metadatas") else [{}] * len(docs)
                    distances = res["distances"][0] if res.get("distances") else [0.0] * len(docs)
                    for d, doc_id, meta, dist in zip(docs, ids, metas, distances):
                        sim = max(0.0, min(1.0, 1.0 - float(dist)))
                        results.append({
                            "id": doc_id,
                            "content": d,
                            "metadata": meta,
                            "similarity_score": round(sim, 4),
                        })
                    return results
            except Exception as e:
                logger.debug("ChromaDB query fallback: %s", e)

        # 2. Native Vector Search with NumPy
        coll_data = self._local_index.get(collection_name, {})
        if not coll_data:
            return []

        scored_candidates: list[dict[str, Any]] = []
        for doc_id, item in coll_data.items():
            meta = item.get("metadata", {})
            if filter_metadata:
                match = True
                for fk, fv in filter_metadata.items():
                    if meta.get(fk) != fv:
                        match = False
                        break
                if not match:
                    continue

            doc_vec = _normalize_vector(item["embedding"])
            similarity = _cosine_similarity(query_vec, doc_vec)
            sim_score = max(0.0, min(1.0, (similarity + 1.0) / 2.0))

            scored_candidates.append({
                "id": doc_id,
                "content": item["content"],
                "metadata": meta,
                "similarity_score": round(sim_score, 4),
            })

        scored_candidates.sort(key=lambda x: x["similarity_score"], reverse=True)
        return scored_candidates[:top_k]

    def sync_from_sqlite(self) -> dict[str, int]:
        """
        Synchronizes all records from SQLite kb.sqlite (CVEs and CWEs) into the Vector Store in batch.
        """
        import sqlite3
        sqlite_path = ROOT_DIR / "toolkit" / "data" / "kb.sqlite"
        if not sqlite_path.exists():
            return {"cve_synced": 0, "cwe_synced": 0}

        conn = sqlite3.connect(str(sqlite_path))
        conn.row_factory = sqlite3.Row
        c = conn.cursor()

        cve_count = 0
        cwe_count = 0

        # 1. Sync CVEs
        try:
            c.execute("SELECT cve_id, cvss_v3_score, cvss_v3_severity, cwe_ids, description, source_name FROM cve")
            cve_rows = c.fetchall()
            for r in cve_rows:
                content = f"Vulnerability {r['cve_id']}: {r['description']} (Severity: {r['cvss_v3_severity']}, CVSS: {r['cvss_v3_score']}, CWE: {r['cwe_ids']})"
                self.add_document(
                    collection_name="cve_knowledge",
                    doc_id=r["cve_id"],
                    content=content,
                    metadata={
                        "cve_id": r["cve_id"],
                        "cvss_score": r["cvss_v3_score"],
                        "severity": r["cvss_v3_severity"],
                        "cwe_ids": r["cwe_ids"],
                        "source": r["source_name"],
                    },
                    auto_save=False,
                )
                cve_count += 1
        except Exception as e:
            logger.error("Error syncing CVEs: %s", e)

        # 2. Sync CWEs
        try:
            c.execute("SELECT cwe_id, name, description, likelihood, mitigations, source_name FROM cwe")
            cwe_rows = c.fetchall()
            for r in cwe_rows:
                content = f"Weakness {r['cwe_id']} - {r['name']}: {r['description']} Likelihood: {r['likelihood']}. Mitigations: {r['mitigations']}"
                self.add_document(
                    collection_name="cwe_knowledge",
                    doc_id=r["cwe_id"],
                    content=content,
                    metadata={
                        "cwe_id": r["cwe_id"],
                        "name": r["name"],
                        "likelihood": r["likelihood"],
                        "source": r["source_name"],
                    },
                    auto_save=False,
                )
                cwe_count += 1
        except Exception as e:
            logger.error("Error syncing CWEs: %s", e)

        conn.close()
        self._save_local_index()
        logger.info("Batch synced %d CVEs and %d CWEs into Vector Store", cve_count, cwe_count)
        return {"cve_synced": cve_count, "cwe_synced": cwe_count}

    def get_stats(self) -> dict[str, Any]:
        """Returns statistical overview of collections in the Vector Store."""
        stats: dict[str, int] = {}
        for coll_name, items in self._local_index.items():
            stats[coll_name] = len(items)

        return {
            "engine": "ChromaDB Persistent" if self.chroma_client else "Native Persistent Vector Store (NumPy/Cosine)",
            "storage_path": str(self.storage_dir),
            "collections": stats,
            "total_vectors": sum(stats.values()),
        }

    def clear(self, collection_name: str | None = None) -> None:
        """Clears a specific collection or all collections."""
        if collection_name:
            if collection_name in self._local_index:
                self._local_index[collection_name] = {}
        else:
            self._local_index = {"cve_knowledge": {}, "cwe_knowledge": {}, "custom_knowledge": {}}
        self._save_local_index()


# Global Singleton instance
vector_store = VectorStoreService()
