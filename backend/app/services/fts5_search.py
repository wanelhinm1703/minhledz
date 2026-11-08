"""
SQLite FTS5 Full-Text Search Service (Sparse Search).
Provides BM25-ranked full-text search over CVE and CWE catalogs in kb.sqlite.
Optimized for precise keyword and technical abbreviation matching (SQLi, XSS, RCE, LFI, SSRF).
"""

from __future__ import annotations

import logging
import pathlib
import sqlite3
from typing import Any

logger = logging.getLogger("ai_pentest.fts5_search")

ROOT_DIR = pathlib.Path(__file__).resolve().parent.parent.parent.parent
DB_PATH = ROOT_DIR / "toolkit" / "data" / "kb.sqlite"


class FTS5SearchService:
    """Manages SQLite FTS5 full-text search tables and BM25 ranking queries."""

    def __init__(self, db_path: pathlib.Path | str | None = None):
        self.db_path = pathlib.Path(db_path or DB_PATH)
        self._ensure_fts5_tables()

    def _ensure_fts5_tables(self) -> None:
        """Initializes FTS5 virtual tables and populates them if empty."""
        if not self.db_path.exists():
            return

        try:
            conn = sqlite3.connect(str(self.db_path))
            c = conn.cursor()

            # 1. Create FTS5 virtual table for CVEs
            c.execute("""
                CREATE VIRTUAL TABLE IF NOT EXISTS cve_fts USING fts5(
                    cve_id,
                    description,
                    cwe_ids,
                    tokenize = 'porter unicode61'
                );
            """)

            # 2. Create FTS5 virtual table for CWEs
            c.execute("""
                CREATE VIRTUAL TABLE IF NOT EXISTS cwe_fts USING fts5(
                    cwe_id,
                    name,
                    description,
                    mitigations,
                    tokenize = 'porter unicode61'
                );
            """)

            # Check if cve_fts is populated
            c.execute("SELECT COUNT(*) FROM cve_fts")
            if c.fetchone()[0] == 0:
                c.execute("""
                    INSERT INTO cve_fts (cve_id, description, cwe_ids)
                    SELECT cve_id, description, cwe_ids FROM cve;
                """)

            # Check if cwe_fts is populated
            c.execute("SELECT COUNT(*) FROM cwe_fts")
            if c.fetchone()[0] == 0:
                c.execute("""
                    INSERT INTO cwe_fts (cwe_id, name, description, mitigations)
                    SELECT cwe_id, name, description, mitigations FROM cwe;
                """)

            conn.commit()
            conn.close()
            logger.info("FTS5 tables verified and initialized in %s", self.db_path)
        except Exception as e:
            logger.error("Failed to initialize FTS5 virtual tables: %s", e)

    def search_cve(self, query: str, top_k: int = 5) -> list[dict[str, Any]]:
        """
        Executes BM25-ranked full-text search on CVEs using SQLite FTS5.
        Returns matching records with bm25 relevance rank.
        """
        clean_q = "".join(ch if ch.isalnum() or ch in ("-", "_") else " " for ch in query).strip()
        tokens = [t for t in clean_q.split() if len(t) > 1]
        if not tokens:
            return []

        # Construct FTS5 MATCH query with OR / NEAR
        match_expr = " OR ".join([f'"{tok}"*' for tok in tokens[:6]])

        results: list[dict[str, Any]] = []
        try:
            conn = sqlite3.connect(str(self.db_path))
            conn.row_factory = sqlite3.Row
            c = conn.cursor()

            sql = """
                SELECT 
                    c.cve_id, 
                    c.cvss_v3_score, 
                    c.cvss_v3_severity, 
                    c.cwe_ids, 
                    c.description, 
                    c.source_name,
                    c.source_url,
                    bm25(cve_fts) as rank_score
                FROM cve_fts f
                JOIN cve c ON f.cve_id = c.cve_id
                WHERE cve_fts MATCH ?
                ORDER BY rank_score ASC, c.cvss_v3_score DESC
                LIMIT ?
            """
            c.execute(sql, (match_expr, top_k))
            rows = c.fetchall()
            for r in rows:
                # bm25 returns lower values for better matches (e.g. -2.5 is better than -0.5)
                # Map bm25 to normalized [0.5, 1.0]
                raw_rank = float(r["rank_score"])
                norm_score = round(min(1.0, max(0.5, 1.0 / (1.0 + max(0.0, -raw_rank)))), 4)
                results.append({
                    "id": r["cve_id"],
                    "title": r["cve_id"],
                    "content": r["description"],
                    "score": norm_score,
                    "metadata": {
                        "cvss_score": r["cvss_v3_score"],
                        "severity": r["cvss_v3_severity"],
                        "cwe_ids": r["cwe_ids"],
                        "source": r["source_name"],
                    },
                })
            conn.close()
        except Exception as e:
            logger.debug("FTS5 search error: %s", e)

        return results

    def rebuild_index(self) -> dict[str, int]:
        """Rebuilds the FTS5 virtual tables from the base cve and cwe tables."""
        if not self.db_path.exists():
            return {"cve_fts": 0, "cwe_fts": 0}

        conn = sqlite3.connect(str(self.db_path))
        c = conn.cursor()
        c.execute("DELETE FROM cve_fts;")
        c.execute("INSERT INTO cve_fts (cve_id, description, cwe_ids) SELECT cve_id, description, cwe_ids FROM cve;")
        cve_count = c.rowcount

        c.execute("DELETE FROM cwe_fts;")
        c.execute("INSERT INTO cwe_fts (cwe_id, name, description, mitigations) SELECT cwe_id, name, description, mitigations FROM cwe;")
        cwe_count = c.rowcount

        conn.commit()
        conn.close()
        return {"cve_fts": cve_count, "cwe_fts": cwe_count}


# Global singleton instance
fts5_search = FTS5SearchService()
