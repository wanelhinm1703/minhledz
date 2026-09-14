from __future__ import annotations

import json
import re
from typing import List, Dict, Any, Optional
from backend.app.storage.db import db


class RAGService:
    """
    Hybrid Knowledge Retrieval Service:
    Queries authoritative SQLite KB records, ranks by keyword relevance and CVSS score.
    Preserves strict source citation metadata.
    """

    @classmethod
    def retrieve(cls, query: str, top_k: int = 5) -> List[Dict[str, Any]]:
        tokens = [t.lower() for t in re.findall(r"\b[a-zA-Z0-9.-]+\b", query) if len(t) > 2]
        if not tokens:
            return []

        sources: List[Dict[str, Any]] = []
        with db.get_connection() as conn:
            cursor = conn.cursor()

            # 1. Check for explicit CVE ID match (e.g. CVE-2021-41773)
            cve_match = re.search(r"CVE-\d{4}-\d{4,7}", query, re.IGNORECASE)
            if cve_match:
                cve_id = cve_match.group(0).upper()
                cursor.execute("SELECT * FROM cve WHERE cve_id = ?", (cve_id,))
                row = cursor.fetchone()
                if row:
                    sources.append({
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
                        },
                    })

            # 2. Check for explicit CWE match (e.g. CWE-22)
            cwe_match = re.search(r"CWE-\d+", query, re.IGNORECASE)
            if cwe_match:
                cwe_id = cwe_match.group(0).upper()
                cursor.execute("SELECT * FROM cwe WHERE cwe_id = ?", (cwe_id,))
                row = cursor.fetchone()
                if row:
                    sources.append({
                        "id": row["cwe_id"],
                        "title": f"{row['cwe_id']}: {row['name']}",
                        "source": row["source_name"],
                        "url": row["source_url"],
                        "content": f"{row['description']} Mitigations: {row['mitigations']}",
                        "score": 0.95,
                        "metadata": {"likelihood": row["likelihood"]},
                    })

            # 3. Product & keyword query
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
            existing_ids = {s["id"] for s in sources}
            for r in rows:
                if r["cve_id"] in existing_ids:
                    continue
                score = 0.85 if any(tok in r["description"].lower() for tok in tokens) else 0.70
                sources.append({
                    "id": r["cve_id"],
                    "title": r["cve_id"],
                    "source": r["source_name"],
                    "url": r["source_url"],
                    "content": r["description"],
                    "score": score,
                    "metadata": {
                        "cvss_score": r["cvss_v3_score"],
                        "severity": r["cvss_v3_severity"],
                        "cwe_ids": r["cwe_ids"],
                    },
                })
                if len(sources) >= top_k:
                    break

        return sources[:top_k]
