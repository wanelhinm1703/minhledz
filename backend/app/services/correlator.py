from __future__ import annotations

import re
import sqlite3
from typing import List, Optional, Tuple
from backend.app.schemas.cve import CVECandidate
from backend.app.storage.db import db


def parse_version_tuple(ver_str: str) -> Tuple[int, ...]:
    """Parses version string into numeric tuple for correct semantic comparison (e.g. 2.4.49 > 2.4.9)."""
    if not ver_str:
        return ()
    nums = re.findall(r"\d+", ver_str)
    return tuple(int(n) for n in nums)


class Correlator:
    """
    Correlates detected service and product versions with CVEs in Knowledge Base.
    Confidence levels:
      - Exact version match: 0.95
      - Version range match: 0.85
      - Product-only match:  0.50
    """

    @classmethod
    def normalize_product_name(cls, raw_product: str) -> str:
        p = raw_product.lower().strip()
        p = p.replace("-", "_").replace(" ", "_")
        # Common alias mappings
        aliases = {
            "apache": "http_server",
            "apache_httpd": "http_server",
            "apache_http_server": "http_server",
            "openssh": "openssh",
            "nginx": "nginx",
            "node.js": "node.js",
            "nodejs": "node.js",
            "express": "express",
            "log4j": "log4j",
            "spring": "spring_framework",
        }
        for k, v in aliases.items():
            if k in p:
                return v
        return p

    @classmethod
    def correlate(
        cls,
        product: str,
        version: Optional[str] = None,
        limit: int = 20,
    ) -> List[CVECandidate]:
        norm_prod = cls.normalize_product_name(product)
        candidates: List[CVECandidate] = []

        with db.get_connection() as conn:
            cursor = conn.cursor()

            # Level 1: Exact version match
            if version:
                cursor.execute(
                    """
                    SELECT c.cve_id, c.description, c.cvss_v3_score, c.cvss_v3_severity, c.cwe_ids, c.source_url, a.version_exact
                    FROM cve c
                    JOIN cve_affected a ON c.cve_id = a.cve_id
                    WHERE (a.product LIKE ? OR a.vendor LIKE ?) AND a.version_exact = ?
                    LIMIT ?
                    """,
                    (f"%{norm_prod}%", f"%{norm_prod}%", version.strip(), limit),
                )
                rows = cursor.fetchall()
                for r in rows:
                    cwe_list = [c.strip() for c in (r["cwe_ids"] or "").split(",") if c.strip()]
                    candidates.append(
                        CVECandidate(
                            cve_id=r["cve_id"],
                            description=r["description"],
                            cvss_score=r["cvss_v3_score"],
                            cvss_severity=r["cvss_v3_severity"],
                            cwe_ids=cwe_list,
                            source_url=r["source_url"],
                            confidence=0.95,
                            match_reason=f"Exact version match for {product} {version}",
                        )
                    )

            # Level 2: Version range comparison
            if version and len(candidates) < limit:
                target_tuple = parse_version_tuple(version)
                cursor.execute(
                    """
                    SELECT c.cve_id, c.description, c.cvss_v3_score, c.cvss_v3_severity, c.cwe_ids, c.source_url, a.version_start, a.version_end
                    FROM cve c
                    JOIN cve_affected a ON c.cve_id = a.cve_id
                    WHERE (a.product LIKE ? OR a.vendor LIKE ?) AND a.version_start IS NOT NULL AND a.version_end IS NOT NULL
                    """,
                    (f"%{norm_prod}%", f"%{norm_prod}%"),
                )
                existing_ids = {c.cve_id for c in candidates}
                for r in cursor.fetchall():
                    if r["cve_id"] in existing_ids:
                        continue
                    v_start = parse_version_tuple(r["version_start"])
                    v_end = parse_version_tuple(r["version_end"])
                    if v_start and v_end and v_start <= target_tuple <= v_end:
                        cwe_list = [c.strip() for c in (r["cwe_ids"] or "").split(",") if c.strip()]
                        candidates.append(
                            CVECandidate(
                                cve_id=r["cve_id"],
                                description=r["description"],
                                cvss_score=r["cvss_v3_score"],
                                cvss_severity=r["cvss_v3_severity"],
                                cwe_ids=cwe_list,
                                source_url=r["source_url"],
                                confidence=0.85,
                                match_reason=f"Version range match: {r['version_start']} <= {version} <= {r['version_end']}",
                            )
                        )
                        if len(candidates) >= limit:
                            break

            # Level 3: Product-only match (if no version or low count)
            if len(candidates) < limit:
                existing_ids = {c.cve_id for c in candidates}
                cursor.execute(
                    """
                    SELECT c.cve_id, c.description, c.cvss_v3_score, c.cvss_v3_severity, c.cwe_ids, c.source_url
                    FROM cve c
                    JOIN cve_affected a ON c.cve_id = a.cve_id
                    WHERE a.product LIKE ? OR a.vendor LIKE ?
                    LIMIT ?
                    """,
                    (f"%{norm_prod}%", f"%{norm_prod}%", limit * 2),
                )
                for r in cursor.fetchall():
                    if r["cve_id"] in existing_ids:
                        continue
                    cwe_list = [c.strip() for c in (r["cwe_ids"] or "").split(",") if c.strip()]
                    candidates.append(
                        CVECandidate(
                            cve_id=r["cve_id"],
                            description=r["description"],
                            cvss_score=r["cvss_v3_score"],
                            cvss_severity=r["cvss_v3_severity"],
                            cwe_ids=cwe_list,
                            source_url=r["source_url"],
                            confidence=0.50,
                            match_reason=f"Product-only match for {product} (version unverified)",
                        )
                    )
                    if len(candidates) >= limit:
                        break

        return candidates
