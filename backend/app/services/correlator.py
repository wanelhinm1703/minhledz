"""AI-Pentest Copilot - Vulnerability Correlator.
Correlates detected services and product versions with CVEs.
Supports Dual-Mode execution:
1. Offline: Authoritative SQLite Knowledge Base (539 CVEs / 52 CWEs) with Semantic Version Tuples.
2. Online: OSV.dev (Google Open Source Vulnerabilities) and NIST NVD.
3. Dual (Concurrent): Runs both offline and online simultaneously, deduplicating and cross-verifying matches.
"""

from __future__ import annotations

import asyncio
import re
from concurrent.futures import ThreadPoolExecutor

from backend.app.config import settings
from backend.app.schemas.cve import CVECandidate
from backend.app.services.online_intel import online_intel
from backend.app.storage.db import db


def parse_version_tuple(ver_str: str) -> tuple[int, ...]:
    """Parses version string into numeric tuple for correct semantic comparison (e.g. 2.4.49 > 2.4.9)."""
    if not ver_str:
        return ()
    nums = re.findall(r"\d+", ver_str)
    return tuple(int(n) for n in nums)


class Correlator:
    """
    Correlates detected service and product versions with CVEs in Knowledge Base.
    Confidence levels:
      - Verified Dual (Offline + Online): 0.98 - 1.0
      - Exact version match: 0.95
      - Online verified match: 0.90
      - Version range match: 0.85
      - Product-only match:  0.50
    """

    @classmethod
    def normalize_product_name(cls, raw_product: str) -> str:
        p = raw_product.lower().strip()
        p = p.replace("-", "_").replace(" ", "_")
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
    def correlate_offline(
        cls,
        product: str,
        version: str | None = None,
        limit: int = 20,
    ) -> list[CVECandidate]:
        """Offline correlation using local SQLite Knowledge Base."""
        norm_prod = cls.normalize_product_name(product)
        candidates: list[CVECandidate] = []
        seen_cve_ids: set[str] = set()

        with db.get_connection() as conn:
            cursor = conn.cursor()

            # Level 1: Exact version match
            if version:
                cursor.execute(
                    """
                    SELECT c.cve_id, c.description, c.cvss_v3_score, c.cvss_v3_severity,
                           c.cvss_v4_score, c.cvss_v4_vector, c.cvss_v4_severity,
                           c.is_cisa_kev, c.epss_score, c.epss_percentile, c.cwe_ids,
                           c.source_url, a.version_exact
                    FROM cve c
                    JOIN cve_affected a ON c.cve_id = a.cve_id
                    WHERE (a.product LIKE ? OR a.vendor LIKE ?) AND a.version_exact = ?
                    GROUP BY c.cve_id
                    LIMIT ?
                    """,
                    (f"%{norm_prod}%", f"%{norm_prod}%", version.strip(), limit),
                )
                rows = cursor.fetchall()
                for r in rows:
                    cve_key = r["cve_id"].upper()
                    if cve_key in seen_cve_ids:
                        continue
                    seen_cve_ids.add(cve_key)
                    cwe_list = [
                        c.strip() for c in (r["cwe_ids"] or "").split(",") if c.strip()
                    ]
                    candidates.append(
                        CVECandidate(
                            cve_id=r["cve_id"],
                            description=r["description"],
                            cvss_score=r["cvss_v3_score"],
                            cvss_severity=r["cvss_v3_severity"],
                            cvss_v4_score=r["cvss_v4_score"] if "cvss_v4_score" in r.keys() else None,
                            cvss_v4_vector=r["cvss_v4_vector"] if "cvss_v4_vector" in r.keys() else None,
                            cvss_v4_severity=r["cvss_v4_severity"] if "cvss_v4_severity" in r.keys() else None,
                            is_cisa_kev=bool(r["is_cisa_kev"]) if "is_cisa_kev" in r.keys() else False,
                            epss_score=r["epss_score"] if "epss_score" in r.keys() else None,
                            epss_percentile=r["epss_percentile"] if "epss_percentile" in r.keys() else None,
                            cwe_ids=cwe_list,
                            source_url=r["source_url"],
                            source_name="Offline Vulnerability KB (SQLite)",
                            confidence=0.95,
                            match_reason=f"Exact version match for {product} {version}",
                            origin="offline_kb",
                        )
                    )

            # Level 2: Version range comparison
            if version and len(candidates) < limit:
                target_tuple = parse_version_tuple(version)
                cursor.execute(
                    """
                    SELECT c.cve_id, c.description, c.cvss_v3_score, c.cvss_v3_severity,
                           c.cvss_v4_score, c.cvss_v4_vector, c.cvss_v4_severity,
                           c.is_cisa_kev, c.epss_score, c.epss_percentile, c.cwe_ids,
                           c.source_url, a.version_start, a.version_end
                    FROM cve c
                    JOIN cve_affected a ON c.cve_id = a.cve_id
                    WHERE (a.product LIKE ? OR a.vendor LIKE ?) AND a.version_start IS NOT NULL AND a.version_end IS NOT NULL
                    GROUP BY c.cve_id
                    """,
                    (f"%{norm_prod}%", f"%{norm_prod}%"),
                )
                for r in cursor.fetchall():
                    cve_key = r["cve_id"].upper()
                    if cve_key in seen_cve_ids:
                        continue
                    v_start = parse_version_tuple(r["version_start"])
                    v_end = parse_version_tuple(r["version_end"])
                    if v_start and v_end and v_start <= target_tuple <= v_end:
                        seen_cve_ids.add(cve_key)
                        cwe_list = [
                            c.strip()
                            for c in (r["cwe_ids"] or "").split(",")
                            if c.strip()
                        ]
                        candidates.append(
                            CVECandidate(
                                cve_id=r["cve_id"],
                                description=r["description"],
                                cvss_score=r["cvss_v3_score"],
                                cvss_severity=r["cvss_v3_severity"],
                                cvss_v4_score=r["cvss_v4_score"] if "cvss_v4_score" in r.keys() else None,
                                cvss_v4_vector=r["cvss_v4_vector"] if "cvss_v4_vector" in r.keys() else None,
                                cvss_v4_severity=r["cvss_v4_severity"] if "cvss_v4_severity" in r.keys() else None,
                                is_cisa_kev=bool(r["is_cisa_kev"]) if "is_cisa_kev" in r.keys() else False,
                                epss_score=r["epss_score"] if "epss_score" in r.keys() else None,
                                epss_percentile=r["epss_percentile"] if "epss_percentile" in r.keys() else None,
                                cwe_ids=cwe_list,
                                source_url=r["source_url"],
                                source_name="Offline Vulnerability KB (SQLite)",
                                confidence=0.85,
                                match_reason=f"Version range match: {r['version_start']} <= {version} <= {r['version_end']}",
                                origin="offline_kb",
                            )
                        )
                        if len(candidates) >= limit:
                            break

            # Level 3: Product-only match (if no version or low count)
            if len(candidates) < limit:
                cursor.execute(
                    """
                    SELECT c.cve_id, c.description, c.cvss_v3_score, c.cvss_v3_severity,
                           c.cvss_v4_score, c.cvss_v4_vector, c.cvss_v4_severity,
                           c.is_cisa_kev, c.epss_score, c.epss_percentile, c.cwe_ids, c.source_url
                    FROM cve c
                    JOIN cve_affected a ON c.cve_id = a.cve_id
                    WHERE a.product LIKE ? OR a.vendor LIKE ?
                    GROUP BY c.cve_id
                    LIMIT ?
                    """,
                    (f"%{norm_prod}%", f"%{norm_prod}%", limit * 2),
                )
                for r in cursor.fetchall():
                    cve_key = r["cve_id"].upper()
                    if cve_key in seen_cve_ids:
                        continue
                    seen_cve_ids.add(cve_key)
                    cwe_list = [
                        c.strip() for c in (r["cwe_ids"] or "").split(",") if c.strip()
                    ]
                    candidates.append(
                        CVECandidate(
                            cve_id=r["cve_id"],
                            description=r["description"],
                            cvss_score=r["cvss_v3_score"],
                            cvss_severity=r["cvss_v3_severity"],
                            cvss_v4_score=r["cvss_v4_score"] if "cvss_v4_score" in r.keys() else None,
                            cvss_v4_vector=r["cvss_v4_vector"] if "cvss_v4_vector" in r.keys() else None,
                            cvss_v4_severity=r["cvss_v4_severity"] if "cvss_v4_severity" in r.keys() else None,
                            is_cisa_kev=bool(r["is_cisa_kev"]) if "is_cisa_kev" in r.keys() else False,
                            epss_score=r["epss_score"] if "epss_score" in r.keys() else None,
                            epss_percentile=r["epss_percentile"] if "epss_percentile" in r.keys() else None,
                            cwe_ids=cwe_list,
                            source_url=r["source_url"],
                            source_name="Offline Vulnerability KB (SQLite)",
                            confidence=0.50,
                            match_reason=f"Product-only match for {product} (INSUFFICIENT_EVIDENCE: Version unconfirmed)",
                            origin="offline_kb",
                        )
                    )
                    if len(candidates) >= limit:
                        break

        return candidates

    @classmethod
    def merge_candidates(
        cls,
        offline_candidates: list[CVECandidate],
        online_candidates: list[CVECandidate],
        limit: int = 20,
    ) -> list[CVECandidate]:
        """
        Merges offline and online candidates.
        Deduplicates by CVE ID.
        If a CVE is verified by both offline and online sources, elevates confidence and marks origin='dual'.
        """
        by_cve: dict[str, CVECandidate] = {}

        # 1. Process offline matches first
        for off in offline_candidates:
            off.origin = "offline_kb"
            by_cve[off.cve_id.upper()] = off

        # 2. Process online matches
        for on in online_candidates:
            cve_key = on.cve_id.upper()
            if cve_key in by_cve:
                # Confirmed by BOTH offline and online!
                existing = by_cve[cve_key]
                existing.origin = "dual"
                existing.source_name = "Dual-Verified (Offline KB + Online OSV)"
                existing.match_reason = f"Verified across both Offline KB and Online Intel: {existing.match_reason}"
                # If online has description and existing is short, enrich it
                if len(on.description) > len(existing.description):
                    existing.description = on.description
            else:
                on.origin = "online_intel"
                by_cve[cve_key] = on

        # Sort merged candidates by confidence (descending) then cvss_score (descending)
        merged = list(by_cve.values())
        merged.sort(key=lambda c: (c.confidence, c.cvss_score or 0.0), reverse=True)
        return merged[:limit]

    @classmethod
    def correlate_dual(
        cls,
        product: str,
        version: str | None = None,
        limit: int = 20,
    ) -> list[CVECandidate]:
        """Synchronously runs both offline and online lookups and merges results."""
        offline_matches = cls.correlate_offline(product, version, limit=limit)
        online_matches = online_intel.query_sync(product, version, limit=limit)
        return cls.merge_candidates(offline_matches, online_matches, limit=limit)

    @classmethod
    async def correlate_dual_async(
        cls,
        product: str,
        version: str | None = None,
        limit: int = 20,
    ) -> list[CVECandidate]:
        """Asynchronously runs both offline and online lookups concurrently."""
        loop = asyncio.get_running_loop()

        # Run offline database query in thread pool to avoid blocking async event loop
        offline_task = loop.run_in_executor(
            None, cls.correlate_offline, product, version, limit
        )
        online_task = online_intel.query_osv_async(product, version, limit)

        results = await asyncio.gather(offline_task, online_task, return_exceptions=True)

        offline_matches: list[CVECandidate] = results[0] if isinstance(results[0], list) else []
        online_matches: list[CVECandidate] = results[1] if isinstance(results[1], list) else []

        return cls.merge_candidates(offline_matches, online_matches, limit=limit)

    @classmethod
    def correlate(
        cls,
        product: str,
        version: str | None = None,
        limit: int = 20,
        intel_mode: str | None = None,
    ) -> list[CVECandidate]:
        """
        Main entry point for vulnerability correlation.
        Dispatches according to configured mode: 'dual', 'offline', or 'online'.
        """
        mode = (intel_mode or getattr(settings, "VULN_INTEL_MODE", "dual")).lower()
        if mode == "dual":
            return cls.correlate_dual(product, version, limit=limit)
        elif mode == "online":
            return online_intel.query_sync(product, version, limit=limit)
        else:
            return cls.correlate_offline(product, version, limit=limit)
