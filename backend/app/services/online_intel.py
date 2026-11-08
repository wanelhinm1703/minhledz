"""AI-Pentest Copilot - Online Threat Intel Service.
Queries open, read-only vulnerability databases (OSV.dev, NIST NVD) asynchronously.
Strictly read-only advisory lookup: never downloads or executes exploit payloads.
Graceful degradation: if offline or timed out, returns empty results without throwing.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import httpx

from backend.app.config import settings
from backend.app.schemas.cve import CVECandidate

logger = logging.getLogger("online_intel")


class OnlineIntelService:
    """Provides safe, read-only threat intelligence lookups from online APIs."""

    OSV_API_URL = "https://api.osv.dev/v1/query"
    NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(
        self,
        timeout: float | None = None,
        enabled: bool | None = None,
    ):
        self.timeout = timeout if timeout is not None else settings.ONLINE_INTEL_TIMEOUT
        self.enabled = (
            enabled
            if enabled is not None
            else (settings.VULN_INTEL_MODE.lower() in ("dual", "online"))
        )

    def is_online_enabled(self) -> bool:
        """Check if online queries are currently permitted by configuration."""
        mode = getattr(settings, "VULN_INTEL_MODE", "dual").lower()
        return self.enabled and mode in ("dual", "online")

    async def query_osv_async(
        self,
        product: str,
        version: str | None = None,
        limit: int = 10,
    ) -> list[CVECandidate]:
        """
        Query OSV.dev API asynchronously for a product and version.
        Returns a list of standardized CVECandidate objects.
        """
        if not self.is_online_enabled():
            return []

        clean_prod = product.strip()
        clean_ver = version.strip() if version else None

        if not clean_prod:
            return []

        payload: dict[str, Any] = {
            "package": {"name": clean_prod.lower()},
        }
        if clean_ver:
            payload["version"] = clean_ver

        candidates: list[CVECandidate] = []

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(self.OSV_API_URL, json=payload)
                if resp.status_code != 200:
                    logger.debug(
                        "OSV.dev returned HTTP %s for product %s",
                        resp.status_code,
                        clean_prod,
                    )
                    return []

                data = resp.json()
                vulns = data.get("vulns", [])

                seen_cves: set[str] = set()
                for item in vulns:
                    candidate = self._parse_osv_item(item, clean_prod, clean_ver)
                    if candidate and candidate.cve_id.upper() not in seen_cves:
                        seen_cves.add(candidate.cve_id.upper())
                        candidates.append(candidate)
                        if len(candidates) >= limit:
                            break

        except (httpx.TimeoutException, httpx.NetworkError, Exception) as exc:
            logger.debug(
                "Online intel query failed gracefully for %s %s: %s",
                clean_prod,
                clean_ver,
                exc,
            )
            return []

        return candidates

    def _parse_osv_item(
        self,
        item: dict[str, Any],
        product: str,
        version: str | None,
    ) -> CVECandidate | None:
        """Parse a single OSV vulnerability record into a CVECandidate."""
        raw_id = item.get("id", "")
        aliases = item.get("aliases", [])

        # Find CVE identifier (either id itself or in aliases)
        cve_id = None
        if raw_id.upper().startswith("CVE-"):
            cve_id = raw_id.upper()
        else:
            for a in aliases:
                if a.upper().startswith("CVE-"):
                    cve_id = a.upper()
                    break

        if not cve_id:
            cve_id = raw_id or "VULN-UNKNOWN"

        summary = item.get("summary") or item.get("details") or f"Vulnerability {cve_id} in {product}"
        if len(summary) > 400:
            summary = summary[:397] + "..."

        # Determine severity & CVSS
        cvss_score = 7.5  # Standard medium-high baseline if unspecified
        cvss_severity = "HIGH"

        severities = item.get("severity", [])
        for s in severities:
            score_str = s.get("score")
            if score_str and isinstance(score_str, str) and score_str.startswith("CVSS:"):
                cvss_score = 8.0
                cvss_severity = "HIGH"
                break

        database_specific = item.get("database_specific", {})
        if "severity" in database_specific:
            db_sev = str(database_specific["severity"]).upper()
            if db_sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                cvss_severity = db_sev
                if db_sev == "CRITICAL":
                    cvss_score = 9.5
                elif db_sev == "HIGH":
                    cvss_score = 7.8
                elif db_sev == "MEDIUM":
                    cvss_score = 5.5
                elif db_sev == "LOW":
                    cvss_score = 3.0

        # References
        refs = item.get("references", [])
        source_url = f"https://osv.dev/vulnerability/{raw_id}"
        for ref in refs:
            url = ref.get("url", "")
            if "cve.mitre.org" in url or "nvd.nist.gov" in url:
                source_url = url
                break

        # CWEs
        cwe_ids: list[str] = []
        for ref in refs:
            url = ref.get("url", "")
            if "cwe.mitre.org" in url and "CWE-" in url:
                part = url.split("CWE-")[-1].split(".")[0].split("/")[0]
                if part.isdigit():
                    cwe_ids.append(f"CWE-{part}")

        return CVECandidate(
            cve_id=cve_id,
            description=summary,
            cvss_score=cvss_score,
            cvss_severity=cvss_severity,
            cwe_ids=cwe_ids,
            source_url=source_url,
            source_name="Google OSV.dev (Online Intel)",
            confidence=0.90 if version else 0.70,
            match_reason=f"Online OSV match for {product}" + (f" {version}" if version else ""),
            origin="online_intel",
        )

    def query_sync(
        self,
        product: str,
        version: str | None = None,
        limit: int = 10,
    ) -> list[CVECandidate]:
        """Synchronous wrapper for query_osv_async for non-async callers."""
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                return self._query_sync_internal(product, version, limit)
            return loop.run_until_complete(
                self.query_osv_async(product, version, limit)
            )
        except RuntimeError:
            return self._query_sync_internal(product, version, limit)

    def _query_sync_internal(
        self,
        product: str,
        version: str | None = None,
        limit: int = 10,
    ) -> list[CVECandidate]:
        """Direct synchronous HTTP query to OSV."""
        if not self.is_online_enabled():
            return []

        clean_prod = product.strip()
        clean_ver = version.strip() if version else None
        if not clean_prod:
            return []

        payload: dict[str, Any] = {
            "package": {"name": clean_prod.lower()},
        }
        if clean_ver:
            payload["version"] = clean_ver

        candidates: list[CVECandidate] = []
        try:
            with httpx.Client(timeout=self.timeout) as client:
                resp = client.post(self.OSV_API_URL, json=payload)
                if resp.status_code == 200:
                    vulns = resp.json().get("vulns", [])
                    for item in vulns[:limit]:
                        c = self._parse_osv_item(item, clean_prod, clean_ver)
                        if c:
                            candidates.append(c)
        except Exception as exc:
            logger.debug("Sync online intel query failed gracefully: %s", exc)
            return []

        return candidates


online_intel = OnlineIntelService()
