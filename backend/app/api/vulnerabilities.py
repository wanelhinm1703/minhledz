from __future__ import annotations

import json

from fastapi import APIRouter, HTTPException, Query

from backend.app.schemas.cve import CorrelateResponse
from backend.app.schemas.cwe import CWEDetail
from backend.app.services.correlator import Correlator
from backend.app.storage.db import db

router = APIRouter(prefix="/vulnerabilities", tags=["vulnerabilities"])


@router.get("/cve/{cve_id}")
def get_cve(cve_id: str):
    with db.get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM cve WHERE cve_id = ?", (cve_id.upper(),))
        row = cursor.fetchone()
        if not row:
            raise HTTPException(
                status_code=404, detail=f"CVE '{cve_id}' not found in Knowledge Base."
            )

        # Fetch affected products
        cursor.execute(
            "SELECT vendor, product, version_start, version_end, version_exact, cpe_uri FROM cve_affected WHERE cve_id = ?",
            (cve_id.upper(),),
        )
        affected = [dict(r) for r in cursor.fetchall()]

        data = dict(row)
        data["is_cisa_kev"] = bool(data.get("is_cisa_kev", 0))
        data["cwe_ids"] = [
            c.strip() for c in (data["cwe_ids"] or "").split(",") if c.strip()
        ]
        data["references"] = json.loads(data["references_json"] or "[]")
        data["affected_products"] = affected
        return data


@router.get("/cwe/{cwe_id}", response_model=CWEDetail)
def get_cwe(cwe_id: str):
    cwe_clean = cwe_id.upper()
    if not cwe_clean.startswith("CWE-"):
        cwe_clean = f"CWE-{cwe_clean}"

    with db.get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM cwe WHERE cwe_id = ?", (cwe_clean,))
        row = cursor.fetchone()
        if not row:
            raise HTTPException(
                status_code=404, detail=f"CWE '{cwe_id}' not found in Knowledge Base."
            )
        return CWEDetail(**dict(row))


@router.get("/correlate", response_model=CorrelateResponse)
def correlate_vulnerabilities(
    product: str = Query(
        ..., description="Service or product name (e.g. Apache, OpenSSH, nginx)"
    ),
    version: str | None = Query(None, description="Exact version string (e.g. 2.4.49)"),
    limit: int = Query(20, ge=1, le=100),
    mode: str | None = Query(None, description="Threat intel mode: 'dual', 'offline', 'online'"),
):
    candidates = Correlator.correlate(
        product=product, version=version, limit=limit, intel_mode=mode
    )
    return CorrelateResponse(
        query={"product": product, "version": version, "mode": mode or "dual"},
        count=len(candidates),
        candidates=candidates,
    )


@router.get("/correlate-target")
@router.get("/correlate-target/{target_id:path}")
def correlate_target_recon_services(
    target_id: str = "",
    mode: str | None = Query("dual", description="Threat intel mode: 'dual', 'offline', 'online'"),
    limit_per_service: int = Query(15, ge=1, le=50),
):
    """Automatically correlate all recon-discovered services of a target against online & offline threat intel."""
    from backend.app.services.target_service_discovery import discover_target_services

    services = discover_target_services(target_id)
    results = []
    total_cves = 0
    total_kev = 0

    for svc in services:
        product = svc.get("product", "")
        version = svc.get("version", "")
        if not product:
            continue

        candidates = Correlator.correlate(
            product=product,
            version=version,
            limit=limit_per_service,
            intel_mode=mode,
        )

        has_kev = any(c.is_cisa_kev for c in candidates)
        max_cvss = max([c.cvss_score or 0 for c in candidates], default=0.0)
        cve_count = len(candidates)
        total_cves += cve_count
        if has_kev:
            total_kev += 1

        results.append({
            "service": svc,
            "product": product,
            "version": version,
            "candidates": [c.model_dump() if hasattr(c, "model_dump") else c.dict() for c in candidates],
            "total_cves": cve_count,
            "has_kev": has_kev,
            "max_cvss": max_cvss,
        })

    return {
        "target_id": target_id,
        "mode": mode or "dual",
        "total_services": len(services),
        "total_correlated_cves": total_cves,
        "services_with_kev": total_kev,
        "results": results,
    }


@router.get("/stats")
def get_kb_stats():
    return db.get_stats()


@router.get("/search")
def search_vulnerabilities(
    query: str = Query(..., min_length=2), limit: int = Query(20, ge=1, le=100)
):
    with db.get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT cve_id, description, cvss_v3_score, cvss_v3_severity, cwe_ids, source_url
            FROM cve
            WHERE cve_id LIKE ? OR description LIKE ?
            LIMIT ?
            """,
            (f"%{query}%", f"%{query}%", limit),
        )
        rows = [dict(r) for r in cursor.fetchall()]
        return {"query": query, "count": len(rows), "results": rows}
