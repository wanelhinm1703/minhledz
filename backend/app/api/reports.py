"""REST endpoints for Generating and Viewing Pentest Reports, Compliance Matrix & SARIF."""

from __future__ import annotations

import json
from fastapi import APIRouter, HTTPException, Query, Response
from fastapi.responses import HTMLResponse, JSONResponse

from backend.app.services.compliance_engine import compliance_engine
from backend.app.services.report_generator import report_generator
from backend.app.services.sarif_exporter import sarif_exporter
from backend.app.storage.findings_db import findings_db

router = APIRouter(prefix="/reports", tags=["reports"])


@router.post("/generate/{target_id}")
def generate_report(
    target_id: str,
    campaign_name: str | None = Query("Automated Lab Assessment"),
):
    result = report_generator.generate_report(
        target_id=target_id, campaign_name=campaign_name
    )
    return result


@router.get("")
def list_reports():
    return {"reports": report_generator.list_reports()}


@router.get("/{target_id}")
def get_report(target_id: str):
    report = report_generator.get_report(target_id)
    if not report:
        raise HTTPException(
            status_code=404, detail=f"No report found for target '{target_id}'"
        )
    return report


@router.get("/{target_id}/html", response_class=HTMLResponse)
def get_report_html(target_id: str):
    report = report_generator.get_report(target_id)
    if not report or not report.get("html_content"):
        raise HTTPException(
            status_code=404, detail=f"No HTML report found for target '{target_id}'"
        )
    return HTMLResponse(content=report["html_content"])


@router.get("/{target_id}/pdf")
def get_report_pdf(target_id: str, download: bool = False):
    """Retrieve or generate professional PDF 1.4 report."""
    # Resolve candidates (e.g. 'target-192.168.100.153' vs '192.168.100.153')
    candidates = [target_id]
    if target_id.startswith("target-"):
        candidates.append(target_id[7:])
    else:
        candidates.append(f"target-{target_id}")

    resolved_target = None
    pdf_path = None

    for cand in candidates:
        clean = cand.replace(":", "-").replace("/", "-")
        p_pdf = report_generator.reports_dir / f"{clean}_report.pdf"
        p_md = report_generator.reports_dir / f"{clean}_report.md"
        f_list = findings_db.list_findings(target_id=cand)
        if p_pdf.exists() or p_md.exists() or f_list:
            resolved_target = cand
            pdf_path = p_pdf
            break

    if not resolved_target or not pdf_path:
        raise HTTPException(
            status_code=404, detail=f"No assessment report found for target '{target_id}'"
        )

    clean_target = resolved_target.replace(":", "-").replace("/", "-")
    pdf_bytes = None
    if pdf_path.exists():
        pdf_bytes = pdf_path.read_bytes()
    else:
        findings = findings_db.list_findings(target_id=resolved_target)
        summary = findings_db.get_summary(target_id=resolved_target)
        compliance_summary = compliance_engine.evaluate_compliance_summary(findings)
        from backend.app.services.pdf_generator import pdf_report_generator
        pdf_bytes = pdf_report_generator.generate_pdf_report(
            target_id=resolved_target,
            campaign_name="Automated Lab Assessment",
            findings=findings,
            summary=summary,
            compliance_summary=compliance_summary,
            output_path=pdf_path,
        )

    headers = {}
    filename = f"{clean_target}_report.pdf"
    if download:
        headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    else:
        headers["Content-Disposition"] = f'inline; filename="{filename}"'

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers=headers,
    )


@router.get("/{target_id}/sarif")
def get_report_sarif(target_id: str, download: bool = False):
    """Retrieve or generate OASIS SARIF v2.1.0 report for GitHub Actions and GitLab CI."""
    report = report_generator.get_report(target_id)
    sarif_str = report.get("sarif_content") if report else None

    if not sarif_str:
        findings = findings_db.list_findings(target_id=target_id)
        sarif_doc = sarif_exporter.export_sarif(target_id, findings)
        sarif_str = json.dumps(sarif_doc, indent=2)

    headers = {}
    if download:
        clean_target = target_id.replace(":", "-").replace("/", "-")
        headers["Content-Disposition"] = f'attachment; filename="{clean_target}_report.sarif"'

    return Response(
        content=sarif_str,
        media_type="application/sarif+json",
        headers=headers,
    )


@router.get("/{target_id}/compliance")
def get_target_compliance(target_id: str):
    """Retrieve compliance assessment across OWASP Top 10, CWE Top 25, NIST SP 800-115, CIS Controls."""
    findings = findings_db.list_findings(target_id=target_id)
    compliance_summary = compliance_engine.evaluate_compliance_summary(findings)
    detailed_mappings = [
        {
            "finding_id": f.id,
            "title": f.title,
            "severity": f.cvss_severity.value,
            "cvss_score": f.cvss_score,
            "affected_asset": f.affected_asset,
            "compliance": compliance_engine.map_finding(f),
        }
        for f in findings
        if getattr(f.status, "value", str(f.status)) != "FALSE_POSITIVE"
    ]
    return {
        "target_id": target_id,
        "summary": compliance_summary,
        "detailed_mappings": detailed_mappings,
    }
