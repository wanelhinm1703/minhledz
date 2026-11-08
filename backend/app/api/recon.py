from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from backend.app.services.scope_validator import ScopeViolation
from toolkit.scripts.pipeline_runner import run_pipeline

router = APIRouter(prefix="/recon", tags=["recon"])


class TriggerReconRequest(BaseModel):
    target: str
    campaign_id: str = "lab-local"
    tools: list[str] | None = None


@router.post("/trigger")
def trigger_recon(req: TriggerReconRequest):
    try:
        manifest = run_pipeline(
            raw_target=req.target,
            campaign_id=req.campaign_id,
            requested_tools=req.tools,
        )
        findings_count = manifest.get("consolidated_findings_count", 0)
        return {
            "status": "success",
            "message": f"Reconnaissance completed successfully. {findings_count} consolidated findings generated.",
            "manifest": manifest,
            "consolidated_findings_count": findings_count,
        }
    except ScopeViolation as e:
        raise HTTPException(status_code=403, detail=f"Scope violation: {e!s}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
