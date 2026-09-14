from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from backend.app.services.scope_validator import ScopeViolation
from toolkit.scripts.pipeline_runner import run_pipeline

router = APIRouter(prefix="/recon", tags=["recon"])


class TriggerReconRequest(BaseModel):
    target: str
    campaign_id: str = "lab-local"


@router.post("/trigger")
def trigger_recon(req: TriggerReconRequest):
    try:
        manifest = run_pipeline(raw_target=req.target, campaign_id=req.campaign_id)
        return {
            "status": "success",
            "message": "Reconnaissance completed successfully.",
            "manifest": manifest,
        }
    except ScopeViolation as e:
        raise HTTPException(status_code=403, detail=f"Scope violation: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
