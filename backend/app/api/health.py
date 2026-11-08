from __future__ import annotations

from fastapi import APIRouter

from backend.app.config import settings
from backend.app.storage.db import db

router = APIRouter(prefix="/health", tags=["health"])


@router.get("")
def check_health():
    stats = db.get_stats()
    return {
        "status": "ok",
        "version": settings.VERSION,
        "database": {
            "cve_count": stats["cve_count"],
            "cwe_count": stats["cwe_count"],
        },
    }
