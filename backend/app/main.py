"""FastAPI application entry point with REST endpoints and WebSocket chat."""

from __future__ import annotations

from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from backend.app.api.health import router as health_router
from backend.app.api.vulnerabilities import router as vuln_router
from backend.app.api.recon import router as recon_router
from backend.app.api.targets import router as targets_router
from backend.app.api.scans import router as scans_router
from backend.app.api.chat import router as chat_router
from backend.app.api.llm import router as llm_router
from backend.app.api.findings import router as findings_router
from backend.app.api.verification import router as verification_router
from backend.app.api.reports import router as reports_router
from backend.app.ws.chat import ws_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup hooks
    yield
    # Shutdown hooks


app = FastAPI(
    title="AI-Pentest Copilot Backend",
    version="1.0.0",
    description="Knowledge Base, Dynamic Target Recon & RAG Copilot API",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register REST Routers
app.include_router(health_router, prefix="/api")
app.include_router(vuln_router, prefix="/api")
app.include_router(recon_router, prefix="/api")
app.include_router(targets_router, prefix="/api")
app.include_router(scans_router, prefix="/api")
app.include_router(chat_router, prefix="/api/chat")
app.include_router(llm_router, prefix="/api/llm")
app.include_router(findings_router, prefix="/api")
app.include_router(verification_router, prefix="/api")
app.include_router(reports_router, prefix="/api")

# Register WebSocket Routers
app.include_router(ws_router)


@app.get("/health")
def health_check():
    return {"status": "ok", "service": "ai-pentest-copilot-backend"}
