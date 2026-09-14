from __future__ import annotations

import pathlib
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.app.config import settings
from backend.app.storage.db import db
from backend.app.api import health, vulnerabilities

from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Ensure database schema is initialized on startup
    db.init_db()
    yield

app = FastAPI(
    title="AI-Pentest Copilot API",
    description="Security Workbench + AI Copilot + IDE Chat + Vulnerability Knowledge Base API",
    version=settings.VERSION,
    lifespan=lifespan,
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register Routers
app.include_router(health.router, prefix=settings.API_V1_STR)
app.include_router(vulnerabilities.router, prefix=settings.API_V1_STR)


@app.get("/")
def root():
    return {
        "message": "AI-Pentest Copilot Backend API is running.",
        "docs": "/docs",
        "health": f"{settings.API_V1_STR}/health",
    }
