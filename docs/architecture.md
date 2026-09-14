# AI-Pentest Copilot - Architecture Overview

## Layer Separation (8 Layers)
1. `backend/`: FastAPI core, Context Engine, LLM Service, Ingest, Correlator, RAG.
2. `frontend/`: React 18, TypeScript, Monaco Editor, xterm.js terminal, IDE Chat.
3. `security/`: JSON Schemas, datasets, evaluation benchmarks, attack plans.
4. `toolkit/`: Reconnaissance tools, raw immutable evidence, structured JSON, command audit logs.
5. `shared/`: Single source of truth for FE <-> BE contracts.
6. `docs/`: Architecture, API reference, security model, and guides.
7. `infra/`: Docker, Docker Compose profiles, deployment scripts.
8. `scripts/`: Initialization and automation scripts.

## Dependency Rules
- `toolkit/` NEVER imports `backend/`.
- `security/` NEVER imports `backend/app`.
- `backend/` consumes `toolkit/` and `security/`.
- `frontend/` only accesses the Backend via HTTP/WebSocket APIs.
- `shared/` defines contracts across frontend and backend.
