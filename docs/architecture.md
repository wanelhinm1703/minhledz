# AI-Pentest Copilot - Architecture Overview

## Layer Separation (8 Layers)
1. `backend/`: FastAPI core, Context Engine, LLM Service, Ingest, Correlator, RAG, Recon Planner, Tool Registry, Findings Builder, and Report Generator.
2. `frontend/`: React 18, TypeScript, Monaco Editor, xterm.js terminal, IDE Chat Copilot, Findings Manager, Report Viewer.
3. `security/`: JSON Schemas for all original tools, CVE/CWE datasets, evaluation benchmarks, attack plans.
4. `toolkit/`: Reconnaissance tools, raw immutable evidence, structured JSON, command audit logs.
5. `shared/`: Single source of truth for FE <-> BE contracts, target types, and tool statuses.
6. `docs/`: Architecture, API reference, security model, target system, and toolkit guide.
7. `infra/`: Docker, Docker Compose profiles, deployment scripts.
8. `scripts/`: Initialization and automation scripts.

## Core Services & Extensions

### 1. Tool Registry & Availability (`backend/app/services/tool_registry.py`)
Centralized metadata definitions for all 16 supported tools across 5 categories:
- **Network**: Nmap (primary), Masscan (high-speed), RustScan (modern), Naabu (secondary preserved).
- **Web**: HTTPx (probing), WhatWeb (tech fingerprinting), Nikto (web server vuln), Gobuster (directory bruteforce), FFUF (web fuzzer), Katana (spider).
- **Vulnerability**: Nuclei (template assessment), Nmap Safe NSE, SearchSploit (exploit reference lookup).
- **Service Enum**: enum4linux (SMB), smbclient (shares), snmpwalk (SNMP), ldapsearch (LDAP), database clients (MySQL, Postgres, Redis, MongoDB, MSSQL).
- **Manual / Proxy**: Burp Suite & OWASP ZAP upstream configuration and scope generation.

Real-time binary detection checks system PATH and OS-specific standard binary locations (`shutil.which` + executable probing). Missing binaries fail gracefully (`installed: False`) without breaking the pipeline.

### 2. Recon Planner & Target Ingestion (`backend/app/services/recon_planner.py`)
- Automatically matches target capabilities (`IPV4`, `CIDR`, `URL`, `HOST_PORT`, `DOMAIN`) to appropriate toolsets.
- Service-driven discovery: automatically selects specialized service enumeration tools upon discovering relevant ports:
  - Port 445/139 -> `enum4linux`, `smbclient`
  - Port 161 -> `snmpwalk`
  - Port 389/636 -> `ldapsearch`
  - Ports 3306, 5432, 6379, 27017, 1433 -> Database clients
  - Discovered web services / versions -> `searchsploit`, `whatweb`, `nikto`
- Supports explicit operator tool selection (`requested_tools`).

### 3. Context Engine & Conflict Detection (`backend/app/core/context.py`)
- Discovers raw and structured evidence across all category directories (`03-network`, `04-web`, `05-vulnerability`, `06-service-enum`, `08-manual`).
- Detects version and service discrepancies across tools (e.g. Nmap reporting Apache 2.4.49 while WhatWeb reports Apache 2.4.51).
- Alerts the LLM and operator with explicit conflict warnings and recommended verification probes.

### 4. Dependency Rules
- `toolkit/` NEVER imports `backend/`.
- `security/` NEVER imports `backend/app`.
- `backend/` consumes `toolkit/` and `security/`.
- `frontend/` only accesses the Backend via HTTP/WebSocket APIs.
- `shared/` defines contracts across frontend and backend.
