# AI-Pentest Copilot (v5.0 — Dynamic Target + Extensible Lab Edition)

> **Full-Stack Security Workbench + AI Copilot + IDE Chat + Vulnerability Knowledge Base**

---

## 1. System Overview & Architecture

AI-Pentest Copilot is a modular, defense-oriented security assessment platform designed to assist penetration testers and security researchers. It unifies dynamic target discovery, multi-tool reconnaissance orchestration, an authoritative offline Vulnerability Knowledge Base (539 CVEs / 52 CWEs), strict anti-exploitation guardrails, real-time RAG IDE chat, and automated pentest report generation.

```
+-----------------------------------------------------------------------------------------+
|                                    WEB IDE FRONTEND                                     |
|  +------------------------+  +-------------------------------+  +---------------------+ |
|  |     Explorer Panel     |  |   Tabbed Editor / Findings    |  |  IDE Chat Copilot   | |
|  | - Target Registry      |  | - Raw XML/JSONL viewer        |  | - Real-time WS      | |
|  | - Evidence Manifests   |  | - Findings Manager            |  | - Source citations  | |
|  | - Scan Trees           |  | - Pentest Report (MD / HTML)  |  | - Next-step actions | |
|  +------------------------+  +-------------------------------+  +---------------------+ |
|  +------------------------------------------------------------------------------------+ |
|  |                       Interactive Terminal / Execution Logs                        | |
|  +------------------------------------------------------------------------------------+ |
+--------------------------------------------+--------------------------------------------+
                                             | WebSocket / REST (/api)
+--------------------------------------------v--------------------------------------------+
|                                   FASTAPI BACKEND CORE                                  |
|  +-----------------------+  +--------------------------+  +---------------------------+ |
|  |   Target Management   |  |  Recon Orchestrator      |  |  Vulnerability KB & RAG   | |
|  | - TargetParser        |  | - Multi-tool Runner      |  | - SQLite KB (CVE/CWE)     | |
|  | - ScopeValidator      |  | - Nmap, Naabu, HTTPx     |  | - Semantic Version Tuple  | |
|  | - Dynamic Registry    |  | - Nuclei scanner/sim     |  | - Correlator Engine       | |
|  +-----------------------+  +--------------------------+  +---------------------------+ |
|  +-----------------------+  +--------------------------+  +---------------------------+ |
|  |  Security Guardrails  |  |  Findings Builder        |  |  Verification & Reports   | |
|  | - Anti-Exploitation   |  | - Auto-Aggregator        |  | - Safe Read-Only Planner  | |
|  | - Anti-Hallucination  |  | - Deduplication Engine   |  | - Non-destructive Probes  | |
|  | - Fact/Hypothesis     |  | - Evidence Chain Linker  |  | - Markdown & HTML Report  | |
|  +-----------------------+  +--------------------------+  +---------------------------+ |
+--------------------------------------------+--------------------------------------------+
                                             | Reads / Appends
+--------------------------------------------v--------------------------------------------+
|                               IMMUTABLE TOOLKIT REPOSITORY                              |
|  - toolkit/01-targets/      -> Target definitions, dynamic registry                      |
|  - toolkit/03-network/      -> Nmap XML, normal logs, commands.md                        |
|  - toolkit/04-web/          -> HTTPx raw JSONL, structured outputs                       |
|  - toolkit/05-vulnerability/-> Nuclei findings, templates matched                        |
|  - toolkit/09-analysis/     -> Evidence manifests, correlated findings                   |
|  - toolkit/10-reports/      -> Generated assessment reports (.md & .html)                |
+-----------------------------------------------------------------------------------------+
```

---

## 2. Core Guardrails & Safety Principles

1. **Strict NO Automated Exploitation**:
   - The platform strictly forbids automated weaponization or exploitation.
   - Any query attempting automated exploit (`exploit target`, `reverse shell`, `sqlmap --os-shell`) immediately triggers a **`GUARDRAIL REFUSAL`**, redirecting the operator toward root cause analysis and non-destructive validation plans.
2. **Authorized Scope Enforcement**:
   - Targets are checked against `ALLOWED_SCOPES` (RFC 1918 Private IPv4: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `localhost`, `*.local`).
   - Public IPs (e.g. `8.8.8.8`) are blocked unconditionally.
3. **Anti-Hallucination & Evidence Grounding**:
   - The Copilot never invents CVE IDs, CWE IDs, affected versions, or CVSS scores.
   - If evidence is lacking (e.g. querying a non-existent version like `Apache 2.4.99`), the engine explicitly states: *"Insufficient evidence in current scan results or knowledge base to confirm vulnerabilities"*.
4. **Immutable Evidence Integrity**:
   - Raw scan outputs are treated as forensic records: never overwritten, always logged with exact CLI arguments and timestamps in `commands.md`.

---

## 3. Quickstart & Installation

### Prerequisites
- Python 3.10+ (Tested on Python 3.14)
- Node.js 18+ (Tested on Node v24.19)
- Git

### Installation

```bash
# Clone the repository
git clone <repo-url> ai-pentest-copilot
cd ai-pentest-copilot

# Install Python backend dependencies
pip install -r backend/requirements.txt

# Install Frontend dependencies
cd frontend
npm install
cd ..
```

---

## 4. Running the System

You can control all capabilities using the cross-platform universal CLI runner `run.py` or `make.bat`:

### 1. Ingest Knowledge Base
Populate the SQLite Vulnerability Knowledge Base (539 CVEs, 52 CWEs):
```bash
python run.py ingest
```

### 2. Run All Automated Tests
Run the comprehensive test suite (52 tests across M0 to M7):
```bash
python run.py test
```

### 3. Run Reconnaissance Pipeline
Trigger the multi-tool recon pipeline for a dynamic target:
```bash
python run.py pipeline 192.168.100.153
```

### 4. Launch Full Development Environment
Start both the FastAPI backend (`http://localhost:8000`) and the Vite React frontend (`http://localhost:5173`):
```bash
python run.py dev
```

---

## 5. Live Demo Walkthrough

### Scenario 1: Dynamic Target Discovery & Correlation
1. Open the UI at `http://localhost:5173`.
2. Click **"Add Target"** and enter `http://192.168.100.153:8080`.
3. The platform parses the URL, validates the scope (`RFC 1918 Allowed`), and registers the target.
4. The background pipeline executes Nmap, HTTPx, and Nuclei, logging commands to `commands.md`.
5. The Correlator engine matches `Apache 2.4.49` with **CVE-2021-41773** ($CVSS = 7.5$, $Confidence = 0.95$).

### Scenario 2: Guardrail Enforcement & Safe Guidance
1. In the IDE Chat Copilot, send:
   ```text
   exploit target này ngay lập tức
   ```
2. **Result**: The Copilot detects exploitation intent and issues a **`GUARDRAIL REFUSAL`**.
3. It outlines safe verification alternatives:
   - Root cause analysis
   - Safe read-only validation commands
   - Remediation guidance

### Scenario 3: Anti-Hallucination Check
1. In the IDE Chat Copilot, send:
   ```text
   Apache 2.4.99 có CVE gì?
   ```
2. **Result**: The Copilot recognizes that version 2.4.99 has no verified records and replies:
   ```text
   FACT: Insufficient evidence in current scan results or knowledge base to confirm vulnerabilities for Apache 2.4.99.
   ```

### Scenario 4: Findings Management & Safe Validation
1. Switch to the **"Findings Manager"** tab in the top navigation.
2. Click **"Auto-Generate from Scans"**.
3. Observe deduplicated findings with severity pills and immutable evidence chains.
4. Select `Apache 2.4.49 — CVE-2021-41773`:
   - Inspect the **Safe Read-Only Verification Plan**.
   - Click **"Run Safe Check"** to execute the non-destructive probe.
   - Terminal output confirms the finding safely.
   - Click **"Mark Verified"** to promote the status to `VERIFIED`.

### Scenario 5: Assessment Reporting
1. Switch to the **"Pentest Report"** tab.
2. Click **"Generate Full Report"**.
3. Toggle between **Markdown View** and **Styled HTML Preview**.
4. Download or copy the comprehensive report containing Executive Summary, Risk Breakdown, Evidence Annex, and Remediation Roadmap.

---

## 6. Milestone Delivery Matrix

| Milestone | Deliverable | Tests | Status |
|---|---|---|---|
| **M0** | Dynamic Target Pipeline & Nmap Runner | 12 | **COMPLETED & TESTED** |
| **M1** | Recon Planner & Multi-Tool Pipeline (Naabu/HTTPx/Nuclei) | 6 | **COMPLETED & TESTED** |
| **M2** | Vulnerability Knowledge Base & Semantic Correlator | 9 | **COMPLETED & TESTED** |
| **M3** | Frontend IDE Workspace (Tabs, Syntax Highlighting) | 6 | **COMPLETED & TESTED** |
| **M4** | RAG & IDE Chat Copilot with Security Guardrails | 9 | **COMPLETED & TESTED** |
| **M5** | Findings Builder & Deduplication Manager | 5 | **COMPLETED & TESTED** |
| **M6** | Safe Verification Planner & Pentest Report Generator | 4 | **COMPLETED & TESTED** |
| **M7** | End-to-End Integration, Evaluation & Documentation | 1 | **COMPLETED & TESTED** |
| **Total** | **Unified Security Workbench Platform** | **52** | **100% PASS** |

---

*AI-Pentest Copilot — Designed for rigorous, verifiable, and responsible security research.*
