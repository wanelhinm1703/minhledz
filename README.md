# AI-Pentest Copilot (v5.0 — Dynamic Target + Integrated Pentest Toolset)

> **Full-Stack Security Workbench + AI Copilot + IDE Chat + Vulnerability Knowledge Base**

---

## 1. System Overview & Architecture

AI-Pentest Copilot is a modular, defense-oriented security assessment platform designed to assist penetration testers and security researchers. It unifies dynamic target discovery, multi-tool reconnaissance orchestration with the official pentest toolset (Nmap, Masscan, RustScan, HTTPx, WhatWeb, Nikto, Gobuster, FFUF, Katana, Nuclei, SearchSploit, enum4linux, smbclient, snmpwalk, ldapsearch, database clients, Burp Suite, OWASP ZAP), an authoritative offline Vulnerability Knowledge Base (539 CVEs / 52 CWEs), strict anti-exploitation guardrails, real-time RAG IDE chat, cross-tool conflict detection, and automated pentest report generation.

```
+-----------------------------------------------------------------------------------------+
|                                    WEB IDE FRONTEND                                     |
|  +------------------------+  +-------------------------------+  +---------------------+ |
|  |     Explorer Panel     |  |   Tabbed Editor / Findings    |  |  IDE Chat Copilot   | |
|  | - Target Registry      |  | - Raw XML/JSONL viewer        |  | - Real-time WS      | |
|  | - Evidence Manifests   |  | - Findings Manager            |  | - Source citations  | |
|  | - Scan Trees & Tools   |  | - Pentest Report (MD / HTML)  |  | - Tool conflict alert|
|  +------------------------+  +-------------------------------+  +---------------------+ |
|  +------------------------------------------------------------------------------------+ |
|  |                       Interactive Terminal / Execution Logs                        | |
|  +------------------------------------------------------------------------------------+ |
+--------------------------------------------+--------------------------------------------+
                                             | WebSocket / REST (/api)
+--------------------------------------------v--------------------------------------------+
                                    FASTAPI BACKEND CORE                                  |
|  +-----------------------+  +--------------------------+  +---------------------------+ |
|  |   Target Management   |  |  Recon Orchestrator      |  |  Vulnerability KB & RAG   | |
|  | - TargetParser        |  | - Multi-tool Runner      |  | - SQLite KB (CVE/CWE)     | |
|  | - ScopeValidator      |  | - 16 Supported Tools     |  | - Semantic Version Tuple  | |
|  | - Dynamic Registry    |  | - Service-driven Routing |  | - Correlator Engine       | |
|  +-----------------------+  +--------------------------+  +---------------------------+ |
|  +-----------------------+  +--------------------------+  +---------------------------+ |
|  |  Security Guardrails  |  |  Findings & Conflicts    |  |  Verification & Reports   | |
|  | - Anti-Exploitation   |  | - Auto-Aggregator        |  | - Safe Read-Only Planner  | |
|  | - Anti-Hallucination  |  | - Cross-Tool Conflict Det|  | - Non-destructive Probes  | |
|  | - Fact/Hypothesis     |  | - Evidence Chain Linker  |  | - Markdown & HTML Report  | |
|  +-----------------------+  +--------------------------+  +---------------------------+ |
+--------------------------------------------+--------------------------------------------+
                                             | Reads / Appends
+--------------------------------------------v--------------------------------------------+
|                               IMMUTABLE TOOLKIT REPOSITORY                              |
|  - toolkit/01-targets/      -> Target definitions, dynamic registry                      |
|  - toolkit/03-network/      -> Nmap, Masscan, RustScan, Naabu (raw + structured + audit) |
|  - toolkit/04-web/          -> HTTPx, WhatWeb, Nikto, Gobuster, FFUF, Katana             |
|  - toolkit/05-vulnerability/-> Nuclei, SearchSploit, Nmap Safe NSE                       |
|  - toolkit/06-service-enum/ -> enum4linux, smbclient, snmpwalk, ldapsearch, DB clients   |
|  - toolkit/08-manual/       -> Burp Suite & OWASP ZAP configs & scope definitions        |
|  - toolkit/09-analysis/     -> Evidence manifests, correlated findings                   |
|  - toolkit/10-reports/      -> Generated assessment reports (.md & .html)                |
+-----------------------------------------------------------------------------------------+
```

---

## 2. Integrated Pentest Toolset Matrix

| Category | Primary Tools | Secondary / Specialized Tools | Evidence Paths |
|---|---|---|---|
| **Network Discovery** | **Nmap** (version, safe NSE), **Masscan** (fast SYN), **RustScan** (adaptive) | Naabu (preserved) | `toolkit/03-network/{tool}/raw` & `structured/` |
| **Web Probing & Crawling** | **HTTPx** (probing), **WhatWeb** (tech/CMS), **Nikto** (server scan) | **Gobuster**, **FFUF**, **Katana** | `toolkit/04-web/{tool}/raw` & `structured/` |
| **Vulnerability Assessment** | **Nuclei** (templates), **Nmap NSE** (safe scripts) | **SearchSploit** (read-only reference) | `toolkit/05-vulnerability/{tool}/` |
| **Service Enumeration** | **enum4linux**, **smbclient** (SMB) | **snmpwalk** (SNMP), **ldapsearch** (LDAP), **DB clients** | `toolkit/06-service-enum/{tool}/` |
| **Manual / Proxy** | **Burp Suite**, **OWASP ZAP** | Scope configs, project files, upstream routing | `toolkit/08-manual/{tool}/` |

---

## 3. Core Guardrails & Safety Principles

1. **Strict NO Automated Exploitation**:
   - The platform strictly forbids automated weaponization or exploitation.
   - Any query attempting automated exploit (`exploit target`, `reverse shell`, `sqlmap --os-shell`) immediately triggers a **`GUARDRAIL REFUSAL`**, redirecting the operator toward root cause analysis and non-destructive validation plans.
2. **Authorized Scope Enforcement**:
   - Targets are checked against `ALLOWED_SCOPES` (RFC 1918 Private IPv4: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `localhost`, `*.local`).
   - Public IPs (e.g. `8.8.8.8`) are blocked unconditionally.
3. **Anti-Hallucination & Evidence Grounding**:
   - The Copilot never invents CVE IDs, CWE IDs, affected versions, or CVSS scores.
   - If evidence is lacking, the engine explicitly states: *"Insufficient evidence in current scan results or knowledge base to confirm vulnerabilities"*.
4. **Cross-Tool Conflict Detection**:
   - When tools report contradictory information (e.g. Nmap reporting Apache 2.4.49 vs WhatWeb reporting Apache 2.4.51), the Context Engine isolates the discrepancy and alerts the operator to execute a verification probe.
5. **Immutable Evidence Integrity**:
   - Raw scan outputs are treated as forensic records: never overwritten, always logged with exact CLI arguments and timestamps in `commands.md`.
6. **Graceful Binary Degradation**:
   - Missing tool binaries return exit code 127 with diagnostic `ToolNotInstalled` status. The system never fabricates fake open ports or mock services in production.

---

## 4. Quickstart & Installation

### Prerequisites
- Python 3.10+ (Tested on Python 3.14)
- Node.js 18+ (Tested on Node v24.19)
- Git
- Pentest tools (optional on host — missing tools fail gracefully and safe checks verify their absence).

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

## 5. Running the System

You can control all capabilities using the cross-platform universal CLI runner `run.py` or `make.bat`:

### 1. Ingest Knowledge Base
Populate the SQLite Vulnerability Knowledge Base (539 CVEs, 52 CWEs):
```bash
python run.py ingest
```

### 2. Run All Automated Tests
Run the comprehensive test suite (76 tests across M0 to M7 + Original Tools + Tool Registry):
```bash
python run.py test
# or: py -3.14 -m pytest backend/tests -v
```

### 3. Run Reconnaissance Pipeline
Trigger the multi-tool recon pipeline for a dynamic target:
```bash
python run.py pipeline 192.168.56.101
python run.py pipeline http://192.168.56.101:3000
```

### 4. Launch Full Development Environment
Start both the FastAPI backend (`http://localhost:8000`) and the Vite React frontend (`http://localhost:5173`):
```bash
python run.py dev
```

---

## 6. Live Demo Walkthrough

### Scenario 1: Dynamic Target Discovery & Correlation
1. Open the UI at `http://localhost:5173`.
2. Click **"Add Target"** and enter `http://192.168.56.101:3000`.
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

### Scenario 4: Tool Conflict Detection
1. When WhatWeb and Nmap detect differing software versions on the same target port:
2. The Context Engine surfaces:
   ```text
   [WARNING] Tool Conflict Detected: nmap reports 'Apache 2.4.49' while whatweb reports 'Apache 2.4.51'. Verification probe required.
   ```
3. A safe banner grab plan is generated to resolve the ambiguity.

### Scenario 5: Findings Management & Safe Validation
1. Switch to the **"Findings Manager"** tab in the top navigation.
2. Click **"Auto-Generate from Scans"**.
3. Observe deduplicated findings with severity pills and immutable evidence chains.
4. Select `Apache 2.4.49 — CVE-2021-41773`:
   - Inspect the **Safe Read-Only Verification Plan**.
   - Click **"Run Safe Check"** to execute the non-destructive probe.
   - Terminal output confirms the finding safely.
   - Click **"Mark Verified"** to promote the status to `VERIFIED`.

### Scenario 6: Assessment Reporting
1. Switch to the **"Pentest Report"** tab.
2. Click **"Generate Full Report"**.
3. Toggle between **Markdown View** and **Styled HTML Preview**.
4. Download or copy the comprehensive report containing Executive Summary, Risk Breakdown, Evidence Annex, and Remediation Roadmap.

---

## 7. Delivery & Test Matrix

| Category | Components | Tests | Status |
|---|---|---|---|
| **Target Pipeline & Ingestion** | Parser, Normalizer, Scope Validator, Target Registry | 12 | **PASS** |
| **Original Tool Runners & Parsers** | Masscan, RustScan, WhatWeb, Nikto, Gobuster, FFUF, Katana, SearchSploit, enum4linux, smbclient, snmpwalk, ldapsearch, DB clients, Proxy Manual | 11 | **PASS** |
| **Tool Registry & Availability** | Registry definitions, live binary check, `/api/scans/tools` | 3 | **PASS** |
| **Recon Planner & Routing** | Service-driven routing, explicit user tool selection, conflict detection | 4 | **PASS** |
| **Recon Pipeline (Preserved)** | Naabu, Nmap, HTTPx, Nuclei, Scope violation | 6 | **PASS** |
| **Vulnerability KB & Correlator** | 539 CVEs / 52 CWEs, Semantic Version Tuple, Correlator API | 9 | **PASS** |
| **Security Guardrails & RAG Chat** | Anti-Exploit, Anti-Hallucination, Context Priority, Chat DB, WS streaming | 9 | **PASS** |
| **Findings Manager & Evidence** | Deduplication, CRUD, Auto-generation from scans | 5 | **PASS** |
| **Verification & Reporting** | Non-destructive verification planner, MD/HTML pentest report | 4 | **PASS** |
| **Terminal API & Security** | Safe presets, whitelist command execution, guardrail refusal | 6 | **PASS** |
| **Target & Scan REST APIs** | Target CRUD, scan listing, directory traversal protection | 6 | **PASS** |
| **End-to-End Lifecycle** | Full target-to-report lifecycle integration test | 1 | **PASS** |
| **Total** | **Unified Security Workbench Platform** | **76** | **100% PASS** |

---

*AI-Pentest Copilot — Designed for rigorous, verifiable, and responsible security research.*
