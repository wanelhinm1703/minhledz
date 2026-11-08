# Toolkit Documentation — Integrated Original Pentest Toolset

## 1. Overview

AI-Pentest Copilot integrates a comprehensive, production-grade penetration testing toolset across five primary reconnaissance and assessment categories:
1. **Network Discovery & Port Scanning**
2. **Web Probing & Content Discovery**
3. **Vulnerability Assessment & Exploit Reference**
4. **Service Enumeration & Target Fingerprinting**
5. **Proxy Configuration & Manual Testing Workflow**

All tools conform to the project's strict architectural principles:
- **Zero Simulation in Production**: Missing binaries fail safely (`exit_code != 0`, `ToolNotInstalled`), logging clear diagnostic messages.
- **Immutable Raw Evidence**: Raw CLI tool outputs (`.xml`, `.jsonl`, `.txt`) are forensically stored under immutable category directories in `toolkit/`.
- **Standardized Structured Parsing**: Every tool runner feeds into an associated schema-validated JSON parser under `security/schemas/`.
- **Command Audit Logging**: Every invocation is recorded in `toolkit/<category>/commands.md`.
- **Read-Only / Non-Destructive Guardrails**: Offensive exploitation, brute forcing, and invasive scripts are strictly blocked or restricted to safe inspection.

---

## 2. Supported Tools Matrix

| Category | Tool ID | Binary | Purpose | Evidence Subdirectory | Schema |
|---|---|---|---|---|---|
| **Network** | `nmap` | `nmap` / `nmap.exe` | Port scanning, OS & service version detection, safe NSE | `toolkit/03-network/nmap/` | `nmap_scan_result.schema.json` |
| **Network** | `masscan` | `masscan` | High-rate asynchronous TCP port scanning | `toolkit/03-network/masscan/` | `masscan_result.schema.json` |
| **Network** | `rustscan` | `rustscan` | Modern fast port scanner with Nmap piping | `toolkit/03-network/rustscan/` | `rustscan_result.schema.json` |
| **Network** | `naabu` | `naabu` | Fast SYN/Connect port discovery (preserved) | `toolkit/03-network/naabu/` | `naabu_scan_result.schema.json` |
| **Web** | `httpx` | `httpx` | Fast multi-purpose HTTP probing & tech detection | `toolkit/04-web/httpx/` | `httpx_scan_result.schema.json` |
| **Web** | `whatweb` | `whatweb` | Web technology & CMS fingerprinting | `toolkit/04-web/whatweb/` | `whatweb_result.schema.json` |
| **Web** | `nikto` | `nikto` / `nikto.pl` | Web server vulnerability & misconfiguration scanning | `toolkit/04-web/nikto/` | `nikto_result.schema.json` |
| **Web** | `gobuster` | `gobuster` | Directory & file enumeration | `toolkit/04-web/gobuster/` | `gobuster_result.schema.json` |
| **Web** | `ffuf` | `ffuf` | High-speed web fuzzer and path discoverer | `toolkit/04-web/ffuf/` | `ffuf_result.schema.json` |
| **Web** | `katana` | `katana` | Next-generation web crawler and spider | `toolkit/04-web/katana/` | `katana_result.schema.json` |
| **Vulnerability** | `nuclei` | `nuclei` | Fast template-based vulnerability assessment | `toolkit/05-vulnerability/nuclei/` | `nuclei_scan_result.schema.json` |
| **Vulnerability** | `searchsploit` | `searchsploit` | Offline Exploit-DB title & CVE reference lookup | `toolkit/05-vulnerability/searchsploit/` | `searchsploit_result.schema.json` |
| **Service Enum** | `enum4linux` | `enum4linux` / `enum4linux.pl` | Windows/Samba information enumeration | `toolkit/06-service-enum/enum4linux/` | `service_enum_result.schema.json` |
| **Service Enum** | `smbclient` | `smbclient` | SMB share listing & null session verification | `toolkit/06-service-enum/smbclient/` | `service_enum_result.schema.json` |
| **Service Enum** | `snmpwalk` | `snmpwalk` | SNMP MIB tree query & OID enumeration | `toolkit/06-service-enum/snmpwalk/` | `service_enum_result.schema.json` |
| **Service Enum** | `ldapsearch` | `ldapsearch` | LDAP directory service querying | `toolkit/06-service-enum/ldapsearch/` | `service_enum_result.schema.json` |
| **Service Enum** | `database` | `mysql`/`psql`/`redis-cli`/`mongosh`/`sqlcmd` | Database banner grabbing and read-only status | `toolkit/06-service-enum/database/` | `service_enum_result.schema.json` |
| **Manual/Proxy** | `burpsuite` | `burpsuite` | HTTP proxy setup & scope configuration | `toolkit/08-manual/burpsuite/` | `proxy_manual.schema.json` |
| **Manual/Proxy** | `zap` | `zap.sh` / `zap.bat` | OWASP ZAP proxy setup & context configuration | `toolkit/08-manual/zap/` | `proxy_manual.schema.json` |

---

## 3. Tool Details & Execution Profiles

### 3.1 Network Discovery

#### Nmap (`run_nmap.py`, `parse_nmap.py`)
- **Profiles**:
  - `default`: `-sS -sV -T3 -F`
  - `stealth`: `-sS -sV -T2 --randomize-hosts`
  - `fast`: `-sS -sV -T4 -F`
  - `comprehensive`: `-sS -sV -O -p-`
  - `safe_nse`: `-sV --script="banner,default and safe"`
- **Inputs**: Target IP, CIDR, or hostname.
- **Outputs**:
  - Raw: `toolkit/03-network/nmap/raw/<target>_nmap.xml` and `.nmap`
  - Structured: `toolkit/03-network/nmap/structured/<target>_nmap.json`

#### Masscan (`run_masscan.py`, `parse_masscan.py`)
- **Profiles**:
  - `default`: `--rate=1000 -p1-1000`
  - `stealth`: `--rate=100 -p1-1000`
  - `fast`: `--rate=5000 -p1-10000`
  - `comprehensive`: `--rate=2000 -p1-65535`
- **Output Formats**: `-oJ` (JSON output).
- **Safety**: Masscan requires user confirmation (`requires_user_confirmation: true`) due to high packet generation rate.

#### RustScan (`run_rustscan.py`, `parse_rustscan.py`)
- **Profiles**:
  - `default`: `-b 1000 -t 1500 -- -sV`
  - `stealth`: `-b 200 -t 3000 -- -sV`
  - `fast`: `-b 2500 -t 1000 -- -sV`
  - `comprehensive`: `-b 1500 -t 2000 -- -sV -sC -O`
- **Output Formats**: `--greppable` output parsed into port arrays and service details.

---

### 3.2 Web Enumeration & Crawling

#### WhatWeb (`run_whatweb.py`, `parse_whatweb.py`)
- **Profiles**:
  - `stealth`: `-a 1` (passive header inspection)
  - `default`: `-a 3` (standard active probing)
  - `comprehensive`: `-a 4` (heavy probing)
- **Output**: JSON output format (`--log-json`). Captures server headers, frameworks, CMS version, plugins, and hashes.

#### Nikto (`run_nikto.py`, `parse_nikto.py`)
- **Profiles**:
  - `default`: `-Tuning 1234b`
  - `stealth`: `-Tuning 1 -evasion 1`
  - `comprehensive`: `-Tuning 1234567890abc`
- **Output**: JSON output (`-Format json -output <path>`). Captures outdated server components, security headers, sensitive files, and misconfigurations.

#### Gobuster (`run_gobuster.py`, `parse_gobuster.py`)
- **Profiles**:
  - `default`: `-t 10`
  - `stealth`: `-t 2 --delay 500ms`
  - `fast`: `-t 25`
- **Wordlist Handling**: Built-in fallback wordlist if external wordlist (`common.txt` / `dirb`) is not present.
- **Output**: Extracted status codes, URLs, and discovered routes.

#### FFUF (`run_ffuf.py`, `parse_ffuf.py`)
- **Profiles**:
  - `default`: `-rate 50 -mc 200,204,301,302,307,401,403`
  - `stealth`: `-rate 10 -p 0.5`
  - `fast`: `-rate 150`
- **Output**: JSON output (`-o <path> -of json`).

#### Katana (`run_katana.py`, `parse_katana.py`)
- **Profiles**:
  - `default`: `-depth 3 -concurrency 5`
  - `stealth`: `-depth 2 -concurrency 2 -delay 1`
  - `fast`: `-depth 3 -concurrency 15`
- **Output**: Structured JSON lines with endpoints, request methods, and parameters.

---

### 3.3 Vulnerability & Service Enumeration

#### SearchSploit (`run_searchsploit.py`, `parse_searchsploit.py`)
- **Execution**: Read-only reference querying via `--json <query>`.
- **Safety**: Pure reference lookup. No exploit staging, compilation, or execution. Correlates identified software versions with Exploit-DB entries and CVE references.

#### Service Enumeration (`run_service_enum.py`, `parse_service_enum.py`)
- **SMB / Windows**:
  - `enum4linux -U -S <target>`: Gathers domain, workgroup, users, and share names.
  - `smbclient -L //<target> -N`: Enumerates SMB shares anonymously.
- **SNMP**:
  - `snmpwalk -v2c -c public <target> system`: Reads standard system MIB descriptions safely.
- **LDAP**:
  - `ldapsearch -x -H ldap://<target> -b "" -s base namingContexts`: Inspects directory naming contexts.
- **Database Clients**:
  - Queries banners and status read-only (e.g. `mysql -h <target> -e "STATUS;"`, `redis-cli -h <target> INFO`).

---

### 3.4 Proxy & Manual Testing

#### Burp Suite & OWASP ZAP (`run_proxy_manual.py`)
- **Functionality**:
  - Generates ready-to-import proxy upstream configuration.
  - Generates strict in-scope target URL definitions for Burp Suite project files (`burpsuite_project_config.json`) and OWASP ZAP context files (`zap_context.xml`).
  - Prepares browser proxy instructions (HTTP 127.0.0.1:8080).
- **Safety**: Strictly manual and non-destructive. No automated attacking spiders or active fuzzing engines are launched.

---

## 4. Availability & Health Verification

Tool availability is dynamically detected in real-time via the API:
```http
GET /api/scans/tools
```
Or via Python:
```python
from backend.app.services.tool_registry import check_tool_availability
status = check_tool_availability("nmap")
```

When a tool binary is not installed on the system:
- The system returns `installed: False`.
- In production scanning pipelines (`simulate=False`), execution returns exit code 127 with diagnostic status `unavailable` and safe failure messages.
- The pipeline skips missing tools gracefully without interrupting other available tools or generating mock evidence.

---

## 5. Conflict Resolution Mechanism

When multiple tools report conflicting findings (e.g., Nmap identifying `Apache 2.4.49` on port 80 while WhatWeb identifies `Apache 2.4.51`):
1. **Context Engine** runs `detect_conflicts(evidence_dict)`.
2. Conflicting attributes are isolated with tool source names and detected values.
3. The Copilot Chat alerts the operator with a high-priority warning:
   > `Tool Conflict Detected: nmap reports 'Apache 2.4.49' while whatweb reports 'Apache 2.4.51'. Verification probe required.`
4. The system recommends running a non-destructive banner grab or verification probe to validate the exact version.
