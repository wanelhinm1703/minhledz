# Security Model & Guardrails

## Core Guardrail Rules

1. **NO Automated Exploitation**:
   - The AI assistant strictly performs analysis, verification steps, and read-only plan generation.
   - Any query attempting automated exploit execution (`exploit target`, `reverse shell`, `sqlmap --os-shell`) immediately triggers a `GUARDRAIL REFUSAL`.
   - Exploit tools (e.g. SearchSploit) are strictly limited to offline read-only metadata querying (`--json <search_term>`). Automated compiling, downloading, or running exploits is forbidden.

2. **Immutable Raw Evidence**:
   - Tool outputs (`.xml`, `.nmap`, `.jsonl`, `.txt`) are strictly immutable once written to forensically separated folders under `toolkit/`.
   - Manifests in `toolkit/09-analysis/manifests/` track cryptographic references and paths to raw and structured artifacts.

3. **Command Auditing**:
   - Every tool command executed by runners is logged to `toolkit/<category>/commands.md` with timestamp, tool, arguments, duration, and exit code.

4. **No Hallucination & Fact/Hypothesis Separation**:
   - The AI must NEVER invent CVEs, CWEs, software versions, CVSS scores, or source URLs.
   - If evidence is missing, the Copilot explicitly states insufficient evidence.

5. **Strict Scope Validation**:
   - Targets outside authorized scopes (`ALLOWED_SCOPES`: RFC1918 subnets `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `localhost`, `*.local`) are blocked unconditionally before scanning.

6. **Safety Profiles & Risk Management**:
   - High-rate or intrusive tools (such as Masscan or comprehensive NSE scripts) enforce operator confirmation (`requires_user_confirmation: true`).
   - Default profiles enforce non-destructive flags (e.g., Nmap safe NSE `--script="banner,default and safe"`).

7. **Zero Simulation in Production**:
   - Missing binaries return exit code 127 with diagnostic `ToolNotInstalled` status. The system never fabricates open ports or services when a tool is absent.
