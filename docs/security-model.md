# Security Model & Guardrails

## Core Guardrail Rules
1. **NO Automated Exploitation**: The AI assistant strictly performs analysis, verification steps, and read-only plan generation.
2. **Immutable Raw Evidence**: Tool outputs (`.xml`, `.nmap`, etc.) are immutable once written.
3. **Command Auditing**: Every command executed is logged to `commands.md` with timestamp, tool, arguments, duration, and exit code.
4. **No Hallucination**: AI must NEVER invent CVEs, CWEs, versions, CVSS scores, or source URLs.
5. **Strict Scope Validation**: Targets outside authorized scopes are blocked unconditionally before scanning.
