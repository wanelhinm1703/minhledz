"""Safe Read-Only Verification Planner enforcing non-destructive security validation."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Optional, List
from backend.app.schemas.finding import Finding
from backend.app.schemas.verification import VerificationPlan, VerificationStep, VerificationResult
from backend.app.storage.findings_db import findings_db


class VerificationPlanner:
    """Generates strictly non-destructive, read-only verification plans for findings."""

    SAFE_COMMAND_WHITELIST = ["curl", "nmap", "nc", "ping", "dig", "openssl"]
    DISALLOWED_PATTERNS = ["--os-shell", "meterpreter", "rm -rf", "drop table", "upload", "write", "eval"]

    def generate_plan(self, finding: Finding) -> VerificationPlan:
        ts = datetime.now(timezone.utc).isoformat()
        steps: List[VerificationStep] = []

        asset = finding.affected_asset
        # Extract host and port
        host = asset.split(":")[0].replace("http://", "").replace("https://", "").split("/")[0]
        port = "80"
        if ":" in asset:
            parts = asset.split(":")
            if len(parts) >= 2:
                port = parts[1].split("/")[0]

        # Step 1: Pre-condition connectivity check
        steps.append(
            VerificationStep(
                step_number=1,
                name="Reachability & Banner Inspection",
                description="Verify that the target port is actively responding and inspect the HTTP/service banner.",
                command=f"curl -s -I --connect-timeout 5 http://{asset}/",
                is_safe_readonly=True,
                expected_evidence="HTTP status line (e.g. HTTP/1.1 200 OK) with Server header matching the reported version.",
                remediation_check="ServerTokens configured to Prod / Min, suppressing granular software build numbers.",
            )
        )

        # Step 2: Targeted safe validation probe based on vulnerability type
        cve = (finding.cve_id or "").upper()
        if "CVE-2021-41773" in cve or "CVE-2021-42013" in cve:
            steps.append(
                VerificationStep(
                    step_number=2,
                    name="Safe Read-Only Path Traversal Probe",
                    description="Issue a read-only probe using percent-encoded traversal sequence to observe if document root restriction is bypassed.",
                    command=f"curl -s --path-as-is http://{asset}/icons/.%%32%65/.%%32%65/etc/passwd -o /dev/null -w '%{{http_code}}'",
                    is_safe_readonly=True,
                    expected_evidence="HTTP 200 with file content indicates vulnerability. HTTP 400 or 403/404 indicates mitigated state.",
                    remediation_check="Returns HTTP 403 Forbidden or HTTP 400 Bad Request after patching to Apache 2.4.51+.",
                )
            )
        elif "CWE-22" in (finding.cwe_id or ""):
            steps.append(
                VerificationStep(
                    step_number=2,
                    name="Path Traversal Boundary Probe",
                    description="Verify path normalization without retrieving sensitive files or writing data.",
                    command=f"curl -s -I http://{asset}/..%2f..%2findex.html",
                    is_safe_readonly=True,
                    expected_evidence="Server responds with 403 Forbidden or 400 Bad Request on normalized traversal sequences.",
                    remediation_check="Path is strictly sanitized before filesystem resolution.",
                )
            )
        elif "SSH" in finding.title.upper() or "22" in port:
            steps.append(
                VerificationStep(
                    step_number=2,
                    name="Passive SSH Banner Audit",
                    description="Passively read the SSH daemon identification banner without initiating authentication.",
                    command=f"nc -v -w 3 {host} {port}",
                    is_safe_readonly=True,
                    expected_evidence="SSH-2.0 banner disclosing exact daemon implementation and patch level.",
                    remediation_check="Banner reflects updated SSH package version.",
                )
            )
        else:
            # Generic safe HTTP / port audit
            steps.append(
                VerificationStep(
                    step_number=2,
                    name="Passive Service Fingerprint Probe",
                    description="Send safe HTTP OPTIONS or GET request to verify server response behavior.",
                    command=f"curl -s -X OPTIONS -I http://{asset}/",
                    is_safe_readonly=True,
                    expected_evidence="Supported HTTP methods and server headers.",
                    remediation_check="Insecure methods (e.g. PUT, DELETE, TRACE) are disabled.",
                )
            )

        # Step 3: Post-verification non-regression check
        steps.append(
            VerificationStep(
                step_number=3,
                name="Service Availability Confirmation",
                description="Confirm service remains fully operational with zero disruption after verification checks.",
                command=f"curl -s -o /dev/null -w '%{{http_code}}' http://{asset}/",
                is_safe_readonly=True,
                expected_evidence="Normal HTTP response code (200, 301, or 302).",
                remediation_check="Service availability uptime remains 100%.",
            )
        )

        return VerificationPlan(
            finding_id=finding.id,
            target_id=finding.target_id,
            title=finding.title,
            cve_id=finding.cve_id,
            affected_asset=finding.affected_asset,
            rationale=f"Validation plan specifically designed for {finding.title} on {finding.affected_asset} strictly following read-only principles.",
            steps=steps,
            created_at=ts,
        )

    def execute_safe_check(self, command: str) -> VerificationResult:
        """Simulate or execute a strictly read-only validation command."""
        # Validate command against safety rules
        cmd_lower = command.lower()
        if any(bad in cmd_lower for bad in self.DISALLOWED_PATTERNS):
            return VerificationResult(
                finding_id="",
                step_number=0,
                command=command,
                output="[ERROR] Command contains potentially unsafe or destructive patterns. Execution aborted.",
                status="BLOCKED",
                is_vulnerable_indicated=False,
                timestamp=datetime.now(timezone.utc).isoformat(),
            )

        # Simulated high-fidelity execution
        output = f"[+] Executing safe read-only command: {command}\n"
        if "icons/.%32e" in command or "icons/.%%32%65" in command or "icons" in command:
            output += (
                "HTTP/1.1 200 OK\n"
                "Server: Apache/2.4.49 (Unix)\n"
                "Content-Type: text/plain\n\n"
                "root:x:0:0:root:/root:/bin/bash\n"
                "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
            )
            is_vuln = True
        elif "-I" in command:
            output += (
                "HTTP/1.1 200 OK\n"
                "Server: Apache/2.4.49 (Unix)\n"
                "Content-Type: text/html\n"
            )
            is_vuln = True
        else:
            output += "HTTP Status: 200\n[+] Service responded normally."
            is_vuln = False

        return VerificationResult(
            finding_id="",
            step_number=1,
            command=command,
            output=output,
            status="SUCCESS",
            is_vulnerable_indicated=is_vuln,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )


verification_planner = VerificationPlanner()
