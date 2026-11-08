"""Compliance Engine: Maps vulnerabilities and findings to international security standards.
Covers:
- OWASP Top 10 (2021 & 2025 preview)
- MITRE CWE Top 25 Most Dangerous Software Weaknesses
- NIST SP 800-115 (Technical Guide to Information Security Testing and Assessment)
- CIS Controls v8 (Critical Security Controls)
"""

from __future__ import annotations

from typing import Any


# 1. OWASP Top 10 (2021) Mapping from CWE IDs
OWASP_2021_MAPPING: dict[str, dict[str, str]] = {
    # A01:2021 - Broken Access Control
    "CWE-22": {"id": "A01:2021", "name": "Broken Access Control", "desc": "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')"},
    "CWE-284": {"id": "A01:2021", "name": "Broken Access Control", "desc": "Improper Access Control"},
    "CWE-285": {"id": "A01:2021", "name": "Broken Access Control", "desc": "Improper Authorization"},
    "CWE-639": {"id": "A01:2021", "name": "Broken Access Control", "desc": "Authorization Bypass Through User-Controlled Key (IDOR)"},
    "CWE-862": {"id": "A01:2021", "name": "Broken Access Control", "desc": "Missing Authorization"},
    "CWE-863": {"id": "A01:2021", "name": "Broken Access Control", "desc": "Incorrect Authorization"},
    "CWE-200": {"id": "A01:2021", "name": "Broken Access Control", "desc": "Exposure of Sensitive Information to an Unauthorized Actor"},

    # A02:2021 - Cryptographic Failures
    "CWE-259": {"id": "A02:2021", "name": "Cryptographic Failures", "desc": "Use of Hard-coded Password"},
    "CWE-319": {"id": "A02:2021", "name": "Cryptographic Failures", "desc": "Cleartext Transmission of Sensitive Information"},
    "CWE-326": {"id": "A02:2021", "name": "Cryptographic Failures", "desc": "Inadequate Encryption Strength"},
    "CWE-327": {"id": "A02:2021", "name": "Cryptographic Failures", "desc": "Use of a Broken or Risky Cryptographic Algorithm"},
    "CWE-330": {"id": "A02:2021", "name": "Cryptographic Failures", "desc": "Use of Insufficiently Random Values"},

    # A03:2021 - Injection
    "CWE-78": {"id": "A03:2021", "name": "Injection", "desc": "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')"},
    "CWE-79": {"id": "A03:2021", "name": "Injection", "desc": "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')"},
    "CWE-89": {"id": "A03:2021", "name": "Injection", "desc": "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')"},
    "CWE-77": {"id": "A03:2021", "name": "Injection", "desc": "Improper Neutralization of Special Elements used in a Command ('Command Injection')"},
    "CWE-94": {"id": "A03:2021", "name": "Injection", "desc": "Improper Control of Generation of Code ('Code Injection')"},

    # A04:2021 - Insecure Design
    "CWE-209": {"id": "A04:2021", "name": "Insecure Design", "desc": "Generation of Error Message Containing Sensitive Information"},
    "CWE-256": {"id": "A04:2021", "name": "Insecure Design", "desc": "Unprotected Storage of Credentials"},
    "CWE-501": {"id": "A04:2021", "name": "Insecure Design", "desc": "Trust Boundary Violation"},
    "CWE-522": {"id": "A04:2021", "name": "Insecure Design", "desc": "Insufficiently Protected Credentials"},

    # A05:2021 - Security Misconfiguration
    "CWE-16": {"id": "A05:2021", "name": "Security Misconfiguration", "desc": "Configuration"},
    "CWE-611": {"id": "A05:2021", "name": "Security Misconfiguration", "desc": "Improper Restriction of XML External Entity Reference ('XXE')"},
    "CWE-1004": {"id": "A05:2021", "name": "Security Misconfiguration", "desc": "Sensitive Cookie Without 'HttpOnly' Flag"},

    # A06:2021 - Vulnerable and Outdated Components
    "CWE-1104": {"id": "A06:2021", "name": "Vulnerable and Outdated Components", "desc": "Use of Unmaintained Third-Party Components"},

    # A07:2021 - Identification and Authentication Failures
    "CWE-287": {"id": "A07:2021", "name": "Identification and Authentication Failures", "desc": "Improper Authentication"},
    "CWE-306": {"id": "A07:2021", "name": "Identification and Authentication Failures", "desc": "Missing Authentication for Critical Function"},
    "CWE-307": {"id": "A07:2021", "name": "Identification and Authentication Failures", "desc": "Improper Restriction of Excessive Authentication Attempts"},
    "CWE-798": {"id": "A07:2021", "name": "Identification and Authentication Failures", "desc": "Use of Hard-coded Credentials"},

    # A08:2021 - Software and Data Integrity Failures
    "CWE-494": {"id": "A08:2021", "name": "Software and Data Integrity Failures", "desc": "Download of Code Without Integrity Check"},
    "CWE-502": {"id": "A08:2021", "name": "Software and Data Integrity Failures", "desc": "Deserialization of Untrusted Data"},
    "CWE-829": {"id": "A08:2021", "name": "Software and Data Integrity Failures", "desc": "Inclusion of Functionality from Untrusted Control Sphere"},

    # A09:2021 - Security Logging and Monitoring Failures
    "CWE-117": {"id": "A09:2021", "name": "Security Logging and Monitoring Failures", "desc": "Improper Output Handling for Logs"},
    "CWE-778": {"id": "A09:2021", "name": "Security Logging and Monitoring Failures", "desc": "Insufficient Logging"},

    # A10:2021 - Server-Side Request Forgery (SSRF)
    "CWE-918": {"id": "A10:2021", "name": "Server-Side Request Forgery (SSRF)", "desc": "Server-Side Request Forgery (SSRF)"},
}

# 2. MITRE CWE Top 25 Most Dangerous Software Weaknesses (Rank & Severity)
CWE_TOP_25: dict[str, dict[str, Any]] = {
    "CWE-787": {"rank": 1, "score": 63.55, "name": "Out-of-bounds Write"},
    "CWE-79": {"rank": 2, "score": 46.13, "name": "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')"},
    "CWE-89": {"rank": 3, "score": 34.20, "name": "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')"},
    "CWE-20": {"rank": 4, "score": 26.31, "name": "Improper Input Validation"},
    "CWE-125": {"rank": 5, "score": 25.10, "name": "Out-of-bounds Read"},
    "CWE-78": {"rank": 6, "score": 21.43, "name": "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')"},
    "CWE-416": {"rank": 7, "score": 21.12, "name": "Use After Free"},
    "CWE-22": {"rank": 8, "score": 19.85, "name": "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')"},
    "CWE-352": {"rank": 9, "score": 16.50, "name": "Cross-Site Request Forgery (CSRF)"},
    "CWE-434": {"rank": 10, "score": 15.22, "name": "Unrestricted Upload of File with Dangerous Type"},
    "CWE-476": {"rank": 11, "score": 14.80, "name": "NULL Pointer Dereference"},
    "CWE-502": {"rank": 12, "score": 13.94, "name": "Deserialization of Untrusted Data"},
    "CWE-190": {"rank": 13, "score": 13.56, "name": "Integer Overflow or Wraparound"},
    "CWE-287": {"rank": 14, "score": 12.18, "name": "Improper Authentication"},
    "CWE-798": {"rank": 15, "score": 11.85, "name": "Use of Hard-coded Credentials"},
    "CWE-862": {"rank": 16, "score": 11.20, "name": "Missing Authorization"},
    "CWE-77": {"rank": 17, "score": 10.95, "name": "Improper Neutralization of Special Elements used in a Command ('Command Injection')"},
    "CWE-306": {"rank": 18, "score": 10.42, "name": "Missing Authentication for Critical Function"},
    "CWE-119": {"rank": 19, "score": 9.98, "name": "Improper Restriction of Operations within the Bounds of a Memory Buffer"},
    "CWE-276": {"rank": 20, "score": 9.54, "name": "Incorrect Default Permissions"},
    "CWE-918": {"rank": 21, "score": 9.20, "name": "Server-Side Request Forgery (SSRF)"},
    "CWE-362": {"rank": 22, "score": 8.75, "name": "Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')"},
    "CWE-400": {"rank": 23, "score": 8.32, "name": "Uncontrolled Resource Consumption"},
    "CWE-611": {"rank": 24, "score": 8.10, "name": "Improper Restriction of XML External Entity Reference ('XXE')"},
    "CWE-94": {"rank": 25, "score": 7.90, "name": "Improper Control of Generation of Code ('Code Injection')"},
}

# 3. NIST SP 800-115 Assessment Activities & CIS Controls v8 Mappings
STANDARDS_CATALOG = {
    "network_discovery": {
        "nist": {"section": "NIST SP 800-115 §4.2", "title": "Target Identification and Port Scanning"},
        "cis": {"control": "CIS Control 7.1", "title": "Establish and Maintain a Vulnerability Management Process"},
    },
    "web_vulnerability": {
        "nist": {"section": "NIST SP 800-115 §4.4", "title": "Web Application Vulnerability Scanning"},
        "cis": {"control": "CIS Control 16.1", "title": "Establish and Maintain a Secure Application Development Process"},
    },
    "service_flaw": {
        "nist": {"section": "NIST SP 800-115 §4.3", "title": "Vulnerability Identification and Verification"},
        "cis": {"control": "CIS Control 4.1", "title": "Establish and Maintain a Secure Configuration Process"},
    },
    "auth_flaw": {
        "nist": {"section": "NIST SP 800-115 §5.1", "title": "Penetration Testing - Authentication & Privilege Verification"},
        "cis": {"control": "CIS Control 5.1", "title": "Establish and Maintain an Inventory of Accounts"},
    },
}


class ComplianceEngine:
    """Evaluates findings and correlates them with regulatory & security frameworks."""

    def map_finding(self, finding: Any) -> dict[str, Any]:
        cwe_id = getattr(finding, "cwe_id", None) or ""
        cve_id = getattr(finding, "cve_id", None) or ""
        title = getattr(finding, "title", "").lower()

        # 1. OWASP Top 10 (2021)
        owasp_entry = OWASP_2021_MAPPING.get(cwe_id)
        if not owasp_entry:
            # Fallback heuristic based on CVE/Title
            if "traversal" in title or "path" in title or "unauthorized" in title:
                owasp_entry = OWASP_2021_MAPPING["CWE-22"]
            elif "injection" in title or "sqli" in title or "xss" in title:
                owasp_entry = OWASP_2021_MAPPING["CWE-89"]
            elif "auth" in title or "login" in title:
                owasp_entry = OWASP_2021_MAPPING["CWE-287"]
            elif "outdated" in title or "cve" in title or cve_id:
                owasp_entry = {
                    "id": "A06:2021",
                    "name": "Vulnerable and Outdated Components",
                    "desc": "Known component vulnerability matching CVE database",
                }
            else:
                owasp_entry = {
                    "id": "A05:2021",
                    "name": "Security Misconfiguration",
                    "desc": "Security weakness or configuration flaw",
                }

        # 2. CWE Top 25
        top25_info = CWE_TOP_25.get(cwe_id)
        is_top25 = top25_info is not None
        top25_rank = top25_info["rank"] if top25_info else None

        # 3. NIST SP 800-115 & CIS Controls
        if "web" in title or cwe_id in ("CWE-79", "CWE-89", "CWE-22", "CWE-352", "CWE-918"):
            standards = STANDARDS_CATALOG["web_vulnerability"]
        elif cwe_id in ("CWE-287", "CWE-306", "CWE-798", "CWE-862"):
            standards = STANDARDS_CATALOG["auth_flaw"]
        elif cve_id:
            standards = STANDARDS_CATALOG["service_flaw"]
        else:
            standards = STANDARDS_CATALOG["network_discovery"]

        return {
            "cwe_id": cwe_id,
            "cve_id": cve_id,
            "owasp": owasp_entry,
            "cwe_top_25": {
                "is_top_25": is_top25,
                "rank": top25_rank,
                "details": top25_info,
            },
            "nist_sp_800_115": standards["nist"],
            "cis_controls": standards["cis"],
        }

    def evaluate_compliance_summary(self, findings: list[Any]) -> dict[str, Any]:
        """Aggregate compliance posture across all findings."""
        owasp_hits: dict[str, int] = {}
        cwe_top25_hits: list[dict[str, Any]] = []
        nist_activities: set[str] = set()
        cis_controls: set[str] = set()
        total_violations = 0
        critical_high_count = 0

        for f in findings:
            # Only count active and trustworthy findings
            status = getattr(f.status, "value", str(f.status))
            if status == "FALSE_POSITIVE":
                continue
            if not getattr(f, "trustworthy", True) or getattr(f, "is_simulated", False):
                continue

            total_violations += 1
            sev = getattr(f.cvss_severity, "value", str(f.cvss_severity)).upper()
            if sev in ("CRITICAL", "HIGH"):
                critical_high_count += 1

            mapping = self.map_finding(f)

            # OWASP
            owasp_id = mapping["owasp"]["id"]
            owasp_hits[owasp_id] = owasp_hits.get(owasp_id, 0) + 1

            # CWE Top 25
            if mapping["cwe_top_25"]["is_top_25"]:
                cwe_top25_hits.append(
                    {
                        "finding_id": getattr(f, "id", "unknown"),
                        "cwe_id": mapping["cwe_id"],
                        "rank": mapping["cwe_top_25"]["rank"],
                        "name": mapping["cwe_top_25"]["details"]["name"],
                        "severity": sev,
                    }
                )

            # NIST & CIS
            nist_activities.add(mapping["nist_sp_800_115"]["section"])
            cis_controls.add(mapping["cis_controls"]["control"])

        # Compliance Score calculation (100% baseline, deducted by severity)
        deduction = (critical_high_count * 25) + ((total_violations - critical_high_count) * 10)
        compliance_score = max(0, 100 - deduction)

        status_text = "PASSED (COMPLIANT)"
        if critical_high_count > 0:
            status_text = "NON-COMPLIANT (CRITICAL/HIGH VIOLATIONS)"
        elif total_violations > 0:
            status_text = "CONDITIONALLY COMPLIANT (MINOR DEFICIENCIES)"

        return {
            "compliance_score": compliance_score,
            "status": status_text,
            "total_active_violations": total_violations,
            "critical_high_count": critical_high_count,
            "owasp_top_10_breakdown": owasp_hits,
            "cwe_top_25_hits": sorted(cwe_top25_hits, key=lambda x: x["rank"] or 99),
            "nist_sp_800_115_sections": sorted(list(nist_activities)),
            "cis_controls_v8": sorted(list(cis_controls)),
        }


compliance_engine = ComplianceEngine()
