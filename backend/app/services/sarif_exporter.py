"""SARIF Exporter: Generates OASIS Static Analysis Results Interchange Format (SARIF v2.1.0).
Provides direct interoperability with:
- GitHub Actions (Code Scanning Alerts / upload-sarif)
- GitLab CI (Security & Vulnerability Dashboard)
- CI/CD Security Gates & Break-Build Policies
"""

from __future__ import annotations

import json
import pathlib
from datetime import datetime, timezone
from typing import Any

from backend.app.services.compliance_engine import compliance_engine


def cvss_to_sarif_level(severity: str) -> str:
    s = severity.upper()
    if s in ("CRITICAL", "HIGH"):
        return "error"
    if s == "MEDIUM":
        return "warning"
    return "note"


class SarifExporter:
    """Exports findings to OASIS SARIF v2.1.0 standard schema."""

    def __init__(self, root_dir: pathlib.Path | None = None):
        self.root_dir = (
            root_dir or pathlib.Path(__file__).resolve().parent.parent.parent.parent
        )
        self.reports_dir = self.root_dir / "toolkit" / "10-reports"
        self.reports_dir.mkdir(parents=True, exist_ok=True)

    def export_sarif(
        self,
        target_id: str,
        findings: list[Any],
        campaign_name: str = "Automated Lab Assessment",
    ) -> dict[str, Any]:
        """Generate SARIF 2.1.0 JSON log for GitHub Actions & GitLab CI."""
        rules_map: dict[str, dict[str, Any]] = {}
        results_list: list[dict[str, Any]] = []

        # Filter out False Positives
        active_findings = [
            f for f in findings
            if getattr(f.status, "value", str(f.status)) != "FALSE_POSITIVE"
        ]

        for f in active_findings:
            f_id = getattr(f, "id", "FIND-UNKNOWN")
            cve_id = getattr(f, "cve_id", None)
            cwe_id = getattr(f, "cwe_id", None)
            title = getattr(f, "title", "Security Finding")
            desc = getattr(f, "description", "")
            remediation = getattr(f, "remediation", "")
            cvss_score = float(getattr(f, "cvss_score", 0.0) or 0.0)
            sev = getattr(f.cvss_severity, "value", str(f.cvss_severity)).upper()
            asset = getattr(f, "affected_asset", target_id)

            mapping = compliance_engine.map_finding(f)
            rule_id = cve_id or f_id
            level = cvss_to_sarif_level(sev)

            # Help URI
            help_uri = "https://cve.mitre.org"
            if cve_id:
                help_uri = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
            elif cwe_id and cwe_id.startswith("CWE-"):
                cwe_num = cwe_id.split("-")[-1]
                help_uri = f"https://cwe.mitre.org/data/definitions/{cwe_num}.html"

            tags = ["security", "pentest-finding", f"cvss-{sev.lower()}"]
            if mapping["owasp"]:
                tags.append(f"owasp-{mapping['owasp']['id'].lower()}")
            if mapping["cwe_top_25"]["is_top_25"]:
                tags.append(f"cwe-top25-rank-{mapping['cwe_top_25']['rank']}")

            # Construct SARIF Rule definition
            if rule_id not in rules_map:
                rule_def: dict[str, Any] = {
                    "id": rule_id,
                    "name": title.replace(" ", "_").replace(":", "_").replace("-", "_"),
                    "shortDescription": {"text": title},
                    "fullDescription": {"text": desc or title},
                    "helpUri": help_uri,
                    "defaultConfiguration": {"level": level},
                    "properties": {
                        "tags": tags,
                        "security-severity": f"{cvss_score:.1f}",  # GitHub Code Scanning requires this field!
                        "cwe": [cwe_id] if cwe_id else [],
                        "owasp": mapping["owasp"]["id"],
                        "nist_sp_800_115": mapping["nist_sp_800_115"]["section"],
                        "cis_control": mapping["cis_controls"]["control"],
                    },
                }
                if remediation:
                    rule_def["help"] = {
                        "text": f"Remediation:\n{remediation}",
                        "markdown": f"### Remediation Guidance\n{remediation}",
                    }
                rules_map[rule_id] = rule_def

            # Construct SARIF Result item
            result_item: dict[str, Any] = {
                "ruleId": rule_id,
                "ruleIndex": list(rules_map.keys()).index(rule_id),
                "level": level,
                "message": {
                    "text": f"{title}\n\nAffected Asset: {asset}\nCVSS Score: {cvss_score} ({sev})\n\n{desc}"
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": f"target://{asset}",
                                "uriBaseId": "%SRCROOT%",
                            }
                        },
                        "logicalLocations": [
                            {
                                "name": asset,
                                "kind": "endpoint",
                            }
                        ],
                    }
                ],
                "properties": {
                    "target_id": target_id,
                    "cvssScore": cvss_score,
                    "cvssSeverity": sev,
                    "remediation": remediation,
                    "trustworthy": getattr(f, "trustworthy", True),
                    "is_simulated": getattr(f, "is_simulated", False),
                    "compliance": mapping,
                },
            }
            results_list.append(result_item)

        sarif_doc: dict[str, Any] = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "AI-Pentest Copilot",
                            "semanticVersion": "5.0.0",
                            "informationUri": "https://github.com/ai-pentest-copilot",
                            "rules": list(rules_map.values()),
                        }
                    },
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "endTimeUtc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                        }
                    ],
                    "results": results_list,
                }
            ],
        }

        # Write to file
        clean_target = target_id.replace(":", "-").replace("/", "-")
        sarif_file = self.reports_dir / f"{clean_target}_report.sarif"
        sarif_file.write_text(json.dumps(sarif_doc, indent=2), encoding="utf-8")

        return sarif_doc


sarif_exporter = SarifExporter()
