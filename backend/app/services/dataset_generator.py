"""
QLoRA Security Fine-Tuning Dataset Generator.
Extracts structured training pairs (Alpaca JSONL format) from Knowledge Base (CVE, CWE, Affected Versions, Attack Paths).
Produces high-quality domain-specific instruction datasets for fine-tuning open-source LLMs (Llama-3, Mistral)
into specialized AI-Pentest Copilots.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
from pathlib import Path
from typing import Any, Generator

logger = logging.getLogger("ai_pentest.dataset_generator")

DEFAULT_KB_PATH = Path("toolkit/data/kb.sqlite")
DEFAULT_OUTPUT_PATH = Path("security/datasets/finetune_pentest_alpaca.jsonl")


class FineTuneDatasetGenerator:
    """Generates instruction-tuning datasets for security LLM fine-tuning."""

    def __init__(self, db_path: Path | str = DEFAULT_KB_PATH):
        self.db_path = Path(db_path)

    def _get_connection(self) -> sqlite3.Connection:
        if not self.db_path.exists():
            raise FileNotFoundError(f"Database not found at {self.db_path}")
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def generate_cve_analysis_samples(self, limit: int = 500) -> list[dict[str, str]]:
        """Generates CVE analysis & safe verification instruction pairs."""
        samples = []
        conn = self._get_connection()
        cursor = conn.cursor()

        query = """
            SELECT c.cve_id, c.description, c.cvss_v3_score, c.cvss_v3_severity,
                   c.cwe_ids, c.epss_score, c.is_cisa_kev,
                   a.vendor, a.product, a.version_exact, a.version_start, a.version_end
            FROM cve c
            LEFT JOIN cve_affected a ON c.cve_id = a.cve_id
            WHERE c.description IS NOT NULL AND c.description != ''
            GROUP BY c.cve_id
            ORDER BY c.cvss_v3_score DESC NULLS LAST
            LIMIT ?
        """
        cursor.execute(query, (limit,))
        rows = cursor.fetchall()

        for r in rows:
            cve_id = r["cve_id"]
            desc = r["description"]
            score = r["cvss_v3_score"] or 7.5
            severity = r["cvss_v3_severity"] or "HIGH"
            cwe = r["cwe_ids"] or "CWE-Unknown"
            epss = r["epss_score"] or 0.05
            is_kev = bool(r["is_cisa_kev"])
            product = f"{r['vendor'] or 'target'} {r['product'] or 'software'}"
            ver = r["version_exact"] or r["version_end"] or "all versions"

            instruction = (
                "You are an AI Cybersecurity Pentest Copilot. Analyze the following vulnerability, "
                "assess threat intelligence metrics (CVSS, EPSS, CISA KEV), and propose a 100% safe, "
                "read-only verification probe that adheres strictly to ethical guardrails."
            )
            user_input = (
                f"Vulnerability ID: {cve_id}\n"
                f"Target Service: {product} (Version: {ver})\n"
                f"Description: {desc}"
            )

            # Generate safe verification command based on context
            safe_probe = f"curl -s -I -m 5 http://{{TARGET}}:80/ | grep -i '{product.split()[0]}'"
            if "ssh" in product.lower():
                safe_probe = "nmap -sV -p 22 --script banner {TARGET}"
            elif "ftp" in product.lower():
                safe_probe = "nmap -sV -p 21 --script ftp-anon,banner {TARGET}"
            elif "sql" in product.lower() or "database" in product.lower():
                safe_probe = "nmap -sV -p 3306,5432 --script banner {TARGET}"

            output = (
                f"### Vulnerability Analysis: {cve_id}\n"
                f"- **Severity**: {severity} (CVSS v3.1: {score})\n"
                f"- **Weakness**: {cwe}\n"
                f"- **EPSS Exploit Likelihood**: {epss * 100:.2f}%\n"
                f"- **CISA Known Exploited (KEV)**: {'YES - Immediate Patching Required' if is_kev else 'No active in-the-wild exploitation confirmed'}\n\n"
                f"### Impact Assessment\n"
                f"The flaw affects {product} ({ver}). An unauthorized adversary could exploit this condition to compromise system confidentiality and integrity.\n\n"
                f"### Safe Read-Only Verification Plan\n"
                f"To verify whether the target is susceptible without disrupting service availability:\n"
                f"```bash\n{safe_probe}\n```\n"
                f"**Expected Evidence**: Service banner indicating {ver} or HTTP response header confirming vulnerable software build.\n\n"
                f"### Remediation Guidance\n"
                f"1. Upgrade {product} to the latest vendor security release.\n"
                f"2. Restrict network exposure using access control lists (ACLs) or web application firewall (WAF) virtual patching."
            )

            samples.append({
                "instruction": instruction,
                "input": user_input,
                "output": output,
            })

        conn.close()
        return samples

    def generate_cwe_remediation_samples(self, limit: int = 60) -> list[dict[str, str]]:
        """Generates CWE root-cause analysis and compliance guidance pairs."""
        samples = []
        conn = self._get_connection()
        cursor = conn.cursor()

        query = """
            SELECT cwe_id, name, description, extended_description, likelihood, mitigations
            FROM cwe
            WHERE description IS NOT NULL
            ORDER BY cwe_id ASC
            LIMIT ?
        """
        cursor.execute(query, (limit,))
        rows = cursor.fetchall()

        for r in rows:
            cwe_id = r["cwe_id"]
            name = r["name"]
            desc = r["description"]
            likelihood = r["likelihood"] or "Medium"
            mitigations = r["mitigations"] or "Apply standard input validation, output encoding, and principle of least privilege."

            instruction = (
                f"Provide a root-cause explanation for weakness {cwe_id} ({name}), identify affected compliance "
                "frameworks (OWASP Top 10, ISO 27001, PCI-DSS), and provide concrete mitigation best practices."
            )
            user_input = f"Weakness Identifier: {cwe_id}: {name}\nDetails: {desc}"

            # Map to compliance
            owasp_category = "A03:2021-Injection" if "inject" in name.lower() or "sql" in name.lower() else "A01:2021-Broken Access Control"
            pci_req = "Requirement 6.5 - Address common coding vulnerabilities in software development"

            output = (
                f"### Root-Cause Analysis: {cwe_id} ({name})\n"
                f"{desc}\n\n"
                f"**Exploit Likelihood**: {likelihood}\n\n"
                f"### Regulatory & Standard Compliance Impact\n"
                f"- **OWASP Top 10 (2021)**: {owasp_category}\n"
                f"- **PCI-DSS v4.0**: {pci_req}\n"
                f"- **ISO/IEC 27001:2022**: Control A.8.28 (Secure Coding) & Control A.8.8 (Management of Technical Vulnerabilities)\n\n"
                f"### Recommended Mitigations\n"
                f"{mitigations}\n\n"
                f"### Defensive Architecture Principle\n"
                f"Employ defense-in-depth: enforce strict parameterized interfaces, schema validations, and context-aware sanitization."
            )

            samples.append({
                "instruction": instruction,
                "input": user_input,
                "output": output,
            })

        conn.close()
        return samples

    def generate_recon_synthesis_samples(self, limit: int = 100) -> list[dict[str, str]]:
        """Generates Reconnaissance synthesis and attack surface triage pairs."""
        samples = []
        conn = self._get_connection()
        cursor = conn.cursor()

        # Select distinct vendors & products
        query = """
            SELECT vendor, product, COUNT(cve_id) as cve_count, GROUP_CONCAT(cve_id, ', ') as cves
            FROM cve_affected
            WHERE vendor IS NOT NULL AND product IS NOT NULL
            GROUP BY vendor, product
            HAVING cve_count >= 2
            ORDER BY cve_count DESC
            LIMIT ?
        """
        cursor.execute(query, (limit,))
        rows = cursor.fetchall()

        for r in rows:
            vendor = r["vendor"]
            product = r["product"]
            count = r["cve_count"]
            sample_cves = ", ".join(r["cves"].split(", ")[:3])

            instruction = (
                "You are an automated Recon Analyst Copilot. Evaluate the detected network service, "
                "identify potential historical vulnerabilities, and recommend safe reconnaissance verification steps."
            )
            user_input = (
                f"Service Fingerprint: {vendor} {product}\n"
                f"Associated CVEs identified in Knowledge Base: {sample_cves} (Total: {count})"
            )

            output = (
                f"### Service Risk Evaluation: {vendor} {product}\n"
                f"The target hosts {vendor} {product} which is associated with {count} documented CVE vulnerabilities in the local knowledge base.\n\n"
                f"### Key Exposures to Check\n"
                f"Priority CVEs for this component include: {sample_cves}.\n\n"
                f"### Non-Destructive Reconnaissance Actions\n"
                f"1. **Banner Grab & Version Verification**:\n"
                f"   ```bash\n   curl -s -I http://{{TARGET}}:8080/ | grep -i '{product}'\n   ```\n"
                f"2. **NSE Safe Script Probe**:\n"
                f"   ```bash\n   nmap -sV --version-light -p 80,443,8080 --script http-headers {{TARGET}}\n   ```\n\n"
                f"### Operational Note\n"
                f"All proposed actions are safe read-only queries. Automated exploitation is disabled in accordance with ethical pentesting standards."
            )

            samples.append({
                "instruction": instruction,
                "input": user_input,
                "output": output,
            })

        conn.close()
        return samples

    def build_full_dataset(
        self,
        output_file: Path | str = DEFAULT_OUTPUT_PATH,
        cve_limit: int = 500,
        cwe_limit: int = 52,
        recon_limit: int = 100,
    ) -> dict[str, Any]:
        """
        Builds the complete multi-domain security dataset and writes to Alpaca JSONL format.
        """
        out_path = Path(output_file)
        out_path.parent.mkdir(parents=True, exist_ok=True)

        logger.info("Generating CVE analysis instruction samples...")
        cve_samples = self.generate_cve_analysis_samples(limit=cve_limit)

        logger.info("Generating CWE root-cause & compliance samples...")
        cwe_samples = self.generate_cwe_remediation_samples(limit=cwe_limit)

        logger.info("Generating Recon synthesis samples...")
        recon_samples = self.generate_recon_synthesis_samples(limit=recon_limit)

        all_samples = cve_samples + cwe_samples + recon_samples

        # Write to JSONL
        with open(out_path, "w", encoding="utf-8") as f:
            for item in all_samples:
                f.write(json.dumps(item, ensure_ascii=False) + "\n")

        file_size_kb = out_path.stat().st_size / 1024

        stats = {
            "output_path": str(out_path),
            "total_samples": len(all_samples),
            "cve_samples": len(cve_samples),
            "cwe_samples": len(cwe_samples),
            "recon_samples": len(recon_samples),
            "file_size_kb": round(file_size_kb, 2),
            "format": "alpaca_jsonl",
        }
        logger.info("Generated fine-tune dataset: %s (%d samples)", out_path, len(all_samples))
        return stats


# Global instance
dataset_generator = FineTuneDatasetGenerator()
