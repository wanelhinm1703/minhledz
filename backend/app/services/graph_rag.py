"""
Graph RAG Service: Knowledge Graph for Defensive Security Analysis & Attack Chaining.
Traverses relational knowledge:
Asset -> Service -> CVE -> CWE -> MITRE ATT&CK Tactics & Techniques.
Enables AI Copilot to reason about multi-hop Attack Paths (Path Traversal -> Sensitive File Exposure -> Privilege Escalation).
"""

from __future__ import annotations

import json
import logging
import pathlib
import sqlite3
from typing import Any

from backend.app.storage.db import db
from backend.app.storage.graph_db import graph_db

logger = logging.getLogger("ai_pentest.graph_rag")

ROOT_DIR = pathlib.Path(__file__).resolve().parent.parent.parent.parent


class GraphRAGService:
    """
    Knowledge Graph reasoning service for Attack Path Analysis and Context Augmentation.
    """

    # Mapping common CWE classes to MITRE ATT&CK Techniques for attack chain inference
    CWE_TO_ATTACK_MAPPING: dict[str, list[dict[str, str]]] = {
        "CWE-22": [
            {"tactic": "Discovery", "technique_id": "T1083", "name": "File and Directory Discovery"},
            {"tactic": "Credential Access", "technique_id": "T1552", "name": "Unsecured Credentials"},
        ],
        "CWE-89": [
            {"tactic": "Initial Access", "technique_id": "T1190", "name": "Exploit Public-Facing Application"},
            {"tactic": "Credential Access", "technique_id": "T1003", "name": "OS Credential Dumping"},
            {"tactic": "Collection", "technique_id": "T1560", "name": "Archive Collected Data"},
        ],
        "CWE-78": [
            {"tactic": "Execution", "technique_id": "T1059", "name": "Command and Scripting Interpreter"},
            {"tactic": "Privilege Escalation", "technique_id": "T1068", "name": "Exploitation for Privilege Escalation"},
        ],
        "CWE-79": [
            {"tactic": "Initial Access", "technique_id": "T1189", "name": "Drive-by Compromise"},
            {"tactic": "Credential Access", "technique_id": "T1539", "name": "Steal Web Session Cookie"},
        ],
        "CWE-918": [
            {"tactic": "Initial Access", "technique_id": "T1190", "name": "Exploit Public-Facing Application"},
            {"tactic": "Discovery", "technique_id": "T1016", "name": "System Network Configuration Discovery"},
            {"tactic": "Lateral Movement", "technique_id": "T1210", "name": "Exploitation of Remote Services"},
        ],
        "CWE-502": [
            {"tactic": "Execution", "technique_id": "T1203", "name": "Exploitation for Client Execution"},
            {"tactic": "Defense Evasion", "technique_id": "T1027", "name": "Obfuscated Files or Information"},
        ],
    }

    @classmethod
    def get_attack_chains_for_target(cls, target_id: str) -> list[dict[str, Any]]:
        """
        Builds and traverses multi-hop causal attack chains for a target.
        Asset -> Port/Service -> CVE -> CWE -> MITRE ATT&CK TTPs.
        """
        graph_data = graph_db.get_graph_by_target(target_id)
        nodes = graph_data.nodes
        edges = graph_data.edges

        chains: list[dict[str, Any]] = []

        # Find all vulnerability/finding nodes
        vuln_nodes = [n for n in nodes if n.type.value in ("vulnerability", "cve") or n.risk_level.value in ("CRITICAL", "HIGH", "MEDIUM")]

        for vn in vuln_nodes:
            props = vn.properties or {}
            cve_id = props.get("cve_id") or (vn.label if "CVE-" in vn.label else None)
            cwe_id = props.get("cwe_id")

            # Look up CWE and MITRE mapping
            mitre_steps: list[dict[str, str]] = []
            if cwe_id and cwe_id in cls.CWE_TO_ATTACK_MAPPING:
                mitre_steps.extend(cls.CWE_TO_ATTACK_MAPPING[cwe_id])

            # Query database for additional MITRE mappings
            with db.get_connection() as conn:
                cur = conn.cursor()
                if cve_id:
                    cur.execute("SELECT cwe_ids FROM cve WHERE cve_id = ?", (cve_id,))
                    row = cur.fetchone()
                    if row and row["cwe_ids"]:
                        for cw in row["cwe_ids"].split(","):
                            cw_clean = cw.strip()
                            if cw_clean in cls.CWE_TO_ATTACK_MAPPING and not mitre_steps:
                                mitre_steps.extend(cls.CWE_TO_ATTACK_MAPPING[cw_clean])

            # Construct causal chain
            chain_steps = [
                {
                    "step": 1,
                    "stage": "Reconnaissance & Asset Discovery",
                    "entity": vn.label,
                    "description": f"Target asset exposed on {vn.label}",
                },
                {
                    "step": 2,
                    "stage": "Vulnerability Exploitation Boundary",
                    "entity": cve_id or vn.label,
                    "cwe": cwe_id or "General Weakness",
                    "severity": vn.risk_level.value,
                    "description": props.get("description", "Exposed vulnerable service"),
                },
            ]

            step_counter = 3
            for ms in mitre_steps:
                chain_steps.append({
                    "step": step_counter,
                    "stage": f"Post-Exploit: {ms['tactic']}",
                    "technique": f"{ms['technique_id']} - {ms['name']}",
                    "description": f"Potential lateral progression via {ms['name']}",
                })
                step_counter += 1

            chains.append({
                "chain_id": f"chain_{vn.id}",
                "target_id": target_id,
                "initial_finding": vn.label,
                "risk_level": vn.risk_level.value,
                "length": len(chain_steps),
                "chain_steps": chain_steps,
            })

        return chains

    @classmethod
    def get_graph_rag_prompt_context(cls, target_id: str, query: str = "") -> str:
        """
        Formats Knowledge Graph attack paths and relations into a structured context block for LLM prompting.
        """
        chains = cls.get_attack_chains_for_target(target_id)
        if not chains:
            return ""

        lines = ["[GRAPH RAG KNOWLEDGE GRAPH - ATTACK CHAIN REASONING]"]
        lines.append(f"Target: {target_id}")
        lines.append("Multi-hop attack propagation paths identified in Knowledge Graph:")

        for idx, chain in enumerate(chains[:4], 1):
            lines.append(f"\n--- Attack Path #{idx} ({chain['risk_level']}) ---")
            for step in chain["chain_steps"]:
                if "technique" in step:
                    lines.append(f"  Step {step['step']} [{step['stage']}]: {step['technique']}")
                else:
                    lines.append(f"  Step {step['step']} [{step['stage']}]: {step['entity']} ({step.get('cwe', '')})")

        lines.append("\n[OPERATIONAL GUIDELINES FOR AI COPILOT]:")
        lines.append("- ATTACK CHAIN (Chuỗi tấn công): Dùng để phân tích đường dẫn xâm nhập, leo thang đặc quyền và di chuyển ngang tiềm ẩn (Descriptive/Modeling).")
        lines.append("- ATTACK PLAN (Kế hoạch tấn công): Dùng khi người dùng yêu cầu kịch bản kiểm thử/xác minh (Prescriptive/Actionable). Bắt buộc phải là lệnh Read-Only an toàn (curl, nc, nmap passive), nêu rõ Expected Evidence và điểm cắt chuỗi (Break the Chain).")
        lines.append("\n[END GRAPH RAG CONTEXT]\n")
        return "\n".join(lines)



# Global singleton instance
graph_rag = GraphRAGService()
