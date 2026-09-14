from __future__ import annotations

from datetime import datetime, timezone
import sqlite3

MITRE_TECHNIQUES = [
    ("T1595", "Active Scanning", "Reconnaissance", "Adversaries may execute active scans to gather info about victim infrastructure.", "Network monitoring and rate limit inspection", "Linux, Windows, macOS"),
    ("T1592", "Gather Victim Host Information", "Reconnaissance", "Adversaries may gather host information such as OS, architecture, and installed software.", "Audit access to public documentation", "Linux, Windows"),
    ("T1190", "Exploit Public-Facing Application", "Initial Access", "Adversaries may attempt to exploit vulnerabilities in Internet-facing applications.", "Application firewalls (WAF) and vulnerability scanning", "Linux, Windows"),
    ("T1059", "Command and Scripting Interpreter", "Execution", "Adversaries may abuse command and script interpreters to execute commands.", "Process command-line auditing", "Linux, Windows, macOS"),
    ("T1083", "File and Directory Discovery", "Discovery", "Adversaries may enumerate files and directories looking for sensitive data.", "File integrity monitoring", "Linux, Windows"),
    ("T1046", "Network Service Discovery", "Discovery", "Adversaries may attempt to get a listing of services running on remote hosts.", "Monitor internal connection bursts", "Network"),
]

def ingest_mitre_techniques(conn: sqlite3.Connection) -> int:
    timestamp = datetime.now(timezone.utc).isoformat()
    cursor = conn.cursor()
    count = 0
    for tid, name, tactic, desc, detect, platforms in MITRE_TECHNIQUES:
        source_url = f"https://attack.mitre.org/techniques/{tid}/"
        cursor.execute(
            """
            INSERT INTO mitre_technique (technique_id, name, tactic, description, detection, platforms, source_url, ingested_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(technique_id) DO UPDATE SET
                name=excluded.name,
                description=excluded.description,
                ingested_at=excluded.ingested_at
            """,
            (tid, name, tactic, desc, detect, platforms, source_url, timestamp),
        )
        count += 1
    conn.commit()
    return count
