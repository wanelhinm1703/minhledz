"""SQLite storage for Findings with indexing and deduplication support."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import sqlite3
from typing import Any, Dict, List, Optional
from backend.app.storage.db import db
from backend.app.schemas.finding import Finding, FindingCreate, FindingUpdate, FindingStatus, FindingSeverity

FINDINGS_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    target_id TEXT NOT NULL,
    title TEXT NOT NULL,
    cve_id TEXT,
    cwe_id TEXT,
    cvss_score REAL DEFAULT 0.0,
    cvss_severity TEXT DEFAULT 'INFO',
    status TEXT DEFAULT 'CANDIDATE',
    affected_asset TEXT NOT NULL,
    description TEXT NOT NULL,
    evidence_chain_json TEXT,
    remediation TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_findings_target ON findings(target_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(cvss_severity);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE INDEX IF NOT EXISTS idx_findings_cve ON findings(cve_id);
"""


class FindingsDatabase:
    def __init__(self):
        self.init_tables()

    def init_tables(self):
        with db.get_connection() as conn:
            conn.executescript(FINDINGS_SCHEMA_SQL)
            conn.commit()

    def create_finding(self, finding_id: str, item: FindingCreate) -> Finding:
        ts = datetime.now(timezone.utc).isoformat()
        with db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT OR REPLACE INTO findings (
                    id, target_id, title, cve_id, cwe_id, cvss_score, cvss_severity,
                    status, affected_asset, description, evidence_chain_json, remediation,
                    created_at, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    finding_id,
                    item.target_id,
                    item.title,
                    item.cve_id,
                    item.cwe_id,
                    item.cvss_score,
                    item.cvss_severity.value,
                    item.status.value,
                    item.affected_asset,
                    item.description,
                    json.dumps([e.model_dump() for e in item.evidence_chain]),
                    item.remediation,
                    ts,
                    ts,
                ),
            )
            conn.commit()
        return self.get_finding(finding_id)  # type: ignore

    def get_finding(self, finding_id: str) -> Optional[Finding]:
        with db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM findings WHERE id = ?", (finding_id,))
            row = cursor.fetchone()
            if not row:
                return None
            return self._row_to_finding(dict(row))

    def list_findings(
        self,
        target_id: Optional[str] = None,
        severity: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Finding]:
        query = "SELECT * FROM findings WHERE 1=1"
        params = []
        if target_id:
            query += " AND target_id = ?"
            params.append(target_id)
        if severity:
            query += " AND cvss_severity = ?"
            params.append(severity.upper())
        if status:
            query += " AND status = ?"
            params.append(status.upper())
        query += " ORDER BY cvss_score DESC, updated_at DESC"

        with db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, tuple(params))
            rows = cursor.fetchall()
            return [self._row_to_finding(dict(r)) for r in rows]

    def update_finding(self, finding_id: str, update: FindingUpdate) -> Optional[Finding]:
        existing = self.get_finding(finding_id)
        if not existing:
            return None

        fields = []
        values = []
        if update.title is not None:
            fields.append("title = ?")
            values.append(update.title)
        if update.status is not None:
            fields.append("status = ?")
            values.append(update.status.value)
        if update.cvss_score is not None:
            fields.append("cvss_score = ?")
            values.append(update.cvss_score)
        if update.cvss_severity is not None:
            fields.append("cvss_severity = ?")
            values.append(update.cvss_severity.value)
        if update.remediation is not None:
            fields.append("remediation = ?")
            values.append(update.remediation)
        if update.description is not None:
            fields.append("description = ?")
            values.append(update.description)

        if not fields:
            return existing

        ts = datetime.now(timezone.utc).isoformat()
        fields.append("updated_at = ?")
        values.append(ts)
        values.append(finding_id)

        query = f"UPDATE findings SET {', '.join(fields)} WHERE id = ?"
        with db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, tuple(values))
            conn.commit()

        return self.get_finding(finding_id)

    def delete_finding(self, finding_id: str) -> bool:
        with db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM findings WHERE id = ?", (finding_id,))
            conn.commit()
            return cursor.rowcount > 0

    def find_duplicate(self, target_id: str, affected_asset: str, cve_id: Optional[str], title: str) -> Optional[Finding]:
        with db.get_connection() as conn:
            cursor = conn.cursor()
            if cve_id:
                cursor.execute(
                    "SELECT * FROM findings WHERE target_id = ? AND affected_asset = ? AND cve_id = ?",
                    (target_id, affected_asset, cve_id),
                )
            else:
                cursor.execute(
                    "SELECT * FROM findings WHERE target_id = ? AND affected_asset = ? AND title = ?",
                    (target_id, affected_asset, title),
                )
            row = cursor.fetchone()
            if row:
                return self._row_to_finding(dict(row))
        return None

    def append_evidence(self, finding_id: str, new_evidence: List[dict]) -> Optional[Finding]:
        finding = self.get_finding(finding_id)
        if not finding:
            return None
        existing_chain = [e.model_dump() for e in finding.evidence_chain]
        
        # Avoid duplicate evidence file_path + tool
        for ev in new_evidence:
            if not any(e.get("file_path") == ev.get("file_path") and e.get("tool") == ev.get("tool") for e in existing_chain):
                existing_chain.append(ev)

        ts = datetime.now(timezone.utc).isoformat()
        with db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE findings SET evidence_chain_json = ?, updated_at = ? WHERE id = ?",
                (json.dumps(existing_chain), ts, finding_id),
            )
            conn.commit()
        return self.get_finding(finding_id)

    def get_summary(self, target_id: Optional[str] = None) -> Dict[str, Any]:
        findings = self.list_findings(target_id=target_id)
        by_sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        by_stat = {"CANDIDATE": 0, "UNVERIFIED": 0, "VERIFIED": 0, "FALSE_POSITIVE": 0, "RESOLVED": 0}
        for f in findings:
            sev = f.cvss_severity.value
            stat = f.status.value
            by_sev[sev] = by_sev.get(sev, 0) + 1
            by_stat[stat] = by_stat.get(stat, 0) + 1
        return {
            "total": len(findings),
            "by_severity": by_sev,
            "by_status": by_stat,
        }

    def _row_to_finding(self, row: dict) -> Finding:
        chain_data = json.loads(row.get("evidence_chain_json") or "[]")
        return Finding(
            id=row["id"],
            target_id=row["target_id"],
            title=row["title"],
            cve_id=row.get("cve_id"),
            cwe_id=row.get("cwe_id"),
            cvss_score=float(row.get("cvss_score") or 0.0),
            cvss_severity=FindingSeverity(row.get("cvss_severity") or "INFO"),
            status=FindingStatus(row.get("status") or "CANDIDATE"),
            affected_asset=row["affected_asset"],
            description=row["description"],
            remediation=row.get("remediation"),
            evidence_chain=chain_data,
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )


findings_db = FindingsDatabase()
