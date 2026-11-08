"""SQLite storage for Findings with indexing and deduplication support."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

import re
from urllib.parse import urlparse

from backend.app.schemas.finding import (
    Finding,
    FindingCreate,
    FindingSeverity,
    FindingStatus,
    FindingUpdate,
)
from backend.app.storage.db import db


def score_to_severity(score: float) -> FindingSeverity:
    if score >= 9.0:
        return FindingSeverity.CRITICAL
    if score >= 7.0:
        return FindingSeverity.HIGH
    if score >= 4.0:
        return FindingSeverity.MEDIUM
    if score > 0.0:
        return FindingSeverity.LOW
    return FindingSeverity.INFO


def normalize_target_id(target_id: str | None) -> str:
    if not target_id:
        return ""
    clean = target_id.strip()
    if clean.startswith("target-"):
        clean = clean[7:]
    return clean


def normalize_asset(asset: str | None) -> tuple[str, int | None]:
    """Returns (host, port) from an asset string (URL, host:port, or bare host)."""
    if not asset:
        return ("", None)
    raw = asset.strip()
    if raw.startswith("target-"):
        raw = raw[7:]

    # If it's a URL
    if "://" in raw:
        try:
            parsed = urlparse(raw)
            host = parsed.hostname or ""
            port = parsed.port
            if not port:
                if parsed.scheme == "http":
                    port = 80
                elif parsed.scheme == "https":
                    port = 443
            return (host.lower(), port)
        except Exception:
            pass

    # If it's host:port
    if ":" in raw:
        parts = raw.split(":")
        host = parts[0].strip()
        port_part = parts[1].split("/")[0].strip()
        try:
            port = int(port_part)
            return (host.lower(), port)
        except ValueError:
            return (raw.lower(), None)

    # Bare host / IP
    clean_host = raw.split("/")[0].strip().lower()
    return (clean_host, None)


def are_assets_compatible(asset1: str, asset2: str) -> bool:
    """Check if two assets represent the same host and service/port."""
    h1, p1 = normalize_asset(asset1)
    h2, p2 = normalize_asset(asset2)

    # If both have explicit host and they differ, not compatible
    if h1 and h2 and h1 != h2:
        return False

    # If ports are identical, compatible
    if p1 == p2:
        return True

    # If one has no specific port (host-level finding), compatible
    if p1 is None or p2 is None:
        return True

    # Web ports on the same host (e.g. 80 vs http://host default port 80)
    web_ports = {80, 443, 8080, 8443, 3000, 5000, 8000}
    if p1 in web_ports and p2 in web_ports:
        return True

    return False


def clean_finding_title(title: str) -> str:
    """Strip tool prefixes and noise from finding title."""
    t = title.strip()
    prefixes = [
        "[SIMULATED] ",
        "[LƯU Ý: DỮ LIỆU MÔ PHỎNG / CHƯA XÁC MINH BẰNG CHỨNG THỰC TẾ]\n",
        "Nikto: ",
        "WhatWeb: ",
        "HTTPx Web Banner: ",
        "Nuclei: ",
        "SearchSploit Reference: ",
    ]
    for p in prefixes:
        if t.startswith(p):
            t = t[len(p) :].strip()
    return t


def normalize_title(title: str) -> str:
    """Normalized representation for comparing titles."""
    cleaned = clean_finding_title(title).lower()
    cleaned = re.sub(r"[^a-z0-9\s]", " ", cleaned)
    tokens = [tok for tok in cleaned.split() if len(tok) > 2]
    return " ".join(tokens)


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
    trustworthy INTEGER DEFAULT 1,
    is_simulated INTEGER DEFAULT 0,
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
            # Add columns if migrating existing db
            cursor = conn.cursor()
            try:
                cursor.execute(
                    "ALTER TABLE findings ADD COLUMN trustworthy INTEGER DEFAULT 1"
                )
            except Exception:
                pass
            try:
                cursor.execute(
                    "ALTER TABLE findings ADD COLUMN is_simulated INTEGER DEFAULT 0"
                )
            except Exception:
                pass
            conn.commit()

        # Run deduplication cleanup on initialization
        try:
            self.deduplicate_all()
        except Exception:
            pass

    def create_finding(self, finding_id: str, item: FindingCreate) -> Finding:
        ts = datetime.now(timezone.utc).isoformat()
        with db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT OR REPLACE INTO findings (
                    id, target_id, title, cve_id, cwe_id, cvss_score, cvss_severity,
                    status, affected_asset, description, evidence_chain_json, remediation,
                    trustworthy, is_simulated, created_at, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    1 if item.trustworthy else 0,
                    1 if item.is_simulated else 0,
                    ts,
                    ts,
                ),
            )
            conn.commit()
        return self.get_finding(finding_id)  # type: ignore

    def get_finding(self, finding_id: str) -> Finding | None:
        with db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM findings WHERE id = ?", (finding_id,))
            row = cursor.fetchone()
            if not row:
                return None
            return self._row_to_finding(dict(row))

    def list_findings(
        self,
        target_id: str | None = None,
        severity: str | None = None,
        status: str | None = None,
        trustworthy: bool | None = None,
    ) -> list[Finding]:
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
        if trustworthy is not None:
            query += " AND trustworthy = ?"
            params.append(1 if trustworthy else 0)
        query += " ORDER BY cvss_score DESC, updated_at DESC"

        with db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, tuple(params))
            rows = cursor.fetchall()
            return [self._row_to_finding(dict(r)) for r in rows]

    def update_finding(self, finding_id: str, update: FindingUpdate) -> Finding | None:
        existing = self.get_finding(finding_id)
        if not existing:
            return None

        fields = []
        values = []
        if update.title is not None:
            fields.append("title = ?")
            values.append(update.title)
        if update.cwe_id is not None:
            fields.append("cwe_id = ?")
            values.append(update.cwe_id)
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
        if update.trustworthy is not None:
            fields.append("trustworthy = ?")
            values.append(1 if update.trustworthy else 0)
        if update.is_simulated is not None:
            fields.append("is_simulated = ?")
            values.append(1 if update.is_simulated else 0)

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

    def delete_by_target(self, target_id: str) -> int:
        with db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM findings WHERE target_id = ?", (target_id,))
            conn.commit()
            return cursor.rowcount

    def find_duplicate(
        self, target_id: str, affected_asset: str, cve_id: str | None, title: str
    ) -> Finding | None:
        norm_target = normalize_target_id(target_id)
        candidates = self.list_findings(target_id=norm_target)
        if not candidates and target_id != norm_target:
            candidates = self.list_findings(target_id=target_id)
        if not candidates:
            candidates = self.list_findings(target_id=f"target-{norm_target}")

        # 1. Deduplicate by CVE if present (strongest deduplication key)
        if cve_id and cve_id.strip():
            clean_cve = cve_id.strip().upper()
            for cand in candidates:
                if cand.cve_id and cand.cve_id.strip().upper() == clean_cve:
                    if are_assets_compatible(cand.affected_asset, affected_asset):
                        return cand
            # If no asset-compatible match, same target + same CVE = duplicate
            for cand in candidates:
                if cand.cve_id and cand.cve_id.strip().upper() == clean_cve:
                    return cand

        # 2. Deduplicate by Title & Asset for non-CVE findings
        norm_t = normalize_title(title)
        if norm_t:
            for cand in candidates:
                cand_norm_t = normalize_title(cand.title)
                if cand_norm_t and (
                    cand_norm_t == norm_t
                    or cand_norm_t in norm_t
                    or norm_t in cand_norm_t
                ):
                    if are_assets_compatible(cand.affected_asset, affected_asset):
                        return cand

        # 3. Fallback exact match query
        with db.get_connection() as conn:
            cursor = conn.cursor()
            if cve_id:
                cursor.execute(
                    "SELECT * FROM findings WHERE (target_id = ? OR target_id = ?) AND affected_asset = ? AND cve_id = ?",
                    (norm_target, target_id, affected_asset, cve_id),
                )
            else:
                cursor.execute(
                    "SELECT * FROM findings WHERE (target_id = ? OR target_id = ?) AND affected_asset = ? AND title = ?",
                    (norm_target, target_id, affected_asset, title),
                )
            row = cursor.fetchone()
            if row:
                return self._row_to_finding(dict(row))
        return None

    def merge_findings(self, master_id: str, duplicate_ids: list[str]) -> Finding | None:
        """Merge multiple duplicate findings into a single consolidated master finding."""
        master = self.get_finding(master_id)
        if not master:
            return None

        valid_dup_ids = [d for d in duplicate_ids if d != master_id]
        if not valid_dup_ids:
            return master

        duplicates: list[Finding] = []
        for did in valid_dup_ids:
            d = self.get_finding(did)
            if d:
                duplicates.append(d)

        if not duplicates:
            return master

        # 1. Combine unique evidence chain entries
        existing_chain = [e.model_dump() for e in master.evidence_chain]
        for d in duplicates:
            for ev in d.evidence_chain:
                ev_dict = ev.model_dump()
                if not any(
                    e.get("file_path") == ev_dict.get("file_path")
                    and e.get("tool") == ev_dict.get("tool")
                    for e in existing_chain
                ):
                    existing_chain.append(ev_dict)

        # 2. Maximum CVSS and Severity
        all_cvss = [master.cvss_score] + [d.cvss_score for d in duplicates]
        max_cvss = max(all_cvss)
        max_sev = score_to_severity(max_cvss)

        # 3. Prefer specific CWE over generic
        cwe_id = master.cwe_id
        for d in duplicates:
            if d.cwe_id and (not cwe_id or cwe_id in ("CWE-20", "CWE-Other")):
                cwe_id = d.cwe_id

        # 4. Trustworthy & Simulation flags
        is_trustworthy = master.trustworthy or any(d.trustworthy for d in duplicates)
        is_simulated = master.is_simulated and all(d.is_simulated for d in duplicates)

        # 5. Status: If any is verified, status becomes VERIFIED
        status = master.status
        if any(d.status == FindingStatus.VERIFIED for d in duplicates):
            status = FindingStatus.VERIFIED

        # 6. Title: Pick the cleanest, most informative title
        clean_titles = [clean_finding_title(master.title)] + [
            clean_finding_title(d.title) for d in duplicates
        ]
        best_title = master.title
        for t in clean_titles:
            if master.cve_id and master.cve_id in t and not any(
                t.startswith(p)
                for p in ("Nikto:", "WhatWeb:", "HTTPx:", "SearchSploit:")
            ):
                best_title = t
                break
        if is_simulated and not best_title.startswith("[SIMULATED]"):
            best_title = f"[SIMULATED] {best_title}"
        elif not is_simulated and best_title.startswith("[SIMULATED]"):
            best_title = best_title.replace("[SIMULATED] ", "").strip()

        # 7. Asset: Prefer asset with explicit port
        affected_asset = master.affected_asset
        for d in duplicates:
            if ":" in d.affected_asset and ":" not in affected_asset:
                affected_asset = d.affected_asset
                break

        # 8. Remediation: Keep longest / most complete description
        remediation = master.remediation
        for d in duplicates:
            if d.remediation and len(d.remediation) > len(remediation or ""):
                remediation = d.remediation

        ts = datetime.now(timezone.utc).isoformat()
        with db.get_connection() as conn:
            cursor = conn.cursor()
            # Delete redundant duplicate records
            placeholders = ",".join(["?"] * len(valid_dup_ids))
            cursor.execute(
                f"DELETE FROM findings WHERE id IN ({placeholders})",
                tuple(valid_dup_ids),
            )

            # Update consolidated master record
            cursor.execute(
                """
                UPDATE findings
                SET title = ?, cwe_id = ?, cvss_score = ?, cvss_severity = ?,
                    status = ?, affected_asset = ?, evidence_chain_json = ?,
                    remediation = ?, trustworthy = ?, is_simulated = ?, updated_at = ?
                WHERE id = ?
                """,
                (
                    best_title,
                    cwe_id,
                    max_cvss,
                    max_sev.value,
                    status.value,
                    affected_asset,
                    json.dumps(existing_chain),
                    remediation,
                    1 if is_trustworthy else 0,
                    1 if is_simulated else 0,
                    ts,
                    master_id,
                ),
            )
            conn.commit()

        return self.get_finding(master_id)

    def deduplicate_all(self, target_id: str | None = None) -> dict:
        """Finds duplicate findings across target(s) and merges them into consolidated master findings."""
        norm_target = normalize_target_id(target_id) if target_id else None
        findings = self.list_findings(target_id=norm_target)
        if norm_target and not findings:
            findings = self.list_findings(target_id=f"target-{norm_target}")
        if not norm_target:
            findings = self.list_findings()

        # Group findings by deduplication key
        groups: dict[str, list[Finding]] = {}
        for f in findings:
            t_id = normalize_target_id(f.target_id)
            if f.cve_id and f.cve_id.strip():
                # Same target + same CVE = same vulnerability
                key = f"cve:{t_id}:{f.cve_id.strip().upper()}"
            else:
                _, p = normalize_asset(f.affected_asset)
                norm_t = normalize_title(f.title)
                p_str = str(p) if p else "all"
                key = f"title:{t_id}:{p_str}:{norm_t}"
            groups.setdefault(key, []).append(f)

        merged_groups = 0
        removed_count = 0
        for key, group in groups.items():
            if len(group) > 1:
                # Sort group to pick the highest quality finding as master:
                # 1. Real evidence first, 2. Highest CVSS, 3. Verified, 4. Most evidence items
                group.sort(
                    key=lambda x: (
                        1 if x.trustworthy and not x.is_simulated else 0,
                        x.cvss_score,
                        1 if x.status == FindingStatus.VERIFIED else 0,
                        len(x.evidence_chain),
                    ),
                    reverse=True,
                )
                master = group[0]
                dup_ids = [item.id for item in group[1:]]
                self.merge_findings(master.id, dup_ids)
                merged_groups += 1
                removed_count += len(dup_ids)

        remaining = len(self.list_findings(target_id=norm_target if norm_target else None))
        return {
            "target_id": target_id,
            "merged_groups": merged_groups,
            "removed_duplicates": removed_count,
            "remaining_findings": remaining,
        }

    def append_evidence(
        self, finding_id: str, new_evidence: list[dict]
    ) -> Finding | None:
        finding = self.get_finding(finding_id)
        if not finding:
            return None
        existing_chain = [e.model_dump() for e in finding.evidence_chain]

        for ev in new_evidence:
            if not any(
                e.get("file_path") == ev.get("file_path")
                and e.get("tool") == ev.get("tool")
                for e in existing_chain
            ):
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

    def get_summary(self, target_id: str | None = None) -> dict[str, Any]:
        findings = self.list_findings(target_id=target_id)
        by_sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        by_stat = {
            "CANDIDATE": 0,
            "UNVERIFIED": 0,
            "VERIFIED": 0,
            "FALSE_POSITIVE": 0,
            "RESOLVED": 0,
        }
        trustworthy_count = 0
        simulated_count = 0

        for f in findings:
            sev = f.cvss_severity.value
            stat = f.status.value
            by_sev[sev] = by_sev.get(sev, 0) + 1
            by_stat[stat] = by_stat.get(stat, 0) + 1
            if f.trustworthy and not f.is_simulated:
                trustworthy_count += 1
            else:
                simulated_count += 1

        return {
            "total": len(findings),
            "by_severity": by_sev,
            "by_status": by_stat,
            "trustworthy_count": trustworthy_count,
            "simulated_count": simulated_count,
            "has_insufficient_evidence": (trustworthy_count == 0),
        }

    def _row_to_finding(self, row: dict) -> Finding:
        chain_data = json.loads(row.get("evidence_chain_json") or "[]")
        cve_id = row.get("cve_id")
        threat_intel: dict[str, Any] = {}
        if cve_id:
            try:
                with db.get_connection() as conn:
                    c = conn.cursor().execute(
                        "SELECT is_cisa_kev, epss_score, epss_percentile, cvss_v4_score, cvss_v4_vector, cvss_v4_severity FROM cve WHERE cve_id = ?",
                        (cve_id.upper(),)
                    ).fetchone()
                    if c:
                        threat_intel = dict(c)
            except Exception:
                pass

        return Finding(
            id=row["id"],
            target_id=row["target_id"],
            title=row["title"],
            cve_id=cve_id,
            cwe_id=row.get("cwe_id"),
            cvss_score=float(row.get("cvss_score") or 0.0),
            cvss_severity=FindingSeverity(row.get("cvss_severity") or "INFO"),
            cvss_v4_score=threat_intel.get("cvss_v4_score"),
            cvss_v4_vector=threat_intel.get("cvss_v4_vector"),
            cvss_v4_severity=threat_intel.get("cvss_v4_severity"),
            is_cisa_kev=bool(threat_intel.get("is_cisa_kev", 0)),
            epss_score=threat_intel.get("epss_score"),
            epss_percentile=threat_intel.get("epss_percentile"),
            status=FindingStatus(row.get("status") or "CANDIDATE"),
            affected_asset=row["affected_asset"],
            description=row["description"],
            remediation=row.get("remediation"),
            evidence_chain=chain_data,
            trustworthy=bool(row.get("trustworthy", 1)),
            is_simulated=bool(row.get("is_simulated", 0)),
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )


findings_db = FindingsDatabase()
