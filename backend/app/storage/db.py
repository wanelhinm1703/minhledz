import pathlib
import sqlite3
import sys

# Ensure repo root is in sys.path
REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from backend.app.config import settings

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS cve (
    cve_id TEXT PRIMARY KEY,
    description TEXT NOT NULL,
    published TEXT,
    last_modified TEXT,
    cvss_v3_score REAL,
    cvss_v3_vector TEXT,
    cvss_v3_severity TEXT,
    cvss_v4_score REAL,
    cvss_v4_vector TEXT,
    cvss_v4_severity TEXT,
    epss_score REAL DEFAULT 0.0,
    epss_percentile REAL DEFAULT 0.0,
    is_cisa_kev INTEGER DEFAULT 0,
    cwe_ids TEXT,
    references_json TEXT,
    source_url TEXT NOT NULL,
    source_name TEXT NOT NULL,
    ingested_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cve_affected (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id TEXT NOT NULL,
    vendor TEXT,
    product TEXT,
    version_start TEXT,
    version_end TEXT,
    version_exact TEXT,
    cpe_uri TEXT,
    FOREIGN KEY (cve_id) REFERENCES cve(cve_id)
);

CREATE TABLE IF NOT EXISTS cwe (
    cwe_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    extended_description TEXT,
    likelihood TEXT,
    mitigations TEXT,
    parent_cwe TEXT,
    source_url TEXT NOT NULL,
    source_name TEXT NOT NULL,
    ingested_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS mitre_technique (
    technique_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    tactic TEXT,
    description TEXT,
    detection TEXT,
    platforms TEXT,
    source_url TEXT NOT NULL,
    ingested_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cisa_kev (
    cve_id TEXT PRIMARY KEY,
    vendor_project TEXT,
    product TEXT,
    vulnerability_name TEXT,
    date_added TEXT,
    required_action TEXT,
    due_date TEXT,
    FOREIGN KEY (cve_id) REFERENCES cve(cve_id)
);

CREATE TABLE IF NOT EXISTS product_version_index (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    vendor TEXT NOT NULL,
    product TEXT NOT NULL,
    version TEXT NOT NULL,
    cve_ids TEXT,
    confidence REAL
);

CREATE INDEX IF NOT EXISTS idx_affected_product ON cve_affected(vendor, product);
CREATE INDEX IF NOT EXISTS idx_product_version ON product_version_index(vendor, product, version);
"""


class Database:
    def __init__(self, db_path: pathlib.Path | None = None):
        self.db_path = db_path or settings.get_kb_db_path()
        self.init_db()

    def get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def init_db(self):
        with self.get_connection() as conn:
            conn.executescript(SCHEMA_SQL)
            cursor = conn.cursor()
            for col, col_type in [
                ("cvss_v4_severity", "TEXT"),
                ("epss_score", "REAL DEFAULT 0.0"),
                ("epss_percentile", "REAL DEFAULT 0.0"),
                ("is_cisa_kev", "INTEGER DEFAULT 0"),
            ]:
                try:
                    cursor.execute(f"ALTER TABLE cve ADD COLUMN {col} {col_type}")
                except Exception:
                    pass
            conn.commit()

    def get_stats(self) -> dict[str, int]:
        with self.get_connection() as conn:
            cve_count = conn.execute("SELECT COUNT(*) FROM cve").fetchone()[0]
            affected_count = conn.execute(
                "SELECT COUNT(*) FROM cve_affected"
            ).fetchone()[0]
            cwe_count = conn.execute("SELECT COUNT(*) FROM cwe").fetchone()[0]
            mitre_count = conn.execute(
                "SELECT COUNT(*) FROM mitre_technique"
            ).fetchone()[0]
            kev_count = conn.execute("SELECT COUNT(*) FROM cisa_kev").fetchone()[0]
            idx_count = conn.execute(
                "SELECT COUNT(*) FROM product_version_index"
            ).fetchone()[0]

        return {
            "cve_count": cve_count,
            "cve_affected_count": affected_count,
            "cwe_count": cwe_count,
            "mitre_technique_count": mitre_count,
            "cisa_kev_count": kev_count,
            "product_version_index_count": idx_count,
        }


db = Database()


if __name__ == "__main__":
    stats = db.get_stats()
    print("Vulnerability Knowledge Base Statistics:")
    for k, v in stats.items():
        print(f"  {k}: {v}")
