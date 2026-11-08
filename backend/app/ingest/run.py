#!/usr/bin/env python3
"""
AI-Pentest Copilot - Knowledge Base Ingestion Runner.
Loads authoritative CVE, CWE, MITRE, and CISA KEV data into SQLite.
Populates product_version_index for high-performance correlation.
"""

from __future__ import annotations

import argparse
import time

from backend.app.ingest.cwe import ingest_cwes
from backend.app.ingest.kev import ingest_cisa_kev
from backend.app.ingest.mitre import ingest_mitre_techniques
from backend.app.ingest.nvd import ingest_nvd_cves
from backend.app.storage.db import db


def populate_product_version_index(conn):
    cursor = conn.cursor()
    cursor.execute("DELETE FROM product_version_index")

    # Query distinct vendor, product, version from cve_affected
    cursor.execute("""
        SELECT vendor, product, version_exact, GROUP_CONCAT(cve_id) 
        FROM cve_affected 
        WHERE version_exact IS NOT NULL 
        GROUP BY vendor, product, version_exact
    """)
    rows = cursor.fetchall()
    for vendor, prod, ver, cves in rows:
        cursor.execute(
            """
            INSERT INTO product_version_index (vendor, product, version, cve_ids, confidence)
            VALUES (?, ?, ?, ?, ?)
            """,
            (vendor.lower(), prod.lower(), ver, cves, 0.95),
        )
    conn.commit()


def run_ingest(update: bool = False):
    print("\n=======================================================")
    print("[*] AI-PENTEST COPILOT - KNOWLEDGE BASE INGESTION")
    print(f"[*] Mode: {'Update' if update else 'Full Ingest'}")
    print(f"[*] Target Database: {db.db_path}")
    print("=======================================================\n")

    start_time = time.time()
    with db.get_connection() as conn:
        print("==> [1/5] Ingesting MITRE CWE catalog...")
        cwe_count = ingest_cwes(conn)
        print(f"    [OK] Ingested {cwe_count} CWE entries.")

        print("==> [2/5] Ingesting National Vulnerability Database (NVD) CVEs...")
        cve_count = ingest_nvd_cves(conn)
        print(f"    [OK] Ingested {cve_count} CVE records.")

        print("==> [3/5] Ingesting MITRE ATT&CK techniques...")
        mitre_count = ingest_mitre_techniques(conn)
        print(f"    [OK] Ingested {mitre_count} ATT&CK techniques.")

        print("==> [4/5] Ingesting CISA Known Exploited Vulnerabilities (KEV)...")
        kev_count = ingest_cisa_kev(conn)
        print(f"    [OK] Ingested {kev_count} KEV catalog items.")

        print("==> [5/5] Building Product-Version Correlation Index...")
        populate_product_version_index(conn)
        print("    [OK] Index built successfully.")

    duration = time.time() - start_time
    stats = db.get_stats()

    print("\n-------------------------------------------------------")
    print("[*] INGESTION COMPLETED SUCCESSFULLY!")
    print(f"[*] Total CVEs in Knowledge Base:  {stats['cve_count']}")
    print(f"[*] Total CWEs in Knowledge Base:  {stats['cwe_count']}")
    print(f"[*] Affected Versions Indexed:    {stats['product_version_index_count']}")
    print(f"[*] Elapsed Time:                 {duration:.2f}s")
    print("-------------------------------------------------------\n")


def main():
    parser = argparse.ArgumentParser(description="AI-Pentest Copilot KB Ingest")
    parser.add_argument(
        "--update", action="store_true", help="Perform incremental update"
    )
    args = parser.parse_args()
    run_ingest(update=args.update)


if __name__ == "__main__":
    main()
