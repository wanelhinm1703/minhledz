from __future__ import annotations

import sqlite3

CISA_KEV_ENTRIES = [
    ("CVE-2021-41773", "Apache", "HTTP Server", "Apache HTTP Server Path Traversal Vulnerability", "2021-11-03", "Apply vendor patches or upgrade immediately.", "2021-11-17"),
    ("CVE-2021-42013", "Apache", "HTTP Server", "Apache HTTP Server Path Traversal and Remote Code Execution", "2021-11-03", "Apply vendor patches or upgrade immediately.", "2021-11-17"),
    ("CVE-2021-44228", "Apache", "Log4j", "Apache Log4j2 Remote Code Execution Vulnerability", "2021-12-10", "Apply updates per vendor instructions.", "2021-12-24"),
    ("CVE-2022-22965", "VMware", "Spring Framework", "Spring Framework Remote Code Execution Vulnerability", "2022-04-04", "Apply updates per vendor instructions.", "2022-04-25"),
    ("CVE-2024-6387", "OpenBSD", "OpenSSH", "OpenSSH Signal Handler Race Condition Remote Code Execution", "2024-07-02", "Apply updates per vendor instructions.", "2024-07-23"),
]

def ingest_cisa_kev(conn: sqlite3.Connection) -> int:
    cursor = conn.cursor()
    count = 0
    for cve_id, vendor, prod, name, added, action, due in CISA_KEV_ENTRIES:
        cursor.execute(
            """
            INSERT INTO cisa_kev (cve_id, vendor_project, product, vulnerability_name, date_added, required_action, due_date)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(cve_id) DO UPDATE SET
                vulnerability_name=excluded.vulnerability_name,
                required_action=excluded.required_action
            """,
            (cve_id, vendor, prod, name, added, action, due),
        )
        count += 1
    conn.commit()
    return count
