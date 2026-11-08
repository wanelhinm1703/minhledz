from __future__ import annotations

import sqlite3

CISA_KEV_ENTRIES = [
    (
        "CVE-2021-41773",
        "Apache",
        "HTTP Server",
        "Apache HTTP Server Path Traversal Vulnerability",
        "2021-11-03",
        "Apply vendor patches or upgrade immediately.",
        "2021-11-17",
    ),
    (
        "CVE-2021-42013",
        "Apache",
        "HTTP Server",
        "Apache HTTP Server Path Traversal and Remote Code Execution",
        "2021-11-03",
        "Apply vendor patches or upgrade immediately.",
        "2021-11-17",
    ),
    (
        "CVE-2021-44228",
        "Apache",
        "Log4j",
        "Apache Log4j2 Remote Code Execution Vulnerability",
        "2021-12-10",
        "Apply updates per vendor instructions.",
        "2021-12-24",
    ),
    (
        "CVE-2022-22965",
        "VMware",
        "Spring Framework",
        "Spring Framework Remote Code Execution Vulnerability",
        "2022-04-04",
        "Apply updates per vendor instructions.",
        "2022-04-25",
    ),
    (
        "CVE-2024-6387",
        "OpenBSD",
        "OpenSSH",
        "OpenSSH Signal Handler Race Condition Remote Code Execution",
        "2024-07-02",
        "Apply updates per vendor instructions.",
        "2024-07-23",
    ),
]


THREAT_INTEL_ENRICHMENT = {
    "CVE-2021-41773": {
        "is_cisa_kev": 1,
        "epss_score": 0.975,
        "epss_percentile": 0.998,
        "cvss_v4_score": 8.7,
        "cvss_v4_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
        "cvss_v4_severity": "HIGH",
    },
    "CVE-2021-42013": {
        "is_cisa_kev": 1,
        "epss_score": 0.968,
        "epss_percentile": 0.997,
        "cvss_v4_score": 9.3,
        "cvss_v4_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
        "cvss_v4_severity": "CRITICAL",
    },
    "CVE-2021-44228": {
        "is_cisa_kev": 1,
        "epss_score": 0.974,
        "epss_percentile": 0.999,
        "cvss_v4_score": 10.0,
        "cvss_v4_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
        "cvss_v4_severity": "CRITICAL",
    },
    "CVE-2022-22965": {
        "is_cisa_kev": 1,
        "epss_score": 0.953,
        "epss_percentile": 0.989,
        "cvss_v4_score": 9.3,
        "cvss_v4_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
        "cvss_v4_severity": "CRITICAL",
    },
    "CVE-2024-6387": {
        "is_cisa_kev": 1,
        "epss_score": 0.812,
        "epss_percentile": 0.954,
        "cvss_v4_score": 8.1,
        "cvss_v4_vector": "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
        "cvss_v4_severity": "HIGH",
    },
    "CVE-2017-0144": {
        "is_cisa_kev": 1,
        "epss_score": 0.972,
        "epss_percentile": 0.998,
        "cvss_v4_score": 9.8,
        "cvss_v4_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
        "cvss_v4_severity": "CRITICAL",
    },
    "CVE-2020-1472": {
        "is_cisa_kev": 1,
        "epss_score": 0.971,
        "epss_percentile": 0.998,
        "cvss_v4_score": 9.9,
        "cvss_v4_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
        "cvss_v4_severity": "CRITICAL",
    },
}


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
        # Update cve table
        cursor.execute("UPDATE cve SET is_cisa_kev = 1 WHERE cve_id = ?", (cve_id,))
        count += 1

    # Enrich CVEs with threat intel (EPSS, CVSS 4.0)
    for cve_id, data in THREAT_INTEL_ENRICHMENT.items():
        cursor.execute(
            """
            UPDATE cve
            SET is_cisa_kev = ?,
                epss_score = ?,
                epss_percentile = ?,
                cvss_v4_score = ?,
                cvss_v4_vector = ?,
                cvss_v4_severity = ?
            WHERE cve_id = ?
            """,
            (
                data["is_cisa_kev"],
                data["epss_score"],
                data["epss_percentile"],
                data["cvss_v4_score"],
                data["cvss_v4_vector"],
                data["cvss_v4_severity"],
                cve_id,
            ),
        )

    conn.commit()
    return count
