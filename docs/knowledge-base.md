# Vulnerability Knowledge Base & Correlation Engine

## Architecture & Storage
AI-Pentest Copilot utilizes a hybrid storage model:
- **SQLite Database**: Exact metadata matching, structured queries, version index, and authoritative records (`cve`, `cve_affected`, `cwe`, `mitre_technique`, `cisa_kev`, `product_version_index`).
- **Data Provenance**: Every record preserves strict traceability with `source_url`, `source_name`, `ingested_at`, and `last_modified`.

## Authoritative Sources
1. **National Vulnerability Database (NVD)**: CVE IDs, descriptions, CVSS v3/v4 vectors, CWE mappings, CPE URIs, affected version ranges.
2. **MITRE CWE**: Weakness enumeration, likelihood of exploit, mitigations, hierarchical relationships.
3. **MITRE ATT&CK**: Adversary techniques and tactics.
4. **CISA KEV**: Known Exploited Vulnerabilities catalog.

## Semantic Version Correlator
The correlator matches detected service banners and versions against indexed vulnerabilities using semantic numeric tuple comparisons (e.g., `2.4.49` vs `2.4.9` correctly compared as `(2, 4, 49) > (2, 4, 9)`):
- **Exact Version Match**: Confidence `0.95`.
- **Version Range Match**: Confidence `0.85`.
- **Product-Only Match**: Confidence `0.50` (clearly flagged as unverified version).

## REST API Endpoints
- `GET /api/vulnerabilities/cve/{cve_id}`: Retrieves full CVE record, CVSS scores, CWEs, and affected products.
- `GET /api/vulnerabilities/cwe/{cwe_id}`: Retrieves weakness details, likelihood, and mitigation guidance.
- `GET /api/vulnerabilities/correlate?product={prod}&version={ver}`: Returns correlated CVE candidates ranked by confidence.
- `GET /api/vulnerabilities/stats`: Returns database item counts.
- `GET /api/vulnerabilities/search?query={q}`: Performs full-text search across CVE descriptions and IDs.
