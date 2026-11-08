# Dynamic Target System & Extensible Lab Model

## Overview
AI-Pentest Copilot introduces a zero-friction, dynamic target ingestion pipeline. Users do not need to author static YAML files before launching reconnaissance. Targets are validated in real-time, matched against security scopes, and mapped to optimized multi-tool reconnaissance plans.

## Pipeline Flow
```text
User Target Input (IP, CIDR, URL, Host:Port, Domain)
  ↓
Target Parser (Type detection, URI extraction, protocol parsing)
  ↓
Target Normalizer (Canonical form, lowercase, default port resolution)
  ↓
Target Validator (Syntax & RFC constraints)
  ↓
Scope Validator (Authorization whitelist check against ALLOWED_SCOPES)
  ↓
Target Registry (Persisted Target Object)
  ↓
Recon Planner (Capability mapping & service-driven tool scheduling)
  ↓
Recon Runner (Multi-tool execution, raw evidence & commands.md audit)
  ↓
Structured JSON Parsers & Schema Validation (security/schemas/)
  ↓
Evidence Consolidation & Manifest Indexing (toolkit/09-analysis/manifests/)
  ↓
Context Engine & Conflict Detection (Cross-tool discrepancy analysis)
```

## Supported Target Types
- **IPv4**: `192.168.56.101`
- **IPv6**: `::1`, `fe80::1`
- **CIDR**: `192.168.56.0/24`
- **URL**: `http://192.168.56.101:3000`, `https://example.local/app`
- **Host:Port**: `10.10.10.20:8080`
- **Domain / Hostname**: `juice-shop.local`, `target.corp`

## Scope Enforcement
Configured via `ALLOWED_SCOPES` (default: RFC1918 private subnets, localhost, and `*.local`). Any target outside authorized boundaries is immediately blocked with exit code 2.

## Service-Driven Tool Routing
The Recon Planner dynamically adapts tool selection based on discovered services and open ports:
- **Port 445 / 139 (SMB)**: Schedules `enum4linux` (domain/users/shares) and `smbclient` (null sessions).
- **Port 161 (SNMP)**: Schedules `snmpwalk` (system MIB tree enumeration).
- **Port 389 / 636 (LDAP)**: Schedules `ldapsearch` (directory schema and naming contexts).
- **Database Ports (3306, 5432, 6379, 27017, 1433)**: Schedules non-destructive database client inspection (`mysql`, `psql`, `redis-cli`, `mongosh`, `sqlcmd`).
- **Web Ports & URLs (80, 443, 8080, etc.)**: Schedules `httpx`, `whatweb`, `nikto`, `gobuster`, `ffuf`, and `katana`.
- **Identified Software Versions**: Schedules `searchsploit` for offline CVE and exploit reference lookups.
