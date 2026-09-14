# Dynamic Target System & Extensible Lab Model

## Overview
AI-Pentest Copilot v5.0 introduces a zero-friction, dynamic target ingestion pipeline. Users do not need to author static YAML files before launching reconnaissance.

## Pipeline Flow
```text
User Target Input (IP, CIDR, URL, Host:Port, Domain)
  ↓
Target Parser (Type detection, URI extraction)
  ↓
Target Normalizer (Canonical form, lowercase, port resolution)
  ↓
Target Validator (Syntax & RFC constraints)
  ↓
Scope Validator (Authorization whitelist check)
  ↓
Target Registry (Persisted Target Object)
  ↓
Recon Planner (Capability mapping & verification-only steps)
  ↓
Recon Runner (Nmap raw evidence & commands.md audit)
  ↓
Structured JSON Parser & Schema Validation
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
