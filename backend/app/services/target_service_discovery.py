"""Target Service Discovery: discovers and normalizes open ports, services, and software versions for a target."""

from __future__ import annotations

import json
import pathlib
import re
from typing import Any

from backend.app.storage.findings_db import findings_db

ROOT_DIR = pathlib.Path(__file__).resolve().parent.parent.parent.parent


def normalize_product_name(raw_name: str) -> str:
    """Normalize service product name for CVE and Vulnerability Intel matching."""
    s = (raw_name or "").strip()
    low = s.lower()

    if "apache" in low:
        return "Apache"
    if "openssh" in low:
        return "OpenSSH"
    if "nginx" in low:
        return "nginx"
    if "node" in low:
        return "Node.js"
    if "mysql" in low:
        return "MySQL"
    if "postgres" in low:
        return "PostgreSQL"
    if "redis" in low:
        return "Redis"
    if "vsftpd" in low:
        return "vsftpd"
    if "proftpd" in low:
        return "ProFTPD"
    if "samba" in low or "smbd" in low:
        return "Samba"
    if "log4j" in low:
        return "Log4j"
    if "php" in low:
        return "PHP"

    return s


def infer_well_known_service(port: int, proto: str = "tcp") -> tuple[str, str, str]:
    """Infers (service_name, product, version) from well-known ports when banner is missing."""
    known = {
        21: ("ftp", "FTP", ""),
        22: ("ssh", "OpenSSH", ""),
        23: ("telnet", "Telnet", ""),
        25: ("smtp", "SMTP", ""),
        53: ("domain", "DNS", ""),
        80: ("http", "HTTP", ""),
        110: ("pop3", "POP3", ""),
        143: ("imap", "IMAP", ""),
        443: ("https", "HTTPS", ""),
        902: ("vmware-auth", "VMware Authentication Daemon", ""),
        993: ("imaps", "IMAP SSL", ""),
        995: ("pop3s", "POP3 SSL", ""),
        3000: ("http", "Node.js", ""),
        3306: ("mysql", "MySQL", ""),
        5173: ("http", "Vite", ""),
        5432: ("postgresql", "PostgreSQL", ""),
        6379: ("redis", "Redis", ""),
        8000: ("http", "Uvicorn", ""),
        8080: ("http-proxy", "HTTP-Proxy", ""),
        8443: ("https-alt", "HTTPS-Alt", ""),
        9200: ("elasticsearch", "Elasticsearch", ""),
        27017: ("mongodb", "MongoDB", ""),
    }
    if port in known:
        return known[port]
    return (f"port-{port}", f"TCP-{port}" if proto == "tcp" else f"UDP-{port}", "")


def discover_target_services(target_id: str) -> list[dict[str, Any]]:
    """Discover all open ports, services, and software versions for a given target.

    Inspects:
    1. Network scan results (Nmap, RustScan, Naabu structured and simulated)
    2. Web recon results (HTTPX & WhatWeb)
    3. Target findings in SQLite database (strictly cross-validated with verified open ports)
    """
    raw_id = (
        target_id[7:] if target_id.startswith("target-") else target_id
    )
    clean_id = (
        raw_id.replace("http://", "")
        .replace("https://", "")
        .strip("/")
        .replace(":", "-")
    )
    candidates = [
        raw_id,
        clean_id,
        target_id,
        f"target-{clean_id}",
        f"target-{raw_id}",
    ]
    seen_cands = []
    for c in candidates:
        if c not in seen_cands:
            seen_cands.append(c)

    services_by_key: dict[str, dict[str, Any]] = {}
    verified_network_ports: set[int] = set()
    network_scans_performed = False

    # 1. Network Scans (Nmap, RustScan, Naabu) - primary source of ground truth
    net_base = ROOT_DIR / "toolkit" / "03-network" / "scans"
    for cand in seen_cands:
        cand_dir = net_base / cand
        if not cand_dir.exists():
            continue

        # 1a. Nmap scans
        nmap_dir = cand_dir / "nmap"
        if nmap_dir.exists():
            network_scans_performed = True
            json_candidates = [
                nmap_dir / "structured" / "nmap_result.json",
                nmap_dir / "simulated" / "nmap_result.json",
            ]

            for jf in json_candidates:
                if not jf.exists():
                    continue
                try:
                    data = json.loads(jf.read_text(encoding="utf-8", errors="replace"))
                    ports_list = []
                    hosts = data.get("hosts", [])
                    for h in hosts:
                        ports_list.extend(h.get("ports", []))
                    if not ports_list:
                        ports_list = data.get("ports", []) or data.get("open_ports", [])

                    for p in ports_list:
                        if not isinstance(p, dict):
                            continue
                        state = p.get("state", "open")
                        if isinstance(state, dict):
                            state = state.get("state", "open")
                        if state != "open":
                            continue

                        raw_port = p.get("portid") or p.get("port") or 0
                        try:
                            port_num = int(raw_port)
                        except Exception:
                            port_num = 0

                        if not (1 <= port_num <= 65535):
                            continue

                        verified_network_ports.add(port_num)
                        proto = p.get("protocol") or "tcp"
                        svc_obj = p.get("service", {})
                        if isinstance(svc_obj, dict):
                            s_name = svc_obj.get("name", "")
                            prod = svc_obj.get("product", "")
                            ver = svc_obj.get("version", "")
                            cpe = svc_obj.get("cpe", [])
                        else:
                            s_name = str(svc_obj)
                            prod = p.get("product", "")
                            ver = p.get("version", "")
                            cpe = []

                        raw_prod = prod or s_name
                        clean_prod = normalize_product_name(raw_prod)
                        if not clean_prod:
                            clean_prod = s_name or f"Port-{port_num}"

                        key = f"{port_num}:{proto}:{clean_prod}".lower()
                        label = f"Port {port_num}/{proto} — {clean_prod}"
                        if ver:
                            label += f" {ver}"

                        services_by_key[key] = {
                            "port": port_num,
                            "protocol": proto,
                            "service_name": s_name or clean_prod.lower(),
                            "product": clean_prod,
                            "raw_product": raw_prod,
                            "version": ver,
                            "cpe": cpe if isinstance(cpe, list) else [str(cpe)],
                            "source": "nmap",
                            "label": label,
                        }
                except Exception:
                    pass

        # 1b. RustScan scans
        rustscan_dir = cand_dir / "rustscan"
        if rustscan_dir.exists():
            network_scans_performed = True
            for rj in [rustscan_dir / "structured" / "rustscan_result.json", rustscan_dir / "simulated" / "rustscan_result.json"]:
                if not rj.exists():
                    continue
                try:
                    rdata = json.loads(rj.read_text(encoding="utf-8", errors="replace"))
                    for p in rdata.get("open_ports", []):
                        try:
                            p_num = int(p)
                        except Exception:
                            continue
                        if 1 <= p_num <= 65535:
                            verified_network_ports.add(p_num)
                            if not any(s["port"] == p_num for s in services_by_key.values()):
                                s_name, prod, ver = infer_well_known_service(p_num, "tcp")
                                clean_prod = normalize_product_name(prod)
                                key = f"{p_num}:tcp:{clean_prod}".lower()
                                services_by_key[key] = {
                                    "port": p_num,
                                    "protocol": "tcp",
                                    "service_name": s_name,
                                    "product": clean_prod,
                                    "raw_product": prod,
                                    "version": ver,
                                    "cpe": [],
                                    "source": "rustscan",
                                    "label": f"Port {p_num}/tcp — {clean_prod}",
                                }
                except Exception:
                    pass

        # 1c. Naabu scans
        naabu_dir = cand_dir / "naabu"
        if naabu_dir.exists():
            network_scans_performed = True
            raw_file = naabu_dir / "raw" / "naabu_raw.txt"
            if raw_file.exists():
                try:
                    lines = raw_file.read_text(encoding="utf-8", errors="replace").splitlines()
                    for line in lines:
                        line = line.strip()
                        if ":" in line:
                            try:
                                p_num = int(line.split(":")[-1])
                                if 1 <= p_num <= 65535:
                                    verified_network_ports.add(p_num)
                                    if not any(s["port"] == p_num for s in services_by_key.values()):
                                        s_name, prod, ver = infer_well_known_service(p_num, "tcp")
                                        clean_prod = normalize_product_name(prod)
                                        key = f"{p_num}:tcp:{clean_prod}".lower()
                                        services_by_key[key] = {
                                            "port": p_num,
                                            "protocol": "tcp",
                                            "service_name": s_name,
                                            "product": clean_prod,
                                            "raw_product": prod,
                                            "version": ver,
                                            "cpe": [],
                                            "source": "naabu",
                                            "label": f"Port {p_num}/tcp — {clean_prod}",
                                        }
                            except Exception:
                                pass
                except Exception:
                    pass

    # 2. Web Recon Scans (HTTPX & WhatWeb)
    web_base = ROOT_DIR / "toolkit" / "04-web" / "scans"
    for cand in seen_cands:
        cand_dir = web_base / cand
        if not cand_dir.exists():
            continue

        httpx_dir = cand_dir / "httpx"
        for hf in [httpx_dir / "structured" / "httpx_result.json", httpx_dir / "raw" / "httpx_raw.jsonl"]:
            if not hf.exists():
                continue
            try:
                if hf.name.endswith(".json"):
                    h_data = json.loads(hf.read_text(encoding="utf-8", errors="replace"))
                    items = h_data.get("results", [])
                else:
                    items = [json.loads(line) for line in hf.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip()]

                for item in items:
                    if not isinstance(item, dict):
                        continue
                    port_val = item.get("port") or (443 if item.get("scheme") == "https" else 80)
                    try:
                        port_num = int(port_val)
                    except Exception:
                        port_num = 80

                    # If network port scans were performed, only accept HTTPX results for verified open ports
                    if network_scans_performed and port_num not in verified_network_ports:
                        continue
                    verified_network_ports.add(port_num)

                    ws = item.get("webserver") or ""
                    if ws:
                        m = re.search(r"([a-zA-Z\-_]+)(?:/([0-9\.]+[\w\.\-]*))?", ws)
                        if m:
                            clean_prod = normalize_product_name(m.group(1))
                            ver = m.group(2) or ""
                            key = f"{port_num}:tcp:{clean_prod}".lower()
                            if key not in services_by_key:
                                label = f"Port {port_num}/tcp — {clean_prod}"
                                if ver:
                                    label += f" {ver}"
                                services_by_key[key] = {
                                    "port": port_num,
                                    "protocol": "tcp",
                                    "service_name": clean_prod.lower(),
                                    "product": clean_prod,
                                    "raw_product": ws,
                                    "version": ver,
                                    "cpe": [],
                                    "source": "httpx",
                                    "label": label,
                                }
                            elif ver and not services_by_key[key].get("version"):
                                services_by_key[key]["version"] = ver
                                services_by_key[key]["label"] = f"Port {port_num}/tcp — {clean_prod} {ver}"

                    techs = item.get("tech") or item.get("technologies") or []
                    for t in techs:
                        if not isinstance(t, str):
                            continue
                        tm = re.search(r"([a-zA-Z\-_.]+)(?::([0-9\.]+[\w\.\-]*))?", t)
                        if tm:
                            raw_t = tm.group(1)
                            clean_t = normalize_product_name(raw_t)
                            t_ver = tm.group(2) or ""
                            if clean_t.lower() in ("apache", "nginx", "php", "node.js", "uvicorn", "mysql", "openssh", "log4j", "wordpress"):
                                key = f"{port_num}:tcp:{clean_t}".lower()
                                if key not in services_by_key:
                                    label = f"Port {port_num}/tcp — {clean_t}"
                                    if t_ver:
                                        label += f" {t_ver}"
                                    services_by_key[key] = {
                                        "port": port_num,
                                        "protocol": "tcp",
                                        "service_name": clean_t.lower(),
                                        "product": clean_t,
                                        "raw_product": t,
                                        "version": t_ver,
                                        "cpe": [],
                                        "source": "httpx",
                                        "label": label,
                                    }
                                elif t_ver and not services_by_key[key].get("version"):
                                    services_by_key[key]["version"] = t_ver
                                    services_by_key[key]["label"] = f"Port {port_num}/tcp — {clean_t} {t_ver}"
            except Exception:
                pass

    # 3. Findings Database and JSON files - secondary sources
    for cand in seen_cands:
        target_findings = findings_db.list_findings(target_id=cand)
        # Fallback to findings JSON files on disk
        if not target_findings:
            f_path = ROOT_DIR / "toolkit" / "09-analysis" / "findings" / f"{cand}_findings.json"
            if f_path.exists():
                try:
                    f_data = json.loads(f_path.read_text(encoding="utf-8", errors="replace"))
                    for raw_f in f_data.get("findings", []):
                        class MockFinding:
                            def __init__(self, d):
                                self.title = d.get("title", "")
                                self.affected_asset = d.get("affected_asset", "")
                        target_findings.append(MockFinding(raw_f))
                except Exception:
                    pass

        for f in target_findings:
            title = getattr(f, "title", "") or ""
            m = re.search(
                r"(Apache(?: httpd)?|OpenSSH|nginx|Node\.js|MySQL|Redis|PHP|ProFTPD|vsftpd|Samba|Log4j|Uvicorn)(?:\s*\([^)]+\))?\s*([0-9\.]+[\w\.\-]*)?",
                title,
                re.IGNORECASE,
            )
            if m:
                raw_prod = m.group(1).strip()
                clean_prod = normalize_product_name(raw_prod)
                ver = (m.group(2) or "").strip()

                port_num = 0
                affected_asset = getattr(f, "affected_asset", "") or ""
                if affected_asset:
                    port_match = re.search(r":(\d{1,5})(?:/|$)", affected_asset)
                    if port_match:
                        try:
                            val = int(port_match.group(1))
                            if 1 <= val <= 65535:
                                port_num = val
                        except Exception:
                            port_num = 0

                # CRITICAL RECONCILIATION: If network scans were executed,
                # NEVER assert a service on a port verified to be closed!
                if network_scans_performed:
                    if port_num > 0 and port_num not in verified_network_ports:
                        continue
                    if port_num == 0:
                        matching_svc = next(
                            (s for s in services_by_key.values() if s["product"].lower() == clean_prod.lower() and s["port"] in verified_network_ports),
                            None
                        )
                        if not matching_svc:
                            continue
                        port_num = matching_svc["port"]

                key = f"{port_num}:tcp:{clean_prod}".lower()
                already_has_real_port = any(
                    s["product"].lower() == clean_prod.lower() and s["port"] > 0
                    for s in services_by_key.values()
                )
                if port_num == 0 and already_has_real_port:
                    continue

                if key not in services_by_key:
                    label = f"Port {port_num}/tcp — {clean_prod}" if port_num else clean_prod
                    if ver:
                        label += f" {ver}"
                    services_by_key[key] = {
                        "port": port_num,
                        "protocol": "tcp",
                        "service_name": clean_prod.lower(),
                        "product": clean_prod,
                        "raw_product": raw_prod,
                        "version": ver,
                        "cpe": [],
                        "source": "findings",
                        "label": label,
                    }
                elif ver and not services_by_key[key].get("version"):
                    services_by_key[key]["version"] = ver
                    services_by_key[key]["label"] = f"Port {port_num}/tcp — {clean_prod} {ver}"

    services = list(services_by_key.values())

    # Sort services: items with real port and version first, then port number
    services.sort(
        key=lambda x: (
            0 if (x["port"] > 0 and x["version"]) else (1 if x["port"] > 0 else 2),
            x["port"],
        )
    )

    return services
