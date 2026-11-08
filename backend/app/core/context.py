from __future__ import annotations

import json
import pathlib
import re
from typing import Any

from pydantic import BaseModel, Field

from backend.app.core.prompts import SYSTEM_PROMPT
from backend.app.services.correlator import Correlator
from backend.app.services.rag import RAGService
from backend.app.storage.chat_db import chat_db
from toolkit.scripts.scan_status import load_scan_status


class ContextData(BaseModel):
    user_message: str
    active_target: dict | None = None
    active_file: dict | None = None
    recent_scans: list[dict] = Field(default_factory=list)
    conflicts: list[str] = Field(default_factory=list)
    rag_sources: list[dict] = Field(default_factory=list)
    correlator_candidates: list[dict] = Field(default_factory=list)
    conversation_history: list[dict] = Field(default_factory=list)
    attachments: list[dict] = Field(default_factory=list)


class ContextEngine:
    """
    Context Orchestrator for IDE Copilot.
    Priority hierarchy:
      1. User message
      2. Active target
      3. Active file content
      4. Current scan evidence (Original toolset)
      5. Tool conflict / discrepancy detection
      6. Correlator candidates
      7. RAG knowledge sources
      8. Conversation history
    """

    @classmethod
    def extract_product_and_version(cls, text: str) -> tuple[str | None, str | None]:
        match = re.search(
            r"\b(apache|openssh|nginx|node\.js|nodejs|express|php|mysql|redis|log4j|spring|samba)\b[\s/]*([0-9]+[0-9a-zA-Z._-]*)?",
            text,
            re.IGNORECASE,
        )
        if match:
            prod = match.group(1)
            ver = match.group(2) if match.group(2) else None
            return prod, ver
        return None, None

    @classmethod
    def detect_conflicts(cls, scans: list[dict]) -> list[str]:
        """Detect conflicting version or service reports among tools (e.g. Nmap vs WhatWeb)."""
        conflicts = []
        nmap_products: dict[str, tuple[str, str]] = {}
        for sc in scans:
            if sc.get("tool") == "nmap":
                for p in sc.get("ports", []):
                    if isinstance(p, dict):
                        prod = p.get("product", "").strip()
                        ver = p.get("version", "").strip()
                        if prod and ver:
                            nmap_products[prod.lower()] = (prod, ver)


        for sc in scans:
            if sc.get("tool") == "whatweb":
                for t in sc.get("technologies", []):
                    w_name = t.get("name", "").strip()
                    w_ver = t.get("version", "").strip()
                    if not w_name or not w_ver:
                        continue
                    w_lower = w_name.lower()
                    for np_key, (np_name, np_ver) in nmap_products.items():
                        if (np_key in w_lower or w_lower in np_key) and np_ver != w_ver:
                            conflicts.append(
                                f"Version discrepancy detected: Nmap reports '{np_name} {np_ver}', while WhatWeb reports '{w_name} {w_ver}'. Further validation is required."
                            )

        return list(dict.fromkeys(conflicts))

    @classmethod
    def discover_target_scans(
        cls, target_identifier: str, root_dir: pathlib.Path
    ) -> list[dict]:
        """Auto-discover all scan evidence across original toolset for a given target."""
        scans = []
        if not target_identifier:
            return scans

        cleaned = (
            target_identifier.replace("http://", "")
            .replace("https://", "")
            .replace("/", "")
            .replace(":", "-")
        )
        target_keys = {
            target_identifier,
            cleaned,
            f"target-{target_identifier}",
            f"target-{cleaned}",
        }
        if target_identifier.startswith("target-"):
            target_keys.add(target_identifier[7:])

        net_base = root_dir / "toolkit" / "03-network" / "scans"
        web_base = root_dir / "toolkit" / "04-web" / "scans"
        vuln_base = root_dir / "toolkit" / "05-vulnerability" / "scans"
        enum_base = root_dir / "toolkit" / "06-service-enum" / "scans"

        for key in target_keys:
            # 1. Nmap
            nmap_dir = net_base / key / "nmap"
            nmap_st = load_scan_status(nmap_dir)
            if nmap_st and nmap_st.mode == "failed":
                scans.append(
                    {
                        "tool": "nmap",
                        "type": "port_scan",
                        "mode": "failed",
                        "trustworthy": False,
                        "reason": nmap_st.reason,
                        "summary": f"Nmap scan thất bại ({nmap_st.reason or 'lỗi thực thi'}). Không có cổng mở được xác minh.",
                    }
                )
            else:
                nmap_json = (
                    (nmap_dir / "simulated" / "nmap_result.json")
                    if (
                        nmap_st
                        and nmap_st.mode == "simulated"
                        and (nmap_dir / "simulated" / "nmap_result.json").exists()
                    )
                    else (nmap_dir / "structured" / "nmap_result.json")
                )
                if nmap_json.exists():
                    try:
                        data = json.loads(
                            nmap_json.read_text(encoding="utf-8", errors="replace")
                        )
                        ports_info = []
                        for host in data.get("hosts", []):
                            for p in host.get("ports", []):
                                s = p.get("service", {})
                                pid = p.get("portid")
                                proto = p.get("protocol", "tcp")
                                state = p.get("state", "open")
                                sname = s.get("name", "")
                                prod = s.get("product", "")
                                ver = s.get("version", "")
                                ports_info.append(
                                    {
                                        "port": pid,
                                        "protocol": proto,
                                        "state": state,
                                        "service": sname,
                                        "product": prod,
                                        "version": ver,
                                        "label": f"Port {pid}/{proto} ({state}): {sname} - {prod} {ver}".strip(),
                                    }
                                )
                        if ports_info:
                            is_sim = bool(nmap_st and nmap_st.mode == "simulated")
                            scans.append(
                                {
                                    "tool": "nmap",
                                    "type": "port_scan",
                                    "mode": "simulated" if is_sim else "real",
                                    "trustworthy": not is_sim,
                                    "ports": ports_info,
                                    "summary": f"Nmap ({'SIMULATED' if is_sim else 'REAL'}) ghi nhận {len(ports_info)} cổng: "
                                    + ", ".join(
                                        [
                                            f"{p['port']}/{p['service']}"
                                            for p in ports_info
                                        ]
                                    ),
                                }
                            )
                    except Exception:
                        pass

            # 2. Naabu
            naabu_dir = net_base / key / "naabu"
            naabu_st = load_scan_status(naabu_dir)
            if naabu_st and naabu_st.mode == "failed":
                scans.append(
                    {
                        "tool": "naabu",
                        "type": "fast_port_scan",
                        "mode": "failed",
                        "trustworthy": False,
                        "reason": naabu_st.reason,
                        "summary": f"Naabu scan thất bại ({naabu_st.reason or 'lỗi thực thi'}).",
                    }
                )
            else:
                naabu_raw = (
                    (naabu_dir / "simulated" / "naabu_raw.txt")
                    if (
                        naabu_st
                        and naabu_st.mode == "simulated"
                        and (naabu_dir / "simulated" / "naabu_raw.txt").exists()
                    )
                    else (naabu_dir / "raw" / "naabu_raw.txt")
                )
                if naabu_raw.exists():
                    try:
                        lines = [
                            l.strip()
                            for l in naabu_raw.read_text(
                                encoding="utf-8", errors="replace"
                            ).splitlines()
                            if l.strip()
                        ]
                        if lines:
                            is_sim = bool(naabu_st and naabu_st.mode == "simulated")
                            scans.append(
                                {
                                    "tool": "naabu",
                                    "type": "fast_port_scan",
                                    "mode": "simulated" if is_sim else "real",
                                    "trustworthy": not is_sim,
                                    "raw_lines": lines,
                                    "summary": f"Naabu ({'SIMULATED' if is_sim else 'REAL'}) ghi nhận các cổng: {', '.join(lines)}",
                                }
                            )
                    except Exception:
                        pass

            # 3. Masscan
            masscan_dir = net_base / key / "masscan"
            masscan_st = load_scan_status(masscan_dir)
            if masscan_st and masscan_st.mode == "failed":
                scans.append(
                    {
                        "tool": "masscan",
                        "type": "large_scale_port_scan",
                        "mode": "failed",
                        "trustworthy": False,
                        "reason": masscan_st.reason,
                        "summary": f"Masscan scan thất bại ({masscan_st.reason or 'lỗi thực thi'}).",
                    }
                )
            else:
                masscan_json = (
                    (masscan_dir / "simulated" / "masscan_result.json")
                    if (
                        masscan_st
                        and masscan_st.mode == "simulated"
                        and (masscan_dir / "simulated" / "masscan_result.json").exists()
                    )
                    else (masscan_dir / "structured" / "masscan_result.json")
                )
                if masscan_json.exists():
                    try:
                        m_data = json.loads(
                            masscan_json.read_text(encoding="utf-8", errors="replace")
                        )
                        m_ports = []
                        for h in m_data.get("hosts", []):
                            for p in h.get("ports", []):
                                m_ports.append(p.get("port"))
                        if m_ports:
                            is_sim = bool(masscan_st and masscan_st.mode == "simulated")
                            scans.append(
                                {
                                    "tool": "masscan",
                                    "type": "large_scale_port_scan",
                                    "mode": "simulated" if is_sim else "real",
                                    "trustworthy": not is_sim,
                                    "ports": m_ports,
                                    "summary": f"Masscan ({'SIMULATED' if is_sim else 'REAL'}) ghi nhận các cổng: {', '.join(str(p) for p in m_ports)}",
                                }
                            )
                    except Exception:
                        pass

            # 4. RustScan
            rustscan_dir = net_base / key / "rustscan"
            rustscan_st = load_scan_status(rustscan_dir)
            if rustscan_st and rustscan_st.mode == "failed":
                scans.append(
                    {
                        "tool": "rustscan",
                        "type": "fast_port_scan",
                        "mode": "failed",
                        "trustworthy": False,
                        "reason": rustscan_st.reason,
                        "summary": f"RustScan scan thất bại ({rustscan_st.reason or 'lỗi thực thi'}).",
                    }
                )
            else:
                rustscan_json = (
                    (rustscan_dir / "simulated" / "rustscan_result.json")
                    if (
                        rustscan_st
                        and rustscan_st.mode == "simulated"
                        and (
                            rustscan_dir / "simulated" / "rustscan_result.json"
                        ).exists()
                    )
                    else (rustscan_dir / "structured" / "rustscan_result.json")
                )
                if rustscan_json.exists():
                    try:
                        r_data = json.loads(
                            rustscan_json.read_text(encoding="utf-8", errors="replace")
                        )
                        r_ports = r_data.get("open_ports", [])
                        if r_ports:
                            is_sim = bool(
                                rustscan_st and rustscan_st.mode == "simulated"
                            )
                            scans.append(
                                {
                                    "tool": "rustscan",
                                    "type": "fast_port_scan",
                                    "mode": "simulated" if is_sim else "real",
                                    "trustworthy": not is_sim,
                                    "ports": r_ports,
                                    "summary": f"RustScan ({'SIMULATED' if is_sim else 'REAL'}) ghi nhận các cổng: {', '.join(str(p) for p in r_ports)}",
                                }
                            )
                    except Exception:
                        pass

            # 5. Httpx
            httpx_dir = web_base / key / "httpx"
            httpx_st = load_scan_status(httpx_dir)
            if httpx_st and httpx_st.mode == "failed":
                scans.append(
                    {
                        "tool": "httpx",
                        "type": "web_probe",
                        "mode": "failed",
                        "trustworthy": False,
                        "reason": httpx_st.reason,
                        "summary": f"HTTPx scan thất bại ({httpx_st.reason or 'lỗi thực thi'}).",
                    }
                )
            else:
                httpx_json = (
                    (httpx_dir / "simulated" / "httpx_result.json")
                    if (
                        httpx_st
                        and httpx_st.mode == "simulated"
                        and (httpx_dir / "simulated" / "httpx_result.json").exists()
                    )
                    else (httpx_dir / "structured" / "httpx_result.json")
                )
                if httpx_json.exists():
                    try:
                        h_data = json.loads(
                            httpx_json.read_text(encoding="utf-8", errors="replace")
                        )
                        endpoints = []
                        for ep in h_data.get("endpoints", []) or h_data.get(
                            "results", []
                        ):
                            endpoints.append(
                                {
                                    "url": ep.get("url"),
                                    "status_code": ep.get("status_code"),
                                    "title": ep.get("title"),
                                    "webserver": ep.get("webserver"),
                                    "tech": ep.get("technologies", [])
                                    or ep.get("tech", []),
                                }
                            )
                        if endpoints:
                            is_sim = bool(httpx_st and httpx_st.mode == "simulated")
                            scans.append(
                                {
                                    "tool": "httpx",
                                    "type": "web_probe",
                                    "mode": "simulated" if is_sim else "real",
                                    "trustworthy": not is_sim,
                                    "endpoints": endpoints,
                                    "summary": f"HTTPx ({'SIMULATED' if is_sim else 'REAL'}) phát hiện {len(endpoints)} web endpoint: "
                                    + ", ".join(
                                        [
                                            f"{e['url']} [{e['status_code']}]"
                                            for e in endpoints
                                        ]
                                    ),
                                }
                            )
                    except Exception:
                        pass

            # 6. WhatWeb
            whatweb_dir = web_base / key / "whatweb"
            whatweb_st = load_scan_status(whatweb_dir)
            if whatweb_st and whatweb_st.mode == "failed":
                scans.append(
                    {
                        "tool": "whatweb",
                        "type": "technology_fingerprint",
                        "mode": "failed",
                        "trustworthy": False,
                        "reason": whatweb_st.reason,
                        "summary": f"WhatWeb scan thất bại ({whatweb_st.reason or 'lỗi thực thi'}).",
                    }
                )
            else:
                whatweb_json = (
                    (whatweb_dir / "simulated" / "whatweb_result.json")
                    if (
                        whatweb_st
                        and whatweb_st.mode == "simulated"
                        and (whatweb_dir / "simulated" / "whatweb_result.json").exists()
                    )
                    else (whatweb_dir / "structured" / "whatweb_result.json")
                )
                if whatweb_json.exists():
                    try:
                        w_data = json.loads(
                            whatweb_json.read_text(encoding="utf-8", errors="replace")
                        )
                        techs = []
                        for t_item in w_data.get("targets", []):
                            for tech in t_item.get("technologies", []):
                                techs.append(tech)
                        if techs:
                            is_sim = bool(whatweb_st and whatweb_st.mode == "simulated")
                            scans.append(
                                {
                                    "tool": "whatweb",
                                    "type": "technology_fingerprint",
                                    "mode": "simulated" if is_sim else "real",
                                    "trustworthy": not is_sim,
                                    "technologies": techs,
                                    "summary": f"WhatWeb ({'SIMULATED' if is_sim else 'REAL'}) ghi nhận công nghệ: "
                                    + ", ".join(
                                        [
                                            f"{t['name']} {t.get('version', '')}".strip()
                                            for t in techs[:5]
                                        ]
                                    ),
                                }
                            )
                    except Exception:
                        pass

            # 7. Nikto
            nikto_dir = web_base / key / "nikto"
            nikto_st = load_scan_status(nikto_dir)
            if nikto_st and nikto_st.mode == "failed":
                scans.append(
                    {
                        "tool": "nikto",
                        "type": "web_security_audit",
                        "mode": "failed",
                        "trustworthy": False,
                        "reason": nikto_st.reason,
                        "summary": f"Nikto scan thất bại ({nikto_st.reason or 'lỗi thực thi'}).",
                    }
                )
            else:
                nikto_json = (
                    (nikto_dir / "simulated" / "nikto_result.json")
                    if (
                        nikto_st
                        and nikto_st.mode == "simulated"
                        and (nikto_dir / "simulated" / "nikto_result.json").exists()
                    )
                    else (nikto_dir / "structured" / "nikto_result.json")
                )
                if nikto_json.exists():
                    try:
                        nik_data = json.loads(
                            nikto_json.read_text(encoding="utf-8", errors="replace")
                        )
                        nik_items = nik_data.get("items", [])
                        if nik_items:
                            is_sim = bool(nikto_st and nikto_st.mode == "simulated")
                            scans.append(
                                {
                                    "tool": "nikto",
                                    "type": "web_security_audit",
                                    "mode": "simulated" if is_sim else "real",
                                    "trustworthy": not is_sim,
                                    "items": nik_items,
                                    "summary": f"Nikto ({'SIMULATED' if is_sim else 'REAL'}) phát hiện {len(nik_items)} cảnh báo cấu hình: "
                                    + ", ".join(
                                        [i["description"][:50] for i in nik_items[:2]]
                                    ),
                                }
                            )
                    except Exception:
                        pass

            # 8. Katana
            katana_dir = web_base / key / "katana"
            katana_st = load_scan_status(katana_dir)
            if katana_st and katana_st.mode == "failed":
                scans.append(
                    {
                        "tool": "katana",
                        "type": "web_crawling",
                        "mode": "failed",
                        "trustworthy": False,
                        "reason": katana_st.reason,
                        "summary": f"Katana scan thất bại ({katana_st.reason or 'lỗi thực thi'}).",
                    }
                )
            else:
                katana_json = (
                    (katana_dir / "simulated" / "katana_result.json")
                    if (
                        katana_st
                        and katana_st.mode == "simulated"
                        and (katana_dir / "simulated" / "katana_result.json").exists()
                    )
                    else (katana_dir / "structured" / "katana_result.json")
                )
                if katana_json.exists():
                    try:
                        k_data = json.loads(
                            katana_json.read_text(encoding="utf-8", errors="replace")
                        )
                        k_eps = k_data.get("endpoints", [])
                        if k_eps:
                            is_sim = bool(katana_st and katana_st.mode == "simulated")
                            scans.append(
                                {
                                    "tool": "katana",
                                    "type": "web_crawling",
                                    "mode": "simulated" if is_sim else "real",
                                    "trustworthy": not is_sim,
                                    "endpoints": k_eps,
                                    "summary": f"Katana ({'SIMULATED' if is_sim else 'REAL'}) crawl được {len(k_eps)} endpoint.",
                                }
                            )
                    except Exception:
                        pass

            # 9. Nuclei
            nuclei_dir = vuln_base / key / "nuclei"
            nuclei_st = load_scan_status(nuclei_dir)
            if nuclei_st and nuclei_st.mode == "failed":
                scans.append(
                    {
                        "tool": "nuclei",
                        "type": "vulnerabilities",
                        "mode": "failed",
                        "trustworthy": False,
                        "reason": nuclei_st.reason,
                        "summary": f"Nuclei scan thất bại ({nuclei_st.reason or 'lỗi thực thi'}). Không có CVE nào được xác nhận.",
                    }
                )
            else:
                nuclei_json = (
                    (nuclei_dir / "simulated" / "nuclei_result.json")
                    if (
                        nuclei_st
                        and nuclei_st.mode == "simulated"
                        and (nuclei_dir / "simulated" / "nuclei_result.json").exists()
                    )
                    else (nuclei_dir / "structured" / "nuclei_result.json")
                )
                if nuclei_json.exists():
                    try:
                        nu_data = json.loads(
                            nuclei_json.read_text(encoding="utf-8", errors="replace")
                        )
                        vulns = []
                        items = nu_data.get("matches", []) or nu_data.get(
                            "findings", []
                        )
                        for m in items:
                            t_id = m.get("template_id") or m.get("template-id")
                            info = m.get("info", {})
                            sev = (
                                info.get("severity")
                                if isinstance(info, dict)
                                else m.get("severity", "info")
                            )
                            name = (
                                info.get("name")
                                if isinstance(info, dict)
                                else m.get("name", t_id)
                            )
                            vulns.append(
                                {
                                    "template": t_id,
                                    "severity": sev,
                                    "name": name,
                                    "matched_at": m.get("matched_at")
                                    or m.get("matched-at"),
                                }
                            )
                        if vulns:
                            is_sim = bool(nuclei_st and nuclei_st.mode == "simulated")
                            scans.append(
                                {
                                    "tool": "nuclei",
                                    "type": "vulnerabilities",
                                    "mode": "simulated" if is_sim else "real",
                                    "trustworthy": not is_sim,
                                    "matches": vulns,
                                    "summary": f"Nuclei ({'SIMULATED' if is_sim else 'REAL'}) ghi nhận {len(vulns)} template: "
                                    + ", ".join(
                                        [
                                            f"{v['template']} ({v['severity']})"
                                            for v in vulns[:3]
                                        ]
                                    ),
                                }
                            )
                    except Exception:
                        pass

            # 10. SearchSploit
            searchsploit_dir = vuln_base / key / "searchsploit"
            searchsploit_st = load_scan_status(searchsploit_dir)
            if searchsploit_st and searchsploit_st.mode == "failed":
                scans.append(
                    {
                        "tool": "searchsploit",
                        "type": "exploit_references",
                        "mode": "failed",
                        "trustworthy": False,
                        "reason": searchsploit_st.reason,
                        "summary": f"SearchSploit scan thất bại ({searchsploit_st.reason or 'lỗi thực thi'}).",
                    }
                )
            else:
                searchsploit_json = (
                    (searchsploit_dir / "simulated" / "searchsploit_result.json")
                    if (
                        searchsploit_st
                        and searchsploit_st.mode == "simulated"
                        and (
                            searchsploit_dir / "simulated" / "searchsploit_result.json"
                        ).exists()
                    )
                    else (searchsploit_dir / "structured" / "searchsploit_result.json")
                )
                if searchsploit_json.exists():
                    try:
                        ss_data = json.loads(
                            searchsploit_json.read_text(
                                encoding="utf-8", errors="replace"
                            )
                        )
                        ss_results = ss_data.get("results", [])
                        if ss_results:
                            is_sim = bool(
                                searchsploit_st and searchsploit_st.mode == "simulated"
                            )
                            scans.append(
                                {
                                    "tool": "searchsploit",
                                    "type": "exploit_references",
                                    "mode": "simulated" if is_sim else "real",
                                    "trustworthy": not is_sim,
                                    "references": ss_results,
                                    "summary": f"SearchSploit ({'SIMULATED' if is_sim else 'REAL'}) tìm thấy {len(ss_results)} tài liệu tham khảo.",
                                }
                            )
                    except Exception:
                        pass

            # 11. Service Enum (SMB, SNMP, LDAP, Database)
            t_enum_dir = enum_base / key
            if t_enum_dir.exists():
                for s_tool in [
                    "enum4linux",
                    "smbclient",
                    "snmpwalk",
                    "ldapsearch",
                    "database",
                ]:
                    s_tool_dir = t_enum_dir / s_tool
                    s_st = load_scan_status(s_tool_dir)
                    if s_st and s_st.mode == "failed":
                        scans.append(
                            {
                                "tool": s_tool,
                                "type": "service_enumeration",
                                "mode": "failed",
                                "trustworthy": False,
                                "reason": s_st.reason,
                                "summary": f"{s_tool} thất bại ({s_st.reason or 'lỗi thực thi'}).",
                            }
                        )
                        continue
                    s_file = (
                        (s_tool_dir / "simulated" / f"{s_tool}_result.json")
                        if (
                            s_st
                            and s_st.mode == "simulated"
                            and (
                                s_tool_dir / "simulated" / f"{s_tool}_result.json"
                            ).exists()
                        )
                        else (s_tool_dir / "structured" / f"{s_tool}_result.json")
                    )
                    if s_file.exists():
                        try:
                            s_data = json.loads(
                                s_file.read_text(encoding="utf-8", errors="replace")
                            )
                            s_findings = s_data.get("findings", [])
                            if s_findings:
                                is_sim = bool(s_st and s_st.mode == "simulated")
                                scans.append(
                                    {
                                        "tool": s_tool,
                                        "type": "service_enumeration",
                                        "mode": "simulated" if is_sim else "real",
                                        "trustworthy": not is_sim,
                                        "findings": s_findings,
                                        "summary": f"{s_tool} ({'SIMULATED' if is_sim else 'REAL'}): "
                                        + ", ".join(
                                            [
                                                f["description"][:60]
                                                for f in s_findings[:2]
                                            ]
                                        ),
                                    }
                                )
                        except Exception:
                            pass

            if scans:
                break

        return scans

    @classmethod
    def build(
        cls,
        user_message: str,
        active_target: dict | None = None,
        active_file_path: str | None = None,
        active_file_content: str | None = None,
        conversation_id: str | None = None,
        attachments: list[dict] | None = None,
    ) -> ContextData:
        root_dir = pathlib.Path(__file__).resolve().parent.parent.parent.parent

        # 1. Read Active File
        active_file_data = None
        if active_file_content:
            clean_name = pathlib.Path(active_file_path or "active_file").name
            content_str = active_file_content
            if len(content_str) > 8000:
                content_str = content_str[:8000] + "\n...[TRUNCATED]"
            active_file_data = {
                "path": active_file_path or clean_name,
                "name": clean_name,
                "content": content_str,
            }
        elif active_file_path:
            clean_rel = active_file_path.lstrip("/\\")
            candidates = [
                root_dir / clean_rel,
                root_dir / "toolkit" / clean_rel,
                root_dir / "toolkit" / "03-network" / clean_rel,
                root_dir / "toolkit" / "04-web" / clean_rel,
                root_dir / "toolkit" / "05-vulnerability" / clean_rel,
                root_dir / "toolkit" / "06-service-enum" / clean_rel,
            ]
            file_disk = next(
                (p for p in candidates if p.exists() and p.is_file()), None
            )
            if file_disk:
                try:
                    content_str = file_disk.read_text(
                        encoding="utf-8", errors="replace"
                    )
                    if len(content_str) > 8000:
                        content_str = content_str[:8000] + "\n...[TRUNCATED]"
                    active_file_data = {
                        "path": str(file_disk),
                        "name": file_disk.name,
                        "content": content_str,
                    }
                except Exception:
                    pass
            else:
                active_file_data = {
                    "path": active_file_path,
                    "name": pathlib.Path(clean_rel).name,
                    "content": f"[Referenced file: {clean_rel}]",
                }

        # 2. Discover Scans
        recent_scans = []
        if active_target:
            t_ident = (
                active_target.get("host")
                or active_target.get("normalized_value")
                or active_target.get("name")
                or ""
            )
            recent_scans = cls.discover_target_scans(t_ident, root_dir)

        # 3. Detect Conflicts among Tool Results
        conflicts = cls.detect_conflicts(recent_scans)

        # 4. Correlator Check
        correlator_candidates = []
        prod, ver = cls.extract_product_and_version(user_message)
        if not prod and active_file_data:
            prod, ver = cls.extract_product_and_version(active_file_data["content"])
        if not prod and recent_scans:
            for sc in recent_scans:
                for p in sc.get("ports", []):
                    if isinstance(p, dict) and p.get("product"):
                        prod, ver = p["product"], p.get("version")
                        break

                if not prod:
                    for t in sc.get("technologies", []):
                        if t.get("name"):
                            prod, ver = t["name"], t.get("version")
                            break
                if prod:
                    break

        if prod:
            cands = Correlator.correlate(product=prod, version=ver, limit=5)
            correlator_candidates = [c.model_dump() for c in cands]

        # 5. RAG Retrieval
        rag_query = user_message
        if prod and ver:
            rag_query = f"{prod} {ver} {user_message}"
        rag_sources = RAGService.retrieve(rag_query, top_k=5)

        # 6. Conversation History
        conv_history = []
        if conversation_id:
            conv_history = chat_db.get_messages(conversation_id, limit=10)

        return ContextData(
            user_message=user_message,
            active_target=active_target,
            active_file=active_file_data,
            recent_scans=recent_scans,
            conflicts=conflicts,
            rag_sources=rag_sources,
            correlator_candidates=correlator_candidates,
            conversation_history=conv_history,
            attachments=attachments or [],
        )

    @classmethod
    def to_prompt_messages(cls, ctx: ContextData | dict) -> list[dict]:
        if isinstance(ctx, dict) and "ctx_data" in ctx:
            ctx = ctx["ctx_data"]
        context_parts = []

        # Target section
        if getattr(ctx, "active_target", None):
            context_parts.append(
                f"### ACTIVE TARGET (MỤC TIÊU ĐANG KIỂM THỬ)\n"
                f"- Name: {ctx.active_target.get('name')}\n"
                f"- Host: {ctx.active_target.get('host')}\n"
                f"- Type: {ctx.active_target.get('type')}\n"
                f"- Environment: {ctx.active_target.get('environment', 'lab')}"
            )

        # Tool Conflicts section
        if ctx.conflicts:
            conflict_lines = [f"- [DISCREPANCY] {c}" for c in ctx.conflicts]
            conflict_lines.append(
                "\n*Rule: Khi có mâu thuẫn giữa các tool, KHÔNG tự ý chọn một kết quả làm sự thật. Cần nêu rõ nguồn gốc, độ tin cậy và đề xuất bước kiểm thử/thẩm định thủ công.*"
            )
            context_parts.append(
                "### TOOL RESULT CONFLICTS & DISCREPANCIES (MÂU THUẪN DỮ LIỆU GIỮA CÁC TOOL)\n"
                + "\n".join(conflict_lines)
            )

        # Target Scan Evidence section
        if ctx.recent_scans:
            scan_lines = []
            has_failed_tools = False
            has_simulated_tools = False
            verified_scan_count = 0

            for sc in ctx.recent_scans:
                tool_name = sc.get("tool", "").upper()
                tool_mode = sc.get("mode", "real")
                is_trustworthy = sc.get("trustworthy", True)

                if tool_mode == "failed":
                    has_failed_tools = True
                    scan_lines.append(
                        f"#### Công cụ: {tool_name} [FAILED ⚠️] ({sc.get('type', 'scan')})\n"
                        f"  - Trạng thái: SCAN THẤT BẠI (Reason: {sc.get('reason', 'lỗi không xác định')})\n"
                        f"  - Chú ý: Không có bằng chứng thực tế nào từ {tool_name}. KHÔNG ĐƯỢC suy đoán hay tạo finding giả."
                    )
                elif tool_mode == "simulated" or not is_trustworthy:
                    has_simulated_tools = True
                    scan_lines.append(
                        f"#### Công cụ: {tool_name} [SIMULATED ⚠️] ({sc.get('type', 'scan')})\n"
                        f"  - Trạng thái: DỮ LIỆU MÔ PHỎNG / KHÔNG ĐƯỢC XÁC MINH TRÊN TARGET THẬT\n"
                        f"  - Tóm tắt: {sc.get('summary', '')}"
                    )
                else:
                    verified_scan_count += 1
                    scan_lines.append(
                        f"#### Công cụ: {tool_name} [VERIFIED REAL ✓] ({sc.get('type', '')})"
                    )
                    if sc.get("ports") and isinstance(sc["ports"][0], dict):
                        for p in sc["ports"]:
                            scan_lines.append(f"  - {p['label']}")
                    elif sc.get("summary"):
                        scan_lines.append(f"  - {sc['summary']}")

            audit_notices = []
            if has_failed_tools or has_simulated_tools:
                audit_notices.append(
                    "\n> [!WARNING]\n"
                    "> **CẢNH BÁO KIỂM THỨC:** Một hoặc nhiều công cụ đã thất bại hoặc chạy ở chế độ SIMULATED.\n"
                    "> Tuyệt đối KHÔNG được bịa đặt CVE, cổng mở hoặc lỗ hổng từ các công cụ FAILED/SIMULATED.\n"
                    "> Phải phản hồi trung thực về lỗi thực thi hoặc trạng thái thiếu bằng chứng (Insufficient Evidence)."
                )
            if verified_scan_count == 0 and ctx.active_target:
                audit_notices.append(
                    "\n> [!CAUTION]\n"
                    "> **CHƯA CÓ BẰNG CHỨNG QUÉT THỰC TẾ:** Không có công cụ nào hoàn thành scan thực tế trên target này.\n"
                    "> Phải thông báo rõ ràng cho pentester rằng mục tiêu chưa có bằng chứng đã xác minh."
                )

            context_parts.append(
                "### TARGET SCAN & RECON EVIDENCE (CHỨNG CỨ QUÉT TRÊN TARGET)\n"
                + "\n".join(scan_lines)
                + ("\n" + "\n".join(audit_notices) if audit_notices else "")
            )

        # Active File section
        if ctx.active_file:
            context_parts.append(
                f"### ACTIVE FILE EVIDENCE IN EDITOR ({ctx.active_file['name']})\n"
                f"```json\n{ctx.active_file['content']}\n```"
            )

        # Correlator section
        if ctx.correlator_candidates:
            cand_lines = []
            for c in ctx.correlator_candidates[:4]:
                cand_lines.append(
                    f"- {c['cve_id']} (CVSS {c.get('cvss_score', 'N/A')} - {c.get('cvss_severity', '')}): {c['description'][:160]}... [Confidence: {c['confidence']}]"
                )
            context_parts.append(
                "### CORRELATED VULNERABILITY CANDIDATES\n" + "\n".join(cand_lines)
            )

        # RAG Knowledge Sources
        if ctx.rag_sources:
            rag_lines = []
            for idx, s in enumerate(ctx.rag_sources, 1):
                rag_lines.append(
                    f"[{idx}] {s['source']} {s['title']}: {s['content'][:200]}"
                )
            context_parts.append(
                "### AUTHORITATIVE KNOWLEDGE BASE SOURCES\n" + "\n".join(rag_lines)
            )

        # User Attachments section
        if ctx.attachments:
            att_lines = []
            for att in ctx.attachments:
                name = att.get("name", "attachment")
                mime = att.get("type", "")
                if mime.startswith("image/"):
                    att_lines.append(f"- [Hình ảnh đính kèm]: `{name}` ({mime})")
                else:
                    content = att.get("content") or att.get("data") or ""
                    if len(content) > 4000:
                        content_snip = content[:4000] + "\n... [còn tiếp]"
                    else:
                        content_snip = content
                    att_lines.append(f"#### TẬP TIN ĐÍNH KÈM: {name} ({mime})\n```\n{content_snip}\n```")
            if att_lines:
                context_parts.append(
                    "### TẬP TIN & HÌNH ẢNH ĐÍNH KÈM TỪ NGƯỜI DÙNG (USER ATTACHMENTS)\n"
                    + "\n".join(att_lines)
                )

        full_context = "\n\n".join(context_parts)

        messages = [{"role": "system", "content": SYSTEM_PROMPT}]

        if full_context.strip():
            messages.append(
                {
                    "role": "system",
                    "content": f"=== CONTEXTUAL EVIDENCE & KNOWLEDGE BASE ===\n{full_context}\n===============================================",
                }
            )

        # Inject conversation history
        for msg in ctx.conversation_history:
            messages.append({"role": msg["role"], "content": msg["content"]})

        # Inject current user query
        messages.append({"role": "user", "content": ctx.user_message})

        return messages

    def build_context(
        self,
        message: str,
        active_target: Any | None = None,
        active_file: str | None = None,
        active_file_content: str | None = None,
        conversation_id: str | None = None,
        attachments: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        target_dict = None
        target_str = ""
        if isinstance(active_target, dict):
            target_dict = active_target
            target_str = (
                active_target.get("normalized_value")
                or active_target.get("host")
                or active_target.get("name")
                or ""
            )
        elif isinstance(active_target, str):
            target_str = active_target
            target_dict = {
                "name": active_target,
                "host": active_target,
                "type": "target",
            }

        ctx_data = self.build(
            user_message=message,
            active_target=target_dict,
            active_file_path=active_file,
            active_file_content=active_file_content,
            conversation_id=conversation_id,
            attachments=attachments,
        )
        messages = self.to_prompt_messages(ctx_data)

        context_parts = []
        for m in messages:
            if m["role"] == "system" and "CONTEXTUAL EVIDENCE" in m["content"]:
                context_parts.append(m["content"])
            elif m["role"] == "user":
                context_parts.append(f"User Query: {m['content']}")

        full_prompt = "\n\n".join(context_parts)

        sources = []
        for c in ctx_data.correlator_candidates:
            origin_badge = f" [{c.get('origin', '').upper()}]" if c.get("origin") else ""
            sources.append(
                {
                    "source": c.get("source") or "Offline Vulnerability KB",
                    "title": f"{c.get('cve_id')} (CVSS {c.get('cvss_score', 'N/A')}){origin_badge}",
                    "score": c.get("confidence", 0.95),
                    "snippet": c.get("description", "")[:180],
                    "url": c.get("source_url", "https://nvd.nist.gov"),
                }
            )
        for s in ctx_data.rag_sources:
            sources.append(
                {
                    "source": s.get("source", "KB"),
                    "title": s.get("title", ""),
                    "score": s.get("score", 0.8),
                    "snippet": s.get("content", "")[:180],
                    "url": s.get("url", ""),
                }
            )

        return {
            "ctx_data": ctx_data,
            "full_prompt": full_prompt,
            "sources": sources,
            "conflicts": ctx_data.conflicts,
            "correlations": ctx_data.correlator_candidates,
            "rag_results": ctx_data.rag_sources,
            "active_target": target_str,
            "active_file": active_file,
            "attachments": ctx_data.attachments,
        }


context_engine = ContextEngine()
