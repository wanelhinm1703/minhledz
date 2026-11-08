from __future__ import annotations

import json
import pathlib
import re
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from backend.app.core.prompts import SYSTEM_PROMPT
from backend.app.services.correlator import Correlator
from backend.app.services.rag import RAGService
from backend.app.storage.chat_db import chat_db


class ContextData(BaseModel):
    user_message: str
    active_target: Optional[dict] = None
    active_file: Optional[dict] = None
    recent_scans: List[dict] = Field(default_factory=list)
    conflicts: List[str] = Field(default_factory=list)
    rag_sources: List[dict] = Field(default_factory=list)
    correlator_candidates: List[dict] = Field(default_factory=list)
    conversation_history: List[dict] = Field(default_factory=list)


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
    def extract_product_and_version(cls, text: str) -> tuple[Optional[str], Optional[str]]:
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
    def detect_conflicts(cls, scans: List[dict]) -> List[str]:
        """Detect conflicting version or service reports among tools (e.g. Nmap vs WhatWeb)."""
        conflicts = []
        nmap_products: Dict[str, tuple[str, str]] = {}
        for sc in scans:
            if sc.get("tool") == "nmap":
                for p in sc.get("ports", []):
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
    def discover_target_scans(cls, target_identifier: str, root_dir: pathlib.Path) -> List[dict]:
        """Auto-discover all scan evidence across original toolset for a given target."""
        scans = []
        if not target_identifier:
            return scans

        cleaned = target_identifier.replace("http://", "").replace("https://", "").replace("/", "").replace(":", "-")
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
            nmap_json = net_base / key / "nmap" / "structured" / "nmap_result.json"
            if nmap_json.exists():
                try:
                    data = json.loads(nmap_json.read_text(encoding="utf-8", errors="replace"))
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
                            ports_info.append({
                                "port": pid,
                                "protocol": proto,
                                "state": state,
                                "service": sname,
                                "product": prod,
                                "version": ver,
                                "label": f"Port {pid}/{proto} ({state}): {sname} - {prod} {ver}".strip(),
                            })
                    if ports_info:
                        scans.append({
                            "tool": "nmap",
                            "type": "port_scan",
                            "ports": ports_info,
                            "summary": f"Nmap phát hiện {len(ports_info)} cổng mở: " + ", ".join([f"{p['port']}/{p['service']}" for p in ports_info]),
                        })
                except Exception:
                    pass

            # 2. Naabu
            naabu_raw = net_base / key / "naabu" / "raw" / "naabu_raw.txt"
            if naabu_raw.exists():
                try:
                    lines = [l.strip() for l in naabu_raw.read_text(encoding="utf-8", errors="replace").splitlines() if l.strip()]
                    if lines:
                        scans.append({
                            "tool": "naabu",
                            "type": "fast_port_scan",
                            "raw_lines": lines,
                            "summary": f"Naabu phát hiện các cổng: {', '.join(lines)}",
                        })
                except Exception:
                    pass

            # 3. Masscan
            masscan_json = net_base / key / "masscan" / "structured" / "masscan_result.json"
            if masscan_json.exists():
                try:
                    m_data = json.loads(masscan_json.read_text(encoding="utf-8", errors="replace"))
                    m_ports = []
                    for h in m_data.get("hosts", []):
                        for p in h.get("ports", []):
                            m_ports.append(p.get("port"))
                    if m_ports:
                        scans.append({
                            "tool": "masscan",
                            "type": "large_scale_port_scan",
                            "ports": m_ports,
                            "summary": f"Masscan phát hiện các cổng: {', '.join(str(p) for p in m_ports)}",
                        })
                except Exception:
                    pass

            # 4. RustScan
            rustscan_json = net_base / key / "rustscan" / "structured" / "rustscan_result.json"
            if rustscan_json.exists():
                try:
                    r_data = json.loads(rustscan_json.read_text(encoding="utf-8", errors="replace"))
                    r_ports = r_data.get("open_ports", [])
                    if r_ports:
                        scans.append({
                            "tool": "rustscan",
                            "type": "fast_port_scan",
                            "ports": r_ports,
                            "summary": f"RustScan phát hiện các cổng: {', '.join(str(p) for p in r_ports)}",
                        })
                except Exception:
                    pass

            # 5. Httpx
            httpx_json = web_base / key / "httpx" / "structured" / "httpx_result.json"
            if httpx_json.exists():
                try:
                    h_data = json.loads(httpx_json.read_text(encoding="utf-8", errors="replace"))
                    endpoints = []
                    for ep in h_data.get("endpoints", []) or h_data.get("results", []):
                        endpoints.append({
                            "url": ep.get("url"),
                            "status_code": ep.get("status_code"),
                            "title": ep.get("title"),
                            "webserver": ep.get("webserver"),
                            "tech": ep.get("technologies", []) or ep.get("tech", []),
                        })
                    if endpoints:
                        scans.append({
                            "tool": "httpx",
                            "type": "web_probe",
                            "endpoints": endpoints,
                            "summary": f"HTTPx phát hiện {len(endpoints)} web endpoint: " + ", ".join([f"{e['url']} [{e['status_code']}]" for e in endpoints]),
                        })
                except Exception:
                    pass

            # 6. WhatWeb
            whatweb_json = web_base / key / "whatweb" / "structured" / "whatweb_result.json"
            if whatweb_json.exists():
                try:
                    w_data = json.loads(whatweb_json.read_text(encoding="utf-8", errors="replace"))
                    techs = []
                    for t_item in w_data.get("targets", []):
                        for tech in t_item.get("technologies", []):
                            techs.append(tech)
                    if techs:
                        scans.append({
                            "tool": "whatweb",
                            "type": "technology_fingerprint",
                            "technologies": techs,
                            "summary": f"WhatWeb ghi nhận công nghệ: " + ", ".join([f"{t['name']} {t.get('version', '')}".strip() for t in techs[:5]]),
                        })
                except Exception:
                    pass

            # 7. Nikto
            nikto_json = web_base / key / "nikto" / "structured" / "nikto_result.json"
            if nikto_json.exists():
                try:
                    nik_data = json.loads(nikto_json.read_text(encoding="utf-8", errors="replace"))
                    nik_items = nik_data.get("items", [])
                    if nik_items:
                        scans.append({
                            "tool": "nikto",
                            "type": "web_security_audit",
                            "items": nik_items,
                            "summary": f"Nikto phát hiện {len(nik_items)} cảnh báo cấu hình web: " + ", ".join([i["description"][:50] for i in nik_items[:2]]),
                        })
                except Exception:
                    pass

            # 8. Katana
            katana_json = web_base / key / "katana" / "structured" / "katana_result.json"
            if katana_json.exists():
                try:
                    k_data = json.loads(katana_json.read_text(encoding="utf-8", errors="replace"))
                    k_eps = k_data.get("endpoints", [])
                    if k_eps:
                        scans.append({
                            "tool": "katana",
                            "type": "web_crawling",
                            "endpoints": k_eps,
                            "summary": f"Katana crawl được {len(k_eps)} endpoint trên ứng dụng.",
                        })
                except Exception:
                    pass

            # 9. Nuclei
            nuclei_json = vuln_base / key / "nuclei" / "structured" / "nuclei_result.json"
            if nuclei_json.exists():
                try:
                    nu_data = json.loads(nuclei_json.read_text(encoding="utf-8", errors="replace"))
                    vulns = []
                    items = nu_data.get("matches", []) or nu_data.get("findings", [])
                    for m in items:
                        t_id = m.get("template_id") or m.get("template-id")
                        info = m.get("info", {})
                        sev = info.get("severity") if isinstance(info, dict) else m.get("severity", "info")
                        name = info.get("name") if isinstance(info, dict) else m.get("name", t_id)
                        vulns.append({
                            "template": t_id,
                            "severity": sev,
                            "name": name,
                            "matched_at": m.get("matched_at") or m.get("matched-at"),
                        })
                    if vulns:
                        scans.append({
                            "tool": "nuclei",
                            "type": "vulnerabilities",
                            "matches": vulns,
                            "summary": f"Nuclei phát hiện {len(vulns)} lỗ hổng/cảnh báo: " + ", ".join([f"{v['template']} ({v['severity']})" for v in vulns[:3]]),
                        })
                except Exception:
                    pass

            # 10. SearchSploit
            searchsploit_json = vuln_base / key / "searchsploit" / "structured" / "searchsploit_result.json"
            if searchsploit_json.exists():
                try:
                    ss_data = json.loads(searchsploit_json.read_text(encoding="utf-8", errors="replace"))
                    ss_results = ss_data.get("results", [])
                    if ss_results:
                        scans.append({
                            "tool": "searchsploit",
                            "type": "exploit_references",
                            "references": ss_results,
                            "summary": f"SearchSploit tìm thấy {len(ss_results)} tài liệu/exploit tham khảo.",
                        })
                except Exception:
                    pass

            # 11. Service Enum (SMB, SNMP, LDAP, Database)
            t_enum_dir = enum_base / key
            if t_enum_dir.exists():
                for s_tool in ["enum4linux", "smbclient", "snmpwalk", "ldapsearch", "database"]:
                    s_file = t_enum_dir / s_tool / "structured" / f"{s_tool}_result.json"
                    if s_file.exists():
                        try:
                            s_data = json.loads(s_file.read_text(encoding="utf-8", errors="replace"))
                            s_findings = s_data.get("findings", [])
                            if s_findings:
                                scans.append({
                                    "tool": s_tool,
                                    "type": "service_enumeration",
                                    "findings": s_findings,
                                    "summary": f"{s_tool}: " + ", ".join([f['description'][:60] for f in s_findings[:2]]),
                                })
                        except Exception:
                            pass

            if scans:
                break

        return scans

    @classmethod
    def build(
        cls,
        user_message: str,
        active_target: Optional[dict] = None,
        active_file_path: Optional[str] = None,
        active_file_content: Optional[str] = None,
        conversation_id: Optional[str] = None,
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
            file_disk = next((p for p in candidates if p.exists() and p.is_file()), None)
            if file_disk:
                try:
                    content_str = file_disk.read_text(encoding="utf-8", errors="replace")
                    if len(content_str) > 8000:
                        content_str = content_str[:8000] + "...\n[TRUNCATED]"
                    active_file_data = {
                        "path": active_file_path,
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

        # 2. Auto-discover Scans for Active Target
        recent_scans = []
        if active_target:
            t_ident = active_target.get("target_id") or active_target.get("host") or active_target.get("normalized_value") or active_target.get("name") or ""
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
                    if p.get("product"):
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
        )

    @classmethod
    def to_prompt_messages(cls, ctx: ContextData) -> List[dict]:
        context_parts = []

        # Target section
        if ctx.active_target:
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
            context_parts.append("### TOOL RESULT CONFLICTS & DISCREPANCIES (MÂU THUẪN DỮ LIỆU GIỮA CÁC TOOL)\n" + "\n".join(conflict_lines))

        # Target Scan Evidence section
        if ctx.recent_scans:
            scan_lines = []
            for sc in ctx.recent_scans:
                scan_lines.append(f"#### Công cụ: {sc.get('tool', '').upper()} ({sc.get('type', '')})")
                if sc.get("ports") and isinstance(sc["ports"][0], dict):
                    for p in sc["ports"]:
                        scan_lines.append(f"  - {p['label']}")
                elif sc.get("summary"):
                    scan_lines.append(f"  - {sc['summary']}")
            context_parts.append("### TARGET SCAN & RECON EVIDENCE (CHỨNG CỨ QUÉT TRÊN TARGET)\n" + "\n".join(scan_lines))

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
            context_parts.append("### CORRELATED VULNERABILITY CANDIDATES\n" + "\n".join(cand_lines))

        # RAG Knowledge Sources
        if ctx.rag_sources:
            rag_lines = []
            for idx, s in enumerate(ctx.rag_sources, 1):
                rag_lines.append(f"[{idx}] {s['source']} {s['title']}: {s['content'][:200]}")
            context_parts.append("### AUTHORITATIVE KNOWLEDGE BASE SOURCES\n" + "\n".join(rag_lines))

        full_context = "\n\n".join(context_parts)

        messages = [{"role": "system", "content": SYSTEM_PROMPT}]

        if full_context.strip():
            messages.append({
                "role": "system",
                "content": f"=== CONTEXTUAL EVIDENCE & KNOWLEDGE BASE ===\n{full_context}\n===============================================",
            })

        # Inject conversation history
        for msg in ctx.conversation_history:
            messages.append({"role": msg["role"], "content": msg["content"]})

        # Inject current user query
        messages.append({"role": "user", "content": ctx.user_message})

        return messages

    def build_context(
        self,
        message: str,
        active_target: Optional[Any] = None,
        active_file: Optional[str] = None,
        active_file_content: Optional[str] = None,
        conversation_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        target_dict = None
        target_str = ""
        if isinstance(active_target, dict):
            target_dict = active_target
            target_str = active_target.get("normalized_value") or active_target.get("host") or active_target.get("name") or ""
        elif isinstance(active_target, str):
            target_str = active_target
            target_dict = {"name": active_target, "host": active_target, "type": "target"}

        ctx_data = self.build(
            user_message=message,
            active_target=target_dict,
            active_file_path=active_file,
            active_file_content=active_file_content,
            conversation_id=conversation_id,
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
            sources.append({
                "source": "NVD / CVE KB",
                "title": f"{c.get('cve_id')} (CVSS {c.get('cvss_score', 'N/A')})",
                "score": c.get("confidence", 0.95),
                "snippet": c.get("description", "")[:180],
                "url": c.get("source_url", "https://nvd.nist.gov"),
            })
        for s in ctx_data.rag_sources:
            sources.append({
                "source": s.get("source", "KB"),
                "title": s.get("title", ""),
                "score": s.get("score", 0.8),
                "snippet": s.get("content", "")[:180],
                "url": s.get("url", ""),
            })

        return {
            "ctx_data": ctx_data,
            "full_prompt": full_prompt,
            "sources": sources,
            "conflicts": ctx_data.conflicts,
            "correlations": ctx_data.correlator_candidates,
            "rag_results": ctx_data.rag_sources,
            "active_target": target_str,
            "active_file": active_file,
        }


context_engine = ContextEngine()
