"""Findings Builder: aggregates scan evidence from Original Toolset (Nmap, HTTPx, Nuclei, WhatWeb, Nikto, Service Enum, SearchSploit) into deduplicated findings."""

from __future__ import annotations

import hashlib
import json
import pathlib
from datetime import datetime, timezone

from backend.app.schemas.finding import (
    EvidenceItem,
    Finding,
    FindingCreate,
    FindingSeverity,
    FindingStatus,
    FindingUpdate,
)
from backend.app.services.correlator import Correlator
from backend.app.storage.findings_db import findings_db
from toolkit.scripts.scan_status import load_scan_status


def score_to_severity(score: float) -> FindingSeverity:
    if score >= 9.0:
        return FindingSeverity.CRITICAL
    if score >= 7.0:
        return FindingSeverity.HIGH
    if score >= 4.0:
        return FindingSeverity.MEDIUM
    if score > 0.0:
        return FindingSeverity.LOW
    return FindingSeverity.INFO


class FindingsBuilder:
    def __init__(self, root_dir: pathlib.Path | None = None):
        self.root_dir = (
            root_dir or pathlib.Path(__file__).resolve().parent.parent.parent.parent
        )

    def _resolve_tool_dir(
        self, category_dir: str, target_id: str, tool_name: str
    ) -> pathlib.Path | None:
        """Find the existing tool scan directory trying various target naming conventions."""
        clean_target = target_id.replace(":", "-")
        candidates = [
            self.root_dir
            / "toolkit"
            / category_dir
            / "scans"
            / f"target-{clean_target}"
            / tool_name,
            self.root_dir
            / "toolkit"
            / category_dir
            / "scans"
            / clean_target
            / tool_name,
            self.root_dir / "toolkit" / category_dir / "scans" / target_id / tool_name,
        ]
        if target_id.startswith("target-"):
            raw_id = target_id[7:]
            candidates.append(
                self.root_dir / "toolkit" / category_dir / "scans" / raw_id / tool_name
            )

        for c in candidates:
            if c.exists() and c.is_dir():
                return c
        return None

    def generate_findings_for_target(self, target_id: str) -> list[Finding]:
        """Aggregate evidence for a target across original toolset, correlate with KB, and deduplicate."""
        created_or_updated: list[Finding] = []

        # 1. Nmap structured results
        nmap_dir = self._resolve_tool_dir("03-network", target_id, "nmap")
        if nmap_dir:
            created_or_updated.extend(
                self._dispatch_tool_processing(
                    target_id, nmap_dir, "nmap", self._process_nmap
                )
            )

        # 2. Nuclei structured results
        nuclei_dir = self._resolve_tool_dir("05-vulnerability", target_id, "nuclei")
        if nuclei_dir:
            created_or_updated.extend(
                self._dispatch_tool_processing(
                    target_id, nuclei_dir, "nuclei", self._process_nuclei
                )
            )

        # 3. HTTPx structured results
        httpx_dir = self._resolve_tool_dir("04-web", target_id, "httpx")
        if httpx_dir:
            created_or_updated.extend(
                self._dispatch_tool_processing(
                    target_id, httpx_dir, "httpx", self._process_httpx
                )
            )

        # 4. WhatWeb structured results
        whatweb_dir = self._resolve_tool_dir("04-web", target_id, "whatweb")
        if whatweb_dir:
            created_or_updated.extend(
                self._dispatch_tool_processing(
                    target_id, whatweb_dir, "whatweb", self._process_whatweb
                )
            )

        # 5. Nikto structured results
        nikto_dir = self._resolve_tool_dir("04-web", target_id, "nikto")
        if nikto_dir:
            created_or_updated.extend(
                self._dispatch_tool_processing(
                    target_id, nikto_dir, "nikto", self._process_nikto
                )
            )

        # 6. Service Enumeration results
        clean_target = target_id.replace(":", "-")
        enum_base = self.root_dir / "toolkit" / "06-service-enum" / "scans"
        enum_dir = enum_base / f"target-{clean_target}"
        if not enum_dir.exists():
            enum_dir = enum_base / clean_target
        if enum_dir.exists():
            created_or_updated.extend(self._process_service_enum(target_id, enum_dir))

        # 7. SearchSploit lookup results
        searchsploit_dir = self._resolve_tool_dir(
            "05-vulnerability", target_id, "searchsploit"
        )
        if searchsploit_dir:
            created_or_updated.extend(
                self._dispatch_tool_processing(
                    target_id,
                    searchsploit_dir,
                    "searchsploit",
                    self._process_searchsploit,
                )
            )

        # Deduplicate & consolidate all findings for this target
        findings_db.deduplicate_all(target_id)

        # Export findings JSON to 09-analysis/findings/
        self._export_target_findings(target_id)

        clean_target = (
            target_id[7:] if target_id.startswith("target-") else target_id
        )
        final_findings = findings_db.list_findings(target_id=clean_target)
        if not final_findings and clean_target != target_id:
            final_findings = findings_db.list_findings(target_id=target_id)
        return final_findings

    def _dispatch_tool_processing(
        self,
        target_id: str,
        tool_dir: pathlib.Path,
        tool_name: str,
        processor_func,
    ) -> list[Finding]:
        """Inspects status.json before treating structured data as evidence."""
        status = load_scan_status(tool_dir)
        filename_map = {
            "nmap": "nmap_result.json",
            "nuclei": "nuclei_result.json",
            "httpx": "httpx_result.json",
            "whatweb": "whatweb_result.json",
            "nikto": "nikto_result.json",
            "searchsploit": "searchsploit_result.json",
        }
        res_file_name = filename_map.get(tool_name, f"{tool_name}_result.json")

        if status:
            mode = status.get("mode")
            trustworthy = bool(status.get("evidence_trustworthy", False))
            if mode == "failed":
                # Tool failed to run real scan -> do not fabricate or report fake findings
                return []
            if mode == "simulated" or not trustworthy:
                # Look in simulated/ directory or structured/ marked as simulated
                sim_file = tool_dir / "simulated" / res_file_name
                struct_file = tool_dir / "structured" / res_file_name
                target_file = sim_file if sim_file.exists() else struct_file
                if target_file.exists():
                    return processor_func(
                        target_id, target_file, trustworthy=False, is_simulated=True
                    )
                return []

            # Real & trustworthy
            struct_file = tool_dir / "structured" / res_file_name
            if struct_file.exists():
                return processor_func(
                    target_id, struct_file, trustworthy=True, is_simulated=False
                )
            return []

        # Legacy data without status.json: check structured file
        struct_file = tool_dir / "structured" / res_file_name
        if struct_file.exists():
            return processor_func(
                target_id, struct_file, trustworthy=True, is_simulated=False
            )
        return []

    def _process_nmap(
        self,
        target_id: str,
        file_path: pathlib.Path,
        trustworthy: bool = True,
        is_simulated: bool = False,
    ) -> list[Finding]:
        results = []
        try:
            data = json.loads(file_path.read_text(encoding="utf-8"))
            rel_path = str(file_path.relative_to(self.root_dir / "toolkit")).replace(
                "\\", "/"
            )

            for host in data.get("hosts", []):
                ip = host.get("ip") or host.get("addresses", {}).get("ipv4", target_id)
                for port_info in host.get("ports", []):
                    port = port_info.get("port") or port_info.get("portid")
                    service_obj = port_info.get("service", {})
                    if isinstance(service_obj, dict):
                        service = service_obj.get("name", "")
                        product = service_obj.get("product", "")
                        version = service_obj.get("version", "")
                    else:
                        service = str(service_obj)
                        product = port_info.get("product", "")
                        version = port_info.get("version", "")

                    state = port_info.get("state", "")
                    if state != "open":
                        continue

                    asset = f"{ip}:{port}"

                    # Normalize product for KB correlation
                    clean_prod = product
                    if "apache" in product.lower():
                        clean_prod = "Apache"
                    elif "openssh" in product.lower():
                        clean_prod = "OpenSSH"
                    elif "nginx" in product.lower():
                        clean_prod = "nginx"

                    # Correlate product & version with Vulnerability KB
                    if clean_prod and version:
                        matches = Correlator.correlate(
                            product=clean_prod, version=version, limit=3
                        )
                        for m in matches:
                            title_prefix = "[SIMULATED] " if is_simulated else ""
                            desc_prefix = (
                                "[LƯU Ý: DỮ LIỆU MÔ PHỎNG / CHƯA XÁC MINH BẰNG CHỨNG THỰC TẾ]\n"
                                if is_simulated
                                else ""
                            )
                            finding = self._upsert_finding(
                                target_id=target_id,
                                asset=asset,
                                cve_id=m.cve_id,
                                cwe_id=m.cwe_ids[0] if m.cwe_ids else "CWE-20",
                                title=f"{title_prefix}{product} {version} — {m.cve_id}",
                                description=f"{desc_prefix}Dịch vụ {product} phiên bản {version} chạy trên cổng {port} khớp với lỗ hổng đã xác nhận trong NVD: {m.description}",
                                cvss_score=m.cvss_score or 7.5,
                                remediation=f"Nâng cấp {product} lên phiên bản mới nhất đã được vá lỗi.",
                                evidence=EvidenceItem(
                                    tool="nmap",
                                    file_path=rel_path,
                                    matched_text=f"Port {port}/tcp open: {product} {version} (Service: {service})",
                                    timestamp=datetime.now(timezone.utc).isoformat(),
                                    trustworthy=trustworthy,
                                    is_simulated=is_simulated,
                                ),
                                trustworthy=trustworthy,
                                is_simulated=is_simulated,
                            )
                            results.append(finding)
        except Exception as e:
            print(f"[!] Error processing nmap results: {e}")
        return results

    def _process_nuclei(
        self,
        target_id: str,
        file_path: pathlib.Path,
        trustworthy: bool = True,
        is_simulated: bool = False,
    ) -> list[Finding]:
        results = []
        try:
            data = json.loads(file_path.read_text(encoding="utf-8"))
            rel_path = str(file_path.relative_to(self.root_dir / "toolkit")).replace(
                "\\", "/"
            )

            findings_list = (
                data
                if isinstance(data, list)
                else (data.get("findings") or data.get("matches") or [])
            )
            for item in findings_list:
                template_id = item.get("template_id") or item.get(
                    "template-id", "nuclei-finding"
                )
                name = item.get("info", {}).get("name", template_id)
                severity_str = (item.get("info", {}).get("severity") or "info").upper()
                cve_id = item.get("cve_id")
                if not cve_id:
                    info_cve = item.get("info", {}).get("cve_id") or item.get(
                        "info", {}
                    ).get("cve-id")
                    if isinstance(info_cve, list) and info_cve:
                        cve_id = info_cve[0]
                    elif isinstance(info_cve, str):
                        cve_id = info_cve

                if not cve_id and template_id.upper().startswith("CVE-"):
                    cve_id = template_id.upper()

                cwe_id = None
                cwes = item.get("info", {}).get("classification", {}).get("cwe-id", [])
                if cwes:
                    cwe_id = cwes[0] if isinstance(cwes, list) else str(cwes)

                cvss = float(
                    item.get("info", {})
                    .get("classification", {})
                    .get("cvss-score", 0.0)
                )
                matched_at = (
                    item.get("matched_at") or item.get("matched-at") or target_id
                )

                title_prefix = "[SIMULATED] " if is_simulated else ""
                desc_prefix = (
                    "[LƯU Ý: DỮ LIỆU MÔ PHỎNG / CHƯA XÁC MINH BẰNG CHỨNG THỰC TẾ]\n"
                    if is_simulated
                    else ""
                )

                finding = self._upsert_finding(
                    target_id=target_id,
                    asset=matched_at,
                    cve_id=cve_id,
                    cwe_id=cwe_id,
                    title=f"{title_prefix}Nuclei: {name}",
                    description=f"{desc_prefix}Nuclei scanner phát hiện dấu hiệu lỗ hổng thông qua template `{template_id}`.\nPhát hiện tại: `{matched_at}`",
                    cvss_score=cvss
                    if cvss > 0
                    else (7.5 if severity_str == "HIGH" else 5.0),
                    remediation="Kiểm tra lại cấu hình endpoint hoặc áp dụng bản vá tương ứng.",
                    evidence=EvidenceItem(
                        tool="nuclei",
                        file_path=rel_path,
                        matched_text=f"Template {template_id} [{severity_str}] matched at {matched_at}",
                        timestamp=datetime.now(timezone.utc).isoformat(),
                        trustworthy=trustworthy,
                        is_simulated=is_simulated,
                    ),
                    trustworthy=trustworthy,
                    is_simulated=is_simulated,
                )
                results.append(finding)
        except Exception as e:
            print(f"[!] Error processing nuclei results: {e}")
        return results

    def _process_httpx(
        self,
        target_id: str,
        file_path: pathlib.Path,
        trustworthy: bool = True,
        is_simulated: bool = False,
    ) -> list[Finding]:
        results = []
        try:
            data = json.loads(file_path.read_text(encoding="utf-8"))
            rel_path = str(file_path.relative_to(self.root_dir / "toolkit")).replace(
                "\\", "/"
            )
            endpoints = (
                data
                if isinstance(data, list)
                else (data.get("endpoints", []) or data.get("results", []))
            )

            for ep in endpoints:
                url = ep.get("url", target_id)
                webserver = ep.get("webserver", "")
                title = ep.get("title", "")
                tech = ep.get("technologies", []) or ep.get("tech", [])

                if "apache" in webserver.lower():
                    import re

                    m = re.search(r"apache/([0-9.]+)", webserver, re.IGNORECASE)
                    if m:
                        ver = m.group(1)
                        matches = Correlator.correlate(
                            product="Apache", version=ver, limit=2
                        )
                        for match in matches:
                            title_prefix = "[SIMULATED] " if is_simulated else ""
                            desc_prefix = (
                                "[LƯU Ý: DỮ LIỆU MÔ PHỎNG / CHƯA XÁC MINH BẰNG CHỨNG THỰC TẾ]\n"
                                if is_simulated
                                else ""
                            )
                            finding = self._upsert_finding(
                                target_id=target_id,
                                asset=url,
                                cve_id=match.cve_id,
                                cwe_id=match.cwe_ids[0] if match.cwe_ids else "CWE-22",
                                title=f"{title_prefix}HTTPx Web Banner: Apache {ver} — {match.cve_id}",
                                description=f"{desc_prefix}HTTPx ghi nhận server banner `{webserver}` tại `{url}`. Tương quan với lỗ hổng {match.cve_id}.",
                                cvss_score=match.cvss_score or 7.5,
                                remediation="Nâng cấp Apache HTTP Server hoặc cấu hình ẩn ServerTokens.",
                                evidence=EvidenceItem(
                                    tool="httpx",
                                    file_path=rel_path,
                                    matched_text=f"URL: {url} | Server: {webserver} | Title: {title} | Tech: {', '.join(tech) if isinstance(tech, list) else tech}",
                                    timestamp=datetime.now(timezone.utc).isoformat(),
                                    trustworthy=trustworthy,
                                    is_simulated=is_simulated,
                                ),
                                trustworthy=trustworthy,
                                is_simulated=is_simulated,
                            )
                            results.append(finding)
        except Exception as e:
            print(f"[!] Error processing httpx results: {e}")
        return results

    def _process_whatweb(
        self,
        target_id: str,
        file_path: pathlib.Path,
        trustworthy: bool = True,
        is_simulated: bool = False,
    ) -> list[Finding]:
        results = []
        try:
            data = json.loads(file_path.read_text(encoding="utf-8"))
            rel_path = str(file_path.relative_to(self.root_dir / "toolkit")).replace(
                "\\", "/"
            )
            targets = data.get("targets", [])
            for t_item in targets:
                target_url = t_item.get("target", target_id)
                for tech in t_item.get("technologies", []):
                    name = tech.get("name", "")
                    ver = tech.get("version", "")
                    clean_prod = name
                    if "apache" in name.lower():
                        clean_prod = "Apache"
                    elif "php" in name.lower():
                        clean_prod = "PHP"

                    if clean_prod and ver:
                        matches = Correlator.correlate(
                            product=clean_prod, version=ver, limit=2
                        )
                        for match in matches:
                            title_prefix = "[SIMULATED] " if is_simulated else ""
                            desc_prefix = (
                                "[LƯU Ý: DỮ LIỆU MÔ PHỎNG / CHƯA XÁC MINH BẰNG CHỨNG THỰC TẾ]\n"
                                if is_simulated
                                else ""
                            )
                            finding = self._upsert_finding(
                                target_id=target_id,
                                asset=target_url,
                                cve_id=match.cve_id,
                                cwe_id=match.cwe_ids[0] if match.cwe_ids else "CWE-200",
                                title=f"{title_prefix}WhatWeb: {clean_prod} {ver} — {match.cve_id}",
                                description=f"{desc_prefix}WhatWeb fingerprinting ghi nhận {clean_prod} phiên bản {ver} tại {target_url}.",
                                cvss_score=match.cvss_score or 7.5,
                                remediation=f"Cập nhật {clean_prod} lên phiên bản an toàn.",
                                evidence=EvidenceItem(
                                    tool="whatweb",
                                    file_path=rel_path,
                                    matched_text=f"WhatWeb detected: {name} {ver}",
                                    timestamp=datetime.now(timezone.utc).isoformat(),
                                    trustworthy=trustworthy,
                                    is_simulated=is_simulated,
                                ),
                                trustworthy=trustworthy,
                                is_simulated=is_simulated,
                            )
                            results.append(finding)
        except Exception as e:
            print(f"[!] Error processing whatweb results: {e}")
        return results

    def _process_nikto(
        self,
        target_id: str,
        file_path: pathlib.Path,
        trustworthy: bool = True,
        is_simulated: bool = False,
    ) -> list[Finding]:
        results = []
        try:
            data = json.loads(file_path.read_text(encoding="utf-8"))
            rel_path = str(file_path.relative_to(self.root_dir / "toolkit")).replace(
                "\\", "/"
            )
            host = data.get("host", target_id)
            port = data.get("port", 80)
            asset = f"{host}:{port}"

            for item in data.get("items", []):
                desc = item.get("description", "")
                nik_id = item.get("id", "0")
                sev_str = item.get("severity", "low")
                cvss = (
                    4.5 if sev_str == "low" else (6.5 if sev_str == "medium" else 3.0)
                )

                title_prefix = "[SIMULATED] " if is_simulated else ""
                desc_prefix = (
                    "[LƯU Ý: DỮ LIỆU MÔ PHỎNG / CHƯA XÁC MINH BẰNG CHỨNG THỰC TẾ]\n"
                    if is_simulated
                    else ""
                )

                finding = self._upsert_finding(
                    target_id=target_id,
                    asset=asset,
                    title=f"{title_prefix}Nikto: {desc[:60]}...",
                    description=f"{desc_prefix}Nikto phát hiện cấu hình web tiềm ẩn rủi ro: {desc}",
                    cvss_score=cvss,
                    remediation="Kiểm tra cấu hình web server và thiết lập các header bảo mật phù hợp.",
                    evidence=EvidenceItem(
                        tool="nikto",
                        file_path=rel_path,
                        matched_text=f"Nikto Item {nik_id}: {desc}",
                        timestamp=datetime.now(timezone.utc).isoformat(),
                        trustworthy=trustworthy,
                        is_simulated=is_simulated,
                    ),
                    trustworthy=trustworthy,
                    is_simulated=is_simulated,
                )
                results.append(finding)
        except Exception as e:
            print(f"[!] Error processing nikto results: {e}")
        return results

    def _process_service_enum(
        self, target_id: str, enum_dir: pathlib.Path
    ) -> list[Finding]:
        results = []
        try:
            for tool_folder in enum_dir.iterdir():
                if not tool_folder.is_dir():
                    continue
                tool_name = tool_folder.name
                status = load_scan_status(tool_folder)
                if status and status.get("mode") == "failed":
                    continue

                is_sim = bool(
                    status
                    and (
                        status.get("mode") == "simulated"
                        or not status.get("evidence_trustworthy", True)
                    )
                )
                trustworthy = (
                    bool(status.get("evidence_trustworthy", True)) if status else True
                )

                json_file = (
                    tool_folder
                    / ("simulated" if is_sim else "structured")
                    / f"{tool_name}_result.json"
                )
                if not json_file.exists():
                    json_file = tool_folder / "structured" / f"{tool_name}_result.json"
                if not json_file.exists():
                    continue

                data = json.loads(json_file.read_text(encoding="utf-8"))
                rel_path = str(
                    json_file.relative_to(self.root_dir / "toolkit")
                ).replace("\\", "/")

                for f_item in data.get("findings", []):
                    cat = f_item.get("category", "service_enum")
                    desc = f_item.get("description", "")
                    sev = f_item.get("severity", "info")
                    cvss = 5.0 if sev == "medium" else (2.0 if sev == "low" else 1.0)

                    title_prefix = "[SIMULATED] " if is_sim else ""
                    desc_prefix = (
                        "[LƯU Ý: DỮ LIỆU MÔ PHỎNG / CHƯA XÁC MINH BẰNG CHỨNG THỰC TẾ]\n"
                        if is_sim
                        else ""
                    )

                    finding = self._upsert_finding(
                        target_id=target_id,
                        asset=target_id,
                        title=f"{title_prefix}{tool_name.upper()}: {cat}",
                        description=f"{desc_prefix}{desc}",
                        cvss_score=cvss,
                        remediation="Đảm bảo dịch vụ không cho phép truy cập nặc danh hoặc rò rỉ thông tin người dùng/chia sẻ.",
                        evidence=EvidenceItem(
                            tool=tool_name,
                            file_path=rel_path,
                            matched_text=desc,
                            timestamp=datetime.now(timezone.utc).isoformat(),
                            trustworthy=trustworthy,
                            is_simulated=is_sim,
                        ),
                        trustworthy=trustworthy,
                        is_simulated=is_sim,
                    )
                    results.append(finding)
        except Exception as e:
            print(f"[!] Error processing service enum results: {e}")
        return results

    def _process_searchsploit(
        self,
        target_id: str,
        file_path: pathlib.Path,
        trustworthy: bool = True,
        is_simulated: bool = False,
    ) -> list[Finding]:
        results = []
        try:
            data = json.loads(file_path.read_text(encoding="utf-8"))
            rel_path = str(file_path.relative_to(self.root_dir / "toolkit")).replace(
                "\\", "/"
            )
            query = data.get("query", target_id)

            for exp in data.get("results", [])[:3]:
                title = exp.get("title", "")
                edb_id = exp.get("edb_id", "")
                cve_list = exp.get("cve_ids", [])
                cve_id = cve_list[0] if cve_list else None

                title_prefix = "[SIMULATED] " if is_simulated else ""
                desc_prefix = (
                    "[LƯU Ý: DỮ LIỆU MÔ PHỎNG / CHƯA XÁC MINH BẰNG CHỨNG THỰC TẾ]\n"
                    if is_simulated
                    else ""
                )

                finding = self._upsert_finding(
                    target_id=target_id,
                    asset=target_id,
                    cve_id=cve_id,
                    title=f"{title_prefix}SearchSploit Reference: {title[:70]}",
                    description=(
                        f"{desc_prefix}SearchSploit phát hiện tài liệu tham khảo lỗ hổng EDB-{edb_id} liên quan đến truy vấn '{query}'.\n"
                        f"Lưu ý: Đây là tài liệu tham khảo; không chứng minh mục tiêu có thể bị khai thác thực tế mà không qua kiểm thử an toàn."
                    ),
                    cvss_score=5.0,
                    remediation="Xác minh phiên bản phần mềm thực tế và đối chiếu với bản vá của nhà cung cấp.",
                    evidence=EvidenceItem(
                        tool="searchsploit",
                        file_path=rel_path,
                        matched_text=f"SearchSploit match: {title} (EDB-{edb_id})",
                        timestamp=datetime.now(timezone.utc).isoformat(),
                        trustworthy=trustworthy,
                        is_simulated=is_simulated,
                    ),
                    trustworthy=trustworthy,
                    is_simulated=is_simulated,
                )
                results.append(finding)
        except Exception as e:
            print(f"[!] Error processing searchsploit results: {e}")
        return results

    def _upsert_finding(
        self,
        target_id: str,
        asset: str,
        title: str,
        description: str,
        cvss_score: float,
        evidence: EvidenceItem,
        cve_id: str | None = None,
        cwe_id: str | None = None,
        remediation: str | None = None,
        trustworthy: bool = True,
        is_simulated: bool = False,
    ) -> Finding:
        """Deduplicate by (target_id, asset, cve_id) or (target_id, asset, title)."""
        clean_target = (
            target_id[7:] if target_id.startswith("target-") else target_id
        )
        existing = findings_db.find_duplicate(
            target_id=clean_target,
            affected_asset=asset,
            cve_id=cve_id,
            title=title,
        )

        if existing:
            # 1. Append evidence
            findings_db.append_evidence(existing.id, [evidence.model_dump()])

            # 2. Upgrade attributes if new evidence is better/richer
            update_data: dict[str, Any] = {}
            if cvss_score > existing.cvss_score:
                update_data["cvss_score"] = cvss_score
                update_data["cvss_severity"] = score_to_severity(cvss_score)
            if cwe_id and (not existing.cwe_id or existing.cwe_id in ("CWE-20", "CWE-Other")):
                update_data["cwe_id"] = cwe_id
            if trustworthy and not existing.trustworthy:
                update_data["trustworthy"] = True
            if not is_simulated and existing.is_simulated:
                update_data["is_simulated"] = False
                if existing.title.startswith("[SIMULATED] "):
                    update_data["title"] = existing.title.replace("[SIMULATED] ", "").strip()
            if remediation and len(remediation) > len(existing.remediation or ""):
                update_data["remediation"] = remediation

            if update_data:
                updated = findings_db.update_finding(
                    existing.id, FindingUpdate(**update_data)
                )
                return updated or existing
            return findings_db.get_finding(existing.id) or existing

        hash_seed = f"{clean_target}:{cve_id or title}"
        hash_suffix = hashlib.sha256(hash_seed.encode("utf-8")).hexdigest()[:8].upper()
        clean_target_str = clean_target.replace(":", "-").replace(".", "-")
        finding_id = f"FIND-{clean_target_str}-{hash_suffix}"

        sev = score_to_severity(cvss_score)
        if not trustworthy or is_simulated:
            init_status = FindingStatus.INSUFFICIENT_EVIDENCE
        elif cve_id and cvss_score > 0:
            init_status = FindingStatus.APPLICABLE
        else:
            init_status = FindingStatus.CANDIDATE

        create_item = FindingCreate(
            target_id=clean_target,
            title=title,
            cve_id=cve_id,
            cwe_id=cwe_id,
            cvss_score=cvss_score,
            cvss_severity=sev,
            status=init_status,
            affected_asset=asset,
            description=description,
            remediation=remediation
            or "Review configuration and apply vendor security patches.",
            evidence_chain=[evidence],
            trustworthy=trustworthy,
            is_simulated=is_simulated,
        )
        return findings_db.create_finding(finding_id, create_item)

    def _export_target_findings(self, target_id: str):
        """Export findings to toolkit/09-analysis/findings/<target_id>_findings.json with trustworthy audit metrics."""
        out_dir = self.root_dir / "toolkit" / "09-analysis" / "findings"
        out_dir.mkdir(parents=True, exist_ok=True)
        findings = findings_db.list_findings(target_id=target_id)
        clean_name = target_id.replace(":", "-")
        out_file = out_dir / f"{clean_name}_findings.json"

        trustworthy_count = sum(
            1 for f in findings if f.trustworthy and not f.is_simulated
        )
        simulated_count = sum(
            1 for f in findings if not f.trustworthy or f.is_simulated
        )

        data = {
            "target_id": target_id,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "total_findings": len(findings),
            "trustworthy_findings_count": trustworthy_count,
            "simulated_findings_count": simulated_count,
            "has_insufficient_evidence": (trustworthy_count == 0),
            "findings": [f.model_dump() for f in findings],
        }
        out_file.write_text(json.dumps(data, indent=2), encoding="utf-8")


findings_builder = FindingsBuilder()
