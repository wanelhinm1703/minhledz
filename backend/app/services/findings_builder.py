"""Findings Builder: aggregates scan evidence from Original Toolset (Nmap, HTTPx, Nuclei, WhatWeb, Nikto, Service Enum, SearchSploit) into deduplicated findings."""

from __future__ import annotations

import os
import json
import hashlib
import pathlib
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from backend.app.schemas.finding import (
    Finding,
    FindingCreate,
    FindingSeverity,
    FindingStatus,
    EvidenceItem,
)
from backend.app.storage.findings_db import findings_db
from backend.app.services.correlator import Correlator


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
    def __init__(self, root_dir: Optional[pathlib.Path] = None):
        self.root_dir = root_dir or pathlib.Path(__file__).resolve().parent.parent.parent.parent

    def generate_findings_for_target(self, target_id: str) -> List[Finding]:
        """Aggregate evidence for a target across original toolset, correlate with KB, and deduplicate."""
        created_or_updated: List[Finding] = []
        target_dir_name = f"target-{target_id.replace(':', '-')}"

        # 1. Nmap structured results
        nmap_file = self.root_dir / "toolkit" / "03-network" / "scans" / target_dir_name / "nmap" / "structured" / "nmap_result.json"
        if nmap_file.exists():
            created_or_updated.extend(self._process_nmap(target_id, nmap_file))

        # 2. Nuclei structured results
        nuclei_file = self.root_dir / "toolkit" / "05-vulnerability" / "scans" / target_dir_name / "nuclei" / "structured" / "nuclei_result.json"
        if nuclei_file.exists():
            created_or_updated.extend(self._process_nuclei(target_id, nuclei_file))

        # 3. HTTPx structured results
        httpx_file = self.root_dir / "toolkit" / "04-web" / "scans" / target_dir_name / "httpx" / "structured" / "httpx_result.json"
        if httpx_file.exists():
            created_or_updated.extend(self._process_httpx(target_id, httpx_file))

        # 4. WhatWeb structured results
        whatweb_file = self.root_dir / "toolkit" / "04-web" / "scans" / target_dir_name / "whatweb" / "structured" / "whatweb_result.json"
        if whatweb_file.exists():
            created_or_updated.extend(self._process_whatweb(target_id, whatweb_file))

        # 5. Nikto structured results
        nikto_file = self.root_dir / "toolkit" / "04-web" / "scans" / target_dir_name / "nikto" / "structured" / "nikto_result.json"
        if nikto_file.exists():
            created_or_updated.extend(self._process_nikto(target_id, nikto_file))

        # 6. Service Enumeration results (SMB, SNMP, LDAP, DB)
        service_enum_dir = self.root_dir / "toolkit" / "06-service-enum" / "scans" / target_dir_name
        if service_enum_dir.exists():
            created_or_updated.extend(self._process_service_enum(target_id, service_enum_dir))

        # 7. SearchSploit lookup results
        searchsploit_file = self.root_dir / "toolkit" / "05-vulnerability" / "scans" / target_dir_name / "searchsploit" / "structured" / "searchsploit_result.json"
        if searchsploit_file.exists():
            created_or_updated.extend(self._process_searchsploit(target_id, searchsploit_file))

        # Export findings JSON to 09-analysis/findings/
        self._export_target_findings(target_id)

        return created_or_updated

    def _process_nmap(self, target_id: str, file_path: pathlib.Path) -> List[Finding]:
        results = []
        try:
            data = json.loads(file_path.read_text(encoding="utf-8"))
            rel_path = str(file_path.relative_to(self.root_dir / "toolkit")).replace("\\", "/")

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
                        matches = Correlator.correlate(product=clean_prod, version=version, limit=3)
                        for m in matches:
                            finding = self._upsert_finding(
                                target_id=target_id,
                                asset=asset,
                                cve_id=m.cve_id,
                                cwe_id=m.cwe_ids[0] if m.cwe_ids else "CWE-20",
                                title=f"{product} {version} — {m.cve_id}",
                                description=f"Dịch vụ {product} phiên bản {version} chạy trên cổng {port} khớp với lỗ hổng đã xác nhận trong NVD: {m.description}",
                                cvss_score=m.cvss_score or 7.5,
                                remediation=f"Nâng cấp {product} lên phiên bản mới nhất đã được vá lỗi.",
                                evidence=EvidenceItem(
                                    tool="nmap",
                                    file_path=rel_path,
                                    matched_text=f"Port {port}/tcp open: {product} {version} (Service: {service})",
                                    timestamp=datetime.now(timezone.utc).isoformat(),
                                ),
                            )
                            results.append(finding)
        except Exception as e:
            print(f"[!] Error processing nmap results: {e}")
        return results

    def _process_nuclei(self, target_id: str, file_path: pathlib.Path) -> List[Finding]:
        results = []
        try:
            data = json.loads(file_path.read_text(encoding="utf-8"))
            rel_path = str(file_path.relative_to(self.root_dir / "toolkit")).replace("\\", "/")

            findings_list = data if isinstance(data, list) else data.get("findings", [])
            for item in findings_list:
                template_id = item.get("template_id") or item.get("template-id", "nuclei-finding")
                name = item.get("info", {}).get("name", template_id)
                severity_str = (item.get("info", {}).get("severity") or "info").upper()
                cve_id = item.get("cve_id")
                if not cve_id:
                    info_cve = item.get("info", {}).get("cve_id") or item.get("info", {}).get("cve-id")
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

                cvss = float(item.get("info", {}).get("classification", {}).get("cvss-score", 0.0))
                matched_at = item.get("matched_at") or item.get("matched-at") or target_id

                finding = self._upsert_finding(
                    target_id=target_id,
                    asset=matched_at,
                    cve_id=cve_id,
                    cwe_id=cwe_id,
                    title=f"Nuclei: {name}",
                    description=f"Nuclei scanner phát hiện dấu hiệu lỗ hổng thông qua template `{template_id}`.\nPhát hiện tại: `{matched_at}`",
                    cvss_score=cvss if cvss > 0 else (7.5 if severity_str == "HIGH" else 5.0),
                    remediation="Kiểm tra lại cấu hình endpoint hoặc áp dụng bản vá tương ứng.",
                    evidence=EvidenceItem(
                        tool="nuclei",
                        file_path=rel_path,
                        matched_text=f"Template {template_id} [{severity_str}] matched at {matched_at}",
                        timestamp=datetime.now(timezone.utc).isoformat(),
                    ),
                )
                results.append(finding)
        except Exception as e:
            print(f"[!] Error processing nuclei results: {e}")
        return results

    def _process_httpx(self, target_id: str, file_path: pathlib.Path) -> List[Finding]:
        results = []
        try:
            data = json.loads(file_path.read_text(encoding="utf-8"))
            rel_path = str(file_path.relative_to(self.root_dir / "toolkit")).replace("\\", "/")
            endpoints = data if isinstance(data, list) else (data.get("endpoints", []) or data.get("results", []))

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
                        matches = Correlator.correlate(product="Apache", version=ver, limit=2)
                        for match in matches:
                            finding = self._upsert_finding(
                                target_id=target_id,
                                asset=url,
                                cve_id=match.cve_id,
                                cwe_id=match.cwe_ids[0] if match.cwe_ids else "CWE-22",
                                title=f"HTTPx Web Banner: Apache {ver} — {match.cve_id}",
                                description=f"HTTPx ghi nhận server banner `{webserver}` tại `{url}`. Tương quan với lỗ hổng {match.cve_id}.",
                                cvss_score=match.cvss_score or 7.5,
                                remediation="Nâng cấp Apache HTTP Server hoặc cấu hình ẩn ServerTokens.",
                                evidence=EvidenceItem(
                                    tool="httpx",
                                    file_path=rel_path,
                                    matched_text=f"URL: {url} | Server: {webserver} | Title: {title} | Tech: {', '.join(tech) if isinstance(tech, list) else tech}",
                                    timestamp=datetime.now(timezone.utc).isoformat(),
                                ),
                            )
                            results.append(finding)
        except Exception as e:
            print(f"[!] Error processing httpx results: {e}")
        return results

    def _process_whatweb(self, target_id: str, file_path: pathlib.Path) -> List[Finding]:
        results = []
        try:
            data = json.loads(file_path.read_text(encoding="utf-8"))
            rel_path = str(file_path.relative_to(self.root_dir / "toolkit")).replace("\\", "/")
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
                        matches = Correlator.correlate(product=clean_prod, version=ver, limit=2)
                        for match in matches:
                            finding = self._upsert_finding(
                                target_id=target_id,
                                asset=target_url,
                                cve_id=match.cve_id,
                                cwe_id=match.cwe_ids[0] if match.cwe_ids else "CWE-200",
                                title=f"WhatWeb: {clean_prod} {ver} — {match.cve_id}",
                                description=f"WhatWeb fingerprinting ghi nhận {clean_prod} phiên bản {ver} tại {target_url}.",
                                cvss_score=match.cvss_score or 7.5,
                                remediation=f"Cập nhật {clean_prod} lên phiên bản an toàn.",
                                evidence=EvidenceItem(
                                    tool="whatweb",
                                    file_path=rel_path,
                                    matched_text=f"WhatWeb detected: {name} {ver}",
                                    timestamp=datetime.now(timezone.utc).isoformat(),
                                ),
                            )
                            results.append(finding)
        except Exception as e:
            print(f"[!] Error processing whatweb results: {e}")
        return results

    def _process_nikto(self, target_id: str, file_path: pathlib.Path) -> List[Finding]:
        results = []
        try:
            data = json.loads(file_path.read_text(encoding="utf-8"))
            rel_path = str(file_path.relative_to(self.root_dir / "toolkit")).replace("\\", "/")
            host = data.get("host", target_id)
            port = data.get("port", 80)
            asset = f"{host}:{port}"

            for item in data.get("items", []):
                desc = item.get("description", "")
                nik_id = item.get("id", "0")
                sev_str = item.get("severity", "low")
                cvss = 4.5 if sev_str == "low" else (6.5 if sev_str == "medium" else 3.0)

                finding = self._upsert_finding(
                    target_id=target_id,
                    asset=asset,
                    title=f"Nikto: {desc[:60]}...",
                    description=f"Nikto phát hiện cấu hình web tiềm ẩn rủi ro: {desc}",
                    cvss_score=cvss,
                    remediation="Kiểm tra cấu hình web server và thiết lập các header bảo mật phù hợp.",
                    evidence=EvidenceItem(
                        tool="nikto",
                        file_path=rel_path,
                        matched_text=f"Nikto Item {nik_id}: {desc}",
                        timestamp=datetime.now(timezone.utc).isoformat(),
                    ),
                )
                results.append(finding)
        except Exception as e:
            print(f"[!] Error processing nikto results: {e}")
        return results

    def _process_service_enum(self, target_id: str, enum_dir: pathlib.Path) -> List[Finding]:
        results = []
        try:
            for tool_folder in enum_dir.iterdir():
                if not tool_folder.is_dir():
                    continue
                tool_name = tool_folder.name
                json_file = tool_folder / "structured" / f"{tool_name}_result.json"
                if not json_file.exists():
                    continue

                data = json.loads(json_file.read_text(encoding="utf-8"))
                rel_path = str(json_file.relative_to(self.root_dir / "toolkit")).replace("\\", "/")

                for f_item in data.get("findings", []):
                    cat = f_item.get("category", "service_enum")
                    desc = f_item.get("description", "")
                    sev = f_item.get("severity", "info")
                    cvss = 5.0 if sev == "medium" else (2.0 if sev == "low" else 1.0)

                    finding = self._upsert_finding(
                        target_id=target_id,
                        asset=target_id,
                        title=f"{tool_name.upper()}: {cat}",
                        description=desc,
                        cvss_score=cvss,
                        remediation="Đảm bảo dịch vụ không cho phép truy cập nặc danh hoặc rò rỉ thông tin người dùng/chia sẻ.",
                        evidence=EvidenceItem(
                            tool=tool_name,
                            file_path=rel_path,
                            matched_text=desc,
                            timestamp=datetime.now(timezone.utc).isoformat(),
                        ),
                    )
                    results.append(finding)
        except Exception as e:
            print(f"[!] Error processing service enum results: {e}")
        return results

    def _process_searchsploit(self, target_id: str, file_path: pathlib.Path) -> List[Finding]:
        results = []
        try:
            data = json.loads(file_path.read_text(encoding="utf-8"))
            rel_path = str(file_path.relative_to(self.root_dir / "toolkit")).replace("\\", "/")
            query = data.get("query", target_id)

            for exp in data.get("results", [])[:3]:
                title = exp.get("title", "")
                edb_id = exp.get("edb_id", "")
                cve_list = exp.get("cve_ids", [])
                cve_id = cve_list[0] if cve_list else None

                finding = self._upsert_finding(
                    target_id=target_id,
                    asset=target_id,
                    cve_id=cve_id,
                    title=f"SearchSploit Reference: {title[:70]}",
                    description=(
                        f"SearchSploit phát hiện tài liệu tham khảo lỗ hổng EDB-{edb_id} liên quan đến truy vấn '{query}'.\n"
                        f"Lưu ý: Đây là tài liệu tham khảo; không chứng minh mục tiêu có thể bị khai thác thực tế mà không qua kiểm thử an toàn."
                    ),
                    cvss_score=5.0,
                    remediation="Xác minh phiên bản phần mềm thực tế và đối chiếu với bản vá của nhà cung cấp.",
                    evidence=EvidenceItem(
                        tool="searchsploit",
                        file_path=rel_path,
                        matched_text=f"SearchSploit match: {title} (EDB-{edb_id})",
                        timestamp=datetime.now(timezone.utc).isoformat(),
                    ),
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
        cve_id: Optional[str] = None,
        cwe_id: Optional[str] = None,
        remediation: Optional[str] = None,
    ) -> Finding:
        """Deduplicate by (target_id, asset, cve_id) or (target_id, asset, title)."""
        existing = findings_db.find_duplicate(
            target_id=target_id,
            affected_asset=asset,
            cve_id=cve_id,
            title=title,
        )

        if existing:
            updated = findings_db.append_evidence(existing.id, [evidence.model_dump()])
            return updated or existing

        hash_seed = f"{target_id}:{asset}:{cve_id or title}"
        hash_suffix = hashlib.sha256(hash_seed.encode("utf-8")).hexdigest()[:8].upper()
        clean_target = target_id.replace(":", "-").replace(".", "-")
        finding_id = f"FIND-{clean_target}-{hash_suffix}"

        sev = score_to_severity(cvss_score)
        create_item = FindingCreate(
            target_id=target_id,
            title=title,
            cve_id=cve_id,
            cwe_id=cwe_id,
            cvss_score=cvss_score,
            cvss_severity=sev,
            status=FindingStatus.CANDIDATE,
            affected_asset=asset,
            description=description,
            remediation=remediation or "Review configuration and apply vendor security patches.",
            evidence_chain=[evidence],
        )
        return findings_db.create_finding(finding_id, create_item)

    def _export_target_findings(self, target_id: str):
        """Export findings to toolkit/09-analysis/findings/<target_id>_findings.json."""
        out_dir = self.root_dir / "toolkit" / "09-analysis" / "findings"
        out_dir.mkdir(parents=True, exist_ok=True)
        findings = findings_db.list_findings(target_id=target_id)
        clean_name = target_id.replace(":", "-")
        out_file = out_dir / f"{clean_name}_findings.json"
        data = {
            "target_id": target_id,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "total_findings": len(findings),
            "findings": [f.model_dump() for f in findings],
        }
        out_file.write_text(json.dumps(data, indent=2), encoding="utf-8")


findings_builder = FindingsBuilder()
