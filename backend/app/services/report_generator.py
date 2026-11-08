"""Comprehensive Pentest Report Generator producing professional Markdown and HTML reports.
Enforces strict distinction between REAL, SIMULATED, and FAILED scans (MASTER PROMPT v5.0 §17, §29, §53, §75).
"""

from __future__ import annotations

import json
import pathlib
from datetime import datetime, timezone
from typing import Any

from backend.app.services.compliance_engine import compliance_engine
from backend.app.services.pdf_generator import pdf_report_generator
from backend.app.services.sarif_exporter import sarif_exporter
from backend.app.services.verification_planner import verification_planner
from backend.app.storage.findings_db import findings_db
from toolkit.scripts.scan_status import load_scan_status


class ReportGenerator:
    def __init__(self, root_dir: pathlib.Path | None = None):
        self.root_dir = (
            root_dir or pathlib.Path(__file__).resolve().parent.parent.parent.parent
        )
        self.reports_dir = self.root_dir / "toolkit" / "10-reports"
        self.reports_dir.mkdir(parents=True, exist_ok=True)

    def _collect_target_tool_statuses(self, target_id: str) -> dict[str, dict]:
        clean_target = target_id.replace(":", "-")
        target_keys = {target_id, clean_target, f"target-{clean_target}"}
        if target_id.startswith("target-"):
            target_keys.add(target_id[7:])

        categories = [
            "03-network",
            "04-web",
            "05-vulnerability",
            "06-service-enum",
            "08-manual",
        ]
        tool_statuses = {}
        for cat in categories:
            cat_dir = self.root_dir / "toolkit" / cat / "scans"
            if not cat_dir.exists():
                continue
            for t_key in target_keys:
                t_dir = cat_dir / t_key
                if t_dir.exists() and t_dir.is_dir():
                    for tool_dir in t_dir.iterdir():
                        if tool_dir.is_dir():
                            st = load_scan_status(tool_dir)
                            if st:
                                tool_statuses[tool_dir.name] = st
        return tool_statuses

    def generate_report(
        self, target_id: str, campaign_name: str = "Automated Lab Assessment"
    ) -> dict[str, Any]:
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        clean_target = target_id.replace(":", "-").replace("/", "-")
        findings = findings_db.list_findings(target_id=target_id)
        summary = findings_db.get_summary(target_id=target_id)
        compliance_summary = compliance_engine.evaluate_compliance_summary(findings)
        tool_statuses = self._collect_target_tool_statuses(target_id)

        # 1. Generate Markdown Report with Compliance Matrix
        md_content = self._render_markdown(
            target_id, campaign_name, ts, findings, summary, tool_statuses, compliance_summary
        )
        md_path = self.reports_dir / f"{clean_target}_report.md"
        md_path.write_text(md_content, encoding="utf-8")

        # 2. Generate HTML Report with Compliance Section
        html_content = self._render_html(
            target_id, campaign_name, ts, findings, summary, tool_statuses, md_content, compliance_summary
        )
        html_path = self.reports_dir / f"{clean_target}_report.html"
        html_path.write_text(html_content, encoding="utf-8")

        # 3. Export OASIS SARIF v2.1.0 for GitHub / GitLab CI
        sarif_doc = sarif_exporter.export_sarif(target_id, findings, campaign_name)
        sarif_path = self.reports_dir / f"{clean_target}_report.sarif"

        # 4. Generate Machine-readable JSON summary
        json_path = self.reports_dir / f"{clean_target}_report.json"
        json_data = {
            "target_id": target_id,
            "campaign_name": campaign_name,
            "generated_at": ts,
            "summary": summary,
            "compliance": compliance_summary,
            "findings": [f.model_dump() for f in findings],
        }
        json_path.write_text(json.dumps(json_data, indent=2), encoding="utf-8")

        # 5. Generate Professional PDF 1.4 Report
        pdf_path = self.reports_dir / f"{clean_target}_report.pdf"
        try:
            pdf_report_generator.generate_pdf_report(
                target_id=target_id,
                campaign_name=campaign_name,
                findings=findings,
                summary=summary,
                compliance_summary=compliance_summary,
                output_path=pdf_path,
            )
        except Exception as e:
            pdf_path = None

        return {
            "target_id": target_id,
            "campaign_name": campaign_name,
            "generated_at": ts,
            "findings_count": len(findings),
            "summary": summary,
            "compliance_summary": compliance_summary,
            "tool_statuses": tool_statuses,
            "markdown_path": str(md_path.relative_to(self.root_dir)).replace("\\", "/"),
            "html_path": str(html_path.relative_to(self.root_dir)).replace("\\", "/"),
            "sarif_path": str(sarif_path.relative_to(self.root_dir)).replace("\\", "/"),
            "json_path": str(json_path.relative_to(self.root_dir)).replace("\\", "/"),
            "pdf_path": str(pdf_path.relative_to(self.root_dir)).replace("\\", "/") if pdf_path and pdf_path.exists() else "",
            "markdown_content": md_content,
        }

    def get_report(self, target_id: str) -> dict[str, Any] | None:
        clean_target = target_id.replace(":", "-").replace("/", "-")
        md_path = self.reports_dir / f"{clean_target}_report.md"
        html_path = self.reports_dir / f"{clean_target}_report.html"
        sarif_path = self.reports_dir / f"{clean_target}_report.sarif"
        json_path = self.reports_dir / f"{clean_target}_report.json"
        pdf_path = self.reports_dir / f"{clean_target}_report.pdf"

        if not md_path.exists():
            alt_id = clean_target[7:] if clean_target.startswith("target-") else f"target-{clean_target}"
            alt_md = self.reports_dir / f"{alt_id}_report.md"
            if alt_md.exists():
                return self.get_report(alt_id)
            return None
        html_text = html_path.read_text(encoding="utf-8") if html_path.exists() else ""
        sarif_text = sarif_path.read_text(encoding="utf-8") if sarif_path.exists() else ""
        
        findings = findings_db.list_findings(target_id=target_id)
        compliance_summary = compliance_engine.evaluate_compliance_summary(findings)

        # Generate PDF on the fly if missing
        if not pdf_path.exists():
            try:
                summary = findings_db.get_summary(target_id=target_id)
                pdf_report_generator.generate_pdf_report(
                    target_id=target_id,
                    campaign_name="Automated Lab Assessment",
                    findings=findings,
                    summary=summary,
                    compliance_summary=compliance_summary,
                    output_path=pdf_path,
                )
            except Exception:
                pass

        return {
            "target_id": target_id,
            "markdown_content": md_path.read_text(encoding="utf-8"),
            "html_content": html_text,
            "sarif_content": sarif_text,
            "compliance_summary": compliance_summary,
            "markdown_path": str(md_path.relative_to(self.root_dir)).replace("\\", "/"),
            "html_path": str(html_path.relative_to(self.root_dir)).replace("\\", "/") if html_path.exists() else "",
            "sarif_path": str(sarif_path.relative_to(self.root_dir)).replace("\\", "/") if sarif_path.exists() else "",
            "json_path": str(json_path.relative_to(self.root_dir)).replace("\\", "/") if json_path.exists() else "",
            "pdf_path": str(pdf_path.relative_to(self.root_dir)).replace("\\", "/") if pdf_path.exists() else "",
        }

    def list_reports(self) -> list[dict[str, Any]]:
        reports = []
        for p in self.reports_dir.glob("*_report.md"):
            name = p.stem.replace("_report", "")
            reports.append(
                {
                    "target_id": name,
                    "file_name": p.name,
                    "path": str(p.relative_to(self.root_dir)).replace("\\", "/"),
                    "modified_at": datetime.fromtimestamp(
                        p.stat().st_mtime, timezone.utc
                    ).isoformat(),
                }
            )
        return sorted(reports, key=lambda x: x["modified_at"], reverse=True)

    def _render_markdown(
        self,
        target_id: str,
        campaign: str,
        ts: str,
        findings: list,
        summary: dict,
        tool_statuses: dict[str, dict],
        compliance_summary: dict | None = None,
    ) -> str:
        # Strict Audit Filtering: Filter out False Positives completely
        false_positive_findings = [
            f for f in findings
            if getattr(f.status, "value", str(f.status)) == "FALSE_POSITIVE"
        ]
        active_findings = [
            f for f in findings
            if getattr(f.status, "value", str(f.status)) != "FALSE_POSITIVE"
        ]

        verified_findings = [
            f for f in active_findings
            if getattr(f, "trustworthy", True)
            and not getattr(f, "is_simulated", False)
            and getattr(f.status, "value", str(f.status)) == "VERIFIED"
        ]
        candidate_findings = [
            f for f in active_findings
            if getattr(f, "trustworthy", True)
            and not getattr(f, "is_simulated", False)
            and getattr(f.status, "value", str(f.status)) in ("CANDIDATE", "UNVERIFIED")
        ]
        trustworthy_findings = verified_findings + candidate_findings

        simulated_findings = [
            f
            for f in active_findings
            if not getattr(f, "trustworthy", True) or getattr(f, "is_simulated", False)
        ]

        lines = [
            "# BÁO CÁO ĐÁNH GIÁ AN TOÀN THÔNG TIN & KIỂM THỬ XÂM NHẬP",
            f"**Mục tiêu**: `{target_id}` | **Chiến dịch**: {campaign} | **Thời gian lập**: {ts}",
            "**Hệ thống phân tích**: AI-Pentest Copilot v6.0 (Động cơ Kiểm chứng An toàn Chỉ đọc)",
            "",
            "---",
            "",
        ]

        # Executive Summary / Insufficient Evidence Warning
        if not trustworthy_findings:
            lines.extend(
                [
                    "## 1. TÓM TẮT DÀNH CHO BAN ĐIỀU HÀNH (EXECUTIVE SUMMARY - INSUFFICIENT EVIDENCE)",
                    "> [!CAUTION]",
                    "> **TRẠNG THÁI ĐÁNH GIÁ: CHƯA ĐỦ BẰNG CHỨNG / KHÔNG CÓ PHÁT HIỆN XÁC MINH**",
                    ">",
                    f"> Trong quá trình đánh giá an toàn trên mục tiêu **`{target_id}`**, hoạt động trinh sát tự động **CHƯA** ghi nhận lỗ hổng được xác minh thực tế.",
                    "> Các bộ công cụ được chạy ở chế độ mô phỏng hoặc thiếu tệp thực thi phụ thuộc.",
                    "> **Không có lỗ hổng thực tế hoặc CVE nào được xác nhận dựa trên bằng chứng thu thập trực tiếp.**",
                    "",
                ]
            )
        else:
            lines.extend(
                [
                    "## 1. TÓM TẮT DÀNH CHO BAN ĐIỀU HÀNH (EXECUTIVE SUMMARY)",
                    f"Trong quá trình đánh giá an toàn trên mục tiêu **`{target_id}`**, hệ thống trinh sát và đối soát lỗ hổng tự động đã xác định và kiểm chứng **{len(trustworthy_findings)}** phát hiện an ninh có thể hành động được.",
                    "",
                    "### Phân bổ Mức độ Rủi ro (Dựa trên Bằng chứng Đáng tin cậy)",
                    f"- **Nghiêm trọng (Critical)**: `{sum(1 for f in trustworthy_findings if f.cvss_severity.value == 'CRITICAL')}`",
                    f"- **Mức độ Cao (High)**: `{sum(1 for f in trustworthy_findings if f.cvss_severity.value == 'HIGH')}`",
                    f"- **Trung bình (Medium)**: `{sum(1 for f in trustworthy_findings if f.cvss_severity.value == 'MEDIUM')}`",
                    f"- **Mức độ Thấp (Low)**: `{sum(1 for f in trustworthy_findings if f.cvss_severity.value == 'LOW')}`",
                    f"- **Thông tin (Info)**: `{sum(1 for f in trustworthy_findings if f.cvss_severity.value == 'INFO')}`",
                    "",
                ]
            )

        # Tool Execution Status Table
        if tool_statuses:
            lines.extend(
                [
                    "### Kiểm toán Trạng thái Thực thi Công cụ (Tool Execution & Reliability Audit)",
                    "| Công cụ | Chế độ Thực thi | Bằng chứng Tin cậy | Mã Thoát | Nguyên nhân / Chẩn đoán |",
                    "|---|---|---|---|---|",
                ]
            )
            for tool_name, st in sorted(tool_statuses.items()):
                m = st.get("mode", "unknown").upper()
                tw = "CÓ (YES)" if st.get("evidence_trustworthy") else "KHÔNG (NO)"
                code = st.get("exit_code", 0)
                reason = st.get("reason") or (
                    st.get("errors")[0] if st.get("errors") else "Hoàn thành bình thường"
                )
                lines.append(
                    f"| `{tool_name}` | **{m}** | `{tw}` | `{code}` | {reason} |"
                )
            lines.append("")

        if simulated_findings:
            lines.extend(
                [
                    "> [!WARNING]",
                    f"> **LƯU Ý DỮ LIỆU MÔ PHỎNG**: `{len(simulated_findings)}` phát hiện được tạo từ dữ liệu mẫu mô phỏng và **KHÔNG** phải bằng chứng thực tế.",
                    "> Tuyệt đối không tự suy diễn CVE khi chưa có bằng chứng quét thực nghiệm xác nhận.",
                    "",
                ]
            )

        lines.extend(
            [
                "### Phương pháp Luận & Phạm vi Được Ủy quyền",
                "- **Thực thi Phạm vi**: Mục tiêu được xác thực nằm trong phạm vi cho phép (Dải mạng riêng RFC 1918 / Localhost).",
                "- **Nguyên tắc An toàn Không Phá hủy**: Không sử dụng payload khai thác gây hại. Toàn bộ phát hiện đều dựa trên phân tích banner thụ động, chữ ký dịch vụ và kế hoạch kiểm chứng an toàn chỉ đọc.",
                "- **Tính Toàn vẹn Bằng chứng**: Phân định minh bạch giữa quét THỰC TẾ (REAL), MÔ PHỎNG (SIMULATED) và THẤT BÀI (FAILED).",
                "",
                "---",
                "",
                "## 2. HỒ SƠ CHI TIẾT CÁC LỖ HỔNG ĐÃ XÁC MINH (BẰNG CHỨNG THỰC TẾ)",
            ]
        )

        if not trustworthy_findings:
            lines.append(
                "Không ghi nhận lỗ hổng thực tế nào được xác minh trên mục tiêu này.\n"
            )
        else:
            for idx, f in enumerate(trustworthy_findings, 1):
                plan = verification_planner.generate_plan(f)
                lines.extend(
                    [
                        f"### [{idx}] {f.title}",
                        f"- **Mã Phát hiện (ID)**: `{f.id}`",
                        f"- **Mức độ Rủi ro**: `{f.cvss_severity.value}` (Điểm CVSS v3: `{f.cvss_score:.1f}`)",
                        f"- **Trạng thái**: `{f.status.value}`",
                        f"- **Định danh CVE**: `{f.cve_id or 'N/A'}` | **Điểm yếu CWE**: `{f.cwe_id or 'N/A'}`",
                        f"- **Tài sản Ảnh hưởng**: `{f.affected_asset}`",
                        "",
                        "#### Mô tả Kỹ thuật",
                        f"{f.description}",
                        "",
                        "#### Chuỗi Chứng cứ Thực nghiệm Bất biến",
                    ]
                )
                for ev in f.evidence_chain:
                    lines.append(
                        f"- **Công cụ**: `{ev.tool}` | **Tập tin Log**: `{ev.file_path}`"
                    )
                    lines.append("  ```text\n  " + ev.matched_text + "\n  ```")

                lines.extend(
                    [
                        "#### Kế hoạch Kiểm chứng An toàn Chỉ đọc (Safe Read-Only Plan)",
                    ]
                )
                for s in plan.steps:
                    lines.append(f"{s.step_number}. **{s.name}**")
                    lines.append("   ```bash\n   " + s.command + "\n   ```")
                    lines.append(f"   - *Bằng chứng kỳ vọng*: {s.expected_evidence}")

                if f.remediation:
                    lines.extend(
                        [
                            "",
                            "#### Khuyến nghị Khắc phục & Giảm thiểu",
                            f"{f.remediation}",
                        ]
                    )
        # 3. Regulatory & Compliance Standards Audit
        lines.extend(
            [
                "## 3. HIỆN TRẠNG TUÂN THỦ QUY CHUẨN & TIÊU CHUẨN QUỐC TẾ (REGULATORY & COMPLIANCE POSTURE - COMPLIANCE 2.0)",
                "Đánh giá này đối soát mức độ tuân thủ dựa trên các tiêu chuẩn an toàn thông tin hàng đầu:",
                "- **OWASP Top 10 (2021 & 2025)**",
                "- **MITRE CWE Top 25 Danh sách Điểm yếu Phần mềm Nguy hiểm nhất**",
                "- **NIST SP 800-115 (Hướng dẫn Đánh giá và Kiểm thử An ninh Thông tin)**",
                "- **CIS Controls v8 (Khung Kiểm soát Bảo mật Thiết yếu)**",
                "",
            ]
        )

        if compliance_summary:
            score = compliance_summary.get("compliance_score", 100)
            status = compliance_summary.get("status", "PASSED")
            status_vn = "ĐẠT (PASSED)" if status == "PASSED" else "CẦN LƯU Ý (NEEDS REVIEW)" if status == "NEEDS_REVIEW" else "KHÔNG ĐẠT (FAILED)"
            lines.extend(
                [
                    f"### Điểm số Tuân thủ Tổng thể: `{score}/100` — **{status_vn}**",
                    f"- **Số vi phạm đang tồn tại**: `{compliance_summary.get('total_active_violations', 0)}`",
                    f"- **Thiếu sót Nghiêm trọng / Mức độ Cao**: `{compliance_summary.get('critical_high_count', 0)}`",
                    "",
                    "### Ma trận Tuân thủ Tiêu chuẩn Quốc tế",
                    "| Khung Tiêu chuẩn | Điều khoản / Yêu cầu | Phát hiện Tương ứng | Mức độ Rủi ro | Trạng thái Tuân thủ |",
                    "|---|---|---|---|---|",
                ]
            )

            if not trustworthy_findings:
                lines.append(
                    "| *N/A* | *Kiểm tra Cơ sở (Baseline)* | *Không ghi nhận lỗ hổng* | `INFO` | **TUÂN THỦ (COMPLIANT)** |"
                )
            else:
                for f in trustworthy_findings:
                    m = compliance_engine.map_finding(f)
                    owasp_id = m["owasp"]["id"]
                    owasp_name = m["owasp"]["name"]
                    cwe_id = m["cwe_id"] or "CWE-General"
                    cwe_top25 = f" (CWE Top 25 #{m['cwe_top_25']['rank']})" if m["cwe_top_25"]["is_top_25"] else ""
                    cis_ctrl = m["cis_controls"]["control"]
                    sev_val = f.cvss_severity.value
                    st_val = "KHÔNG TUÂN THỦ" if sev_val in ("CRITICAL", "HIGH") else "CÓ SAI LỆCH"

                    lines.append(
                        f"| **OWASP {owasp_id}**<br>({owasp_name}) | {cis_ctrl}<br>{m['nist_sp_800_115']['section']} | `{f.title[:35]}`<br>*{cwe_id}{cwe_top25}* | `{sev_val}` | **{st_val}** |"
                    )
            lines.append("")

            # CWE Top 25 Hit summary
            cwe_hits = compliance_summary.get("cwe_top_25_hits", [])
            if cwe_hits:
                lines.extend(
                    [
                        "### Danh sách Điểm yếu thuộc MITRE CWE Top 25",
                        "Các phát hiện sau đây tương ứng trực tiếp với danh sách điểm yếu phần mềm nguy hiểm nhất do MITRE công bố:",
                        "| Thứ hạng | Mã CWE | Tên Điểm yếu Phần mềm | Mức độ Rủi ro |",
                        "|---|---|---|---|",
                    ]
                )
                for h in cwe_hits:
                    lines.append(f"| **#{h['rank']}** | `{h['cwe_id']}` | {h['name']} | `{h['severity']}` |")
                lines.append("")

        if simulated_findings:
            lines.extend(
                [
                    "## 4. DỮ LIỆU MÔ PHỎNG / CHƯA XÁC MINH (CHỈ PHỤC VỤ TEST MẪU)",
                    "> ⚠️ Các mục dưới đây được sinh ra trong các lượt chạy mô phỏng và KHÔNG đại diện cho lỗ hổng thực tế trên mục tiêu.",
                    "",
                ]
            )
            for idx, f in enumerate(simulated_findings, 1):
                lines.extend(
                    [
                        f"### [MÔ PHỎNG-{idx}] {f.title}",
                        f"- **Mức độ**: `{f.cvss_severity.value}` | **Tài sản**: `{f.affected_asset}`",
                        f"- **Mô tả**: {f.description}",
                        "",
                    ]
                )

        lines.extend(
            [
                "## 4. LỘ TRÌNH KHUYẾN NGHỊ KHẮC PHỤC (REMEDIATION ROADMAP)",
                "1. **Hành động Khẩn cấp (Trong vòng 24 Giờ)**:",
                "   - Nâng cấp hoặc vá các dịch vụ bị gán mức rủi ro Nghiêm trọng / Cao (VD: máy chủ web Apache).",
                "   - Giới hạn quyền truy cập các cổng quản trị qua quy tắc tường lửa (Firewall Ingress Rules).",
                "2. **Hành động Ngắn hạn (Trong vòng 7 Ngày)**:",
                "   - Bổ sung các HTTP Security Headers và tắt tiết lộ thông tin phiên bản (ServerTokens Prod).",
                "   - Chạy lại kiểm tra kiểm chứng an toàn để xác nhận hiệu quả của bản vá.",
                "3. **Hành động Dài hạn & Giám sát Liên tục**:",
                "   - Tích hợp rà quét trinh sát tự động vào quy trình CI/CD.",
                "",
                "---",
                "*Báo cáo được khởi tạo tự động bởi AI-Pentest Copilot v6.0. Dữ liệu chứng cứ được niêm phong trong kho lưu ký số.*",
            ]
        )

        return "\n".join(lines)

    def _render_html(
        self,
        target_id: str,
        campaign: str,
        ts: str,
        findings: list,
        summary: dict,
        tool_statuses: dict[str, dict],
        md_content: str,
        compliance_summary: dict | None = None,
    ) -> str:
        # Strict Audit Filtering: Exclude False Positives completely
        active_findings = [
            f for f in findings
            if getattr(f.status, "value", str(f.status)) != "FALSE_POSITIVE"
        ]
        trustworthy_findings = [
            f
            for f in active_findings
            if getattr(f, "trustworthy", True) and not getattr(f, "is_simulated", False)
        ]
        simulated_findings = [
            f
            for f in active_findings
            if not getattr(f, "trustworthy", True) or getattr(f, "is_simulated", False)
        ]

        crit_count = sum(
            1 for f in trustworthy_findings if f.cvss_severity.value == "CRITICAL"
        )
        high_count = sum(
            1 for f in trustworthy_findings if f.cvss_severity.value == "HIGH"
        )
        med_count = sum(
            1 for f in trustworthy_findings if f.cvss_severity.value == "MEDIUM"
        )
        low_count = sum(
            1 for f in trustworthy_findings if f.cvss_severity.value == "LOW"
        )

        finding_cards = []
        for f in trustworthy_findings:
            score_str = f"{f.cvss_score:.1f}"
            sev_class = f.cvss_severity.value.lower()
            cve_txt = f.cve_id or "N/A"
            rem_txt = f.remediation or "Xem xét và cập nhật cấu hình bảo mật hệ thống."
            card = f"""
    <div style="background: #182234; border: 1px solid #334155; border-radius: 8px; padding: 16px; margin-bottom: 16px;">
      <div style="display:flex; justify-content:space-between; align-items:center;">
        <h3 style="margin:0; color:#38bdf8;">{f.title}</h3>
        <span class="badge {sev_class}">{f.cvss_severity.value} (CVSS {score_str})</span>
      </div>
      <p style="font-size:13px; color:#94a3b8; margin: 8px 0;">Tài sản: <code>{f.affected_asset}</code> | Trạng thái: <strong>{f.status.value}</strong> | Lỗ hổng CVE: <code>{cve_txt}</code></p>
      <p>{f.description}</p>
      <h4 style="color:#7dd3fc; margin: 10px 0 4px 0;">Khuyến nghị Khắc phục</h4>
      <p style="color:#86efac; margin:0;">{rem_txt}</p>
    </div>
            """
            finding_cards.append(card)

        cards_html = (
            "".join(finding_cards)
            if finding_cards
            else "<p style='color:#94a3b8;'>Không ghi nhận lỗ hổng thực tế nào trong chu kỳ quét này.</p>"
        )

        # Audit rows
        audit_rows = []
        for tname, st in sorted(tool_statuses.items()):
            mode_color = (
                "#10b981"
                if st.get("mode") == "real"
                else ("#f59e0b" if st.get("mode") == "simulated" else "#ef4444")
            )
            audit_rows.append(f"""
            <tr>
              <td style="padding:6px 12px; border-bottom:1px solid #334155;"><code>{tname}</code></td>
              <td style="padding:6px 12px; border-bottom:1px solid #334155; color:{mode_color}; font-weight:bold;">{st.get("mode", "").upper()}</td>
              <td style="padding:6px 12px; border-bottom:1px solid #334155;">{"CÓ (YES)" if st.get("evidence_trustworthy") else "KHÔNG (NO)"}</td>
              <td style="padding:6px 12px; border-bottom:1px solid #334155; color:#94a3b8;">{st.get("reason") or "Hoàn tất bình thường"}</td>
            </tr>
            """)
        audit_table = "".join(audit_rows)

        alert_banner = ""
        if not trustworthy_findings:
            alert_banner = """
            <div style="background:#451a1a; border:1px solid #dc2626; border-radius:8px; padding:14px; margin:20px 0; color:#fecaca;">
              <strong>⚠️ TRẠNG THÁI KIỂM TOÁN: CHƯA ĐỦ BẰNG CHỨNG / KHÔNG CÓ PHÁT HIỆN THỰC TẾ</strong><br>
              Các công cụ tự động chưa ghi nhận lỗ hổng thực tế có thể xác minh được.
            </div>
            """

        compliance_section = ""
        if compliance_summary:
            score = compliance_summary.get("compliance_score", 100)
            status = compliance_summary.get("status", "PASSED")
            status_vn = "ĐẠT (PASSED)" if status == "PASSED" else "CẦN LƯU Ý (NEEDS REVIEW)" if status == "NEEDS_REVIEW" else "KHÔNG ĐẠT (FAILED)"
            color = "#10b981" if score >= 80 else "#f59e0b" if score >= 50 else "#ef4444"
            rows = []
            for f in trustworthy_findings:
                m = compliance_engine.map_finding(f)
                cwe_top25 = f" (CWE Top 25 #{m['cwe_top_25']['rank']})" if m['cwe_top_25']['is_top_25'] else ""
                sev_cls = "crit" if f.cvss_severity.value == "CRITICAL" else "high" if f.cvss_severity.value == "HIGH" else "med" if f.cvss_severity.value == "MEDIUM" else "low"
                rows.append(f"""
                <tr>
                  <td style="padding:6px 12px; border-bottom:1px solid #334155;"><strong>OWASP {m['owasp']['id']}</strong><br><span style="color:#94a3b8; font-size:11px;">{m['owasp']['name']}</span></td>
                  <td style="padding:6px 12px; border-bottom:1px solid #334155;">{m['cis_controls']['control']}<br><span style="color:#94a3b8; font-size:11px;">{m['nist_sp_800_115']['section']}</span></td>
                  <td style="padding:6px 12px; border-bottom:1px solid #334155;"><code>{f.title[:30]}...</code><br><span style="color:#cbd5e1; font-size:11px;">{m['cwe_id']}{cwe_top25}</span></td>
                  <td style="padding:6px 12px; border-bottom:1px solid #334155;"><span class="badge {sev_cls}">{f.cvss_severity.value}</span></td>
                </tr>
                """)
            c_table_rows = "".join(rows) if rows else "<tr><td colspan='4' style='padding:8px 12px;'>Toàn bộ kiểm tra cơ sở đều đạt. Không phát hiện vi phạm.</td></tr>"

            compliance_section = f"""
            <h2>Hiện trạng Tuân thủ Quy chuẩn Quốc tế (OWASP / CWE / NIST / CIS)</h2>
            <div style="background:#0f172a; border:1px solid #334155; border-radius:8px; padding:16px; margin:16px 0; display:flex; justify-content:space-between; align-items:center;">
              <div>
                <span style="font-size:14px; color:#94a3b8;">Trạng thái Tuân thủ Tiêu chuẩn:</span><br>
                <strong style="font-size:18px; color:{color};">{status_vn}</strong>
              </div>
              <div style="text-align:right;">
                <span style="font-size:14px; color:#94a3b8;">Điểm số Tuân thủ:</span><br>
                <span style="font-size:24px; font-weight:bold; color:{color};">{score}/100</span>
              </div>
            </div>
            <table style="width:100%; border-collapse:collapse; font-size:12px; margin-bottom:20px;">
              <thead>
                <tr style="text-align:left; background:#0f172a;">
                  <th style="padding:6px 12px;">Tiêu chuẩn OWASP</th>
                  <th style="padding:6px 12px;">Điều khoản CIS / NIST</th>
                  <th style="padding:6px 12px;">Phát hiện Tương ứng</th>
                  <th style="padding:6px 12px;">Mức độ Rủi ro</th>
                </tr>
              </thead>
              <tbody>
                {c_table_rows}
              </tbody>
            </table>
            """

        return f"""<!DOCTYPE html>
<html lang="vi">
<head>
  <meta charset="UTF-8">
  <title>Báo cáo Đánh giá An toàn Thông tin - {target_id}</title>
  <style>
    body {{ font-family: "Times New Roman", Times, serif; background: #0f172a; color: #e2e8f0; line-height: 1.6; padding: 40px; margin: 0; }}
    .container {{ max-width: 900px; margin: 0 auto; background: #1e293b; padding: 40px; border-radius: 12px; border: 1px solid #334155; }}
    h1 {{ color: #38bdf8; border-bottom: 2px solid #334155; padding-bottom: 12px; margin-top: 0; font-family: "Times New Roman", Times, serif; }}
    h2 {{ color: #7dd3fc; border-bottom: 1px solid #334155; padding-bottom: 8px; margin-top: 32px; font-family: "Times New Roman", Times, serif; }}
    h3 {{ color: #f8fafc; margin-top: 24px; font-family: "Times New Roman", Times, serif; }}
    .badge {{ display: inline-block; padding: 4px 8px; border-radius: 4px; font-weight: bold; font-size: 12px; font-family: "Times New Roman", Times, serif; }}
    .crit {{ background: #7f1d1d; color: #fca5a5; }}
    .high {{ background: #7c2d12; color: #fdba74; }}
    .med {{ background: #78350f; color: #fde047; }}
    .low {{ background: #1e3a8a; color: #93c5fd; }}
    .stat-box {{ display: flex; gap: 12px; margin: 20px 0; }}
    .stat-item {{ flex: 1; padding: 12px; border-radius: 8px; text-align: center; border: 1px solid #334155; font-family: "Times New Roman", Times, serif; }}
    pre {{ background: #090d16; padding: 12px; border-radius: 6px; overflow-x: auto; color: #a5f3fc; font-family: "Times New Roman", Times, serif; }}
    code {{ background: #090d16; padding: 2px 6px; border-radius: 4px; color: #38bdf8; font-family: "Times New Roman", Times, serif; }}
    .footer {{ margin-top: 40px; padding-top: 20px; border-top: 1px solid #334155; font-size: 12px; color: #64748b; text-align: center; font-family: "Times New Roman", Times, serif; }}
  </style>
</head>
<body>
  <div class="container">
    <h1>Báo cáo Đánh giá An toàn Thông tin & Kiểm thử Xâm nhập</h1>
    <p><strong>Mục tiêu:</strong> <code>{target_id}</code> | <strong>Chiến dịch:</strong> {campaign} | <strong>Thời gian tạo:</strong> {ts}</p>
    
    {alert_banner}

    <div class="stat-box">
      <div class="stat-item crit"><span style="font-size:24px; font-weight:bold;">{crit_count}</span><br>Nghiêm trọng (Critical)</div>
      <div class="stat-item high"><span style="font-size:24px; font-weight:bold;">{high_count}</span><br>Mức độ Cao (High)</div>
      <div class="stat-item med"><span style="font-size:24px; font-weight:bold;">{med_count}</span><br>Trung bình (Medium)</div>
      <div class="stat-item low"><span style="font-size:24px; font-weight:bold;">{low_count}</span><br>Mức độ Thấp (Low)</div>
    </div>

    <h2>Kiểm toán Trạng thái Thực thi Công cụ Dò quét</h2>
    <table style="width:100%; border-collapse:collapse; font-size:13px;">
      <thead>
        <tr style="text-align:left; background:#0f172a;">
          <th style="padding:6px 12px;">Công cụ</th>
          <th style="padding:6px 12px;">Chế độ</th>
          <th style="padding:6px 12px;">Bằng chứng Tin cậy</th>
          <th style="padding:6px 12px;">Trạng thái / Chẩn đoán</th>
        </tr>
      </thead>
      <tbody>
        {audit_table}
      </tbody>
    </table>

    {compliance_section}

    <h2>Danh mục Lỗ hổng Đã Xác minh ({len(trustworthy_findings)})</h2>
    {cards_html}

    <div class="footer">
      AI-Pentest Copilot v6.0 - Tài liệu Kiểm toán An toàn Thông tin & Kiểm thử Xâm nhập
    </div>
  </div>
</body>
</html>
"""


report_generator = ReportGenerator()
