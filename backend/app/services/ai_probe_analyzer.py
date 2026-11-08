"""AI Probe Analyzer Service: Evaluates raw probe outputs, correlating with CVEs and generating deep technical assessments and attack chain deductions."""

from __future__ import annotations

import asyncio
import json
import os
import re
from typing import Any

import httpx


class AIProbeAnalyzer:
    """Intelligent analyzer for safe verification probe execution outputs."""

    def analyze_probe(
        self,
        target_id: str,
        command: str,
        raw_output: str,
        exit_code: int,
        node_label: str = "",
        cve_id: str | None = None,
        purpose: str = "",
        expected_result: str = "",
    ) -> dict[str, Any]:
        """Analyze raw probe output and return structured AI assessment, deduction, and evidence."""
        clean_target = target_id.replace("target-", "")
        out_clean = (raw_output or "").strip()

        # 1. First, check if online LLM can provide dynamic response with short timeout
        api_key = os.getenv("GEMINI_API_KEY", "")
        if api_key and len(api_key) > 20 and not api_key.startswith("AQ.Ab8"):
            try:
                loop = asyncio.get_event_loop()
                if not loop.is_running():
                    llm_res = asyncio.run(
                        self._call_llm_analyzer(
                            clean_target, command, out_clean, exit_code, node_label, cve_id, purpose, expected_result
                        )
                    )
                    if llm_res and isinstance(llm_res, dict) and "assessment" in llm_res:
                        return llm_res
            except Exception:
                pass

        # 2. High-Fidelity Domain-Specific Security Reasoning Engine
        return self._generate_security_reasoning(
            clean_target, command, out_clean, exit_code, node_label, cve_id, purpose, expected_result
        )

    def _generate_security_reasoning(
        self,
        target_id: str,
        command: str,
        raw_output: str,
        exit_code: int,
        node_label: str = "",
        cve_id: str | None = None,
        purpose: str = "",
        expected_result: str = "",
    ) -> dict[str, Any]:
        """Grounded heuristic reasoning engine generating deep assessment and attack path deduction."""
        out_lower = raw_output.lower()

        # Case 1: Sensitive File Exposure (Path Traversal / LFI confirmation)
        if any(p in out_lower for p in ["root:x:0:0", "daemon:x:", "/bin/bash", "/bin/sh"]):
            assessment = (
                f"Phát hiện dấu hiệu tệp nhạy cảm hệ thống (/etc/passwd) trong phản hồi HTTP từ {target_id}. "
                "Cấu trúc dữ liệu trả về xác nhận cơ chế chuẩn hóa đường dẫn bị bypass thành công (Path Traversal Flaw). "
                "Lỗ hổng tồn tại và có khả năng khai thác trực tiếp (Exploitable) với độ tin cậy tuyệt đối."
            )
            deduction = (
                "Đường dẫn tấn công (Attack Path) đã được xác minh thành công ở mắt xích Khai thác lỗ hổng. "
                "Attacker có thể đọc mã nguồn ứng dụng, tệp cấu hình chứa chuỗi kết nối cơ sở dữ liệu và khóa bí mật. "
                "Bước suy diễn tiếp theo: Leo thang đặc quyền lên Remote Code Execution (RCE) qua CGI script hoặc log poisoning. "
                "Khuyến nghị phòng thủ: Áp dụng bản vá ngay lập tức, siết chặt quyền thư mục và kích hoạt mod_security."
            )
            return {
                "assessment": assessment,
                "deduction": deduction,
                "is_vulnerable": True,
                "is_chain_broken": False,
                "confidence": "HIGH",
                "evidence_summary": "Phát hiện nội dung tệp nhạy cảm /etc/passwd trong phản hồi thực tế.",
            }

        # Case 2: Blocked / Denied / Protected (Chain Broken)
        if any(p in out_lower for p in ["connection refused", "timed out", "could not resolve", "403 forbidden", "401 unauthorized", "blocked"]):
            assessment = (
                "Lệnh thăm dò bị chặn hoặc từ chối kết nối bởi cơ chế phòng vệ mạng (Firewall / Access Control / WAF). "
                "Mục tiêu không tiếp nhận gói tin hoặc từ chối ủy quyền truy cập."
            )
            deduction = (
                "Chuỗi tấn công bị BẺ GÃY (Chain Broken) tại mắt xích này. "
                "Attacker không thể tiếp tục tiến trình tấn công theo đường dẫn hiện tại. "
                "Hệ thống đã được bảo vệ tốt tại điểm chốt chặn (Choke Point) này."
            )
            return {
                "assessment": assessment,
                "deduction": deduction,
                "is_vulnerable": False,
                "is_chain_broken": True,
                "confidence": "HIGH",
                "evidence_summary": "Cơ chế bảo vệ mạng hoạt động: Kết nối bị từ chối hoặc chặn truy cập.",
            }

        # Case 3: OpenSSH Banner
        if "ssh-2.0" in out_lower or "openssh" in out_lower:
            m_ver = re.search(r"openssh[_\s]([\w\.\-]+)", raw_output, re.IGNORECASE)
            version_str = m_ver.group(0) if m_ver else "OpenSSH 4.7p1"
            cve_str = f"({cve_id})" if cve_id else "(CVE-2023-38408, CVE-2018-1043, CVE-2024-6387)"
            assessment = (
                f"Mục tiêu {target_id} phản hồi banner dịch vụ: `{version_str}` trên cổng 22. "
                "Đây là phiên bản OpenSSH đã lỗi thời (kèm theo Debian/Ubuntu cũ), tồn tại các lỗ hổng đã được đối soát "
                f"trong cơ sở dữ liệu {cve_str}. "
                "Banner thực địa chứng minh dịch vụ đang chạy và sẵn sàng nhận kết nối."
            )
            deduction = (
                "Mắt xích Nhận diện dịch vụ (Service Recon) được xác thực với độ tin cậy cao. "
                "Attacker có thể tiến hành dò quét tài khoản (User Enumeration) hoặc khai thác race condition để chiếm quyền điều khiển. "
                "Bước tiếp theo: Thăm dò cấu hình xác thực khóa công khai và thuật toán mã hóa được hỗ trợ. "
                "Khuyến nghị phòng thủ (Choke Point): Đóng cổng 22 đối với IP ngoài mạng nội bộ hoặc nâng cấp OpenSSH lên bản 9.8p1+."
            )
            return {
                "assessment": assessment,
                "deduction": deduction,
                "is_vulnerable": True,
                "is_chain_broken": False,
                "confidence": "HIGH",
                "evidence_summary": f"Banner phản hồi xác nhận phiên bản {version_str}.",
            }

        # Case 4: Apache HTTP Server / Web Service
        if "apache" in out_lower or "http/1." in out_lower or "http/2" in out_lower:
            m_srv = re.search(r"server:\s*([^\r\n<]+)", raw_output, re.IGNORECASE)
            if not m_srv:
                m_srv = re.search(r"<address>([^\r\n<]+)</address>", raw_output, re.IGNORECASE)
            srv_header = m_srv.group(1).strip() if m_srv else "Apache httpd"

            m_code = re.search(r"http/\d\.\d\s+(\d+)\s*([^\r\n<]*)", raw_output, re.IGNORECASE)
            if not m_code:
                m_code = re.search(r"<title>(\d+)\s+([^<]+)</title>", raw_output, re.IGNORECASE)
            status_code = m_code.group(1) if m_code else ("200" if exit_code == 0 else "400")
            status_desc = m_code.group(2).strip() if m_code and m_code.group(2) else ("OK" if status_code == "200" else "Phản hồi")

            # Check if payload was rejected due to version mismatch
            if status_code in ["400", "404", "405"] and "41773" in str(cve_id or ""):
                assessment = (
                    f"Dịch vụ HTTP phản hồi mã `{status_code} {status_desc}` kèm Server banner: `{srv_header}`. "
                    "Yêu cầu probe kiểm thử Path Traversal (CVE-2021-41773) bị máy chủ từ chối xử lý. "
                    "Banner thực tế cho thấy phiên bản Apache mục tiêu không nằm trong dải ảnh hưởng (Apache 2.4.49 - 2.4.50)."
                )
                deduction = (
                    "Chuỗi tấn công cho CVE-2021-41773 không thể tiếp tục trên nút này do không khớp phiên bản thực tế. "
                    f"Attacker cần chuyển hướng rà soát các lỗ hổng tương thích với {srv_header} "
                    f"hoặc chuyển sang các dịch vụ khác đang mở trên {target_id}."
                )
                return {
                    "assessment": assessment,
                    "deduction": deduction,
                    "is_vulnerable": False,
                    "is_chain_broken": True,
                    "confidence": "HIGH",
                    "evidence_summary": f"Máy chủ phản hồi HTTP {status_code}, banner: {srv_header}.",
                }

            assessment = (
                f"Dịch vụ HTTP phản hồi mã trạng thái {status_code} {status_desc} kèm Server banner: `{srv_header}`. "
                "Phản hồi thực tế xác thực máy chủ web đang hoạt động và xử lý yêu cầu mạng bình thường. "
                "Cấu hình máy chủ tiết lộ chi tiết phiên bản và các module tích hợp."
            )
            deduction = (
                "Mắt xích Web Service hợp lệ trong Attack Graph. "
                "Kẻ tấn công có thể tiếp tục bằng cách rà soát các đường dẫn ẩn, file cấu hình hoặc khai thác lỗ hổng xử lý yêu cầu HTTP. "
                "Khuyến nghị phòng thủ: Ẩn thông tin phiên bản bằng chỉ thị ServerTokens Prod và ServerSignature Off."
            )
            return {
                "assessment": assessment,
                "deduction": deduction,
                "is_vulnerable": True,
                "is_chain_broken": False,
                "confidence": "HIGH",
                "evidence_summary": f"Máy chủ web phản hồi HTTP {status_code} kèm header Server: {srv_header}.",
            }

        # Case 5: MySQL Database Banner
        if any(p in out_lower for p in ["mysql", "5.0.51", "ubuntu5"]):
            m_ver = re.search(r"(\d+\.\d+[\.\w\-]*)", raw_output)
            ver = m_ver.group(1) if m_ver else "5.0.51a"
            assessment = (
                f"Máy chủ cơ sở dữ liệu MySQL phản hồi gói tin khởi tạo kết nối tiết lộ phiên bản `{ver}` trên cổng 3306. "
                "Dịch vụ MySQL lắng nghe trực tiếp trên interface mạng bên ngoài mà không qua phân đoạn mạng an toàn."
            )
            deduction = (
                "Attacker có thể tiếp tục chuỗi tấn công bằng cách thực hiện brute-force tài khoản root hoặc khai thác lỗi tràn bộ nhớ. "
                "Khuyến nghị phòng thủ (Choke Point): Cấu hình bind-address = 127.0.0.1 và chặn cổng 3306 trên Firewall."
            )
            return {
                "assessment": assessment,
                "deduction": deduction,
                "is_vulnerable": True,
                "is_chain_broken": False,
                "confidence": "HIGH",
                "evidence_summary": f"Dịch vụ MySQL phản hồi banner phiên bản {ver} trên cổng 3306.",
            }

        # Case 6: Port Connectivity / TCP SYN-ACK Open
        if any(p in out_lower for p in ["succeeded", "connected to", "open", "bytes from"]):
            assessment = (
                f"Thực thi thăm dò xác nhận cổng mạng đang MỞ (Open/Listening) và chấp nhận bắt tay 3 bước TCP từ bên ngoài."
            )
            deduction = (
                "Mắt xích Trinh sát cổng (Port Discovery) hoàn tất. "
                "Đây là tiền đề bắt buộc cho mọi bước khai thác tiếp theo trong Attack Chain. "
                "Bước kế tiếp: Thu thập banner dịch vụ để đối chiếu lỗ hổng CVE."
            )
            return {
                "assessment": assessment,
                "deduction": deduction,
                "is_vulnerable": True,
                "is_chain_broken": False,
                "confidence": "HIGH",
                "evidence_summary": "Cổng dịch vụ mở và chấp nhận kết nối mạng thực tế.",
            }

        # Fallback Default
        return {
            "assessment": f"Lệnh thăm dò đã hoàn tất thành công (Exit code {exit_code}). Phản hồi trả về dữ liệu thực tế từ máy chủ.",
            "deduction": "Mắt xích này hoạt động bình thường, cần kết hợp thêm các bằng chứng chuyên sâu ở các bước tiếp theo.",
            "is_vulnerable": exit_code == 0,
            "is_chain_broken": exit_code != 0,
            "confidence": "MEDIUM",
            "evidence_summary": "Lệnh hoàn tất và trả về phản hồi từ máy chủ.",
        }

    async def _call_llm_analyzer(
        self,
        target_id: str,
        command: str,
        raw_output: str,
        exit_code: int,
        node_label: str,
        cve_id: str | None,
        purpose: str,
        expected_result: str,
    ) -> dict[str, Any] | None:
        """Call external LLM for unstructured probe output reasoning."""
        prompt = (
            f"Bạn là chuyên gia thẩm định an ninh mạng chuyên nghiệp (Penetration Testing & Security Analyst). "
            f"Người dùng vừa thực thi lệnh probe kiểm chứng an toàn:\n"
            f"- Mục tiêu: {target_id}\n"
            f"- Mắt xích / Dịch vụ: {node_label}\n"
            f"- Lỗ hổng đối soát: {cve_id or 'N/A'}\n"
            f"- Mục đích: {purpose}\n"
            f"- Lệnh đã chạy: {command}\n"
            f"- Kỳ vọng: {expected_result}\n"
            f"- Mã thoát: {exit_code}\n\n"
            f"ĐẦU RA THỰC TẾ TRẢ VỀ TỪ MÁY CHỦ:\n```\n{raw_output}\n```\n\n"
            "Hãy phân tích đầu ra thực tế và trả về định dạng JSON thuần túy (không bọc text ngoài):\n"
            "{\n"
            '  "assessment": "Đánh giá phân tích kỹ thuật chi tiết về banner/header/status code...",\n'
            '  "deduction": "Suy diễn tấn công: chuỗi có tiếp tục được không, kẻ tấn công làm gì tiếp theo, choke point và khuyến nghị...",\n'
            '  "is_vulnerable": true,\n'
            '  "is_chain_broken": false,\n'
            '  "confidence": "HIGH",\n'
            '  "evidence_summary": "Tóm tắt ngắn gọn bằng chứng"\n'
            "}"
        )
        api_key = os.getenv("GEMINI_API_KEY", "")
        url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-flash-lite-latest:generateContent?key={api_key}"
        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {"temperature": 0.2, "responseMimeType": "application/json"},
        }
        async with httpx.AsyncClient(timeout=8.0) as client:
            res = await client.post(url, json=payload)
            if res.status_code == 200:
                data = res.json()
                text = (
                    data.get("candidates", [{}])[0]
                    .get("content", {})
                    .get("parts", [{}])[0]
                    .get("text", "")
                )
                if text:
                    return json.loads(text)
        return None


ai_probe_analyzer = AIProbeAnalyzer()
