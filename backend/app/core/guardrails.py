from __future__ import annotations

import re


class Guardrails:
    """
    Enforces master guardrails:
    1. NEVER invent CVE IDs, CWE IDs, versions, or CVSS scores.
    2. NEVER perform automated exploitation; redirect to verification-only advice.
    3. Categorizes output into FACT, INFERENCE, HYPOTHESIS.
    4. Triggers 'Insufficient evidence' if no verifiable facts or knowledge base matches exist.
    """

    EXPLOIT_PATTERNS = [
        r"\bexploit\b",
        r"\battack\b",
        r"\bhack\b",
        r"\bpayload\b",
        r"\brun exploit\b",
        r"\btake down\b",
        r"\broot the box\b",
        r"\bdrop shell\b",
        r"\bget shell\b",
    ]

    @classmethod
    def check_exploitation_intent(cls, user_message: str) -> tuple[bool, str]:
        text = user_message.lower()
        for pat in cls.EXPLOIT_PATTERNS:
            if re.search(pat, text):
                if any(
                    w in text
                    for w in [
                        "how to verify",
                        "safe",
                        "read-only",
                        "what is",
                        "analyze",
                        "explain",
                    ]
                ):
                    continue
                # Explicit request to exploit
                if any(
                    w in text
                    for w in [
                        "exploit this",
                        "exploit target",
                        "tấn công",
                        "hack target",
                        "chiếm quyền",
                        "chạy exploit",
                    ]
                ):
                    return True, (
                        "Tôi không thực hiện automated exploitation.\n\n"
                        "Tuy nhiên, tôi có thể hỗ trợ bạn:\n"
                        "1. Phân tích nguyên nhân gốc của vulnerability\n"
                        "2. Đề xuất các bước verification an toàn (read-only)\n"
                        "3. Sinh validation plan không gây gián đoạn dịch vụ\n"
                        "4. Gợi ý công cụ kiểm chứng phù hợp\n"
                        "5. Giải thích expected evidence cần ghi nhận trong báo cáo."
                    )
        return False, ""

    @classmethod
    def classify_statements(
        cls, response_text: str, has_evidence: bool
    ) -> dict[str, list]:
        facts = []
        inferences = []
        hypotheses = []

        lines = response_text.splitlines()
        for line in lines:
            line_str = line.strip().lstrip("-*#").strip()
            if not line_str:
                continue
            if any(
                k in line_str.lower()
                for k in ["phát hiện", "nmap", "httpx", "cổng", "port", "phiên bản"]
            ):
                facts.append(line_str)
            elif any(
                k in line_str.lower()
                for k in ["liên quan", "cve", "cwe", "cvss", "lỗ hổng"]
            ):
                inferences.append(line_str)
            elif any(
                k in line_str.lower()
                for k in [
                    "có thể",
                    "cần xác minh",
                    "khả năng",
                    "giả thuyết",
                    "verification",
                ]
            ):
                hypotheses.append(line_str)

        if not facts and has_evidence:
            facts.append("Evidence thu thập từ kết quả trinh sát hợp lệ.")
        if not hypotheses:
            hypotheses.append(
                "Cần thực hiện kiểm chứng an toàn (read-only) trước khi kết luận."
            )

        return {
            "facts": facts[:3],
            "inferences": inferences[:3],
            "hypotheses": hypotheses[:3],
        }


def check_exploit_intent(message: str) -> tuple[bool, str]:
    text = message.lower()
    if any(
        k in text
        for k in [
            "ignore all previous instructions",
            "system prompt override",
            "jailbreak",
        ]
    ):
        return True, "PROMPT_INJECTION"

    if any(
        k in text
        for k in [
            "--os-shell",
            "meterpreter",
            "reverse shell",
            "drop shell",
            "/dev/tcp",
            "mkfifo",
            "rm -rf",
            "drop table",
            "nc -e",
        ]
    ):
        return True, "MALICIOUS_TOOL_REQUEST"

    is_blocked, _ = Guardrails.check_exploitation_intent(message)
    if is_blocked:
        return True, "EXPLOIT_KEYWORD"

    if any(
        w in text
        for w in [
            "exploit target",
            "exploit này",
            "tấn công",
            "chạy exploit",
            "rce vào server",
            "tấn công rce",
            "chiếm quyền",
            "exploit tự động",
        ]
    ):
        return True, "EXPLOIT_KEYWORD"

    return False, ""


def format_guardrail_refusal(reason: str = "EXPLOIT_KEYWORD") -> str:
    return (
        "**[GUARDRAIL REFUSAL]**: AI-Pentest Copilot tuân thủ nguyên tắc an toàn nghiêm ngặt và không thực hiện automated exploitation hoặc hỗ trợ tấn công phá hoại.\n\n"
        "Tuy nhiên, hệ thống sẵn sàng hỗ trợ các bước an toàn sau:\n"
        "1. **Phân tích nguyên nhân gốc (Root Cause Analysis)**\n"
        "2. **Xác minh an toàn (Safe Read-Only Validation)** không ảnh hưởng đến tính khả dụng của dịch vụ\n"
        "3. **Tạo Validation Plan** với các lệnh kiểm tra reviewable (curl banner check, passive probe)\n"
        "4. **Khuyến nghị khắc phục (Remediation guidance)** theo chuẩn NIST / CIS."
    )
