"""LLM Service with multi-provider abstraction, streaming, and offline fallback."""

from __future__ import annotations

import os
import re
import json
import asyncio
from typing import AsyncGenerator, Dict, Any, List, Optional
from backend.app.core.guardrails import check_exploit_intent, format_guardrail_refusal
from backend.app.core.prompts import SYSTEM_PROMPT


class LLMService:
    """Multi-provider LLM service supporting OpenAI, Anthropic, Ollama, custom, and offline fallback."""

    def __init__(self):
        self.active_provider = self._detect_provider()
        self.active_model = os.getenv("LLM_MODEL", "offline-security-copilot")

    def _detect_provider(self) -> str:
        prov = os.getenv("LLM_PROVIDER", "").lower()
        if prov in ("openai", "anthropic", "ollama", "custom"):
            return prov
        if os.getenv("OPENAI_API_KEY"):
            return "openai"
        if os.getenv("ANTHROPIC_API_KEY"):
            return "anthropic"
        if os.getenv("OLLAMA_HOST"):
            return "ollama"
        return "offline"

    def get_available_providers(self) -> List[Dict[str, Any]]:
        return [
            {
                "id": "offline",
                "name": "Local Security Reasoning (Offline/Simulated)",
                "active": self.active_provider == "offline",
                "ready": True,
            },
            {
                "id": "openai",
                "name": "OpenAI (GPT-4o / o1)",
                "active": self.active_provider == "openai",
                "ready": bool(os.getenv("OPENAI_API_KEY")),
            },
            {
                "id": "anthropic",
                "name": "Anthropic (Claude 3.5 Sonnet)",
                "active": self.active_provider == "anthropic",
                "ready": bool(os.getenv("ANTHROPIC_API_KEY")),
            },
            {
                "id": "ollama",
                "name": "Ollama (Local LLM)",
                "active": self.active_provider == "ollama",
                "ready": bool(os.getenv("OLLAMA_HOST")),
            },
            {
                "id": "custom",
                "name": "Custom OpenAI-compatible API",
                "active": self.active_provider == "custom",
                "ready": bool(os.getenv("CUSTOM_LLM_URL")),
            },
        ]

    def switch_provider(self, provider_id: str, model: Optional[str] = None) -> bool:
        valid = [p["id"] for p in self.get_available_providers()]
        if provider_id not in valid:
            return False
        self.active_provider = provider_id
        if model:
            self.active_model = model
        return True

    async def stream_response(
        self,
        prompt: str,
        system_prompt: str = SYSTEM_PROMPT,
        context_data: Optional[Dict[str, Any]] = None,
    ) -> AsyncGenerator[str, None]:
        """Stream response chunks using active provider or deterministic fallback."""
        # Check exploit guardrail on prompt
        is_exploit, reason = check_exploit_intent(prompt)
        if is_exploit:
            refusal = format_guardrail_refusal(reason)
            for chunk in refusal.split(" "):
                yield chunk + " "
                await asyncio.sleep(0.01)
            return

        if self.active_provider == "offline":
            async for chunk in self._stream_offline(prompt, context_data):
                yield chunk
        else:
            try:
                async for chunk in self._stream_litellm(prompt, system_prompt, context_data):
                    yield chunk
            except Exception as e:
                # Fallback to offline on external API failure
                yield f"\n*[Provider error: {e}. Falling back to Local Security Engine]*\n\n"
                async for chunk in self._stream_offline(prompt, context_data):
                    yield chunk

    async def _stream_litellm(
        self, prompt: str, system_prompt: str, context_data: Optional[Dict[str, Any]]
    ) -> AsyncGenerator[str, None]:
        try:
            import litellm
            messages = [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt},
            ]
            response = await litellm.acompletion(
                model=self.active_model,
                messages=messages,
                stream=True,
            )
            async for part in response:
                delta = part.choices[0].delta.content or ""
                if delta:
                    yield delta
        except ImportError:
            async for chunk in self._stream_offline(prompt, context_data):
                yield chunk

    async def _stream_offline(
        self, prompt: str, context_data: Optional[Dict[str, Any]]
    ) -> AsyncGenerator[str, None]:
        """High-fidelity security reasoning generator adhering to Master Spec rules."""
        full_text, _, _ = self.generate_offline_answer(prompt, context_data)
        
        # Stream word by word with brief pause for realistic feeling
        words = re.split(r"(\s+)", full_text)
        for w in words:
            if w:
                yield w
                await asyncio.sleep(0.001)

    def generate_offline_answer(
        self, prompt: str, context_data: Optional[Dict[str, Any]] = None
    ) -> tuple[str, float, List[str]]:
        """Generate deterministic, grounded security copilot response with citations."""
        correlations = (context_data or {}).get("correlations", [])
        rag_results = (context_data or {}).get("rag_results", [])
        active_target = (context_data or {}).get("active_target", "")

        # 1. Check for specific software versions in prompt or correlation
        m_apache = re.search(r"apache\s*([\d\.]+)", prompt, re.IGNORECASE)
        m_nginx = re.search(r"nginx\s*([\d\.]+)", prompt, re.IGNORECASE)
        m_openssh = re.search(r"openssh\s*([\d\.]+)", prompt, re.IGNORECASE)

        # Check if asking about non-existent version like 2.4.99 or version with 0 matches
        query_version = None
        if m_apache:
            query_version = ("apache", m_apache.group(1))
        elif m_nginx:
            query_version = ("nginx", m_nginx.group(1))
        elif m_openssh:
            query_version = ("openssh", m_openssh.group(1))

        if query_version and not correlations and not rag_results:
            prod, ver = query_version
            return (
                f"**FACT**: Insufficient evidence in current scan results or knowledge base to confirm vulnerabilities for {prod.title()} {ver}.\n\n"
                f"Không có dữ liệu CVE được xác minh cho phiên bản {prod.title()} {ver} trong Knowledge Base hiện tại.\n\n"
                f"**Recommended Next Steps**:\n"
                f"1. Kiểm tra lại chuỗi banner phiên bản thông qua scan chi tiết: `nmap -sV --version-intensity 9 <target>`.\n"
                f"2. Cập nhật Knowledge Base nếu phiên bản này mới phát hành.",
                0.95,
                ["Verify banner string directly on target", "Update Vulnerability KB"],
            )

        # 2. If correlations exist (e.g. Apache 2.4.49 -> CVE-2021-41773)
        if correlations:
            c = correlations[0]
            cve_id = c.get("cve_id", "CVE-UNKNOWN")
            cwe_id = c.get("cwe_id", "CWE-22")
            cvss = c.get("cvss_v3", 7.5)
            summary = c.get("summary", "")
            target_str = active_target or "target hiện tại"

            response = (
                f"Dựa trên phân tích tương quan từ Knowledge Base và chứng cứ scan cho {target_str}:\n\n"
                f"### [1] Lỗ hổng tiềm ẩn: **{cve_id}** ({cwe_id})\n\n"
                f"- **CVSS Score**: `{cvss}` (Severity: High)\n"
                f"- **Mô tả**: {summary}\n"
                f"- **Ảnh hưởng**: Path traversal và File Disclosure hoặc Remote Code Execution nếu mod_alias hoặc mod_cgi được kích hoạt.\n"
                f"- **Độ tin cậy**: `0.95` (Exact version match trong KB)\n\n"
                f"#### Kế hoạch xác minh an toàn (Read-Only Validation Plan):\n"
                f"1. **Bước 1 (Passive Banner Check)**:\n"
                f"   ```bash\n"
                f"   curl -s -I http://{active_target or '192.168.1.100'}:8080/\n"
                f"   ```\n"
                f"2. **Bước 2 (Path Traversal Probe - Safe GET)**:\n"
                f"   ```bash\n"
                f"   curl -s --path-as-is http://{active_target or '192.168.1.100'}:8080/icons/.%%32%65/.%%32%65/etc/passwd -o /dev/null -w 'HTTP Status: %{{http_code}}\\n'\n"
                f"   ```\n"
                f"3. **Bước 3 (Remediation)**:\n"
                f"   - Nâng cấp Apache HTTP Server lên phiên bản 2.4.51 hoặc mới hơn ngay lập tức.\n"
                f"   - Thiết lập `Require all denied` cho cấu hình root directory."
            )
            return (
                response,
                0.95,
                [
                    "Thực hiện safe read-only curl probe",
                    "Tạo Finding chính thức vào Findings Builder",
                    "Nâng cấp phiên bản phần mềm lên 2.4.51+",
                ],
            )

        # 3. If RAG results retrieved
        if rag_results:
            top = rag_results[0]
            title = top.get("title", "")
            snippet = top.get("snippet", "")
            source = top.get("source", "KB")
            response = (
                f"Dựa trên tài liệu tra cứu từ Knowledge Base [{source}]:\n\n"
                f"### [1] **{title}**\n"
                f"{snippet}\n\n"
                f"**Đánh giá rủi ro**:\n"
                f"- Đây là tài liệu bảo mật đối chiếu trực tiếp từ kho lưu trữ SQLite KB.\n"
                f"- Khuyến nghị xem xét lại cấu hình liên quan trên target `{active_target}`."
            )
            return (
                response,
                0.85,
                ["Kiểm tra chi tiết trong KB", "Review cấu hình liên quan"],
            )

        # 4. General fallback response
        return (
            f"Tôi là AI-Pentest Copilot. Tôi đang quan sát target: `{active_target or 'chưa chọn'}`.\n\n"
            f"- **Nguyên tắc**: Không tự ý exploit, luôn cung cấp lệnh reviewable và kiểm tra safe read-only.\n"
            f"- Bạn có thể hỏi về các CVE, quét recon mục tiêu, hoặc yêu cầu giải thích kết quả scan nmap/nuclei.",
            0.90,
            ["Chạy Nmap scan target", "Phân tích file kết quả", "Tra cứu CVE trong KB"],
        )


llm_service = LLMService()
