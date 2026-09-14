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
      4. Current scan evidence
      5. Correlator candidates
      6. RAG knowledge sources
      7. Conversation history
    """

    @classmethod
    def extract_product_and_version(cls, text: str) -> tuple[Optional[str], Optional[str]]:
        # Check patterns like 'Apache 2.4.49', 'OpenSSH 8.2p1', 'nginx 1.20'
        match = re.search(r"\b(apache|openssh|nginx|node\.js|nodejs|express|php|mysql|redis|log4j|spring)\b[\s/]*([0-9]+[0-9a-zA-Z._-]*)?", text, re.IGNORECASE)
        if match:
            prod = match.group(1)
            ver = match.group(2) if match.group(2) else None
            return prod, ver
        return None, None

    @classmethod
    def build(
        cls,
        user_message: str,
        active_target: Optional[dict] = None,
        active_file_path: Optional[str] = None,
        conversation_id: Optional[str] = None,
    ) -> ContextData:
        root_dir = pathlib.Path(__file__).resolve().parent.parent.parent.parent

        # 1. Read Active File
        active_file_data = None
        if active_file_path:
            clean_rel = active_file_path.lstrip("/\\")
            candidates = [
                root_dir / clean_rel,
                root_dir / "toolkit" / clean_rel,
                root_dir / "toolkit" / "03-network" / clean_rel,
            ]
            file_disk = next((p for p in candidates if p.exists() and p.is_file()), None)
            if file_disk:
                try:
                    content_str = file_disk.read_text(encoding="utf-8", errors="replace")
                    if len(content_str) > 6000:
                        content_str = content_str[:6000] + "...\n[TRUNCATED]"
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

        # 2. Correlator Check
        correlator_candidates = []
        prod, ver = cls.extract_product_and_version(user_message)
        # If not in query, check active file content
        if not prod and active_file_data:
            prod, ver = cls.extract_product_and_version(active_file_data["content"])
        if prod:
            cands = Correlator.correlate(product=prod, version=ver, limit=5)
            correlator_candidates = [c.model_dump() for c in cands]

        # 3. RAG Retrieval
        rag_query = user_message
        if prod and ver:
            rag_query = f"{prod} {ver} {user_message}"
        rag_sources = RAGService.retrieve(rag_query, top_k=5)

        # 4. Conversation History (Last 10 messages)
        conv_history = []
        if conversation_id:
            conv_history = chat_db.get_messages(conversation_id, limit=10)

        return ContextData(
            user_message=user_message,
            active_target=active_target,
            active_file=active_file_data,
            recent_scans=[],
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
                f"### ACTIVE TARGET\n"
                f"- Name: {ctx.active_target.get('name')}\n"
                f"- Host: {ctx.active_target.get('host')}\n"
                f"- Type: {ctx.active_target.get('type')}\n"
                f"- Environment: {ctx.active_target.get('environment', 'lab')}"
            )

        # Active File section
        if ctx.active_file:
            context_parts.append(
                f"### ACTIVE FILE EVIDENCE ({ctx.active_file['name']})\n"
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

        # Format sources
        sources = []
        # Correlated CVEs
        for c in ctx_data.correlator_candidates:
            sources.append({
                "source": "NVD / CVE KB",
                "title": f"{c.get('cve_id')} (CVSS {c.get('cvss_score', 'N/A')})",
                "score": c.get("confidence", 0.95),
                "snippet": c.get("description", "")[:180],
                "url": c.get("source_url", "https://nvd.nist.gov"),
            })
        # RAG sources
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
            "correlations": ctx_data.correlator_candidates,
            "rag_results": ctx_data.rag_sources,
            "active_target": target_str,
            "active_file": active_file,
        }


context_engine = ContextEngine()

