"""REST API endpoints for Chat history, conversations, and REST sync fallback."""

from __future__ import annotations

import uuid
from typing import Optional, List, Dict, Any
from pydantic import BaseModel
from fastapi import APIRouter, HTTPException
from backend.app.storage.chat_db import chat_db
from backend.app.core.guardrails import check_exploit_intent, format_guardrail_refusal
from backend.app.core.context import context_engine
from backend.app.services.llm import llm_service

router = APIRouter(tags=["chat"])


class CreateConversationRequest(BaseModel):
    title: Optional[str] = "New Pentest Session"


class SendMessageRequest(BaseModel):
    message: str
    conversation_id: Optional[str] = None
    active_target: Optional[str] = None
    active_file: Optional[str] = None


@router.get("/conversations")
def get_conversations():
    return {"conversations": chat_db.list_conversations()}


@router.post("/conversations")
def create_conversation(req: CreateConversationRequest):
    cid = str(uuid.uuid4())
    conv = chat_db.create_conversation(cid, title=req.title or "New Pentest Session")
    return conv


@router.get("/conversations/{conversation_id}/messages")
def get_messages(conversation_id: str):
    messages = chat_db.get_messages(conversation_id)
    return {"conversation_id": conversation_id, "messages": messages}


@router.delete("/conversations/{conversation_id}")
def delete_conversation(conversation_id: str):
    success = chat_db.delete_conversation(conversation_id)
    if not success:
        raise HTTPException(status_code=404, detail="Conversation not found")
    return {"status": "deleted", "conversation_id": conversation_id}


@router.post("/message")
async def send_message_sync(req: SendMessageRequest):
    """Synchronous fallback endpoint for chat interactions."""
    cid = req.conversation_id or str(uuid.uuid4())
    if not req.conversation_id:
        chat_db.create_conversation(cid, title=req.message[:40])

    chat_db.add_message(
        conversation_id=cid,
        role="user",
        content=req.message,
        active_target=req.active_target,
        active_file=req.active_file,
    )

    # Check guardrails
    is_exploit, reason = check_exploit_intent(req.message)
    if is_exploit:
        refusal = format_guardrail_refusal(reason)
        chat_db.add_message(conversation_id=cid, role="assistant", content=refusal, confidence=1.0)
        return {
            "conversation_id": cid,
            "response": refusal,
            "sources": [],
            "confidence": 1.0,
            "next_steps": ["Sử dụng safe read-only validation commands"],
        }

    ctx = context_engine.build_context(
        message=req.message,
        active_target=req.active_target,
        active_file=req.active_file,
        conversation_id=cid,
    )

    if llm_service.active_provider != "offline":
        chunks = []
        async for chunk in llm_service.stream_response(prompt=req.message, context_data=ctx):
            chunks.append(chunk)
        text = "".join(chunks)
        conf = 0.95
        next_steps = [
            "Phân tích thêm chi tiết mục tiêu",
            "Tạo verification plan an toàn (read-only)",
            "Đề xuất giải pháp phòng thủ",
        ]
    else:
        text, conf, next_steps = llm_service.generate_offline_answer(req.message, ctx)

    chat_db.add_message(
        conversation_id=cid,
        role="assistant",
        content=text,
        sources=ctx["sources"],
        confidence=conf,
    )

    return {
        "conversation_id": cid,
        "response": text,
        "sources": ctx["sources"],
        "confidence": conf,
        "next_steps": next_steps,
    }
