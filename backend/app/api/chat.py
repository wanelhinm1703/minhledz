"""REST API endpoints for Chat history, conversations, and REST sync fallback."""

from __future__ import annotations

import base64
import mimetypes
import os
import pathlib
import uuid

from fastapi import APIRouter, File, HTTPException, UploadFile
from fastapi.responses import FileResponse
from pydantic import BaseModel

from backend.app.core.context import context_engine
from backend.app.core.guardrails import check_exploit_intent, format_guardrail_refusal
from backend.app.services.llm import llm_service
from backend.app.storage.chat_db import chat_db

router = APIRouter(tags=["chat"])

UPLOAD_DIR = pathlib.Path(__file__).resolve().parent.parent.parent / "data" / "chat_uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)


class CreateConversationRequest(BaseModel):
    title: str | None = "New Pentest Session"
    target_id: str | None = None


class SendMessageRequest(BaseModel):
    message: str
    conversation_id: str | None = None
    target_id: str | None = None
    active_target: str | None = None
    active_file: str | None = None
    active_file_content: str | None = None
    attachments: list[dict] | None = None


@router.get("/conversations")
def get_conversations(target_id: str | None = None):
    return {"conversations": chat_db.list_conversations(target_id=target_id)}


@router.post("/conversations")
def create_conversation(req: CreateConversationRequest):
    cid = str(uuid.uuid4())
    conv = chat_db.create_conversation(
        cid, title=req.title or "New Pentest Session", target_id=req.target_id
    )
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
    cid = req.conversation_id
    if not cid:
        if req.target_id:
            cid = f"target_{req.target_id}"
        else:
            cid = str(uuid.uuid4())
        chat_db.create_conversation(
            cid,
            title=f"Target: {req.active_target}"
            if req.active_target
            else req.message[:40],
            target_id=req.target_id,
        )

    chat_db.add_message(
        conversation_id=cid,
        role="user",
        content=req.message,
        active_target=req.active_target,
        active_file=req.active_file,
        target_id=req.target_id,
        attachments=req.attachments,
    )

    # Check guardrails
    is_exploit, reason = check_exploit_intent(req.message)
    if is_exploit:
        refusal = format_guardrail_refusal(reason)
        chat_db.add_message(
            conversation_id=cid, role="assistant", content=refusal, confidence=1.0
        )
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
        active_file_content=req.active_file_content,
        conversation_id=cid,
        attachments=req.attachments,
    )

    if llm_service.active_provider != "offline":
        chunks = []
        async for chunk in llm_service.stream_response(
            prompt=req.message, context_data=ctx
        ):
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


@router.post("/upload")
async def upload_chat_file(file: UploadFile = File(...)):
    """Upload an image or document/scan file for multimodal AI chat analysis."""
    file_id = f"att_{uuid.uuid4().hex[:12]}"
    original_filename = file.filename or "uploaded_file"
    safe_filename = f"{file_id}_{pathlib.Path(original_filename).name}"
    file_path = UPLOAD_DIR / safe_filename

    content_bytes = await file.read()
    file_path.write_bytes(content_bytes)

    mime_type = (
        file.content_type
        or mimetypes.guess_type(original_filename)[0]
        or "application/octet-stream"
    )
    is_image = mime_type.startswith("image/")

    # If image, prepare base64 data URL for instant vision preview & Gemini inline_data
    data_uri = ""
    text_content = ""
    if is_image:
        b64 = base64.b64encode(content_bytes).decode("utf-8")
        data_uri = f"data:{mime_type};base64,{b64}"
    else:
        try:
            text_content = content_bytes.decode("utf-8", errors="replace")
        except Exception:
            text_content = f"Binary file ({len(content_bytes)} bytes)"

    return {
        "id": file_id,
        "name": original_filename,
        "size": len(content_bytes),
        "type": mime_type,
        "data": data_uri,
        "content": text_content,
        "url": f"/api/chat/attachments/{safe_filename}",
    }


@router.get("/attachments/{filename}")
async def get_chat_attachment(filename: str):
    """Serve uploaded chat attachments (images/documents)."""
    safe_name = pathlib.Path(filename).name
    file_path = UPLOAD_DIR / safe_name
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="Attachment not found")
    mime_type = mimetypes.guess_type(safe_name)[0] or "application/octet-stream"
    return FileResponse(path=file_path, media_type=mime_type, filename=safe_name)
