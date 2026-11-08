"""WebSocket handler for IDE Chat with live streaming and RAG context."""

from __future__ import annotations

import json
import uuid
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from backend.app.core.guardrails import check_exploit_intent, format_guardrail_refusal
from backend.app.core.context import context_engine
from backend.app.services.llm import llm_service
from backend.app.storage.chat_db import chat_db

ws_router = APIRouter()


@ws_router.websocket("/ws/chat")
async def chat_websocket(websocket: WebSocket):
    await websocket.accept()
    try:
        while True:
            raw_data = await websocket.receive_text()
            try:
                payload = json.loads(raw_data)
            except Exception:
                await websocket.send_text(
                    json.dumps({"type": "error", "data": "Invalid JSON format"})
                )
                continue

            message = payload.get("message", "").strip()
            if not message:
                continue

            target_id = payload.get("target_id")
            active_file = payload.get("active_file")
            active_file_content = payload.get("active_file_content")
            active_target = payload.get("active_target")

            conversation_id = payload.get("conversation_id")
            if not conversation_id:
                if target_id:
                    conversation_id = f"target_{target_id}"
                else:
                    conversation_id = str(uuid.uuid4())
                chat_db.create_conversation(
                    conversation_id,
                    title=f"Target: {active_target}" if active_target else message[:40],
                    target_id=target_id,
                )

            # 1. Save user message
            chat_db.add_message(
                conversation_id=conversation_id,
                role="user",
                content=message,
                active_target=active_target,
                active_file=active_file,
                target_id=target_id,
            )

            # 2. Check Guardrails for Exploit Intent
            is_exploit, reason = check_exploit_intent(message)
            if is_exploit:
                refusal = format_guardrail_refusal(reason)
                # Send empty sources
                await websocket.send_text(
                    json.dumps({"type": "sources", "data": [], "conversation_id": conversation_id})
                )
                # Stream refusal text
                words = refusal.split(" ")
                for w in words:
                    await websocket.send_text(
                        json.dumps({"type": "chunk", "data": w + " ", "conversation_id": conversation_id})
                    )
                # Save assistant message
                chat_db.add_message(
                    conversation_id=conversation_id,
                    role="assistant",
                    content=refusal,
                    confidence=1.0,
                )
                # Send done
                await websocket.send_text(
                    json.dumps({
                        "type": "done",
                        "data": refusal,
                        "confidence": 1.0,
                        "conversation_id": conversation_id,
                        "next_steps": [
                            "Sử dụng safe read-only validation commands",
                            "Tạo verification plan không phá hủy",
                        ],
                    })
                )
                continue

            # 3. Assemble Context via ContextEngine
            ctx_data = context_engine.build_context(
                message=message,
                active_target=active_target,
                active_file=active_file,
                active_file_content=active_file_content,
                conversation_id=conversation_id,
            )

            # 4. Emit sources first
            await websocket.send_text(
                json.dumps({
                    "type": "sources",
                    "data": ctx_data["sources"],
                    "conversation_id": conversation_id,
                })
            )

            # 5. Stream response chunks
            accumulated_chunks: list[str] = []
            async for chunk in llm_service.stream_response(
                prompt=ctx_data["full_prompt"],
                context_data=ctx_data,
            ):
                accumulated_chunks.append(chunk)
                await websocket.send_text(
                    json.dumps({
                        "type": "chunk",
                        "data": chunk,
                        "conversation_id": conversation_id,
                    })
                )

            full_response = "".join(accumulated_chunks)

            # 6. Save assistant response to DB
            chat_db.add_message(
                conversation_id=conversation_id,
                role="assistant",
                content=full_response,
                sources=ctx_data["sources"],
                confidence=0.95 if ctx_data.get("correlations") else 0.85,
            )

            # 7. Emit done
            next_steps = [
                "Tạo finding từ kết quả này",
                "Chạy kiểm tra xác nhận an toàn (safe read-only probe)",
            ]
            if ctx_data.get("correlations"):
                next_steps.insert(0, f"Review CVE: {ctx_data['correlations'][0].get('cve_id')}")

            await websocket.send_text(
                json.dumps({
                    "type": "done",
                    "data": full_response,
                    "confidence": 0.95 if ctx_data.get("correlations") else 0.85,
                    "conversation_id": conversation_id,
                    "next_steps": next_steps,
                })
            )

    except WebSocketDisconnect:
        pass
    except Exception as e:
        try:
            await websocket.send_text(json.dumps({"type": "error", "data": str(e)}))
        except Exception:
            pass
