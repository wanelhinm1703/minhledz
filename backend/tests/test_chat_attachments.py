"""Tests for chat attachments (images, logs, scripts) upload, storage, and multimodal context."""

import io
import pytest
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.core.context import context_engine
from backend.app.storage.chat_db import chat_db
from backend.app.services.llm import llm_service

client = TestClient(app)


def test_upload_image_attachment():
    # 1x1 transparent PNG bytes
    png_bytes = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15c4\x00\x00\x00\nIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82"
    file = ("screenshot_vuln.png", io.BytesIO(png_bytes), "image/png")

    response = client.post("/api/chat/upload", files={"file": file})
    assert response.status_code == 200
    data = response.json()

    assert data["name"] == "screenshot_vuln.png"
    assert data["type"] == "image/png"
    assert data["data"].startswith("data:image/png;base64,")
    assert "/api/chat/attachments/" in data["url"]

    # Verify fetching attachment file
    att_url = data["url"]
    fetch_resp = client.get(att_url)
    assert fetch_resp.status_code == 200
    assert fetch_resp.content == png_bytes


def test_upload_text_scan_attachment():
    nmap_log = "Nmap scan report for 192.168.1.10\nPORT 80/tcp open http Apache 2.4.49\nPORT 443/tcp open ssl/http\n"
    file = ("nmap_recon.log", io.BytesIO(nmap_log.encode("utf-8")), "text/plain")

    response = client.post("/api/chat/upload", files={"file": file})
    assert response.status_code == 200
    data = response.json()

    assert data["name"] == "nmap_recon.log"
    assert "text" in data["type"] or data["type"] == "application/octet-stream"
    assert data["content"] == nmap_log
    assert "/api/chat/attachments/" in data["url"]


def test_send_message_with_attachments_and_persist():
    conv_id = "test_conv_with_att_123"
    att = {
        "id": "att_1",
        "name": "scan.txt",
        "size": 100,
        "type": "text/plain",
        "data": "",
        "content": "Port 80 is open with CVE-2021-41773",
        "url": "/api/chat/attachments/scan.txt",
    }

    payload = {
        "message": "Phân tích file scan đính kèm giúp tôi",
        "conversation_id": conv_id,
        "attachments": [att],
    }

    response = client.post("/api/chat/message", json=payload)
    assert response.status_code == 200
    res_data = response.json()
    assert res_data["conversation_id"] == conv_id

    # Verify messages endpoint returns attachments
    history_resp = client.get(f"/api/chat/conversations/{conv_id}/messages")
    assert history_resp.status_code == 200
    history = history_resp.json()["messages"]
    assert len(history) >= 2

    # Find the user message
    user_msg = [m for m in history if m["role"] == "user"][-1]
    assert user_msg["content"] == "Phân tích file scan đính kèm giúp tôi"
    assert len(user_msg["attachments"]) == 1
    assert user_msg["attachments"][0]["name"] == "scan.txt"


def test_context_engine_includes_attachments():
    att = {
        "id": "att_log",
        "name": "target_recon.log",
        "size": 50,
        "type": "text/plain",
        "content": "Port 80: Apache/2.4.49 (Unix)",
    }
    ctx = context_engine.build_context(
        message="Kiểm tra CVE",
        attachments=[att],
    )
    assert "attachments" in ctx
    assert len(ctx["attachments"]) == 1

    prompt_messages = context_engine.to_prompt_messages(ctx)
    all_content = "\n".join(m["content"] for m in prompt_messages)
    assert "TẬP TIN & HÌNH ẢNH ĐÍNH KÈM TỪ NGƯỜI DÙNG" in all_content
    assert "target_recon.log" in all_content
    assert "Apache/2.4.49" in all_content
