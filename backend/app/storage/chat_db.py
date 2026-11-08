from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from backend.app.storage.db import db

CHAT_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS conversations (
    conversation_id TEXT PRIMARY KEY,
    target_id TEXT,
    title TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS chat_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    conversation_id TEXT NOT NULL,
    role TEXT NOT NULL,
    content TEXT NOT NULL,
    sources_json TEXT,
    classification_json TEXT,
    attachments_json TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY (conversation_id) REFERENCES conversations(conversation_id)
);

CREATE INDEX IF NOT EXISTS idx_chat_conv ON chat_messages(conversation_id);
"""


class ChatDatabase:
    def __init__(self):
        self.init_chat_tables()

    def init_chat_tables(self):
        with db.get_connection() as conn:
            conn.executescript(CHAT_SCHEMA_SQL)
            try:
                conn.execute("ALTER TABLE chat_messages ADD COLUMN attachments_json TEXT")
            except Exception:
                pass
            conn.commit()

    def create_or_get_conversation(
        self,
        conversation_id: str,
        target_id: str | None = None,
        title: str | None = None,
    ) -> str:
        timestamp = datetime.now(timezone.utc).isoformat()
        with db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT conversation_id FROM conversations WHERE conversation_id = ?",
                (conversation_id,),
            )
            row = cursor.fetchone()
            if not row:
                cursor.execute(
                    """
                    INSERT INTO conversations (conversation_id, target_id, title, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        conversation_id,
                        target_id,
                        title or "New Conversation",
                        timestamp,
                        timestamp,
                    ),
                )
                conn.commit()
        return conversation_id

    def create_conversation(
        self,
        conversation_id: str,
        title: str | None = None,
        target_id: str | None = None,
    ) -> dict[str, Any]:
        self.create_or_get_conversation(
            conversation_id, target_id=target_id, title=title
        )
        return {
            "id": conversation_id,
            "conversation_id": conversation_id,
            "title": title or "New Conversation",
        }

    def delete_conversation(self, conversation_id: str) -> bool:
        with db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "DELETE FROM chat_messages WHERE conversation_id = ?",
                (conversation_id,),
            )
            cursor.execute(
                "DELETE FROM conversations WHERE conversation_id = ?",
                (conversation_id,),
            )
            conn.commit()
            return True

    def add_message(
        self,
        conversation_id: str,
        role: str,
        content: str,
        sources: list[dict[str, Any]] | None = None,
        classification: dict[str, Any] | None = None,
        confidence: float | None = None,
        active_target: str | None = None,
        active_file: str | None = None,
        target_id: str | None = None,
        attachments: list[dict[str, Any]] | None = None,
        **kwargs,
    ):
        self.create_or_get_conversation(
            conversation_id, target_id=target_id or active_target
        )
        classif = classification or {}
        if confidence is not None:
            classif["confidence"] = confidence

        timestamp = datetime.now(timezone.utc).isoformat()
        with db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO chat_messages (conversation_id, role, content, sources_json, classification_json, attachments_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    conversation_id,
                    role,
                    content,
                    json.dumps(sources or []),
                    json.dumps(classif),
                    json.dumps(attachments or []),
                    timestamp,
                ),
            )
            cursor.execute(
                "UPDATE conversations SET updated_at = ? WHERE conversation_id = ?",
                (timestamp, conversation_id),
            )
            conn.commit()

    def get_messages(
        self, conversation_id: str, limit: int = 50
    ) -> list[dict[str, Any]]:
        with db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT role, content, sources_json, classification_json, attachments_json, created_at
                FROM chat_messages
                WHERE conversation_id = ?
                ORDER BY id ASC
                LIMIT ?
                """,
                (conversation_id, limit),
            )
            rows = cursor.fetchall()
            messages = []
            for r in rows:
                classif = json.loads(r["classification_json"] or "{}")
                att_raw = r["attachments_json"] if "attachments_json" in r.keys() else None
                messages.append(
                    {
                        "role": r["role"],
                        "content": r["content"],
                        "sources": json.loads(r["sources_json"] or "[]"),
                        "classification": classif,
                        "confidence": classif.get("confidence"),
                        "attachments": json.loads(att_raw or "[]"),
                        "created_at": r["created_at"],
                    }
                )
            return messages

    def list_conversations(self, target_id: str | None = None) -> list[dict[str, Any]]:
        with db.get_connection() as conn:
            cursor = conn.cursor()
            if target_id:
                cursor.execute(
                    "SELECT conversation_id, target_id, title, created_at, updated_at FROM conversations WHERE target_id = ? ORDER BY updated_at DESC",
                    (target_id,),
                )
            else:
                cursor.execute(
                    "SELECT conversation_id, target_id, title, created_at, updated_at FROM conversations ORDER BY updated_at DESC"
                )
            rows = cursor.fetchall()
            return [{"id": r["conversation_id"], **dict(r)} for r in rows]

    def delete_target_conversations(self, target_id: str):
        with db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT conversation_id FROM conversations WHERE target_id = ?",
                (target_id,),
            )
            rows = cursor.fetchall()
            for r in rows:
                cid = r["conversation_id"]
                cursor.execute(
                    "DELETE FROM chat_messages WHERE conversation_id = ?", (cid,)
                )
                cursor.execute(
                    "DELETE FROM conversations WHERE conversation_id = ?", (cid,)
                )
            conn.commit()


chat_db = ChatDatabase()
