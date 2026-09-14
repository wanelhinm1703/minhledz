from __future__ import annotations

from datetime import datetime, timezone
import json
import sqlite3
from typing import Any, Dict, List, Optional
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
            conn.commit()

    def create_or_get_conversation(self, conversation_id: str, target_id: Optional[str] = None, title: Optional[str] = None) -> str:
        timestamp = datetime.now(timezone.utc).isoformat()
        with db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT conversation_id FROM conversations WHERE conversation_id = ?", (conversation_id,))
            row = cursor.fetchone()
            if not row:
                cursor.execute(
                    """
                    INSERT INTO conversations (conversation_id, target_id, title, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (conversation_id, target_id, title or "New Conversation", timestamp, timestamp),
                )
                conn.commit()
        return conversation_id

    def create_conversation(self, conversation_id: str, title: Optional[str] = None, target_id: Optional[str] = None) -> Dict[str, Any]:
        self.create_or_get_conversation(conversation_id, target_id=target_id, title=title)
        return {"id": conversation_id, "conversation_id": conversation_id, "title": title or "New Conversation"}

    def delete_conversation(self, conversation_id: str) -> bool:
        with db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM chat_messages WHERE conversation_id = ?", (conversation_id,))
            cursor.execute("DELETE FROM conversations WHERE conversation_id = ?", (conversation_id,))
            conn.commit()
            return True

    def add_message(
        self,
        conversation_id: str,
        role: str,
        content: str,
        sources: Optional[List[Dict[str, Any]]] = None,
        classification: Optional[Dict[str, Any]] = None,
        confidence: Optional[float] = None,
        active_target: Optional[str] = None,
        active_file: Optional[str] = None,
        **kwargs,
    ):
        self.create_or_get_conversation(conversation_id)
        classif = classification or {}
        if confidence is not None:
            classif["confidence"] = confidence

        timestamp = datetime.now(timezone.utc).isoformat()
        with db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO chat_messages (conversation_id, role, content, sources_json, classification_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    conversation_id,
                    role,
                    content,
                    json.dumps(sources or []),
                    json.dumps(classif),
                    timestamp,
                ),
            )
            cursor.execute(
                "UPDATE conversations SET updated_at = ? WHERE conversation_id = ?",
                (timestamp, conversation_id),
            )
            conn.commit()

    def get_messages(self, conversation_id: str, limit: int = 50) -> List[Dict[str, Any]]:
        with db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT role, content, sources_json, classification_json, created_at
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
                messages.append({
                    "role": r["role"],
                    "content": r["content"],
                    "sources": json.loads(r["sources_json"] or "[]"),
                    "classification": classif,
                    "confidence": classif.get("confidence"),
                    "created_at": r["created_at"],
                })
            return messages

    def list_conversations(self) -> List[Dict[str, Any]]:
        with db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT conversation_id, target_id, title, created_at, updated_at FROM conversations ORDER BY updated_at DESC")
            rows = cursor.fetchall()
            return [{"id": r["conversation_id"], **dict(r)} for r in rows]


chat_db = ChatDatabase()

