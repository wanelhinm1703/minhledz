from __future__ import annotations

import os
import pathlib
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    PROJECT_NAME: str = "AI-Pentest Copilot"
    VERSION: str = "5.0.0"
    API_V1_STR: str = "/api"

    # Repository Root
    ROOT_DIR: pathlib.Path = pathlib.Path(__file__).resolve().parent.parent.parent

    # Knowledge Base SQLite Path
    KB_SQLITE_PATH: str = os.getenv("KB_SQLITE_PATH", "toolkit/data/kb.sqlite")

    # LLM Settings
    LLM_PROVIDER: str = os.getenv("LLM_PROVIDER", "auto")
    OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY", "")
    OPENAI_MODEL: str = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
    ANTHROPIC_API_KEY: str = os.getenv("ANTHROPIC_API_KEY", "")
    ANTHROPIC_MODEL: str = os.getenv("ANTHROPIC_MODEL", "claude-3-5-sonnet-20241022")
    OLLAMA_BASE_URL: str = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
    OLLAMA_MODEL: str = os.getenv("OLLAMA_MODEL", "llama3.1:8b")

    def get_kb_db_path(self) -> pathlib.Path:
        p = pathlib.Path(self.KB_SQLITE_PATH)
        if not p.is_absolute():
            p = self.ROOT_DIR / p
        p.parent.mkdir(parents=True, exist_ok=True)
        return p


settings = Settings()
