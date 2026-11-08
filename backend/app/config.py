from __future__ import annotations

import os
import pathlib

from dotenv import load_dotenv
from pydantic_settings import BaseSettings

# Load .env file from project root
_env_path = pathlib.Path(__file__).resolve().parent.parent.parent / ".env"
if _env_path.exists():
    load_dotenv(_env_path)


class Settings(BaseSettings):
    PROJECT_NAME: str = "AI-Pentest Copilot"
    VERSION: str = "5.0.0"
    API_V1_STR: str = "/api"

    # Repository Root
    ROOT_DIR: pathlib.Path = pathlib.Path(__file__).resolve().parent.parent.parent

    # Knowledge Base SQLite Path
    KB_SQLITE_PATH: str = os.getenv("KB_SQLITE_PATH", "toolkit/data/kb.sqlite")

    # LLM Settings
    LLM_PROVIDER: str = os.getenv("LLM_PROVIDER", "gemini")
    GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "")
    GEMINI_MODEL: str = os.getenv("GEMINI_MODEL", "gemini-flash-lite-latest")
    OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY", "")
    OPENAI_MODEL: str = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
    ANTHROPIC_API_KEY: str = os.getenv("ANTHROPIC_API_KEY", "")
    ANTHROPIC_MODEL: str = os.getenv("ANTHROPIC_MODEL", "claude-3-5-sonnet-20241022")
    OLLAMA_BASE_URL: str = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
    OLLAMA_MODEL: str = os.getenv("OLLAMA_MODEL", "llama3.1:8b")

    # Vulnerability Threat Intel Settings (Dual-mode: online + offline)
    VULN_INTEL_MODE: str = os.getenv("VULN_INTEL_MODE", "dual")  # 'dual', 'offline', 'online'
    ONLINE_INTEL_TIMEOUT: float = float(os.getenv("ONLINE_INTEL_TIMEOUT", "4.0"))
    OSV_API_URL: str = os.getenv("OSV_API_URL", "https://api.osv.dev/v1/query")
    NVD_API_KEY: str = os.getenv("NVD_API_KEY", "")

    def get_kb_db_path(self) -> pathlib.Path:
        p = pathlib.Path(self.KB_SQLITE_PATH)
        if not p.is_absolute():
            p = self.ROOT_DIR / p
        p.parent.mkdir(parents=True, exist_ok=True)
        return p


settings = Settings()
