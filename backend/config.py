"""
ReversAI Configuration
Loads environment variables and provides default settings.
"""

import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    """Application configuration."""

    # Server
    HOST = os.getenv("HOST", "0.0.0.0")
    PORT = int(os.getenv("PORT", 8000))
    MAX_FILE_SIZE_MB = int(os.getenv("MAX_FILE_SIZE_MB", 100))
    MAX_FILE_SIZE_BYTES = MAX_FILE_SIZE_MB * 1024 * 1024

    # AI Providers
    OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
    ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
    AI_PROVIDER = os.getenv("AI_PROVIDER", "openai")
    OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o")
    ANTHROPIC_MODEL = os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-20250514")

    # Analysis
    MAX_FUNCTIONS_TO_DECOMPILE = int(os.getenv("MAX_FUNCTIONS_TO_DECOMPILE", 30))
    ANALYSIS_TIMEOUT_SECONDS = int(os.getenv("ANALYSIS_TIMEOUT_SECONDS", 300))

    # Paths
    UPLOAD_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "uploads")

    @classmethod
    def has_ai_key(cls) -> bool:
        """Check if at least one AI API key is configured."""
        return bool(cls.OPENAI_API_KEY and cls.OPENAI_API_KEY != "sk-your-openai-key-here") or \
               bool(cls.ANTHROPIC_API_KEY and cls.ANTHROPIC_API_KEY != "sk-ant-your-anthropic-key-here")

    @classmethod
    def get_active_provider(cls) -> str | None:
        """Return the active AI provider, or None if no key is set."""
        if cls.AI_PROVIDER == "anthropic" and cls.ANTHROPIC_API_KEY:
            return "anthropic"
        if cls.OPENAI_API_KEY and cls.OPENAI_API_KEY != "sk-your-openai-key-here":
            return "openai"
        if cls.ANTHROPIC_API_KEY and cls.ANTHROPIC_API_KEY != "sk-ant-your-anthropic-key-here":
            return "anthropic"
        return None
