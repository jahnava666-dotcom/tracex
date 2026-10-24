import os
from pathlib import Path
from typing import List

# Base directory of the backend
BASE_DIR = Path(__file__).resolve().parent.parent.parent

class Settings:
    PROJECT_NAME: str = "TRACE-X AI Forensic Intelligence Platform"
    PROJECT_VERSION: str = "1.0.0"
    API_V1_PREFIX: str = "/api"
    
    # Environment
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development")
    DEBUG: bool = os.getenv("DEBUG", "True").lower() in ("true", "1")
    
    # Server
    HOST: str = os.getenv("HOST", "0.0.0.0")
    PORT: int = int(os.getenv("PORT", "8000"))
    
    # CORS
    CORS_ORIGINS: List[str] = [
        origin.strip()
        for origin in os.getenv(
            "CORS_ORIGINS",
            "http://localhost:5173,http://127.0.0.1:5173,http://localhost:3000,http://127.0.0.1:3000"
        ).split(",")
        if origin.strip()
    ]
    
    # Storage & Database
    DATA_DIR: Path = BASE_DIR / "data"
    EVIDENCE_VAULT_DIR: Path = Path(os.getenv("EVIDENCE_VAULT_DIR", str(DATA_DIR / "evidence_vault")))
    DATABASE_URL: str = os.getenv("DATABASE_URL", f"sqlite:///{DATA_DIR / 'tracex.db'}")
    
    # Security limits
    MAX_UPLOAD_SIZE_BYTES: int = 25 * 1024 * 1024  # 25 MB max upload
    ALLOWED_EXTENSIONS: set = {".eml", ".msg", ".txt", ".zip", ".pdf", ".docx", ".raw"}
    
    # External APIs (Optional)
    VIRUSTOTAL_API_KEY: str = os.getenv("VIRUSTOTAL_API_KEY", "")
    ABUSEIPDB_API_KEY: str = os.getenv("ABUSEIPDB_API_KEY", "")
    IPINFO_TOKEN: str = os.getenv("IPINFO_TOKEN", "")
    
    # Modular AI Chatbot Provider Integration
    # Supports OpenAI, Gemini, Anthropic, Ollama, and Groq via server-side env vars
    OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY", "")
    OPENAI_MODEL: str = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
    GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "")
    GEMINI_MODEL: str = os.getenv("GEMINI_MODEL", "gemini-1.5-flash")
    ANTHROPIC_API_KEY: str = os.getenv("ANTHROPIC_API_KEY", "")
    OLLAMA_BASE_URL: str = os.getenv("OLLAMA_BASE_URL", "")
    OLLAMA_MODEL: str = os.getenv("OLLAMA_MODEL", "llama3")
    GROQ_API_KEY: str = os.getenv("GROQ_API_KEY", "")

settings = Settings()

# Ensure directories exist
settings.DATA_DIR.mkdir(parents=True, exist_ok=True)
settings.EVIDENCE_VAULT_DIR.mkdir(parents=True, exist_ok=True)
