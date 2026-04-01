from __future__ import annotations

import os
from dotenv import load_dotenv
from dataclasses import dataclass

load_dotenv()

@dataclass(frozen=True)
class Settings:
    supabase_db_host: str | None
    supabase_db_port: str | None
    supabase_db_name: str | None
    supabase_db_user: str | None
    supabase_db_password: str | None
    kb_id: str | None
    kb_jwt_token: str | None
    kb_api_base_url: str
    kb_preset_name: str
    admin_login: str
    admin_password: str
    auth_secret: str
    smtp_host: str | None
    smtp_port: int
    smtp_username: str | None
    smtp_password: str | None
    smtp_sender: str | None
    smtp_use_tls: bool

    @property
    def database_url(self) -> str:
        parts = [
            self.supabase_db_host,
            self.supabase_db_port,
            self.supabase_db_name,
            self.supabase_db_user,
            self.supabase_db_password,
        ]
        if all(parts):
            return (
                f"postgresql+psycopg2://{self.supabase_db_user}:{self.supabase_db_password}"
                f"@{self.supabase_db_host}:{self.supabase_db_port}/{self.supabase_db_name}"
            )
        # Local fallback so existing app/tests continue to run without Supabase credentials.
        return "sqlite:///./monitoring.db"


settings = Settings(
    supabase_db_host=os.getenv("SUPABASE_DB_HOST"),
    supabase_db_port=os.getenv("SUPABASE_DB_PORT"),
    supabase_db_name=os.getenv("SUPABASE_DB_NAME"),
    supabase_db_user=os.getenv("SUPABASE_DB_USER"),
    supabase_db_password=os.getenv("SUPABASE_DB_PASSWORD"),
    kb_id=os.getenv("KB_ID"),
    kb_jwt_token=os.getenv("KB_JWT_TOKEN"),
    kb_api_base_url=os.getenv("KB_API_BASE_URL", "https://kb.ai-hippocrates.ru/kbapi"),
    kb_preset_name=os.getenv("KB_PRESET_NAME", "Monitoring server"),
    admin_login=os.getenv("ADMIN_LOGIN", "admin"),
    admin_password=os.getenv("ADMIN_PASSWORD", "admin"),
    auth_secret=os.getenv("AUTH_SECRET", "change-me-in-production"),
    smtp_host=os.getenv("SMTP_HOST"),
    smtp_port=int(os.getenv("SMTP_PORT", "587")),
    smtp_username=os.getenv("SMTP_USERNAME"),
    smtp_password=os.getenv("SMTP_PASSWORD"),
    smtp_sender=os.getenv("SMTP_SENDER"),
    smtp_use_tls=os.getenv("SMTP_USE_TLS", "true").strip().lower() in {"1", "true", "yes", "on"},
)
