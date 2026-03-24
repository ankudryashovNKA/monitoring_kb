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
)
