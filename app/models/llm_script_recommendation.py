from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class LlmScriptRecommendation(Base):
    __tablename__ = "llm_script_recommendations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    node_id: Mapped[str] = mapped_column(String(100), ForeignKey("nodes.display_name", ondelete="CASCADE"), index=True)
    agent_id: Mapped[str] = mapped_column(String(64), ForeignKey("agents.agent_id", ondelete="CASCADE"), index=True)
    script_id: Mapped[str] = mapped_column(String(200), nullable=False, index=True)
    script_content_hash: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    args_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    summary: Mapped[str] = mapped_column(Text, nullable=False, default="")
    reason: Mapped[str] = mapped_column(Text, nullable=False, default="")
    evidence_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    risk_level: Mapped[str] = mapped_column(String(16), nullable=False, default="medium")
    requires_confirmation: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    dry_run_first: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="proposed")
    model_name: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    prompt_hash: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    rejected_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    executed_command_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
