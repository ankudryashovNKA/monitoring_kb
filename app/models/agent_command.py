from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class AgentCommand(Base):
    __tablename__ = "agent_commands"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    agent_id: Mapped[str] = mapped_column(String(64), ForeignKey("agents.agent_id", ondelete="CASCADE"), index=True)
    node_id: Mapped[str] = mapped_column(String(100), ForeignKey("nodes.display_name", ondelete="CASCADE"), index=True)
    trigger_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("triggers.id", ondelete="SET NULL"), nullable=True, index=True)
    script_id: Mapped[str] = mapped_column(String(200), nullable=False)
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="trigger")
    recommendation_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    args_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    dry_run: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    requested_by_user_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    risk_level_snapshot: Mapped[str] = mapped_column(String(16), nullable=False, default="medium")
    status: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    stdout: Mapped[str | None] = mapped_column(Text, nullable=True)
    stderr: Mapped[str | None] = mapped_column(Text, nullable=True)
    exit_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    trigger = relationship("Trigger")
    node = relationship("Node", back_populates="agent_commands")
    agent = relationship("Agent")
