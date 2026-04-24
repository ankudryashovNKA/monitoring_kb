from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class AgentScript(Base):
    __tablename__ = "agent_scripts"
    __table_args__ = (UniqueConstraint("node_id", "script_id", name="uq_agent_scripts_node_script"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    agent_id: Mapped[str] = mapped_column(String(64), ForeignKey("agents.agent_id", ondelete="CASCADE"), index=True)
    node_id: Mapped[str] = mapped_column(String(100), ForeignKey("nodes.display_name", ondelete="CASCADE"), index=True)
    script_id: Mapped[str] = mapped_column(String(200), nullable=False)
    script_path: Mapped[str] = mapped_column(String(500), nullable=False)
    content_hash: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    os_family: Mapped[str] = mapped_column(String(32), nullable=False, default="any")
    title: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    tags_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    risk_level: Mapped[str] = mapped_column(String(16), nullable=False, default="medium")
    requires_confirmation: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    dry_run_supported: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    args_schema_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    manifest_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    agent = relationship("Agent")
    node = relationship("Node", back_populates="agent_scripts")
