from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class Node(Base):
    __tablename__ = "nodes"

    display_name: Mapped[str] = mapped_column(String(100), primary_key=True)
    agent_id: Mapped[str | None] = mapped_column(
        String(64),
        ForeignKey("agents.agent_id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    os_name: Mapped[str] = mapped_column(String(200), nullable=False)
    cpu_cores: Mapped[int] = mapped_column(Integer, nullable=False)
    ram_total_mb: Mapped[int] = mapped_column(Integer, nullable=False)
    ip_address: Mapped[str] = mapped_column(String(100), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    metrics = relationship("Metric", back_populates="node", cascade="all, delete-orphan")
    triggers = relationship("Trigger", back_populates="node", cascade="all, delete-orphan")
    log_entries = relationship("LogEntry", back_populates="node", cascade="all, delete-orphan")
