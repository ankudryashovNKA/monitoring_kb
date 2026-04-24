from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class ProcessSample(Base):
    __tablename__ = "process_samples"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    node_id: Mapped[str] = mapped_column(String(100), ForeignKey("nodes.display_name", ondelete="CASCADE"), index=True)
    pid: Mapped[int] = mapped_column(Integer, nullable=False)
    name: Mapped[str] = mapped_column(String(300), nullable=False)
    username: Mapped[str | None] = mapped_column(String(300), nullable=True)
    cmdline: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str | None] = mapped_column(String(64), nullable=True)
    cpu_percent: Mapped[float] = mapped_column(Float, nullable=False)
    ram_percent: Mapped[float] = mapped_column(Float, nullable=False)
    ram_mb: Mapped[int] = mapped_column(Integer, nullable=False)
    kind: Mapped[str] = mapped_column(String(16), nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True, nullable=False)

    node = relationship("Node", back_populates="process_samples")
