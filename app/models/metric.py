from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class Metric(Base):
    __tablename__ = "metrics"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    node_id: Mapped[str] = mapped_column(String(100), ForeignKey("nodes.display_name", ondelete="CASCADE"), index=True)
    cpu_percent: Mapped[float] = mapped_column(Float, nullable=False)
    ram_percent: Mapped[float] = mapped_column(Float, nullable=False)
    uptime_seconds: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    swap_percent: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    disk_read_time_ms: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    disk_write_time_ms: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    zombie_processes: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True, nullable=False)

    node = relationship("Node", back_populates="metrics")
