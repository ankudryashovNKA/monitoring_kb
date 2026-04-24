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
    net_recv_kbps: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    net_sent_kbps: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    process_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    zombie_processes: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    load1: Mapped[float | None] = mapped_column(Float, nullable=True)
    load5: Mapped[float | None] = mapped_column(Float, nullable=True)
    load15: Mapped[float | None] = mapped_column(Float, nullable=True)
    cpu_iowait_percent: Mapped[float | None] = mapped_column(Float, nullable=True)
    cpu_steal_percent: Mapped[float | None] = mapped_column(Float, nullable=True)
    ram_used_mb: Mapped[int | None] = mapped_column(Integer, nullable=True)
    ram_available_mb: Mapped[int | None] = mapped_column(Integer, nullable=True)
    swap_used_mb: Mapped[int | None] = mapped_column(Integer, nullable=True)
    swap_free_mb: Mapped[int | None] = mapped_column(Integer, nullable=True)
    disk_read_kbps: Mapped[float | None] = mapped_column(Float, nullable=True)
    disk_write_kbps: Mapped[float | None] = mapped_column(Float, nullable=True)
    disk_read_iops: Mapped[float | None] = mapped_column(Float, nullable=True)
    disk_write_iops: Mapped[float | None] = mapped_column(Float, nullable=True)
    net_packets_recv_per_sec: Mapped[float | None] = mapped_column(Float, nullable=True)
    net_packets_sent_per_sec: Mapped[float | None] = mapped_column(Float, nullable=True)
    net_errors_in_per_sec: Mapped[float | None] = mapped_column(Float, nullable=True)
    net_errors_out_per_sec: Mapped[float | None] = mapped_column(Float, nullable=True)
    net_drops_in_per_sec: Mapped[float | None] = mapped_column(Float, nullable=True)
    net_drops_out_per_sec: Mapped[float | None] = mapped_column(Float, nullable=True)
    tcp_established: Mapped[int | None] = mapped_column(Integer, nullable=True)
    tcp_listen: Mapped[int | None] = mapped_column(Integer, nullable=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True, nullable=False)

    node = relationship("Node", back_populates="metrics")
