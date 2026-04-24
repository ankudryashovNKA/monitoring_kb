from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class FilesystemSample(Base):
    __tablename__ = "filesystem_samples"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    node_id: Mapped[str] = mapped_column(String(100), ForeignKey("nodes.display_name", ondelete="CASCADE"), index=True)
    device: Mapped[str] = mapped_column(String(300), nullable=False)
    mountpoint: Mapped[str] = mapped_column(String(300), index=True, nullable=False)
    fstype: Mapped[str] = mapped_column(String(64), nullable=False)
    total_gb: Mapped[float] = mapped_column(Float, nullable=False)
    used_gb: Mapped[float] = mapped_column(Float, nullable=False)
    free_gb: Mapped[float] = mapped_column(Float, nullable=False)
    percent: Mapped[float] = mapped_column(Float, nullable=False)
    inodes_total: Mapped[int | None] = mapped_column(Integer, nullable=True)
    inodes_used: Mapped[int | None] = mapped_column(Integer, nullable=True)
    inodes_free: Mapped[int | None] = mapped_column(Integer, nullable=True)
    inodes_percent: Mapped[float | None] = mapped_column(Float, nullable=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True, nullable=False)

    node = relationship("Node", back_populates="filesystem_samples")
