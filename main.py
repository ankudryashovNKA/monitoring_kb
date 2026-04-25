from __future__ import annotations

from collections import defaultdict, deque
import contextlib
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
import hashlib
import json
import logging
import operator
import os
import re
import smtplib
from typing import Deque

from fastapi import FastAPI, HTTPException, Query, Request, Response, status
import httpx
import ollama

from app.api.users import router as users_router
from app.config import settings
from app.db.base import Base
from app.db.session import SessionLocal, engine
from app.models.agent import Agent
import app.models.metric  # noqa: F401
import app.models.node  # noqa: F401
import app.models.log_entry  # noqa: F401
import app.models.trigger  # noqa: F401
import app.models.agent_script  # noqa: F401
import app.models.agent_command  # noqa: F401
import app.models.user  # noqa: F401
import app.models.agent  # noqa: F401
import app.models.filesystem_sample  # noqa: F401
import app.models.process_sample  # noqa: F401
import app.models.llm_script_recommendation  # noqa: F401
from app.security.agent_auth import (
    register_agent,
    rotate_agent_secret,
    validate_agent_request,
)
from fastapi.responses import HTMLResponse, StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.models.metric import Metric
from app.models.node import Node
from app.models.log_entry import LogEntry
from app.models.trigger import Trigger
from app.models.agent_script import AgentScript
from app.models.agent_command import AgentCommand
from app.models.user import User
from app.models.filesystem_sample import FilesystemSample
from app.models.process_sample import ProcessSample
from app.models.llm_script_recommendation import LlmScriptRecommendation
from app.security.user_auth import decode_session_token, hash_password, make_session_token, verify_password
from sqlalchemy import inspect, text
from app.services.llm_context import build_node_analysis_context
from app.services.llm_prompt import build_node_analysis_prompt, build_script_recommendation_prompt

METRICS_RETENTION_HOURS = int(os.getenv("METRICS_RETENTION_HOURS", "168"))
FILESYSTEM_RETENTION_HOURS = int(os.getenv("FILESYSTEM_RETENTION_HOURS", "168"))
PROCESS_RETENTION_HOURS = int(os.getenv("PROCESS_RETENTION_HOURS", "24"))
LOG_RETENTION_PER_NODE_AND_SEVERITY = int(os.getenv("LOG_RETENTION_PER_NODE_AND_SEVERITY", "2000"))
RETENTION_PERIOD = timedelta(hours=METRICS_RETENTION_HOURS)
RECENT_POINTS_LIMIT = 10
LOG_POINTS_LIMIT = 100
MAX_STORED_LOGS_PER_NODE_AND_SEVERITY = LOG_RETENTION_PER_NODE_AND_SEVERITY
LOG_SEVERITY_LEVELS = ("DEBUG", "INFO", "NOTICE", "WARNING", "ERROR", "CRITICAL", "ALERT", "EMERGENCY")

logger = logging.getLogger(__name__)
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "gpt-oss:120b-cloud")
OLLAMA_HOST = os.getenv("OLLAMA_HOST", "https://ollama.com")
OLLAMA_KEEP_ALIVE = os.getenv("OLLAMA_KEEP_ALIVE", "30m")
LLM_CONTEXT_MAX_RECENT_POINTS = int(os.getenv("LLM_CONTEXT_MAX_RECENT_POINTS", "15"))
LLM_CONTEXT_MAX_LOG_SIGNATURES = int(os.getenv("LLM_CONTEXT_MAX_LOG_SIGNATURES", "10"))
LLM_CONTEXT_MAX_LOG_EXAMPLES_PER_SIGNATURE = int(os.getenv("LLM_CONTEXT_MAX_LOG_EXAMPLES_PER_SIGNATURE", "3"))

METRIC_VALUE_EXTRACTORS = {
    "cpu_percent": lambda metric: float(metric.cpu_percent),
    "ram_percent": lambda metric: float(metric.ram_percent),
    "swap_percent": lambda metric: float(metric.swap_percent),
    "uptime_seconds": lambda metric: float(metric.uptime_seconds),
    "disk_read_time_ms": lambda metric: float(metric.disk_read_time_ms),
    "disk_write_time_ms": lambda metric: float(metric.disk_write_time_ms),
    "net_recv_kbps": lambda metric: float(metric.net_recv_kbps),
    "net_sent_kbps": lambda metric: float(metric.net_sent_kbps),
    "process_count": lambda metric: float(metric.process_count),
    "zombie_processes": lambda metric: float(metric.zombie_processes),
    "load1": lambda metric: float(metric.load1 or 0.0),
    "load5": lambda metric: float(metric.load5 or 0.0),
    "load15": lambda metric: float(metric.load15 or 0.0),
    "cpu_iowait_percent": lambda metric: float(metric.cpu_iowait_percent or 0.0),
    "cpu_steal_percent": lambda metric: float(metric.cpu_steal_percent or 0.0),
    "ram_used_mb": lambda metric: float(metric.ram_used_mb or 0.0),
    "ram_available_mb": lambda metric: float(metric.ram_available_mb or 0.0),
    "swap_used_mb": lambda metric: float(metric.swap_used_mb or 0.0),
    "swap_free_mb": lambda metric: float(metric.swap_free_mb or 0.0),
    "disk_read_kbps": lambda metric: float(metric.disk_read_kbps or 0.0),
    "disk_write_kbps": lambda metric: float(metric.disk_write_kbps or 0.0),
    "disk_read_iops": lambda metric: float(metric.disk_read_iops or 0.0),
    "disk_write_iops": lambda metric: float(metric.disk_write_iops or 0.0),
    "net_packets_recv_per_sec": lambda metric: float(metric.net_packets_recv_per_sec or 0.0),
    "net_packets_sent_per_sec": lambda metric: float(metric.net_packets_sent_per_sec or 0.0),
    "net_errors_in_per_sec": lambda metric: float(metric.net_errors_in_per_sec or 0.0),
    "net_errors_out_per_sec": lambda metric: float(metric.net_errors_out_per_sec or 0.0),
    "net_drops_in_per_sec": lambda metric: float(metric.net_drops_in_per_sec or 0.0),
    "net_drops_out_per_sec": lambda metric: float(metric.net_drops_out_per_sec or 0.0),
    "tcp_established": lambda metric: float(metric.tcp_established or 0.0),
    "tcp_listen": lambda metric: float(metric.tcp_listen or 0.0),
}


@dataclass
class MetricPoint:
    node_id: str
    cpu_percent: float
    ram_percent: float
    timestamp: datetime


@dataclass
class NodeInfo:
    node_id: str
    display_name: str
    os_name: str
    cpu_cores: int
    ram_total_mb: int
    ip_address: str
    last_seen: datetime


class TopProcessIn(BaseModel):
    pid: int = Field(..., ge=0)
    name: str = Field(..., min_length=1, max_length=300)
    username: str | None = Field(default=None, max_length=300)
    cmdline: str | None = Field(default=None, max_length=500)
    status: str | None = Field(default=None, max_length=64)
    create_time: datetime | None = None
    cpu_percent: float = Field(..., ge=0)
    ram_percent: float = Field(..., ge=0, le=100)
    ram_mb: int = Field(..., ge=0)


class FilesystemUsageIn(BaseModel):
    device: str = Field(..., min_length=1, max_length=300)
    mountpoint: str = Field(..., min_length=1, max_length=300)
    fstype: str = Field(..., min_length=1, max_length=64)
    total_gb: float = Field(..., ge=0)
    used_gb: float = Field(..., ge=0)
    free_gb: float = Field(..., ge=0)
    percent: float = Field(..., ge=0, le=100)
    inodes_total: int | None = Field(default=None, ge=0)
    inodes_used: int | None = Field(default=None, ge=0)
    inodes_free: int | None = Field(default=None, ge=0)
    inodes_percent: float | None = Field(default=None, ge=0, le=100)


class MetricIn(BaseModel):
    node_id: str = Field(..., min_length=1, max_length=100)
    agent_id: str | None = Field(default=None, min_length=1, max_length=64)
    cpu_percent: float = Field(..., ge=0, le=100)
    ram_percent: float = Field(..., ge=0, le=100)
    uptime_seconds: float = Field(default=0, ge=0)
    swap_percent: float = Field(default=0, ge=0, le=100)
    disk_read_time_ms: float = Field(default=0, ge=0)
    disk_write_time_ms: float = Field(default=0, ge=0)
    net_recv_kbps: float = Field(default=0, ge=0)
    net_sent_kbps: float = Field(default=0, ge=0)
    process_count: int = Field(default=0, ge=0)
    zombie_processes: int = Field(default=0, ge=0)
    load1: float | None = Field(default=None)
    load5: float | None = Field(default=None)
    load15: float | None = Field(default=None)
    cpu_iowait_percent: float | None = Field(default=None)
    cpu_steal_percent: float | None = Field(default=None)
    ram_used_mb: int | None = Field(default=None, ge=0)
    ram_available_mb: int | None = Field(default=None, ge=0)
    swap_used_mb: int | None = Field(default=None, ge=0)
    swap_free_mb: int | None = Field(default=None, ge=0)
    disk_read_kbps: float | None = Field(default=None, ge=0)
    disk_write_kbps: float | None = Field(default=None, ge=0)
    disk_read_iops: float | None = Field(default=None, ge=0)
    disk_write_iops: float | None = Field(default=None, ge=0)
    net_packets_recv_per_sec: float | None = Field(default=None, ge=0)
    net_packets_sent_per_sec: float | None = Field(default=None, ge=0)
    net_errors_in_per_sec: float | None = Field(default=None, ge=0)
    net_errors_out_per_sec: float | None = Field(default=None, ge=0)
    net_drops_in_per_sec: float | None = Field(default=None, ge=0)
    net_drops_out_per_sec: float | None = Field(default=None, ge=0)
    tcp_established: int | None = Field(default=None, ge=0)
    tcp_listen: int | None = Field(default=None, ge=0)
    os_name: str = Field(..., min_length=1, max_length=200)
    cpu_cores: int = Field(..., ge=1, le=4096)
    ram_total_mb: int = Field(..., ge=1)
    ip_address: str = Field(..., min_length=1, max_length=100)
    top_cpu_processes: list[TopProcessIn] = Field(default_factory=list, max_length=10)
    top_ram_processes: list[TopProcessIn] = Field(default_factory=list, max_length=10)
    filesystems: list[FilesystemUsageIn] = Field(default_factory=list, max_length=100)
    timestamp: datetime | None = None


class NodeRenameIn(BaseModel):
    display_name: str = Field(..., min_length=1, max_length=100)


class LogEntryIn(BaseModel):
    source: str = Field(..., min_length=1, max_length=120)
    severity: str = Field(default="INFO", pattern="^(DEBUG|INFO|NOTICE|WARNING|ERROR|CRITICAL|ALERT|EMERGENCY)$")
    message: str = Field(..., min_length=1, max_length=8000)
    captured_at: datetime | None = None


class LogsIn(BaseModel):
    node_id: str = Field(..., min_length=1, max_length=100)
    agent_id: str | None = Field(default=None, min_length=1, max_length=64)
    os_name: str = Field(..., min_length=1, max_length=200)
    cpu_cores: int = Field(..., ge=1, le=4096)
    ram_total_mb: int = Field(..., ge=1)
    ip_address: str = Field(..., min_length=1, max_length=100)
    entries: list[LogEntryIn] = Field(default_factory=list, max_length=LOG_POINTS_LIMIT)


class AgentScriptEntryIn(BaseModel):
    script_id: str = Field(..., min_length=1, max_length=200)
    script_path: str = Field(..., min_length=1, max_length=500)
    content_hash: str = Field(default="", max_length=128)
    os_family: str = Field(default="any", pattern="^(linux|windows|any)$")
    title: str = Field(default="", max_length=255)
    description: str = Field(default="", max_length=5000)
    tags: list[str] = Field(default_factory=list, max_length=100)
    risk_level: str = Field(default="medium", pattern="^(low|medium|high)$")
    requires_confirmation: bool = True
    dry_run_supported: bool = False
    args_schema: dict[str, object] = Field(default_factory=dict)
    enabled: bool = True
    manifest_error: str | None = Field(default=None, max_length=5000)


class AgentScriptsIn(BaseModel):
    node_id: str = Field(..., min_length=1, max_length=100)
    scripts: list[AgentScriptEntryIn] = Field(default_factory=list, max_length=500)


class AgentCommandResultIn(BaseModel):
    status: str = Field(..., pattern="^(running|completed|failed)$")
    stdout: str | None = Field(default=None, max_length=200000)
    stderr: str | None = Field(default=None, max_length=200000)
    exit_code: int | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None


class LLMScriptRecommendIn(BaseModel):
    node_id: str = Field(..., min_length=1, max_length=100)
    window_minutes: int = Field(default=60, ge=10, le=1440)


class LLMRecommendationApproveIn(BaseModel):
    confirm: bool = False
    dry_run: bool = True


class LLMRecommendationRejectIn(BaseModel):
    reason: str | None = Field(default=None, max_length=2000)


class TriggerCreateIn(BaseModel):
    node_id: str = Field(..., min_length=1, max_length=100)
    name: str = Field("Trigger", min_length=1, max_length=120)
    metric_name: str = Field(
        ...,
        pattern="^(cpu_percent|ram_percent|swap_percent|uptime_seconds|disk_read_time_ms|disk_write_time_ms|net_recv_kbps|net_sent_kbps|process_count|zombie_processes)$",
    )
    operator: str = Field(..., pattern="^(>|<)$")
    threshold: float = Field(..., ge=0)
    alert_user_id: int | None = Field(default=None, ge=1)
    action_script_id: str = Field(..., min_length=1, max_length=200)


class TriggerUpdateIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=120)
    threshold: float = Field(..., ge=0)
    alert_user_id: int | None = Field(default=None, ge=1)
    action_script_id: str = Field(..., min_length=1, max_length=200)


class KBExplanatoryItem(BaseModel):
    name: str
    description: str = ""


class KBResultItem(BaseModel):
    name: str
    description: str = ""
    explanatorySet: list[KBExplanatoryItem] = Field(default_factory=list)


class KBSolveResponse(BaseModel):
    results: list[KBResultItem] = Field(default_factory=list)


class LLMGenerateIn(BaseModel):
    prompt: str = Field(..., min_length=1, max_length=20000)


class LLMNodeAnalysisIn(BaseModel):
    node_id: str = Field(..., min_length=1, max_length=100)
    window_minutes: int = Field(default=60, ge=10, le=1440)
    include_raw: bool = False


class LoginIn(BaseModel):
    login: str = Field(..., min_length=1, max_length=64)
    password: str = Field(..., min_length=1, max_length=256)


app = FastAPI(title="Monitoring KB")
app.include_router(users_router)

_kb_last_updated: datetime | None = None

UNPROTECTED_PATH_PREFIXES = (
    "/api/auth/login",
    "/api/auth/logout",
    "/api/agent/metrics",
    "/api/agent/logs",
    "/api/agent/scripts",
    "/api/agent/commands/",
    "/openapi.json",
    "/docs",
    "/redoc",
)


@app.middleware("http")
async def dashboard_auth_middleware(request: Request, call_next):
    path = request.url.path
    if path.startswith(UNPROTECTED_PATH_PREFIXES) or path.startswith("/static/"):
        return await call_next(request)

    if path.startswith("/api"):
        token = request.cookies.get("dashboard_session")
        login = decode_session_token(token) if token else None
        if not login:
            return Response(
                content='{"detail":"Authentication required"}',
                status_code=status.HTTP_401_UNAUTHORIZED,
                media_type="application/json",
            )
    return await call_next(request)


@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    return response


def init_db() -> None:
    # For production use Alembic migrations instead of create_all.
    Base.metadata.create_all(bind=engine)
    _migrate_users_table()
    _migrate_triggers_table()
    _migrate_agent_scripts_table()
    _migrate_agent_commands_table()
    _migrate_llm_script_recommendations_table()
    _migrate_metrics_table()
    _migrate_log_entries_table()
    _migrate_filesystem_samples_table()
    _migrate_process_samples_table()
    _ensure_admin_user()


def _migrate_users_table() -> None:
    inspector = inspect(engine)
    if "users" not in inspector.get_table_names():
        return

    dialect_name = engine.dialect.name
    existing_columns = {column["name"] for column in inspector.get_columns("users")}
    statements: list[str] = []
    if "login" not in existing_columns:
        statements.append("ALTER TABLE users ADD COLUMN login VARCHAR(64)")
    if "password_hash" not in existing_columns:
        statements.append("ALTER TABLE users ADD COLUMN password_hash VARCHAR(512)")
    if "display_name" not in existing_columns:
        statements.append("ALTER TABLE users ADD COLUMN display_name VARCHAR(255)")
    if "created_at" not in existing_columns:
        if dialect_name == "postgresql":
            statements.append("ALTER TABLE users ADD COLUMN created_at TIMESTAMP WITH TIME ZONE")
        else:
            statements.append("ALTER TABLE users ADD COLUMN created_at DATETIME")

    with engine.begin() as connection:
        for statement in statements:
            connection.execute(text(statement))

        connection.execute(
            text("UPDATE users SET login = email WHERE login IS NULL OR login = ''")
        )
        connection.execute(
            text("UPDATE users SET password_hash = :password_hash WHERE password_hash IS NULL OR password_hash = ''"),
            {"password_hash": hash_password(settings.admin_password)},
        )
        connection.execute(text("UPDATE users SET created_at = CURRENT_TIMESTAMP WHERE created_at IS NULL"))


def _ensure_admin_user() -> None:
    admin_email = f"{settings.admin_login}@monitoring-kb.com"
    with SessionLocal() as db:
        admin = db.query(User).filter(User.login == settings.admin_login).first()
        if admin is None:
            existing_email = db.query(User).filter(
                User.email.in_([f"{settings.admin_login}@local", f"{settings.admin_login}@local.test", admin_email])
            ).first()
            if existing_email is not None:
                existing_email.login = settings.admin_login
                existing_email.password_hash = hash_password(settings.admin_password)
                existing_email.email = admin_email
                if not existing_email.display_name:
                    existing_email.display_name = "Administrator"
            else:
                db.add(
                    User(
                        login=settings.admin_login,
                        password_hash=hash_password(settings.admin_password),
                        email=admin_email,
                        display_name="Administrator",
                    )
                )
        else:
            if not admin.password_hash:
                admin.password_hash = hash_password(settings.admin_password)
            if admin.email in [f"{settings.admin_login}@local", f"{settings.admin_login}@local.test"]:
                admin.email = admin_email
        db.commit()


def _migrate_log_entries_table() -> None:
    inspector = inspect(engine)
    if "log_entries" not in inspector.get_table_names():
        return

    dialect_name = engine.dialect.name
    existing_columns = {column["name"] for column in inspector.get_columns("log_entries")}
    statements: list[str] = []
    if "severity" not in existing_columns:
        statements.append("ALTER TABLE log_entries ADD COLUMN severity VARCHAR(16)")

    with engine.begin() as connection:
        for statement in statements:
            connection.execute(text(statement))
        connection.execute(text("UPDATE log_entries SET severity = 'INFO' WHERE severity IS NULL OR severity = ''"))

        index_statements = [
            "CREATE INDEX IF NOT EXISTS ix_log_entries_severity ON log_entries (severity)",
            "CREATE INDEX IF NOT EXISTS ix_log_entries_node_severity_captured_at ON log_entries (node_id, severity, captured_at DESC, id DESC)",
        ]
        for statement in index_statements:
            if dialect_name == "postgresql":
                connection.execute(text(statement))
            else:
                with contextlib.suppress(Exception):
                    connection.execute(text(statement))


def _migrate_metrics_table() -> None:
    inspector = inspect(engine)
    if "metrics" not in inspector.get_table_names():
        return

    existing_columns = {column["name"] for column in inspector.get_columns("metrics")}
    statements: list[str] = []
    if "uptime_seconds" not in existing_columns:
        statements.append("ALTER TABLE metrics ADD COLUMN uptime_seconds FLOAT NOT NULL DEFAULT 0")
    if "swap_percent" not in existing_columns:
        statements.append("ALTER TABLE metrics ADD COLUMN swap_percent FLOAT NOT NULL DEFAULT 0")
    if "disk_read_time_ms" not in existing_columns:
        statements.append("ALTER TABLE metrics ADD COLUMN disk_read_time_ms FLOAT NOT NULL DEFAULT 0")
    if "disk_write_time_ms" not in existing_columns:
        statements.append("ALTER TABLE metrics ADD COLUMN disk_write_time_ms FLOAT NOT NULL DEFAULT 0")
    if "net_recv_kbps" not in existing_columns:
        statements.append("ALTER TABLE metrics ADD COLUMN net_recv_kbps FLOAT NOT NULL DEFAULT 0")
    if "net_sent_kbps" not in existing_columns:
        statements.append("ALTER TABLE metrics ADD COLUMN net_sent_kbps FLOAT NOT NULL DEFAULT 0")
    if "process_count" not in existing_columns:
        statements.append("ALTER TABLE metrics ADD COLUMN process_count INTEGER NOT NULL DEFAULT 0")
    if "zombie_processes" not in existing_columns:
        statements.append("ALTER TABLE metrics ADD COLUMN zombie_processes INTEGER NOT NULL DEFAULT 0")
    for col, ddl in (
        ("load1", "FLOAT"), ("load5", "FLOAT"), ("load15", "FLOAT"), ("cpu_iowait_percent", "FLOAT"),
        ("cpu_steal_percent", "FLOAT"), ("ram_used_mb", "INTEGER"), ("ram_available_mb", "INTEGER"),
        ("swap_used_mb", "INTEGER"), ("swap_free_mb", "INTEGER"), ("disk_read_kbps", "FLOAT"),
        ("disk_write_kbps", "FLOAT"), ("disk_read_iops", "FLOAT"), ("disk_write_iops", "FLOAT"),
        ("net_packets_recv_per_sec", "FLOAT"), ("net_packets_sent_per_sec", "FLOAT"), ("net_errors_in_per_sec", "FLOAT"),
        ("net_errors_out_per_sec", "FLOAT"), ("net_drops_in_per_sec", "FLOAT"), ("net_drops_out_per_sec", "FLOAT"),
        ("tcp_established", "INTEGER"), ("tcp_listen", "INTEGER"),
    ):
        if col not in existing_columns:
            statements.append(f"ALTER TABLE metrics ADD COLUMN {col} {ddl}")

    with engine.begin() as connection:
        for statement in statements:
            connection.execute(text(statement))
        with contextlib.suppress(Exception):
            connection.execute(text("CREATE INDEX IF NOT EXISTS ix_metrics_node_timestamp_desc ON metrics (node_id, timestamp DESC)"))


def _migrate_triggers_table() -> None:
    inspector = inspect(engine)
    if "triggers" not in inspector.get_table_names():
        return

    dialect_name = engine.dialect.name
    bool_default_false = "FALSE" if dialect_name == "postgresql" else "0"
    existing_columns = {column["name"] for column in inspector.get_columns("triggers")}
    statements: list[str] = []
    if "alert_user_id" not in existing_columns:
        statements.append("ALTER TABLE triggers ADD COLUMN alert_user_id INTEGER")
    if "alert_sent" not in existing_columns:
        statements.append(f"ALTER TABLE triggers ADD COLUMN alert_sent BOOLEAN DEFAULT {bool_default_false} NOT NULL")
    if "action_script_id" not in existing_columns:
        statements.append("ALTER TABLE triggers ADD COLUMN action_script_id VARCHAR(200) DEFAULT '' NOT NULL")
    if "remediation_sent" not in existing_columns:
        statements.append(f"ALTER TABLE triggers ADD COLUMN remediation_sent BOOLEAN DEFAULT {bool_default_false} NOT NULL")

    with engine.begin() as connection:
        for statement in statements:
            connection.execute(text(statement))


def _migrate_agent_scripts_table() -> None:
    inspector = inspect(engine)
    if "agent_scripts" not in inspector.get_table_names():
        return
    dialect_name = engine.dialect.name
    bool_default_true = "TRUE" if dialect_name == "postgresql" else "1"
    bool_default_false = "FALSE" if dialect_name == "postgresql" else "0"
    bool_true_value = "TRUE" if dialect_name == "postgresql" else "1"
    bool_false_value = "FALSE" if dialect_name == "postgresql" else "0"
    existing_columns = {column["name"] for column in inspector.get_columns("agent_scripts")}
    statements: list[str] = []
    if "content_hash" not in existing_columns:
        statements.append("ALTER TABLE agent_scripts ADD COLUMN content_hash VARCHAR(128) DEFAULT '' NOT NULL")
    if "os_family" not in existing_columns:
        statements.append("ALTER TABLE agent_scripts ADD COLUMN os_family VARCHAR(32) DEFAULT 'any' NOT NULL")
    if "title" not in existing_columns:
        statements.append("ALTER TABLE agent_scripts ADD COLUMN title VARCHAR(255) DEFAULT '' NOT NULL")
    if "description" not in existing_columns:
        statements.append("ALTER TABLE agent_scripts ADD COLUMN description TEXT DEFAULT '' NOT NULL")
    if "tags_json" not in existing_columns:
        statements.append("ALTER TABLE agent_scripts ADD COLUMN tags_json TEXT DEFAULT '[]' NOT NULL")
    if "risk_level" not in existing_columns:
        statements.append("ALTER TABLE agent_scripts ADD COLUMN risk_level VARCHAR(16) DEFAULT 'medium' NOT NULL")
    if "requires_confirmation" not in existing_columns:
        statements.append(f"ALTER TABLE agent_scripts ADD COLUMN requires_confirmation BOOLEAN DEFAULT {bool_default_true} NOT NULL")
    if "dry_run_supported" not in existing_columns:
        statements.append(f"ALTER TABLE agent_scripts ADD COLUMN dry_run_supported BOOLEAN DEFAULT {bool_default_false} NOT NULL")
    if "args_schema_json" not in existing_columns:
        statements.append("ALTER TABLE agent_scripts ADD COLUMN args_schema_json TEXT DEFAULT '{}' NOT NULL")
    if "enabled" not in existing_columns:
        statements.append(f"ALTER TABLE agent_scripts ADD COLUMN enabled BOOLEAN DEFAULT {bool_default_true} NOT NULL")
    if "manifest_error" not in existing_columns:
        statements.append("ALTER TABLE agent_scripts ADD COLUMN manifest_error TEXT")
    with engine.begin() as connection:
        for statement in statements:
            connection.execute(text(statement))
        connection.execute(text("UPDATE agent_scripts SET content_hash = '' WHERE content_hash IS NULL"))
        connection.execute(text("UPDATE agent_scripts SET os_family = 'any' WHERE os_family IS NULL OR os_family = ''"))
        connection.execute(text("UPDATE agent_scripts SET title = script_id WHERE title IS NULL OR title = ''"))
        connection.execute(text("UPDATE agent_scripts SET description = '' WHERE description IS NULL"))
        connection.execute(text("UPDATE agent_scripts SET tags_json = '[]' WHERE tags_json IS NULL OR tags_json = ''"))
        connection.execute(text("UPDATE agent_scripts SET risk_level = 'medium' WHERE risk_level IS NULL OR risk_level = ''"))
        connection.execute(text(f"UPDATE agent_scripts SET requires_confirmation = {bool_true_value} WHERE requires_confirmation IS NULL"))
        connection.execute(text(f"UPDATE agent_scripts SET dry_run_supported = {bool_false_value} WHERE dry_run_supported IS NULL"))
        connection.execute(text("UPDATE agent_scripts SET args_schema_json = '{}' WHERE args_schema_json IS NULL OR args_schema_json = ''"))
        connection.execute(text(f"UPDATE agent_scripts SET enabled = {bool_true_value} WHERE enabled IS NULL"))
        statement = "CREATE UNIQUE INDEX IF NOT EXISTS ix_agent_scripts_node_script ON agent_scripts (node_id, script_id)"
        if dialect_name == "postgresql":
            connection.execute(text(statement))
        else:
            with contextlib.suppress(Exception):
                connection.execute(text(statement))


def _migrate_agent_commands_table() -> None:
    inspector = inspect(engine)
    if "agent_commands" not in inspector.get_table_names():
        return
    dialect_name = engine.dialect.name
    bool_default_false = "FALSE" if dialect_name == "postgresql" else "0"
    bool_false_value = "FALSE" if dialect_name == "postgresql" else "0"
    existing_columns = {column["name"] for column in inspector.get_columns("agent_commands")}
    statements: list[str] = []
    if "source" not in existing_columns:
        statements.append("ALTER TABLE agent_commands ADD COLUMN source VARCHAR(32) DEFAULT 'trigger' NOT NULL")
    if "recommendation_id" not in existing_columns:
        statements.append("ALTER TABLE agent_commands ADD COLUMN recommendation_id INTEGER")
    if "args_json" not in existing_columns:
        statements.append("ALTER TABLE agent_commands ADD COLUMN args_json TEXT DEFAULT '{}' NOT NULL")
    if "dry_run" not in existing_columns:
        statements.append(f"ALTER TABLE agent_commands ADD COLUMN dry_run BOOLEAN DEFAULT {bool_default_false} NOT NULL")
    if "requested_by_user_id" not in existing_columns:
        statements.append("ALTER TABLE agent_commands ADD COLUMN requested_by_user_id INTEGER")
    if "risk_level_snapshot" not in existing_columns:
        statements.append("ALTER TABLE agent_commands ADD COLUMN risk_level_snapshot VARCHAR(16) DEFAULT 'medium' NOT NULL")
    with engine.begin() as connection:
        for statement in statements:
            connection.execute(text(statement))
        connection.execute(text("UPDATE agent_commands SET source = 'trigger' WHERE source IS NULL OR source = ''"))
        connection.execute(text("UPDATE agent_commands SET args_json = '{}' WHERE args_json IS NULL OR args_json = ''"))
        connection.execute(text(f"UPDATE agent_commands SET dry_run = {bool_false_value} WHERE dry_run IS NULL"))
        connection.execute(text("UPDATE agent_commands SET risk_level_snapshot = 'medium' WHERE risk_level_snapshot IS NULL OR risk_level_snapshot = ''"))
        for statement in (
            "CREATE INDEX IF NOT EXISTS ix_agent_commands_agent_status_created ON agent_commands (agent_id, status, created_at)",
            "CREATE INDEX IF NOT EXISTS ix_agent_commands_trigger_status ON agent_commands (trigger_id, status)",
            "CREATE INDEX IF NOT EXISTS ix_agent_commands_node_script_status_created ON agent_commands (node_id, script_id, status, created_at)",
        ):
            if dialect_name == "postgresql":
                connection.execute(text(statement))
            else:
                with contextlib.suppress(Exception):
                    connection.execute(text(statement))


def _migrate_llm_script_recommendations_table() -> None:
    inspector = inspect(engine)
    if "llm_script_recommendations" not in inspector.get_table_names():
        return
    dialect_name = engine.dialect.name
    bool_default_true = "TRUE" if dialect_name == "postgresql" else "1"
    bool_default_false = "FALSE" if dialect_name == "postgresql" else "0"
    existing_columns = {column["name"] for column in inspector.get_columns("llm_script_recommendations")}
    statements: list[str] = []
    desired_columns = [
        ("node_id", "VARCHAR(100)"),
        ("agent_id", "VARCHAR(64)"),
        ("script_id", "VARCHAR(200)"),
        ("script_content_hash", "VARCHAR(128) DEFAULT '' NOT NULL"),
        ("args_json", "TEXT DEFAULT '{}' NOT NULL"),
        ("summary", "TEXT DEFAULT '' NOT NULL"),
        ("reason", "TEXT DEFAULT '' NOT NULL"),
        ("evidence_json", "TEXT DEFAULT '[]' NOT NULL"),
        ("confidence", "FLOAT DEFAULT 0.0 NOT NULL"),
        ("risk_level", "VARCHAR(16) DEFAULT 'medium' NOT NULL"),
        ("requires_confirmation", f"BOOLEAN DEFAULT {bool_default_true} NOT NULL"),
        ("dry_run_first", f"BOOLEAN DEFAULT {bool_default_false} NOT NULL"),
        ("status", "VARCHAR(32) DEFAULT 'proposed' NOT NULL"),
        ("model_name", "VARCHAR(128) DEFAULT '' NOT NULL"),
        ("prompt_hash", "VARCHAR(128) DEFAULT '' NOT NULL"),
        ("approved_at", "TIMESTAMP"),
        ("rejected_at", "TIMESTAMP"),
        ("executed_command_id", "INTEGER"),
        ("error_message", "TEXT"),
    ]
    for name, ddl in desired_columns:
        if name not in existing_columns:
            statements.append(f"ALTER TABLE llm_script_recommendations ADD COLUMN {name} {ddl}")
    with engine.begin() as connection:
        for statement in statements:
            connection.execute(text(statement))
        for statement in (
            "CREATE INDEX IF NOT EXISTS ix_llm_recommendations_node_status_created ON llm_script_recommendations (node_id, status, created_at)",
            "CREATE INDEX IF NOT EXISTS ix_llm_recommendations_node_created ON llm_script_recommendations (node_id, created_at)",
        ):
            if dialect_name == "postgresql":
                connection.execute(text(statement))
            else:
                with contextlib.suppress(Exception):
                    connection.execute(text(statement))


def _migrate_filesystem_samples_table() -> None:
    inspector = inspect(engine)
    if "filesystem_samples" not in inspector.get_table_names():
        return
    with engine.begin() as connection:
        with contextlib.suppress(Exception):
            connection.execute(text("CREATE INDEX IF NOT EXISTS ix_filesystem_samples_node_mount_ts_desc ON filesystem_samples (node_id, mountpoint, timestamp DESC)"))


def _migrate_process_samples_table() -> None:
    inspector = inspect(engine)
    if "process_samples" not in inspector.get_table_names():
        return
    with engine.begin() as connection:
        with contextlib.suppress(Exception):
            connection.execute(text("CREATE INDEX IF NOT EXISTS ix_process_samples_node_ts_desc ON process_samples (node_id, timestamp DESC)"))


def _knowledge_base_enabled() -> bool:
    return bool(settings.kb_id and settings.kb_jwt_token)


def _normalize_kb_results(payload: dict) -> list[dict[str, str | list[dict[str, str]]]]:
    response = KBSolveResponse.model_validate(payload)
    return [
        {
            "name": result.name,
            "description": result.description,
            "explanatory_set": [
                {"name": explanatory.name, "description": explanatory.description}
                for explanatory in result.explanatorySet
            ],
        }
        for result in response.results
    ]


@app.on_event("startup")
async def on_startup() -> None:
    init_db()


# Backward-compatible placeholders used by legacy tests.
_storage: dict[str, Deque[MetricPoint]] = defaultdict(deque)
_nodes: dict[str, NodeInfo] = {}
_latest_top_processes: dict[str, dict[str, object]] = {}
_latest_filesystems: dict[str, dict[str, object]] = {}

init_db()


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _prune(points: Deque[MetricPoint], now: datetime) -> None:
    cutoff = now - RETENTION_PERIOD
    while points and points[0].timestamp < cutoff:
        points.popleft()


def _serialize_metric(point: MetricPoint) -> dict[str, str | float]:
    item = asdict(point)
    item["timestamp"] = point.timestamp.isoformat()
    node = _nodes.get(point.node_id)
    item["display_name"] = node.display_name if node else point.node_id
    return item


def _serialize_node(node: NodeInfo) -> dict[str, str | int]:
    item = asdict(node)
    item["last_seen"] = node.last_seen.isoformat()
    return item


def _is_secure_request(request: Request) -> bool:
    if request.url.scheme == "https":
        return True
    forwarded_proto = request.headers.get("x-forwarded-proto", "")
    return forwarded_proto.lower() == "https"


@app.post("/api/auth/login")
def login(payload: LoginIn, request: Request, response: Response) -> dict[str, str]:
    with SessionLocal() as db:
        user = db.query(User).filter(User.login == payload.login.strip()).first()
        if user is None or not verify_password(payload.password, user.password_hash):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid login or password")

    token = make_session_token(payload.login.strip())
    response.set_cookie(
        "dashboard_session",
        token,
        httponly=True,
        samesite="lax",
        secure=_is_secure_request(request),
        max_age=24 * 3600,
    )
    return {"status": "ok"}


@app.post("/api/auth/logout")
def logout(response: Response) -> dict[str, str]:
    response.delete_cookie("dashboard_session")
    return {"status": "ok"}


@app.get("/api/auth/me")
def auth_me(request: Request) -> dict[str, str]:
    token = request.cookies.get("dashboard_session")
    login = decode_session_token(token) if token else None
    if not login:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")
    return {"login": login}


def _serialize_agent(agent: Agent) -> dict[str, str | bool | None]:
    return {
        "agent_id": agent.agent_id,
        "enabled": agent.enabled,
        "created_at": agent.created_at.isoformat(),
        "updated_at": agent.updated_at.isoformat(),
        "last_seen": agent.last_seen.isoformat() if agent.last_seen else None,
    }


def _is_trigger_active(trigger: Trigger, metric: Metric | None) -> bool:
    if metric is None:
        return False
    comparator = operator.gt if trigger.operator == ">" else operator.lt
    metric_value = _extract_metric_value(metric, trigger.metric_name)
    return comparator(metric_value, trigger.threshold)


def _serialize_trigger(
    trigger: Trigger,
    node_display_name: str,
    metric: Metric | None,
    include_latest: bool = True,
) -> dict[str, str | float | int | bool | None]:
    latest_value = None
    if metric is not None:
        latest_value = _extract_metric_value(metric, trigger.metric_name)
    payload: dict[str, str | float | int | bool | None] = {
        "id": trigger.id,
        "node_id": trigger.node_id,
        "node_display_name": node_display_name,
        "name": trigger.name,
        "metric_name": trigger.metric_name,
        "operator": trigger.operator,
        "threshold": trigger.threshold,
        "alert_user_id": trigger.alert_user_id,
        "action_script_id": trigger.action_script_id,
        "alert_to_login": trigger.alert_user.login if trigger.alert_user else None,
        "alert_to_display_name": trigger.alert_user.display_name if trigger.alert_user else None,
        "is_active": _is_trigger_active(trigger, metric),
        "created_at": trigger.created_at.isoformat(),
    }
    if include_latest:
        payload["latest_value"] = latest_value
    return payload


def _serialize_agent_script(script: AgentScript) -> dict[str, object]:
    try:
        tags = json.loads(script.tags_json or "[]")
    except Exception:
        tags = []
    try:
        args_schema = json.loads(script.args_schema_json or "{}")
    except Exception:
        args_schema = {}
    return {
        "script_id": script.script_id,
        "script_path": script.script_path,
        "content_hash": script.content_hash,
        "os_family": script.os_family,
        "title": script.title,
        "description": script.description,
        "tags": tags if isinstance(tags, list) else [],
        "risk_level": script.risk_level,
        "requires_confirmation": bool(script.requires_confirmation),
        "dry_run_supported": bool(script.dry_run_supported),
        "args_schema": args_schema if isinstance(args_schema, dict) else {},
        "enabled": bool(script.enabled),
        "manifest_error": script.manifest_error,
        "updated_at": script.updated_at.isoformat(),
    }


def _validate_trigger_script(db: Session, *, node_id: str, action_script_id: str) -> None:
    script = (
        db.query(AgentScript)
        .filter(AgentScript.node_id == node_id, AgentScript.script_id == action_script_id)
        .first()
    )
    if script is None:
        raise HTTPException(status_code=400, detail="Selected action_script_id is not available for this node")


def _os_family_matches_node(node_os_name: str | None, script_os_family: str | None) -> bool:
    family = (script_os_family or "any").lower()
    if family == "any":
        return True
    node_os = (node_os_name or "").lower()
    if "linux" in node_os:
        return family in {"linux", "any"}
    if "windows" in node_os:
        return family in {"windows", "any"}
    return family == "any"


def _load_json_dict(raw: str | None, default: dict[str, object] | None = None) -> dict[str, object]:
    if not raw:
        return default or {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return default or {}
    return parsed if isinstance(parsed, dict) else (default or {})


def _validate_and_apply_args_schema(args_schema: dict[str, object], args: object) -> dict[str, object]:
    if args is None:
        args_data: dict[str, object] = {}
    elif isinstance(args, dict):
        args_data = dict(args)
    else:
        raise HTTPException(status_code=400, detail="args must be a JSON object")
    if args_schema and args_schema.get("type") != "object":
        raise HTTPException(status_code=400, detail="args_schema.type must be object")
    properties = args_schema.get("properties", {})
    required = args_schema.get("required", [])
    if properties and not isinstance(properties, dict):
        raise HTTPException(status_code=400, detail="args_schema.properties must be object")
    if required and not isinstance(required, list):
        raise HTTPException(status_code=400, detail="args_schema.required must be array")
    normalized: dict[str, object] = {}
    props = properties if isinstance(properties, dict) else {}
    for key in args_data:
        if key not in props:
            raise HTTPException(status_code=400, detail=f"Unknown arg: {key}")
    for name, spec in props.items():
        if not isinstance(spec, dict):
            continue
        if name in args_data:
            value = args_data[name]
        elif "default" in spec:
            value = spec["default"]
        else:
            continue
        expected_type = spec.get("type")
        if expected_type == "string":
            if not isinstance(value, str):
                raise HTTPException(status_code=400, detail=f"Arg {name} must be string")
            if len(value) > 500:
                raise HTTPException(status_code=400, detail=f"Arg {name} is too long")
        elif expected_type == "integer":
            if not isinstance(value, int) or isinstance(value, bool):
                raise HTTPException(status_code=400, detail=f"Arg {name} must be integer")
        elif expected_type == "number":
            if not isinstance(value, (int, float)) or isinstance(value, bool):
                raise HTTPException(status_code=400, detail=f"Arg {name} must be number")
        elif expected_type == "boolean":
            if not isinstance(value, bool):
                raise HTTPException(status_code=400, detail=f"Arg {name} must be boolean")
        normalized[name] = value
    for req_name in required if isinstance(required, list) else []:
        if req_name not in normalized:
            raise HTTPException(status_code=400, detail=f"Missing required arg: {req_name}")
    return normalized


def _extract_json_object_from_llm_text(raw_text: str) -> dict[str, object]:
    text_body = (raw_text or "").strip()
    try:
        parsed = json.loads(text_body)
        if isinstance(parsed, dict):
            return parsed
    except json.JSONDecodeError:
        pass
    if "```" in text_body:
        cleaned = text_body.replace("```json", "```")
        for part in cleaned.split("```"):
            candidate = part.strip()
            if not candidate:
                continue
            try:
                parsed = json.loads(candidate)
                if isinstance(parsed, dict):
                    return parsed
            except json.JSONDecodeError:
                continue
    raise HTTPException(status_code=502, detail="LLM returned invalid JSON for script recommendations")


def _generate_llm_recommendation_text(prompt: str) -> str:
    chunks: list[str] = []
    for data in _stream_ollama_generate(prompt):
        chunk = str(data.get("response", ""))
        if chunk:
            chunks.append(chunk)
    return "".join(chunks)


def _send_trigger_alert_email(trigger: Trigger, user: User, metric_value: float) -> bool:
    if not settings.smtp_host or not settings.smtp_sender:
        logger.warning("SMTP is not configured, skipping trigger alert email for trigger_id=%s", trigger.id)
        return False

    subject = f"[Monitoring] Trigger fired: {trigger.name}"
    recipient_name = user.display_name or user.login
    body = (
        f"Hello, {recipient_name}!\n\n"
        f"Trigger '{trigger.name}' is active on node '{trigger.node_id}'.\n"
        f"Condition: {trigger.metric_name} {trigger.operator} {trigger.threshold:.2f}\n"
        f"Current value: {metric_value:.2f}\n"
        f"Triggered at (UTC): {_utcnow().isoformat()}\n"
    )
    message = EmailMessage()
    message["From"] = settings.smtp_sender
    message["To"] = user.email
    message["Subject"] = subject
    message.set_content(body)

    try:
        with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=15) as smtp:
            if settings.smtp_use_tls:
                smtp.starttls()
            if settings.smtp_username:
                smtp.login(settings.smtp_username, settings.smtp_password or "")
            smtp.send_message(message)
        return True
    except Exception:
        logger.exception("Failed to send trigger alert email for trigger_id=%s", trigger.id)
        return False


def _process_trigger_alerts(db: Session, node_id: str, metric: MetricIn) -> None:
    triggers = db.query(Trigger).filter(Trigger.node_id == node_id).all()
    for trigger in triggers:
        metric_value = _extract_metric_input_value(metric, trigger.metric_name)
        is_active = metric_value > trigger.threshold if trigger.operator == ">" else metric_value < trigger.threshold
        if not is_active:
            trigger.alert_sent = False
            trigger.remediation_sent = False
            continue
        if not trigger.alert_sent and trigger.alert_user_id is not None:
            user = db.query(User).filter(User.id == trigger.alert_user_id).first()
            if user is not None and _send_trigger_alert_email(trigger, user, metric_value):
                trigger.alert_sent = True

        if trigger.remediation_sent or not trigger.action_script_id:
            continue
        node = db.query(Node).filter(Node.display_name == trigger.node_id).first()
        if node is None or not node.agent_id:
            continue
        script = (
            db.query(AgentScript)
            .filter(
                AgentScript.node_id == trigger.node_id,
                AgentScript.agent_id == node.agent_id,
                AgentScript.script_id == trigger.action_script_id,
            )
            .first()
        )
        if script is None:
            continue
        existing = (
            db.query(AgentCommand.id)
            .filter(
                AgentCommand.trigger_id == trigger.id,
                AgentCommand.status.in_(("pending", "running")),
            )
            .first()
        )
        if existing is not None:
            trigger.remediation_sent = True
            continue
        db.add(
            AgentCommand(
                agent_id=node.agent_id,
                node_id=trigger.node_id,
                trigger_id=trigger.id,
                script_id=trigger.action_script_id,
                source="trigger",
                args_json="{}",
                dry_run=False,
                risk_level_snapshot=script.risk_level or "medium",
                status="pending",
                created_at=_utcnow(),
            )
        )
        trigger.remediation_sent = True


def _extract_metric_value(metric: Metric, metric_name: str) -> float:
    extractor = METRIC_VALUE_EXTRACTORS.get(metric_name)
    if extractor is None:
        raise ValueError(f"Unsupported metric name: {metric_name}")
    return extractor(metric)


def _extract_metric_input_value(metric: MetricIn, metric_name: str) -> float:
    extractor = METRIC_VALUE_EXTRACTORS.get(metric_name)
    if extractor is None:
        raise ValueError(f"Unsupported metric name: {metric_name}")
    return extractor(metric)


@app.post("/api/metrics")
def ingest_metric(metric: MetricIn) -> dict[str, str]:
    timestamp = metric.timestamp or _utcnow()
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)

    normalized_timestamp = timestamp.astimezone(timezone.utc)
    metrics_cutoff = _utcnow() - timedelta(hours=METRICS_RETENTION_HOURS)
    fs_cutoff = _utcnow() - timedelta(hours=FILESYSTEM_RETENTION_HOURS)
    proc_cutoff = _utcnow() - timedelta(hours=PROCESS_RETENTION_HOURS)

    with SessionLocal() as db:
        db.query(Metric).filter(Metric.timestamp < metrics_cutoff).delete(synchronize_session=False)

        node = db.query(Node).filter(Node.display_name == metric.node_id).first()
        if node is None:
            node = Node(
                display_name=metric.node_id,
                agent_id=metric.agent_id,
                os_name=metric.os_name,
                cpu_cores=metric.cpu_cores,
                ram_total_mb=metric.ram_total_mb,
                ip_address=metric.ip_address,
                last_seen=normalized_timestamp,
            )
            db.add(node)
        else:
            node.os_name = metric.os_name
            node.cpu_cores = metric.cpu_cores
            node.ram_total_mb = metric.ram_total_mb
            node.ip_address = metric.ip_address
            node.last_seen = normalized_timestamp
            if metric.agent_id:
                node.agent_id = metric.agent_id

        db.add(
            Metric(
                node_id=metric.node_id,
                cpu_percent=metric.cpu_percent,
                ram_percent=metric.ram_percent,
                uptime_seconds=metric.uptime_seconds,
                swap_percent=metric.swap_percent,
                disk_read_time_ms=metric.disk_read_time_ms,
                disk_write_time_ms=metric.disk_write_time_ms,
                net_recv_kbps=metric.net_recv_kbps,
                net_sent_kbps=metric.net_sent_kbps,
                process_count=metric.process_count,
                zombie_processes=metric.zombie_processes,
                load1=metric.load1,
                load5=metric.load5,
                load15=metric.load15,
                cpu_iowait_percent=metric.cpu_iowait_percent,
                cpu_steal_percent=metric.cpu_steal_percent,
                ram_used_mb=metric.ram_used_mb,
                ram_available_mb=metric.ram_available_mb,
                swap_used_mb=metric.swap_used_mb,
                swap_free_mb=metric.swap_free_mb,
                disk_read_kbps=metric.disk_read_kbps,
                disk_write_kbps=metric.disk_write_kbps,
                disk_read_iops=metric.disk_read_iops,
                disk_write_iops=metric.disk_write_iops,
                net_packets_recv_per_sec=metric.net_packets_recv_per_sec,
                net_packets_sent_per_sec=metric.net_packets_sent_per_sec,
                net_errors_in_per_sec=metric.net_errors_in_per_sec,
                net_errors_out_per_sec=metric.net_errors_out_per_sec,
                net_drops_in_per_sec=metric.net_drops_in_per_sec,
                net_drops_out_per_sec=metric.net_drops_out_per_sec,
                tcp_established=metric.tcp_established,
                tcp_listen=metric.tcp_listen,
                timestamp=normalized_timestamp,
            )
        )
        for fs in metric.filesystems[:100]:
            db.add(FilesystemSample(node_id=metric.node_id, device=fs.device, mountpoint=fs.mountpoint, fstype=fs.fstype, total_gb=fs.total_gb, used_gb=fs.used_gb, free_gb=fs.free_gb, percent=fs.percent, inodes_total=fs.inodes_total, inodes_used=fs.inodes_used, inodes_free=fs.inodes_free, inodes_percent=fs.inodes_percent, timestamp=normalized_timestamp))
        for proc in metric.top_cpu_processes[:10]:
            db.add(ProcessSample(node_id=metric.node_id, pid=proc.pid, name=proc.name, username=proc.username, cmdline=proc.cmdline, status=proc.status, cpu_percent=proc.cpu_percent, ram_percent=proc.ram_percent, ram_mb=proc.ram_mb, kind="cpu", timestamp=normalized_timestamp))
        for proc in metric.top_ram_processes[:10]:
            db.add(ProcessSample(node_id=metric.node_id, pid=proc.pid, name=proc.name, username=proc.username, cmdline=proc.cmdline, status=proc.status, cpu_percent=proc.cpu_percent, ram_percent=proc.ram_percent, ram_mb=proc.ram_mb, kind="ram", timestamp=normalized_timestamp))
        _process_trigger_alerts(db, metric.node_id, metric)
        db.commit()

    _latest_top_processes[metric.node_id] = {
        "node_id": metric.node_id,
        "top_cpu_processes": [item.model_dump() for item in metric.top_cpu_processes[:10]],
        "top_ram_processes": [item.model_dump() for item in metric.top_ram_processes[:10]],
        "timestamp": normalized_timestamp.isoformat(),
    }
    _latest_filesystems[metric.node_id] = {
        "node_id": metric.node_id,
        "filesystems": [item.model_dump() for item in metric.filesystems[:100]],
        "timestamp": normalized_timestamp.isoformat(),
    }
    return {"status": "ok"}


@app.post("/api/agent/metrics")
async def ingest_metric_from_agent(request: Request) -> dict[str, str]:
    raw_body = await request.body()
    request.state.raw_body = raw_body
    metric = MetricIn.model_validate_json(raw_body)
    with SessionLocal() as db:
        authenticated_agent = validate_agent_request(request, db)
    metric.agent_id = authenticated_agent.agent_id
    return ingest_metric(metric)


def _authenticate_agent_without_body(request: Request) -> str:
    request.state.raw_body = b""
    with SessionLocal() as db:
        authenticated_agent = validate_agent_request(request, db)
    return authenticated_agent.agent_id


@app.post("/api/logs")
def ingest_logs(payload: LogsIn) -> dict[str, str | int]:
    now = _utcnow()
    with SessionLocal() as db:
        node = db.query(Node).filter(Node.display_name == payload.node_id).first()
        if node is None:
            node = Node(
                display_name=payload.node_id,
                agent_id=payload.agent_id,
                os_name=payload.os_name,
                cpu_cores=payload.cpu_cores,
                ram_total_mb=payload.ram_total_mb,
                ip_address=payload.ip_address,
                last_seen=now,
            )
            db.add(node)
        else:
            node.os_name = payload.os_name
            node.cpu_cores = payload.cpu_cores
            node.ram_total_mb = payload.ram_total_mb
            node.ip_address = payload.ip_address
            node.last_seen = now
            if payload.agent_id:
                node.agent_id = payload.agent_id

        inserted_count = 0
        touched_severities: set[str] = set()
        for entry in payload.entries:
            captured_at = entry.captured_at or now
            if captured_at.tzinfo is None:
                captured_at = captured_at.replace(tzinfo=timezone.utc)
            normalized_severity = entry.severity.upper()
            db.add(
                LogEntry(
                    node_id=payload.node_id,
                    source=entry.source,
                    severity=normalized_severity,
                    message=entry.message,
                    captured_at=captured_at.astimezone(timezone.utc),
                )
            )
            touched_severities.add(normalized_severity)
            inserted_count += 1

        for severity in touched_severities:
            overflow_ids = [
                row[0]
                for row in (
                    db.query(LogEntry.id)
                    .filter(LogEntry.node_id == payload.node_id, LogEntry.severity == severity)
                    .order_by(LogEntry.captured_at.desc(), LogEntry.id.desc())
                    .offset(MAX_STORED_LOGS_PER_NODE_AND_SEVERITY)
                    .all()
                )
            ]
            if overflow_ids:
                db.query(LogEntry).filter(LogEntry.id.in_(overflow_ids)).delete(synchronize_session=False)

        db.commit()
    return {"status": "ok", "inserted": inserted_count}


@app.post("/api/agent/logs")
async def ingest_logs_from_agent(request: Request) -> dict[str, str | int]:
    raw_body = await request.body()
    request.state.raw_body = raw_body
    payload = LogsIn.model_validate_json(raw_body)
    with SessionLocal() as db:
        authenticated_agent = validate_agent_request(request, db)
    payload.agent_id = authenticated_agent.agent_id
    return ingest_logs(payload)


@app.post("/api/agent/scripts")
async def upsert_agent_scripts(request: Request) -> dict[str, str | int]:
    raw_body = await request.body()
    request.state.raw_body = raw_body
    payload = AgentScriptsIn.model_validate_json(raw_body)
    with SessionLocal() as db:
        authenticated_agent = validate_agent_request(request, db)
        node = db.query(Node).filter(Node.display_name == payload.node_id).first()
        if node is None:
            raise HTTPException(status_code=404, detail="Node not found")
        if node.agent_id != authenticated_agent.agent_id:
            raise HTTPException(status_code=403, detail="Node does not belong to authenticated agent")
        db.query(AgentScript).filter(AgentScript.node_id == payload.node_id).delete(synchronize_session=False)
        now = _utcnow()
        for script in payload.scripts:
            db.add(
                AgentScript(
                    agent_id=authenticated_agent.agent_id,
                    node_id=payload.node_id,
                    script_id=script.script_id,
                    script_path=script.script_path,
                    content_hash=script.content_hash or "",
                    os_family=script.os_family or "any",
                    title=script.title or script.script_id,
                    description=script.description or "",
                    tags_json=json.dumps(script.tags or [], ensure_ascii=False),
                    risk_level=script.risk_level or "medium",
                    requires_confirmation=bool(script.requires_confirmation),
                    dry_run_supported=bool(script.dry_run_supported),
                    args_schema_json=json.dumps(script.args_schema or {}, ensure_ascii=False),
                    enabled=bool(script.enabled),
                    manifest_error=script.manifest_error,
                    updated_at=now,
                )
            )
        db.commit()
    return {"status": "ok", "count": len(payload.scripts)}


@app.get("/api/agent/commands/next")
def get_next_agent_command(request: Request) -> dict[str, object]:
    agent_id = _authenticate_agent_without_body(request)
    with SessionLocal() as db:
        command = (
            db.query(AgentCommand)
            .filter(AgentCommand.agent_id == agent_id, AgentCommand.status == "pending")
            .order_by(AgentCommand.created_at.asc(), AgentCommand.id.asc())
            .first()
        )
        if command is None:
            return {"item": None}
        return {
            "item": {
                "id": command.id,
                "node_id": command.node_id,
                "trigger_id": command.trigger_id,
                "script_id": command.script_id,
                "args_json": command.args_json,
                "dry_run": bool(command.dry_run),
                "status": command.status,
                "created_at": command.created_at.isoformat(),
            }
        }


@app.post("/api/agent/commands/{command_id}/result")
async def update_agent_command_result(command_id: int, request: Request) -> dict[str, str | int]:
    raw_body = await request.body()
    request.state.raw_body = raw_body
    payload = AgentCommandResultIn.model_validate_json(raw_body)
    with SessionLocal() as db:
        authenticated_agent = validate_agent_request(request, db)
        command = db.query(AgentCommand).filter(AgentCommand.id == command_id).first()
        if command is None:
            raise HTTPException(status_code=404, detail="Command not found")
        if command.agent_id != authenticated_agent.agent_id:
            raise HTTPException(status_code=403, detail="Command does not belong to authenticated agent")
        command.status = payload.status
        command.stdout = payload.stdout
        command.stderr = payload.stderr
        command.exit_code = payload.exit_code
        command.started_at = payload.started_at.astimezone(timezone.utc) if payload.started_at else command.started_at
        command.finished_at = payload.finished_at.astimezone(timezone.utc) if payload.finished_at else command.finished_at
        if command.recommendation_id and payload.status in {"completed", "failed"}:
            recommendation = db.query(LlmScriptRecommendation).filter(LlmScriptRecommendation.id == command.recommendation_id).first()
            if recommendation is not None:
                recommendation.status = "executed" if payload.status == "completed" else "error"
                recommendation.error_message = payload.stderr if payload.status == "failed" else None
        db.commit()
    return {"status": "ok", "id": command_id}


@app.get("/api/logs")
def list_logs(node_id: str, severity: str = Query(default="INFO")) -> dict[str, str | list[dict[str, str]]]:
    normalized_severity = severity.upper()
    if normalized_severity not in LOG_SEVERITY_LEVELS:
        raise HTTPException(status_code=400, detail=f"Unsupported severity: {severity}")

    with SessionLocal() as db:
        node = db.query(Node).filter(Node.display_name == node_id).first()
        if node is None:
            raise HTTPException(status_code=404, detail="Node not found")

        rows = (
            db.query(LogEntry)
            .filter(LogEntry.node_id == node_id, LogEntry.severity == normalized_severity)
            .order_by(LogEntry.captured_at.desc(), LogEntry.id.desc())
            .limit(LOG_POINTS_LIMIT)
            .all()
        )
        items = [
            {
                "source": row.source,
                "severity": row.severity,
                "message": row.message,
                "captured_at": row.captured_at.isoformat(),
            }
            for row in rows
        ]
        return {
            "node_id": node.display_name,
            "display_name": node.display_name,
            "os_name": node.os_name,
            "severity": normalized_severity,
            "items": items,
        }


@app.get("/api/metrics")
def list_metrics(node_id: str | None = None) -> dict[str, list[dict[str, str | int | float | None]]]:
    now = _utcnow()
    cutoff = now - RETENTION_PERIOD
    metrics_cutoff = cutoff

    with SessionLocal() as db:
        db.query(Metric).filter(Metric.timestamp < metrics_cutoff).delete(synchronize_session=False)
        db.commit()

        query = (
            db.query(Metric, Node.display_name)
            .join(Node, Node.display_name == Metric.node_id)
            .filter(Metric.timestamp >= cutoff)
        )
        if node_id:
            node_exists = db.query(Node.display_name).filter(Node.display_name == node_id).first()
            if node_exists is None:
                raise HTTPException(status_code=404, detail="Node not found")
            query = query.filter(Metric.node_id == node_id)

        rows = query.order_by(Metric.timestamp.desc()).limit(RECENT_POINTS_LIMIT).all()
        items = [
            {
                "node_id": metric.node_id,
                "cpu_percent": metric.cpu_percent,
                "ram_percent": metric.ram_percent,
                "uptime_seconds": metric.uptime_seconds,
                "swap_percent": metric.swap_percent,
                "disk_read_time_ms": metric.disk_read_time_ms,
                "disk_write_time_ms": metric.disk_write_time_ms,
                "net_recv_kbps": metric.net_recv_kbps,
                "net_sent_kbps": metric.net_sent_kbps,
                "process_count": metric.process_count,
                "zombie_processes": metric.zombie_processes,
                "load1": metric.load1,
                "load5": metric.load5,
                "load15": metric.load15,
                "cpu_iowait_percent": metric.cpu_iowait_percent,
                "cpu_steal_percent": metric.cpu_steal_percent,
                "ram_used_mb": metric.ram_used_mb,
                "ram_available_mb": metric.ram_available_mb,
                "swap_used_mb": metric.swap_used_mb,
                "swap_free_mb": metric.swap_free_mb,
                "disk_read_kbps": metric.disk_read_kbps,
                "disk_write_kbps": metric.disk_write_kbps,
                "disk_read_iops": metric.disk_read_iops,
                "disk_write_iops": metric.disk_write_iops,
                "net_packets_recv_per_sec": metric.net_packets_recv_per_sec,
                "net_packets_sent_per_sec": metric.net_packets_sent_per_sec,
                "net_errors_in_per_sec": metric.net_errors_in_per_sec,
                "net_errors_out_per_sec": metric.net_errors_out_per_sec,
                "net_drops_in_per_sec": metric.net_drops_in_per_sec,
                "net_drops_out_per_sec": metric.net_drops_out_per_sec,
                "tcp_established": metric.tcp_established,
                "tcp_listen": metric.tcp_listen,
                "timestamp": metric.timestamp.isoformat(),
                "display_name": display_name,
            }
            for metric, display_name in rows
        ]
        items.reverse()
        return {"items": items}


@app.get("/api/top-processes")
def list_top_processes(node_id: str) -> dict[str, object]:
    with SessionLocal() as db:
        node = db.query(Node).filter(Node.display_name == node_id).first()
        if node is None:
            raise HTTPException(status_code=404, detail="Node not found")

    payload = _latest_top_processes.get(node_id)
    if payload is None:
        return {
            "node_id": node_id,
            "top_cpu_processes": [],
            "top_ram_processes": [],
            "timestamp": None,
        }
    return payload


@app.get("/api/filesystems")
def list_filesystems(node_id: str) -> dict[str, object]:
    with SessionLocal() as db:
        node = db.query(Node).filter(Node.display_name == node_id).first()
        if node is None:
            raise HTTPException(status_code=404, detail="Node not found")
        rows = (
            db.query(FilesystemSample)
            .filter(FilesystemSample.node_id == node_id)
            .order_by(FilesystemSample.timestamp.desc())
            .limit(500)
            .all()
        )

    latest_by_mount: dict[str, FilesystemSample] = {}
    for row in rows:
        latest_by_mount.setdefault(row.mountpoint, row)
    items = [
        {
            "device": row.device,
            "mountpoint": row.mountpoint,
            "fstype": row.fstype,
            "total_gb": row.total_gb,
            "used_gb": row.used_gb,
            "free_gb": row.free_gb,
            "percent": row.percent,
            "inodes_total": row.inodes_total,
            "inodes_used": row.inodes_used,
            "inodes_free": row.inodes_free,
            "inodes_percent": row.inodes_percent,
            "timestamp": row.timestamp.isoformat(),
        }
        for row in latest_by_mount.values()
    ]
    latest_ts = max((item["timestamp"] for item in items), default=None)
    return {"node_id": node_id, "filesystems": items, "timestamp": latest_ts}


@app.get("/api/metrics/history")
def list_metric_history(
    node_id: str,
    metric_name: str = Query("cpu_percent", pattern="^[a-z0-9_]+$"),
    interval_minutes: int = Query(15, ge=1, le=60),
) -> dict[str, str | list[dict[str, str | float]]]:
    if metric_name not in METRIC_VALUE_EXTRACTORS:
        raise HTTPException(status_code=400, detail=f"Unsupported metric: {metric_name}")
    now = _utcnow()
    cutoff = max(now - RETENTION_PERIOD, now - timedelta(minutes=interval_minutes))

    with SessionLocal() as db:
        db.query(Metric).filter(Metric.timestamp < now - RETENTION_PERIOD).delete(synchronize_session=False)
        db.commit()

        node = db.query(Node).filter(Node.display_name == node_id).first()
        if node is None:
            raise HTTPException(status_code=404, detail="Node not found")

        rows = (
            db.query(Metric)
            .filter(Metric.node_id == node_id, Metric.timestamp >= cutoff)
            .order_by(Metric.timestamp.asc())
            .all()
        )
        items = [
            {
                "timestamp": metric.timestamp.isoformat(),
                "value": _extract_metric_value(metric, metric_name),
            }
            for metric in rows
        ]

        return {"node_id": node_id, "metric_name": metric_name, "items": items}


@app.get("/api/nodes")
def list_nodes() -> dict[str, list[dict[str, str | int | bool | None]]]:
    with SessionLocal() as db:
        rows = (
            db.query(Node, Agent)
            .outerjoin(Agent, Agent.agent_id == Node.agent_id)
            .order_by(func.lower(Node.display_name))
            .all()
        )
        items = [
            {
                "node_id": node.display_name,
                "display_name": node.display_name,
                "os_name": node.os_name,
                "cpu_cores": node.cpu_cores,
                "ram_total_mb": node.ram_total_mb,
                "ip_address": node.ip_address,
                "last_seen": node.last_seen.isoformat(),
                "agent_id": node.agent_id,
                "agent_enabled": agent.enabled if agent else None,
            }
            for node, agent in rows
        ]
        return {"items": items}


@app.get("/api/nodes/{node_id}/scripts")
def list_node_scripts(node_id: str) -> dict[str, object]:
    with SessionLocal() as db:
        node = db.query(Node).filter(Node.display_name == node_id).first()
        if node is None:
            raise HTTPException(status_code=404, detail="Node not found")
        scripts = (
            db.query(AgentScript)
            .filter(AgentScript.node_id == node_id)
            .order_by(func.lower(AgentScript.script_id))
            .all()
        )
        return {"node_id": node_id, "items": [_serialize_agent_script(item) for item in scripts]}


@app.patch("/api/nodes/{node_id}")
def rename_node(node_id: str, payload: NodeRenameIn) -> dict[str, str | int]:
    next_name = payload.display_name.strip()
    if not next_name:
        raise HTTPException(status_code=400, detail="Display name cannot be empty")
    with SessionLocal() as db:
        node = db.query(Node).filter(Node.display_name == node_id).first()
        if node is None:
            raise HTTPException(status_code=404, detail="Node not found")
        duplicate = db.query(Node).filter(Node.display_name == next_name).first()
        if duplicate is not None and duplicate.display_name != node_id:
            raise HTTPException(status_code=409, detail="Node with this display name already exists")

        db.query(Metric).filter(Metric.node_id == node_id).update({"node_id": next_name}, synchronize_session=False)
        db.query(LogEntry).filter(LogEntry.node_id == node_id).update({"node_id": next_name}, synchronize_session=False)
        db.query(Trigger).filter(Trigger.node_id == node_id).update({"node_id": next_name}, synchronize_session=False)
        db.query(AgentScript).filter(AgentScript.node_id == node_id).update({"node_id": next_name}, synchronize_session=False)
        db.query(AgentCommand).filter(AgentCommand.node_id == node_id).update({"node_id": next_name}, synchronize_session=False)
        db.query(FilesystemSample).filter(FilesystemSample.node_id == node_id).update({"node_id": next_name}, synchronize_session=False)
        db.query(ProcessSample).filter(ProcessSample.node_id == node_id).update({"node_id": next_name}, synchronize_session=False)
        node.display_name = next_name
        db.commit()
        db.refresh(node)

        top_payload = _latest_top_processes.pop(node_id, None)
        if top_payload is not None:
            top_payload["node_id"] = next_name
            _latest_top_processes[next_name] = top_payload

        filesystems_payload = _latest_filesystems.pop(node_id, None)
        if filesystems_payload is not None:
            filesystems_payload["node_id"] = next_name
            _latest_filesystems[next_name] = filesystems_payload

        return {
            "node_id": node.display_name,
            "display_name": node.display_name,
            "os_name": node.os_name,
            "cpu_cores": node.cpu_cores,
            "ram_total_mb": node.ram_total_mb,
            "ip_address": node.ip_address,
            "last_seen": node.last_seen.isoformat(),
        }


@app.delete("/api/nodes/{node_id}")
def delete_node(node_id: str) -> dict[str, str]:
    with SessionLocal() as db:
        node = db.query(Node).filter(Node.display_name == node_id).first()
        if node is None:
            raise HTTPException(status_code=404, detail="Node not found")
        db.delete(node)
        db.commit()

    _latest_top_processes.pop(node_id, None)
    _latest_filesystems.pop(node_id, None)
    return {"status": "ok"}


@app.get("/api/agents")
def list_agents() -> dict[str, list[dict[str, str | bool | None]]]:
    with SessionLocal() as db:
        rows = db.query(Agent).order_by(Agent.created_at.desc()).all()
        return {"items": [_serialize_agent(agent) for agent in rows]}


@app.post("/api/agents/register")
def register_new_agent() -> dict[str, str]:
    with SessionLocal() as db:
        agent_id, secret = register_agent(db)
        return {"agent_id": agent_id, "secret": secret}


@app.post("/api/agents/{agent_id}/disable")
def disable_agent(agent_id: str) -> dict[str, str | bool]:
    with SessionLocal() as db:
        agent = db.query(Agent).filter(Agent.agent_id == agent_id).first()
        if agent is None:
            raise HTTPException(status_code=404, detail="Agent not found")
        agent.enabled = False
        agent.updated_at = _utcnow()
        db.commit()
        return {"agent_id": agent.agent_id, "enabled": agent.enabled}


@app.post("/api/agents/{agent_id}/enable")
def enable_agent(agent_id: str) -> dict[str, str | bool]:
    with SessionLocal() as db:
        agent = db.query(Agent).filter(Agent.agent_id == agent_id).first()
        if agent is None:
            raise HTTPException(status_code=404, detail="Agent not found")
        agent.enabled = True
        agent.updated_at = _utcnow()
        db.commit()
        return {"agent_id": agent.agent_id, "enabled": agent.enabled}


@app.post("/api/agents/{agent_id}/rotate-secret")
def rotate_agent_secret_endpoint(agent_id: str) -> dict[str, str]:
    with SessionLocal() as db:
        agent = db.query(Agent).filter(Agent.agent_id == agent_id).first()
        if agent is None:
            raise HTTPException(status_code=404, detail="Agent not found")
        secret = rotate_agent_secret(db, agent)
        return {"agent_id": agent.agent_id, "secret": secret}


@app.post("/api/triggers")
def create_trigger(payload: TriggerCreateIn) -> dict[str, str | float | int | bool | None]:
    with SessionLocal() as db:
        node = db.query(Node).filter(Node.display_name == payload.node_id).first()
        if node is None:
            raise HTTPException(status_code=404, detail="Node not found")
        if payload.alert_user_id is not None:
            alert_user = db.query(User).filter(User.id == payload.alert_user_id).first()
            if alert_user is None:
                raise HTTPException(status_code=404, detail="User for alert not found")
        _validate_trigger_script(db, node_id=payload.node_id, action_script_id=payload.action_script_id)

        trigger = Trigger(
            node_id=payload.node_id,
            name=payload.name,
            metric_name=payload.metric_name,
            operator=payload.operator,
            threshold=payload.threshold,
            alert_user_id=payload.alert_user_id,
            action_script_id=payload.action_script_id,
            alert_sent=False,
            remediation_sent=False,
            created_at=_utcnow(),
        )
        db.add(trigger)
        db.commit()
        db.refresh(trigger)

        latest_metric = (
            db.query(Metric)
            .filter(Metric.node_id == payload.node_id)
            .order_by(Metric.timestamp.desc())
            .first()
        )
        return _serialize_trigger(trigger, node.display_name, latest_metric)


@app.patch("/api/triggers/{trigger_id}")
def update_trigger(trigger_id: int, payload: TriggerUpdateIn) -> dict[str, str | float | int | bool | None]:
    with SessionLocal() as db:
        trigger = db.query(Trigger).filter(Trigger.id == trigger_id).first()
        if trigger is None:
            raise HTTPException(status_code=404, detail="Trigger not found")
        if payload.alert_user_id is not None:
            alert_user = db.query(User).filter(User.id == payload.alert_user_id).first()
            if alert_user is None:
                raise HTTPException(status_code=404, detail="User for alert not found")
        _validate_trigger_script(db, node_id=trigger.node_id, action_script_id=payload.action_script_id)

        trigger.name = payload.name
        trigger.threshold = payload.threshold
        trigger.alert_user_id = payload.alert_user_id
        trigger.action_script_id = payload.action_script_id
        trigger.alert_sent = False
        trigger.remediation_sent = False
        db.commit()
        db.refresh(trigger)

        node = db.query(Node).filter(Node.display_name == trigger.node_id).first()
        if node is None:
            raise HTTPException(status_code=404, detail="Node not found")

        latest_metric = (
            db.query(Metric)
            .filter(Metric.node_id == trigger.node_id)
            .order_by(Metric.timestamp.desc())
            .first()
        )
        return _serialize_trigger(trigger, node.display_name, latest_metric)


@app.delete("/api/triggers/{trigger_id}")
def delete_trigger(trigger_id: int) -> dict[str, str]:
    with SessionLocal() as db:
        trigger = db.query(Trigger).filter(Trigger.id == trigger_id).first()
        if trigger is None:
            raise HTTPException(status_code=404, detail="Trigger not found")
        db.delete(trigger)
        db.commit()
    return {"status": "ok"}


@app.get("/api/triggers")
def list_triggers(node_id: str | None = None) -> dict[str, list[dict[str, str | float | int | bool | None]]]:
    with SessionLocal() as db:
        query = db.query(Trigger, Node.display_name).join(Node, Node.display_name == Trigger.node_id)
        if node_id:
            node_exists = db.query(Node.display_name).filter(Node.display_name == node_id).first()
            if node_exists is None:
                raise HTTPException(status_code=404, detail="Node not found")
            query = query.filter(Trigger.node_id == node_id)

        rows = query.order_by(Trigger.created_at.desc(), Trigger.id.desc()).all()
        latest_metrics_by_node: dict[str, Metric] = {}
        for trigger, _display_name in rows:
            if trigger.node_id in latest_metrics_by_node:
                continue
            metric = (
                db.query(Metric)
                .filter(Metric.node_id == trigger.node_id)
                .order_by(Metric.timestamp.desc())
                .first()
            )
            if metric is not None:
                latest_metrics_by_node[trigger.node_id] = metric

        items = [
            _serialize_trigger(trigger, display_name, latest_metrics_by_node.get(trigger.node_id))
            for trigger, display_name in rows
        ]
        return {"items": items}


@app.get("/api/problems")
def list_problems() -> dict[str, list[dict[str, str | float | int | bool | None]]]:
    with SessionLocal() as db:
        rows = (
            db.query(Trigger, Node.display_name)
            .join(Node, Node.display_name == Trigger.node_id)
            .order_by(Trigger.created_at.desc(), Trigger.id.desc())
            .all()
        )
        latest_metrics_by_node: dict[str, Metric] = {}
        for trigger, _display_name in rows:
            if trigger.node_id in latest_metrics_by_node:
                continue
            metric = (
                db.query(Metric)
                .filter(Metric.node_id == trigger.node_id)
                .order_by(Metric.timestamp.desc())
                .first()
            )
            if metric is not None:
                latest_metrics_by_node[trigger.node_id] = metric

        active = []
        for trigger, display_name in rows:
            metric = latest_metrics_by_node.get(trigger.node_id)
            if _is_trigger_active(trigger, metric):
                active.append(_serialize_trigger(trigger, display_name, metric))
        return {"items": active}


KB_AGENT_PRESET_NAME = "agent_preset"


def _kb_headers(accept: str = "*/*") -> dict[str, str]:
    assert settings.kb_jwt_token is not None
    return {"accept": accept, "Authorization": settings.kb_jwt_token}


def _kb_payload_kb_id() -> int | str:
    assert settings.kb_id is not None
    with contextlib.suppress(ValueError):
        return int(settings.kb_id)
    return settings.kb_id


def _active_trigger_names_for_node(db: Session, node_id: str) -> list[str]:
    triggers = db.query(Trigger).filter(Trigger.node_id == node_id).all()
    metric = db.query(Metric).filter(Metric.node_id == node_id).order_by(Metric.timestamp.desc()).first()
    active_names = [trigger.name for trigger in triggers if _is_trigger_active(trigger, metric)]
    return list(dict.fromkeys(active_names))


def _match_kb_nodes(objects_payload: list[dict], trigger_names: list[str]) -> list[int]:
    names = set(trigger_names)
    matched: list[int] = []
    for item in objects_payload:
        if item.get("name") not in names:
            continue
        node_id = item.get("nodeId")
        if isinstance(node_id, int):
            matched.append(node_id)
    return list(dict.fromkeys(matched))


async def _get_or_create_agent_preset_id(client: httpx.AsyncClient, kb_id: str) -> int:
    presets_response = await client.get(
        f"{settings.kb_api_base_url.rstrip('/')}/api/Test/getPresets/{kb_id}",
        headers=_kb_headers(),
    )
    presets_response.raise_for_status()
    presets = presets_response.json()
    preset = next((item for item in presets if item.get("presetName") == KB_AGENT_PRESET_NAME), None)
    if preset is not None and isinstance(preset.get("id"), int):
        return preset["id"]

    create_response = await client.post(
        f"{settings.kb_api_base_url.rstrip('/')}/api/Test/savePresets",
        headers={**_kb_headers(), "Content-Type": "application/json-patch+json"},
        json={"presetName": KB_AGENT_PRESET_NAME, "kbId": _kb_payload_kb_id(), "nodesId": []},
    )
    create_response.raise_for_status()

    presets_response = await client.get(
        f"{settings.kb_api_base_url.rstrip('/')}/api/Test/getPresets/{kb_id}",
        headers=_kb_headers(),
    )
    presets_response.raise_for_status()
    presets = presets_response.json()
    preset = next((item for item in presets if item.get("presetName") == KB_AGENT_PRESET_NAME), None)
    if preset is None or not isinstance(preset.get("id"), int):
        raise HTTPException(status_code=502, detail="Failed to create or resolve agent_preset id in KB service")
    return preset["id"]


@app.get("/api/knowledge-base")
async def get_knowledge_base(node_id: str = Query(..., min_length=1, max_length=100)) -> dict[str, object]:
    global _kb_last_updated
    if not _knowledge_base_enabled():
        return {
            "status": "disabled",
            "node_id": node_id,
            "last_updated": _kb_last_updated.isoformat() if _kb_last_updated else None,
            "error": "Knowledge Base integration disabled: missing KB_ID or KB_JWT_TOKEN.",
            "items": [],
            "active_triggers": [],
            "matched_node_ids": [],
        }

    with SessionLocal() as db:
        active_triggers = _active_trigger_names_for_node(db, node_id)

    assert settings.kb_id is not None
    kb_id = settings.kb_id

    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            objects_response = await client.get(
                f"{settings.kb_api_base_url.rstrip('/')}/api/Objects/GetAllObjects/{kb_id}",
                headers=_kb_headers("text/plain"),
            )
            objects_response.raise_for_status()
            objects_payload = objects_response.json()
            matched_node_ids = _match_kb_nodes(objects_payload, active_triggers)

            preset_id = await _get_or_create_agent_preset_id(client, kb_id)

            update_response = await client.put(
                f"{settings.kb_api_base_url.rstrip('/')}/api/Test/update/{preset_id}",
                headers={**_kb_headers(), "Content-Type": "application/json-patch+json"},
                json={"presetName": KB_AGENT_PRESET_NAME, "kbId": _kb_payload_kb_id(), "nodesId": matched_node_ids},
            )
            update_response.raise_for_status()

            solve_response = await client.post(
                f"{settings.kb_api_base_url.rstrip('/')}/solve/{kb_id}",
                headers={**_kb_headers(), "Content-Type": "application/json-patch+json"},
                json={"presetName": KB_AGENT_PRESET_NAME},
            )
            solve_response.raise_for_status()
            items = _normalize_kb_results(solve_response.json())
    except httpx.HTTPError as exc:
        logger.exception("Knowledge Base request failed")
        return {
            "status": "error",
            "node_id": node_id,
            "last_updated": _kb_last_updated.isoformat() if _kb_last_updated else None,
            "error": str(exc),
            "items": [],
            "active_triggers": active_triggers,
            "matched_node_ids": [],
        }

    _kb_last_updated = _utcnow()
    return {
        "status": "ok",
        "node_id": node_id,
        "last_updated": _kb_last_updated.isoformat(),
        "error": None,
        "items": items,
        "active_triggers": active_triggers,
        "matched_node_ids": matched_node_ids,
    }


def _sanitize_log_for_llm(message: str) -> str:
    sanitized = message.replace("\\n", " ").replace("\\r", " ").replace("\\t", " ")
    sanitized = sanitized.replace("\n", " ").replace("\r", " ").replace("\t", " ")
    sanitized = re.sub(r"[\x00-\x1f\x7f]", " ", sanitized)
    sanitized = re.sub(r"\s+", " ", sanitized)
    return sanitized.strip()


def _collect_logs_for_llm(db: Session, node_id: str, per_severity_limit: int = 20) -> list[dict[str, str]]:
    severities = LOG_SEVERITY_LEVELS[2:]
    cutoff = _utcnow() - timedelta(hours=1)
    items: list[dict[str, str]] = []
    for severity in severities:
        rows = (
            db.query(LogEntry)
            .filter(LogEntry.node_id == node_id, LogEntry.severity == severity, LogEntry.captured_at >= cutoff)
            .order_by(LogEntry.captured_at.desc(), LogEntry.id.desc())
            .limit(per_severity_limit)
            .all()
        )
        for row in rows:
            items.append(
                {
                    "source": row.source,
                    "severity": row.severity,
                    "message": _sanitize_log_for_llm(row.message),
                    "captured_at": row.captured_at.isoformat(),
                }
            )
    items.sort(key=lambda item: item["captured_at"], reverse=True)
    return items[:100]


def _build_node_analysis_prompt(payload: dict[str, object]) -> str:
    return (
        "Ты SRE-инженер мониторинга. Проанализируй состояние узла и ответь на русском языке.\n\n"
        "Структура ответа:\n"
        "1) Краткий вердикт о состоянии (OK / DEGRADED / CRITICAL).\n"
        "2) Обнаруженные проблемы (если есть).\n"
        "3) Приоритетный план действий (по шагам).\n"
        "4) Что проверить после исправления.\n\n"
        "Важно:\n"
        "- Учитывай только данные из входного JSON.\n"
        "- Не выдумывай факты, явно отмечай нехватку данных.\n"
        "- Если проблем нет, дай профилактические рекомендации.\n\n"
        "Данные узла:\n"
        f"{json.dumps(payload, ensure_ascii=False, indent=2)}"
    )


def _stream_ollama_generate(prompt: str) -> object:
    api_key = os.getenv("OLLAMA_API_KEY")
    headers = {"Authorization": f"Bearer {api_key}"} if api_key else None
    client = ollama.Client(host=OLLAMA_HOST, headers=headers)
    return client.generate(
        model=OLLAMA_MODEL,
        prompt=prompt,
        keep_alive=OLLAMA_KEEP_ALIVE,
        stream=True,
    )


@app.get("/api/llm/context")
def get_llm_node_context(node_id: str = Query(..., min_length=1, max_length=100), window_minutes: int = Query(60, ge=10, le=1440)) -> dict[str, object]:
    with SessionLocal() as db:
        node = db.query(Node).filter(Node.display_name == node_id).first()
        if node is None:
            raise HTTPException(status_code=404, detail="Node not found")
        context = build_node_analysis_context(
            db,
            node_id=node_id,
            window_minutes=window_minutes,
            max_recent_points=LLM_CONTEXT_MAX_RECENT_POINTS,
            max_log_signatures=LLM_CONTEXT_MAX_LOG_SIGNATURES,
            max_log_examples_per_signature=LLM_CONTEXT_MAX_LOG_EXAMPLES_PER_SIGNATURE,
        )
    return context


@app.post("/api/llm/analyze-node")
async def analyze_node_with_llm(payload: LLMNodeAnalysisIn) -> StreamingResponse:
    with SessionLocal() as db:
        node = db.query(Node).filter(Node.display_name == payload.node_id).first()
        if node is None:
            raise HTTPException(status_code=404, detail="Node not found")
        context = build_node_analysis_context(
            db,
            node_id=payload.node_id,
            window_minutes=payload.window_minutes,
            max_recent_points=LLM_CONTEXT_MAX_RECENT_POINTS,
            max_log_signatures=LLM_CONTEXT_MAX_LOG_SIGNATURES,
            max_log_examples_per_signature=LLM_CONTEXT_MAX_LOG_EXAMPLES_PER_SIGNATURE,
        )
    try:
        kb_payload = await get_knowledge_base(payload.node_id)
    except Exception as exc:
        kb_payload = {"status": "error", "error": str(exc), "items": [], "active_triggers": [], "matched_node_ids": [], "last_updated": None}
    context["knowledge_base"] = {
        "status": kb_payload.get("status") if isinstance(kb_payload, dict) else "error",
        "error": kb_payload.get("error") if isinstance(kb_payload, dict) else "Unknown KB response",
        "items": kb_payload.get("items", []) if isinstance(kb_payload, dict) else [],
        "active_triggers": kb_payload.get("active_triggers", []) if isinstance(kb_payload, dict) else [],
        "matched_node_ids": kb_payload.get("matched_node_ids", []) if isinstance(kb_payload, dict) else [],
        "last_updated": kb_payload.get("last_updated") if isinstance(kb_payload, dict) else None,
    }

    prompt = build_node_analysis_prompt(context)

    def stream_llm_response() -> object:
        try:
            for data in _stream_ollama_generate(prompt):
                chunk = str(data.get("response", ""))
                if chunk:
                    yield chunk
            if payload.include_raw:
                yield "\n\n---\nRaw context JSON:\n" + json.dumps(context, ensure_ascii=False, indent=2)
        except Exception as exc:
            raise HTTPException(status_code=502, detail=f"LLM service error: {exc}") from exc

    return StreamingResponse(stream_llm_response(), media_type="text/plain; charset=utf-8")


@app.post("/api/llm/recommend-scripts")
def recommend_scripts_with_llm(payload: LLMScriptRecommendIn) -> dict[str, object]:
    with SessionLocal() as db:
        node = db.query(Node).filter(Node.display_name == payload.node_id).first()
        if node is None:
            raise HTTPException(status_code=404, detail="Node not found")
        context = build_node_analysis_context(
            db,
            node_id=payload.node_id,
            window_minutes=payload.window_minutes,
            max_recent_points=LLM_CONTEXT_MAX_RECENT_POINTS,
            max_log_signatures=LLM_CONTEXT_MAX_LOG_SIGNATURES,
            max_log_examples_per_signature=LLM_CONTEXT_MAX_LOG_EXAMPLES_PER_SIGNATURE,
        )
        available_scripts = {item["script_id"]: item for item in context.get("available_scripts", []) if isinstance(item, dict)}
        if not available_scripts:
            return {"node_id": payload.node_id, "summary": "Нет доступных remediation scripts для узла.", "recommendations": []}
        prompt = build_script_recommendation_prompt(context)
        prompt_hash = f"sha256:{hashlib.sha256(prompt.encode('utf-8')).hexdigest()}"
        try:
            raw_text = _generate_llm_recommendation_text(prompt)
            llm_payload = _extract_json_object_from_llm_text(raw_text)
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(status_code=502, detail=f"LLM service error: {exc}") from exc
        summary = str(llm_payload.get("summary") or "").strip()
        incoming_recommendations = llm_payload.get("recommendations", [])
        if not isinstance(incoming_recommendations, list):
            raise HTTPException(status_code=502, detail="LLM payload field 'recommendations' must be a list")
        stored: list[dict[str, object]] = []
        now = _utcnow()
        for item in incoming_recommendations:
            if not isinstance(item, dict):
                continue
            script_id = str(item.get("script_id") or "").strip()
            script = available_scripts.get(script_id)
            if not script:
                continue
            confidence = float(item.get("confidence") or 0.0)
            if not (0.0 <= confidence <= 1.0):
                continue
            risk_level = str(item.get("risk_level") or script.get("risk_level") or "medium").lower()
            if risk_level not in {"low", "medium", "high"}:
                continue
            requires_confirmation = bool(item.get("requires_confirmation", script.get("requires_confirmation", True)))
            if risk_level in {"medium", "high"}:
                requires_confirmation = True
            args_schema = script.get("args_schema") if isinstance(script.get("args_schema"), dict) else {}
            try:
                normalized_args = _validate_and_apply_args_schema(args_schema, item.get("args", {}))
            except HTTPException:
                continue
            dry_run_supported = bool(script.get("dry_run_supported"))
            dry_run_first = bool(item.get("dry_run_first", dry_run_supported))
            if dry_run_supported and not dry_run_first:
                reason = str(item.get("reason") or "").lower()
                if "why not" not in reason and "почему" not in reason:
                    dry_run_first = True
            rec = LlmScriptRecommendation(
                node_id=payload.node_id,
                agent_id=node.agent_id or "",
                script_id=script_id,
                script_content_hash=str(script.get("content_hash") or ""),
                args_json=json.dumps(normalized_args, ensure_ascii=False),
                summary=summary,
                reason=str(item.get("reason") or ""),
                evidence_json=json.dumps(item.get("evidence") if isinstance(item.get("evidence"), list) else [], ensure_ascii=False),
                confidence=confidence,
                risk_level=risk_level,
                requires_confirmation=requires_confirmation,
                dry_run_first=dry_run_first,
                status="proposed",
                model_name=OLLAMA_MODEL,
                prompt_hash=prompt_hash,
                created_at=now,
            )
            db.add(rec)
            db.flush()
            stored.append(
                {
                    "id": rec.id,
                    "script_id": rec.script_id,
                    "confidence": rec.confidence,
                    "risk_level": rec.risk_level,
                    "requires_confirmation": rec.requires_confirmation,
                    "dry_run_first": rec.dry_run_first,
                    "reason": rec.reason,
                    "evidence": json.loads(rec.evidence_json or "[]"),
                    "args": json.loads(rec.args_json or "{}"),
                    "status": rec.status,
                }
            )
        db.commit()
    return {"node_id": payload.node_id, "summary": summary, "recommendations": stored}


@app.get("/api/llm/script-recommendations")
def list_script_recommendations(node_id: str = Query(..., min_length=1, max_length=100)) -> dict[str, object]:
    with SessionLocal() as db:
        rows = (
            db.query(LlmScriptRecommendation)
            .filter(LlmScriptRecommendation.node_id == node_id)
            .order_by(LlmScriptRecommendation.created_at.desc(), LlmScriptRecommendation.id.desc())
            .limit(100)
            .all()
        )
        return {
            "items": [
                {
                    "id": row.id,
                    "node_id": row.node_id,
                    "script_id": row.script_id,
                    "confidence": row.confidence,
                    "risk_level": row.risk_level,
                    "requires_confirmation": row.requires_confirmation,
                    "dry_run_first": row.dry_run_first,
                    "summary": row.summary,
                    "reason": row.reason,
                    "evidence": json.loads(row.evidence_json or "[]"),
                    "args": json.loads(row.args_json or "{}"),
                    "status": row.status,
                    "created_at": row.created_at.isoformat(),
                }
                for row in rows
            ]
        }


@app.post("/api/llm/script-recommendations/{recommendation_id}/approve")
def approve_script_recommendation(recommendation_id: int, payload: LLMRecommendationApproveIn, request: Request) -> dict[str, object]:
    with SessionLocal() as db:
        recommendation = db.query(LlmScriptRecommendation).filter(LlmScriptRecommendation.id == recommendation_id).first()
        if recommendation is None:
            raise HTTPException(status_code=404, detail="Recommendation not found")
        if recommendation.status != "proposed":
            raise HTTPException(status_code=409, detail="Recommendation is not in proposed status")
        node = db.query(Node).filter(Node.display_name == recommendation.node_id).first()
        if node is None:
            raise HTTPException(status_code=404, detail="Node not found")
        script = (
            db.query(AgentScript)
            .filter(AgentScript.node_id == recommendation.node_id, AgentScript.script_id == recommendation.script_id)
            .first()
        )
        if script is None:
            raise HTTPException(status_code=404, detail="Script not found for recommendation")
        if not script.enabled or script.manifest_error:
            raise HTTPException(status_code=400, detail="Script is disabled or has manifest_error")
        if recommendation.script_content_hash != script.content_hash:
            raise HTTPException(status_code=409, detail="Script changed since recommendation")
        if not _os_family_matches_node(node.os_name, script.os_family):
            raise HTTPException(status_code=400, detail="Script OS family is incompatible with node")
        args_schema = _load_json_dict(script.args_schema_json, {})
        recommendation_args = _load_json_dict(recommendation.args_json, {})
        normalized_args = _validate_and_apply_args_schema(args_schema, recommendation_args)
        if recommendation.risk_level in {"medium", "high"} or recommendation.requires_confirmation:
            if not payload.confirm:
                raise HTTPException(status_code=400, detail="Explicit confirmation is required")
        existing = (
            db.query(AgentCommand.id)
            .filter(
                AgentCommand.node_id == recommendation.node_id,
                AgentCommand.script_id == recommendation.script_id,
                AgentCommand.status.in_(("pending", "running")),
            )
            .first()
        )
        if existing is not None:
            raise HTTPException(status_code=409, detail="Pending/running command already exists for this script")
        requested_login = decode_session_token(request.cookies.get("dashboard_session") or "")
        requested_user_id = None
        if requested_login:
            user = db.query(User).filter(User.login == requested_login).first()
            requested_user_id = user.id if user else None
        dry_run_value = bool(payload.dry_run or recommendation.dry_run_first)
        command = AgentCommand(
            agent_id=recommendation.agent_id or (node.agent_id or ""),
            node_id=recommendation.node_id,
            trigger_id=None,
            script_id=recommendation.script_id,
            status="pending",
            source="llm",
            recommendation_id=recommendation.id,
            args_json=json.dumps(normalized_args, ensure_ascii=False),
            dry_run=dry_run_value,
            requested_by_user_id=requested_user_id,
            risk_level_snapshot=recommendation.risk_level,
            created_at=_utcnow(),
        )
        db.add(command)
        db.flush()
        recommendation.status = "approved"
        recommendation.approved_at = _utcnow()
        recommendation.executed_command_id = command.id
        db.commit()
        return {
            "status": "ok",
            "command": {
                "id": command.id,
                "node_id": command.node_id,
                "script_id": command.script_id,
                "status": command.status,
                "dry_run": command.dry_run,
                "source": command.source,
            },
        }


@app.post("/api/llm/script-recommendations/{recommendation_id}/reject")
def reject_script_recommendation(recommendation_id: int, payload: LLMRecommendationRejectIn) -> dict[str, object]:
    with SessionLocal() as db:
        recommendation = db.query(LlmScriptRecommendation).filter(LlmScriptRecommendation.id == recommendation_id).first()
        if recommendation is None:
            raise HTTPException(status_code=404, detail="Recommendation not found")
        if recommendation.status != "proposed":
            raise HTTPException(status_code=409, detail="Recommendation is not in proposed status")
        recommendation.status = "rejected"
        recommendation.rejected_at = _utcnow()
        if payload.reason:
            recommendation.error_message = payload.reason
        db.commit()
    return {"status": "ok"}


@app.post("/api/llm/generate")
async def generate_llm(payload: LLMGenerateIn) -> dict[str, str]:
    chunks: list[str] = []
    try:
        for data in _stream_ollama_generate(payload.prompt):
            chunk = str(data.get("response", ""))
            if chunk:
                chunks.append(chunk)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"LLM service error: {exc}") from exc

    return {"response": "".join(chunks)}


@app.get("/", response_class=HTMLResponse)
def dashboard() -> str:
    return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Monitoring KB MVP</title>
    <link
        rel="icon"
        type="image/svg+xml"
        href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'%3E%3Crect width='64' height='64' rx='12' fill='%23189de8'/%3E%3Ctext x='50%25' y='52%25' dominant-baseline='middle' text-anchor='middle' font-family='Inter,Arial,sans-serif' font-size='38' font-weight='700' fill='white'%3EM%3C/text%3E%3C/svg%3E"
    />
    <style>
        @import url("https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@300;400;600&family=IBM+Plex+Mono:wght@400&display=swap");

        :root {
            --cds-background: #ffffff;
            --cds-layer-01: #f4f4f4;
            --cds-layer-hover: #e8e8e8;
            --cds-layer-02: #e0e0e0;
            --cds-text-primary: #161616;
            --cds-text-secondary: #525252;
            --cds-text-helper: #6f6f6f;
            --cds-border-subtle: #c6c6c6;
            --cds-border-strong: #8d8d8d;
            --cds-link-primary: #0f62fe;
            --cds-link-primary-hover: #0043ce;
            --cds-button-primary: #0f62fe;
            --cds-button-primary-hover: #0353e9;
            --cds-button-primary-active: #002d9c;
            --cds-button-secondary: #393939;
            --cds-button-secondary-hover: #4c4c4c;
            --cds-button-danger: #da1e28;
            --cds-focus: #0f62fe;
            --cds-support-error: #da1e28;
            --cds-shadow: 0 2px 6px rgba(0, 0, 0, 0.28);
        }

        * { box-sizing: border-box; }

        body {
            margin: 0;
            background: var(--cds-background);
            color: var(--cds-text-primary);
            font-family: "IBM Plex Sans", "Helvetica Neue", Arial, sans-serif;
            font-size: 14px;
            line-height: 1.29;
            letter-spacing: 0.16px;
        }

        .layout {
            display: grid;
            grid-template-columns: 256px 1fr;
            min-height: 100vh;
            background: var(--cds-background);
        }

        .sidebar {
            position: sticky;
            top: 0;
            height: 100vh;
            overflow-y: auto;
            background: #161616;
            border-right: 1px solid #393939;
            padding: 16px 12px;
            transition: width 0.2s ease, padding 0.2s ease, border-color 0.2s ease;
            z-index: 10;
        }

        .brand {
            display: flex;
            align-items: flex-start;
            justify-content: space-between;
            gap: 8px;
            padding: 8px 8px 16px;
            margin-bottom: 16px;
            border-bottom: 1px solid #393939;
        }

        .brand-title {
            margin: 0;
            color: #f4f4f4;
            font-size: 20px;
            line-height: 1.4;
            font-weight: 400;
            letter-spacing: 0;
        }

        .brand-kicker {
            margin: 0 0 4px;
            color: #c6c6c6;
            font-size: 12px;
            line-height: 1.33;
            letter-spacing: 0.32px;
            text-transform: uppercase;
            font-family: "IBM Plex Mono", Menlo, monospace;
        }

        .nav-btn,
        button,
        select,
        input,
        textarea {
            appearance: none;
            border-radius: 0;
            font-family: inherit;
        }

        .nav-btn,
        button { cursor: pointer; }

        .nav {
            display: flex;
            flex-direction: column;
            gap: 4px;
        }

        .nav-btn {
            width: 100%;
            border: none;
            border-left: 2px solid transparent;
            text-align: left;
            padding: 10px 12px;
            background: transparent;
            color: #c6c6c6;
            font-size: 14px;
            letter-spacing: 0.16px;
            min-height: 40px;
        }

        .nav-btn:hover {
            color: #ffffff;
            background: #262626;
        }

        .nav-btn.active {
            color: #ffffff;
            border-left-color: var(--cds-link-primary);
            background: #262626;
        }

        .content {
            padding: 32px;
            background: var(--cds-background);
        }

        .panel {
            background: var(--cds-layer-01);
            border: 1px solid var(--cds-border-subtle);
            border-radius: 0;
            padding: 24px;
            margin-bottom: 16px;
        }

        h1, h2, h3, p { margin-top: 0; }
        h1 {
            font-size: 42px;
            line-height: 1.19;
            font-weight: 300;
            letter-spacing: 0;
            margin-bottom: 8px;
        }
        h2 {
            font-size: 32px;
            line-height: 1.25;
            font-weight: 400;
            letter-spacing: 0;
            margin-bottom: 8px;
        }
        h3 {
            font-size: 20px;
            line-height: 1.4;
            font-weight: 600;
            letter-spacing: 0;
            margin-bottom: 12px;
        }

        .meta {
            color: var(--cds-text-secondary);
            font-size: 12px;
            line-height: 1.33;
            letter-spacing: 0.32px;
        }

        .toolbar {
            display: flex;
            flex-wrap: wrap;
            gap: 12px 16px;
            align-items: flex-end;
            margin-bottom: 16px;
        }

        .toolbar label {
            display: flex;
            flex-direction: column;
            gap: 4px;
            min-width: 220px;
        }

        input,
        textarea,
        select {
            min-height: 40px;
            padding: 0 16px;
            border: none;
            border-bottom: 2px solid var(--cds-border-subtle);
            background: #ffffff;
            color: var(--cds-text-primary);
            font-size: 14px;
            line-height: 1.29;
            letter-spacing: 0.16px;
        }

        select {
            padding-right: 44px;
            background-image: linear-gradient(45deg, transparent 50%, #161616 50%), linear-gradient(135deg, #161616 50%, transparent 50%);
            background-position: calc(100% - 20px) calc(50% + 1px), calc(100% - 14px) calc(50% + 1px);
            background-size: 6px 6px, 6px 6px;
            background-repeat: no-repeat;
        }

        select:hover,
        input:hover,
        textarea:hover { border-bottom-color: var(--cds-border-strong); }

        select:focus,
        input:focus,
        textarea:focus {
            outline: none;
            border-bottom-color: var(--cds-focus);
        }

        button:focus,
        .nav-btn:focus,
        .menu-btn:focus {
            outline: none;
            box-shadow: none;
        }

        textarea {
            width: 100%;
            min-height: 220px;
            resize: vertical;
            padding-top: 12px;
            padding-bottom: 12px;
        }

        button {
            min-height: 40px;
            padding: 10px 18px;
            border: 1px solid transparent;
            background: var(--cds-button-primary);
            color: #ffffff;
            font-size: 14px;
            font-weight: 400;
            letter-spacing: 0.16px;
        }

        button:hover { background: var(--cds-button-primary-hover); }
        button:active { background: var(--cds-button-primary-active); }

        button.secondary {
            background: var(--cds-button-secondary);
            border-color: var(--cds-button-secondary);
        }
        button.secondary:hover { background: var(--cds-button-secondary-hover); }

        button.danger {
            background: var(--cds-button-danger);
            border-color: var(--cds-button-danger);
        }

        table {
            width: 100%;
            border-collapse: collapse;
            border: 1px solid var(--cds-border-subtle);
            margin-top: 16px;
            background: #ffffff;
        }

        th,
        td {
            padding: 12px;
            border-bottom: 1px solid var(--cds-border-subtle);
            text-align: left;
            vertical-align: top;
        }

        th {
            background: #f4f4f4;
            color: var(--cds-text-secondary);
            font-size: 12px;
            line-height: 1.33;
            letter-spacing: 0.32px;
            font-weight: 600;
            text-transform: uppercase;
        }

        tr:hover td { background: #edf5ff; }
        tr:last-child td { border-bottom: none; }

        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 16px;
            margin-bottom: 16px;
        }

        .stat {
            background: #ffffff;
            border: 1px solid var(--cds-border-subtle);
            padding: 16px;
            border-radius: 0;
        }

        .stat-label {
            color: var(--cds-text-helper);
            font-size: 12px;
            line-height: 1.33;
            letter-spacing: 0.32px;
            text-transform: uppercase;
            font-family: "IBM Plex Mono", Menlo, monospace;
        }

        .stat-value {
            margin-top: 8px;
            font-size: 24px;
            line-height: 1.33;
            letter-spacing: 0;
            font-weight: 400;
        }

        .menu-cell { position: relative; text-align: right; width: 64px; }

        .menu-btn {
            min-height: 32px;
            padding: 4px 10px;
            line-height: 1;
        }

        .menu-popover {
            position: fixed;
            z-index: 9999;
            display: flex;
            flex-direction: column;
            gap: 6px;
            padding: 8px;
            border: 1px solid var(--cds-border-subtle);
            background: #ffffff;
            min-width: 170px;
            box-shadow: var(--cds-shadow);
        }

        .menu-popover button {
            width: 100%;
            text-align: left;
            min-height: 36px;
        }

        #global-menu[hidden] { display: none !important; }

        .empty,
        .status { color: var(--cds-text-secondary); padding: 12px 0; }

        .error { color: var(--cds-support-error); }

        .modal-backdrop {
            position: fixed;
            inset: 0;
            background: rgba(22, 22, 22, 0.55);
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 16px;
            z-index: 10000;
        }

        .modal {
            width: min(640px, 100%);
            background: #ffffff;
            border: 1px solid var(--cds-border-subtle);
            border-radius: 0;
            padding: 16px;
            box-shadow: var(--cds-shadow);
        }

        .credentials-grid {
            display: grid;
            grid-template-columns: 1fr auto;
            gap: 8px;
            align-items: end;
        }

        .credentials-grid input {
            width: 100%;
            font-family: "IBM Plex Mono", Menlo, monospace;
        }

        .modal-actions {
            display: flex;
            gap: 8px;
            justify-content: flex-end;
            margin-top: 12px;
        }

        .modal-form-grid {
            display: grid;
            gap: 12px;
            margin-top: 8px;
        }

        #llm-output {
            width: 100%;
            min-height: 280px;
            max-height: 280px;
            overflow: auto;
            border: 1px solid var(--cds-border-subtle);
            border-radius: 0;
            background: #ffffff;
            padding: 12px;
            line-height: 1.45;
        }

        #llm-output pre {
            overflow: auto;
            background: #f4f4f4;
            border: 1px solid var(--cds-border-subtle);
            border-radius: 0;
            padding: 10px;
        }

        #llm-output code {
            font-family: "IBM Plex Mono", Menlo, monospace;
        }

        .llm-grid {
            display: grid;
            grid-template-columns: repeat(2, minmax(280px, 1fr));
            gap: 16px;
        }

        [hidden] { display: none !important; }

        @media (max-width: 900px) {
            .layout { grid-template-columns: 1fr; }
            .content { padding: 16px; }
            .sidebar { position: fixed; width: 256px; }
            .llm-grid { grid-template-columns: 1fr; }
            .toolbar label { min-width: 100%; }
        }
    </style>
</head>
<body>
    <div class="layout">
        <aside id="sidebar" class="sidebar">
            <div class="brand">
                <div class="brand-copy">
                    <p class="brand-title">Monitoring KB</p>
                </div>
            </div>
            <nav class="nav">
                <button class="nav-btn active" data-tab="latest" type="button"><span class="nav-label">Latest metrics</span></button>
                <button class="nav-btn" data-tab="nodes" type="button"><span class="nav-label">Nodes</span></button>
                <button class="nav-btn" data-tab="graphs" type="button"><span class="nav-label">Graphs</span></button>
                <button class="nav-btn" data-tab="triggers" type="button"><span class="nav-label">Triggers</span></button>
                <button class="nav-btn" data-tab="problems" type="button"><span class="nav-label">Problems</span></button>
                <button class="nav-btn" data-tab="logs" type="button"><span class="nav-label">Logs</span></button>
                <button class="nav-btn" data-tab="top" type="button"><span class="nav-label">Top</span></button>
                <button class="nav-btn" data-tab="knowledge-base" type="button"><span class="nav-label">Knowledge Base</span></button>
                <button class="nav-btn" data-tab="users" type="button"><span class="nav-label">Users</span></button>
                <button class="nav-btn" data-tab="llm" type="button"><span class="nav-label">LLM</span></button>
                <button id="sign-out" class="nav-btn" type="button"><span class="nav-label">Sign out</span></button>
            </nav>
        </aside>
        <main class="content">
            <section class="panel tab-panel" data-panel="latest">
                <div class="page-header">
                    <h1>Latest metrics</h1>
                    <p class="meta">Choose a node and inspect the latest 10 samples for all metrics received from it.</p>
                </div>
                <div class="toolbar">
                    <label>
                        <span class="meta">Node</span><br />
                        <select id="node-select"></select>
                    </label>
                    <button id="refresh-latest" type="button">Refresh now</button>
                </div>
                <div id="latest-summary" class="grid"></div>
                <div id="latest-status" class="status"></div>
                <h3>Filesystems</h3>
                <table>
                    <thead>
                        <tr>
                            <th>Device</th>
                            <th>Mountpoint</th>
                            <th>FS type</th>
                            <th>Total (GB)</th>
                            <th>Used (GB)</th>
                            <th>Free (GB)</th>
                            <th>Used %</th>
                            <th>Inodes %</th>
                            <th>Sample time (UTC+3)</th>
                        </tr>
                    </thead>
                    <tbody id="filesystems-body"></tbody>
                </table>
                <table>
                    <thead>
                        <tr>
                            <th>Time (UTC+3)</th>
                            <th>Node</th>
                            <th>CPU %</th>
                            <th>RAM %</th>
                            <th>Swap %</th>
                            <th>Uptime (s)</th>
                            <th>Disk read await (ms/op)</th>
                            <th>Disk write await (ms/op)</th>
                            <th>Net recv (KB/s)</th>
                            <th>Net sent (KB/s)</th>
                            <th>Processes</th>
                            <th>Zombie processes</th>
                        </tr>
                    </thead>
                    <tbody id="metrics-body"></tbody>
                </table>
            </section>

            <section class="panel tab-panel" data-panel="nodes" hidden>
                <div class="page-header">
                    <h2>Nodes</h2>
                    <p class="meta">Connected nodes with system info and the ability to rename them.</p>
                </div>
                <div class="toolbar">
                    <button id="register-node-agent" type="button">Register new node</button>
                </div>
                <div id="nodes-status" class="status"></div>
                <table>
                    <thead>
                        <tr>
                            <th>Name</th>
                            <th>OS</th>
                            <th>CPU cores</th>
                            <th>RAM</th>
                            <th>IP</th>
                            <th>Last seen (UTC+3)</th>
                            <th>Agent status</th>
                            <th></th>
                        </tr>
                    </thead>
                    <tbody id="nodes-body"></tbody>
                </table>
            </section>

            <section class="panel tab-panel" data-panel="graphs" hidden>
                <div class="page-header">
                    <h2>Graphs</h2>
                    <p class="meta">Select node, metric and interval to inspect the trend.</p>
                </div>
                <div class="toolbar">
                    <label>
                        <span class="meta">Node</span><br />
                        <select id="graph-node-select"></select>
                    </label>
                    <label>
                        <span class="meta">Metric</span><br />
                        <select id="graph-metric-select">
                            <option value="cpu_percent">CPU %</option>
                            <option value="ram_percent">RAM %</option>
                            <option value="swap_percent">Swap %</option>
                            <option value="uptime_seconds">Uptime (s)</option>
                            <option value="disk_read_time_ms">Disk read await (ms/op)</option>
                            <option value="disk_write_time_ms">Disk write await (ms/op)</option>
                            <option value="net_recv_kbps">Net recv (KB/s)</option>
                            <option value="net_sent_kbps">Net sent (KB/s)</option>
                            <option value="process_count">Processes</option>
                            <option value="zombie_processes">Zombie processes</option>
                        </select>
                    </label>
                    <label>
                        <span class="meta">Interval</span><br />
                        <select id="graph-interval-select">
                            <option value="5">5 minutes</option>
                            <option value="15" selected>15 minutes</option>
                            <option value="30">30 minutes</option>
                            <option value="60">60 minutes</option>
                        </select>
                    </label>
                    <button id="refresh-graph" type="button">Refresh graph</button>
                </div>
                <div id="graph-status" class="status"></div>
                <svg id="graph-canvas" viewBox="0 0 1200 360" width="100%" height="360" role="img" aria-label="Metric graph">
                    <rect x="0" y="0" width="1200" height="360" fill="#ffffff" stroke="#c6c6c6"></rect>
                    <g id="graph-y-grid"></g>
                    <line x1="80" y1="300" x2="1160" y2="300" stroke="#c6c6c6" />
                    <line x1="80" y1="40" x2="80" y2="300" stroke="#c6c6c6" />
                    <g id="graph-y-labels"></g>
                    <g id="graph-x-labels"></g>
                    <polyline id="graph-line" fill="none" stroke="#0f62fe" stroke-width="1.8" points=""></polyline>
                    <g id="graph-points"></g>
                    <text id="graph-title" x="80" y="24" fill="#525252">No data</text>
                </svg>
            </section>

            <section class="panel tab-panel" data-panel="triggers" hidden>
                <div class="page-header">
                    <h2>Triggers</h2>
                    <p class="meta">Create trigger rules for a node and inspect existing trigger definitions.</p>
                </div>
                <form id="create-trigger-form" class="toolbar">
                    <label>
                        <span class="meta">Node</span><br />
                        <select id="trigger-node-select" required></select>
                    </label>
                    <label>
                        <span class="meta">Name</span><br />
                        <input id="trigger-name-input" type="text" maxlength="120" value="Resource threshold" required />
                    </label>
                    <label>
                        <span class="meta">Metric</span><br />
                        <select id="trigger-metric-select">
                            <option value="cpu_percent">CPU %</option>
                            <option value="ram_percent">RAM %</option>
                            <option value="swap_percent">Swap %</option>
                            <option value="uptime_seconds">Uptime (s)</option>
                            <option value="disk_read_time_ms">Disk read await (ms/op)</option>
                            <option value="disk_write_time_ms">Disk write await (ms/op)</option>
                            <option value="net_recv_kbps">Net recv (KB/s)</option>
                            <option value="net_sent_kbps">Net sent (KB/s)</option>
                            <option value="process_count">Processes</option>
                            <option value="zombie_processes">Zombie processes</option>
                        </select>
                    </label>
                    <label>
                        <span class="meta">Operator</span><br />
                        <select id="trigger-operator-select">
                            <option value=">">&gt;</option>
                            <option value="<">&lt;</option>
                        </select>
                    </label>
                    <label>
                        <span class="meta">Alert to</span><br />
                        <select id="trigger-alert-user-select"></select>
                    </label>
                    <label>
                        <span class="meta">Action script</span><br />
                        <select id="trigger-action-script-select" required></select>
                    </label>
                    <label>
                        <span class="meta">Threshold</span><br />
                        <input id="trigger-threshold-input" type="number" min="0" step="0.1" value="80" required />
                    </label>
                    <button type="submit">Create trigger</button>
                </form>
                <div id="triggers-status" class="status"></div>
                <table>
                    <thead>
                        <tr>
                            <th>Node</th>
                            <th>Name</th>
                            <th>Condition</th>
                            <th>Action script</th>
                            <th>Latest value</th>
                            <th>Alert to</th>
                            <th>Status</th>
                            <th>Created (UTC+3)</th>
                            <th></th>
                        </tr>
                    </thead>
                    <tbody id="triggers-body"></tbody>
                </table>
            </section>

            <section class="panel tab-panel" data-panel="problems" hidden>
                <div class="page-header">
                    <h2>Problems</h2>
                    <p class="meta">All currently active triggers across all nodes.</p>
                </div>
                <div class="toolbar">
                    <button id="refresh-problems" type="button">Refresh problems</button>
                </div>
                <div id="problems-status" class="status"></div>
                <table>
                    <thead>
                        <tr>
                            <th>Node</th>
                            <th>Trigger</th>
                            <th>Condition</th>
                            <th>Latest value</th>
                            <th>Created (UTC+3)</th>
                        </tr>
                    </thead>
                    <tbody id="problems-body"></tbody>
                </table>
            </section>

            <section class="panel tab-panel" data-panel="logs" hidden>
                <div class="page-header">
                    <h2>Logs</h2>
                    <p class="meta">Latest 100 log entries by selected node and severity.</p>
                </div>
                <div class="toolbar">
                    <label>
                        <span class="meta">Node</span><br />
                        <select id="logs-node-select"></select>
                    </label>
                    <label>
                        <span class="meta">Severity</span><br />
                        <select id="logs-severity-select">
                            <option value="DEBUG">DEBUG</option>
                            <option value="INFO" selected>INFO</option>
                            <option value="NOTICE">NOTICE</option>
                            <option value="WARNING">WARNING</option>
                            <option value="ERROR">ERROR</option>
                            <option value="CRITICAL">CRITICAL</option>
                            <option value="ALERT">ALERT</option>
                            <option value="EMERGENCY">EMERGENCY</option>
                        </select>
                    </label>
                    <button id="refresh-logs" type="button">Refresh logs</button>
                </div>
                <div id="logs-status" class="status"></div>
                <table>
                    <thead>
                        <tr>
                            <th>Time (UTC+3)</th>
                            <th>Source</th>
                            <th>Severity</th>
                            <th>Entry</th>
                        </tr>
                    </thead>
                    <tbody id="logs-body"></tbody>
                </table>
            </section>

            <section class="panel tab-panel" data-panel="top" hidden>
                <div class="page-header">
                    <h2>Top</h2>
                    <p class="meta">Top 10 processes by CPU and RAM on the selected node.</p>
                </div>
                <div class="toolbar">
                    <label>
                        <span class="meta">Node</span><br />
                        <select id="top-node-select"></select>
                    </label>
                    <button id="refresh-top" type="button">Refresh top</button>
                </div>
                <div id="top-status" class="status"></div>
                <div class="llm-grid">
                    <div>
                        <h3>CPU top 10</h3>
                        <table>
                            <thead>
                                <tr>
                                    <th>PID</th>
                                    <th>Process</th>
                                    <th>CPU %</th>
                                    <th>RAM</th>
                                </tr>
                            </thead>
                            <tbody id="top-cpu-body"></tbody>
                        </table>
                    </div>
                    <div>
                        <h3>RAM top 10</h3>
                        <table>
                            <thead>
                                <tr>
                                    <th>PID</th>
                                    <th>Process</th>
                                    <th>RAM %</th>
                                    <th>RAM</th>
                                </tr>
                            </thead>
                            <tbody id="top-ram-body"></tbody>
                        </table>
                    </div>
                </div>
            </section>

            <section class="panel tab-panel" data-panel="knowledge-base" hidden>
                <div class="page-header">
                    <h2>Knowledge Base</h2>
                    <p class="meta">Select a node to run KB solve based on active triggers from this node.</p>
                </div>
                <div class="toolbar">
                    <label>
                        <span class="meta">Node</span><br />
                        <select id="kb-node-select"></select>
                    </label>
                    <button id="refresh-knowledge-base" type="button">Run KB solve</button>
                </div>
                <div id="knowledge-base-status" class="status"></div>
                <table>
                    <thead>
                        <tr>
                            <th>Result name</th>
                            <th>Description</th>
                            <th>Explanatory set</th>
                        </tr>
                    </thead>
                    <tbody id="knowledge-base-body"></tbody>
                </table>
            </section>

            
            <section class="panel tab-panel" data-panel="users" hidden>
                <div class="page-header">
                    <h2>Users</h2>
                    <p class="meta">Manage dashboard users. Required fields: Login, Password, Email.</p>
                </div>
                <form id="create-user-form" class="toolbar">
                    <label><span class="meta">Login</span><br /><input id="user-login-input" type="text" maxlength="64" required /></label>
                    <label><span class="meta">Password</span><br /><input id="user-password-input" type="password" maxlength="256" required /></label>
                    <label><span class="meta">Email</span><br /><input id="user-email-input" type="email" maxlength="255" required /></label>
                    <label><span class="meta">Display name</span><br /><input id="user-display-name-input" type="text" maxlength="255" /></label>
                    <button type="submit">Create user</button>
                </form>
                <div id="users-status" class="status"></div>
                <table>
                    <thead><tr><th>Login</th><th>Email</th><th>Display name</th><th>Created (UTC+3)</th><th></th></tr></thead>
                    <tbody id="users-body"></tbody>
                </table>
            </section>

            <section class="panel tab-panel" data-panel="llm" hidden>
                <div class="page-header">
                    <h2>LLM</h2>
                    <p class="meta">LLM анализирует тренды метрик, filesystem, логи, top processes, triggers, remediation и Knowledge Base.</p>
                </div>
                <div class="toolbar">
                    <label><span class="meta">Node</span><br /><select id="llm-node-select"></select></label>
                    <label><span class="meta">Window</span><br /><select id="llm-window-select"><option value="10">10m</option><option value="30">30m</option><option value="60" selected>60m</option><option value="360">6h</option><option value="1440">24h</option></select></label>
                    <label><input id="llm-show-context" type="checkbox" /> Show context JSON</label>
                    <button id="run-llm" type="button">Analyze node</button>
                    <button id="recommend-llm-scripts" type="button" class="secondary">Recommend scripts</button>
                    <button id="refresh-llm-recommendations" type="button" class="secondary">Refresh recommendations</button>
                </div>
                <details id="llm-context-wrap" hidden><summary>Context JSON</summary><pre id="llm-context-json"></pre></details>
                <div>
                    <label>
                        <span class="meta">Model output</span><br />
                        <div id="llm-output"></div>
                    </label>
                </div>
                <h3>Recommended remediation scripts</h3>
                <div id="llm-recommendations"></div>
                <div id="llm-status" class="status"></div>
            </section>
        </main>
    </div>

    <div id="login-modal-backdrop" class="modal-backdrop" hidden>
        <div class="modal">
            <h3>Sign in</h3>
            <p class="meta">Enter dashboard credentials.</p>
            <div class="modal-form-grid">
                <label><span class="meta">Login</span><br /><input id="auth-login" type="text" maxlength="64" /></label>
                <label><span class="meta">Password</span><br /><input id="auth-password" type="password" maxlength="256" /></label>
            </div>
            <div id="auth-status" class="status"></div>
            <div class="modal-actions"><button id="auth-sign-in" type="button">Sign in</button></div>
        </div>
    </div>

    <div id="global-menu" class="menu-popover" hidden></div>
    <div id="credentials-modal-backdrop" class="modal-backdrop" hidden>
        <div class="modal">
            <h3 id="credentials-modal-title">Agent credentials</h3>
            <p class="meta">Скопируйте значения и сохраните в безопасном месте.</p>
            <div class="credentials-grid">
                <label>
                    <span class="meta">AGENT_ID</span><br />
                    <input id="credentials-agent-id" type="text" readonly />
                </label>
                <button id="copy-agent-id" type="button" class="secondary">Copy</button>
                <label>
                    <span class="meta">AGENT_SECRET</span><br />
                    <input id="credentials-agent-secret" type="text" readonly />
                </label>
                <button id="copy-agent-secret" type="button" class="secondary">Copy</button>
            </div>
            <div class="modal-actions">
                <button id="close-credentials-modal" type="button">Close</button>
            </div>
        </div>
    </div>
    <div id="action-modal-backdrop" class="modal-backdrop" hidden>
        <div class="modal">
            <h3 id="action-modal-title">Confirm action</h3>
            <p id="action-modal-description" class="meta"></p>
            <div id="action-modal-fields" class="modal-form-grid"></div>
            <div class="modal-actions">
                <button id="action-modal-cancel" type="button" class="secondary">Cancel</button>
                <button id="action-modal-confirm" type="button">Confirm</button>
            </div>
        </div>
    </div>

    <script>
        const METRIC_META = {
            cpu_percent: { label: 'CPU %', unit: '%' },
            ram_percent: { label: 'RAM %', unit: '%' },
            swap_percent: { label: 'Swap %', unit: '%' },
            uptime_seconds: { label: 'Uptime (s)', unit: 's' },
            disk_read_time_ms: { label: 'Disk read await (ms/op)', unit: ' ms/op' },
            disk_write_time_ms: { label: 'Disk write await (ms/op)', unit: ' ms/op' },
            net_recv_kbps: { label: 'Net recv (KB/s)', unit: ' KB/s' },
            net_sent_kbps: { label: 'Net sent (KB/s)', unit: ' KB/s' },
            process_count: { label: 'Processes', unit: '' },
            zombie_processes: { label: 'Zombie processes', unit: '' },
            load1: { label: 'Load 1m', unit: '' },
            load5: { label: 'Load 5m', unit: '' },
            load15: { label: 'Load 15m', unit: '' },
            cpu_iowait_percent: { label: 'CPU iowait %', unit: '%' },
            cpu_steal_percent: { label: 'CPU steal %', unit: '%' },
            ram_used_mb: { label: 'RAM used MB', unit: ' MB' },
            ram_available_mb: { label: 'RAM available MB', unit: ' MB' },
            swap_used_mb: { label: 'Swap used MB', unit: ' MB' },
            swap_free_mb: { label: 'Swap free MB', unit: ' MB' },
            disk_read_kbps: { label: 'Disk read KB/s', unit: ' KB/s' },
            disk_write_kbps: { label: 'Disk write KB/s', unit: ' KB/s' },
            disk_read_iops: { label: 'Disk read IOPS', unit: '' },
            disk_write_iops: { label: 'Disk write IOPS', unit: '' },
            net_packets_recv_per_sec: { label: 'Packets recv/s', unit: '' },
            net_packets_sent_per_sec: { label: 'Packets sent/s', unit: '' },
            net_errors_in_per_sec: { label: 'Net errors in/s', unit: '' },
            net_errors_out_per_sec: { label: 'Net errors out/s', unit: '' },
            net_drops_in_per_sec: { label: 'Net drops in/s', unit: '' },
            net_drops_out_per_sec: { label: 'Net drops out/s', unit: '' },
            tcp_established: { label: 'TCP established', unit: '' },
            tcp_listen: { label: 'TCP listen', unit: '' },
        };

        const state = {
            nodes: [],
            agents: [],
            triggers: [],
            problems: [],
            knowledgeBase: [],
            users: [],
            nodeScripts: {},
            currentLogin: '',
            latestSelectedNodeId: '',
            graphSelectedNodeId: '',
            triggerSelectedNodeId: '',
            logsSelectedNodeId: '',
            logsSelectedSeverity: 'INFO',
            topSelectedNodeId: '',
            kbSelectedNodeId: '',
            llmSelectedNodeId: '',
            llmRawOutput: '',
            llmWindowMinutes: 60,
            llmShowContext: false,
            llmContextJson: null,
            llmRecommendations: [],
            activeMenuKey: '',
            activeMenuData: null,
            activeTab: 'latest',
            actionModalHandler: null,
        };

        async function fetchJson(url, options) {
            const response = await fetch(url, options);
            if (!response.ok) {
                let message = `Request failed with status ${response.status}`;
                try {
                    const payload = await response.json();
                    if (payload.detail) message = payload.detail;
                } catch (error) {
                    // no-op
                }
                throw new Error(message);
            }
            return response.json();
        }

        function formatUtc(value) {
            return new Date(value).toLocaleString('en-GB', { timeZone: 'Europe/Moscow' });
        }

        function formatRamMb(value) {
            return `${(value / 1024).toFixed(1)} GB (${value} MB)`;
        }


        function populateGraphMetricOptions() {
            const select = document.getElementById('graph-metric-select');
            const current = select.value || 'cpu_percent';
            select.innerHTML = '';
            Object.entries(METRIC_META).forEach(([metricName, meta]) => {
                const option = document.createElement('option');
                option.value = metricName;
                option.textContent = meta.label;
                select.appendChild(option);
            });
            if (METRIC_META[current]) {
                select.value = current;
            }
        }

        function metricLabel(metricName) {
            return METRIC_META[metricName]?.label || metricName;
        }

        function metricUnit(metricName) {
            return METRIC_META[metricName]?.unit || '';
        }

        function formatMetricValue(metricName, value) {
            const numeric = Number(value);
            if (!Number.isFinite(numeric)) {
                return 'No data';
            }
            const unit = metricUnit(metricName);
            if (metricName === 'zombie_processes' || metricName === 'process_count') {
                return `${Math.round(numeric)}${unit}`;
            }
            return `${numeric.toFixed(2)}${unit}`;
        }

        function escapeHtml(value) {
            return value
                .replaceAll('&', '&amp;')
                .replaceAll('<', '&lt;')
                .replaceAll('>', '&gt;')
                .replaceAll('"', '&quot;')
                .replaceAll("'", '&#39;');
        }

        function markdownToHtml(markdown) {
            const codeBlocks = [];
            const withoutCode = markdown.replace(/```([\\s\\S]*?)```/g, (_match, code) => {
                const token = `__CODE_BLOCK_${codeBlocks.length}__`;
                codeBlocks.push(`<pre><code>${escapeHtml(code.trim())}</code></pre>`);
                return token;
            });
            let html = escapeHtml(withoutCode);
            html = html
                .replace(/^### (.*)$/gm, '<h3>$1</h3>')
                .replace(/^## (.*)$/gm, '<h2>$1</h2>')
                .replace(/^# (.*)$/gm, '<h1>$1</h1>')
                .replace(/\\*\\*(.*?)\\*\\*/g, '<strong>$1</strong>')
                .replace(/\\*(.*?)\\*/g, '<em>$1</em>')
                .replace(/`([^`]+)`/g, '<code>$1</code>')
                .replace(/^- (.*)$/gm, '<li>$1</li>');
            html = html.replace(/(<li>.*<\\/li>)/gs, '<ul>$1</ul>');
            html = html
                .split(/\\n{2,}/)
                .map((block) => {
                    if (block.startsWith('<h') || block.startsWith('<ul>') || block.startsWith('__CODE_BLOCK_')) {
                        return block;
                    }
                    return `<p>${block.replaceAll('\\n', '<br />')}</p>`;
                })
                .join('');
            codeBlocks.forEach((codeBlock, index) => {
                html = html.replace(`__CODE_BLOCK_${index}__`, codeBlock);
            });
            return html;
        }


        function renderLlmContext() {
            const wrap = document.getElementById('llm-context-wrap');
            const pre = document.getElementById('llm-context-json');
            if (!state.llmShowContext) {
                wrap.hidden = true;
                pre.textContent = '';
                return;
            }
            wrap.hidden = false;
            pre.textContent = state.llmContextJson ? JSON.stringify(state.llmContextJson, null, 2) : 'No context loaded';
        }

        function renderLlmOutput() {
            document.getElementById('llm-output').innerHTML = state.llmRawOutput
                ? markdownToHtml(state.llmRawOutput)
                : '<p class="meta">Оценка состояния узла и рекомендации...</p>';
        }

        function renderLlmRecommendations() {
            const box = document.getElementById('llm-recommendations');
            if (!box) return;
            if (!state.llmRecommendations.length) {
                box.innerHTML = '<p class="meta">No recommended scripts yet.</p>';
                return;
            }
            box.innerHTML = state.llmRecommendations.map((item) => `
                <div class="stat">
                    <div><strong>${escapeHtml(item.script_id || 'unknown')}</strong> · ${escapeHtml(item.risk_level || 'medium')} · confidence ${(Number(item.confidence || 0) * 100).toFixed(0)}%</div>
                    <div class="meta">Status: ${escapeHtml(item.status || '-')} · dry_run_first: ${item.dry_run_first ? 'true' : 'false'}</div>
                    <p>${escapeHtml(item.reason || '')}</p>
                    <pre>${escapeHtml(JSON.stringify(item.args || {}, null, 2))}</pre>
                    <div class="meta">Evidence: ${escapeHtml((item.evidence || []).join(' | '))}</div>
                    <div style="display:flex; gap:8px; margin-top:8px;">
                        <button type="button" class="secondary" onclick="runLlmRecommendation(${Number(item.id)}, true)">Run dry-run</button>
                        <button type="button" onclick="runLlmRecommendation(${Number(item.id)}, false)">Run</button>
                        <button type="button" class="danger" onclick="rejectLlmRecommendation(${Number(item.id)})">Reject</button>
                    </div>
                </div>
            `).join('');
        }

        function renderTabs() {
            document.querySelectorAll('.nav-btn').forEach((button) => {
                button.classList.toggle('active', button.dataset.tab === state.activeTab);
            });
            document.querySelectorAll('.tab-panel').forEach((panel) => {
                panel.hidden = panel.dataset.panel !== state.activeTab;
            });
        }

        function renderNodeOptions() {
            const select = document.getElementById('node-select');
            const graphSelect = document.getElementById('graph-node-select');
            const triggerSelect = document.getElementById('trigger-node-select');
            const logsSelect = document.getElementById('logs-node-select');
            const topSelect = document.getElementById('top-node-select');
            const kbSelect = document.getElementById('kb-node-select');
            const llmSelect = document.getElementById('llm-node-select');
            select.innerHTML = '';
            graphSelect.innerHTML = '';
            triggerSelect.innerHTML = '';
            logsSelect.innerHTML = '';
            topSelect.innerHTML = '';
            kbSelect.innerHTML = '';
            llmSelect.innerHTML = '';
            if (!state.nodes.length) {
                const option = document.createElement('option');
                option.textContent = 'No nodes yet';
                option.value = '';
                select.appendChild(option);
                graphSelect.appendChild(option.cloneNode(true));
                triggerSelect.appendChild(option.cloneNode(true));
                logsSelect.appendChild(option.cloneNode(true));
                topSelect.appendChild(option.cloneNode(true));
                kbSelect.appendChild(option.cloneNode(true));
                llmSelect.appendChild(option.cloneNode(true));
                select.disabled = true;
                graphSelect.disabled = true;
                triggerSelect.disabled = true;
                logsSelect.disabled = true;
                topSelect.disabled = true;
                kbSelect.disabled = true;
                llmSelect.disabled = true;
                return;
            }

            select.disabled = false;
            graphSelect.disabled = false;
            triggerSelect.disabled = false;
            logsSelect.disabled = false;
            topSelect.disabled = false;
            kbSelect.disabled = false;
            llmSelect.disabled = false;
            if (!state.latestSelectedNodeId || !state.nodes.some((node) => node.node_id === state.latestSelectedNodeId)) {
                state.latestSelectedNodeId = state.nodes[0].node_id;
            }
            if (!state.graphSelectedNodeId || !state.nodes.some((node) => node.node_id === state.graphSelectedNodeId)) {
                state.graphSelectedNodeId = state.latestSelectedNodeId;
            }
            if (!state.triggerSelectedNodeId || !state.nodes.some((node) => node.node_id === state.triggerSelectedNodeId)) {
                state.triggerSelectedNodeId = state.latestSelectedNodeId;
            }
            if (!state.logsSelectedNodeId || !state.nodes.some((node) => node.node_id === state.logsSelectedNodeId)) {
                state.logsSelectedNodeId = state.latestSelectedNodeId;
            }
            if (!state.topSelectedNodeId || !state.nodes.some((node) => node.node_id === state.topSelectedNodeId)) {
                state.topSelectedNodeId = state.latestSelectedNodeId;
            }
            if (!state.kbSelectedNodeId || !state.nodes.some((node) => node.node_id === state.kbSelectedNodeId)) {
                state.kbSelectedNodeId = state.latestSelectedNodeId;
            }
            if (!state.llmSelectedNodeId || !state.nodes.some((node) => node.node_id === state.llmSelectedNodeId)) {
                state.llmSelectedNodeId = state.latestSelectedNodeId;
            }

            for (const node of state.nodes) {
                const option = document.createElement('option');
                option.value = node.node_id;
                option.textContent = node.display_name;
                select.appendChild(option);
                graphSelect.appendChild(option.cloneNode(true));
                triggerSelect.appendChild(option.cloneNode(true));
                logsSelect.appendChild(option.cloneNode(true));
                topSelect.appendChild(option.cloneNode(true));
                kbSelect.appendChild(option.cloneNode(true));
                llmSelect.appendChild(option.cloneNode(true));
            }
            select.value = state.latestSelectedNodeId;
            graphSelect.value = state.graphSelectedNodeId;
            triggerSelect.value = state.triggerSelectedNodeId;
            logsSelect.value = state.logsSelectedNodeId;
            topSelect.value = state.topSelectedNodeId;
            kbSelect.value = state.kbSelectedNodeId;
            llmSelect.value = state.llmSelectedNodeId;
        }

        function renderGraph(items, metricName, intervalMinutes) {
            const line = document.getElementById('graph-line');
            const yGrid = document.getElementById('graph-y-grid');
            const yLabels = document.getElementById('graph-y-labels');
            const xLabels = document.getElementById('graph-x-labels');
            const pointLayer = document.getElementById('graph-points');
            const title = document.getElementById('graph-title');

            const plotLeft = 80;
            const plotTop = 40;
            const plotWidth = 1080;
            const plotHeight = 260;
            const axisTicks = 5;
            const safeInterval = Math.max(1, Number(intervalMinutes) || 15);
            const endTimeMs = Date.now();
            const startTimeMs = endTimeMs - safeInterval * 60 * 1000;

            const sortedItems = items
                .map((item) => ({ ...item, timeMs: new Date(item.timestamp).getTime() }))
                .filter((item) => item.timeMs >= startTimeMs && item.timeMs <= endTimeMs)
                .sort((a, b) => a.timeMs - b.timeMs);

            const values = sortedItems.map((item) => item.value);
            const rawMinValue = values.length ? Math.min(...values) : 0;
            const rawMaxValue = values.length ? Math.max(...values) : 100;
            const padded = Math.max((rawMaxValue - rawMinValue) * 0.1, 1);
            const minValue = Math.max(0, rawMinValue - padded);
            const maxValue = rawMaxValue + padded;

            yGrid.innerHTML = '';
            yLabels.innerHTML = '';
            xLabels.innerHTML = '';
            pointLayer.innerHTML = '';

            for (let i = 0; i <= axisTicks; i += 1) {
                const ratio = i / axisTicks;
                const y = plotTop + plotHeight - ratio * plotHeight;
                const tickValue = minValue + ratio * (maxValue - minValue);

                const gridLine = document.createElementNS('http://www.w3.org/2000/svg', 'line');
                gridLine.setAttribute('x1', String(plotLeft));
                gridLine.setAttribute('y1', y.toFixed(2));
                gridLine.setAttribute('x2', String(plotLeft + plotWidth));
                gridLine.setAttribute('y2', y.toFixed(2));
                gridLine.setAttribute('stroke', 'rgba(111, 127, 149, 0.5)');
                gridLine.setAttribute('stroke-dasharray', '4 5');
                yGrid.appendChild(gridLine);

                const yLabel = document.createElementNS('http://www.w3.org/2000/svg', 'text');
                yLabel.setAttribute('x', String(plotLeft - 10));
                yLabel.setAttribute('y', (y + 4).toFixed(2));
                yLabel.setAttribute('fill', '#6f7f95');
                yLabel.setAttribute('font-size', '12');
                yLabel.setAttribute('text-anchor', 'end');
                yLabel.textContent = tickValue.toFixed(1);
                yLabels.appendChild(yLabel);
            }

            for (let i = 0; i <= axisTicks; i += 1) {
                const ratio = i / axisTicks;
                const x = plotLeft + ratio * plotWidth;
                const tickMs = startTimeMs + ratio * (endTimeMs - startTimeMs);

                const xLabel = document.createElementNS('http://www.w3.org/2000/svg', 'text');
                xLabel.setAttribute('x', x.toFixed(2));
                xLabel.setAttribute('y', String(plotTop + plotHeight + 20));
                xLabel.setAttribute('fill', '#6f7f95');
                xLabel.setAttribute('font-size', '12');
                xLabel.setAttribute('text-anchor', 'middle');
                xLabel.textContent = new Date(tickMs).toLocaleTimeString('en-GB', {
                    timeZone: 'Europe/Moscow',
                    hour: '2-digit',
                    minute: '2-digit',
                });
                xLabels.appendChild(xLabel);
            }

            if (!sortedItems.length) {
                line.setAttribute('points', '');
                title.textContent = `No data for selected interval (${safeInterval} min)`;
                return;
            }

            const toX = (timeMs) => plotLeft + ((timeMs - startTimeMs) / (endTimeMs - startTimeMs)) * plotWidth;
            const toY = (value) => plotTop + plotHeight - ((value - minValue) / (maxValue - minValue)) * plotHeight;

            const points = sortedItems.map((item) => {
                const x = toX(item.timeMs);
                const y = toY(item.value);
                const point = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
                point.setAttribute('cx', x.toFixed(2));
                point.setAttribute('cy', y.toFixed(2));
                point.setAttribute('r', '2.4');
                point.setAttribute('fill', '#0173b2');
                pointLayer.appendChild(point);
                return `${x.toFixed(2)},${y.toFixed(2)}`;
            });
            line.setAttribute('points', points.join(' '));
            const latestValue = sortedItems[sortedItems.length - 1].value;
            title.textContent = `${metricLabel(metricName)} trend (${safeInterval} min), latest: ${formatMetricValue(metricName, latestValue)}`;
        }

        function renderLatestSummary(items, node) {
            const container = document.getElementById('latest-summary');
            container.innerHTML = '';
            if (!node) {
                return;
            }

            const latest = items.length ? items[items.length - 1] : null;
            const stats = [
                ['Selected node', node.display_name],
                ['OS', node.os_name],
                ['IP', node.ip_address],
                ['Last sample', latest ? formatUtc(latest.timestamp) : 'No data yet'],
            ];

            for (const [label, value] of stats) {
                const card = document.createElement('div');
                card.className = 'stat';
                card.innerHTML = `<div class="stat-label">${label}</div><div class="stat-value">${value}</div>`;
                container.appendChild(card);
            }
        }

        function renderLatestTable(items) {
            const body = document.getElementById('metrics-body');
            body.innerHTML = '';
            if (!items.length) {
                body.innerHTML = '<tr><td colspan="12" class="empty">No metrics for this node yet.</td></tr>';
                return;
            }

            for (const item of items.slice().reverse()) {
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td>${formatUtc(item.timestamp)}</td>
                    <td>${item.display_name || 'Unknown node'}</td>
                    <td>${item.cpu_percent.toFixed(2)}</td>
                    <td>${item.ram_percent.toFixed(2)}</td>
                    <td>${item.swap_percent.toFixed(2)}</td>
                    <td>${item.uptime_seconds.toFixed(2)}</td>
                    <td>${item.disk_read_time_ms.toFixed(2)}</td>
                    <td>${item.disk_write_time_ms.toFixed(2)}</td>
                    <td>${item.net_recv_kbps.toFixed(2)}</td>
                    <td>${item.net_sent_kbps.toFixed(2)}</td>
                    <td>${Number(item.process_count).toFixed(0)}</td>
                    <td>${Number(item.zombie_processes).toFixed(0)}</td>
                `;
                body.appendChild(row);
            }
        }

        function renderFilesystemsTable(filesystems) {
            const body = document.getElementById('filesystems-body');
            body.innerHTML = '';
            if (!filesystems.length) {
                body.innerHTML = '<tr><td colspan="9" class="empty">No filesystem data yet.</td></tr>';
                return;
            }
            for (const item of filesystems) {
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td>${item.device}</td>
                    <td>${item.mountpoint}</td>
                    <td>${item.fstype}</td>
                    <td>${Number(item.total_gb).toFixed(2)}</td>
                    <td>${Number(item.used_gb).toFixed(2)}</td>
                    <td>${Number(item.free_gb).toFixed(2)}</td>
                    <td>${Number(item.percent).toFixed(2)}</td>
                    <td>${item.inodes_percent == null ? "-" : Number(item.inodes_percent).toFixed(2)}</td>
                    <td>${item.timestamp ? formatUtc(item.timestamp) : "-"}</td>
                `;
                body.appendChild(row);
            }
        }

        function renderNodesTable() {
            const body = document.getElementById('nodes-body');
            body.innerHTML = '';
            if (!state.nodes.length) {
                body.innerHTML = '<tr><td colspan="8" class="empty">No nodes have sent data yet.</td></tr>';
                return;
            }

            for (const node of state.nodes) {
                const row = document.createElement('tr');
                const menuKey = `node:${node.node_id}`;
                const statusLabel = node.agent_id
                    ? (node.agent_enabled ? 'Enabled' : 'Disabled')
                    : 'Not linked';
                row.innerHTML = `
                    <td>
                        <strong>${node.display_name}</strong>
                    </td>
                    <td>${node.os_name}</td>
                    <td>${node.cpu_cores}</td>
                    <td>${formatRamMb(node.ram_total_mb)}</td>
                    <td>${node.ip_address}</td>
                    <td>${formatUtc(node.last_seen)}</td>
                    <td>${statusLabel}</td>
                    <td class="menu-cell">
                        <button
                            type="button"
                            class="menu-btn secondary"
                            data-menu-toggle="${menuKey}"
                            data-menu-type="node"
                            data-node-id="${node.node_id}"
                            data-agent-id="${node.agent_id || ''}"
                            data-agent-enabled="${node.agent_enabled == null ? '' : node.agent_enabled}"
                            aria-label="Node actions"
                        >...</button>
                    </td>
                `;
                body.appendChild(row);
            }
        }

        function renderAlertUserOptions() {
            const select = document.getElementById('trigger-alert-user-select');
            select.innerHTML = '';
            const emptyOption = document.createElement('option');
            emptyOption.value = '';
            emptyOption.textContent = 'Not selected';
            select.appendChild(emptyOption);
            for (const user of state.users) {
                const option = document.createElement('option');
                option.value = String(user.id);
                const displayName = user.display_name ? ` (${user.display_name})` : '';
                option.textContent = `${user.login}${displayName}`;
                select.appendChild(option);
            }
        }

        function renderTriggerActionScriptOptions() {
            const select = document.getElementById('trigger-action-script-select');
            select.innerHTML = '';
            const scripts = state.nodeScripts[state.triggerSelectedNodeId] || [];
            if (!scripts.length) {
                const option = document.createElement('option');
                option.value = '';
                option.textContent = 'No scripts available';
                select.appendChild(option);
                select.disabled = true;
                return;
            }
            select.disabled = false;
            for (const script of scripts) {
                const option = document.createElement('option');
                option.value = script.script_id;
                option.textContent = `${script.script_id} (${script.script_path})`;
                select.appendChild(option);
            }
        }

        function renderTriggersTable() {
            const body = document.getElementById('triggers-body');
            body.innerHTML = '';
            if (!state.triggers.length) {
                body.innerHTML = '<tr><td colspan="9" class="empty">No triggers created for the selected node.</td></tr>';
                return;
            }
            for (const trigger of state.triggers) {
                const latestValue = trigger.latest_value == null ? 'No data' : formatMetricValue(trigger.metric_name, trigger.latest_value);
                const alertTo = trigger.alert_to_login
                    ? `${trigger.alert_to_login}${trigger.alert_to_display_name ? ` (${trigger.alert_to_display_name})` : ''}`
                    : '—';
                const menuKey = `trigger:${trigger.id}`;
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td>${trigger.node_display_name}</td>
                    <td>${trigger.name}</td>
                    <td>${metricLabel(trigger.metric_name)} ${trigger.operator} ${formatMetricValue(trigger.metric_name, trigger.threshold)}</td>
                    <td>${trigger.action_script_id || '—'}</td>
                    <td>${latestValue}</td>
                    <td>${alertTo}</td>
                    <td>${trigger.is_active ? 'Active' : 'OK'}</td>
                    <td>${formatUtc(trigger.created_at)}</td>
                    <td class="menu-cell">
                        <button
                            type="button"
                            class="menu-btn secondary"
                            data-menu-toggle="${menuKey}"
                            data-menu-type="trigger"
                            data-trigger-id="${trigger.id}"
                            data-trigger-name="${trigger.name}"
                            data-trigger-threshold="${trigger.threshold}"
                            data-trigger-alert-user-id="${trigger.alert_user_id || ''}"
                            data-trigger-action-script-id="${trigger.action_script_id || ''}"
                            aria-label="Trigger actions"
                        >...</button>
                    </td>
                `;
                body.appendChild(row);
            }
        }

        function renderProblemsTable() {
            const body = document.getElementById('problems-body');
            body.innerHTML = '';
            if (!state.problems.length) {
                body.innerHTML = '<tr><td colspan="5" class="empty">No active triggers now.</td></tr>';
                return;
            }
            for (const trigger of state.problems) {
                const latestValue = trigger.latest_value == null ? 'No data' : formatMetricValue(trigger.metric_name, trigger.latest_value);
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td>${trigger.node_display_name}</td>
                    <td>${trigger.name}</td>
                    <td>${metricLabel(trigger.metric_name)} ${trigger.operator} ${formatMetricValue(trigger.metric_name, trigger.threshold)}</td>
                    <td>${latestValue}</td>
                    <td>${formatUtc(trigger.created_at)}</td>
                `;
                body.appendChild(row);
            }
        }

        function renderKnowledgeBaseTable() {
            const body = document.getElementById('knowledge-base-body');
            body.innerHTML = '';
            if (!state.knowledgeBase.length) {
                body.innerHTML = '<tr><td colspan="3" class="empty">No Knowledge Base results yet.</td></tr>';
                return;
            }
            for (const item of state.knowledgeBase) {
                const explanatorySet = item.explanatory_set || [];
                const explanations = explanatorySet.length
                    ? `<ul>${explanatorySet.map((row) => `<li><strong>${row.name}</strong>${row.description ? `: ${row.description}` : ''}</li>`).join('')}</ul>`
                    : '<span class="meta">No explanatory signals</span>';
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td>${item.name || '-'}</td>
                    <td>${item.description || '-'}</td>
                    <td>${explanations}</td>
                `;
                body.appendChild(row);
            }
        }

        function renderLogsTable(items) {
            const body = document.getElementById('logs-body');
            body.innerHTML = '';
            if (!items.length) {
                body.innerHTML = '<tr><td colspan="4" class="empty">No logs received from this node yet.</td></tr>';
                return;
            }
            for (const entry of items) {
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td>${formatUtc(entry.captured_at)}</td>
                    <td>${entry.source}</td>
                    <td>${entry.severity}</td>
                    <td>${entry.message}</td>
                `;
                body.appendChild(row);
            }
        }

        function renderTopTable(items, bodyId, metricKey) {
            const body = document.getElementById(bodyId);
            body.innerHTML = '';
            if (!items.length) {
                body.innerHTML = '<tr><td colspan="4" class="empty">No process data yet.</td></tr>';
                return;
            }
            for (const item of items) {
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td>${item.pid}</td>
                    <td>${item.name}</td>
                    <td>${Number(item[metricKey]).toFixed(2)}</td>
                    <td>${formatRamMb(item.ram_mb)}</td>
                `;
                body.appendChild(row);
            }
        }

        function setStatus(id, message, isError = false) {
            const element = document.getElementById(id);
            element.textContent = message;
            element.classList.toggle('error', isError);
        }

        function closeAllMenus() {
            const menu = document.getElementById('global-menu');
            menu.hidden = true;
            menu.innerHTML = '';
            state.activeMenuKey = '';
            state.activeMenuData = null;
        }

        function showCredentialsModal({ title, agentId, secret }) {
            document.getElementById('credentials-modal-title').textContent = title;
            document.getElementById('credentials-agent-id').value = agentId || '';
            document.getElementById('credentials-agent-secret').value = secret || '';
            document.getElementById('credentials-modal-backdrop').hidden = false;
        }

        function hideCredentialsModal() {
            document.getElementById('credentials-modal-backdrop').hidden = true;
        }

        function showActionModal({ title, description = '', fields = [], confirmLabel = 'Confirm', danger = false, onConfirm }) {
            document.getElementById('action-modal-title').textContent = title;
            document.getElementById('action-modal-description').textContent = description;
            const fieldsContainer = document.getElementById('action-modal-fields');
            fieldsContainer.innerHTML = '';
            for (const field of fields) {
                const label = document.createElement('label');
                label.innerHTML = `<span class="meta">${field.label}</span><br />`;
                if (field.type === 'select') {
                    const select = document.createElement('select');
                    select.id = field.id;
                    for (const option of field.options || []) {
                        const optionElement = document.createElement('option');
                        optionElement.value = option.value;
                        optionElement.textContent = option.label;
                        if ((field.value || '') === option.value) {
                            optionElement.selected = true;
                        }
                        select.appendChild(optionElement);
                    }
                    label.appendChild(select);
                } else {
                    const input = document.createElement('input');
                    input.type = field.type || 'text';
                    input.id = field.id;
                    input.value = field.value || '';
                    if (field.min != null) input.min = String(field.min);
                    if (field.max != null) input.max = String(field.max);
                    if (field.step != null) input.step = String(field.step);
                    if (field.maxlength != null) input.maxLength = Number(field.maxlength);
                    label.appendChild(input);
                }
                fieldsContainer.appendChild(label);
            }
            const confirmButton = document.getElementById('action-modal-confirm');
            confirmButton.textContent = confirmLabel;
            confirmButton.classList.toggle('danger', danger);
            state.actionModalHandler = onConfirm;
            document.getElementById('action-modal-backdrop').hidden = false;
        }

        function hideActionModal() {
            document.getElementById('action-modal-backdrop').hidden = true;
            document.getElementById('action-modal-fields').innerHTML = '';
            state.actionModalHandler = null;
        }

        async function copyCredentialsField(inputId) {
            const input = document.getElementById(inputId);
            const value = input.value || '';
            if (!value) return;
            try {
                await navigator.clipboard.writeText(value);
            } catch (error) {
                input.focus();
                input.select();
                document.execCommand('copy');
            }
        }

        function openGlobalMenu(toggleButton) {
            const menu = document.getElementById('global-menu');
            const rect = toggleButton.getBoundingClientRect();
            const key = toggleButton.dataset.menuToggle;
            const type = toggleButton.dataset.menuType;
            if (!key || !type) return;

            if (type === 'node') {
                const nodeId = toggleButton.dataset.nodeId;
                const agentId = toggleButton.dataset.agentId;
                const hasAgent = Boolean(agentId);
                const isEnabled = toggleButton.dataset.agentEnabled === 'true';
                menu.innerHTML = `
                    <button type="button" data-node-action="rename" data-node-id="${nodeId}">Rename</button>
                    ${
                        hasAgent
                            ? `<button type="button" data-node-action="${isEnabled ? 'stop-agent' : 'start-agent'}" data-node-id="${nodeId}" data-agent-id="${agentId}">${isEnabled ? 'Stop Agent' : 'Start Agent'}</button>`
                            : ''
                    }
                    <button type="button" class="danger" data-node-action="delete" data-node-id="${nodeId}">Delete</button>
                `;
            } else if (type === 'trigger') {
                const triggerId = toggleButton.dataset.triggerId;
                const triggerName = toggleButton.dataset.triggerName || '';
                const triggerThreshold = toggleButton.dataset.triggerThreshold || '';
                const triggerAlertUserId = toggleButton.dataset.triggerAlertUserId || '';
                const triggerActionScriptId = toggleButton.dataset.triggerActionScriptId || '';
                menu.innerHTML = `
                    <button type="button" data-trigger-action="edit" data-trigger-id="${triggerId}" data-trigger-name="${triggerName}" data-trigger-threshold="${triggerThreshold}" data-trigger-alert-user-id="${triggerAlertUserId}" data-trigger-action-script-id="${triggerActionScriptId}">Edit</button>
                    <button type="button" class="danger" data-trigger-action="delete" data-trigger-id="${triggerId}">Delete</button>
                `;
            } else if (type === 'user') {
                const userId = toggleButton.dataset.userId;
                const userLogin = toggleButton.dataset.userLogin || '';
                const userEmail = toggleButton.dataset.userEmail || '';
                const userDisplayName = toggleButton.dataset.userDisplayName || '';
                menu.innerHTML = `
                    <button type="button" data-user-action="edit" data-user-id="${userId}" data-user-login="${userLogin}" data-user-email="${userEmail}" data-user-display-name="${userDisplayName}">Edit</button>
                `;
            } else {
                return;
            }

            menu.style.top = `${Math.min(window.innerHeight - 120, rect.bottom + 6)}px`;
            menu.style.left = `${Math.max(8, rect.right - 160)}px`;
            menu.hidden = false;
            state.activeMenuKey = key;
            state.activeMenuData = { type };
        }

        async function loadNodes() {
            try {
                const data = await fetchJson('/api/nodes');
                state.nodes = data.items;
                renderNodeOptions();
                renderNodesTable();
                setStatus('nodes-status', state.nodes.length ? '' : 'Waiting for nodes to send data.');
            } catch (error) {
                setStatus('nodes-status', error.message, true);
            }
        }

        async function loadAgents() {
            try {
                const data = await fetchJson('/api/agents');
                state.agents = data.items || [];
            } catch (error) {
                state.agents = [];
                setStatus('nodes-status', `Agents loading failed: ${error.message}`, true);
            }
        }

        async function registerAgent() {
            try {
                const data = await fetchJson('/api/agents/register', { method: 'POST' });
                setStatus('nodes-status', 'Agent created. Save credentials now.', false);
                showCredentialsModal({
                    title: 'New agent credentials',
                    agentId: data.agent_id,
                    secret: data.secret,
                });
                await loadAgents();
                await loadNodes();
            } catch (error) {
                setStatus('nodes-status', error.message, true);
            }
        }

        async function loadLatestMetrics() {
            const node = state.nodes.find((item) => item.node_id === state.latestSelectedNodeId);
            if (!node) {
                renderLatestSummary([], null);
                renderLatestTable([]);
                renderFilesystemsTable([]);
                setStatus('latest-status', 'Waiting for nodes to send data.');
                return;
            }

            try {
                const [data, fsData] = await Promise.all([
                    fetchJson(`/api/metrics?node_id=${encodeURIComponent(node.node_id)}`),
                    fetchJson(`/api/filesystems?node_id=${encodeURIComponent(node.node_id)}`),
                ]);
                renderLatestSummary(data.items, node);
                renderLatestTable(data.items);
                renderFilesystemsTable(fsData.filesystems || []);
                setStatus('latest-status', data.items.length ? '' : 'No recent metrics for the selected node.');
            } catch (error) {
                renderLatestSummary([], node);
                renderLatestTable([]);
                renderFilesystemsTable([]);
                setStatus('latest-status', error.message, true);
            }
        }

        async function loadGraph() {
            const nodeId = state.graphSelectedNodeId;
            const metricName = document.getElementById('graph-metric-select').value;
            const interval = document.getElementById('graph-interval-select').value;
            if (!nodeId) {
                renderGraph([], metricName, interval);
                setStatus('graph-status', 'Waiting for nodes to send data.');
                return;
            }
            try {
                const data = await fetchJson(
                    `/api/metrics/history?node_id=${encodeURIComponent(nodeId)}&metric_name=${encodeURIComponent(metricName)}&interval_minutes=${encodeURIComponent(interval)}`
                );
                renderGraph(data.items, metricName, interval);
                setStatus('graph-status', data.items.length ? '' : 'No recent points for selected options.');
            } catch (error) {
                renderGraph([], metricName, interval);
                setStatus('graph-status', error.message, true);
            }
        }

        async function loadTriggers() {
            if (!state.triggerSelectedNodeId) {
                state.triggers = [];
                renderTriggersTable();
                setStatus('triggers-status', 'Waiting for nodes to send data.');
                return;
            }
            try {
                const data = await fetchJson(`/api/triggers?node_id=${encodeURIComponent(state.triggerSelectedNodeId)}`);
                state.triggers = data.items;
                renderTriggersTable();
                setStatus('triggers-status', state.triggers.length ? '' : 'No triggers yet for this node.');
            } catch (error) {
                state.triggers = [];
                renderTriggersTable();
                setStatus('triggers-status', error.message, true);
            }
        }

        async function loadTriggerScripts() {
            if (!state.triggerSelectedNodeId) {
                renderTriggerActionScriptOptions();
                return;
            }
            try {
                const data = await fetchJson(`/api/nodes/${encodeURIComponent(state.triggerSelectedNodeId)}/scripts`);
                state.nodeScripts[state.triggerSelectedNodeId] = data.items || [];
                renderTriggerActionScriptOptions();
            } catch (error) {
                state.nodeScripts[state.triggerSelectedNodeId] = [];
                renderTriggerActionScriptOptions();
                setStatus('triggers-status', error.message, true);
            }
        }

        async function loadProblems() {
            try {
                const data = await fetchJson('/api/problems');
                state.problems = data.items;
                renderProblemsTable();
                setStatus('problems-status', state.problems.length ? '' : 'No active triggers.');
            } catch (error) {
                state.problems = [];
                renderProblemsTable();
                setStatus('problems-status', error.message, true);
            }
        }

        function renderUsersTable() {
            const body = document.getElementById('users-body');
            body.innerHTML = '';
            if (!state.users.length) {
                body.innerHTML = '<tr><td colspan="5" class="empty">No users yet.</td></tr>';
                return;
            }
            for (const user of state.users) {
                const row = document.createElement('tr');
                const menuKey = `user:${user.id}`;
                row.innerHTML = `
                    <td>${user.login}</td>
                    <td>${user.email}</td>
                    <td>${user.display_name || '-'}</td>
                    <td>${formatUtc(user.created_at)}</td>
                    <td class="menu-cell"><button type="button" class="menu-btn secondary" data-menu-toggle="${menuKey}" data-menu-type="user" data-user-id="${user.id}" data-user-login="${user.login}" data-user-email="${user.email}" data-user-display-name="${user.display_name || ''}">...</button></td>
                `;
                body.appendChild(row);
            }
        }

        async function loadUsers() {
            try {
                const data = await fetchJson('/api/users');
                state.users = data;
                renderUsersTable();
                renderAlertUserOptions();
                setStatus('users-status', state.users.length ? '' : 'No users yet.');
            } catch (error) {
                state.users = [];
                renderUsersTable();
                renderAlertUserOptions();
                setStatus('users-status', error.message, true);
            }
        }

        async function checkAuth() {
            try {
                const data = await fetchJson('/api/auth/me');
                state.currentLogin = data.login;
                document.getElementById('login-modal-backdrop').hidden = true;
                return true;
            } catch (error) {
                document.getElementById('login-modal-backdrop').hidden = false;
                setStatus('auth-status', 'Invalid login or password.', true);
                return false;
            }
        }

        async function signIn() {
            const login = document.getElementById('auth-login').value.trim();
            const password = document.getElementById('auth-password').value;
            if (!login || !password) {
                setStatus('auth-status', 'Fill login and password.', true);
                return;
            }
            try {
                await fetchJson('/api/auth/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ login, password }) });
                setStatus('auth-status', '');
                document.getElementById('auth-password').value = '';
                await refreshAll();
                document.getElementById('login-modal-backdrop').hidden = true;
            } catch (error) {
                setStatus('auth-status', error.message, true);
            }
        }

        async function signOut() {
            await fetchJson('/api/auth/logout', { method: 'POST' });
            state.users = [];
            renderUsersTable();
            document.getElementById('login-modal-backdrop').hidden = false;
        }


        async function loadKnowledgeBase() {
            try {
                if (!state.kbSelectedNodeId) {
                    state.knowledgeBase = [];
                    renderKnowledgeBaseTable();
                    setStatus('knowledge-base-status', 'Choose a node to run Knowledge Base solve.');
                    return;
                }
                const data = await fetchJson(`/api/knowledge-base?node_id=${encodeURIComponent(state.kbSelectedNodeId)}`);
                state.knowledgeBase = data.items || [];
                renderKnowledgeBaseTable();
                if (data.status === 'disabled') {
                    setStatus('knowledge-base-status', data.error || 'Knowledge Base integration is disabled.');
                } else if (data.status === 'error') {
                    setStatus('knowledge-base-status', data.error || 'Failed to load Knowledge Base data.', true);
                } else {
                    const updated = data.last_updated ? formatUtc(data.last_updated) : 'never';
                    const activeCount = (data.active_triggers || []).length;
                    const mappedCount = (data.matched_node_ids || []).length;
                    setStatus(
                        'knowledge-base-status',
                        state.knowledgeBase.length
                            ? `Last solve (UTC+3): ${updated}. Active triggers: ${activeCount}, matched KB nodes: ${mappedCount}.`
                            : `No KB results. Last solve (UTC+3): ${updated}. Active triggers: ${activeCount}, matched KB nodes: ${mappedCount}.`
                    );
                }
            } catch (error) {
                state.knowledgeBase = [];
                renderKnowledgeBaseTable();
                setStatus('knowledge-base-status', error.message, true);
            }
        }

        async function loadLogs() {
            if (!state.logsSelectedNodeId) {
                renderLogsTable([]);
                setStatus('logs-status', 'Waiting for nodes to send data.');
                return;
            }
            try {
                const data = await fetchJson(
                    `/api/logs?node_id=${encodeURIComponent(state.logsSelectedNodeId)}&severity=${encodeURIComponent(state.logsSelectedSeverity)}`
                );
                renderLogsTable(data.items || []);
                const osLabel = data.os_name || 'Unknown OS';
                setStatus(
                    'logs-status',
                    data.items.length
                        ? `Source node OS: ${osLabel}. Severity: ${state.logsSelectedSeverity}.`
                        : `No logs yet for severity ${state.logsSelectedSeverity}. Source node OS: ${osLabel}`
                );
            } catch (error) {
                renderLogsTable([]);
                setStatus('logs-status', error.message, true);
            }
        }

        async function loadTopProcesses() {
            if (!state.topSelectedNodeId) {
                renderTopTable([], 'top-cpu-body', 'cpu_percent');
                renderTopTable([], 'top-ram-body', 'ram_percent');
                setStatus('top-status', 'Waiting for nodes to send data.');
                return;
            }
            try {
                const data = await fetchJson(`/api/top-processes?node_id=${encodeURIComponent(state.topSelectedNodeId)}`);
                renderTopTable(data.top_cpu_processes || [], 'top-cpu-body', 'cpu_percent');
                renderTopTable(data.top_ram_processes || [], 'top-ram-body', 'ram_percent');
                setStatus('top-status', data.timestamp ? `Last updated (UTC+3): ${formatUtc(data.timestamp)}` : 'No process data yet.');
            } catch (error) {
                renderTopTable([], 'top-cpu-body', 'cpu_percent');
                renderTopTable([], 'top-ram-body', 'ram_percent');
                setStatus('top-status', error.message, true);
            }
        }

        async function runLlm() {
            if (!state.llmSelectedNodeId) {
                setStatus('llm-status', 'Choose a node first.', true);
                return;
            }
            setStatus('llm-status', 'Analyzing node with LLM...');
            state.llmRawOutput = '';
            state.llmContextJson = null;
            renderLlmOutput();
            renderLlmContext();
            if (state.llmShowContext) {
                try {
                    state.llmContextJson = await fetchJson(`/api/llm/context?node_id=${encodeURIComponent(state.llmSelectedNodeId)}&window_minutes=${encodeURIComponent(state.llmWindowMinutes)}`);
                    renderLlmContext();
                } catch (contextError) {
                    setStatus('llm-status', `Context fetch failed: ${contextError.message}`, true);
                }
            }
            try {
                const response = await fetch('/api/llm/analyze-node', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ node_id: state.llmSelectedNodeId, window_minutes: Number(state.llmWindowMinutes || 60) }),
                });
                if (!response.ok) {
                    let detail = response.statusText || 'Request failed';
                    try {
                        const payload = await response.json();
                        detail = payload.detail || detail;
                    } catch (_error) {
                        detail = detail || 'Request failed';
                    }
                    throw new Error(detail);
                }
                const reader = response.body?.getReader();
                if (!reader) {
                    throw new Error('Streaming is not available in this browser.');
                }
                const decoder = new TextDecoder();
                while (true) {
                    const { done, value } = await reader.read();
                    if (done) break;
                    state.llmRawOutput += decoder.decode(value, { stream: true });
                    renderLlmOutput();
                }
                state.llmRawOutput += decoder.decode();
                renderLlmOutput();
                setStatus('llm-status', 'Done.');
            } catch (error) {
                state.llmRawOutput = '';
                renderLlmOutput();
                setStatus('llm-status', error.message, true);
            }
        }

        async function fetchLlmRecommendations() {
            if (!state.llmSelectedNodeId) {
                state.llmRecommendations = [];
                renderLlmRecommendations();
                return;
            }
            const data = await fetchJson(`/api/llm/script-recommendations?node_id=${encodeURIComponent(state.llmSelectedNodeId)}`);
            state.llmRecommendations = data.items || [];
            renderLlmRecommendations();
        }

        async function requestLlmScriptRecommendations() {
            if (!state.llmSelectedNodeId) {
                setStatus('llm-status', 'Choose a node first.', true);
                return;
            }
            setStatus('llm-status', 'Requesting remediation script recommendations...');
            const payload = { node_id: state.llmSelectedNodeId, window_minutes: Number(state.llmWindowMinutes || 60) };
            await fetchJson('/api/llm/recommend-scripts', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
            await fetchLlmRecommendations();
            setStatus('llm-status', 'Recommendations updated.');
        }

        async function runLlmRecommendation(recommendationId, dryRun) {
            const rec = state.llmRecommendations.find((item) => Number(item.id) === Number(recommendationId));
            if (!rec) return;
            if (!dryRun && (rec.risk_level === 'medium' || rec.risk_level === 'high')) {
                const ok = window.confirm('Подтвердите запуск remediation-скрипта на удалённом узле');
                if (!ok) return;
            }
            const response = await fetchJson(`/api/llm/script-recommendations/${encodeURIComponent(recommendationId)}/approve`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ confirm: true, dry_run: Boolean(dryRun) }),
            });
            setStatus('llm-status', `Command created: #${response.command.id} (${response.command.status})`);
            await fetchLlmRecommendations();
        }

        async function rejectLlmRecommendation(recommendationId) {
            await fetchJson(`/api/llm/script-recommendations/${encodeURIComponent(recommendationId)}/reject`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({}),
            });
            await fetchLlmRecommendations();
            setStatus('llm-status', `Recommendation #${recommendationId} rejected.`);
        }

        document.querySelectorAll('.nav-btn').forEach((button) => {
            button.addEventListener('click', () => {
                state.activeTab = button.dataset.tab;
                renderTabs();
            });
        });

        document.getElementById('node-select').addEventListener('change', async (event) => {
            state.latestSelectedNodeId = event.target.value;
            state.graphSelectedNodeId = event.target.value;
            state.triggerSelectedNodeId = event.target.value;
            state.logsSelectedNodeId = event.target.value;
            state.topSelectedNodeId = event.target.value;
            state.kbSelectedNodeId = event.target.value;
            state.llmSelectedNodeId = event.target.value;
            document.getElementById('graph-node-select').value = state.graphSelectedNodeId;
            document.getElementById('trigger-node-select').value = state.triggerSelectedNodeId;
            document.getElementById('logs-node-select').value = state.logsSelectedNodeId;
            document.getElementById('top-node-select').value = state.topSelectedNodeId;
            document.getElementById('kb-node-select').value = state.kbSelectedNodeId;
            document.getElementById('llm-node-select').value = state.llmSelectedNodeId;
            await loadLatestMetrics();
            await loadGraph();
            await loadTriggerScripts();
            await loadTriggers();
            await loadLogs();
            await loadTopProcesses();
            await loadKnowledgeBase();
        });

        document.getElementById('refresh-latest').addEventListener('click', loadLatestMetrics);
        document.getElementById('register-node-agent').addEventListener('click', registerAgent);
        document.getElementById('refresh-graph').addEventListener('click', loadGraph);
        document.getElementById('graph-node-select').addEventListener('change', async (event) => {
            state.graphSelectedNodeId = event.target.value;
            await loadGraph();
        });
        document.getElementById('graph-metric-select').addEventListener('change', loadGraph);
        document.getElementById('graph-interval-select').addEventListener('change', loadGraph);
        document.getElementById('trigger-node-select').addEventListener('change', async (event) => {
            state.triggerSelectedNodeId = event.target.value;
            await loadTriggerScripts();
            await loadTriggers();
        });
        document.getElementById('create-trigger-form').addEventListener('submit', async (event) => {
            event.preventDefault();
            if (!state.triggerSelectedNodeId) {
                setStatus('triggers-status', 'Choose a node first.', true);
                return;
            }
            const triggerName = document.getElementById('trigger-name-input').value.trim();
            if (!triggerName) {
                setStatus('triggers-status', 'Trigger name cannot be empty.', true);
                return;
            }
            const threshold = Number(document.getElementById('trigger-threshold-input').value);
            const alertUserRaw = document.getElementById('trigger-alert-user-select').value;
            const actionScriptId = document.getElementById('trigger-action-script-select').value;
            const alertUserId = alertUserRaw ? Number(alertUserRaw) : null;
            if (!Number.isFinite(threshold) || threshold < 0) {
                setStatus('triggers-status', 'Threshold must be a positive number or zero.', true);
                return;
            }
            if (!actionScriptId) {
                setStatus('triggers-status', 'Select action script.', true);
                return;
            }
            try {
                await fetchJson('/api/triggers', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        node_id: state.triggerSelectedNodeId,
                        name: triggerName,
                        metric_name: document.getElementById('trigger-metric-select').value,
                        operator: document.getElementById('trigger-operator-select').value,
                        threshold,
                        alert_user_id: alertUserId,
                        action_script_id: actionScriptId,
                    }),
                });
                setStatus('triggers-status', 'Trigger created.');
                await loadTriggers();
                await loadProblems();
            } catch (error) {
                setStatus('triggers-status', error.message, true);
            }
        });
        document.getElementById('refresh-problems').addEventListener('click', loadProblems);
        document.getElementById('refresh-logs').addEventListener('click', loadLogs);
        document.getElementById('logs-node-select').addEventListener('change', async (event) => {
            state.logsSelectedNodeId = event.target.value;
            await loadLogs();
        });
        document.getElementById('logs-severity-select').addEventListener('change', async (event) => {
            state.logsSelectedSeverity = event.target.value;
            await loadLogs();
        });
        document.getElementById('refresh-top').addEventListener('click', loadTopProcesses);
        document.getElementById('top-node-select').addEventListener('change', async (event) => {
            state.topSelectedNodeId = event.target.value;
            await loadTopProcesses();
        });
        document.getElementById('refresh-knowledge-base').addEventListener('click', loadKnowledgeBase);
        document.getElementById('kb-node-select').addEventListener('change', (event) => {
            state.kbSelectedNodeId = event.target.value;
            setStatus('knowledge-base-status', state.kbSelectedNodeId ? 'Node selected. Click \"Run KB solve\" to fetch Knowledge Base results.' : 'Choose a node to run Knowledge Base solve.');
        });
        document.getElementById('llm-node-select').addEventListener('change', (event) => {
            state.llmSelectedNodeId = event.target.value;
            setStatus('llm-status', state.llmSelectedNodeId ? 'Node selected. Click "Analyze node".' : 'Choose a node for LLM analysis.');
            fetchLlmRecommendations().catch((error) => setStatus('llm-status', error.message, true));
        });
        document.getElementById('llm-window-select').addEventListener('change', (event) => { state.llmWindowMinutes = Number(event.target.value || 60); });
        document.getElementById('llm-show-context').addEventListener('change', (event) => { state.llmShowContext = Boolean(event.target.checked); renderLlmContext(); });
        document.getElementById('run-llm').addEventListener('click', runLlm);
        document.getElementById('recommend-llm-scripts').addEventListener('click', () => requestLlmScriptRecommendations().catch((error) => setStatus('llm-status', error.message, true)));
        document.getElementById('refresh-llm-recommendations').addEventListener('click', () => fetchLlmRecommendations().catch((error) => setStatus('llm-status', error.message, true)));
        document.getElementById('auth-sign-in').addEventListener('click', signIn);
        document.getElementById('sign-out').addEventListener('click', signOut);
        document.getElementById('close-credentials-modal').addEventListener('click', hideCredentialsModal);
        document.getElementById('credentials-modal-backdrop').addEventListener('click', (event) => {
            if (event.target.id === 'credentials-modal-backdrop') {
                hideCredentialsModal();
            }
        });
        document.getElementById('copy-agent-id').addEventListener('click', async () => copyCredentialsField('credentials-agent-id'));
        document.getElementById('copy-agent-secret').addEventListener('click', async () => copyCredentialsField('credentials-agent-secret'));
        document.getElementById('action-modal-cancel').addEventListener('click', hideActionModal);
        document.getElementById('action-modal-backdrop').addEventListener('click', (event) => {
            if (event.target.id === 'action-modal-backdrop') {
                hideActionModal();
            }
        });
        document.getElementById('action-modal-confirm').addEventListener('click', async () => {
            if (typeof state.actionModalHandler === 'function') {
                await state.actionModalHandler();
            }
        });
        document.addEventListener('click', async (event) => {
            const toggleButton = event.target.closest('[data-menu-toggle]');
            if (toggleButton) {
                const key = toggleButton.dataset.menuToggle;
                const shouldOpen = state.activeMenuKey !== key;
                closeAllMenus();
                if (shouldOpen) {
                    openGlobalMenu(toggleButton);
                }
                return;
            }

            const nodeActionButton = event.target.closest('[data-node-action]');
            if (nodeActionButton) {
                closeAllMenus();
                const action = nodeActionButton.dataset.nodeAction;
                const nodeId = nodeActionButton.dataset.nodeId;
                const agentId = nodeActionButton.dataset.agentId;
                if (action === 'rename') {
                    const node = state.nodes.find((item) => item.node_id === nodeId);
                    showActionModal({
                        title: 'Rename node',
                        description: 'Set a new unique display name for this node.',
                        fields: [{ id: 'rename-node-name', label: 'Display name', value: node ? node.display_name : '', maxlength: 100 }],
                        confirmLabel: 'Save',
                        onConfirm: async () => {
                            const nextName = document.getElementById('rename-node-name').value.trim();
                            if (!nextName) {
                                setStatus('nodes-status', 'Display name cannot be empty.', true);
                                return;
                            }
                            try {
                                await fetchJson(`/api/nodes/${encodeURIComponent(nodeId)}`, {
                                    method: 'PATCH',
                                    headers: { 'Content-Type': 'application/json' },
                                    body: JSON.stringify({ display_name: nextName }),
                                });
                                hideActionModal();
                                setStatus('nodes-status', 'Node renamed.');
                                await loadNodes();
                            } catch (error) {
                                setStatus('nodes-status', error.message, true);
                            }
                        },
                    });
                }
                if (action === 'stop-agent' || action === 'start-agent') {
                    showActionModal({
                        title: action === 'stop-agent' ? 'Stop agent' : 'Start agent',
                        description: action === 'stop-agent' ? 'Disable this linked agent?' : 'Enable this linked agent?',
                        confirmLabel: action === 'stop-agent' ? 'Stop Agent' : 'Start Agent',
                        onConfirm: async () => {
                            try {
                                await fetchJson(`/api/agents/${encodeURIComponent(agentId)}/${action === 'stop-agent' ? 'disable' : 'enable'}`, { method: 'POST' });
                                hideActionModal();
                                setStatus('nodes-status', `Agent ${action === 'stop-agent' ? 'stopped' : 'started'}.`);
                                await loadAgents();
                                await loadNodes();
                            } catch (error) {
                                setStatus('nodes-status', error.message, true);
                            }
                        },
                    });
                }
                if (action === 'delete') {
                    showActionModal({
                        title: 'Delete node',
                        description: 'Delete node with all related metrics, logs and triggers?',
                        confirmLabel: 'Delete',
                        danger: true,
                        onConfirm: async () => {
                            try {
                                await fetchJson(`/api/nodes/${encodeURIComponent(nodeId)}`, { method: 'DELETE' });
                                hideActionModal();
                                setStatus('nodes-status', 'Node deleted.');
                                await refreshAll();
                            } catch (error) {
                                setStatus('nodes-status', error.message, true);
                            }
                        },
                    });
                }
                return;
            }

            const userActionButton = event.target.closest('[data-user-action]');
            if (userActionButton) {
                closeAllMenus();
                const action = userActionButton.dataset.userAction;
                const userId = userActionButton.dataset.userId;
                if (action === 'edit') {
                    showActionModal({
                        title: 'Edit user',
                        description: 'Update login, password, email and display name.',
                        fields: [
                            { id: 'edit-user-login', label: 'Login', value: userActionButton.dataset.userLogin || '', maxlength: 64 },
                            { id: 'edit-user-password', label: 'Password', type: 'password', value: '', maxlength: 256 },
                            { id: 'edit-user-email', label: 'Email', value: userActionButton.dataset.userEmail || '', maxlength: 255 },
                            { id: 'edit-user-display-name', label: 'Display name', value: userActionButton.dataset.userDisplayName || '', maxlength: 255 },
                        ],
                        confirmLabel: 'Save',
                        onConfirm: async () => {
                            const login = document.getElementById('edit-user-login').value.trim();
                            const password = document.getElementById('edit-user-password').value;
                            const email = document.getElementById('edit-user-email').value.trim();
                            const display_name = document.getElementById('edit-user-display-name').value.trim();
                            if (!login || !password || !email) {
                                setStatus('users-status', 'Login, Password and Email are required.', true);
                                return;
                            }
                            try {
                                await fetchJson(`/api/users/${encodeURIComponent(userId)}`, {
                                    method: 'PATCH',
                                    headers: { 'Content-Type': 'application/json' },
                                    body: JSON.stringify({ login, password, email, display_name: display_name || null }),
                                });
                                hideActionModal();
                                setStatus('users-status', 'User updated.');
                                await loadUsers();
                            } catch (error) {
                                setStatus('users-status', error.message, true);
                            }
                        },
                    });
                }
                return;
            }


            const triggerActionButton = event.target.closest('[data-trigger-action]');
            if (triggerActionButton) {
                closeAllMenus();
                const action = triggerActionButton.dataset.triggerAction;
                const triggerId = triggerActionButton.dataset.triggerId;
                if (action === 'edit') {
                    const scripts = state.nodeScripts[state.triggerSelectedNodeId] || [];
                    const scriptOptions = scripts.map((script) => ({
                        value: script.script_id,
                        label: `${script.script_id} (${script.script_path})`,
                    }));
                    const alertUserOptions = [{ value: '', label: 'Not selected' }].concat(
                        state.users.map((user) => ({
                            value: String(user.id),
                            label: `${user.login}${user.display_name ? ` (${user.display_name})` : ''}`,
                        }))
                    );
                    showActionModal({
                        title: 'Edit trigger',
                        description: 'Update trigger name, threshold and alert recipient.',
                        fields: [
                            { id: 'edit-trigger-name', label: 'Name', value: triggerActionButton.dataset.triggerName || '', maxlength: 120 },
                            { id: 'edit-trigger-threshold', label: 'Threshold (0-100)', type: 'number', value: triggerActionButton.dataset.triggerThreshold || '', min: 0, max: 100, step: 0.1 },
                            { id: 'edit-trigger-alert-user-id', label: 'Alert to', type: 'select', value: triggerActionButton.dataset.triggerAlertUserId || '', options: alertUserOptions },
                            { id: 'edit-trigger-action-script-id', label: 'Action script', type: 'select', value: triggerActionButton.dataset.triggerActionScriptId || '', options: scriptOptions },
                        ],
                        confirmLabel: 'Save',
                        onConfirm: async () => {
                            const nextName = document.getElementById('edit-trigger-name').value.trim();
                            const threshold = Number(document.getElementById('edit-trigger-threshold').value);
                            const alertUserRaw = document.getElementById('edit-trigger-alert-user-id').value;
                            const actionScriptId = document.getElementById('edit-trigger-action-script-id').value;
                            const alertUserId = alertUserRaw ? Number(alertUserRaw) : null;
                            if (!nextName) {
                                setStatus('triggers-status', 'Trigger name cannot be empty.', true);
                                return;
                            }
                            if (!Number.isFinite(threshold) || threshold < 0 || threshold > 100) {
                                setStatus('triggers-status', 'Threshold must be between 0 and 100.', true);
                                return;
                            }
                            if (!actionScriptId) {
                                setStatus('triggers-status', 'Select action script.', true);
                                return;
                            }
                            try {
                                await fetchJson(`/api/triggers/${encodeURIComponent(triggerId)}`, {
                                    method: 'PATCH',
                                    headers: { 'Content-Type': 'application/json' },
                                    body: JSON.stringify({ name: nextName, threshold, alert_user_id: alertUserId, action_script_id: actionScriptId }),
                                });
                                hideActionModal();
                                setStatus('triggers-status', 'Trigger updated.');
                                await loadTriggers();
                                await loadProblems();
                            } catch (error) {
                                setStatus('triggers-status', error.message, true);
                            }
                        },
                    });
                }
                if (action === 'delete') {
                    showActionModal({
                        title: 'Delete trigger',
                        description: 'Delete this trigger?',
                        confirmLabel: 'Delete',
                        danger: true,
                        onConfirm: async () => {
                            try {
                                await fetchJson(`/api/triggers/${encodeURIComponent(triggerId)}`, { method: 'DELETE' });
                                hideActionModal();
                                setStatus('triggers-status', 'Trigger deleted.');
                                await loadTriggers();
                                await loadProblems();
                            } catch (error) {
                                setStatus('triggers-status', error.message, true);
                            }
                        },
                    });
                }
                return;
            }

            if (!event.target.closest('.menu-popover')) {
                closeAllMenus();
            }
        });

        async function refreshAll() {
            const authed = await checkAuth();
            if (!authed) return;
            await loadNodes();
            await loadUsers();
            await loadAgents();
            await loadLatestMetrics();
            await loadGraph();
            await loadTriggerScripts();
            await loadTriggers();
            await loadProblems();
            await loadLogs();
            await loadTopProcesses();
        }

        renderTabs();
        setStatus('knowledge-base-status', 'Choose a node and click "Run KB solve" to fetch Knowledge Base results.');
        setStatus('llm-status', 'Choose a node and click "Analyze node" to run LLM diagnostics.');
        renderLlmOutput();
        renderLlmRecommendations();
        document.getElementById('create-user-form').addEventListener('submit', async (event) => {
            event.preventDefault();
            const login = document.getElementById('user-login-input').value.trim();
            const password = document.getElementById('user-password-input').value;
            const email = document.getElementById('user-email-input').value.trim();
            const display_name = document.getElementById('user-display-name-input').value.trim();
            if (!login || !password || !email) {
                setStatus('users-status', 'Login, Password and Email are required.', true);
                return;
            }
            try {
                await fetchJson('/api/users', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ login, password, email, display_name: display_name || null }),
                });
                event.target.reset();
                setStatus('users-status', 'User created.');
                await loadUsers();
            } catch (error) {
                setStatus('users-status', error.message, true);
            }
        });
        refreshAll();
        setInterval(refreshAll, 5000);
    </script>
</body>
</html>
    """
