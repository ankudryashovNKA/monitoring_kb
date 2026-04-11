from __future__ import annotations

from collections import defaultdict, deque
import contextlib
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
import logging
import operator
import smtplib
from typing import Deque

from fastapi import FastAPI, HTTPException, Query, Request, Response, status
import httpx

from app.api.users import router as users_router
from app.config import settings
from app.db.base import Base
from app.db.session import SessionLocal, engine
from app.models.agent import Agent
import app.models.metric  # noqa: F401
import app.models.node  # noqa: F401
import app.models.log_entry  # noqa: F401
import app.models.trigger  # noqa: F401
import app.models.user  # noqa: F401
import app.models.agent  # noqa: F401
from app.security.agent_auth import (
    register_agent,
    rotate_agent_secret,
    validate_agent_request,
)
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.models.metric import Metric
from app.models.node import Node
from app.models.log_entry import LogEntry
from app.models.trigger import Trigger
from app.models.user import User
from app.security.user_auth import decode_session_token, hash_password, make_session_token, verify_password
from sqlalchemy import inspect, text

RETENTION_PERIOD = timedelta(hours=1)
RECENT_POINTS_LIMIT = 10
LOG_POINTS_LIMIT = 100
MAX_STORED_LOGS_PER_NODE_AND_SEVERITY = 2000
LOG_SEVERITY_LEVELS = ("DEBUG", "INFO", "NOTICE", "WARNING", "ERROR", "CRITICAL", "ALERT", "EMERGENCY")

logger = logging.getLogger(__name__)


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


class MetricIn(BaseModel):
    node_id: str = Field(..., min_length=1, max_length=100)
    agent_id: str | None = Field(default=None, min_length=1, max_length=64)
    cpu_percent: float = Field(..., ge=0, le=100)
    ram_percent: float = Field(..., ge=0, le=100)
    uptime_seconds: float = Field(default=0, ge=0)
    swap_percent: float = Field(default=0, ge=0, le=100)
    disk_read_time_ms: float = Field(default=0, ge=0)
    disk_write_time_ms: float = Field(default=0, ge=0)
    zombie_processes: int = Field(default=0, ge=0)
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


class TriggerCreateIn(BaseModel):
    node_id: str = Field(..., min_length=1, max_length=100)
    name: str = Field("Trigger", min_length=1, max_length=120)
    metric_name: str = Field(
        ...,
        pattern="^(cpu_percent|ram_percent|swap_percent|uptime_seconds|disk_read_time_ms|disk_write_time_ms|zombie_processes)$",
    )
    operator: str = Field(..., pattern="^(>|<)$")
    threshold: float = Field(..., ge=0)
    alert_user_id: int | None = Field(default=None, ge=1)


class TriggerUpdateIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=120)
    threshold: float = Field(..., ge=0)
    alert_user_id: int | None = Field(default=None, ge=1)


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


class LoginIn(BaseModel):
    login: str = Field(..., min_length=1, max_length=64)
    password: str = Field(..., min_length=1, max_length=256)


app = FastAPI(title="Monitoring KB MVP")
app.include_router(users_router)

_kb_last_updated: datetime | None = None

UNPROTECTED_PATH_PREFIXES = (
    "/api/auth/login",
    "/api/auth/logout",
    "/api/agent/metrics",
    "/api/agent/logs",
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


def init_db() -> None:
    # For production use Alembic migrations instead of create_all.
    Base.metadata.create_all(bind=engine)
    _migrate_users_table()
    _migrate_triggers_table()
    _migrate_metrics_table()
    _migrate_log_entries_table()
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
    if "zombie_processes" not in existing_columns:
        statements.append("ALTER TABLE metrics ADD COLUMN zombie_processes INTEGER NOT NULL DEFAULT 0")

    with engine.begin() as connection:
        for statement in statements:
            connection.execute(text(statement))


def _migrate_triggers_table() -> None:
    inspector = inspect(engine)
    if "triggers" not in inspector.get_table_names():
        return

    existing_columns = {column["name"] for column in inspector.get_columns("triggers")}
    statements: list[str] = []
    if "alert_user_id" not in existing_columns:
        statements.append("ALTER TABLE triggers ADD COLUMN alert_user_id INTEGER")
    if "alert_sent" not in existing_columns:
        statements.append("ALTER TABLE triggers ADD COLUMN alert_sent BOOLEAN DEFAULT 0 NOT NULL")

    with engine.begin() as connection:
        for statement in statements:
            connection.execute(text(statement))


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


@app.post("/api/auth/login")
def login(payload: LoginIn, response: Response) -> dict[str, str]:
    with SessionLocal() as db:
        user = db.query(User).filter(User.login == payload.login.strip()).first()
        if user is None or not verify_password(payload.password, user.password_hash):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid login or password")

    token = make_session_token(payload.login.strip())
    response.set_cookie("dashboard_session", token, httponly=True, samesite="lax", secure=False, max_age=24 * 3600)
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
        "alert_to_login": trigger.alert_user.login if trigger.alert_user else None,
        "alert_to_display_name": trigger.alert_user.display_name if trigger.alert_user else None,
        "is_active": _is_trigger_active(trigger, metric),
        "created_at": trigger.created_at.isoformat(),
    }
    if include_latest:
        payload["latest_value"] = latest_value
    return payload


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
            continue
        if trigger.alert_sent:
            continue
        if trigger.alert_user_id is None:
            continue
        user = db.query(User).filter(User.id == trigger.alert_user_id).first()
        if user is None:
            continue
        if _send_trigger_alert_email(trigger, user, metric_value):
            trigger.alert_sent = True


def _extract_metric_value(metric: Metric, metric_name: str) -> float:
    if metric_name == "cpu_percent":
        return metric.cpu_percent
    if metric_name == "ram_percent":
        return metric.ram_percent
    if metric_name == "swap_percent":
        return metric.swap_percent
    if metric_name == "uptime_seconds":
        return metric.uptime_seconds
    if metric_name == "disk_read_time_ms":
        return metric.disk_read_time_ms
    if metric_name == "disk_write_time_ms":
        return metric.disk_write_time_ms
    if metric_name == "zombie_processes":
        return float(metric.zombie_processes)
    raise ValueError(f"Unsupported metric name: {metric_name}")


def _extract_metric_input_value(metric: MetricIn, metric_name: str) -> float:
    if metric_name == "cpu_percent":
        return metric.cpu_percent
    if metric_name == "ram_percent":
        return metric.ram_percent
    if metric_name == "swap_percent":
        return metric.swap_percent
    if metric_name == "uptime_seconds":
        return metric.uptime_seconds
    if metric_name == "disk_read_time_ms":
        return metric.disk_read_time_ms
    if metric_name == "disk_write_time_ms":
        return metric.disk_write_time_ms
    if metric_name == "zombie_processes":
        return float(metric.zombie_processes)
    raise ValueError(f"Unsupported metric name: {metric_name}")


@app.post("/api/metrics")
def ingest_metric(metric: MetricIn) -> dict[str, str]:
    timestamp = metric.timestamp or _utcnow()
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)

    normalized_timestamp = timestamp.astimezone(timezone.utc)
    cutoff = _utcnow() - RETENTION_PERIOD

    with SessionLocal() as db:
        db.query(Metric).filter(Metric.timestamp < cutoff).delete(synchronize_session=False)

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
                zombie_processes=metric.zombie_processes,
                timestamp=normalized_timestamp,
            )
        )
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
def list_metrics(node_id: str | None = None) -> dict[str, list[dict[str, str | float]]]:
    now = _utcnow()
    cutoff = now - RETENTION_PERIOD

    with SessionLocal() as db:
        db.query(Metric).filter(Metric.timestamp < cutoff).delete(synchronize_session=False)
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
                "zombie_processes": metric.zombie_processes,
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

    payload = _latest_filesystems.get(node_id)
    if payload is None:
        return {"node_id": node_id, "filesystems": [], "timestamp": None}
    return payload


@app.get("/api/metrics/history")
def list_metric_history(
    node_id: str,
    metric_name: str = Query(
        "cpu_percent",
        pattern="^(cpu_percent|ram_percent|swap_percent|uptime_seconds|disk_read_time_ms|disk_write_time_ms|zombie_processes)$",
    ),
    interval_minutes: int = Query(15, ge=1, le=60),
) -> dict[str, str | list[dict[str, str | float]]]:
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
        node.display_name = next_name
        db.commit()
        db.refresh(node)
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

        trigger = Trigger(
            node_id=payload.node_id,
            name=payload.name,
            metric_name=payload.metric_name,
            operator=payload.operator,
            threshold=payload.threshold,
            alert_user_id=payload.alert_user_id,
            alert_sent=False,
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

        trigger.name = payload.name
        trigger.threshold = payload.threshold
        trigger.alert_user_id = payload.alert_user_id
        trigger.alert_sent = False
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


@app.post("/api/llm/generate")
async def generate_llm(payload: LLMGenerateIn) -> dict[str, str]:
    try:
        async with httpx.AsyncClient(timeout=120.0) as client:
            response = await client.post(
                "http://localhost:11434/api/generate",
                json={"model": "gemma3:4b", "prompt": payload.prompt, "stream": False},
            )
            response.raise_for_status()
            data = response.json()
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail=f"LLM service error: {exc}") from exc

    return {"response": str(data.get("response", ""))}


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
        :root {
            color-scheme: light;
            --bg: #f4f7fb;
            --bg-gradient-start: #f8fbff;
            --bg-gradient-end: #eef3fa;
            --panel: #ffffff;
            --panel-alt: #f8fbff;
            --border: #dbe3ef;
            --text: #1f2d3d;
            --muted: #6f7f95;
            --accent: #2f95e9;
            --accent-soft: rgba(47, 149, 233, 0.18);
            --danger: #cf4557;
            --shadow: 0 6px 12px rgba(31, 45, 61, 0.06);
            --sidebar-bg: #174a72;
            --sidebar-bg-strong: #0f3b5f;
            --sidebar-text: #d7e7f7;
            --sidebar-muted: #9ebdd8;
            --sidebar-active: #0f3e63;
        }
        * { box-sizing: border-box; }
        body {
            margin: 0;
            font-family: Inter, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background: linear-gradient(180deg, var(--bg-gradient-start) 0%, var(--bg-gradient-end) 100%);
            color: var(--text);
        }
        .layout {
            display: flex;
            min-height: 100vh;
        }
        .sidebar {
            width: 260px;
            position: sticky;
            top: 0;
            height: 100vh;
            overflow-y: auto;
            background: linear-gradient(180deg, var(--sidebar-bg-strong) 0%, var(--sidebar-bg) 100%);
            border-right: 1px solid rgba(170, 202, 230, 0.25);
            padding: 1rem 0.65rem;
            transition: width 0.25s ease, padding 0.25s ease, border-color 0.25s ease;
            box-shadow: 4px 0 10px rgba(8, 24, 39, 0.14);
            z-index: 10;
        }
        .sidebar.collapsed {
            width: 0;
            padding: 0;
            border-right-color: transparent;
            overflow: hidden;
        }
        .brand {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 0.5rem;
            margin-bottom: 1.5rem;
        }
        .brand-title {
            font-size: 1.1rem;
            font-weight: bold;
            margin: 0;
            color: #f5fbff;
        }
        .sidebar.collapsed .brand-copy {
            display: none;
        }
        .toggle-btn, .nav-btn, button, select, input, textarea {
            border-radius: 0.35rem;
            border: 1px solid var(--border);
            background: #fff;
            color: var(--text);
        }
        .toggle-btn, .nav-btn, button {
            cursor: pointer;
        }
        .toggle-btn {
            width: 34px;
            height: 34px;
            border-color: rgba(194, 219, 242, 0.4);
            background: rgba(255, 255, 255, 0.08);
            color: #dceeff;
        }
        .nav {
            display: flex;
            flex-direction: column;
            gap: 0.35rem;
        }
        .nav-btn {
            display: flex;
            align-items: center;
            gap: 0.55rem;
            width: 100%;
            padding: 0.48rem 0.58rem;
            text-align: left;
            transition: background 0.2s ease, border-color 0.2s ease;
            border: 1px solid transparent;
            background: transparent;
            color: var(--sidebar-text);
            font-weight: 500;
        }
        .nav-btn:hover {
            border-color: rgba(178, 210, 235, 0.35);
            background: rgba(15, 62, 99, 0.72);
            transform: none;
        }
        .nav-btn.active {
            background: var(--sidebar-active);
            border-color: rgba(176, 209, 235, 0.35);
            color: #f4fbff;
        }
        .nav-label {
            white-space: nowrap;
        }
        .content {
            flex: 1;
            padding: 2rem;
        }
        .sidebar-unhide-btn {
            position: fixed;
            top: 12px;
            left: 12px;
            z-index: 20;
            width: 34px;
            height: 34px;
            border-radius: 0.35rem;
            border: 1px solid #c5d8ee;
            background: #ffffff;
            box-shadow: 0 3px 8px rgba(31, 45, 61, 0.14);
            cursor: pointer;
        }
        .panel {
            background: var(--panel);
            border: 1px solid var(--border);
            border-radius: 0.9rem;
            padding: 1.5rem;
            box-shadow: var(--shadow);
        }
        .page-header {
            margin-bottom: 1.25rem;
        }
        h1, h2, h3, p { margin-top: 0; }
        .meta { color: var(--muted); }
        .toolbar {
            display: flex;
            flex-wrap: wrap;
            gap: 0.75rem;
            align-items: flex-end;
            margin-bottom: 1rem;
        }
        .toolbar label {
            display: flex;
            flex-direction: column;
            gap: 0.35rem;
        }
        select, input, textarea {
            min-height: 32px;
            padding: 0.3rem 0.5rem;
        }
        textarea {
            width: 100%;
            min-height: 220px;
            resize: vertical;
            font-family: inherit;
        }
        .llm-grid {
            display: grid;
            grid-template-columns: repeat(2, minmax(280px, 1fr));
            gap: 1rem;
        }
        button {
            min-height: 32px;
            padding: 0.28rem 0.62rem;
            background: var(--accent-soft);
            border-color: var(--accent);
            font-weight: 600;
            transition: background 0.2s ease, border-color 0.2s ease, transform 0.2s ease;
        }
        button:hover {
            background: rgba(1, 115, 178, 0.16);
            border-color: #016198;
            transform: translateY(-1px);
        }
        button.danger {
            border-color: var(--danger);
            background: rgba(207, 69, 87, 0.1);
        }
        button.secondary {
            background: transparent;
            border-color: var(--border);
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 1rem;
            background: #fff;
            border-radius: 0.8rem;
        }
        th, td {
            padding: 0.85rem;
            border-bottom: 1px solid var(--border);
            text-align: left;
            vertical-align: top;
        }
        th {
            background: #f2f7fc;
        }
        tr:hover td {
            background: #fbfdff;
        }
        tr:last-child td { border-bottom: none; }
        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 1rem;
            margin-bottom: 1rem;
        }
        .stat {
            background: var(--panel-alt);
            border: 1px solid var(--border);
            border-radius: 0.8rem;
            padding: 1rem;
        }
        .stat-label { color: var(--muted); font-size: 0.9rem; }
        .stat-value { font-size: 1.5rem; font-weight: bold; margin-top: 0.35rem; }
        .menu-cell {
            position: relative;
            text-align: right;
            width: 64px;
        }
        .menu-btn {
            min-height: 26px;
            padding: 0.15rem 0.32rem;
            line-height: 1;
        }
        .menu-popover {
            position: fixed;
            z-index: 9999;
            display: flex;
            flex-direction: column;
            gap: 0.35rem;
            padding: 0.5rem;
            border: 1px solid var(--border);
            border-radius: 0.55rem;
            background: #fff;
            min-width: 146px;
            box-shadow: 0 6px 14px rgba(31, 45, 61, 0.1);
        }
        .menu-popover button { width: 100%; text-align: left; }
        #global-menu[hidden] { display: none !important; }
        .empty, .status {
            color: var(--muted);
            padding: 1rem 0;
        }
        .error { color: var(--danger); }
        .modal-backdrop {
            position: fixed;
            inset: 0;
            background: rgba(18, 33, 53, 0.45);
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 1rem;
            z-index: 10000;
        }
        .modal {
            width: min(560px, 100%);
            background: #fff;
            border: 1px solid var(--border);
            border-radius: 0.8rem;
            padding: 1rem;
            box-shadow: var(--shadow);
        }
        .modal h3 { margin-bottom: 0.75rem; }
        .credentials-grid {
            display: grid;
            grid-template-columns: 1fr auto;
            gap: 0.5rem;
            align-items: end;
        }
        .credentials-grid input { width: 100%; font-family: monospace; }
        .modal-actions {
            display: flex;
            gap: 0.5rem;
            justify-content: flex-end;
            margin-top: 0.75rem;
        }
        .modal-form-grid {
            display: grid;
            gap: 0.75rem;
            margin-top: 0.5rem;
        }
        [hidden] { display: none !important; }
        @media (max-width: 900px) {
            .content { padding: 1rem; }
            .sidebar { position: fixed; }
            .llm-grid { grid-template-columns: 1fr; }
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
                <button id="sidebar-toggle" class="toggle-btn" type="button" aria-label="Toggle menu">☰</button>
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
        <button id="sidebar-unhide" class="sidebar-unhide-btn" type="button" aria-label="Show menu" hidden>☰</button>
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
                <table>
                    <thead>
                        <tr>
                            <th>Time (UTC+3)</th>
                            <th>Node</th>
                            <th>CPU %</th>
                            <th>RAM %</th>
                            <th>Swap %</th>
                            <th>Uptime (s)</th>
                            <th>Disk read (ms)</th>
                            <th>Disk write (ms)</th>
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
                            <option value="disk_read_time_ms">Disk read time (ms)</option>
                            <option value="disk_write_time_ms">Disk write time (ms)</option>
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
                    <rect x="0" y="0" width="1200" height="360" fill="#f8fbff" stroke="#c9d8ea"></rect>
                    <g id="graph-y-grid"></g>
                    <line x1="80" y1="300" x2="1160" y2="300" stroke="#c9d8ea" />
                    <line x1="80" y1="40" x2="80" y2="300" stroke="#c9d8ea" />
                    <g id="graph-y-labels"></g>
                    <g id="graph-x-labels"></g>
                    <polyline id="graph-line" fill="none" stroke="#0173b2" stroke-width="1.8" points=""></polyline>
                    <g id="graph-points"></g>
                    <text id="graph-title" x="80" y="24" fill="#6f7f95">No data</text>
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
                            <option value="disk_read_time_ms">Disk read time (ms)</option>
                            <option value="disk_write_time_ms">Disk write time (ms)</option>
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
                    <p class="meta">Input: введите промпт, Output: получите ответ локальной модели gemma3:4b.</p>
                </div>
                <div class="toolbar">
                    <button id="run-llm" type="button">Run LLM</button>
                </div>
                <div class="llm-grid">
                    <label>
                        <span class="meta">Input</span><br />
                        <textarea id="llm-input" placeholder="Введите текст..."></textarea>
                    </label>
                    <label>
                        <span class="meta">Output</span><br />
                        <textarea id="llm-output" readonly placeholder="Ответ модели..."></textarea>
                    </label>
                </div>
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
            disk_read_time_ms: { label: 'Disk read time (ms)', unit: 'ms' },
            disk_write_time_ms: { label: 'Disk write time (ms)', unit: 'ms' },
            zombie_processes: { label: 'Zombie processes', unit: '' },
        };

        const state = {
            nodes: [],
            agents: [],
            triggers: [],
            problems: [],
            knowledgeBase: [],
            users: [],
            currentLogin: '',
            latestSelectedNodeId: '',
            graphSelectedNodeId: '',
            triggerSelectedNodeId: '',
            logsSelectedNodeId: '',
            logsSelectedSeverity: 'INFO',
            topSelectedNodeId: '',
            kbSelectedNodeId: '',
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
            if (metricName === 'zombie_processes') {
                return `${Math.round(numeric)}${unit}`;
            }
            return `${numeric.toFixed(2)}${unit}`;
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
            select.innerHTML = '';
            graphSelect.innerHTML = '';
            triggerSelect.innerHTML = '';
            logsSelect.innerHTML = '';
            topSelect.innerHTML = '';
            kbSelect.innerHTML = '';
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
                select.disabled = true;
                graphSelect.disabled = true;
                triggerSelect.disabled = true;
                logsSelect.disabled = true;
                topSelect.disabled = true;
                kbSelect.disabled = true;
                return;
            }

            select.disabled = false;
            graphSelect.disabled = false;
            triggerSelect.disabled = false;
            logsSelect.disabled = false;
            topSelect.disabled = false;
            kbSelect.disabled = false;
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
            }
            select.value = state.latestSelectedNodeId;
            graphSelect.value = state.graphSelectedNodeId;
            triggerSelect.value = state.triggerSelectedNodeId;
            logsSelect.value = state.logsSelectedNodeId;
            topSelect.value = state.topSelectedNodeId;
            kbSelect.value = state.kbSelectedNodeId;
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
                body.innerHTML = '<tr><td colspan="9" class="empty">No metrics for this node yet.</td></tr>';
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
                    <td>${Number(item.zombie_processes).toFixed(0)}</td>
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

        function renderTriggersTable() {
            const body = document.getElementById('triggers-body');
            body.innerHTML = '';
            if (!state.triggers.length) {
                body.innerHTML = '<tr><td colspan="8" class="empty">No triggers created for the selected node.</td></tr>';
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
                menu.innerHTML = `
                    <button type="button" data-trigger-action="edit" data-trigger-id="${triggerId}" data-trigger-name="${triggerName}" data-trigger-threshold="${triggerThreshold}">Edit</button>
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
                setStatus('latest-status', 'Waiting for nodes to send data.');
                return;
            }

            try {
                const data = await fetchJson(`/api/metrics?node_id=${encodeURIComponent(node.node_id)}`);
                renderLatestSummary(data.items, node);
                renderLatestTable(data.items);
                setStatus('latest-status', data.items.length ? '' : 'No recent metrics for the selected node.');
            } catch (error) {
                renderLatestSummary([], node);
                renderLatestTable([]);
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
            const prompt = document.getElementById('llm-input').value.trim();
            if (!prompt) {
                setStatus('llm-status', 'Введите текст в input.', true);
                return;
            }
            setStatus('llm-status', 'Generating...');
            document.getElementById('llm-output').value = '';
            try {
                const data = await fetchJson('/api/llm/generate', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ prompt }),
                });
                document.getElementById('llm-output').value = data.response || '';
                setStatus('llm-status', 'Done.');
            } catch (error) {
                document.getElementById('llm-output').value = '';
                setStatus('llm-status', error.message, true);
            }
        }

        function setSidebarCollapsed(collapsed) {
            document.getElementById('sidebar').classList.toggle('collapsed', collapsed);
            document.getElementById('sidebar-unhide').hidden = !collapsed;
        }

        document.getElementById('sidebar-toggle').addEventListener('click', () => {
            setSidebarCollapsed(true);
        });

        document.getElementById('sidebar-unhide').addEventListener('click', () => {
            setSidebarCollapsed(false);
        });

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
            document.getElementById('graph-node-select').value = state.graphSelectedNodeId;
            document.getElementById('trigger-node-select').value = state.triggerSelectedNodeId;
            document.getElementById('logs-node-select').value = state.logsSelectedNodeId;
            document.getElementById('top-node-select').value = state.topSelectedNodeId;
            document.getElementById('kb-node-select').value = state.kbSelectedNodeId;
            await loadLatestMetrics();
            await loadGraph();
            await loadTriggers();
            await loadLogs();
            await loadTopProcesses();
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
            const alertUserId = alertUserRaw ? Number(alertUserRaw) : null;
            if (!Number.isFinite(threshold) || threshold < 0) {
                setStatus('triggers-status', 'Threshold must be a positive number or zero.', true);
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
        document.getElementById('run-llm').addEventListener('click', runLlm);
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
                        ],
                        confirmLabel: 'Save',
                        onConfirm: async () => {
                            const nextName = document.getElementById('edit-trigger-name').value.trim();
                            const threshold = Number(document.getElementById('edit-trigger-threshold').value);
                            const alertUserRaw = document.getElementById('edit-trigger-alert-user-id').value;
                            const alertUserId = alertUserRaw ? Number(alertUserRaw) : null;
                            if (!nextName) {
                                setStatus('triggers-status', 'Trigger name cannot be empty.', true);
                                return;
                            }
                            if (!Number.isFinite(threshold) || threshold < 0 || threshold > 100) {
                                setStatus('triggers-status', 'Threshold must be between 0 and 100.', true);
                                return;
                            }
                            try {
                                await fetchJson(`/api/triggers/${encodeURIComponent(triggerId)}`, {
                                    method: 'PATCH',
                                    headers: { 'Content-Type': 'application/json' },
                                    body: JSON.stringify({ name: nextName, threshold, alert_user_id: alertUserId }),
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
            await loadTriggers();
            await loadProblems();
            await loadLogs();
            await loadTopProcesses();
        }

        renderTabs();
        setStatus('knowledge-base-status', 'Choose a node and click "Run KB solve" to fetch Knowledge Base results.');
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
