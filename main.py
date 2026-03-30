from __future__ import annotations

from collections import defaultdict, deque
import contextlib
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
import asyncio
import logging
import operator
from typing import Deque

from fastapi import FastAPI, HTTPException, Query, Request
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

from app.models.metric import Metric
from app.models.node import Node
from app.models.log_entry import LogEntry
from app.models.trigger import Trigger

RETENTION_PERIOD = timedelta(hours=1)
RECENT_POINTS_LIMIT = 10
LOG_POINTS_LIMIT = 100
MAX_STORED_LOGS_PER_NODE = 2000
KB_POLL_INTERVAL_SECONDS = 600

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


class MetricIn(BaseModel):
    node_id: str = Field(..., min_length=1, max_length=100)
    cpu_percent: float = Field(..., ge=0, le=100)
    ram_percent: float = Field(..., ge=0, le=100)
    os_name: str = Field(..., min_length=1, max_length=200)
    cpu_cores: int = Field(..., ge=1, le=4096)
    ram_total_mb: int = Field(..., ge=1)
    ip_address: str = Field(..., min_length=1, max_length=100)
    timestamp: datetime | None = None


class NodeRenameIn(BaseModel):
    display_name: str = Field(..., min_length=1, max_length=100)


class LogEntryIn(BaseModel):
    source: str = Field(..., min_length=1, max_length=120)
    message: str = Field(..., min_length=1, max_length=8000)
    captured_at: datetime | None = None


class LogsIn(BaseModel):
    node_id: str = Field(..., min_length=1, max_length=100)
    os_name: str = Field(..., min_length=1, max_length=200)
    cpu_cores: int = Field(..., ge=1, le=4096)
    ram_total_mb: int = Field(..., ge=1)
    ip_address: str = Field(..., min_length=1, max_length=100)
    entries: list[LogEntryIn] = Field(default_factory=list, max_length=LOG_POINTS_LIMIT)


class TriggerCreateIn(BaseModel):
    node_id: str = Field(..., min_length=1, max_length=100)
    name: str = Field("Trigger", min_length=1, max_length=120)
    metric_name: str = Field(..., pattern="^(cpu_percent|ram_percent)$")
    operator: str = Field(..., pattern="^(>|<)$")
    threshold: float = Field(..., ge=0, le=100)


class TriggerUpdateIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=120)
    threshold: float = Field(..., ge=0, le=100)


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


app = FastAPI(title="Monitoring KB MVP")
app.include_router(users_router)

_kb_results_cache: list[dict[str, str | list[dict[str, str]]]] = []
_kb_last_updated: datetime | None = None
_kb_last_error: str | None = None


def init_db() -> None:
    # For production use Alembic migrations instead of create_all.
    Base.metadata.create_all(bind=engine)


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


async def _fetch_knowledge_base_once() -> None:
    global _kb_results_cache, _kb_last_updated, _kb_last_error
    if not _knowledge_base_enabled():
        _kb_last_error = "Knowledge Base integration disabled: missing KB_ID or KB_JWT_TOKEN."
        return

    assert settings.kb_id is not None
    assert settings.kb_jwt_token is not None
    url = f"{settings.kb_api_base_url.rstrip('/')}/solve/{settings.kb_id}"
    async with httpx.AsyncClient(timeout=20.0) as client:
        response = await client.post(
            url,
            headers={
                "accept": "*/*",
                "Authorization": settings.kb_jwt_token,
                "Content-Type": "application/json-patch+json",
            },
            json={"presetName": settings.kb_preset_name},
        )
        response.raise_for_status()
        _kb_results_cache = _normalize_kb_results(response.json())
        _kb_last_updated = _utcnow()
        _kb_last_error = None


async def _knowledge_base_polling_loop() -> None:
    while True:
        try:
            await _fetch_knowledge_base_once()
        except Exception as exc:  # noqa: BLE001
            logger.exception("Knowledge Base sync failed")
            global _kb_last_error
            _kb_last_error = str(exc)
        await asyncio.sleep(KB_POLL_INTERVAL_SECONDS)


@app.on_event("startup")
async def on_startup() -> None:
    init_db()
    if _knowledge_base_enabled():
        app.state.kb_poller_task = asyncio.create_task(_knowledge_base_polling_loop())
    else:
        global _kb_last_error
        _kb_last_error = "Knowledge Base integration disabled: missing KB_ID or KB_JWT_TOKEN."


@app.on_event("shutdown")
async def on_shutdown() -> None:
    task = getattr(app.state, "kb_poller_task", None)
    if task is not None:
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task


# Backward-compatible placeholders used by legacy tests.
_storage: dict[str, Deque[MetricPoint]] = defaultdict(deque)
_nodes: dict[str, NodeInfo] = {}

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
    metric_value = metric.cpu_percent if trigger.metric_name == "cpu_percent" else metric.ram_percent
    return comparator(metric_value, trigger.threshold)


def _serialize_trigger(
    trigger: Trigger,
    node_display_name: str,
    metric: Metric | None,
    include_latest: bool = True,
) -> dict[str, str | float | int | bool | None]:
    latest_value = None
    if metric is not None:
        latest_value = metric.cpu_percent if trigger.metric_name == "cpu_percent" else metric.ram_percent
    payload: dict[str, str | float | int | bool | None] = {
        "id": trigger.id,
        "node_id": trigger.node_id,
        "node_display_name": node_display_name,
        "name": trigger.name,
        "metric_name": trigger.metric_name,
        "operator": trigger.operator,
        "threshold": trigger.threshold,
        "is_active": _is_trigger_active(trigger, metric),
        "created_at": trigger.created_at.isoformat(),
    }
    if include_latest:
        payload["latest_value"] = latest_value
    return payload


@app.post("/api/metrics")
def ingest_metric(metric: MetricIn) -> dict[str, str]:
    timestamp = metric.timestamp or _utcnow()
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)

    normalized_timestamp = timestamp.astimezone(timezone.utc)
    cutoff = _utcnow() - RETENTION_PERIOD

    with SessionLocal() as db:
        db.query(Metric).filter(Metric.timestamp < cutoff).delete(synchronize_session=False)

        node = db.query(Node).filter(Node.node_id == metric.node_id).first()
        if node is None:
            node = Node(
                node_id=metric.node_id,
                display_name=metric.node_id,
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

        db.add(
            Metric(
                node_id=metric.node_id,
                cpu_percent=metric.cpu_percent,
                ram_percent=metric.ram_percent,
                timestamp=normalized_timestamp,
            )
        )
        db.commit()
    return {"status": "ok"}


@app.post("/api/agent/metrics")
async def ingest_metric_from_agent(request: Request) -> dict[str, str]:
    raw_body = await request.body()
    request.state.raw_body = raw_body
    metric = MetricIn.model_validate_json(raw_body)
    with SessionLocal() as db:
        _agent = validate_agent_request(request, db)
    return ingest_metric(metric)


@app.post("/api/logs")
def ingest_logs(payload: LogsIn) -> dict[str, str | int]:
    now = _utcnow()
    with SessionLocal() as db:
        node = db.query(Node).filter(Node.node_id == payload.node_id).first()
        if node is None:
            node = Node(
                node_id=payload.node_id,
                display_name=payload.node_id,
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

        inserted_count = 0
        for entry in payload.entries:
            captured_at = entry.captured_at or now
            if captured_at.tzinfo is None:
                captured_at = captured_at.replace(tzinfo=timezone.utc)
            db.add(
                LogEntry(
                    node_id=payload.node_id,
                    source=entry.source,
                    message=entry.message,
                    captured_at=captured_at.astimezone(timezone.utc),
                )
            )
            inserted_count += 1

        overflow_ids = [
            row[0]
            for row in (
                db.query(LogEntry.id)
                .filter(LogEntry.node_id == payload.node_id)
                .order_by(LogEntry.captured_at.desc(), LogEntry.id.desc())
                .offset(MAX_STORED_LOGS_PER_NODE)
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
        _agent = validate_agent_request(request, db)
    return ingest_logs(payload)


@app.get("/api/logs")
def list_logs(node_id: str) -> dict[str, str | list[dict[str, str]]]:
    with SessionLocal() as db:
        node = db.query(Node).filter(Node.node_id == node_id).first()
        if node is None:
            raise HTTPException(status_code=404, detail="Node not found")

        rows = (
            db.query(LogEntry)
            .filter(LogEntry.node_id == node_id)
            .order_by(LogEntry.captured_at.desc(), LogEntry.id.desc())
            .limit(LOG_POINTS_LIMIT)
            .all()
        )
        items = [
            {
                "source": row.source,
                "message": row.message,
                "captured_at": row.captured_at.isoformat(),
            }
            for row in rows
        ]
        return {
            "node_id": node.node_id,
            "display_name": node.display_name,
            "os_name": node.os_name,
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
            .join(Node, Node.node_id == Metric.node_id)
            .filter(Metric.timestamp >= cutoff)
        )
        if node_id:
            node_exists = db.query(Node.node_id).filter(Node.node_id == node_id).first()
            if node_exists is None:
                raise HTTPException(status_code=404, detail="Node not found")
            query = query.filter(Metric.node_id == node_id)

        rows = query.order_by(Metric.timestamp.desc()).limit(RECENT_POINTS_LIMIT).all()
        items = [
            {
                "node_id": metric.node_id,
                "cpu_percent": metric.cpu_percent,
                "ram_percent": metric.ram_percent,
                "timestamp": metric.timestamp.isoformat(),
                "display_name": display_name,
            }
            for metric, display_name in rows
        ]
        items.reverse()
        return {"items": items}


@app.get("/api/metrics/history")
def list_metric_history(
    node_id: str,
    metric_name: str = Query("cpu_percent", pattern="^(cpu_percent|ram_percent)$"),
    interval_minutes: int = Query(15, ge=1, le=60),
) -> dict[str, str | list[dict[str, str | float]]]:
    now = _utcnow()
    cutoff = max(now - RETENTION_PERIOD, now - timedelta(minutes=interval_minutes))

    with SessionLocal() as db:
        db.query(Metric).filter(Metric.timestamp < now - RETENTION_PERIOD).delete(synchronize_session=False)
        db.commit()

        node = db.query(Node).filter(Node.node_id == node_id).first()
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
                "value": metric.cpu_percent if metric_name == "cpu_percent" else metric.ram_percent,
            }
            for metric in rows
        ]

        return {"node_id": node_id, "metric_name": metric_name, "items": items}


@app.get("/api/nodes")
def list_nodes() -> dict[str, list[dict[str, str | int | bool | None]]]:
    with SessionLocal() as db:
        rows = (
            db.query(Node, Agent)
            .outerjoin(Agent, Agent.agent_id == Node.node_id)
            .order_by(func.lower(Node.display_name))
            .all()
        )
        items = [
            {
                "node_id": node.node_id,
                "display_name": node.display_name,
                "os_name": node.os_name,
                "cpu_cores": node.cpu_cores,
                "ram_total_mb": node.ram_total_mb,
                "ip_address": node.ip_address,
                "last_seen": node.last_seen.isoformat(),
                "agent_id": agent.agent_id if agent else None,
                "agent_enabled": agent.enabled if agent else None,
            }
            for node, agent in rows
        ]
        return {"items": items}


@app.patch("/api/nodes/{node_id}")
def rename_node(node_id: str, payload: NodeRenameIn) -> dict[str, str | int]:
    with SessionLocal() as db:
        node = db.query(Node).filter(Node.node_id == node_id).first()
        if node is None:
            raise HTTPException(status_code=404, detail="Node not found")

        node.display_name = payload.display_name
        db.commit()
        db.refresh(node)
        return {
            "node_id": node.node_id,
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
        node = db.query(Node).filter(Node.node_id == node_id).first()
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
        node = db.query(Node).filter(Node.node_id == payload.node_id).first()
        if node is None:
            raise HTTPException(status_code=404, detail="Node not found")

        trigger = Trigger(
            node_id=payload.node_id,
            name=payload.name,
            metric_name=payload.metric_name,
            operator=payload.operator,
            threshold=payload.threshold,
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

        trigger.name = payload.name
        trigger.threshold = payload.threshold
        db.commit()
        db.refresh(trigger)

        node = db.query(Node).filter(Node.node_id == trigger.node_id).first()
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
        query = db.query(Trigger, Node.display_name).join(Node, Node.node_id == Trigger.node_id)
        if node_id:
            node_exists = db.query(Node.node_id).filter(Node.node_id == node_id).first()
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
            .join(Node, Node.node_id == Trigger.node_id)
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


@app.get("/api/knowledge-base")
def get_knowledge_base() -> dict[str, str | list[dict[str, str | list[dict[str, str]]]] | None]:
    status = "ok" if _kb_last_error is None else "error"
    if not _knowledge_base_enabled():
        status = "disabled"
    return {
        "status": status,
        "last_updated": _kb_last_updated.isoformat() if _kb_last_updated else None,
        "error": _kb_last_error,
        "items": _kb_results_cache,
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
            --accent: #0173b2;
            --accent-soft: rgba(1, 115, 178, 0.1);
            --danger: #cf4557;
            --shadow: 0 14px 28px rgba(31, 45, 61, 0.08);
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
            background: rgba(255, 255, 255, 0.96);
            border-right: 1px solid var(--border);
            padding: 1.25rem 1rem;
            transition: width 0.25s ease, padding 0.25s ease;
            box-shadow: 6px 0 24px rgba(20, 41, 77, 0.06);
            z-index: 10;
        }
        .sidebar.collapsed {
            width: 84px;
            padding-inline: 0.75rem;
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
        }
        .brand-subtitle, .sidebar.collapsed .nav-label, .sidebar.collapsed .brand-copy {
            display: none;
        }
        .toggle-btn, .nav-btn, button, select, input, textarea {
            border-radius: 0.45rem;
            border: 1px solid var(--border);
            background: #fff;
            color: var(--text);
        }
        .toggle-btn, .nav-btn, button {
            cursor: pointer;
        }
        .toggle-btn {
            width: 40px;
            height: 40px;
        }
        .nav {
            display: flex;
            flex-direction: column;
            gap: 0.75rem;
        }
        .nav-btn {
            display: flex;
            align-items: center;
            gap: 0.75rem;
            width: 100%;
            padding: 0.7rem 0.85rem;
            text-align: left;
            transition: background 0.2s ease, border-color 0.2s ease;
        }
        .nav-btn:hover {
            border-color: #c2d2e9;
            background: #f7faff;
        }
        .nav-btn.active {
            background: var(--accent-soft);
            border-color: var(--accent);
            color: #005489;
        }
        .sidebar.collapsed .nav-btn {
            justify-content: center;
            padding-inline: 0;
        }
        .content {
            flex: 1;
            padding: 2rem;
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
            min-height: 38px;
            padding: 0.5rem 0.65rem;
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
            min-height: 38px;
            padding: 0.45rem 0.8rem;
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
            min-height: 30px;
            padding: 0.25rem 0.45rem;
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
            box-shadow: 0 14px 30px rgba(31, 45, 61, 0.16);
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
            justify-content: flex-end;
            margin-top: 0.75rem;
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
                    <p class="brand-subtitle meta">Simple node overview</p>
                </div>
                <button id="sidebar-toggle" class="toggle-btn" type="button" aria-label="Toggle menu">☰</button>
            </div>
            <nav class="nav">
                <button class="nav-btn active" data-tab="latest" type="button"><span class="nav-label">Latest data</span></button>
                <button class="nav-btn" data-tab="nodes" type="button"><span class="nav-label">Nodes</span></button>
                <button class="nav-btn" data-tab="graphs" type="button"><span class="nav-label">Graphs</span></button>
                <button class="nav-btn" data-tab="triggers" type="button"><span class="nav-label">Triggers</span></button>
                <button class="nav-btn" data-tab="problems" type="button"><span class="nav-label">Problems</span></button>
                <button class="nav-btn" data-tab="logs" type="button"><span class="nav-label">Logs</span></button>
                <button class="nav-btn" data-tab="knowledge-base" type="button"><span class="nav-label">Knowledge Base</span></button>
                <button class="nav-btn" data-tab="llm" type="button"><span class="nav-label">LLM</span></button>
            </nav>
        </aside>
        <main class="content">
            <section class="panel tab-panel" data-panel="latest">
                <div class="page-header">
                    <h1>Latest data</h1>
                    <p class="meta">Choose a node and inspect the latest 10 CPU/RAM samples received from it.</p>
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
                            <th>Time (UTC)</th>
                            <th>Node</th>
                            <th>CPU %</th>
                            <th>RAM %</th>
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
                            <th>Last seen (UTC)</th>
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
                        <span class="meta">Threshold (%)</span><br />
                        <input id="trigger-threshold-input" type="number" min="0" max="100" step="0.1" value="80" required />
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
                            <th>Status</th>
                            <th>Created (UTC)</th>
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
                            <th>Created (UTC)</th>
                        </tr>
                    </thead>
                    <tbody id="problems-body"></tbody>
                </table>
            </section>

            <section class="panel tab-panel" data-panel="logs" hidden>
                <div class="page-header">
                    <h2>Logs</h2>
                    <p class="meta">Latest 100 important system log entries sent by the selected node.</p>
                </div>
                <div class="toolbar">
                    <label>
                        <span class="meta">Node</span><br />
                        <select id="logs-node-select"></select>
                    </label>
                    <button id="refresh-logs" type="button">Refresh logs</button>
                </div>
                <div id="logs-status" class="status"></div>
                <table>
                    <thead>
                        <tr>
                            <th>Time (UTC)</th>
                            <th>Source</th>
                            <th>Entry</th>
                        </tr>
                    </thead>
                    <tbody id="logs-body"></tbody>
                </table>
            </section>

            <section class="panel tab-panel" data-panel="knowledge-base" hidden>
                <div class="page-header">
                    <h2>Knowledge Base</h2>
                    <p class="meta">Results from Hippocrates KB sync (updated every 10 minutes on the backend).</p>
                </div>
                <div class="toolbar">
                    <button id="refresh-knowledge-base" type="button">Refresh now</button>
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

    <script>
        const state = {
            nodes: [],
            agents: [],
            triggers: [],
            problems: [],
            knowledgeBase: [],
            latestSelectedNodeId: '',
            graphSelectedNodeId: '',
            triggerSelectedNodeId: '',
            logsSelectedNodeId: '',
            activeMenuKey: '',
            activeMenuData: null,
            activeTab: 'latest',
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
            return new Date(value).toLocaleString('en-GB', { timeZone: 'UTC' });
        }

        function formatRamMb(value) {
            return `${(value / 1024).toFixed(1)} GB (${value} MB)`;
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
            select.innerHTML = '';
            graphSelect.innerHTML = '';
            triggerSelect.innerHTML = '';
            logsSelect.innerHTML = '';
            if (!state.nodes.length) {
                const option = document.createElement('option');
                option.textContent = 'No nodes yet';
                option.value = '';
                select.appendChild(option);
                graphSelect.appendChild(option.cloneNode(true));
                triggerSelect.appendChild(option.cloneNode(true));
                logsSelect.appendChild(option.cloneNode(true));
                select.disabled = true;
                graphSelect.disabled = true;
                triggerSelect.disabled = true;
                logsSelect.disabled = true;
                return;
            }

            select.disabled = false;
            graphSelect.disabled = false;
            triggerSelect.disabled = false;
            logsSelect.disabled = false;
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

            for (const node of state.nodes) {
                const option = document.createElement('option');
                option.value = node.node_id;
                option.textContent = node.display_name;
                select.appendChild(option);
                graphSelect.appendChild(option.cloneNode(true));
                triggerSelect.appendChild(option.cloneNode(true));
                logsSelect.appendChild(option.cloneNode(true));
            }
            select.value = state.latestSelectedNodeId;
            graphSelect.value = state.graphSelectedNodeId;
            triggerSelect.value = state.triggerSelectedNodeId;
            logsSelect.value = state.logsSelectedNodeId;
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
                    timeZone: 'UTC',
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
            const latestValue = sortedItems[sortedItems.length - 1].value.toFixed(2);
            title.textContent = `${metricName === 'cpu_percent' ? 'CPU' : 'RAM'} trend (${safeInterval} min), latest: ${latestValue}%`;
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
                body.innerHTML = '<tr><td colspan="4" class="empty">No metrics for this node yet.</td></tr>';
                return;
            }

            for (const item of items.slice().reverse()) {
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td>${formatUtc(item.timestamp)}</td>
                    <td>${item.display_name || 'Unknown node'}</td>
                    <td>${item.cpu_percent.toFixed(2)}</td>
                    <td>${item.ram_percent.toFixed(2)}</td>
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

        function metricLabel(metricName) {
            return metricName === 'cpu_percent' ? 'CPU %' : 'RAM %';
        }

        function renderTriggersTable() {
            const body = document.getElementById('triggers-body');
            body.innerHTML = '';
            if (!state.triggers.length) {
                body.innerHTML = '<tr><td colspan="7" class="empty">No triggers created for the selected node.</td></tr>';
                return;
            }
            for (const trigger of state.triggers) {
                const latestValue = trigger.latest_value == null ? 'No data' : `${Number(trigger.latest_value).toFixed(2)}%`;
                const menuKey = `trigger:${trigger.id}`;
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td>${trigger.node_display_name}</td>
                    <td>${trigger.name}</td>
                    <td>${metricLabel(trigger.metric_name)} ${trigger.operator} ${Number(trigger.threshold).toFixed(2)}%</td>
                    <td>${latestValue}</td>
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
                const latestValue = trigger.latest_value == null ? 'No data' : `${Number(trigger.latest_value).toFixed(2)}%`;
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td>${trigger.node_display_name}</td>
                    <td>${trigger.name}</td>
                    <td>${metricLabel(trigger.metric_name)} ${trigger.operator} ${Number(trigger.threshold).toFixed(2)}%</td>
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
                body.innerHTML = '<tr><td colspan="3" class="empty">No logs received from this node yet.</td></tr>';
                return;
            }
            for (const entry of items) {
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td>${formatUtc(entry.captured_at)}</td>
                    <td>${entry.source}</td>
                    <td>${entry.message}</td>
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
                            ? `<button type="button" data-node-action="${isEnabled ? 'disable-agent' : 'enable-agent'}" data-node-id="${nodeId}" data-agent-id="${agentId}">${isEnabled ? 'Disable agent' : 'Enable agent'}</button>
                               <button type="button" data-node-action="rotate-agent-secret" data-node-id="${nodeId}" data-agent-id="${agentId}">Rotate secret</button>`
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

        async function loadKnowledgeBase() {
            try {
                const data = await fetchJson('/api/knowledge-base');
                state.knowledgeBase = data.items || [];
                renderKnowledgeBaseTable();
                if (data.status === 'disabled') {
                    setStatus('knowledge-base-status', data.error || 'Knowledge Base integration is disabled.');
                } else if (data.status === 'error') {
                    setStatus('knowledge-base-status', data.error || 'Failed to load Knowledge Base data.', true);
                } else {
                    const updated = data.last_updated ? formatUtc(data.last_updated) : 'never';
                    setStatus(
                        'knowledge-base-status',
                        state.knowledgeBase.length
                            ? `Last updated (UTC): ${updated}`
                            : `No results yet. Last updated (UTC): ${updated}`
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
                const data = await fetchJson(`/api/logs?node_id=${encodeURIComponent(state.logsSelectedNodeId)}`);
                renderLogsTable(data.items || []);
                const osLabel = data.os_name || 'Unknown OS';
                setStatus('logs-status', data.items.length ? `Source node OS: ${osLabel}` : `No logs yet. Source node OS: ${osLabel}`);
            } catch (error) {
                renderLogsTable([]);
                setStatus('logs-status', error.message, true);
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

        document.getElementById('sidebar-toggle').addEventListener('click', () => {
            document.getElementById('sidebar').classList.toggle('collapsed');
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
            document.getElementById('graph-node-select').value = state.graphSelectedNodeId;
            document.getElementById('trigger-node-select').value = state.triggerSelectedNodeId;
            document.getElementById('logs-node-select').value = state.logsSelectedNodeId;
            await loadLatestMetrics();
            await loadGraph();
            await loadTriggers();
            await loadLogs();
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
            if (!Number.isFinite(threshold) || threshold < 0 || threshold > 100) {
                setStatus('triggers-status', 'Threshold must be between 0 and 100.', true);
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
        document.getElementById('refresh-knowledge-base').addEventListener('click', loadKnowledgeBase);
        document.getElementById('run-llm').addEventListener('click', runLlm);
        document.getElementById('close-credentials-modal').addEventListener('click', hideCredentialsModal);
        document.getElementById('credentials-modal-backdrop').addEventListener('click', (event) => {
            if (event.target.id === 'credentials-modal-backdrop') {
                hideCredentialsModal();
            }
        });
        document.getElementById('copy-agent-id').addEventListener('click', async () => copyCredentialsField('credentials-agent-id'));
        document.getElementById('copy-agent-secret').addEventListener('click', async () => copyCredentialsField('credentials-agent-secret'));
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
                    const nextName = window.prompt('Enter new node name:', node ? node.display_name : '');
                    if (!nextName) return;
                    try {
                        await fetchJson(`/api/nodes/${encodeURIComponent(nodeId)}`, {
                            method: 'PATCH',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ display_name: nextName.trim() }),
                        });
                        setStatus('nodes-status', 'Node renamed.');
                        await loadNodes();
                    } catch (error) {
                        setStatus('nodes-status', error.message, true);
                    }
                }
                if (action === 'disable-agent' || action === 'enable-agent') {
                    try {
                        await fetchJson(`/api/agents/${encodeURIComponent(agentId)}/${action === 'disable-agent' ? 'disable' : 'enable'}`, { method: 'POST' });
                        setStatus('nodes-status', `Agent ${action === 'disable-agent' ? 'disabled' : 'enabled'}.`);
                        await loadAgents();
                        await loadNodes();
                    } catch (error) {
                        setStatus('nodes-status', error.message, true);
                    }
                }
                if (action === 'rotate-agent-secret') {
                    try {
                        const data = await fetchJson(`/api/agents/${encodeURIComponent(agentId)}/rotate-secret`, { method: 'POST' });
                        setStatus('nodes-status', 'Secret rotated. Save new secret now.');
                        showCredentialsModal({
                            title: `Rotated secret for ${data.agent_id}`,
                            agentId: data.agent_id,
                            secret: data.secret,
                        });
                        await loadAgents();
                        await loadNodes();
                    } catch (error) {
                        setStatus('nodes-status', error.message, true);
                    }
                }
                if (action === 'delete') {
                    if (!window.confirm('Delete node with all related data?')) return;
                    try {
                        await fetchJson(`/api/nodes/${encodeURIComponent(nodeId)}`, { method: 'DELETE' });
                        setStatus('nodes-status', 'Node deleted.');
                        await refreshAll();
                    } catch (error) {
                        setStatus('nodes-status', error.message, true);
                    }
                }
                return;
            }

            const triggerActionButton = event.target.closest('[data-trigger-action]');
            if (triggerActionButton) {
                closeAllMenus();
                const action = triggerActionButton.dataset.triggerAction;
                const triggerId = triggerActionButton.dataset.triggerId;
                if (action === 'edit') {
                    const nextName = window.prompt('Trigger name:', triggerActionButton.dataset.triggerName || '');
                    if (!nextName) return;
                    const thresholdRaw = window.prompt('Threshold (0-100):', triggerActionButton.dataset.triggerThreshold || '');
                    if (!thresholdRaw) return;
                    const threshold = Number(thresholdRaw);
                    if (!Number.isFinite(threshold) || threshold < 0 || threshold > 100) {
                        setStatus('triggers-status', 'Threshold must be between 0 and 100.', true);
                        return;
                    }
                    try {
                        await fetchJson(`/api/triggers/${encodeURIComponent(triggerId)}`, {
                            method: 'PATCH',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ name: nextName.trim(), threshold }),
                        });
                        setStatus('triggers-status', 'Trigger updated.');
                        await loadTriggers();
                        await loadProblems();
                    } catch (error) {
                        setStatus('triggers-status', error.message, true);
                    }
                }
                if (action === 'delete') {
                    if (!window.confirm('Delete this trigger?')) return;
                    try {
                        await fetchJson(`/api/triggers/${encodeURIComponent(triggerId)}`, { method: 'DELETE' });
                        setStatus('triggers-status', 'Trigger deleted.');
                        await loadTriggers();
                        await loadProblems();
                    } catch (error) {
                        setStatus('triggers-status', error.message, true);
                    }
                }
                return;
            }

            if (!event.target.closest('.menu-popover')) {
                closeAllMenus();
            }
        });

        async function refreshAll() {
            await loadNodes();
            await loadAgents();
            await loadLatestMetrics();
            await loadGraph();
            await loadTriggers();
            await loadProblems();
            await loadLogs();
            await loadKnowledgeBase();
        }

        renderTabs();
        refreshAll();
        setInterval(refreshAll, 5000);
    </script>
</body>
</html>
    """
