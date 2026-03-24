from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from typing import Deque

from fastapi import FastAPI, HTTPException, Query

from app.api.users import router as users_router
from app.db.base import Base
from app.db.session import SessionLocal, engine
import app.models.metric  # noqa: F401
import app.models.node  # noqa: F401
import app.models.user  # noqa: F401
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field
from sqlalchemy import func

from app.models.metric import Metric
from app.models.node import Node

RETENTION_PERIOD = timedelta(hours=1)
RECENT_POINTS_LIMIT = 10


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


app = FastAPI(title="Monitoring KB MVP")
app.include_router(users_router)


def init_db() -> None:
    # For production use Alembic migrations instead of create_all.
    Base.metadata.create_all(bind=engine)


@app.on_event("startup")
def on_startup() -> None:
    init_db()


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
def list_nodes() -> dict[str, list[dict[str, str | int]]]:
    with SessionLocal() as db:
        nodes = db.query(Node).order_by(func.lower(Node.display_name)).all()
        items = [
            {
                "node_id": node.node_id,
                "display_name": node.display_name,
                "os_name": node.os_name,
                "cpu_cores": node.cpu_cores,
                "ram_total_mb": node.ram_total_mb,
                "ip_address": node.ip_address,
                "last_seen": node.last_seen.isoformat(),
            }
            for node in nodes
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
            color-scheme: dark;
            --bg: #020617;
            --panel: #0f172a;
            --panel-alt: #111827;
            --border: #334155;
            --text: #e2e8f0;
            --muted: #94a3b8;
            --accent: #38bdf8;
            --accent-soft: rgba(56, 189, 248, 0.12);
            --danger: #fb7185;
        }
        * { box-sizing: border-box; }
        body {
            margin: 0;
            font-family: Arial, sans-serif;
            background: linear-gradient(180deg, #020617 0%, #0f172a 100%);
            color: var(--text);
        }
        .layout {
            display: flex;
            min-height: 100vh;
        }
        .sidebar {
            width: 260px;
            background: rgba(15, 23, 42, 0.98);
            border-right: 1px solid var(--border);
            padding: 1.25rem 1rem;
            transition: width 0.25s ease, padding 0.25s ease;
            overflow: hidden;
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
        .toggle-btn, .nav-btn, button, select, input {
            border-radius: 0.75rem;
            border: 1px solid var(--border);
            background: #0b1120;
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
            padding: 0.85rem 1rem;
            text-align: left;
            transition: background 0.2s ease, border-color 0.2s ease;
        }
        .nav-btn.active {
            background: var(--accent-soft);
            border-color: var(--accent);
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
            background: rgba(15, 23, 42, 0.85);
            border: 1px solid var(--border);
            border-radius: 1.25rem;
            padding: 1.5rem;
            box-shadow: 0 20px 45px rgba(2, 6, 23, 0.35);
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
            align-items: center;
            margin-bottom: 1rem;
        }
        select, input {
            min-height: 42px;
            padding: 0.65rem 0.8rem;
        }
        button {
            min-height: 42px;
            padding: 0.65rem 1rem;
            background: var(--accent-soft);
            border-color: var(--accent);
        }
        button.secondary {
            background: transparent;
            border-color: var(--border);
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 1rem;
            background: rgba(2, 6, 23, 0.35);
            border-radius: 1rem;
            overflow: hidden;
        }
        th, td {
            padding: 0.85rem;
            border-bottom: 1px solid var(--border);
            text-align: left;
            vertical-align: top;
        }
        th {
            background: rgba(30, 41, 59, 0.8);
        }
        tr:last-child td { border-bottom: none; }
        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 1rem;
            margin-bottom: 1rem;
        }
        .stat {
            background: rgba(2, 6, 23, 0.35);
            border: 1px solid var(--border);
            border-radius: 1rem;
            padding: 1rem;
        }
        .stat-label { color: var(--muted); font-size: 0.9rem; }
        .stat-value { font-size: 1.5rem; font-weight: bold; margin-top: 0.35rem; }
        .rename-form {
            display: flex;
            gap: 0.5rem;
            flex-wrap: wrap;
            margin-top: 0.5rem;
        }
        .empty, .status {
            color: var(--muted);
            padding: 1rem 0;
        }
        .error { color: var(--danger); }
        [hidden] { display: none !important; }
        @media (max-width: 900px) {
            .content { padding: 1rem; }
            .sidebar { position: sticky; top: 0; height: 100vh; }
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
                <button class="nav-btn active" data-tab="latest" type="button"><span>📈</span><span class="nav-label">Latest data</span></button>
                <button class="nav-btn" data-tab="nodes" type="button"><span>🖥️</span><span class="nav-label">Nodes</span></button>
                <button class="nav-btn" data-tab="graphs" type="button"><span>📊</span><span class="nav-label">Graphs</span></button>
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
                <div id="nodes-status" class="status"></div>
                <table>
                    <thead>
                        <tr>
                            <th>Name</th>
                            <th>Node ID</th>
                            <th>OS</th>
                            <th>CPU cores</th>
                            <th>RAM</th>
                            <th>IP</th>
                            <th>Last seen (UTC)</th>
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
                <svg id="graph-canvas" viewBox="0 0 800 320" width="100%" height="320" role="img" aria-label="Metric graph">
                    <rect x="0" y="0" width="800" height="320" fill="rgba(2, 6, 23, 0.35)" stroke="#334155"></rect>
                    <line x1="50" y1="270" x2="760" y2="270" stroke="#334155" />
                    <line x1="50" y1="30" x2="50" y2="270" stroke="#334155" />
                    <polyline id="graph-line" fill="none" stroke="#38bdf8" stroke-width="3" points=""></polyline>
                    <text id="graph-title" x="50" y="20" fill="#94a3b8">No data</text>
                </svg>
            </section>
        </main>
    </div>

    <script>
        const state = {
            nodes: [],
            latestSelectedNodeId: '',
            graphSelectedNodeId: '',
            nodeNameDrafts: {},
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
            select.innerHTML = '';
            graphSelect.innerHTML = '';
            if (!state.nodes.length) {
                const option = document.createElement('option');
                option.textContent = 'No nodes yet';
                option.value = '';
                select.appendChild(option);
                graphSelect.appendChild(option.cloneNode(true));
                select.disabled = true;
                graphSelect.disabled = true;
                return;
            }

            select.disabled = false;
            graphSelect.disabled = false;
            if (!state.latestSelectedNodeId || !state.nodes.some((node) => node.node_id === state.latestSelectedNodeId)) {
                state.latestSelectedNodeId = state.nodes[0].node_id;
            }
            if (!state.graphSelectedNodeId || !state.nodes.some((node) => node.node_id === state.graphSelectedNodeId)) {
                state.graphSelectedNodeId = state.latestSelectedNodeId;
            }

            for (const node of state.nodes) {
                const option = document.createElement('option');
                option.value = node.node_id;
                option.textContent = `${node.display_name} (${node.node_id})`;
                select.appendChild(option);
                graphSelect.appendChild(option.cloneNode(true));
            }
            select.value = state.latestSelectedNodeId;
            graphSelect.value = state.graphSelectedNodeId;
        }

        function renderGraph(items, metricName) {
            const line = document.getElementById('graph-line');
            const title = document.getElementById('graph-title');
            if (!items.length) {
                line.setAttribute('points', '');
                title.textContent = 'No data for selected interval';
                return;
            }

            const width = 710;
            const height = 240;
            const minX = 50;
            const minY = 30;
            const values = items.map((item) => item.value);
            const maxValue = Math.max(...values, 100);
            const points = items.map((item, index) => {
                const x = minX + (items.length === 1 ? 0 : (index / (items.length - 1)) * width);
                const y = minY + height - (item.value / maxValue) * height;
                return `${x.toFixed(2)},${y.toFixed(2)}`;
            });
            line.setAttribute('points', points.join(' '));
            const latestValue = items[items.length - 1].value.toFixed(2);
            title.textContent = `${metricName === 'cpu_percent' ? 'CPU' : 'RAM'} trend, latest: ${latestValue}%`;
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
                    <td>${item.display_name || item.node_id}</td>
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
                body.innerHTML = '<tr><td colspan="7" class="empty">No nodes have sent data yet.</td></tr>';
                return;
            }

            for (const node of state.nodes) {
                const inputValue = Object.prototype.hasOwnProperty.call(state.nodeNameDrafts, node.node_id)
                    ? state.nodeNameDrafts[node.node_id]
                    : node.display_name;
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td>
                        <strong>${node.display_name}</strong>
                        <form class="rename-form" data-node-id="${node.node_id}">
                            <input name="display_name" value="${inputValue}" aria-label="Display name for ${node.node_id}" />
                            <button type="submit">Save</button>
                        </form>
                    </td>
                    <td>${node.node_id}</td>
                    <td>${node.os_name}</td>
                    <td>${node.cpu_cores}</td>
                    <td>${formatRamMb(node.ram_total_mb)}</td>
                    <td>${node.ip_address}</td>
                    <td>${formatUtc(node.last_seen)}</td>
                `;
                body.appendChild(row);
            }

            body.querySelectorAll('.rename-form').forEach((form) => {
                const input = form.querySelector('input[name="display_name"]');
                input.addEventListener('input', () => {
                    const nodeId = form.dataset.nodeId;
                    state.nodeNameDrafts[nodeId] = input.value;
                });
                form.addEventListener('submit', async (event) => {
                    event.preventDefault();
                    const nodeId = form.dataset.nodeId;
                    const formData = new FormData(form);
                    const displayName = String(formData.get('display_name') || '').trim();
                    if (!displayName) {
                        setStatus('nodes-status', 'Display name cannot be empty.', true);
                        return;
                    }
                    try {
                        await fetchJson(`/api/nodes/${encodeURIComponent(nodeId)}`, {
                            method: 'PATCH',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ display_name: displayName }),
                        });
                        delete state.nodeNameDrafts[nodeId];
                        setStatus('nodes-status', `Saved new name for ${nodeId}.`);
                        await loadNodes();
                        await loadLatestMetrics();
                    } catch (error) {
                        setStatus('nodes-status', error.message, true);
                    }
                });
            });
        }

        function setStatus(id, message, isError = false) {
            const element = document.getElementById(id);
            element.textContent = message;
            element.classList.toggle('error', isError);
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
                renderGraph([], metricName);
                setStatus('graph-status', 'Waiting for nodes to send data.');
                return;
            }
            try {
                const data = await fetchJson(
                    `/api/metrics/history?node_id=${encodeURIComponent(nodeId)}&metric_name=${encodeURIComponent(metricName)}&interval_minutes=${encodeURIComponent(interval)}`
                );
                renderGraph(data.items, metricName);
                setStatus('graph-status', data.items.length ? '' : 'No recent points for selected options.');
            } catch (error) {
                renderGraph([], metricName);
                setStatus('graph-status', error.message, true);
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
            document.getElementById('graph-node-select').value = state.graphSelectedNodeId;
            await loadLatestMetrics();
            await loadGraph();
        });

        document.getElementById('refresh-latest').addEventListener('click', loadLatestMetrics);
        document.getElementById('refresh-graph').addEventListener('click', loadGraph);
        document.getElementById('graph-node-select').addEventListener('change', async (event) => {
            state.graphSelectedNodeId = event.target.value;
            await loadGraph();
        });
        document.getElementById('graph-metric-select').addEventListener('change', loadGraph);
        document.getElementById('graph-interval-select').addEventListener('change', loadGraph);

        async function refreshAll() {
            await loadNodes();
            await loadLatestMetrics();
            await loadGraph();
        }

        renderTabs();
        refreshAll();
        setInterval(refreshAll, 5000);
    </script>
</body>
</html>
    """
