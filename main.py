from __future__ import annotations

import os
import sqlite3
from contextlib import asynccontextmanager
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

RETENTION_PERIOD = timedelta(hours=1)
RECENT_POINTS_LIMIT = 10
DB_PATH = Path(os.getenv("MONITORING_DB_PATH", "monitoring.db"))


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


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    yield


app = FastAPI(title="Monitoring KB MVP", lifespan=lifespan)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _normalize_timestamp(timestamp: datetime | None) -> datetime:
    value = timestamp or _utcnow()
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def init_db() -> None:
    with _connect() as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS nodes (
                node_id TEXT PRIMARY KEY,
                display_name TEXT NOT NULL,
                os_name TEXT NOT NULL,
                cpu_cores INTEGER NOT NULL,
                ram_total_mb INTEGER NOT NULL,
                ip_address TEXT NOT NULL,
                last_seen TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                node_id TEXT NOT NULL,
                cpu_percent REAL NOT NULL,
                ram_percent REAL NOT NULL,
                timestamp TEXT NOT NULL,
                FOREIGN KEY (node_id) REFERENCES nodes (node_id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_metrics_node_timestamp
                ON metrics (node_id, timestamp DESC);
            CREATE INDEX IF NOT EXISTS idx_metrics_timestamp
                ON metrics (timestamp DESC);
            """
        )


def reset_db() -> None:
    with _connect() as connection:
        connection.execute("DELETE FROM metrics")
        connection.execute("DELETE FROM nodes")


def _prune_expired(connection: sqlite3.Connection, now: datetime) -> None:
    cutoff = (now - RETENTION_PERIOD).isoformat()
    connection.execute("DELETE FROM metrics WHERE timestamp < ?", (cutoff,))


def _serialize_metric(row: sqlite3.Row) -> dict[str, str | float]:
    point = MetricPoint(
        node_id=row["node_id"],
        cpu_percent=row["cpu_percent"],
        ram_percent=row["ram_percent"],
        timestamp=datetime.fromisoformat(row["timestamp"]),
    )
    item = asdict(point)
    item["timestamp"] = point.timestamp.isoformat()
    item["display_name"] = row["display_name"]
    return item


def _serialize_node(row: sqlite3.Row) -> dict[str, str | int]:
    node = NodeInfo(
        node_id=row["node_id"],
        display_name=row["display_name"],
        os_name=row["os_name"],
        cpu_cores=row["cpu_cores"],
        ram_total_mb=row["ram_total_mb"],
        ip_address=row["ip_address"],
        last_seen=datetime.fromisoformat(row["last_seen"]),
    )
    item = asdict(node)
    item["last_seen"] = node.last_seen.isoformat()
    return item


@app.post("/api/metrics")
def ingest_metric(metric: MetricIn) -> dict[str, str]:
    timestamp = _normalize_timestamp(metric.timestamp)
    with _connect() as connection:
        _prune_expired(connection, _utcnow())
        current_name = connection.execute(
            "SELECT display_name FROM nodes WHERE node_id = ?",
            (metric.node_id,),
        ).fetchone()
        display_name = current_name["display_name"] if current_name else metric.node_id
        connection.execute(
            """
            INSERT INTO nodes (node_id, display_name, os_name, cpu_cores, ram_total_mb, ip_address, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(node_id) DO UPDATE SET
                display_name = excluded.display_name,
                os_name = excluded.os_name,
                cpu_cores = excluded.cpu_cores,
                ram_total_mb = excluded.ram_total_mb,
                ip_address = excluded.ip_address,
                last_seen = excluded.last_seen
            """,
            (
                metric.node_id,
                display_name,
                metric.os_name,
                metric.cpu_cores,
                metric.ram_total_mb,
                metric.ip_address,
                timestamp.isoformat(),
            ),
        )
        connection.execute(
            "INSERT INTO metrics (node_id, cpu_percent, ram_percent, timestamp) VALUES (?, ?, ?, ?)",
            (metric.node_id, metric.cpu_percent, metric.ram_percent, timestamp.isoformat()),
        )
    return {"status": "ok"}


@app.get("/api/metrics")
def list_metrics(node_id: str | None = None) -> dict[str, list[dict[str, str | float]]]:
    now = _utcnow()
    with _connect() as connection:
        _prune_expired(connection, now)
        if node_id:
            node = connection.execute("SELECT 1 FROM nodes WHERE node_id = ?", (node_id,)).fetchone()
            if node is None:
                raise HTTPException(status_code=404, detail="Node not found")
            rows = connection.execute(
                """
                SELECT metrics.node_id, metrics.cpu_percent, metrics.ram_percent, metrics.timestamp, nodes.display_name
                FROM metrics
                JOIN nodes ON nodes.node_id = metrics.node_id
                WHERE metrics.node_id = ?
                ORDER BY metrics.timestamp DESC
                LIMIT ?
                """,
                (node_id, RECENT_POINTS_LIMIT),
            ).fetchall()
            return {"items": [_serialize_metric(row) for row in reversed(rows)]}

        rows = connection.execute(
            """
            SELECT node_id, cpu_percent, ram_percent, timestamp, display_name
            FROM (
                SELECT metrics.node_id, metrics.cpu_percent, metrics.ram_percent, metrics.timestamp, nodes.display_name
                FROM metrics
                JOIN nodes ON nodes.node_id = metrics.node_id
                ORDER BY metrics.timestamp DESC
                LIMIT ?
            ) recent
            ORDER BY timestamp ASC
            """,
            (RECENT_POINTS_LIMIT,),
        ).fetchall()
        return {"items": [_serialize_metric(row) for row in rows]}


@app.get("/api/nodes")
def list_nodes() -> dict[str, list[dict[str, str | int]]]:
    with _connect() as connection:
        rows = connection.execute(
            "SELECT node_id, display_name, os_name, cpu_cores, ram_total_mb, ip_address, last_seen FROM nodes ORDER BY lower(display_name)"
        ).fetchall()
    return {"items": [_serialize_node(row) for row in rows]}


@app.patch("/api/nodes/{node_id}")
def rename_node(node_id: str, payload: NodeRenameIn) -> dict[str, str | int]:
    with _connect() as connection:
        cursor = connection.execute(
            "UPDATE nodes SET display_name = ? WHERE node_id = ?",
            (payload.display_name, node_id),
        )
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Node not found")
        row = connection.execute(
            "SELECT node_id, display_name, os_name, cpu_cores, ram_total_mb, ip_address, last_seen FROM nodes WHERE node_id = ?",
            (node_id,),
        ).fetchone()
    return _serialize_node(row)


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
        </main>
    </div>

    <script>
        const state = {
            nodes: [],
            selectedNodeId: '',
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
            select.innerHTML = '';
            if (!state.nodes.length) {
                const option = document.createElement('option');
                option.textContent = 'No nodes yet';
                option.value = '';
                select.appendChild(option);
                select.disabled = true;
                return;
            }

            select.disabled = false;
            if (!state.selectedNodeId || !state.nodes.some((node) => node.node_id === state.selectedNodeId)) {
                state.selectedNodeId = state.nodes[0].node_id;
            }

            for (const node of state.nodes) {
                const option = document.createElement('option');
                option.value = node.node_id;
                option.textContent = `${node.display_name} (${node.node_id})`;
                option.selected = node.node_id === state.selectedNodeId;
                select.appendChild(option);
            }
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
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td>
                        <strong>${node.display_name}</strong>
                        <form class="rename-form" data-node-id="${node.node_id}">
                            <input name="display_name" value="${node.display_name}" aria-label="Display name for ${node.node_id}" />
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
            const node = state.nodes.find((item) => item.node_id === state.selectedNodeId);
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
            state.selectedNodeId = event.target.value;
            await loadLatestMetrics();
        });

        document.getElementById('refresh-latest').addEventListener('click', loadLatestMetrics);

        async function refreshAll() {
            await loadNodes();
            await loadLatestMetrics();
        }

        renderTabs();
        refreshAll();
        setInterval(refreshAll, 5000);
    </script>
</body>
</html>
    """
