from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from typing import Deque

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

RETENTION_PERIOD = timedelta(hours=1)
RECENT_POINTS_LIMIT = 10


@dataclass
class MetricPoint:
    node_id: str
    cpu_percent: float
    ram_percent: float
    timestamp: datetime


class MetricIn(BaseModel):
    node_id: str = Field(..., min_length=1, max_length=100)
    cpu_percent: float = Field(..., ge=0, le=100)
    ram_percent: float = Field(..., ge=0, le=100)
    timestamp: datetime | None = None


app = FastAPI(title="Monitoring KB MVP")
_storage: dict[str, Deque[MetricPoint]] = defaultdict(deque)



def _utcnow() -> datetime:
    return datetime.now(timezone.utc)



def _prune(points: Deque[MetricPoint], now: datetime) -> None:
    cutoff = now - RETENTION_PERIOD
    while points and points[0].timestamp < cutoff:
        points.popleft()


@app.post("/api/metrics")
def ingest_metric(metric: MetricIn) -> dict[str, str]:
    timestamp = metric.timestamp or _utcnow()
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)

    point = MetricPoint(
        node_id=metric.node_id,
        cpu_percent=metric.cpu_percent,
        ram_percent=metric.ram_percent,
        timestamp=timestamp.astimezone(timezone.utc),
    )
    points = _storage[metric.node_id]
    points.append(point)
    _prune(points, _utcnow())
    return {"status": "ok"}


@app.get("/api/metrics")
def list_metrics(node_id: str | None = None) -> dict[str, list[dict]]:
    now = _utcnow()
    if node_id:
        points = _storage.get(node_id)
        if points is None:
            raise HTTPException(status_code=404, detail="Node not found")
        _prune(points, now)
        return {"items": [asdict(point) for point in list(points)[-RECENT_POINTS_LIMIT:]]}

    items: list[dict] = []
    for points in _storage.values():
        _prune(points, now)
        items.extend(asdict(point) for point in list(points)[-RECENT_POINTS_LIMIT:])
    items.sort(key=lambda item: item["timestamp"])
    return {"items": items[-RECENT_POINTS_LIMIT:]}


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
        body { font-family: Arial, sans-serif; margin: 2rem; background: #0f172a; color: #e2e8f0; }
        h1 { margin-bottom: 0.5rem; }
        table { width: 100%; border-collapse: collapse; margin-top: 1rem; background: #111827; }
        th, td { padding: 0.75rem; border-bottom: 1px solid #334155; text-align: left; }
        th { background: #1e293b; }
        .meta { color: #94a3b8; margin-bottom: 1rem; }
    </style>
</head>
<body>
    <h1>Monitoring Dashboard</h1>
    <div class="meta">Shows the latest 10 CPU/RAM samples stored in memory for up to 1 hour.</div>
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

    <script>
        async function loadMetrics() {
            const response = await fetch('/api/metrics');
            const data = await response.json();
            const body = document.getElementById('metrics-body');
            body.innerHTML = '';

            for (const item of data.items.slice().reverse()) {
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td>${new Date(item.timestamp).toLocaleString('en-GB', { timeZone: 'UTC' })}</td>
                    <td>${item.node_id}</td>
                    <td>${item.cpu_percent.toFixed(2)}</td>
                    <td>${item.ram_percent.toFixed(2)}</td>
                `;
                body.appendChild(row);
            }
        }

        loadMetrics();
        setInterval(loadMetrics, 5000);
    </script>
</body>
</html>
    """
