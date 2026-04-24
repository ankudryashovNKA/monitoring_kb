from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
import json
import math
import re
from typing import Any

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.models.agent import Agent
from app.models.agent_command import AgentCommand
from app.models.agent_script import AgentScript
from app.models.filesystem_sample import FilesystemSample
from app.models.log_entry import LogEntry
from app.models.metric import Metric
from app.models.node import Node
from app.models.process_sample import ProcessSample
from app.models.trigger import Trigger


UUID_RE = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b", re.I)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
PID_RE = re.compile(r"\b(?:pid|tid|process)\s*[=:]?\s*\d+\b", re.I)
NUM_RE = re.compile(r"\b\d+\b")


METRIC_FIELDS = [
    "cpu_percent", "ram_percent", "swap_percent", "uptime_seconds", "disk_read_time_ms", "disk_write_time_ms", "net_recv_kbps",
    "net_sent_kbps", "process_count", "zombie_processes", "load1", "load5", "load15", "cpu_iowait_percent", "cpu_steal_percent",
    "ram_used_mb", "ram_available_mb", "swap_used_mb", "swap_free_mb", "disk_read_kbps", "disk_write_kbps", "disk_read_iops",
    "disk_write_iops", "net_packets_recv_per_sec", "net_packets_sent_per_sec", "net_errors_in_per_sec", "net_errors_out_per_sec",
    "net_drops_in_per_sec", "net_drops_out_per_sec", "tcp_established", "tcp_listen",
]


def _iso(dt: datetime | None) -> str | None:
    value = _as_utc(dt)
    return value.isoformat() if value else None


def _as_utc(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _p95(values: list[float]) -> float:
    if not values:
        return 0.0
    sorted_values = sorted(values)
    index = max(0, math.ceil(0.95 * len(sorted_values)) - 1)
    return float(sorted_values[index])


def _trend(first: float, last: float, span: float) -> str:
    if span <= 0:
        return "unknown"
    delta = last - first
    epsilon = max(0.5, abs(first) * 0.05)
    if abs(delta) <= epsilon:
        return "flat"
    return "rising" if delta > 0 else "falling"


def get_metric_window_stats(points: list[Metric], metric_names: list[str]) -> dict[str, dict[str, float | int | str | None]]:
    stats: dict[str, dict[str, float | int | str | None]] = {}
    if not points:
        return stats
    first_ts = points[0].timestamp
    last_ts = points[-1].timestamp
    span_min = max(1e-6, (last_ts - first_ts).total_seconds() / 60.0)
    for name in metric_names:
        vals = [float(value) for p in points if (value := getattr(p, name, None)) is not None]
        if len(vals) < 2:
            stats[name] = {"count": len(vals), "avg": None, "min": None, "max": None, "p95": None, "first": None, "last": None,
                           "delta_abs": None, "delta_pct": None, "slope_per_min": None, "trend": "unknown"}
            continue
        first, last = vals[0], vals[-1]
        delta = last - first
        stats[name] = {
            "count": len(vals),
            "avg": round(sum(vals) / len(vals), 4),
            "min": round(min(vals), 4),
            "max": round(max(vals), 4),
            "p95": round(_p95(vals), 4),
            "first": round(first, 4),
            "last": round(last, 4),
            "delta_abs": round(delta, 4),
            "delta_pct": round((delta / first * 100.0), 4) if abs(first) > 1e-9 else None,
            "slope_per_min": round(delta / span_min, 4),
            "trend": _trend(first, last, span_min),
        }
    return stats


def _normalize_log_message(message: str) -> str:
    text = (message or "").strip().lower()
    text = UUID_RE.sub("<uuid>", text)
    text = IP_RE.sub("<ip>", text)
    text = PID_RE.sub("<pid>", text)
    text = NUM_RE.sub("<num>", text)
    text = re.sub(r"\s+", " ", text)
    return text[:300]


def group_log_signatures(logs: list[LogEntry], max_signatures: int = 10, max_examples: int = 3) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str], dict[str, Any]] = {}
    for row in logs:
        signature = _normalize_log_message(row.message)
        key = (signature, row.severity)
        entry = grouped.setdefault(key, {
            "signature": signature,
            "severity": row.severity,
            "count": 0,
            "first_seen": row.captured_at,
            "last_seen": row.captured_at,
            "examples": [],
        })
        entry["count"] += 1
        entry["first_seen"] = min(entry["first_seen"], row.captured_at)
        entry["last_seen"] = max(entry["last_seen"], row.captured_at)
        if len(entry["examples"]) < max_examples:
            entry["examples"].append((row.message or "")[:300])
    items = sorted(grouped.values(), key=lambda item: (item["count"], item["last_seen"]), reverse=True)[:max_signatures]
    for item in items:
        item["first_seen"] = _iso(item["first_seen"])
        item["last_seen"] = _iso(item["last_seen"])
    return items


def build_deterministic_observations(context: dict[str, Any]) -> list[dict[str, str]]:
    obs: list[dict[str, str]] = []
    node = context.get("node", {})
    latest = context.get("metrics", {}).get("latest", {})
    if (age := node.get("last_seen_age_seconds")) and age > 180:
        obs.append({"severity": "warning", "category": "agent", "evidence": f"Agent stale: {age}s", "context_path": "node.last_seen_age_seconds", "recommendation_hint": "Проверьте доступность агента и сети"})
    if (cpu := latest.get("cpu_percent")) is not None and cpu > 90:
        obs.append({"severity": "critical", "category": "cpu", "evidence": f"CPU {cpu}%", "context_path": "metrics.latest.cpu_percent", "recommendation_hint": "Проверьте top CPU процессы"})
    if (ram := latest.get("ram_percent")) is not None and ram > 90:
        obs.append({"severity": "critical", "category": "memory", "evidence": f"RAM {ram}%", "context_path": "metrics.latest.ram_percent", "recommendation_hint": "Проверьте RAM offenders и OOM"})
    if (z := latest.get("zombie_processes")) and z > 0:
        obs.append({"severity": "warning", "category": "agent", "evidence": f"Zombie processes: {z}", "context_path": "metrics.latest.zombie_processes", "recommendation_hint": "Проверьте parent-процессы"})
    for fs in context.get("filesystems", {}).get("latest", []):
        if (fs.get("percent") or 0) >= 90 or (fs.get("free_gb") or 9999) <= 2 or (fs.get("inodes_percent") or 0) >= 90:
            obs.append({"severity": "critical", "category": "filesystem", "evidence": f"{fs.get('mountpoint')} usage={fs.get('percent')} free={fs.get('free_gb')}GB inodes={fs.get('inodes_percent')}", "context_path": "filesystems.latest", "recommendation_hint": "Освободите место/иноды"})
    tops = context.get("logs", {}).get("top_signatures", [])
    if tops and (tops[0].get("severity") in {"ERROR", "CRITICAL", "ALERT", "EMERGENCY"}):
        obs.append({"severity": "warning", "category": "logs", "evidence": f"Repeated logs: {tops[0].get('signature')} x{tops[0].get('count')}", "context_path": "logs.top_signatures", "recommendation_hint": "Сопоставьте время с метриками и remediation"})
    return obs


def build_node_analysis_context(
    db: Session,
    node_id: str,
    window_minutes: int = 60,
    now: datetime | None = None,
    max_recent_points: int = 15,
    max_log_signatures: int = 10,
    max_log_examples_per_signature: int = 3,
) -> dict[str, Any]:
    now = _as_utc(now) or datetime.now(timezone.utc)
    w60 = now - timedelta(minutes=window_minutes)
    w10 = now - timedelta(minutes=min(10, window_minutes))

    node = db.query(Node).filter(Node.display_name == node_id).first()
    if node is None:
        raise ValueError("Node not found")
    agent = db.query(Agent).filter(Agent.agent_id == node.agent_id).first() if node.agent_id else None

    metrics_60 = db.query(Metric).filter(Metric.node_id == node_id, Metric.timestamp >= w60).order_by(Metric.timestamp.asc()).all()
    metrics_10 = [m for m in metrics_60 if (_as_utc(m.timestamp) or m.timestamp) >= w10]
    logs_60 = db.query(LogEntry).filter(LogEntry.node_id == node_id, LogEntry.captured_at >= w60).order_by(LogEntry.captured_at.desc()).all()
    fs_60 = db.query(FilesystemSample).filter(FilesystemSample.node_id == node_id, FilesystemSample.timestamp >= w60).order_by(FilesystemSample.timestamp.desc()).all()
    proc_60 = db.query(ProcessSample).filter(ProcessSample.node_id == node_id, ProcessSample.timestamp >= w60).order_by(ProcessSample.timestamp.desc()).all()
    triggers = db.query(Trigger).filter(Trigger.node_id == node_id).all()
    cmds = db.query(AgentCommand).filter(AgentCommand.node_id == node_id).order_by(AgentCommand.created_at.desc()).limit(20).all()
    scripts = db.query(AgentScript).filter(AgentScript.node_id == node_id).all()

    latest_metric = metrics_60[-1] if metrics_60 else db.query(Metric).filter(Metric.node_id == node_id).order_by(Metric.timestamp.desc()).first()
    latest_fs: dict[str, FilesystemSample] = {}
    for fs in fs_60:
        latest_fs.setdefault(fs.mountpoint, fs)

    latest_cpu = [p for p in proc_60 if p.kind == "cpu"][:10]
    latest_ram = [p for p in proc_60 if p.kind == "ram"][:10]
    offenders = Counter((p.name, p.kind) for p in proc_60)

    recent_points = [{"timestamp": _iso(p.timestamp), **{name: getattr(p, name) for name in METRIC_FIELDS if hasattr(p, name)}} for p in metrics_60[-max_recent_points:]]

    fs_windows: dict[str, Any] = {}
    by_mount: dict[str, list[FilesystemSample]] = defaultdict(list)
    for fs in sorted(fs_60, key=lambda i: _as_utc(i.timestamp) or i.timestamp):
        by_mount[fs.mountpoint].append(fs)
    for mnt, items in by_mount.items():
        percent_vals = [float(i.percent) for i in items]
        free_vals = [float(i.free_gb) for i in items]
        growth = None
        if len(items) > 1:
            hours = max(1e-6, ((_as_utc(items[-1].timestamp) or items[-1].timestamp) - (_as_utc(items[0].timestamp) or items[0].timestamp)).total_seconds() / 3600.0)
            growth = round((items[-1].used_gb - items[0].used_gb) / hours, 4)
        fs_windows[mnt] = {
            "percent": {"count": len(percent_vals), "avg": round(sum(percent_vals)/len(percent_vals),4), "min": min(percent_vals), "max": max(percent_vals), "p95": _p95(percent_vals)} if percent_vals else {},
            "free_gb": {"count": len(free_vals), "avg": round(sum(free_vals)/len(free_vals),4), "min": min(free_vals), "max": max(free_vals), "p95": _p95(free_vals)} if free_vals else {},
            "used_gb_growth_per_hour": growth,
        }

    os_hint = (node.os_name or "").lower()
    preferred_os_families: set[str] = {"any"}
    if "linux" in os_hint:
        preferred_os_families.update({"linux", "any"})
    elif "windows" in os_hint:
        preferred_os_families.update({"windows", "any"})
    else:
        preferred_os_families.update({"linux", "windows"})

    available_scripts: list[dict[str, Any]] = []
    for script in scripts:
        if not script.enabled or script.manifest_error:
            continue
        script_os = (script.os_family or "any").lower()
        if script_os not in preferred_os_families:
            continue
        try:
            tags = json.loads(script.tags_json or "[]")
        except Exception:
            tags = []
        try:
            args_schema = json.loads(script.args_schema_json or "{}")
        except Exception:
            args_schema = {}
        available_scripts.append(
            {
                "script_id": script.script_id,
                "title": script.title,
                "description": script.description,
                "os_family": script.os_family,
                "tags": tags if isinstance(tags, list) else [],
                "risk_level": script.risk_level,
                "requires_confirmation": bool(script.requires_confirmation),
                "dry_run_supported": bool(script.dry_run_supported),
                "args_schema": args_schema if isinstance(args_schema, dict) else {},
                "content_hash": script.content_hash,
                "updated_at": _iso(script.updated_at),
                "manifest_error": script.manifest_error,
            }
        )

    counts_10 = Counter([row.severity for row in logs_60 if row.captured_at >= w10])
    counts_60 = Counter([row.severity for row in logs_60])
    context: dict[str, Any] = {
        "schema_version": "llm_node_context.v2",
        "generated_at": _iso(now),
        "window_minutes": window_minutes,
        "node": {
            "node_id": node.display_name,
            "os_name": node.os_name,
            "ip_address": node.ip_address,
            "agent_id": node.agent_id,
            "agent_enabled": bool(agent.enabled) if agent else False,
            "last_seen": _iso(node.last_seen),
            "last_seen_age_seconds": int((now - (_as_utc(node.last_seen) or now)).total_seconds()) if node.last_seen else None,
        },
        "data_quality": {
            "metric_samples_10m": len(metrics_10),
            "metric_samples_60m": len(metrics_60),
            "filesystem_samples_60m": len(fs_60),
            "process_samples_60m": len(proc_60),
            "log_entries_60m": len(logs_60),
            "missing": [],
            "warnings": [],
        },
        "metrics": {
            "latest": {name: getattr(latest_metric, name, None) for name in METRIC_FIELDS} | {"timestamp": _iso(latest_metric.timestamp) if latest_metric else None},
            "windows": {"10m": get_metric_window_stats(metrics_10, METRIC_FIELDS), "60m": get_metric_window_stats(metrics_60, METRIC_FIELDS)},
            "recent_points": recent_points,
        },
        "filesystems": {
            "latest": [{"mountpoint": fs.mountpoint, "device": fs.device, "fstype": fs.fstype, "total_gb": fs.total_gb, "used_gb": fs.used_gb, "free_gb": fs.free_gb, "percent": fs.percent, "inodes_percent": fs.inodes_percent, "timestamp": _iso(fs.timestamp)} for fs in latest_fs.values()],
            "critical": [],
            "windows": {"60m_by_mountpoint": fs_windows},
        },
        "logs": {
            "counts_by_severity": {"10m": dict(counts_10), "60m": dict(counts_60)},
            "top_signatures": group_log_signatures(logs_60, max_signatures=max_log_signatures, max_examples=max_log_examples_per_signature),
            "recent_high_severity": [{"severity": row.severity, "source": row.source, "message": row.message[:300], "captured_at": _iso(row.captured_at)} for row in logs_60 if row.severity in {"ERROR", "CRITICAL", "ALERT", "EMERGENCY"}][:20],
        },
        "top_processes": {
            "latest_cpu": [{"pid": p.pid, "name": p.name, "cpu_percent": p.cpu_percent, "ram_percent": p.ram_percent, "ram_mb": p.ram_mb, "username": p.username, "status": p.status, "cmdline": p.cmdline} for p in latest_cpu],
            "latest_ram": [{"pid": p.pid, "name": p.name, "cpu_percent": p.cpu_percent, "ram_percent": p.ram_percent, "ram_mb": p.ram_mb, "username": p.username, "status": p.status, "cmdline": p.cmdline} for p in latest_ram],
            "repeated_offenders_60m": [{"name": name, "kind": kind, "count": cnt} for (name, kind), cnt in offenders.most_common(20)],
        },
        "triggers": {"configured": [{"id": t.id, "name": t.name, "metric_name": t.metric_name, "operator": t.operator, "threshold": t.threshold} for t in triggers], "active": []},
        "remediation": {
            "recent_commands": [{"id": c.id, "script_id": c.script_id, "status": c.status, "exit_code": c.exit_code, "created_at": _iso(c.created_at), "finished_at": _iso(c.finished_at)} for c in cmds],
            "failed_recently": [c.script_id for c in cmds if c.status == "failed"],
        },
        "available_scripts": available_scripts,
        "knowledge_base": {},
        "deterministic_observations": [],
    }
    if not metrics_60:
        context["data_quality"]["missing"].append("metrics")
    if not fs_60:
        context["data_quality"]["warnings"].append("no filesystem samples in window")
    context["deterministic_observations"] = build_deterministic_observations(context)
    return context
