from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import sys
import time
from pathlib import Path

from fastapi.testclient import TestClient
from fastapi import HTTPException

sys.path.append(str(Path(__file__).resolve().parents[1]))

from main import (  # noqa: E402
    app,
    RECENT_POINTS_LIMIT,
    _normalize_kb_results,
    TriggerCreateIn,
    create_trigger,
    dashboard,
    get_knowledge_base,
    ingest_metric,
    list_metric_history,
    list_metrics,
    list_logs,
    list_nodes,
    list_problems,
    list_top_processes,
    list_triggers,
    rename_node,
    MetricIn,
    NodeRenameIn,
    LogEntryIn,
    LogsIn,
    ingest_logs,
)
from app.db.session import SessionLocal  # noqa: E402
from app.models.agent import Agent  # noqa: E402
from app.models.filesystem_sample import FilesystemSample  # noqa: E402
from app.models.process_sample import ProcessSample  # noqa: E402
from app.services.llm_context import build_node_analysis_context, get_metric_window_stats, group_log_signatures  # noqa: E402
from app.models.metric import Metric  # noqa: E402
from app.models.node import Node  # noqa: E402
from app.models.log_entry import LogEntry  # noqa: E402
from app.models.trigger import Trigger  # noqa: E402
from app.models.agent_script import AgentScript  # noqa: E402
from app.models.agent_command import AgentCommand  # noqa: E402
from app.security.agent_auth import register_agent  # noqa: E402


def setup_function() -> None:
    with SessionLocal() as db:
        db.query(Metric).delete()
        db.query(LogEntry).delete()
        db.query(Trigger).delete()
        db.query(FilesystemSample).delete()
        db.query(ProcessSample).delete()
        db.query(AgentCommand).delete()
        db.query(AgentScript).delete()
        db.query(Node).delete()
        db.query(Agent).delete()
        db.commit()


def _signed_headers(
    agent_id: str,
    secret: str,
    path: str,
    raw_body: bytes,
    timestamp: int | None = None,
    method: str = "POST",
) -> dict[str, str]:
    ts = str(timestamp if timestamp is not None else int(time.time()))
    payload = f"{method}\n{path}\n{ts}\n".encode("utf-8") + raw_body
    signature = hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()
    return {"X-Agent-ID": agent_id, "X-Timestamp": ts, "X-Signature": signature, "Content-Type": "application/json"}


def test_ingest_and_list_metrics() -> None:
    for index in range(RECENT_POINTS_LIMIT + 2):
        response = ingest_metric(
            MetricIn(
                node_id="node-1",
                cpu_percent=float(index),
                ram_percent=float(index + 1),
                os_name="Linux 6.8",
                cpu_cores=8,
                ram_total_mb=16384,
                ip_address="10.0.0.10",
            )
        )
        assert response == {"status": "ok"}

    items = list_metrics(node_id="node-1")["items"]
    assert len(items) == RECENT_POINTS_LIMIT
    assert items[-1]["cpu_percent"] == float(RECENT_POINTS_LIMIT + 1)
    assert items[-1]["display_name"] == "node-1"


def test_nodes_list_and_rename() -> None:
    ingest_metric(
        MetricIn(
            node_id="node-rename",
            cpu_percent=20.0,
            ram_percent=45.0,
            os_name="Ubuntu 24.04",
            cpu_cores=4,
            ram_total_mb=8192,
            ip_address="192.168.1.20",
        )
    )

    node = next(item for item in list_nodes()["items"] if item["node_id"] == "node-rename")
    assert node["display_name"] == "node-rename"
    assert node["os_name"] == "Ubuntu 24.04"

    renamed = rename_node("node-rename", NodeRenameIn(display_name="Database node"))
    assert renamed["display_name"] == "Database node"

    metrics = list_metrics(node_id="Database node")["items"]
    assert metrics[-1]["display_name"] == "Database node"


def test_dashboard_page_available() -> None:
    html = dashboard()
    assert "Monitoring KB MVP" in html
    assert "Latest metrics" in html
    assert "Nodes" in html
    assert "Graphs" in html
    assert "Triggers" in html
    assert "Problems" in html
    assert "Logs" in html
    assert "Top" in html
    assert "Knowledge Base" in html


def test_metric_history() -> None:
    ingest_metric(
        MetricIn(
            node_id="node-graph",
            cpu_percent=17.5,
            ram_percent=66.0,
            os_name="Ubuntu",
            cpu_cores=4,
            ram_total_mb=8192,
            ip_address="10.0.0.11",
        )
    )
    ingest_metric(
        MetricIn(
            node_id="node-graph",
            cpu_percent=22.0,
            ram_percent=64.0,
            os_name="Ubuntu",
            cpu_cores=4,
            ram_total_mb=8192,
            ip_address="10.0.0.11",
        )
    )

    history = list_metric_history(node_id="node-graph", metric_name="cpu_percent", interval_minutes=60)
    assert history["node_id"] == "node-graph"
    assert history["metric_name"] == "cpu_percent"
    assert len(history["items"]) == 2
    assert history["items"][-1]["value"] == 22.0


def test_top_processes() -> None:
    ingest_metric(
        MetricIn(
            node_id="node-top",
            cpu_percent=18.0,
            ram_percent=33.0,
            os_name="Ubuntu",
            cpu_cores=4,
            ram_total_mb=8192,
            ip_address="10.0.0.14",
            top_cpu_processes=[
                {"pid": 101, "name": "python", "cpu_percent": 72.5, "ram_percent": 2.2, "ram_mb": 180},
                {"pid": 102, "name": "java", "cpu_percent": 34.1, "ram_percent": 6.9, "ram_mb": 560},
            ],
            top_ram_processes=[
                {"pid": 102, "name": "java", "cpu_percent": 34.1, "ram_percent": 6.9, "ram_mb": 560},
                {"pid": 101, "name": "python", "cpu_percent": 72.5, "ram_percent": 2.2, "ram_mb": 180},
            ],
        )
    )

    top_payload = list_top_processes(node_id="node-top")
    assert top_payload["node_id"] == "node-top"
    assert len(top_payload["top_cpu_processes"]) == 2
    assert top_payload["top_cpu_processes"][0]["name"] == "python"


def test_triggers_and_problems() -> None:
    with SessionLocal() as db:
        agent_id, _secret = register_agent(db)
    ingest_metric(
        MetricIn(
            node_id="node-alert",
            agent_id=agent_id,
            cpu_percent=91.0,
            ram_percent=40.0,
            os_name="Ubuntu",
            cpu_cores=4,
            ram_total_mb=8192,
            ip_address="10.0.0.12",
        )
    )
    with SessionLocal() as db:
        db.add(
            AgentScript(
                agent_id=agent_id,
                node_id="node-alert",
                script_id="restart.sh",
                script_path="/tmp/restart.sh",
                updated_at=datetime.now(timezone.utc),
            )
        )
        db.commit()

    created = create_trigger(
        TriggerCreateIn(
            node_id="node-alert",
            metric_name="cpu_percent",
            operator=">",
            threshold=85.0,
            action_script_id="restart.sh",
        )
    )
    assert created["is_active"] is True

    triggers = list_triggers(node_id="node-alert")["items"]
    assert len(triggers) == 1
    assert triggers[0]["metric_name"] == "cpu_percent"
    assert triggers[0]["operator"] == ">"
    assert triggers[0]["threshold"] == 85.0
    assert triggers[0]["is_active"] is True
    assert triggers[0]["action_script_id"] == "restart.sh"

    problems = list_problems()["items"]
    assert len(problems) == 1
    assert problems[0]["node_id"] == "node-alert"


def test_agent_scripts_and_commands_flow() -> None:
    with SessionLocal() as db:
        agent_id, secret = register_agent(db)
    client = TestClient(app)
    ingest_metric(
        MetricIn(
            node_id="node-remediate",
            agent_id=agent_id,
            cpu_percent=95.0,
            ram_percent=20.0,
            os_name="Ubuntu",
            cpu_cores=4,
            ram_total_mb=4096,
            ip_address="10.0.0.66",
        )
    )
    scripts_payload = {"node_id": "node-remediate", "scripts": [{"script_id": "fix.sh", "script_path": "/opt/agent/scripts/fix.sh"}]}
    scripts_raw = json.dumps(scripts_payload, separators=(",", ":")).encode("utf-8")
    scripts_headers = _signed_headers(agent_id, secret, "/api/agent/scripts", scripts_raw)
    scripts_response = client.post("/api/agent/scripts", data=scripts_raw, headers=scripts_headers)
    assert scripts_response.status_code == 200

    created = create_trigger(
        TriggerCreateIn(
            node_id="node-remediate",
            metric_name="cpu_percent",
            operator=">",
            threshold=80.0,
            action_script_id="fix.sh",
        )
    )
    assert created["action_script_id"] == "fix.sh"

    ingest_metric(
        MetricIn(
            node_id="node-remediate",
            agent_id=agent_id,
            cpu_percent=97.0,
            ram_percent=20.0,
            os_name="Ubuntu",
            cpu_cores=4,
            ram_total_mb=4096,
            ip_address="10.0.0.66",
        )
    )
    next_headers = _signed_headers(agent_id, secret, "/api/agent/commands/next", b"", method="GET")
    next_response = client.get("/api/agent/commands/next", headers=next_headers)
    assert next_response.status_code == 200
    item = next_response.json()["item"]
    assert item["script_id"] == "fix.sh"

    result_payload = {
        "status": "completed",
        "stdout": "ok",
        "stderr": "",
        "exit_code": 0,
        "started_at": "2026-04-20T10:00:00+00:00",
        "finished_at": "2026-04-20T10:00:01+00:00",
    }
    result_raw = json.dumps(result_payload, separators=(",", ":")).encode("utf-8")
    result_headers = _signed_headers(agent_id, secret, f"/api/agent/commands/{item['id']}/result", result_raw)
    result_response = client.post(f"/api/agent/commands/{item['id']}/result", data=result_raw, headers=result_headers)
    assert result_response.status_code == 200

    next_response_again = client.get("/api/agent/commands/next", headers=next_headers)
    assert next_response_again.json()["item"] is None


def test_knowledge_base_normalization_and_endpoint() -> None:
    payload = {
        "id": 4206,
        "date": "Wednesday, March 25, 2026",
        "presetName": "Monitoring server",
        "presetId": 733,
        "results": [
            {
                "key": 8972,
                "id": 5071,
                "name": "Утечка памяти",
                "description": "",
                "explanatorySet": [
                    {"fakeId": 22823, "id": 5074, "name": "Memory_Utilization", "description": ""},
                    {"fakeId": 22824, "id": 5079, "name": "Swap_Usage", "description": ""},
                ],
            }
        ],
    }
    normalized = _normalize_kb_results(payload)
    assert normalized[0]["name"] == "Утечка памяти"
    assert normalized[0]["explanatory_set"][0]["name"] == "Memory_Utilization"

    payload = asyncio.run(get_knowledge_base(node_id="node-1"))
    assert "status" in payload
    assert "items" in payload


def test_logs_ingest_and_list() -> None:
    ingest_metric(
        MetricIn(
            node_id="node-logs",
            cpu_percent=10.0,
            ram_percent=20.0,
            os_name="Ubuntu",
            cpu_cores=4,
            ram_total_mb=4096,
            ip_address="10.0.0.13",
        )
    )
    ingest_logs(
        LogsIn(
            node_id="node-logs",
            os_name="Ubuntu 24.04",
            cpu_cores=4,
            ram_total_mb=4096,
            ip_address="10.0.0.13",
            entries=[
                LogEntryIn(source="linux-syslog", severity="INFO", message="kernel: boot complete"),
                LogEntryIn(source="linux-syslog", severity="ERROR", message="sshd: auth failed"),
                LogEntryIn(source="linux-syslog", severity="INFO", message="sshd: accepted publickey"),
            ],
        )
    )

    response = list_logs(node_id="node-logs", severity="INFO")
    assert response["node_id"] == "node-logs"
    assert response["os_name"] == "Ubuntu 24.04"
    assert len(response["items"]) == 2
    assert all(item["severity"] == "INFO" for item in response["items"])

    error_response = list_logs(node_id="node-logs", severity="ERROR")
    assert len(error_response["items"]) == 1
    assert error_response["items"][0]["message"] == "sshd: auth failed"


def test_logs_invalid_severity() -> None:
    ingest_metric(
        MetricIn(
            node_id="node-logs-invalid",
            cpu_percent=10.0,
            ram_percent=20.0,
            os_name="Ubuntu",
            cpu_cores=4,
            ram_total_mb=4096,
            ip_address="10.0.0.130",
        )
    )
    try:
        list_logs(node_id="node-logs-invalid", severity="TRACE")
    except HTTPException as error:
        assert error.status_code == 400
        assert "Unsupported severity" in str(error.detail)
    else:
        raise AssertionError("Expected unsupported severity error")


def test_users_list_returns_valid_admin_email() -> None:
    client = TestClient(app)
    login_response = client.post("/api/auth/login", json={"login": "admin", "password": "admin"})
    assert login_response.status_code == 200

    users_response = client.get("/api/users")
    assert users_response.status_code == 200
    users = users_response.json()
    assert users
    assert users[0]["email"].endswith("@monitoring-kb.com")


def test_agent_auth_success() -> None:
    with SessionLocal() as db:
        agent_id, secret = register_agent(db)
    client = TestClient(app)

    payload = {
        "node_id": "node-auth",
        "cpu_percent": 11.0,
        "ram_percent": 22.0,
        "os_name": "Ubuntu",
        "cpu_cores": 2,
        "ram_total_mb": 4096,
        "ip_address": "10.0.0.30",
        "timestamp": "2026-03-30T00:00:00+00:00",
    }
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    headers = _signed_headers(agent_id, secret, "/api/agent/metrics", raw)
    response = client.post("/api/agent/metrics", data=raw, headers=headers)
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_agent_auth_invalid_signature() -> None:
    with SessionLocal() as db:
        agent_id, secret = register_agent(db)
    client = TestClient(app)
    payload = {
        "node_id": "node-auth",
        "cpu_percent": 11.0,
        "ram_percent": 22.0,
        "os_name": "Ubuntu",
        "cpu_cores": 2,
        "ram_total_mb": 4096,
        "ip_address": "10.0.0.30",
    }
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    headers = _signed_headers(agent_id, secret + "invalid", "/api/agent/metrics", raw)
    response = client.post("/api/agent/metrics", data=raw, headers=headers)
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid signature"


def test_agent_auth_unknown_agent() -> None:
    client = TestClient(app)
    payload = {
        "node_id": "node-auth",
        "cpu_percent": 11.0,
        "ram_percent": 22.0,
        "os_name": "Ubuntu",
        "cpu_cores": 2,
        "ram_total_mb": 4096,
        "ip_address": "10.0.0.30",
    }
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    headers = _signed_headers("unknown-agent", "secret", "/api/agent/metrics", raw)
    response = client.post("/api/agent/metrics", data=raw, headers=headers)
    assert response.status_code == 401
    assert response.json()["detail"] == "Unknown agent"


def test_agent_auth_disabled_agent() -> None:
    with SessionLocal() as db:
        agent_id, secret = register_agent(db)
        agent = db.query(Agent).filter(Agent.agent_id == agent_id).first()
        assert agent is not None
        agent.enabled = False
        db.commit()
    client = TestClient(app)
    payload = {
        "node_id": "node-auth",
        "cpu_percent": 11.0,
        "ram_percent": 22.0,
        "os_name": "Ubuntu",
        "cpu_cores": 2,
        "ram_total_mb": 4096,
        "ip_address": "10.0.0.30",
    }
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    headers = _signed_headers(agent_id, secret, "/api/agent/metrics", raw)
    response = client.post("/api/agent/metrics", data=raw, headers=headers)
    assert response.status_code == 403
    assert response.json()["detail"] == "Agent is disabled"


def test_agent_auth_expired_timestamp() -> None:
    with SessionLocal() as db:
        agent_id, secret = register_agent(db)
    client = TestClient(app)
    payload = {
        "node_id": "node-auth",
        "cpu_percent": 11.0,
        "ram_percent": 22.0,
        "os_name": "Ubuntu",
        "cpu_cores": 2,
        "ram_total_mb": 4096,
        "ip_address": "10.0.0.30",
    }
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    headers = _signed_headers(agent_id, secret, "/api/agent/metrics", raw, timestamp=int(time.time()) - 601)
    response = client.post("/api/agent/metrics", data=raw, headers=headers)
    assert response.status_code == 401
    assert response.json()["detail"] == "Authentication timestamp is outside allowed window"


def test_login_sets_secure_cookie_for_https_proxy() -> None:
    client = TestClient(app)
    response = client.post(
        "/api/auth/login",
        json={"login": "admin", "password": "admin"},
        headers={"X-Forwarded-Proto": "https"},
    )
    assert response.status_code == 200
    set_cookie = response.headers.get("set-cookie", "")
    assert "Secure" in set_cookie


def test_rename_node_updates_cached_top_processes_key() -> None:
    ingest_metric(
        MetricIn(
            node_id="node-cache",
            cpu_percent=18.0,
            ram_percent=33.0,
            os_name="Ubuntu",
            cpu_cores=4,
            ram_total_mb=8192,
            ip_address="10.0.0.14",
            top_cpu_processes=[
                {"pid": 101, "name": "python", "cpu_percent": 72.5, "ram_percent": 2.2, "ram_mb": 180},
            ],
            top_ram_processes=[
                {"pid": 101, "name": "python", "cpu_percent": 72.5, "ram_percent": 2.2, "ram_mb": 180},
            ],
        )
    )

    rename_node("node-cache", NodeRenameIn(display_name="node-cache-renamed"))

    payload = list_top_processes(node_id="node-cache-renamed")
    assert payload["node_id"] == "node-cache-renamed"
    assert payload["top_cpu_processes"]


def test_context_builder_schema_without_metrics() -> None:
    with SessionLocal() as db:
        db.add(Node(display_name="ctx-node", agent_id=None, os_name="Linux", cpu_cores=2, ram_total_mb=2048, ip_address="127.0.0.1", last_seen=datetime.now(timezone.utc)))
        db.commit()
        context = build_node_analysis_context(db, "ctx-node", window_minutes=60)
    assert context["schema_version"] == "llm_node_context.v2"
    assert "metrics" in context


def test_metric_window_stats_synthetic() -> None:
    now = datetime.now(timezone.utc)
    points = [
        Metric(node_id="n", cpu_percent=10, ram_percent=20, uptime_seconds=1, swap_percent=0, disk_read_time_ms=0, disk_write_time_ms=0, net_recv_kbps=0, net_sent_kbps=0, process_count=1, zombie_processes=0, timestamp=now - timedelta(minutes=2)),
        Metric(node_id="n", cpu_percent=20, ram_percent=30, uptime_seconds=1, swap_percent=0, disk_read_time_ms=0, disk_write_time_ms=0, net_recv_kbps=0, net_sent_kbps=0, process_count=1, zombie_processes=0, timestamp=now - timedelta(minutes=1)),
        Metric(node_id="n", cpu_percent=30, ram_percent=40, uptime_seconds=1, swap_percent=0, disk_read_time_ms=0, disk_write_time_ms=0, net_recv_kbps=0, net_sent_kbps=0, process_count=1, zombie_processes=0, timestamp=now),
    ]
    stats = get_metric_window_stats(points, ["cpu_percent"])
    assert stats["cpu_percent"]["avg"] == 20.0
    assert stats["cpu_percent"]["max"] == 30.0
    assert stats["cpu_percent"]["p95"] == 30.0
    assert stats["cpu_percent"]["delta_abs"] == 20.0
    assert stats["cpu_percent"]["trend"] == "rising"


def test_ingest_metric_saves_filesystem_and_process_samples() -> None:
    ingest_metric(
        MetricIn(
            node_id="node-samples",
            cpu_percent=10,
            ram_percent=10,
            os_name="Linux",
            cpu_cores=2,
            ram_total_mb=2048,
            ip_address="10.1.1.1",
            filesystems=[{"device": "/dev/sda1", "mountpoint": "/", "fstype": "ext4", "total_gb": 100, "used_gb": 80, "free_gb": 20, "percent": 80, "inodes_total": 1000, "inodes_used": 500, "inodes_free": 500, "inodes_percent": 50}],
            top_cpu_processes=[{"pid": 1, "name": "python", "cpu_percent": 50, "ram_percent": 1, "ram_mb": 10}],
            top_ram_processes=[{"pid": 2, "name": "java", "cpu_percent": 10, "ram_percent": 20, "ram_mb": 200}],
        )
    )
    with SessionLocal() as db:
        assert db.query(FilesystemSample).filter(FilesystemSample.node_id == "node-samples").count() == 1
        assert db.query(ProcessSample).filter(ProcessSample.node_id == "node-samples").count() == 2


def test_group_log_signatures_normalizes_numbers_uuid_ip() -> None:
    now = datetime.now(timezone.utc)
    logs = [
        LogEntry(node_id="n", source="s", severity="ERROR", message="pid=123 failed for 10.0.0.1 req 42", captured_at=now),
        LogEntry(node_id="n", source="s", severity="ERROR", message="pid=999 failed for 10.0.0.2 req 84", captured_at=now),
    ]
    grouped = group_log_signatures(logs)
    assert grouped[0]["count"] == 2
    assert "<ip>" in grouped[0]["signature"]
    assert "<num>" in grouped[0]["signature"]


def test_llm_context_endpoint_returns_context() -> None:
    ingest_metric(
        MetricIn(node_id="node-llm-context", cpu_percent=1, ram_percent=1, os_name="Linux", cpu_cores=2, ram_total_mb=2048, ip_address="1.1.1.1")
    )
    client = TestClient(app)
    login_resp = client.post('/api/auth/login', json={'login': 'admin', 'password': 'admin'})
    assert login_resp.status_code == 200
    resp = client.get('/api/llm/context', params={'node_id': 'node-llm-context', 'window_minutes': 60})
    assert resp.status_code == 200
    assert resp.json()["schema_version"] == "llm_node_context.v2"


def test_llm_analyze_backward_compatible_payload(monkeypatch) -> None:
    ingest_metric(
        MetricIn(node_id="node-llm", cpu_percent=1, ram_percent=1, os_name="Linux", cpu_cores=2, ram_total_mb=2048, ip_address="1.1.1.1")
    )

    def fake_stream(_prompt: str):
        yield {"response": "ok"}

    monkeypatch.setattr("main._stream_ollama_generate", fake_stream)
    async def fake_kb(_node_id: str):
        return {"status": "disabled", "items": [], "active_triggers": [], "matched_node_ids": [], "last_updated": None, "error": None}

    monkeypatch.setattr("main.get_knowledge_base", fake_kb)
    client = TestClient(app)
    login_resp = client.post('/api/auth/login', json={'login': 'admin', 'password': 'admin'})
    assert login_resp.status_code == 200
    resp = client.post('/api/llm/analyze-node', json={'node_id': 'node-llm'})
    assert resp.status_code == 200
    assert 'ok' in resp.text
