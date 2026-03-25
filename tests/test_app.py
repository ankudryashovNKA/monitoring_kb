from __future__ import annotations

import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1]))

from main import (  # noqa: E402
    RECENT_POINTS_LIMIT,
    TriggerCreateIn,
    create_trigger,
    dashboard,
    ingest_metric,
    list_metric_history,
    list_metrics,
    list_nodes,
    list_problems,
    list_triggers,
    rename_node,
    MetricIn,
    NodeRenameIn,
)
from app.db.session import SessionLocal  # noqa: E402
from app.models.metric import Metric  # noqa: E402
from app.models.node import Node  # noqa: E402
from app.models.trigger import Trigger  # noqa: E402


def setup_function() -> None:
    with SessionLocal() as db:
        db.query(Metric).delete()
        db.query(Trigger).delete()
        db.query(Node).delete()
        db.commit()


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

    metrics = list_metrics(node_id="node-rename")["items"]
    assert metrics[-1]["display_name"] == "Database node"


def test_dashboard_page_available() -> None:
    html = dashboard()
    assert "Monitoring KB MVP" in html
    assert "Latest data" in html
    assert "Nodes" in html
    assert "Graphs" in html
    assert "Triggers" in html
    assert "Problems" in html


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


def test_triggers_and_problems() -> None:
    ingest_metric(
        MetricIn(
            node_id="node-alert",
            cpu_percent=91.0,
            ram_percent=40.0,
            os_name="Ubuntu",
            cpu_cores=4,
            ram_total_mb=8192,
            ip_address="10.0.0.12",
        )
    )

    created = create_trigger(
        TriggerCreateIn(
            node_id="node-alert",
            metric_name="cpu_percent",
            operator=">",
            threshold=85.0,
        )
    )
    assert created["is_active"] is True

    triggers = list_triggers(node_id="node-alert")["items"]
    assert len(triggers) == 1
    assert triggers[0]["metric_name"] == "cpu_percent"
    assert triggers[0]["operator"] == ">"
    assert triggers[0]["threshold"] == 85.0
    assert triggers[0]["is_active"] is True

    problems = list_problems()["items"]
    assert len(problems) == 1
    assert problems[0]["node_id"] == "node-alert"
