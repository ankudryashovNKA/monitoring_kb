from __future__ import annotations

import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1]))

from main import (  # noqa: E402
    RECENT_POINTS_LIMIT,
    MetricIn,
    NodeRenameIn,
    dashboard,
    ingest_metric,
    init_db,
    list_metrics,
    list_nodes,
    rename_node,
    reset_db,
)


def setup_function() -> None:
    init_db()
    reset_db()


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


def test_data_persists_in_database() -> None:
    ingest_metric(
        MetricIn(
            node_id="node-persist",
            cpu_percent=12.5,
            ram_percent=33.3,
            os_name="Debian 12",
            cpu_cores=2,
            ram_total_mb=4096,
            ip_address="10.10.0.5",
        )
    )
    rename_node("node-persist", NodeRenameIn(display_name="Persistent node"))

    init_db()

    metrics = list_metrics(node_id="node-persist")["items"]
    nodes = list_nodes()["items"]

    assert len(metrics) == 1
    assert metrics[0]["display_name"] == "Persistent node"
    assert any(node["display_name"] == "Persistent node" for node in nodes)

def test_dashboard_page_available() -> None:
    html = dashboard()
    assert "Monitoring KB MVP" in html
    assert "Latest data" in html
    assert "Nodes" in html
