from fastapi.testclient import TestClient

from app import RECENT_POINTS_LIMIT, app

client = TestClient(app)


def test_ingest_and_list_metrics() -> None:
    for index in range(RECENT_POINTS_LIMIT + 2):
        response = client.post(
            "/api/metrics",
            json={
                "node_id": "node-1",
                "cpu_percent": float(index),
                "ram_percent": float(index + 1),
            },
        )
        assert response.status_code == 200

    response = client.get("/api/metrics?node_id=node-1")
    assert response.status_code == 200
    items = response.json()["items"]
    assert len(items) == RECENT_POINTS_LIMIT
    assert items[-1]["cpu_percent"] == float(RECENT_POINTS_LIMIT + 1)


def test_dashboard_page_available() -> None:
    response = client.get("/")
    assert response.status_code == 200
    assert "Monitoring Dashboard" in response.text
