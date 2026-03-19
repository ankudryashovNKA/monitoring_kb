from __future__ import annotations

import argparse
import platform
import socket
import time
from datetime import datetime, timezone

import psutil
import requests

DEFAULT_INTERVAL_SECONDS = 60


def detect_primary_ip() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))
            return sock.getsockname()[0]
    except OSError:
        return "127.0.0.1"


def collect_metrics(node_id: str) -> dict[str, str | float | int]:
    virtual_memory = psutil.virtual_memory()
    return {
        "node_id": node_id,
        "cpu_percent": psutil.cpu_percent(interval=1),
        "ram_percent": virtual_memory.percent,
        "os_name": f"{platform.system()} {platform.release()}",
        "cpu_cores": psutil.cpu_count() or 1,
        "ram_total_mb": int(virtual_memory.total / (1024 * 1024)),
        "ip_address": detect_primary_ip(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Monitoring agent")
    parser.add_argument("--server-url", required=True, help="FastAPI server URL, e.g. http://localhost:8000")
    parser.add_argument("--node-id", default=socket.gethostname(), help="Node identifier")
    parser.add_argument("--interval", type=int, default=DEFAULT_INTERVAL_SECONDS, help="Send interval in seconds")
    args = parser.parse_args()

    endpoint = args.server_url.rstrip("/") + "/api/metrics"
    while True:
        payload = collect_metrics(args.node_id)
        response = requests.post(endpoint, json=payload, timeout=10)
        response.raise_for_status()
        print(f"Sent metrics: {payload}")
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
