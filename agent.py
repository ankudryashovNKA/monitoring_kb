from __future__ import annotations

import argparse
from collections import deque
import hashlib
import hmac
import json
import os
import platform
import socket
import subprocess
import time
from datetime import datetime, timezone

import psutil
import requests
from dotenv import load_dotenv

DEFAULT_INTERVAL_SECONDS = 60
MAX_LOG_ENTRIES = 100
TOP_PROCESS_LIMIT = 10

load_dotenv()


def _sanitize_log_text(value: str) -> str:
    """Remove control characters that can break API validation/storage."""
    if not value:
        return ""
    cleaned = value.replace("\x00", "")
    return "".join(ch for ch in cleaned if ch >= " " or ch in "\t\r\n")


def detect_primary_ip() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))
            return sock.getsockname()[0]
    except OSError:
        return "127.0.0.1"


def collect_metrics(display_name: str, agent_id: str) -> dict[str, str | float | int]:
    os_name = detect_os_name()
    virtual_memory = psutil.virtual_memory()
    return {
        "node_id": display_name,
        "agent_id": agent_id,
        "cpu_percent": psutil.cpu_percent(interval=1),
        "ram_percent": virtual_memory.percent,
        "os_name": os_name,
        "cpu_cores": psutil.cpu_count() or 1,
        "ram_total_mb": int(virtual_memory.total / (1024 * 1024)),
        "ip_address": detect_primary_ip(),
        "top_cpu_processes": collect_top_processes(sort_by="cpu_percent"),
        "top_ram_processes": collect_top_processes(sort_by="ram_percent"),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def collect_top_processes(sort_by: str) -> list[dict[str, str | float | int]]:
    if sort_by not in {"cpu_percent", "ram_percent"}:
        raise ValueError(f"Unsupported top process sort key: {sort_by}")

    total_ram = psutil.virtual_memory().total or 1
    entries: list[dict[str, str | float | int]] = []
    for process in psutil.process_iter(["pid", "name", "memory_info"]):
        try:
            memory_info = process.info.get("memory_info")
            rss = int(memory_info.rss) if memory_info is not None else 0
            ram_percent = (rss / total_ram) * 100
            entries.append(
                {
                    "pid": int(process.info.get("pid") or 0),
                    "name": str(process.info.get("name") or "unknown"),
                    "cpu_percent": max(0.0, float(process.cpu_percent(interval=None))),
                    "ram_percent": max(0.0, min(100.0, float(ram_percent))),
                    "ram_mb": int(rss / (1024 * 1024)),
                }
            )
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    sorted_entries = sorted(entries, key=lambda item: float(item[sort_by]), reverse=True)
    return sorted_entries[:TOP_PROCESS_LIMIT]


def detect_os_name() -> str:
    system = platform.system()
    if system != "Linux":
        return f"{system} {platform.release()}"

    distro = "Linux"
    os_release = "/etc/os-release"
    if os.path.exists(os_release):
        try:
            data: dict[str, str] = {}
            with open(os_release, encoding="utf-8") as file:
                for line in file:
                    line = line.strip()
                    if not line or "=" not in line:
                        continue
                    key, value = line.split("=", 1)
                    data[key] = value.strip('"')
            distro = data.get("PRETTY_NAME") or data.get("NAME") or distro
        except OSError:
            distro = "Linux"
    return f"{distro} ({platform.release()})"


def _linux_log_source() -> tuple[str, str]:
    distro_id = ""
    distro_like = ""
    try:
        with open("/etc/os-release", encoding="utf-8") as file:
            for raw in file:
                if raw.startswith("ID="):
                    distro_id = raw.split("=", 1)[1].strip().strip('"').lower()
                if raw.startswith("ID_LIKE="):
                    distro_like = raw.split("=", 1)[1].strip().strip('"').lower()
    except OSError:
        pass

    signature = f"{distro_id} {distro_like}"
    if any(name in signature for name in ("debian", "ubuntu", "mint")) and os.path.exists("/var/log/syslog"):
        return "/var/log/syslog", "linux-syslog"
    if any(name in signature for name in ("rhel", "fedora", "centos", "rocky", "almalinux")) and os.path.exists("/var/log/messages"):
        return "/var/log/messages", "linux-messages"
    if os.path.exists("/var/log/syslog"):
        return "/var/log/syslog", "linux-syslog"
    if os.path.exists("/var/log/messages"):
        return "/var/log/messages", "linux-messages"
    return "journalctl", "linux-journalctl"


def _tail_file(path: str, limit: int) -> list[str]:
    with open(path, encoding="utf-8", errors="replace") as file:
        return [line.strip() for line in deque(file, maxlen=limit) if line.strip()]


def _collect_windows_eventlog() -> list[dict[str, str]]:
    command = ["wevtutil", "qe", "System", "/rd:true", f"/c:{MAX_LOG_ENTRIES}", "/f:text"]
    completed = subprocess.run(command, capture_output=True, text=True, check=False)
    if completed.returncode != 0:
        error_message = _sanitize_log_text(completed.stderr.strip())
        return [{"source": "windows-eventlog", "message": error_message}] if error_message else []

    raw_lines = [line.rstrip() for line in completed.stdout.splitlines()]
    events: list[list[str]] = []
    current_event: list[str] = []
    for raw_line in raw_lines:
        sanitized_line = _sanitize_log_text(raw_line.strip())
        if not sanitized_line:
            continue
        if sanitized_line.startswith("Event["):
            if current_event:
                events.append(current_event)
            current_event = [sanitized_line]
            continue
        if not current_event:
            current_event = [sanitized_line]
            continue
        current_event.append(sanitized_line)

    if current_event:
        events.append(current_event)

    return [
        {"source": "windows-eventlog", "message": "\n".join(event_lines)}
        for event_lines in events[:MAX_LOG_ENTRIES]
    ]


def collect_logs() -> list[dict[str, str]]:
    system = platform.system().lower()
    if system == "windows":
        return _collect_windows_eventlog()

    path, source = _linux_log_source()
    if path == "journalctl":
        command = ["journalctl", "-n", str(MAX_LOG_ENTRIES), "--no-pager", "--output=short-iso"]
        completed = subprocess.run(command, capture_output=True, text=True, check=False)
        text = completed.stdout if completed.returncode == 0 else completed.stderr
        lines = [
            _sanitize_log_text(line.strip())
            for line in text.splitlines()
            if line.strip()
        ][:MAX_LOG_ENTRIES]
        return [{"source": source, "message": line} for line in lines]

    try:
        return [
            {"source": source, "message": _sanitize_log_text(line)}
            for line in _tail_file(path, MAX_LOG_ENTRIES)
        ]
    except OSError as error:
        return [{"source": source, "message": f"Failed to read {path}: {error}"}]


def collect_logs_payload(display_name: str, agent_id: str) -> dict[str, str | int | list[dict[str, str]]]:
    virtual_memory = psutil.virtual_memory()
    return {
        "node_id": display_name,
        "agent_id": agent_id,
        "os_name": detect_os_name(),
        "cpu_cores": psutil.cpu_count() or 1,
        "ram_total_mb": int(virtual_memory.total / (1024 * 1024)),
        "ip_address": detect_primary_ip(),
        "entries": collect_logs(),
    }


def build_signed_headers(
    *,
    method: str,
    endpoint_path: str,
    payload_bytes: bytes,
    agent_id: str,
    agent_secret: str,
) -> dict[str, str]:
    timestamp = str(int(time.time()))
    canonical_payload = f"{method}\n{endpoint_path}\n{timestamp}\n".encode("utf-8") + payload_bytes
    signature = hmac.new(agent_secret.encode("utf-8"), canonical_payload, hashlib.sha256).hexdigest()
    return {
        "Content-Type": "application/json",
        "X-Agent-ID": agent_id,
        "X-Timestamp": timestamp,
        "X-Signature": signature,
    }


def post_signed_json(
    *,
    server_url: str,
    endpoint_path: str,
    payload: dict[str, object],
    timeout: int,
    agent_id: str,
    agent_secret: str,
) -> requests.Response:
    raw_body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    headers = build_signed_headers(
        method="POST",
        endpoint_path=endpoint_path,
        payload_bytes=raw_body,
        agent_id=agent_id,
        agent_secret=agent_secret,
    )
    url = server_url.rstrip("/") + endpoint_path
    return requests.post(url, data=raw_body, headers=headers, timeout=timeout)


def main() -> None:
    parser = argparse.ArgumentParser(description="Monitoring agent")
    parser.add_argument("--server-url", default=os.getenv("SERVER_URL"), help="FastAPI server URL, e.g. http://localhost:8000")
    parser.add_argument(
        "--display-name",
        default=os.getenv("DISPLAY_NAME", os.getenv("NODE_ID", socket.gethostname())),
        help="Display name shown in dashboard",
    )
    parser.add_argument("--agent-id", default=os.getenv("AGENT_ID"), help="Registered agent ID")
    parser.add_argument("--agent-secret", default=os.getenv("AGENT_SECRET"), help="Registered agent secret")
    parser.add_argument("--interval", type=int, default=DEFAULT_INTERVAL_SECONDS, help="Send interval in seconds (minimum 60)")
    args = parser.parse_args()

    if not args.server_url:
        raise SystemExit("SERVER_URL is required (env SERVER_URL or --server-url).")
    if not args.agent_id:
        raise SystemExit("AGENT_ID is required (env AGENT_ID or --agent-id).")
    if not args.agent_secret:
        raise SystemExit("AGENT_SECRET is required (env AGENT_SECRET or --agent-secret).")

    metrics_path = "/api/agent/metrics"
    logs_path = "/api/agent/logs"
    send_interval = max(DEFAULT_INTERVAL_SECONDS, args.interval)

    while True:
        metrics_payload = collect_metrics(args.display_name, args.agent_id)
        logs_payload = collect_logs_payload(args.display_name, args.agent_id)
        metrics_response = post_signed_json(
            server_url=args.server_url,
            endpoint_path=metrics_path,
            payload=metrics_payload,
            timeout=10,
            agent_id=args.agent_id,
            agent_secret=args.agent_secret,
        )
        metrics_response.raise_for_status()
        logs_response = post_signed_json(
            server_url=args.server_url,
            endpoint_path=logs_path,
            payload=logs_payload,
            timeout=20,
            agent_id=args.agent_id,
            agent_secret=args.agent_secret,
        )
        logs_response.raise_for_status()
        print(f"Sent metrics: {json.dumps(metrics_payload)}")
        print(f"Sent logs entries: {len(logs_payload['entries'])}")
        time.sleep(send_interval)


if __name__ == "__main__":
    main()
