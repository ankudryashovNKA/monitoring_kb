from __future__ import annotations

import argparse
from collections import deque
import hashlib
import hmac
import json
import os
from pathlib import Path
import platform
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone

import psutil
import requests
from dotenv import load_dotenv

DEFAULT_INTERVAL_SECONDS = 60
MAX_LOG_ENTRIES = 100
TOP_PROCESS_LIMIT = 10
SCRIPTS_DIR = "scripts"
LOG_SEVERITY_LEVELS = ("DEBUG", "INFO", "NOTICE", "WARNING", "ERROR", "CRITICAL", "ALERT", "EMERGENCY")

load_dotenv()

_last_disk_io_counters: psutil._common.sdiskio | None = None
_last_net_io_counters: psutil._common.snetio | None = None
_last_io_sample_ts: float | None = None


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


def collect_metrics(display_name: str, agent_id: str) -> dict[str, object]:
    os_name = detect_os_name()
    virtual_memory = psutil.virtual_memory()
    swap_memory = psutil.swap_memory()
    disk_io = psutil.disk_io_counters()
    io_rates = collect_io_rates(disk_io)
    load1 = load5 = load15 = None
    try:
        load1, load5, load15 = os.getloadavg()
    except (AttributeError, OSError):
        pass
    cpu_times = psutil.cpu_times_percent(interval=None)
    cpu_iowait = float(getattr(cpu_times, "iowait", 0.0) or 0.0)
    cpu_steal = float(getattr(cpu_times, "steal", 0.0) or 0.0)

    tcp_established = 0
    tcp_listen = 0
    try:
        for conn in psutil.net_connections(kind="inet"):
            status = str(getattr(conn, "status", ""))
            if status == "ESTABLISHED":
                tcp_established += 1
            elif status == "LISTEN":
                tcp_listen += 1
    except (psutil.AccessDenied, psutil.Error):
        tcp_established = 0
        tcp_listen = 0

    return {
        "node_id": display_name,
        "agent_id": agent_id,
        "cpu_percent": psutil.cpu_percent(interval=1),
        "ram_percent": virtual_memory.percent,
        "uptime_seconds": max(0.0, time.time() - psutil.boot_time()),
        "swap_percent": swap_memory.percent,
        "disk_read_time_ms": io_rates["disk_read_time_ms"],
        "disk_write_time_ms": io_rates["disk_write_time_ms"],
        "net_recv_kbps": io_rates["net_recv_kbps"],
        "net_sent_kbps": io_rates["net_sent_kbps"],
        "process_count": count_processes(),
        "zombie_processes": count_zombie_processes(),
        "load1": load1,
        "load5": load5,
        "load15": load15,
        "cpu_iowait_percent": cpu_iowait,
        "cpu_steal_percent": cpu_steal,
        "ram_used_mb": int(virtual_memory.used / (1024 * 1024)),
        "ram_available_mb": int(virtual_memory.available / (1024 * 1024)),
        "swap_used_mb": int(swap_memory.used / (1024 * 1024)),
        "swap_free_mb": int(swap_memory.free / (1024 * 1024)),
        "disk_read_kbps": io_rates["disk_read_kbps"],
        "disk_write_kbps": io_rates["disk_write_kbps"],
        "disk_read_iops": io_rates["disk_read_iops"],
        "disk_write_iops": io_rates["disk_write_iops"],
        "net_packets_recv_per_sec": io_rates["net_packets_recv_per_sec"],
        "net_packets_sent_per_sec": io_rates["net_packets_sent_per_sec"],
        "net_errors_in_per_sec": io_rates["net_errors_in_per_sec"],
        "net_errors_out_per_sec": io_rates["net_errors_out_per_sec"],
        "net_drops_in_per_sec": io_rates["net_drops_in_per_sec"],
        "net_drops_out_per_sec": io_rates["net_drops_out_per_sec"],
        "tcp_established": tcp_established,
        "tcp_listen": tcp_listen,
        "os_name": os_name,
        "cpu_cores": psutil.cpu_count() or 1,
        "ram_total_mb": int(virtual_memory.total / (1024 * 1024)),
        "ip_address": detect_primary_ip(),
        "filesystems": collect_filesystem_usage(),
        "top_cpu_processes": collect_top_processes(sort_by="cpu_percent"),
        "top_ram_processes": collect_top_processes(sort_by="ram_percent"),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def collect_io_rates(disk_io: psutil._common.sdiskio | None) -> dict[str, float]:
    global _last_disk_io_counters, _last_net_io_counters, _last_io_sample_ts

    now = time.time()
    net_io = psutil.net_io_counters()
    defaults = {
        "disk_read_time_ms": 0.0,
        "disk_write_time_ms": 0.0,
        "net_recv_kbps": 0.0,
        "net_sent_kbps": 0.0,
        "disk_read_kbps": 0.0,
        "disk_write_kbps": 0.0,
        "disk_read_iops": 0.0,
        "disk_write_iops": 0.0,
        "net_packets_recv_per_sec": 0.0,
        "net_packets_sent_per_sec": 0.0,
        "net_errors_in_per_sec": 0.0,
        "net_errors_out_per_sec": 0.0,
        "net_drops_in_per_sec": 0.0,
        "net_drops_out_per_sec": 0.0,
    }
    if _last_io_sample_ts is None or _last_disk_io_counters is None or _last_net_io_counters is None:
        _last_io_sample_ts = now
        _last_disk_io_counters = disk_io
        _last_net_io_counters = net_io
        return defaults

    elapsed = max(1e-6, now - _last_io_sample_ts)

    read_latency = 0.0
    write_latency = 0.0
    if disk_io and _last_disk_io_counters:
        read_count_delta = max(0, int(getattr(disk_io, "read_count", 0)) - int(getattr(_last_disk_io_counters, "read_count", 0)))
        write_count_delta = max(0, int(getattr(disk_io, "write_count", 0)) - int(getattr(_last_disk_io_counters, "write_count", 0)))
        read_time_delta = max(0.0, float(getattr(disk_io, "read_time", 0.0)) - float(getattr(_last_disk_io_counters, "read_time", 0.0)))
        write_time_delta = max(
            0.0, float(getattr(disk_io, "write_time", 0.0)) - float(getattr(_last_disk_io_counters, "write_time", 0.0))
        )
        if read_count_delta > 0:
            read_latency = read_time_delta / read_count_delta
        if write_count_delta > 0:
            write_latency = write_time_delta / write_count_delta

    recv_kbps = max(0.0, float(net_io.bytes_recv - _last_net_io_counters.bytes_recv) / elapsed / 1024)
    sent_kbps = max(0.0, float(net_io.bytes_sent - _last_net_io_counters.bytes_sent) / elapsed / 1024)
    read_bytes_delta = 0.0
    write_bytes_delta = 0.0
    read_iops = 0.0
    write_iops = 0.0
    if disk_io and _last_disk_io_counters:
        read_bytes_delta = max(0.0, float(getattr(disk_io, "read_bytes", 0.0)) - float(getattr(_last_disk_io_counters, "read_bytes", 0.0)))
        write_bytes_delta = max(0.0, float(getattr(disk_io, "write_bytes", 0.0)) - float(getattr(_last_disk_io_counters, "write_bytes", 0.0)))
        read_iops = max(0.0, read_count_delta / elapsed)
        write_iops = max(0.0, write_count_delta / elapsed)

    packets_recv = max(0.0, float(net_io.packets_recv - _last_net_io_counters.packets_recv) / elapsed)
    packets_sent = max(0.0, float(net_io.packets_sent - _last_net_io_counters.packets_sent) / elapsed)
    err_in = max(0.0, float(net_io.errin - _last_net_io_counters.errin) / elapsed)
    err_out = max(0.0, float(net_io.errout - _last_net_io_counters.errout) / elapsed)
    drop_in = max(0.0, float(net_io.dropin - _last_net_io_counters.dropin) / elapsed)
    drop_out = max(0.0, float(net_io.dropout - _last_net_io_counters.dropout) / elapsed)

    _last_io_sample_ts = now
    _last_disk_io_counters = disk_io
    _last_net_io_counters = net_io
    return {
        "disk_read_time_ms": read_latency,
        "disk_write_time_ms": write_latency,
        "net_recv_kbps": recv_kbps,
        "net_sent_kbps": sent_kbps,
        "disk_read_kbps": read_bytes_delta / elapsed / 1024,
        "disk_write_kbps": write_bytes_delta / elapsed / 1024,
        "disk_read_iops": read_iops,
        "disk_write_iops": write_iops,
        "net_packets_recv_per_sec": packets_recv,
        "net_packets_sent_per_sec": packets_sent,
        "net_errors_in_per_sec": err_in,
        "net_errors_out_per_sec": err_out,
        "net_drops_in_per_sec": drop_in,
        "net_drops_out_per_sec": drop_out,
    }


def collect_top_processes(sort_by: str) -> list[dict[str, str | float | int]]:
    if sort_by not in {"cpu_percent", "ram_percent"}:
        raise ValueError(f"Unsupported top process sort key: {sort_by}")

    total_ram = psutil.virtual_memory().total or 1
    entries: list[dict[str, str | float | int]] = []
    for process in psutil.process_iter(["pid", "name", "memory_info", "username", "cmdline", "status", "create_time"]):
        try:
            memory_info = process.info.get("memory_info")
            rss = int(memory_info.rss) if memory_info is not None else 0
            ram_percent = (rss / total_ram) * 100
            entries.append(
                {
                    "pid": int(process.info.get("pid") or 0),
                    "name": str(process.info.get("name") or "unknown"),
                    "username": process.info.get("username"),
                    "cmdline": " ".join(process.info.get("cmdline") or [])[:500] or None,
                    "status": process.info.get("status"),
                    "create_time": process.info.get("create_time"),
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


def collect_filesystem_usage() -> list[dict[str, str | float]]:
    filesystems: list[dict[str, str | float]] = []
    seen_mounts: set[str] = set()
    for partition in psutil.disk_partitions(all=True):
        mountpoint = partition.mountpoint
        if not mountpoint or mountpoint in seen_mounts:
            continue
        seen_mounts.add(mountpoint)
        try:
            usage = psutil.disk_usage(mountpoint)
        except (PermissionError, FileNotFoundError, OSError):
            continue

        total_gb = usage.total / (1024 ** 3)
        used_gb = usage.used / (1024 ** 3)
        free_gb = usage.free / (1024 ** 3)
        inodes_total = inodes_free = inodes_used = None
        inodes_percent = None
        try:
            stat = os.statvfs(mountpoint)
            if int(stat.f_files) > 0:
                inodes_total = int(stat.f_files)
                inodes_free = int(stat.f_ffree)
                inodes_used = max(0, inodes_total - inodes_free)
                inodes_percent = (inodes_used / inodes_total) * 100.0
        except (AttributeError, OSError):
            pass
        filesystems.append(
            {
                "device": partition.device or mountpoint,
                "mountpoint": mountpoint,
                "fstype": partition.fstype or "unknown",
                "total_gb": round(total_gb, 2),
                "used_gb": round(used_gb, 2),
                "free_gb": round(free_gb, 2),
                "percent": float(usage.percent),
                "inodes_total": inodes_total,
                "inodes_used": inodes_used,
                "inodes_free": inodes_free,
                "inodes_percent": inodes_percent,
            }
        )
    return sorted(filesystems, key=lambda item: str(item["mountpoint"]).lower())


def count_zombie_processes() -> int:
    zombies = 0
    for process in psutil.process_iter(["status"]):
        try:
            if process.info.get("status") == psutil.STATUS_ZOMBIE:
                zombies += 1
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return zombies


def count_processes() -> int:
    try:
        return len(psutil.pids())
    except Exception:
        return 0


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

    entries: list[dict[str, str]] = []
    for event_lines in events[:MAX_LOG_ENTRIES]:
        severity = "INFO"
        for line in event_lines:
            if line.lower().startswith("level:"):
                severity = _normalize_severity(line.split(":", 1)[1].strip())
                break
        entries.append({"source": "windows-eventlog", "severity": severity, "message": "\n".join(event_lines)})
    return entries


def _normalize_severity(raw_level: str) -> str:
    value = (raw_level or "").strip().upper()
    mapping = {
        "WARN": "WARNING",
        "ERR": "ERROR",
        "FATAL": "CRITICAL",
        "SEVERE": "CRITICAL",
        "INFORMATION": "INFO",
        "INFORMATIONAL": "INFO",
    }
    normalized = mapping.get(value, value)
    return normalized if normalized in LOG_SEVERITY_LEVELS else "INFO"


def _extract_linux_severity(message: str) -> str:
    lowered = message.lower()
    if " emergency" in lowered or lowered.startswith("emerg"):
        return "EMERGENCY"
    if " alert" in lowered or lowered.startswith("alert"):
        return "ALERT"
    if " critical" in lowered or " crit" in lowered:
        return "CRITICAL"
    if " error" in lowered or " err" in lowered:
        return "ERROR"
    if " warning" in lowered or " warn" in lowered:
        return "WARNING"
    if " notice" in lowered:
        return "NOTICE"
    if " debug" in lowered:
        return "DEBUG"
    return "INFO"


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
        return [{"source": source, "severity": _extract_linux_severity(line), "message": line} for line in lines]

    try:
        return [
            {"source": source, "severity": _extract_linux_severity(line), "message": _sanitize_log_text(line)}
            for line in _tail_file(path, MAX_LOG_ENTRIES)
        ]
    except OSError as error:
        return [{"source": source, "severity": "ERROR", "message": f"Failed to read {path}: {error}"}]


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


def get_signed_json(
    *,
    server_url: str,
    endpoint_path: str,
    timeout: int,
    agent_id: str,
    agent_secret: str,
) -> requests.Response:
    raw_body = b""
    headers = build_signed_headers(
        method="GET",
        endpoint_path=endpoint_path,
        payload_bytes=raw_body,
        agent_id=agent_id,
        agent_secret=agent_secret,
    )
    url = server_url.rstrip("/") + endpoint_path
    return requests.get(url, headers=headers, timeout=timeout)


def discover_local_scripts(base_dir: Path) -> list[dict[str, str]]:
    scripts_dir = base_dir / SCRIPTS_DIR
    if not scripts_dir.exists() or not scripts_dir.is_dir():
        return []
    items: list[dict[str, str]] = []
    for path in sorted(scripts_dir.iterdir(), key=lambda item: item.name.lower()):
        if not path.is_file():
            continue
        items.append({"script_id": path.name, "script_path": str(path.resolve())})
    return items


def run_local_script(base_dir: Path, script_id: str) -> tuple[int, str, str]:
    scripts_dir = (base_dir / SCRIPTS_DIR).resolve()
    candidate = (scripts_dir / script_id).resolve()
    if not str(candidate).startswith(str(scripts_dir)):
        return 1, "", "Script path escapes scripts/ directory"
    if not candidate.exists() or not candidate.is_file():
        return 1, "", "Script not found in scripts/ directory"
    extension = candidate.suffix.lower()
    is_windows = platform.system() == "Windows"

    if is_windows:
        if extension == ".ps1":
            command = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(candidate)]
        elif extension in {".bat", ".cmd"}:
            command = ["cmd", "/c", str(candidate)]
        elif extension == ".py":
            command = [sys.executable, str(candidate)]
        else:
            return 1, "", f"Unsupported script extension on Windows: {extension or '(none)'}"
    else:
        if extension == ".sh":
            command = ["bash", str(candidate)]
        elif extension == ".py":
            command = [sys.executable, str(candidate)]
        else:
            return 1, "", f"Unsupported script extension on Linux: {extension or '(none)'}"

    try:
        completed = subprocess.run(command, capture_output=True, text=True, check=False, cwd=str(base_dir))
    except OSError as error:
        return 1, "", str(error)
    return completed.returncode, completed.stdout[-200000:], completed.stderr[-200000:]


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
    scripts_path = "/api/agent/scripts"
    command_next_path = "/api/agent/commands/next"
    base_dir = Path.cwd()

    backoff_seconds = send_interval
    while True:
        try:
            metrics_payload: dict[str, object] = {}
            logs_payload: dict[str, str | int | list[dict[str, str]]] = {"entries": []}
            try:
                metrics_payload = collect_metrics(args.display_name, args.agent_id)
            except Exception as error:
                print(f"collect_metrics failed: {error}", file=sys.stderr)
            try:
                logs_payload = collect_logs_payload(args.display_name, args.agent_id)
            except Exception as error:
                print(f"collect_logs_payload failed: {error}", file=sys.stderr)

            if metrics_payload:
                metrics_response = post_signed_json(server_url=args.server_url, endpoint_path=metrics_path, payload=metrics_payload, timeout=10, agent_id=args.agent_id, agent_secret=args.agent_secret)
                metrics_response.raise_for_status()
            if logs_payload:
                logs_response = post_signed_json(server_url=args.server_url, endpoint_path=logs_path, payload=logs_payload, timeout=20, agent_id=args.agent_id, agent_secret=args.agent_secret)
                logs_response.raise_for_status()

            scripts_payload = {"node_id": args.display_name, "scripts": discover_local_scripts(base_dir)}
            scripts_response = post_signed_json(server_url=args.server_url, endpoint_path=scripts_path, payload=scripts_payload, timeout=10, agent_id=args.agent_id, agent_secret=args.agent_secret)
            scripts_response.raise_for_status()

            command_response = get_signed_json(server_url=args.server_url, endpoint_path=command_next_path, timeout=10, agent_id=args.agent_id, agent_secret=args.agent_secret)
            command_response.raise_for_status()
            command_item = command_response.json().get("item")
            if command_item:
                started_at = datetime.now(timezone.utc).isoformat()
                exit_code, stdout, stderr = run_local_script(base_dir, str(command_item.get("script_id", "")))
                finished_at = datetime.now(timezone.utc).isoformat()
                result_payload = {"status": "completed" if exit_code == 0 else "failed", "stdout": stdout, "stderr": stderr, "exit_code": exit_code, "started_at": started_at, "finished_at": finished_at}
                result_response = post_signed_json(server_url=args.server_url, endpoint_path=f"/api/agent/commands/{int(command_item['id'])}/result", payload=result_payload, timeout=120, agent_id=args.agent_id, agent_secret=args.agent_secret)
                result_response.raise_for_status()
            if metrics_payload:
                print(f"Sent metrics: {json.dumps(metrics_payload)}")
            print(f"Sent logs entries: {len(logs_payload.get('entries', []))}")
            backoff_seconds = send_interval
        except Exception as error:
            print(f"Iteration failed: {error}", file=sys.stderr)
            time.sleep(backoff_seconds)
            backoff_seconds = min(backoff_seconds * 2, max(send_interval, 300))
            continue
        time.sleep(send_interval)


if __name__ == "__main__":
    main()
