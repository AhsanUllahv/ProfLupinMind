from __future__ import annotations

import asyncio
import hashlib
import os
import signal
import subprocess
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from pathlib import Path
from shutil import disk_usage
from typing import Any, Awaitable, Callable


@dataclass
class CacheEntry:
    key: str
    value: dict[str, Any]
    created_at: float
    hits: int = 0


class CommandCache:
    def __init__(self, max_entries: int = 256, ttl_seconds: int = 900):
        self.max_entries = max_entries
        self.ttl_seconds = ttl_seconds
        self._items: OrderedDict[str, CacheEntry] = OrderedDict()
        self.hits = 0
        self.misses = 0
        self.evictions = 0

    def key_for(self, command: str) -> str:
        return hashlib.sha256(command.encode("utf-8")).hexdigest()

    def get(self, command: str) -> dict[str, Any] | None:
        key = self.key_for(command)
        entry = self._items.get(key)
        if not entry:
            self.misses += 1
            return None
        if time.time() - entry.created_at > self.ttl_seconds:
            self._items.pop(key, None)
            self.misses += 1
            return None
        entry.hits += 1
        self.hits += 1
        self._items.move_to_end(key)
        cached = dict(entry.value)
        cached["cached"] = True
        cached["cache_key"] = key
        return cached

    def set(self, command: str, value: dict[str, Any]) -> str:
        key = self.key_for(command)
        self._items[key] = CacheEntry(key=key, value=dict(value), created_at=time.time())
        self._items.move_to_end(key)
        while len(self._items) > self.max_entries:
            self._items.popitem(last=False)
            self.evictions += 1
        return key

    def clear(self) -> int:
        count = len(self._items)
        self._items.clear()
        self.hits = 0
        self.misses = 0
        self.evictions = 0
        return count

    def stats(self) -> dict[str, Any]:
        total = self.hits + self.misses
        utilization = len(self._items) / self.max_entries if self.max_entries else 0.0
        return {
            "entries": len(self._items),
            "size": len(self._items),
            "max_entries": self.max_entries,
            "max_size": self.max_entries,
            "ttl_seconds": self.ttl_seconds,
            "hits": self.hits,
            "hit_count": self.hits,
            "misses": self.misses,
            "miss_count": self.misses,
            "evictions": self.evictions,
            "hit_rate": round(self.hits / total, 3) if total else 0.0,
            "hit_rate_percent": round((self.hits / total) * 100, 1) if total else 0.0,
            "utilization": round(utilization, 3),
            "utilization_percent": round(utilization * 100, 1),
        }


@dataclass
class ProcessInfo:
    pid: int
    command: str
    started_at: float
    status: str = "running"
    ended_at: float | None = None
    exit_code: int | None = None
    progress: float = 0.0
    message: str = ""
    bytes_seen: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "pid": self.pid,
            "command": self.command,
            "status": self.status,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "exit_code": self.exit_code,
            "progress": round(min(max(self.progress, 0.0), 1.0), 3),
            "message": self.message,
            "bytes_seen": self.bytes_seen,
            "runtime_seconds": round((self.ended_at or time.time()) - self.started_at, 2),
        }


class ProcessRegistry:
    def __init__(self):
        self._items: dict[int, ProcessInfo] = {}

    def register(self, pid: int, command: str) -> None:
        self._items[pid] = ProcessInfo(pid=pid, command=command, started_at=time.time())

    def finish(self, pid: int, exit_code: int | None = None) -> None:
        info = self._items.get(pid)
        if not info:
            return
        info.status = "finished"
        info.exit_code = exit_code
        info.progress = 1.0
        info.ended_at = time.time()

    def update(self, pid: int, progress: float | None = None, message: str = "", bytes_seen: int | None = None) -> None:
        info = self._items.get(pid)
        if not info:
            return
        if progress is not None:
            info.progress = min(max(progress, 0.0), 1.0)
        if message:
            info.message = message
        if bytes_seen is not None:
            info.bytes_seen = max(bytes_seen, 0)

    def get(self, pid: int) -> dict[str, Any]:
        info = self._items.get(pid)
        if not info:
            return {"success": False, "error": f"Unknown process: {pid}"}
        return {"success": True, "process": info.to_dict()}

    def list(self, include_finished: bool = False) -> list[dict[str, Any]]:
        rows = []
        for info in self._items.values():
            if include_finished or info.status != "finished":
                rows.append(info.to_dict())
        return sorted(rows, key=lambda row: row["started_at"], reverse=True)

    def signal(self, pid: int, sig: signal.Signals) -> dict[str, Any]:
        info = self._items.get(pid)
        if not info:
            return {"success": False, "error": f"Unknown process: {pid}"}
        try:
            os.kill(pid, sig)
        except ProcessLookupError:
            info.status = "finished"
            info.ended_at = info.ended_at or time.time()
            return {"success": False, "error": f"Process already exited: {pid}"}
        except PermissionError as exc:
            return {"success": False, "error": str(exc)}
        if sig == signal.SIGTERM:
            info.status = "terminating"
        elif sig == signal.SIGSTOP:
            info.status = "paused"
        elif sig == signal.SIGCONT:
            info.status = "running"
        return {"success": True, "pid": pid, "status": info.status}

    async def terminate_gracefully(self, pid: int, timeout: float = 5.0) -> dict[str, Any]:
        info = self._items.get(pid)
        if not info:
            return {"success": False, "error": f"Unknown process: {pid}"}
        try:
            os.kill(pid, signal.SIGTERM)
            info.status = "terminating"
        except ProcessLookupError:
            info.status = "finished"
            info.ended_at = info.ended_at or time.time()
            return {"success": True, "pid": pid, "status": "already_exited"}
        except PermissionError as exc:
            return {"success": False, "error": str(exc)}

        deadline = time.time() + max(timeout, 0.1)
        while time.time() < deadline:
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                info.status = "terminated_gracefully"
                info.ended_at = time.time()
                return {"success": True, "pid": pid, "status": info.status}
            await asyncio.sleep(0.1)

        try:
            os.kill(pid, signal.SIGKILL)
            info.status = "force_killed"
            info.ended_at = time.time()
            return {"success": True, "pid": pid, "status": info.status}
        except ProcessLookupError:
            info.status = "terminated_gracefully"
            info.ended_at = time.time()
            return {"success": True, "pid": pid, "status": info.status}
        except PermissionError as exc:
            return {"success": False, "error": str(exc)}


@dataclass
class TaskInfo:
    task_id: str
    label: str
    target: str = ""
    session_id: str = ""
    status: str = "pending"
    created_at: float = field(default_factory=time.time)
    started_at: float | None = None
    ended_at: float | None = None
    result: dict[str, Any] | None = None
    error: str = ""
    _task: asyncio.Task | None = field(default=None, repr=False)

    def to_dict(self, include_result: bool = False) -> dict[str, Any]:
        row = {
            "task_id": self.task_id,
            "label": self.label,
            "target": self.target,
            "session_id": self.session_id,
            "status": self.status,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "runtime_seconds": round((self.ended_at or time.time()) - (self.started_at or self.created_at), 2),
            "error": self.error,
        }
        if include_result:
            row["result"] = self.result
        return row


class TaskRegistry:
    def __init__(self):
        self._items: dict[str, TaskInfo] = {}
        self._counter = 0

    def start(
        self,
        label: str,
        coro_factory: Callable[[], Awaitable[dict[str, Any]]],
        target: str = "",
        session_id: str = "",
    ) -> TaskInfo:
        self._counter += 1
        task_id = f"task-{int(time.time())}-{self._counter}"
        info = TaskInfo(task_id=task_id, label=label, target=target, session_id=session_id)
        self._items[task_id] = info

        async def runner():
            info.status = "running"
            info.started_at = time.time()
            try:
                info.result = await coro_factory()
                info.status = "completed"
            except asyncio.CancelledError:
                info.status = "cancelled"
                raise
            except Exception as exc:
                info.status = "failed"
                info.error = str(exc)
            finally:
                info.ended_at = time.time()

        info._task = asyncio.create_task(runner())
        return info

    def list(self, include_done: bool = True) -> list[dict[str, Any]]:
        rows = []
        for info in self._items.values():
            if include_done or info.status in {"pending", "running"}:
                rows.append(info.to_dict())
        return sorted(rows, key=lambda row: row["created_at"], reverse=True)

    def get(self, task_id: str, include_result: bool = True) -> dict[str, Any]:
        info = self._items.get(task_id)
        if not info:
            return {"error": f"Unknown task: {task_id}"}
        return info.to_dict(include_result=include_result)

    def cancel(self, task_id: str) -> dict[str, Any]:
        info = self._items.get(task_id)
        if not info or not info._task:
            return {"success": False, "error": f"Unknown task: {task_id}"}
        info._task.cancel()
        info.status = "cancelled"
        info.ended_at = time.time()
        return {"success": True, "task_id": task_id, "status": info.status}


class Telemetry:
    def __init__(self):
        self.started_at = time.time()
        self.commands = 0
        self.successes = 0
        self.failures = 0
        self.timeouts = 0
        self.total_duration = 0.0

    def record(self, exit_code: int, duration: float, timed_out: bool = False, cached: bool = False) -> None:
        if not cached:
            self.commands += 1
            self.total_duration += duration
            if timed_out:
                self.timeouts += 1
            if exit_code == 0:
                self.successes += 1
            else:
                self.failures += 1

    def stats(self) -> dict[str, Any]:
        total = max(self.commands, 1)
        disk = _disk_usage_percent(".")
        return {
            "uptime_seconds": round(time.time() - self.started_at, 2),
            "commands": self.commands,
            "commands_executed": self.commands,
            "successes": self.successes,
            "successful_commands": self.successes,
            "failures": self.failures,
            "failed_commands": self.failures,
            "timeouts": self.timeouts,
            "success_rate": round(self.successes / total, 3),
            "success_rate_percent": round((self.successes / total) * 100, 1),
            "average_duration": round(self.total_duration / total, 2),
            "average_execution_time": round(self.total_duration / total, 2),
            "load_average": os.getloadavg() if hasattr(os, "getloadavg") else None,
            "disk_percent": disk,
        }


def _read_proc_stat() -> tuple[int, int] | None:
    try:
        fields = Path("/proc/stat").read_text(encoding="utf-8").splitlines()[0].split()[1:]
        values = [int(v) for v in fields]
    except Exception:
        return None
    idle = values[3] + (values[4] if len(values) > 4 else 0)
    return sum(values), idle


def _cpu_percent(interval: float = 0.05) -> float:
    first = _read_proc_stat()
    if not first:
        return 0.0
    time.sleep(interval)
    second = _read_proc_stat()
    if not second:
        return 0.0
    total_delta = second[0] - first[0]
    idle_delta = second[1] - first[1]
    if total_delta <= 0:
        return 0.0
    return round((1 - idle_delta / total_delta) * 100, 1)


def _memory_percent() -> float:
    try:
        rows = Path("/proc/meminfo").read_text(encoding="utf-8").splitlines()
    except Exception:
        return 0.0
    values: dict[str, int] = {}
    for row in rows:
        key, value = row.split(":", 1)
        values[key] = int(value.strip().split()[0])
    total = values.get("MemTotal", 0)
    available = values.get("MemAvailable", 0)
    if not total:
        return 0.0
    return round((1 - available / total) * 100, 1)


def _disk_usage_percent(path: str | Path = ".") -> float:
    try:
        usage = disk_usage(path)
    except Exception:
        return 0.0
    return round((usage.used / usage.total) * 100, 1) if usage.total else 0.0


class ResourceMonitor:
    """Small stdlib resource monitor inspired by HexStrike's runtime dashboard."""

    def __init__(self, history_size: int = 120):
        self.history_size = history_size
        self._history: list[dict[str, Any]] = []

    def get_current_usage(self) -> dict[str, Any]:
        load = os.getloadavg() if hasattr(os, "getloadavg") else (0.0, 0.0, 0.0)
        usage = {
            "timestamp": time.time(),
            "cpu_percent": _cpu_percent(),
            "memory_percent": _memory_percent(),
            "disk_percent": _disk_usage_percent("."),
            "load_average": load,
            "load_percent": round((load[0] / max(os.cpu_count() or 1, 1)) * 100, 1),
        }
        self._history.append(usage)
        if len(self._history) > self.history_size:
            self._history = self._history[-self.history_size:]
        return usage

    def get_process_usage(self, pid: int) -> dict[str, Any]:
        status = Path(f"/proc/{pid}/status")
        if not status.exists():
            return {"pid": pid, "running": False}
        data: dict[str, str] = {}
        try:
            for row in status.read_text(encoding="utf-8", errors="replace").splitlines():
                if ":" in row:
                    key, value = row.split(":", 1)
                    data[key] = value.strip()
        except Exception:
            return {"pid": pid, "running": True}
        return {
            "pid": pid,
            "running": True,
            "state": data.get("State", ""),
            "memory_rss": data.get("VmRSS", "0 kB"),
            "threads": data.get("Threads", "0"),
        }

    def get_usage_trends(self) -> dict[str, Any]:
        if not self._history:
            self.get_current_usage()
        recent = self._history[-10:]
        return {
            "samples": len(self._history),
            "recent_samples": recent,
            "cpu_average": round(sum(s["cpu_percent"] for s in recent) / max(len(recent), 1), 1),
            "memory_average": round(sum(s["memory_percent"] for s in recent) / max(len(recent), 1), 1),
            "disk_latest": recent[-1]["disk_percent"] if recent else 0.0,
        }


class PerformanceDashboard:
    def __init__(self, max_history: int = 100):
        self.max_history = max_history
        self._executions: list[dict[str, Any]] = []

    def record_execution(self, command: str, result: dict[str, Any]) -> None:
        row = {
            "timestamp": time.time(),
            "command": command[:160],
            "success": result.get("exit_code", result.get("return_code", 1)) == 0 and not result.get("timed_out", False),
            "exit_code": result.get("exit_code", result.get("return_code")),
            "duration": float(result.get("duration", result.get("execution_time", 0.0)) or 0.0),
            "timed_out": bool(result.get("timed_out", False)),
            "cached": bool(result.get("cached", False)),
        }
        self._executions.append(row)
        if len(self._executions) > self.max_history:
            self._executions = self._executions[-self.max_history:]

    def get_summary(self) -> dict[str, Any]:
        total = len(self._executions)
        successes = sum(1 for row in self._executions if row["success"])
        failures = total - successes
        durations = [row["duration"] for row in self._executions]
        return {
            "total_executions": total,
            "successful_executions": successes,
            "failed_executions": failures,
            "success_rate": round((successes / total) * 100, 1) if total else 0.0,
            "average_duration": round(sum(durations) / total, 2) if total else 0.0,
            "timeouts": sum(1 for row in self._executions if row["timed_out"]),
            "cache_served": sum(1 for row in self._executions if row["cached"]),
            "recent": self._executions[-10:],
        }


class RuntimeHealth:
    def __init__(
        self,
        resource_monitor: ResourceMonitor,
        process_registry: ProcessRegistry,
        task_registry: TaskRegistry,
        cache: CommandCache,
        dashboard: PerformanceDashboard,
    ):
        self.resource_monitor = resource_monitor
        self.process_registry = process_registry
        self.task_registry = task_registry
        self.cache = cache
        self.dashboard = dashboard

    def report(self) -> dict[str, Any]:
        resource = self.resource_monitor.get_current_usage()
        active_processes = self.process_registry.list(include_finished=False)
        active_tasks = self.task_registry.list(include_done=False)
        cache_stats = self.cache.stats()
        performance = self.dashboard.get_summary()

        score = 100
        issues: list[str] = []
        if resource["cpu_percent"] > 95:
            score -= 30
            issues.append("Critical CPU usage")
        elif resource["cpu_percent"] > 80:
            score -= 15
            issues.append("High CPU usage")
        if resource["memory_percent"] > 95:
            score -= 25
            issues.append("Critical memory usage")
        elif resource["memory_percent"] > 85:
            score -= 10
            issues.append("High memory usage")
        if resource["disk_percent"] > 98:
            score -= 20
            issues.append("Critical disk usage")
        elif resource["disk_percent"] > 90:
            score -= 5
            issues.append("High disk usage")
        if len(active_tasks) > 20:
            score -= 10
            issues.append("High task backlog")

        score = max(score, 0)
        if score >= 90:
            status = "excellent"
        elif score >= 75:
            status = "good"
        elif score >= 50:
            status = "fair"
        elif score >= 25:
            status = "poor"
        else:
            status = "critical"

        return {
            "overall_status": status,
            "health_score": score,
            "issues": issues,
            "system_stats": {
                "resource_usage": resource,
                "active_processes": len(active_processes),
                "active_tasks": len(active_tasks),
                "cache": cache_stats,
                "performance_dashboard": performance,
            },
            "recommendations": _health_recommendations(issues),
        }


def _health_recommendations(issues: list[str]) -> list[str]:
    recommendations = []
    if any("CPU" in issue for issue in issues):
        recommendations.append("Reduce concurrent scans or lower scan intensity.")
    if any("memory" in issue.lower() for issue in issues):
        recommendations.append("Clear caches or stop idle long-running tasks.")
    if any("disk" in issue.lower() for issue in issues):
        recommendations.append("Archive reports and clean old workspace files.")
    if any("backlog" in issue.lower() for issue in issues):
        recommendations.append("Wait for running tasks to finish before queuing more work.")
    return recommendations


class SafeWorkspace:
    def __init__(self, base_dir: str | Path = "/tmp/proflupinmind_files"):
        self.base_dir = Path(base_dir).resolve()
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def resolve(self, path: str) -> Path:
        candidate = (self.base_dir / path).resolve()
        if self.base_dir not in candidate.parents and candidate != self.base_dir:
            raise ValueError("path escapes the ProfLupinMind workspace")
        return candidate

    def write(self, path: str, content: str, append: bool = False) -> dict[str, Any]:
        file_path = self.resolve(path)
        file_path.parent.mkdir(parents=True, exist_ok=True)
        mode = "a" if append else "w"
        with file_path.open(mode, encoding="utf-8") as handle:
            handle.write(content)
        return {"success": True, "path": str(file_path), "size": file_path.stat().st_size}

    def read(self, path: str, max_bytes: int = 20000) -> dict[str, Any]:
        file_path = self.resolve(path)
        data = file_path.read_bytes()[:max_bytes]
        return {"success": True, "path": str(file_path), "content": data.decode("utf-8", errors="replace"), "truncated": file_path.stat().st_size > max_bytes}

    def delete(self, path: str) -> dict[str, Any]:
        file_path = self.resolve(path)
        if file_path.is_dir():
            return {"success": False, "error": "directory deletion is not exposed over MCP"}
        file_path.unlink(missing_ok=True)
        return {"success": True, "path": str(file_path)}

    def list(self, path: str = ".") -> dict[str, Any]:
        dir_path = self.resolve(path)
        rows = []
        for item in sorted(dir_path.iterdir(), key=lambda p: p.name):
            rows.append({
                "name": item.name,
                "type": "directory" if item.is_dir() else "file",
                "size": item.stat().st_size,
                "modified": item.stat().st_mtime,
            })
        return {"success": True, "base_dir": str(self.base_dir), "path": str(dir_path), "files": rows}
