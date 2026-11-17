"""Thread-safe, bounded in-memory MCP server metrics.

This module owns metric counters and rolling timing samples only. It has no
HTTP, IDA, registry, or audit dependencies; the server supplies the current
queue depth when it requests a JSON-able snapshot.
"""
from collections import deque
import threading
import time
from typing import Any


class McpMetrics:
    """Bounded per-method and admission-queue counters for one server."""

    def __init__(self, *, sample_window: int = 200) -> None:
        window = max(1, int(sample_window))
        self._stats_lock = threading.Lock()
        self._stats: dict[str, dict[str, Any]] = {}
        self._totals = {"calls": 0, "errors": 0, "busy": 0}
        self._started = time.monotonic()

        self._queue_lock = threading.Lock()
        self._queue_wait_ms: deque[float] = deque(maxlen=window)
        self._queue_stats = {"waits": 0, "timeouts": 0, "full": 0,
                             "cancelled": 0}
        self._sample_window = window

    def record_queue(self, waited_ms: float, reason: str) -> None:
        """Record queue wait/rejection counters; metric failure is non-fatal."""
        try:
            with self._queue_lock:
                if waited_ms > 0:
                    self._queue_wait_ms.append(float(waited_ms))
                if reason == "admitted" and waited_ms > 0:
                    self._queue_stats["waits"] += 1
                elif reason == "timeout":
                    self._queue_stats["timeouts"] += 1
                elif reason == "full":
                    self._queue_stats["full"] += 1
                elif reason == "cancelled":
                    self._queue_stats["cancelled"] += 1
        except Exception:
            pass

    def record_call(
        self,
        name: str,
        *,
        errored: bool = False,
        busy: bool = False,
        duration_ms: float | None = None,
    ) -> None:
        """Update per-method counters; metrics never interrupt dispatch."""
        try:
            with self._stats_lock:
                stat = self._stats.get(name)
                if stat is None:
                    stat = {"calls": 0, "errors": 0, "busy": 0,
                            "durations": deque(maxlen=self._sample_window)}
                    self._stats[name] = stat
                if busy:
                    stat["busy"] += 1
                    self._totals["busy"] += 1
                    return
                stat["calls"] += 1
                self._totals["calls"] += 1
                if errored:
                    stat["errors"] += 1
                    self._totals["errors"] += 1
                if duration_ms is not None:
                    stat["durations"].append(float(duration_ms))
        except Exception:
            pass

    def snapshot(self, *, top: int = 25, queue_depth: int = 0) -> dict[str, Any]:
        """Return bounded JSON-able totals and per-method timing statistics."""
        try:
            with self._stats_lock:
                items = []
                for name, stat in self._stats.items():
                    durations = sorted(stat["durations"])
                    items.append({
                        "name": name,
                        "calls": stat["calls"],
                        "errors": stat["errors"],
                        "busy": stat["busy"],
                        "p50_ms": self._percentile(durations, 50),
                        "p95_ms": self._percentile(durations, 95),
                        "max_ms": round(durations[-1], 1) if durations else None,
                    })
                totals = dict(self._totals)
                uptime = round(time.monotonic() - self._started, 1)
        except Exception:
            return {"error": "stats_unavailable"}

        try:
            with self._queue_lock:
                queue_waits = sorted(self._queue_wait_ms)
                queue_stats = dict(self._queue_stats)
        except Exception:
            return {"error": "stats_unavailable"}

        items.sort(key=lambda item: item["calls"], reverse=True)
        return {
            "uptime_sec": uptime,
            "total_calls": totals["calls"],
            "total_errors": totals["errors"],
            "total_busy": totals["busy"],
            "queue_depth": max(0, int(queue_depth)),
            "queue_waits": queue_stats["waits"],
            "queue_wait_p50_ms": self._percentile(queue_waits, 50),
            "queue_wait_p95_ms": self._percentile(queue_waits, 95),
            "queue_timeouts": queue_stats["timeouts"],
            "queue_full": queue_stats["full"],
            "queue_cancelled": queue_stats["cancelled"],
            "tools": items[:top] if top else items,
        }

    @staticmethod
    def _percentile(sorted_values: list[float], percentile: int) -> float | None:
        if not sorted_values:
            return None
        index = min(len(sorted_values) - 1,
                    int(round((percentile / 100.0) * (len(sorted_values) - 1))))
        return round(sorted_values[index], 1)
