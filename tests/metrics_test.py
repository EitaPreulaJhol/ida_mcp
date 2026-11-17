"""Contract tests for the isolated, bounded MCP metrics collector."""
import os
import sys
import threading

HERE = os.path.dirname(os.path.abspath(__file__))
PKG = os.path.join(HERE, "..", "ida_mcp")
if PKG not in sys.path:
    sys.path.insert(0, PKG)

from zeromcp.metrics import McpMetrics  # noqa: E402

metrics = McpMetrics(sample_window=3)
initial = metrics.snapshot(queue_depth=2)
assert initial["total_calls"] == 0 and initial["queue_depth"] == 2, initial
assert initial["queue_wait_p50_ms"] is None and initial["tools"] == [], initial

metrics.record_call("work", duration_ms=1)
metrics.record_call("work", duration_ms=2)
metrics.record_call("work", duration_ms=3)
metrics.record_call("work", duration_ms=4)
metrics.record_call("failed", errored=True, duration_ms=7)
metrics.record_call("rejected", busy=True)
metrics.record_queue(0, "admitted")
metrics.record_queue(1, "admitted")
metrics.record_queue(2, "admitted")
metrics.record_queue(3, "admitted")
metrics.record_queue(4, "admitted")
metrics.record_queue(5, "timeout")
metrics.record_queue(0, "full")
metrics.record_queue(0, "cancelled")

snapshot = metrics.snapshot(top=2, queue_depth=4)
by_name = {item["name"]: item for item in snapshot["tools"]}
assert snapshot["total_calls"] == 5, snapshot
assert snapshot["total_errors"] == 1 and snapshot["total_busy"] == 1, snapshot
assert snapshot["queue_depth"] == 4, snapshot
assert snapshot["queue_waits"] == 4, snapshot
assert snapshot["queue_timeouts"] == 1 and snapshot["queue_full"] == 1, snapshot
assert snapshot["queue_cancelled"] == 1, snapshot
assert snapshot["queue_wait_p50_ms"] == 4.0, snapshot
assert snapshot["queue_wait_p95_ms"] == 5.0, snapshot
assert by_name["work"]["calls"] == 4, by_name
assert by_name["work"]["p50_ms"] == 3.0 and by_name["work"]["max_ms"] == 4.0, by_name
assert by_name["failed"]["errors"] == 1, by_name
assert "rejected" not in by_name, by_name  # top=2 sorts by executed calls
all_by_name = {item["name"]: item for item in metrics.snapshot(top=0)["tools"]}
assert all_by_name["rejected"]["busy"] == 1, all_by_name
assert all_by_name["rejected"]["calls"] == 0, all_by_name
print("metrics counters, bounded samples, percentiles and top-N OK")

# Concurrent producers must not lose increments or corrupt the rolling sample.
concurrent = McpMetrics(sample_window=32)
workers = 8
calls_per_worker = 250

def record_many():
    for _ in range(calls_per_worker):
        concurrent.record_call("parallel", duration_ms=1.0)
        concurrent.record_queue(1.0, "admitted")

threads = [threading.Thread(target=record_many) for _ in range(workers)]
for thread in threads:
    thread.start()
for thread in threads:
    thread.join()
parallel = concurrent.snapshot()
assert parallel["total_calls"] == workers * calls_per_worker, parallel
assert parallel["queue_waits"] == workers * calls_per_worker, parallel
assert parallel["queue_wait_p50_ms"] == 1.0, parallel
assert parallel["tools"][0]["calls"] == workers * calls_per_worker, parallel
print("metrics concurrent updates OK")
