"""Concurrency admission for IDA's single main thread.

The server serializes tools/call, but MCP clients routinely fan out parallel
requests.  The bounded FIFO queue lets short follow-up calls wait for the
running tool instead of failing immediately.  A full queue or a queue-wait
timeout still returns a retryable busy error; resources keep the old
fail-fast path.

Loads ida_mcp/zeromcp standalone (no IDA needed).
"""
import json
import os
import sys
import threading
import time
import types
import urllib.request


# zeromcp is IDA-free: import the real subpackage (true paths, so coverage
# attributes the lines).
from _harness import real  # noqa: E402

jsonrpc = real("zeromcp.jsonrpc")
mcp = real("zeromcp.mcp")

srv = mcp.McpServer("gate-test")
assert srv.max_concurrent_tools == 1
assert srv.tool_queue_depth == 8
assert srv.tool_queue_wait_sec > 0


@srv.tool
def slow_tool() -> str:
    """Holds the main thread like a long execute_sync."""
    time.sleep(1.5)
    return "slow-done"


@srv.tool
def fast_tool() -> str:
    """Control tool."""
    return "fast"

srv.serve("127.0.0.1", 18997, background=True)
BASE = "http://127.0.0.1:18997/mcp"


def _call(name, id_=1):
    body = json.dumps({"jsonrpc": "2.0", "method": "tools/call",
                       "params": {"name": name, "arguments": {}},
                       "id": id_}).encode()
    req = urllib.request.Request(BASE, data=body,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=20) as r:
        assert r.status == 200, r.status
        return json.loads(r.read().decode())["result"]


def _cancel(id_):
    body = json.dumps({"jsonrpc": "2.0", "method": "notifications/cancelled",
                       "params": {"requestId": id_}}).encode()
    req = urllib.request.Request(BASE, data=body,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as r:
        assert r.status == 202, r.status


def _list():
    body = json.dumps({"jsonrpc": "2.0", "method": "tools/list",
                       "params": {}, "id": 2}).encode()
    req = urllib.request.Request(BASE, data=body,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read().decode())["result"]["tools"]


def _start_slow(id_=10):
    results = {}
    started = threading.Event()

    def _run():
        started.set()
        results["slow"] = _call("slow_tool", id_)

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    assert started.wait(timeout=5)
    return t, results


# --- sequential baseline ---
assert _call("fast_tool")["isError"] is False
print("sequential tools/call OK")

# --- a second call waits in the queue, then succeeds ---
t, results = _start_slow(10)
time.sleep(0.3)  # slow_tool now holds the only slot
t0 = time.monotonic()
queued = _call("fast_tool", 11)
elapsed = time.monotonic() - t0
assert queued["isError"] is False, queued
assert queued["content"][0]["text"] == "fast", queued
assert elapsed >= 0.8, elapsed  # it waited for the slow tool
t.join(timeout=15)
assert results["slow"]["isError"] is False, results["slow"]
stats = srv.get_stats()
assert stats["queue_waits"] >= 1, stats
assert stats["queue_wait_p50_ms"] is not None, stats
assert stats["queue_depth"] == 0, stats
print("concurrent tools/call queues and succeeds OK")

# --- tools/list stays ungated while a tool runs ---
t, results = _start_slow(12)
time.sleep(0.2)
tools = _list()
assert {x["name"] for x in tools} >= {"slow_tool", "fast_tool"}, tools
print("tools/list ungated during slow tool OK")
t.join(timeout=15)

# --- fail fast when the queue is disabled ---
srv.tool_queue_depth = 0
t, results = _start_slow(13)
time.sleep(0.2)
busy = _call("fast_tool", 14)
assert busy["isError"] is True, busy
assert "busy" in busy["content"][0]["text"].lower(), busy
sc = busy.get("structuredContent", {})
assert sc.get("busy") is True and sc.get("retryable") is True, busy
assert sc.get("reason") == "full", busy
t.join(timeout=15)
srv.tool_queue_depth = 8
print("queue disabled -> retryable busy OK")

# --- queue wait timeout ---
srv.tool_queue_wait_sec = 0.1
t, results = _start_slow(15)
time.sleep(0.2)
timed = _call("fast_tool", 16)
assert timed["isError"] is True, timed
sc = timed.get("structuredContent", {})
assert sc.get("busy") is True and sc.get("reason") == "timeout", timed
t.join(timeout=15)
srv.tool_queue_wait_sec = 15.0
print("queue wait timeout -> retryable busy OK")

# --- cancellation while queued: the tool must never execute ---
t, results = _start_slow(17)
time.sleep(0.2)
fast_result = {}


def _queued_fast():
    fast_result["r"] = _call("fast_tool", 18)


tq = threading.Thread(target=_queued_fast, daemon=True)
tq.start()
time.sleep(0.3)  # fast is registered and waiting in the queue
_cancel(18)
tq.join(timeout=10)
assert not tq.is_alive(), "queued call did not return after cancellation"
r = fast_result["r"]
assert r["isError"] is True, r
assert r.get("structuredContent", {}).get("cancelled") is True, r
t.join(timeout=15)
assert results["slow"]["isError"] is False, results["slow"]
print("queued call cancellation OK")

# --- escape hatch: max_concurrent_tools=0 disables the gate ---
srv.max_concurrent_tools = 0
t2, results2 = _start_slow(20)
time.sleep(0.5)
r = _call("fast_tool", 21)
assert r["isError"] is False, r
t2.join(timeout=15)
assert results2["slow"]["isError"] is False
srv.max_concurrent_tools = 1
print("gate escape hatch OK")

# --- initialize advertises the one-tool-at-a-time contract ---
req = urllib.request.Request(
    BASE,
    data=json.dumps({"jsonrpc": "2.0", "id": 30, "method": "initialize",
                     "params": {"protocolVersion": "2025-06-18",
                                "capabilities": {},
                                "clientInfo": {"name": "gate", "version": "1"}}}).encode(),
    headers={"Content-Type": "application/json"})
with urllib.request.urlopen(req, timeout=10) as r:
    init = json.loads(r.read().decode())["result"]
assert "one tools/call" in init["instructions"].lower(), init
print("initialize instructions OK")

# --- a small parallel burst is serialized, not rejected ---
burst = []


def _burst_call(i):
    burst.append(_call("fast_tool", 40 + i))


threads = [threading.Thread(target=_burst_call, args=(i,), daemon=True)
           for i in range(5)]
for th in threads:
    th.start()
for th in threads:
    th.join(timeout=15)
assert len(burst) == 5, burst
assert all(not r["isError"] for r in burst), burst
print("parallel burst admitted through the queue OK")

srv.stop()
print("ALL GATE TESTS PASSED")
