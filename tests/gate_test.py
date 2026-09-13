"""Concurrency gate: second tools/call while one runs must fail fast (Fase 2).

IDA tools serialize on the main thread, so stacking concurrent calls only
extends the UI freeze. The gate returns a retryable isError instead.

Loads ida_mcp/zeromcp standalone (no IDA needed).
"""
import json
import os
import sys
import threading
import types
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ZPKG = os.path.join(HERE, "..", "ida_mcp", "zeromcp")

_zt = types.ModuleType("zt_gate_pkg")
_zt.__path__ = []
sys.modules["zt_gate_pkg"] = _zt


def _load(name, filename, patch=None):
    path = os.path.join(ZPKG, filename)
    src = open(path, "r", encoding="utf-8").read()
    if patch:
        src = patch(src)
    mod = types.ModuleType(name)
    sys.modules[name] = mod
    exec(compile(src, name, "exec"), mod.__dict__)
    return mod


jsonrpc = _load("zt_gate_pkg.jsonrpc", "jsonrpc.py")
mcp = _load("zt_gate_pkg.mcp", "mcp.py",
            patch=lambda s: s.replace("from .jsonrpc import", "from zt_gate_pkg.jsonrpc import"))

srv = mcp.McpServer("gate-test")
assert srv.max_concurrent_tools == 1


@srv.tool
def slow_tool() -> str:
    """Holds the gate like a long execute_sync."""
    import time as _t
    _t.sleep(1.5)
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
    with urllib.request.urlopen(req, timeout=15) as r:
        assert r.status == 200, r.status
        return json.loads(r.read().decode())["result"]


def _list():
    body = json.dumps({"jsonrpc": "2.0", "method": "tools/list",
                       "params": {}, "id": 2}).encode()
    req = urllib.request.Request(BASE, data=body,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read().decode())["result"]["tools"]


# --- sequential baseline ---
assert _call("fast_tool")["isError"] is False
print("sequential tools/call OK")

# --- concurrent: slow in background, fast must fail fast with busy ---
results = {}
started = threading.Event()


def _run_slow():
    started.set()
    results["slow"] = _call("slow_tool", 10)


t = threading.Thread(target=_run_slow, daemon=True)
t.start()
assert started.wait(timeout=5)
import time as _time
_time.sleep(0.5)  # let slow_tool acquire the gate

busy = _call("fast_tool", 11)
assert busy["isError"] is True, busy
assert "busy" in busy["content"][0]["text"].lower(), busy
assert busy.get("structuredContent", {}).get("busy") is True, busy
print("concurrent tools/call fails fast with busy OK")

# --- tools/list stays ungated while a tool runs ---
tools = _list()
assert {x["name"] for x in tools} >= {"slow_tool", "fast_tool"}, tools
print("tools/list ungated during busy OK")

t.join(timeout=15)
assert results["slow"]["isError"] is False, results["slow"]
print("gate released after tool finishes OK")

# --- after release, calls work again ---
assert _call("fast_tool", 12)["isError"] is False
print("post-release tools/call OK")

# --- escape hatch: max_concurrent_tools=0 disables the gate ---
srv.max_concurrent_tools = 0
results2 = {}


def _run_slow2():
    results2["slow"] = _call("slow_tool", 20)


t2 = threading.Thread(target=_run_slow2, daemon=True)
t2.start()
_time.sleep(0.5)
# With the gate disabled the second call queues behind the first instead of
# failing: it must eventually succeed (slower, legacy behavior).
r = _call("fast_tool", 21)
assert r["isError"] is False, r
t2.join(timeout=15)
assert results2["slow"]["isError"] is False
srv.max_concurrent_tools = 1
print("gate escape hatch OK")

srv.stop()
print("ALL GATE TESTS PASSED")
