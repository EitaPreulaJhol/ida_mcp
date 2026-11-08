"""Regression tests for transport robustness fixes. Pure zeromcp, no IDA.

Covers:
  1. the unraisable hook forwards non-disconnect errors to the PREVIOUS hook
     (it used to call itself -> RecursionError) and is installed by serve(),
     restored by stop(), and idempotent across restarts;
  3. resources/read shares the tools/call concurrency gate, output cap,
     metrics, and its backing tool's access gates (profile/unsafe/ext);
  4. metrics + audit are recorded even with the gate disabled, the audit
     carries the error text, and max_concurrent_tools=N really admits N;
  5. notifications/cancelled is scoped to the caller's session, so one
     client cannot cancel another client's request with the same id;
  6. initialize negotiates protocolVersion and malformed JSON gets -32700;
  9. bound off-loopback with auth on, every request needs the token.
"""
import json
import os
import sys
import tempfile
import threading
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
PKG = os.path.join(HERE, "..", "ida_mcp")
if PKG not in sys.path:
    sys.path.insert(0, PKG)

from zeromcp import McpServer, get_current_cancel_event  # noqa: E402

failures = []


def check(cond, msg):
    print(("  ok: " if cond else "  FAIL: ") + msg)
    if not cond:
        failures.append(msg)


PORT = 13431
BASE = f"http://127.0.0.1:{PORT}/mcp"


def post(payload, query="", headers=None):
    req = urllib.request.Request(
        BASE + query, data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", **(headers or {})})
    with urllib.request.urlopen(req, timeout=10) as r:
        body = r.read()
        return json.loads(body) if body else None


def call(name, args=None, query="", headers=None, rid=1):
    return post({"jsonrpc": "2.0", "id": rid, "method": "tools/call",
                 "params": {"name": name, "arguments": args or {}}}, query, headers)


def read_resource(uri, query=""):
    return post({"jsonrpc": "2.0", "id": 7, "method": "resources/read",
                 "params": {"uri": uri}}, query)


def list_resources(query=""):
    res = post({"jsonrpc": "2.0", "id": 8, "method": "resources/list"}, query)
    return {r["uri"] for r in res["result"]["resources"]}


# ===================================================================
# 1. unraisable hook
# ===================================================================
captured = []


def capture_hook(unraisable):
    captured.append(type(unraisable.exc_value).__name__)


sys.unraisablehook = capture_hook


class _RaisesInDel:
    def __init__(self, exc):
        self.exc = exc

    def __del__(self):
        raise self.exc


srv = McpServer("robustness-test")
AUDIT = os.path.join(tempfile.mkdtemp(prefix="idamcp_robust_"), "audit.jsonl")
srv.audit_path = AUDIT

release = threading.Event()


@srv.tool
def fast() -> str:
    """Returns immediately."""
    return "fast"


@srv.tool
def slow() -> str:
    """Blocks until released (holds a gate slot)."""
    release.wait(10)
    return "slow"


@srv.tool
def bad_mutation() -> str:
    """Unsafe tool that fails with a structured error."""
    return json.dumps({"error": "refusing to patch: segment is read-only"})


@srv.tool
def cancellable() -> str:
    """Waits for its own cancel event (request-scoped)."""
    ev = get_current_cancel_event()
    if ev is None:
        return "no-cancel-event"
    return "cancelled" if ev.wait(10) else "timeout"


@srv.tool
def secret_tool() -> str:
    """Unsafe tool backing a resource."""
    return "secret"


srv.unsafe_tools.update({"bad_mutation", "secret_tool"})


@srv.resource("demo://open", mime="text/plain", tool="fast")
def open_resource():
    """Backed by a safe tool."""
    return "open data"


@srv.resource("demo://secret", mime="text/plain", tool="secret_tool")
def secret_resource():
    """Backed by an unsafe tool -> gated like it."""
    return "secret data"


@srv.resource("demo://big", mime="text/plain")
def big_resource():
    """Large payload to exercise the output cap."""
    return "x" * 5000


check(sys.unraisablehook is capture_hook, "importing zeromcp leaves the unraisable hook alone")
srv.serve("127.0.0.1", PORT, background=True)
time.sleep(0.3)
check(sys.unraisablehook is not capture_hook, "serve() installs the quiet hook")

_RaisesInDel(ValueError("boom"))
_RaisesInDel(BrokenPipeError("peer gone"))
check(captured == ["ValueError"],
      f"non-disconnect error forwarded once, disconnect silenced (got {captured})")

srv.stop()
check(sys.unraisablehook is capture_hook, "stop() restores the previous hook")
srv.serve("127.0.0.1", PORT, background=True)
srv.serve("127.0.0.1", PORT, background=True)  # already running: no-op
time.sleep(0.3)
captured.clear()
_RaisesInDel(KeyError("k"))
check(captured == ["KeyError"], "restart does not chain duplicate hooks")

# ===================================================================
# 3. resources/read: gate, output cap, backing-tool access, metrics
# ===================================================================
check(json.loads(json.dumps(read_resource("demo://open")))["result"]["contents"][0]["text"]
      == "open data", "resource readable when idle")

t = threading.Thread(target=call, args=("slow",), daemon=True)
t.start()
time.sleep(0.3)
busy = read_resource("demo://open")
check("error" in busy and "busy" in busy["error"]["message"].lower(),
      "resources/read refused while a tool holds the gate")
release.set()
t.join(5)
release.clear()
check("result" in read_resource("demo://open"), "resource readable again after the tool ends")

check("demo://secret" not in list_resources(), "unsafe-backed resource hidden without ?unsafe")
denied = read_resource("demo://secret")
check("error" in denied and "unsafe" in denied["error"]["message"],
      "unsafe-backed resource refused without ?unsafe")
check("demo://secret" in list_resources("?unsafe=true"), "listed with ?unsafe=true")
check("result" in read_resource("demo://secret", "?unsafe=true"), "readable with ?unsafe=true")

srv.max_output_chars = 1000
too_big = read_resource("demo://big")
check("error" in too_big and "too large" in too_big["error"]["message"].lower(),
      "resources/read honours max_output_chars")
srv.max_output_chars = 512 * 1024

stat_names = {s["name"] for s in srv.get_stats()["tools"]}
check("resource:demo://open" in stat_names, "resource reads show up in metrics")

# ===================================================================
# 4. metrics/audit with the gate off; audit error text; N-slot gate
# ===================================================================
srv.max_concurrent_tools = 0
before = {s["name"]: s["calls"] for s in srv.get_stats()["tools"]}.get("fast", 0)
call("fast")
after = {s["name"]: s["calls"] for s in srv.get_stats()["tools"]}.get("fast", 0)
check(after == before + 1, "metrics recorded with the gate disabled")
r = call("bad_mutation", query="?unsafe=true")
check(r["result"]["isError"] is True, "structured error -> isError")
time.sleep(0.1)
with open(AUDIT, encoding="utf-8") as f:
    recs = [json.loads(ln) for ln in f if ln.strip()]
bad = [x for x in recs if x["tool"] == "bad_mutation"]
check(len(bad) == 1, "unsafe call audited with the gate disabled")
check(bool(bad) and bad[0]["ok"] is False
      and "read-only" in bad[0].get("error", ""), "audit record carries the error text")

srv.max_concurrent_tools = 2
results = []
threads = [threading.Thread(target=lambda: results.append(call("slow")), daemon=True)
           for _ in range(2)]
for th in threads:
    th.start()
time.sleep(0.3)
third = call("fast")
check(third["result"]["isError"] is True
      and third["result"].get("structuredContent", {}).get("busy") is True,
      "third call busy when 2 slots are taken")
release.set()
for th in threads:
    th.join(5)
release.clear()
check(len(results) == 2 and all(not x["result"]["isError"] for x in results),
      "max_concurrent_tools=2 admits two concurrent calls")
srv.max_concurrent_tools = 1

# ===================================================================
# 5. cancellation is scoped to the session
# ===================================================================
outcome = []
SA = {"Mcp-Session-Id": "session-A"}
SB = {"Mcp-Session-Id": "session-B"}


def cancel(rid, headers):
    post({"jsonrpc": "2.0", "method": "notifications/cancelled",
          "params": {"requestId": rid}}, headers=headers)


th = threading.Thread(
    target=lambda: outcome.append(call("cancellable", headers=SA, rid=1)), daemon=True)
th.start()
time.sleep(0.3)
cancel(1, SB)  # other session, same id: must not cancel
cancel(1, {})  # session-less caller: must not cancel either
time.sleep(0.3)
check(th.is_alive(), "cancel from another session is ignored")
cancel(1, SA)
th.join(5)
check(bool(outcome) and outcome[0]["result"]["content"][0]["text"] == "cancelled",
      "cancel from the owning session cancels")

# ===================================================================
# 6. protocol version negotiation + JSON parse errors
# ===================================================================


def initialize(version):
    params = {"capabilities": {}, "clientInfo": {"name": "t", "version": "1"}}
    if version is not None:
        params["protocolVersion"] = version
    return post({"jsonrpc": "2.0", "id": 9, "method": "initialize", "params": params})


check(initialize("2025-03-26")["result"]["protocolVersion"] == "2025-03-26",
      "supported protocol version is echoed")
check(initialize("1999-01-01")["result"]["protocolVersion"] == "2025-06-18",
      "unknown protocol version -> server's preferred version")
check(initialize(None)["result"]["protocolVersion"] == "2025-06-18",
      "missing protocol version -> preferred version (no traceback)")


def post_raw(data):
    req = urllib.request.Request(BASE, data=data,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read())


bad = post_raw(b'{"jsonrpc": "2.0", "id": 1, "method": ')
check(bad.get("error", {}).get("code") == -32700, "malformed JSON -> -32700 parse error")
bad_utf8 = post_raw(b'\xff\xfe{}')
check(bad_utf8.get("error", {}).get("code") == -32700, "undecodable body -> -32700")
check(post_raw(b"[]").get("error", {}).get("code") == -32600,
      "well-formed non-object stays -32600 invalid request")

srv.stop()

# ===================================================================
# 9. off-loopback bind: every request needs the token (when auth is on)
# ===================================================================
import urllib.error  # noqa: E402

mcp_mod = sys.modules["zeromcp.mcp"]
PORT2 = PORT + 1
BASE2 = f"http://127.0.0.1:{PORT2}/mcp"
srv2 = McpServer("offloopback-test")


@srv2.tool
def harmless() -> str:
    """Read-only tool."""
    return "ok"


def status_of(method="POST", query="", headers=None):
    data = (json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                        "params": {"name": "harmless", "arguments": {}}}).encode()
            if method == "POST" else None)
    req = urllib.request.Request(BASE2 + query, data=data, method=method,
                                 headers={"Content-Type": "application/json",
                                          **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers)


srv2.auth_token = "s3cret"
srv2.serve("127.0.0.1", PORT2, background=True)
time.sleep(0.3)
check(status_of()[0] == 200, "loopback bind: read-only call needs no token (unchanged)")

_real_is_loopback = mcp_mod._is_loopback_host
mcp_mod._is_loopback_host = lambda host: False  # pretend we bound 0.0.0.0
try:
    check(status_of()[0] == 401, "off-loopback: request without token -> 401")
    check(status_of(headers={"X-IDA-MCP-Token": "wrong"})[0] == 401,
          "off-loopback: wrong token -> 401")
    check(status_of(headers={"X-IDA-MCP-Token": "s3cret"})[0] == 200,
          "off-loopback: header token accepted")
    check(status_of(query="?token=s3cret")[0] == 200, "off-loopback: ?token= accepted")
    code, hdrs = status_of("OPTIONS", headers={"Origin": "http://localhost:5173"})
    check(code == 204, "off-loopback: CORS preflight needs no token")
    allow = hdrs.get("Access-Control-Allow-Headers", "")
    check("X-IDA-MCP-Token" in allow, "preflight allows the X-IDA-MCP-Token header")
    srv2.auth_token = None  # IDA_MCP_NO_AUTH
    check(status_of()[0] == 200, "off-loopback with auth disabled: no token needed")
finally:
    mcp_mod._is_loopback_host = _real_is_loopback
    srv2.stop()

print("\n" + "=" * 50)
if failures:
    print(f"FAILED ({len(failures)}): " + "; ".join(failures))
    sys.exit(1)
print("ALL ROBUSTNESS TESTS PASSED")
