"""Transport tests: ?unsafe= / ?ext= gating over live HTTP (Lote 4).

Loads ida_mcp/zeromcp standalone from source (stdlib-only, no IDA needed),
registers one plain / one unsafe / one ext-gated tool, and asserts
tools/list + tools/call behavior for every query combination. Also covers
the Lote 1 guards (413 body limit, 403 Host/Origin).
"""
import json
import os
import sys
import types
import urllib.request
import urllib.error

# =========================================================================
# Load zeromcp standalone (no ida_mcp package import — avoids IDA deps)
# =========================================================================

HERE = os.path.dirname(os.path.abspath(__file__))
ZPKG = os.path.join(HERE, "..", "ida_mcp", "zeromcp")

_zt = types.ModuleType("zt_test_pkg")
_zt.__path__ = []
sys.modules["zt_test_pkg"] = _zt


def _load(name, filename, patch=None):
    path = os.path.join(ZPKG, filename)
    src = open(path, "r", encoding="utf-8").read()
    if patch:
        src = patch(src)
    mod = types.ModuleType(name)
    sys.modules[name] = mod
    exec(compile(src, name, "exec"), mod.__dict__)
    return mod


jsonrpc = _load("zt_test_pkg.jsonrpc", "jsonrpc.py")
mcp = _load("zt_test_pkg.mcp", "mcp.py",
            patch=lambda s: s.replace("from .jsonrpc import", "from zt_test_pkg.jsonrpc import"))

McpServer = mcp.McpServer

srv = McpServer("transport-test")


@srv.tool
def plain_tool() -> str:
    """A plain tool."""
    return "plain"


@srv.tool
def unsafe_tool() -> str:
    """An unsafe tool."""
    return "unsafe"


srv.unsafe_tools.add("unsafe_tool")


@srv.tool
def dbg_tool() -> str:
    """An extension tool."""
    return "dbg"


srv._extensions_registry.setdefault("dbg", set()).add("dbg_tool")

srv.serve("127.0.0.1", 18998, background=True)

BASE = "http://127.0.0.1:18998/mcp"


def _rpc(method, params=None, query="", headers=None):
    body = json.dumps({"jsonrpc": "2.0", "method": method,
                       "params": params or {}, "id": 1}).encode()
    req = urllib.request.Request(
        BASE + query, data=body,
        headers={"Content-Type": "application/json", **(headers or {})})
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def _list(query=""):
    st, resp = _rpc("tools/list", {}, query)
    assert st == 200, (query, st, resp)
    return {t["name"] for t in resp["result"]["tools"]}


def _call(name, query=""):
    st, resp = _rpc("tools/call",
                    {"name": name, "arguments": {}}, query)
    assert st == 200, (name, query, st, resp)
    return resp["result"]


# --- tools/list gating ---
assert _list() == {"plain_tool"}, _list()
assert _list("?unsafe=true") == {"plain_tool", "unsafe_tool"}
assert _list("?ext=dbg") == {"plain_tool", "dbg_tool"}, _list("?ext=dbg")
assert _list("?unsafe=true&ext=dbg") == {"plain_tool", "unsafe_tool", "dbg_tool"}
assert _list("?ext=nope") == {"plain_tool"}
print("tools/list gating OK")

# --- tools/call gating ---
r = _call("plain_tool")
assert r["isError"] is False, r
r = _call("unsafe_tool")
assert r["isError"] is True and "unsafe" in r["content"][0]["text"], r
r = _call("unsafe_tool", "?unsafe=true")
assert r["isError"] is False, r
r = _call("dbg_tool")
assert r["isError"] is True and "ext" in r["content"][0]["text"], r
r = _call("dbg_tool", "?ext=dbg")
# extension visible but tool is NOT unsafe -> still callable? dbg_tool here
# is not in unsafe_tools, so ext alone suffices.
assert r["isError"] is False, r
print("tools/call gating OK")

# --- unsafe + ext combined denial message precedence ---
srv.unsafe_tools.add("dbg_tool")  # like real dbg_* (both gates)
r = _call("dbg_tool", "?ext=dbg")
assert r["isError"] is True and "unsafe" in r["content"][0]["text"], r
r = _call("dbg_tool", "?unsafe=true")
assert r["isError"] is True and "ext" in r["content"][0]["text"], r
r = _call("dbg_tool", "?unsafe=true&ext=dbg")
assert r["isError"] is False, r
print("combined unsafe+ext gating OK")

# --- Lote 1 guards still hold ---
st, _ = _rpc("tools/list", {}, "", headers={"Host": "evil.example.com"})
assert st == 403, st
st, _ = _rpc("tools/list", {}, "", headers={"Origin": "https://evil.example.com"})
assert st == 403, st
big = b'{"jsonrpc":"2.0","method":"tools/list","params":{},"id":1,"pad":"'
big += b"x" * (11 * 1024 * 1024) + b'"}'
req = urllib.request.Request(BASE, data=big, headers={"Content-Type": "application/json"})
try:
    urllib.request.urlopen(req)
    status = 200
except urllib.error.HTTPError as e:
    status = e.code
except Exception as e:
    status = f"CONN:{type(e).__name__}"  # reset-before-read also proves rejection
assert status == 413 or str(status).startswith("CONN:"), status
st, resp = _rpc("tools/list", {})
assert st == 200, (st, resp)  # server survived
print("413/403 guards OK")

# --- legacy SSE transport: GET /sse -> endpoint -> POST -> message ---
import socket as _socket


def _sse_session():
    s = _socket.create_connection(("127.0.0.1", 18998), timeout=10)
    f = s.makefile("rb")
    s.sendall(b"GET /sse HTTP/1.1\r\nHost: 127.0.0.1:18998\r\n"
               b"Accept: text/event-stream\r\n\r\n")
    status = f.readline().decode()
    assert "200" in status, status
    while f.readline().strip():
        pass  # headers
    event = f.readline().decode().strip()
    data = f.readline().decode().strip()
    assert event == "event: endpoint", (event, data)
    endpoint = json.loads(data.split("data: ", 1)[1])
    assert endpoint.startswith("/sse?session="), endpoint
    return s, f, endpoint.split("session=", 1)[1]


s, f, session = _sse_session()
print("SSE endpoint event OK", session)

msg_body = json.dumps({"jsonrpc": "2.0", "method": "ping", "id": 7}).encode()
req = urllib.request.Request(
    f"http://127.0.0.1:18998/sse?session={session}",
    data=msg_body, headers={"Content-Type": "application/json"})
try:
    r = urllib.request.urlopen(req)
    assert r.status == 202, r.status
    r.read()
except urllib.error.HTTPError as e:
    raise AssertionError(f"SSE POST failed: {e.code}")
# the reply arrives on the GET stream as a message event (skip blanks)
s.settimeout(10)
lines = []
while len(lines) < 2:
    line = f.readline().decode().strip()
    if line:
        lines.append(line)
assert lines[0] == "event: message", lines
payload = json.loads(lines[1].split("data: ", 1)[1])
assert payload["result"] == {} and payload["id"] == 7, payload
print("SSE POST/message round-trip OK")

# unknown session -> 400; DELETE closes the stream
req = urllib.request.Request(
    "http://127.0.0.1:18998/sse?session=nope",
    data=msg_body, headers={"Content-Type": "application/json"})
try:
    urllib.request.urlopen(req)
    raise AssertionError("unknown session should 400")
except urllib.error.HTTPError as e:
    assert e.code == 400, e.code
req = urllib.request.Request(
    f"http://127.0.0.1:18998/sse?session={session}", method="DELETE")
with urllib.request.urlopen(req) as r:
    assert r.status == 200, r.status
s.close()
print("SSE session errors/DELETE OK")

# --- GET /mcp stays a Streamable-HTTP SSE keep-alive (200) ---
req = urllib.request.Request("http://127.0.0.1:18998/mcp",
                             headers={"Accept": "text/event-stream"})
with urllib.request.urlopen(req, timeout=10) as r:
    assert r.status == 200, r.status
    assert r.headers.get_content_type() == "text/event-stream", r.headers
    first = r.fp.readline()
    assert b"connected" in first, first
print("GET /mcp SSE keep-alive OK")

# --- chunked + gzip bodies ---
import http.client as _http

conn = _http.HTTPConnection("127.0.0.1", 18998, timeout=10)
conn.putrequest("POST", "/mcp")
conn.putheader("Content-Type", "application/json")
conn.putheader("Transfer-Encoding", "chunked")
conn.endheaders()
chunk = json.dumps({"jsonrpc": "2.0", "method": "ping", "id": 9}).encode()
conn.send(f"{len(chunk):X}\r\n".encode() + chunk + b"\r\n0\r\n\r\n")
resp = conn.getresponse()
assert resp.status == 200, resp.status
assert json.loads(resp.read())["result"] == {}, resp.read()[:50]
conn.close()
print("chunked POST OK")

import gzip as _gzip
zbody = _gzip.compress(
    json.dumps({"jsonrpc": "2.0", "method": "ping", "id": 10}).encode())
req = urllib.request.Request(
    BASE, data=zbody,
    headers={"Content-Type": "application/json", "Content-Encoding": "gzip"})
with urllib.request.urlopen(req) as r:
    assert json.loads(r.read())["result"] == {}, "gzip body failed"
print("gzip POST OK")

# --- profile gating (thread-local injection; file loading covered by inventory) ---
mcp._request_profile.current = ("triage", {"plain_tool"})
assert {t["name"] for t in srv._mcp_tools_list()["tools"]} == {"plain_tool"}
mcp._unsafe_per_thread.allowed = True  # isolate the profile gate from unsafe
r = srv._mcp_tools_call("unsafe_tool", {})
assert r["isError"] is True and "profile 'triage'" in r["content"][0]["text"], r
r = srv._mcp_tools_call("plain_tool", {})
assert r["isError"] is False, r
mcp._request_profile.current = (None, None)
mcp._unsafe_per_thread.allowed = False
assert {t["name"] for t in srv._mcp_tools_list()["tools"]} == {"plain_tool"}
print("profile gating OK")

srv.stop()
print("ALL TRANSPORT TESTS PASSED")
