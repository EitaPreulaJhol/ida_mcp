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


# zeromcp is IDA-free: import the real subpackage (true paths, so coverage
# attributes the lines).
from _harness import real  # noqa: E402

jsonrpc = real("zeromcp.jsonrpc")
mcp = real("zeromcp.mcp")

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


def _call(name, query="", arguments=None):
    st, resp = _rpc("tools/call",
                    {"name": name, "arguments": arguments or {}}, query)
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

# --- auth token gating (item 5): the unsafe surface requires a valid token ---
srv.auth_token = "s3cr3t"
# ?unsafe=true without a token no longer lists or runs unsafe tools
assert "unsafe_tool" not in _list("?unsafe=true"), _list("?unsafe=true")
r = _call("unsafe_tool", "?unsafe=true")
assert r["isError"] is True and "token" in r["content"][0]["text"], r
# correct token via ?token= -> listed and callable
assert "unsafe_tool" in _list("?unsafe=true&token=s3cr3t")
r = _call("unsafe_tool", "?unsafe=true&token=s3cr3t")
assert r["isError"] is False and r["content"][0]["text"] == "unsafe", r
# wrong token -> refused with a token hint
r = _call("unsafe_tool", "?unsafe=true&token=nope")
assert r["isError"] is True and "token" in r["content"][0]["text"], r
# correct token via the X-IDA-MCP-Token header
st, resp = _rpc("tools/call", {"name": "unsafe_tool", "arguments": {}},
                "?unsafe=true", headers={"X-IDA-MCP-Token": "s3cr3t"})
assert resp["result"]["isError"] is False, resp
# read-only tools stay reachable without a token
assert "plain_tool" in _list(""), _list("")
assert _call("plain_tool", "")["isError"] is False
srv.auth_token = None  # restore open mode for the remaining assertions
print("auth token gating OK")

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
    raise AssertionError(f"SSE POST failed: {e.code}") from e
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

# negative / non-hex chunk sizes are malformed framing -> 400 (a "-1" used
# to become rfile.read(-1) and buffer the stream past post_body_limit)
for bad_size in (b"-1", b"+5", b"0x5", b"zz"):
    conn = _http.HTTPConnection("127.0.0.1", 18998, timeout=10)
    conn.putrequest("POST", "/mcp")
    conn.putheader("Content-Type", "application/json")
    conn.putheader("Transfer-Encoding", "chunked")
    conn.endheaders()
    conn.send(bad_size + b"\r\n" + b"A" * 4096)
    resp = conn.getresponse()
    assert resp.status == 400, (bad_size, resp.status)
    conn.close()
print("malformed chunk size -> 400 OK")

# gzip bomb: small compressed body that inflates past the limit -> 413
bomb = _gzip.compress(b'{"pad":"' + b"0" * (11 * 1024 * 1024) + b'"}')
assert len(bomb) < 1024 * 1024, len(bomb)
for enc, data in (("gzip", bomb),
                  ("deflate", __import__("zlib").compress(_gzip.decompress(bomb)))):
    req = urllib.request.Request(
        BASE, data=data,
        headers={"Content-Type": "application/json", "Content-Encoding": enc})
    try:
        urllib.request.urlopen(req)
        raise AssertionError(f"{enc} bomb should 413")
    except urllib.error.HTTPError as e:
        assert e.code == 413, (enc, e.code)
st, resp = _rpc("tools/list", {})
assert st == 200, (st, resp)
print("decompression bomb -> 413 OK")

# JSON-RPC batch array -> invalid-request error, not a dropped connection
req = urllib.request.Request(
    BASE, data=b'[{"jsonrpc":"2.0","method":"ping","id":1}]',
    headers={"Content-Type": "application/json"})
with urllib.request.urlopen(req, timeout=10) as r:
    assert json.loads(r.read())["error"]["code"] == -32600
print("batch array -> -32600 OK")

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

# --- tools/call coerces stringified scalars to the annotated types ---
# Registered here (not up top) because the gating assertions above compare
# against an exact tool set.
@srv.tool
def num_tool(size: int = 64, ratio: float = 1.0, flag: bool = False, tag: str = "") -> str:
    """Echoes the runtime types of its scalar arguments."""
    return (f"size={type(size).__name__}:{size} ratio={type(ratio).__name__}:{ratio} "
            f"flag={type(flag).__name__}:{flag} tag={type(tag).__name__}:{tag}")


def _num_text(arguments):
    return _call("num_tool", arguments=arguments)["content"][0]["text"]


text = _num_text({"size": "16", "ratio": "2.5", "flag": "TRUE", "tag": "7"})
assert "size=int:16" in text, text
assert "ratio=float:2.5" in text, text
assert "flag=bool:True" in text, text
assert "tag=str:7" in text, text  # str parameters are never coerced
print("tools/call scalar coercion OK")

text = _num_text({"size": 8, "flag": False})
assert "size=int:8" in text and "flag=bool:False" in text, text

# unparsable strings stay strings, so the tool reports its own error
text = _num_text({"size": "abc"})
assert "size=str:abc" in text, text
print("tools/call coercion leaves bad input alone OK")

# --- MCP tool annotations (P2): derived from the unsafe gating set -------
# The schema (and its hints) is cached per tool on first use; the rest of this
# harness mutates unsafe_tools at runtime, so drop the cache first.
srv._schema_cache.clear()
st, resp = _rpc("tools/list", {}, "?unsafe=true&ext=dbg")
assert st == 200, (st, resp)
by_name = {t["name"]: t for t in resp["result"]["tools"]}
plain_ann = by_name["plain_tool"]["annotations"]
assert plain_ann["readOnlyHint"] is True, plain_ann
assert plain_ann["destructiveHint"] is False, plain_ann
assert plain_ann["idempotentHint"] is True, plain_ann
unsafe_ann = by_name["unsafe_tool"]["annotations"]
assert unsafe_ann["readOnlyHint"] is False, unsafe_ann
assert unsafe_ann["destructiveHint"] is True, unsafe_ann
assert unsafe_ann["idempotentHint"] is False, unsafe_ann
assert by_name["dbg_tool"]["annotations"]["readOnlyHint"] is False
assert plain_ann["openWorldHint"] is False, plain_ann
print("tools/list annotations OK")


# --- deprecated 'count' argument is mapped to 'limit' (P2) ---------------
@srv.tool
def page_tool(limit: int = 10) -> str:
    """A paginated tool."""
    return json.dumps({"limit": limit})


@srv.tool
def counter_tool(count: int = 1) -> str:
    """A tool with a real count parameter."""
    return json.dumps({"count": count})


r = _call("page_tool", "", {"count": 3})
assert r["isError"] is False, r
assert json.loads(r["content"][0]["text"])["limit"] == 3, r

r = _call("page_tool", "", {"limit": 7})
assert json.loads(r["content"][0]["text"])["limit"] == 7, r

r = _call("page_tool", "", {"limit": 7, "count": 3})
assert json.loads(r["content"][0]["text"])["limit"] == 7, r  # canonical wins

r = _call("counter_tool", "", {"count": 4})
assert r["isError"] is False, r
assert json.loads(r["content"][0]["text"])["count"] == 4, r
print("tools/call legacy count alias OK")

srv.stop()
print("ALL TRANSPORT TESTS PASSED")
