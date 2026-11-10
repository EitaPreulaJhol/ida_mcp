"""MCP session enforcement (plan 15, item 15.1).

The server issues an ``Mcp-Session-Id`` on ``initialize`` and tracks it, but
used to accept *any* id: a stale one still reached tools, ``DELETE`` closed
nothing, and an expired id was indistinguishable from a live one. The
Streamable HTTP spec says a server that issues session ids MUST answer 404 for
an id it does not know -- that is how a client learns to re-initialize.

Requests WITHOUT an id keep working (the INSTALL.md curl examples, stateless
clients), so enforcement is "if you send one, it must be real".

Runs over live HTTP (pure zeromcp, no IDA).
"""
import json
import sys
import time
import urllib.error
import urllib.request

from _harness import real  # noqa: E402

jsonrpc = real("zeromcp.jsonrpc")
mcp = real("zeromcp.mcp")

srv = mcp.McpServer("session-test")


@srv.tool
def ping_ok() -> str:
    """A tool that needs no IDA."""
    return "pong"


srv.serve("127.0.0.1", 18995, background=True)
BASE = "http://127.0.0.1:18995/mcp"

INIT = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                   "clientInfo": {"name": "session-test", "version": "1"}}}
PING = {"jsonrpc": "2.0", "id": 2, "method": "ping"}


def _request(payload, sid=None, method="POST"):
    """Returns (status, session_id_header_or_None, body_text_or_object)."""
    data = None
    headers = {"Content-Type": "application/json"}
    if payload is not None:
        data = json.dumps(payload).encode()
    if sid:
        headers["Mcp-Session-Id"] = sid
    req = urllib.request.Request(BASE, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            raw = r.read()
            body = json.loads(raw) if raw else None
            return r.status, r.headers.get("Mcp-Session-Id"), body
    except urllib.error.HTTPError as e:
        return e.code, e.headers.get("Mcp-Session-Id"), e.read().decode(errors="replace")


# 1) initialize issues an id
status, sid, body = _request(INIT)
assert status == 200, (status, body)
assert sid, f"initialize must return Mcp-Session-Id, headers={sid!r}"
assert body["result"]["serverInfo"], body
print("initialize issues a session id OK")

# 2) a known id is accepted and echoed
status, echoed, body = _request(PING, sid)
assert status == 200 and body["result"] == {}, (status, body)
assert echoed == sid, (echoed, sid)
print("known session id accepted + echoed OK")

# 3) an unknown id is rejected (this used to reach the tool)
status, _, body = _request(PING, "deadbeef")
assert status == 404, (status, body)
print("unknown session id -> 404 OK")

# 4) no id at all still works (stateless / curl examples)
status, _, body = _request(PING)
assert status == 200 and body["result"] == {}, (status, body)
print("request without a session id still works OK")

# 5) initialize with a stale id establishes a fresh session (a client that
#    cached an id across an IDA restart must be able to recover)
status, new_sid, body = _request(INIT, "deadbeef")
assert status == 200, (status, body)
assert new_sid and new_sid != "deadbeef", new_sid
print("initialize replaces a stale id OK")

# 6) DELETE terminates the session, and the id stops working
status, _, _ = _request(None, new_sid, method="DELETE")
assert status == 200, status
status, _, body = _request(PING, new_sid)
assert status == 404, (status, body)
print("DELETE terminates the session OK")

# 7) DELETE with an unknown id is a 404, without an id a harmless 200
status, _, _ = _request(None, "deadbeef", method="DELETE")
assert status == 404, status
status, _, _ = _request(None, method="DELETE")
assert status == 200, status
print("DELETE unknown/no id OK")

# 8) the GET stream (server -> client notifications) is validated too
try:
    req = urllib.request.Request(BASE, headers={"Mcp-Session-Id": "deadbeef"})
    with urllib.request.urlopen(req, timeout=5) as r:
        status = r.status
except urllib.error.HTTPError as e:
    status = e.code
assert status == 404, status
print("GET stream with an unknown id -> 404 OK")

# 9) an expired id is rejected like an unknown one
status, exp_sid, _ = _request(INIT)
assert status == 200 and exp_sid, (status, exp_sid)
srv.http_session_ttl_sec = 0.05
time.sleep(0.2)
status, _, body = _request(PING, exp_sid)
assert status == 404, (status, body)
print("expired session id -> 404 OK")

print("ALL SESSION TESTS PASSED")
