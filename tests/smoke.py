import json
import os
import sys
import time
import urllib.request
from typing import Annotated, Literal, Optional

# Make the vendored zeromcp package importable without loading the IDA-dependent
# ida_mcp package __init__.
HERE = os.path.dirname(os.path.abspath(__file__))
PKG = os.path.join(HERE, "..", "ida_mcp")
if PKG not in sys.path:
    sys.path.insert(0, PKG)

from zeromcp import McpServer

server = McpServer("test")
calls = []


@server.tool
def add(a: int, b: int) -> int:
    """Add two numbers."""
    calls.append((a, b))
    return a + b


@server.tool
def boom() -> str:
    """Always raises."""
    raise ValueError("kaboom")


@server.tool
def greet() -> str:
    """Returns a plain multi-line text result (not JSON)."""
    return "line1\nline2"


@server.tool
def hard_fail() -> str:
    """Returns a top-level error payload (hard failure convention)."""
    return json.dumps({"error": "No function at 0x9999"})


@server.tool
def soft_ok() -> str:
    """Success payload that carries error:null and a warning note."""
    return json.dumps({"ok": True, "data": [1, 2], "error": None, "warning": "heuristic"})


@server.tool
def batch_result() -> str:
    """Batch: per-item errors nested in a list are not a top-level failure."""
    return json.dumps([{"id": 1, "error": "bad item"}, {"id": 2, "ok": True}])


@server.tool
def configure(
    fmt: Literal["ida", "x64dbg", "mask"] = "ida",
    count: Annotated[int, "how many rows"] = 20,
    limit: Optional[int] = None,
    maybe: "int | None" = None,
) -> str:
    """Tool exercising defaults, enum, Annotated and Optional/union types."""
    return json.dumps({"fmt": fmt, "count": count, "limit": limit, "maybe": maybe})


server.serve("127.0.0.1", 13399, background=True)
time.sleep(0.5)


def post(payload):
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        "http://127.0.0.1:13399/mcp",
        data=data,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req) as r:
        return r.status, json.loads(r.read())


# initialize
status, resp = post({
    "jsonrpc": "2.0", "method": "initialize",
    "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}},
    "id": 1,
})
assert status == 200, status
assert resp["result"]["serverInfo"]["name"] == "test", resp
print("initialize OK", resp["result"]["serverInfo"])

# tools/list
status, resp = post({"jsonrpc": "2.0", "method": "tools/list", "params": {}, "id": 2})
assert status == 200, status
names = [t["name"] for t in resp["result"]["tools"]]
assert "add" in names and "boom" in names, names
# schema check
add_schema = [t for t in resp["result"]["tools"] if t["name"] == "add"][0]
assert add_schema["inputSchema"]["properties"]["a"]["type"] == "integer", add_schema
assert add_schema["inputSchema"]["required"] == ["a", "b"], add_schema
print("tools/list OK", names)

# richer schema: defaults, enum, Annotated description, Optional/union typing
cfg = [t for t in resp["result"]["tools"] if t["name"] == "configure"][0]
cprops = cfg["inputSchema"]["properties"]
assert cprops["fmt"]["enum"] == ["ida", "x64dbg", "mask"], cprops
assert cprops["fmt"]["type"] == "string" and cprops["fmt"]["default"] == "ida", cprops
assert cprops["count"]["type"] == "integer", cprops
assert cprops["count"]["default"] == 20, cprops
assert cprops["count"]["description"] == "how many rows", cprops
# Optional[int] / int | None must type as integer (not fall back to string)
assert cprops["limit"]["type"] == "integer" and cprops["limit"]["default"] is None, cprops
assert cprops["maybe"]["type"] == "integer", cprops
# all-defaulted tool: nothing required
assert "required" not in cfg["inputSchema"], cfg
print("tools/list rich schema OK")

# schema caching: a second tools/list returns the identical cached object
status2, resp2 = post({"jsonrpc": "2.0", "method": "tools/list", "params": {}, "id": 22})
cfg2 = [t for t in resp2["result"]["tools"] if t["name"] == "configure"][0]
assert cfg2 == cfg, "cached schema must be stable across tools/list calls"
assert server._schema_cache.get("configure") is not None, "schema should be cached"
print("schema cache OK")

# coercion still works through Optional/union + enum params (stringified ints)
status, resp = post({
    "jsonrpc": "2.0", "method": "tools/call",
    "params": {"name": "configure", "arguments": {"count": "5", "limit": "7"}}, "id": 23,
})
assert resp["result"]["isError"] is False, resp
# string results are emitted verbatim (no double-encoding), so a single decode
payload = json.loads(resp["result"]["content"][0]["text"])
assert payload["count"] == 5 and payload["limit"] == 7, payload
# structuredContent carries the parsed object directly
assert resp["result"]["structuredContent"]["count"] == 5, resp
print("tools/call coercion through Optional OK")

# tools/call success
status, resp = post({
    "jsonrpc": "2.0", "method": "tools/call",
    "params": {"name": "add", "arguments": {"a": 2, "b": 3}}, "id": 3,
})
assert status == 200, status
assert resp["result"]["isError"] is False, resp
assert json.loads(resp["result"]["content"][0]["text"]) == 5, resp
print("tools/call OK", resp["result"]["content"][0]["text"])

# tools/call error
status, resp = post({
    "jsonrpc": "2.0", "method": "tools/call",
    "params": {"name": "boom", "arguments": {}}, "id": 4,
})
assert status == 200, status
assert resp["result"]["isError"] is True, resp
print("tools/call error OK", resp["result"]["content"][0]["text"][:40])


def call(name, arguments=None):
    _, rr = post({"jsonrpc": "2.0", "method": "tools/call",
                  "params": {"name": name, "arguments": arguments or {}}, "id": 99})
    return rr["result"]

# no double-encoding: a plain-text result is emitted verbatim (real newline,
# no surrounding quotes or escaping)
r = call("greet")
assert r["content"][0]["text"] == "line1\nline2", r
# a JSON-string result decodes in a SINGLE json.loads (not double-encoded)
r = call("hard_fail")
assert json.loads(r["content"][0]["text"]) == {"error": "No function at 0x9999"}, r
# error convention: top-level error string -> isError:true, structuredContent is the parsed object
assert r["isError"] is True, r
assert r["structuredContent"]["error"] == "No function at 0x9999", r
# error:null + warning note -> NOT a failure
r = call("soft_ok")
assert r["isError"] is False, r
assert r["structuredContent"]["warning"] == "heuristic", r
# per-item error inside a list -> top-level is a list, NOT a failure
r = call("batch_result")
assert r["isError"] is False, r
print("error convention OK")

# output backstop: a result larger than the cap is refused, not dumped
server.max_output_chars = 5
r = call("greet")  # returns "line1\nline2" (11 chars) > 5
assert r["isError"] is True and "too large" in r["content"][0]["text"], r
assert r["structuredContent"]["error"] == "output_too_large", r
server.max_output_chars = 512 * 1024  # restore
r = call("greet")
assert r["isError"] is False and r["content"][0]["text"] == "line1\nline2", r
print("output backstop OK")

server.stop()
assert not server._running
print("ALL ZEROMCP SMOKE TESTS PASSED")
