import json
import os
import sys
import time
import urllib.request

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

server.stop()
assert not server._running
print("ALL ZEROMCP SMOKE TESTS PASSED")
