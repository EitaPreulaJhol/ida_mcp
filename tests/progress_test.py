"""MCP progress notifications over the Streamable-HTTP SSE stream.

The client opens GET /mcp with a session id, calls a tool with
``params._meta.progressToken``, and receives ``notifications/progress``
events on the stream. Long two-phase tools use the same helper.
"""
import json
import socket
import sys
import time
import urllib.request

from _harness import real  # noqa: E402

mcp = real("zeromcp.mcp")
srv = mcp.McpServer("progress-test")
PORT = 18996
BASE = f"http://127.0.0.1:{PORT}/mcp"


@srv.tool
def work() -> str:
    """Emits two progress notifications."""
    srv.report_progress(1, 2, "one")
    srv.report_progress(2, 2, "two")
    return "done"


srv.serve("127.0.0.1", PORT, background=True)
time.sleep(0.2)


def post(payload, sid=None):
    headers = {"Content-Type": "application/json"}
    if sid:
        headers["Mcp-Session-Id"] = sid
    req = urllib.request.Request(BASE, data=json.dumps(payload).encode(),
                                 headers=headers)
    with urllib.request.urlopen(req, timeout=10) as r:
        body = r.read()
        return json.loads(body) if body else None, r.headers.get("Mcp-Session-Id")


init, sid = post({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                  "params": {"protocolVersion": "2025-06-18",
                             "capabilities": {},
                             "clientInfo": {"name": "progress", "version": "1"}}})
assert sid, init

# Open the server->client stream before the tool call.
s = socket.create_connection(("127.0.0.1", PORT), timeout=10)
s.sendall((f"GET /mcp HTTP/1.1\r\nHost: 127.0.0.1:{PORT}\r\n"
           f"Mcp-Session-Id: {sid}\r\nAccept: text/event-stream\r\n\r\n").encode())
f = s.makefile("rb")
status = f.readline().decode()
assert "200" in status, status
while f.readline().strip():
    pass
# Initial comment may be split across lines; consume until the blank line.
while True:
    line = f.readline()
    if not line or line == b"\n":
        break

resp, _ = post({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"name": "work", "arguments": {},
                           "_meta": {"progressToken": "tok-1"}}}, sid)
assert resp["result"]["isError"] is False, resp
assert resp["result"]["content"][0]["text"] == "done", resp

notifications = []
deadline = time.time() + 5
while len(notifications) < 2 and time.time() < deadline:
    line = f.readline().decode()
    if not line:
        break
    if line.startswith("data: "):
        notifications.append(json.loads(line[6:]))

assert len(notifications) == 2, notifications
for i, note in enumerate(notifications, 1):
    assert note["method"] == "notifications/progress", note
    assert note["params"]["progressToken"] == "tok-1", note
    assert note["params"]["progress"] == i, note
    assert note["params"]["total"] == 2, note
print("progress notifications over GET /mcp OK", notifications)

s.close()
srv.stop()
print("ALL PROGRESS TESTS PASSED")
