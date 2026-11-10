"""HTTP connection cap + idle timeout (plan 15, item 15.3).

``ThreadingHTTPServer`` spawns one thread per accepted connection with no bound,
and ``BaseHTTPRequestHandler.timeout`` is ``None``: a local process can hold an
unbounded number of worker threads open by connecting and sending nothing. IDA
is the process that pays for it.

The cap answers ``503`` over the limit; the idle timeout closes a connection
that sends no request. Runs over raw sockets (pure zeromcp, no IDA).
"""
import json
import socket
import sys
import time

from _harness import real  # noqa: E402

jsonrpc = real("zeromcp.jsonrpc")
mcp = real("zeromcp.mcp")

HOST = "127.0.0.1"
PING = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "ping"}).encode()
REQUEST = (b"POST /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\n"
           b"Content-Type: application/json\r\n"
           b"Content-Length: " + str(len(PING)).encode() + b"\r\n\r\n" + PING)


def _status_line(sock, timeout=5.0) -> bytes:
    sock.settimeout(timeout)
    data = b""
    while b"\r\n" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    return data.split(b"\r\n", 1)[0]


def _open():
    s = socket.create_connection((HOST, srv._http_server.server_address[1]), timeout=5)
    s.sendall(REQUEST)
    return s


# =========================================================================
# Phase A: the cap
# =========================================================================

srv = mcp.McpServer("conn-cap-test")
srv.max_connections = 2
srv.idle_timeout_sec = 0            # keep-alive connections stay open
srv.serve(HOST, 18991, background=True)

a = _open()
b = _open()
assert b" 200 " in _status_line(a), _status_line(a)
assert b" 200 " in _status_line(b), _status_line(b)
print("up to the cap: accepted OK")

c = socket.create_connection((HOST, srv._http_server.server_address[1]), timeout=5)
c.sendall(REQUEST)
line = _status_line(c)
assert b" 503 " in line, line
assert c.recv(1) == b""            # the over-limit connection is closed
print("over the cap: 503 + close OK")

a.close()
time.sleep(0.5)                    # the server thread notices the close
d = _open()
assert b" 200 " in _status_line(d), _status_line(d)
print("a freed slot is reusable OK")

for s in (b, c, d):
    try:
        s.close()
    except OSError:
        pass
srv.stop()

# =========================================================================
# Phase B: idle timeout (and the cap disabled)
# =========================================================================

srv2 = mcp.McpServer("conn-idle-test")
srv2.max_connections = 0           # 0 disables the cap
srv2.idle_timeout_sec = 0.3
srv2.serve(HOST, 18992, background=True)

idle = socket.create_connection((HOST, srv2._http_server.server_address[1]), timeout=5)
idle.settimeout(5)
t0 = time.monotonic()
closed = False
try:
    closed = idle.recv(1) == b""
except (socket.timeout, ConnectionResetError):
    closed = False
assert closed, "an idle connection was not closed by the idle timeout"
assert time.monotonic() - t0 < 3.0, "idle timeout took too long"
print("idle connection is closed by the timeout OK")

# the cap is disabled: three simultaneous connections all answered
held = []
for _ in range(3):
    s = socket.create_connection((HOST, srv2._http_server.server_address[1]), timeout=5)
    s.sendall(REQUEST)
    held.append(s)
for s in held:
    assert b" 200 " in _status_line(s), _status_line(s)
    s.close()
print("max_connections=0 disables the cap OK")

srv2.stop()
print("ALL CONNECTION CAP TESTS PASSED")
