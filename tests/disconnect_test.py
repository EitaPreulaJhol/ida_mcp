"""Disconnect robustness: slow tool + client gone must not traceback (Fase 0).

Covers the BrokenPipeError from the report:
  File ".../zeromcp/mcp.py", line 344, in send
    self.wfile.write(data)
  BrokenPipeError: [Errno 32] Broken pipe.

Loads ida_mcp/zeromcp standalone (no IDA needed).
"""
import json
import os
import socket
import sys
import time
import types
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ZPKG = os.path.join(HERE, "..", "ida_mcp", "zeromcp")

_zt = types.ModuleType("zt_disc_pkg")
_zt.__path__ = []
sys.modules["zt_disc_pkg"] = _zt


def _load(name, filename, patch=None):
    path = os.path.join(ZPKG, filename)
    src = open(path, "r", encoding="utf-8").read()
    if patch:
        src = patch(src)
    mod = types.ModuleType(name)
    sys.modules[name] = mod
    exec(compile(src, name, "exec"), mod.__dict__)
    return mod


jsonrpc = _load("zt_disc_pkg.jsonrpc", "jsonrpc.py")
mcp = _load("zt_disc_pkg.mcp", "mcp.py",
            patch=lambda s: s.replace("from .jsonrpc import", "from zt_disc_pkg.jsonrpc import"))

# --- 1. disconnect error tuple covers the reported traceback ---
assert issubclass(BrokenPipeError, mcp._DISCONNECT_ERRORS), "BrokenPipeError must be suppressed"
assert issubclass(ConnectionResetError, mcp._DISCONNECT_ERRORS)
assert issubclass(ConnectionAbortedError, mcp._DISCONNECT_ERRORS)
print("disconnect error tuple OK")

# --- 2. server handle_error swallows disconnects, re-raises real bugs ---
# NOTE: socketserver dispatches to server.handle_error, not handler.
_probe = mcp._McpThreadingHTTPServer.__new__(mcp._McpThreadingHTTPServer)
try:
    raise BrokenPipeError(32, "Broken pipe")
except BrokenPipeError:
    _probe.handle_error(None, ("127.0.0.1", 56522))  # must not raise/print traceback
print("handle_error suppresses BrokenPipeError OK")

import socketserver as _ss
called = []
_orig_parent = _ss.BaseServer.handle_error


def _boom_handle_error(self, request, client_address):
    called.append(True)
    raise RuntimeError("parent called")


_ss.BaseServer.handle_error = _boom_handle_error
try:
    try:
        raise ValueError("real bug")
    except ValueError:
        try:
            _probe.handle_error(None, ("127.0.0.1", 1))
        except RuntimeError as e:
            assert str(e) == "parent called"
        assert called == [True], "non-disconnect errors must reach the parent handler"
finally:
    _ss.BaseServer.handle_error = _orig_parent
print("handle_error delegates real errors OK")
assert issubclass(mcp._McpThreadingHTTPServer, _ss.ThreadingMixIn)
print("quiet server keeps ThreadingMixIn OK")

# --- 3. _safe_send_error never raises on dead peer ---
h2 = mcp.McpHttpRequestHandler.__new__(mcp.McpHttpRequestHandler)


def _raise_pipe(*a, **k):
    raise BrokenPipeError(32, "Broken pipe")


h2.send_error = _raise_pipe
h2._safe_send_error(403, "x")  # must not raise
print("_safe_send_error suppression OK")

# --- 4. live server: client aborts a slow POST, server survives ---
srv = mcp.McpServer("disconnect-test")


@srv.tool
def slow_tool() -> str:
    """Simulates a long IDA op (was: execute_sync holding the main thread)."""
    import time as _t
    _t.sleep(1.5)
    return "slow-done"


srv.serve("127.0.0.1", 18999, background=True)
assert srv._http_server.daemon_threads is True, "request threads must be daemonized"
print("daemon_threads OK")


def _ping():
    body = json.dumps({"jsonrpc": "2.0", "method": "ping", "id": 1}).encode()
    req = urllib.request.Request("http://127.0.0.1:18999/mcp", data=body,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as r:
        assert r.status == 200, r.status
        assert json.loads(r.read().decode())["result"] == {}


_ping()
print("pre-disconnect ping OK")

# Raw socket: send a slow_tool call, then vanish before reading the reply.
payload = json.dumps({"jsonrpc": "2.0", "method": "tools/call",
                      "params": {"name": "slow_tool", "arguments": {}},
                      "id": 99}).encode()
raw = socket.create_connection(("127.0.0.1", 18999), timeout=10)
raw.sendall(b"POST /mcp HTTP/1.1\r\nHost: 127.0.0.1:18999\r\n"
            b"Content-Type: application/json\r\n"
            b"Content-Length: " + str(len(payload)).encode() + b"\r\n"
            b"Connection: close\r\n\r\n" + payload)
time.sleep(0.3)  # let the server enter dispatch...
try:
    raw.shutdown(socket.SHUT_RDWR)
except OSError:
    pass
raw.close()  # ...then disappear: the reply write must hit a dead peer
print("client abort injected")

time.sleep(2.5)  # slow_tool finishes + attempts wfile.write on closed socket
_ping()  # server survived, no zombie thread, next request is fine
print("post-disconnect ping OK (server survived client abort)")

srv.stop()
print("ALL DISCONNECT TESTS PASSED")
