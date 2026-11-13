"""Dependency-free fuzz and conformance checks for the protocol edges.

Covers the P3.1 surface that stubbed unit tests only sample:

- ``JsonRpcRegistry.dispatch`` with malformed JSON, ids, params and batches;
- client regexes: ReDoS shapes, possessive/atomic escapes, deep nesting;
- HTTP chunked framing, body limits and malformed framing;
- MCP sessions, cancellation, progress tokens and SSE close.

Deterministic (fixed seed), stdlib-only and independent of IDA.
"""
import gzip
import json
import logging
import random
import re
import socket
import threading
import time
import urllib.error
import urllib.request
import warnings

from _harness import real  # noqa: E402

jsonrpc = real("zeromcp.jsonrpc")
mcp = real("zeromcp.mcp")
regex_guard = real("regex_guard")
logging.getLogger("ida_mcp.zeromcp.jsonrpc").setLevel(logging.CRITICAL)


# =========================================================================
# 1) JSON-RPC dispatch fuzz
# =========================================================================

reg = jsonrpc.JsonRpcRegistry()
reg.redact_exceptions = True
reg.method(lambda: "pong", "ping")
reg.method(lambda value=None: value, "echo")
method_calls = {"n": 0}


def _counted():
    method_calls["n"] += 1
    return "called"


reg.method(_counted, "counted")

ERROR_CODES = {-32700, -32600, -32601, -32603}


def _check_response(response, request, *, notification=None):
    """Validate a dispatch response; ``notification`` is inferred from None."""
    if notification is None:
        notification = response is None
    if notification:
        assert response is None, (request, response)
        if isinstance(request, dict):
            assert "id" not in request, (request, response)
        return
    assert isinstance(response, dict), (request, response)
    assert response.get("jsonrpc") == "2.0", (request, response)
    assert "id" in response, (request, response)
    if not isinstance(request, dict):
        assert "error" in response and response["id"] is None, (request, response)
        assert response["error"]["code"] in ERROR_CODES, (request, response)
        return
    if "result" in response:
        assert "error" not in response, (request, response)
        assert response["id"] == request.get("id"), (request, response)
    else:
        err = response["error"]
        assert err["code"] in ERROR_CODES, (request, response)
        assert isinstance(err["message"], str) and err["message"], response
        # Invalid ids are rejected before dispatch and use a null id.
        if request.get("id") is None or isinstance(request.get("id"), (dict, list, bool)):
            assert response["id"] is None, (request, response)


fixed = [
    None,
    [],
    [1, 2],
    {},
    {"jsonrpc": "1.0", "method": "ping", "id": 1},
    {"jsonrpc": "2.0", "id": 1},
    {"jsonrpc": "2.0", "method": None, "id": 1},
    {"jsonrpc": "2.0", "method": 7, "id": 1},
    {"jsonrpc": "2.0", "method": "nope", "id": 1},
    {"jsonrpc": "2.0", "method": "ping", "id": True},
    {"jsonrpc": "2.0", "method": "ping", "id": [1]},
    {"jsonrpc": "2.0", "method": "ping", "id": {"n": 1}},
    {"jsonrpc": "2.0", "method": "ping", "id": None},
    {"jsonrpc": "2.0", "method": "ping", "params": []},
    {"jsonrpc": "2.0", "method": "ping", "params": {}},
    {"jsonrpc": "2.0", "method": "ping", "params": 1},
    {"jsonrpc": "2.0", "method": "counted", "params": [1]},
    {"jsonrpc": "2.0", "method": "counted", "params": {"x": 1}},
    {"jsonrpc": "2.0", "method": "ping"},  # notification
    {"jsonrpc": "2.0", "method": "nope"},  # error notification -> no reply
]
for payload in fixed:
    response = reg.dispatch(payload)
    _check_response(response, payload)

# Bytes/strings go through the parser; malformed JSON must be -32700, while
# well-formed non-objects are -32600.
for payload in (b"", b"{", b"\xff", b"not json", b"\x00\x01", "[", "nullx"):
    response = reg.dispatch(payload)
    assert response.get("error", {}).get("code") == -32700, (payload, response)
for payload in ("[]", "null", "1", '"x"', "{}"):
    response = reg.dispatch(payload)
    assert response.get("error", {}).get("code") == -32600, (payload, response)

# A malformed id must never reach the method (and must not leak request state).
before = method_calls["n"]
for bad_id in (True, {}, [], [1]):
    response = reg.dispatch({"jsonrpc": "2.0", "method": "counted", "id": bad_id})
    assert response["error"]["code"] == -32600, response
assert method_calls["n"] == before, method_calls

# A scalar/object/list params shape reaches the method according to JSON-RPC.
assert reg.dispatch({"jsonrpc": "2.0", "method": "echo", "params": 7, "id": 3})[
    "result"] == 7
assert reg.dispatch({"jsonrpc": "2.0", "method": "echo", "params": {"value": 8},
                     "id": 4})["result"] == 8
assert reg.dispatch({"jsonrpc": "2.0", "method": "echo", "params": [9],
                     "id": 5})["result"] == 9

# Seeded random requests: dispatch must always answer or be a notification,
# never raise, and must leave the thread-local request id clean.
rng = random.Random(20261113)
vals = [None, True, False, 0, 1, -1, 1.5, "", "ping", "echo", "bogus",
        [], [1], {}, {"value": 1}, {"jsonrpc": "2.0"}]
for _i in range(600):
    payload = {
        "jsonrpc": rng.choice(["2.0", "1.0", None, 2]),
        "method": rng.choice(["ping", "echo", "bogus", "", None, 1]),
        "params": rng.choice(vals),
    }
    with_id = rng.random() < 0.8
    if with_id:
        payload["id"] = rng.choice([None, 0, 1, -1, 1.5, "id", True,
                                    [], {}, "x"])
    response = reg.dispatch(payload)
    _check_response(response, payload)
    assert jsonrpc.get_current_request_id() is None
print("JSON-RPC dispatch fuzz OK")


# =========================================================================
# 2) Client regex guard fuzz
# =========================================================================

bad_shapes = (
    r"(a+)+b", r"(a*)*b", r"(\w+\s?)*$", r"(?:x|y+){2,}",
    r"((ab)*c)+", r"(a+){2,}b", r"(a{1,}){2,}",
)
for pattern in bad_shapes:
    try:
        regex_guard.compile_client_regex(pattern)
        raise AssertionError(f"ReDoS shape accepted: {pattern!r}")
    except re.error as exc:
        assert "nested quantifiers" in str(exc), (pattern, exc)

good_shapes = (
    r"a+b", r"(ab)+", r"(a|b)+", r"(a{2}){3}", r"[a-z]+",
    r"(a+)++b", r"(?>a+)+b", r"(?:\d{1,3}\.){3}\d{1,3}",
)
for pattern in good_shapes:
    regex_guard.compile_client_regex(pattern)

for pattern in ("a" * (regex_guard.MAX_PATTERN_LEN + 1), "[", "(?P<x>a)(?P<x>b)"):
    try:
        regex_guard.compile_client_regex(pattern)
        raise AssertionError(f"invalid/oversized pattern accepted: {pattern[:20]!r}")
    except re.error:
        pass

# Random patterns: only re.error is acceptable; a RecursionError would escape
# as an internal -32603 and is the bug this guard exists to prevent.
rng = random.Random(424242)
alphabet = "ab()[]{}?*+|.^$\\d,:-_ "
for _ in range(500):
    pattern = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 32)))
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", FutureWarning)
            regex_guard.compile_client_regex(pattern)
    except re.error:
        pass
    except RecursionError:
        raise AssertionError(f"RecursionError escaped for {pattern!r}") from None

# Deep nesting must become re.error (or compile on newer Python), never leak.
deep = "(" * 300 + "a" + ")" * 300
try:
    regex_guard.compile_client_regex(deep)
except re.error:
    pass
except RecursionError:
    raise AssertionError("deep nesting leaked RecursionError") from None
print("client regex guard fuzz OK")


# =========================================================================
# 3) HTTP framing / body-limit conformance
# =========================================================================

PORT = 19015
BASE = f"http://127.0.0.1:{PORT}/mcp"
srv = mcp.McpServer("fuzz-conformance")
started_slow = threading.Event()


@srv.tool
def ping() -> str:
    """A trivial liveness tool."""
    return "pong"


@srv.tool
def slow() -> str:
    """Waits for a notifications/cancelled event."""
    started_slow.set()
    event = jsonrpc.get_current_cancel_event()
    if event is None:
        return "no-event"
    for _ in range(200):
        if event.is_set():
            return "cancelled"
        time.sleep(0.01)
    return "done"


@srv.tool
def progress_tool() -> str:
    """Reports one progress notification when a stream is available."""
    srv.report_progress(1, 1, "half")
    return "ok"


srv.serve("127.0.0.1", PORT, background=True)


def post(payload, sid=None, *, timeout=10):
    headers = {"Content-Type": "application/json"}
    if sid:
        headers["Mcp-Session-Id"] = sid
    req = urllib.request.Request(BASE, data=json.dumps(payload).encode(),
                                 headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read()
            return r.status, r.headers.get("Mcp-Session-Id"), (
                json.loads(body) if body else None)
    except urllib.error.HTTPError as e:
        return e.code, e.headers.get("Mcp-Session-Id"), e.read().decode(errors="replace")


def raw_request(data, *, shutdown_write=False, timeout=5):
    s = socket.create_connection(("127.0.0.1", PORT), timeout=timeout)
    s.settimeout(timeout)
    try:
        s.sendall(data)
        if shutdown_write:
            s.shutdown(socket.SHUT_WR)
        out = b""
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            out += chunk
        return out
    finally:
        s.close()


def status_line(data):
    line = data.split(b"\r\n", 1)[0].decode(errors="replace")
    parts = line.split()
    return int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else None


def http_post_raw(body, *, chunked=False, extra_headers=""):
    if chunked:
        payload = (f"{len(body):X}\r\n".encode() + body + b"\r\n0\r\n\r\n")
        headers = "Transfer-Encoding: chunked\r\n"
    else:
        payload = body
        headers = f"Content-Length: {len(body)}\r\n"
    request = (f"POST /mcp HTTP/1.1\r\nHost: 127.0.0.1:{PORT}\r\n"
               "Content-Type: application/json\r\n"
               f"{headers}{extra_headers}Connection: close\r\n\r\n").encode() + payload
    return status_line(raw_request(request))


def ping_status():
    st, _, body = post({"jsonrpc": "2.0", "id": 1, "method": "ping"})
    assert st == 200 and body["result"] == {}, (st, body)
    return st


def next_sse_event(stream_file):
    """Read one SSE event, ignoring keep-alive comments and blank lines."""
    event = None
    while True:
        line = stream_file.readline()
        if not line:
            return None, None
        if line.startswith(b"event: "):
            event = line[len(b"event: "):].strip()
        elif line.startswith(b"data: ") and event is not None:
            return event, line[len(b"data: "):].strip()


try:
    body = json.dumps({"jsonrpc": "2.0", "id": 2, "method": "ping"}).encode()
    assert http_post_raw(body) == 200
    assert http_post_raw(body, chunked=True) == 200

    # Malformed chunk sizes are rejected before the body is dispatched.
    for size in (b"Z", b"-1", b"+1", b"0x10", b"1_0", b""):
        request = (f"POST /mcp HTTP/1.1\r\nHost: 127.0.0.1:{PORT}\r\n"
                   "Content-Type: application/json\r\n"
                   "Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n").encode()
        request += size + b"\r\n0\r\n\r\n"
        status = status_line(raw_request(request, shutdown_write=True))
        assert status in (400, None), (size, status)
        ping_status()

    # A declared chunk larger than the body, with the peer closing, must not
    # hang or be treated as a valid request.
    truncated = (f"POST /mcp HTTP/1.1\r\nHost: 127.0.0.1:{PORT}\r\n"
                 "Content-Type: application/json\r\n"
                 "Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
                 "10\r\nabc").encode()
    status = status_line(raw_request(truncated, shutdown_write=True))
    assert status in (400, None), status
    ping_status()

    # Content-Length over the cap -> 413, without reading the body.
    old_limit = srv.post_body_limit
    srv.post_body_limit = 64
    try:
        too_big = (f"POST /mcp HTTP/1.1\r\nHost: 127.0.0.1:{PORT}\r\n"
                   "Content-Type: application/json\r\n"
                   "Content-Length: 100000\r\nConnection: close\r\n\r\n").encode()
        assert status_line(raw_request(too_big)) == 413
        ping_status()

        # Chunked over the cap -> 413 too.
        chunked_big = (f"POST /mcp HTTP/1.1\r\nHost: 127.0.0.1:{PORT}\r\n"
                       "Content-Type: application/json\r\n"
                       "Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
                       "80\r\n").encode() + b"x" * 128 + b"\r\n0\r\n\r\n"
        assert status_line(raw_request(chunked_big)) == 413
        ping_status()

        # gzip bomb: compressed bytes are small; decompressed output is capped.
        bomb = gzip.compress(b"x" * 10000)
        request = (f"POST /mcp HTTP/1.1\r\nHost: 127.0.0.1:{PORT}\r\n"
                   "Content-Type: application/json\r\n"
                   "Content-Encoding: gzip\r\n"
                   f"Content-Length: {len(bomb)}\r\nConnection: close\r\n\r\n").encode() + bomb
        assert status_line(raw_request(request)) == 413
        ping_status()
    finally:
        srv.post_body_limit = old_limit
    print("HTTP framing/body-limit conformance OK")

    # =====================================================================
    # 4) MCP session / cancellation / progress / SSE close
    # =====================================================================
    init = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                       "clientInfo": {"name": "fuzz", "version": "1"}}}
    status, sid, init_resp = post(init)
    assert status == 200 and sid, (status, sid, init_resp)
    assert init_resp["result"]["serverInfo"]["name"] == "fuzz-conformance"

    # Unknown session is rejected; no-session requests remain stateless.
    assert post({"jsonrpc": "2.0", "id": 2, "method": "ping"}, "deadbeef")[0] == 404
    assert post({"jsonrpc": "2.0", "id": 3, "method": "ping"})[0] == 200

    # Cancellation is scoped to the session and reaches a pending tools/call.
    started_slow.clear()
    cancelled_result = {}


    def call_slow():
        cancelled_result["v"] = post({
            "jsonrpc": "2.0", "id": 77, "method": "tools/call",
            "params": {"name": "slow", "arguments": {}}}, sid)

    t = threading.Thread(target=call_slow)
    t.start()
    assert started_slow.wait(3), "slow tool did not start"
    assert post({"jsonrpc": "2.0", "method": "notifications/cancelled",
                 "params": {"requestId": 77}}, sid)[0] == 202
    t.join(5)
    assert not t.is_alive(), "cancelled call did not finish"
    assert cancelled_result["v"][0] == 200, cancelled_result
    assert cancelled_result["v"][2]["result"]["content"][0]["text"] == "cancelled", \
        cancelled_result

    # Unknown cancellation id is a harmless notification.
    assert post({"jsonrpc": "2.0", "method": "notifications/cancelled",
                 "params": {"requestId": 9999}}, sid)[0] == 202

    # Progress token without a GET stream is a no-op, not a tool error.
    st, _, resp = post({"jsonrpc": "2.0", "id": 4, "method": "tools/call",
                        "params": {"name": "progress_tool", "arguments": {},
                                   "_meta": {"progressToken": "tok"}}}, sid)
    assert st == 200 and resp["result"]["isError"] is False, resp

    # With a live GET stream, progress arrives; closing the stream must not
    # turn a later tool call into an error.
    stream_sock = socket.create_connection(("127.0.0.1", PORT), timeout=10)
    stream_sock.sendall((f"GET /mcp HTTP/1.1\r\nHost: 127.0.0.1:{PORT}\r\n"
                         f"Mcp-Session-Id: {sid}\r\nAccept: text/event-stream\r\n\r\n").encode())
    stream_file = stream_sock.makefile("rb")
    assert b"200" in stream_file.readline(), "SSE stream did not open"
    while stream_file.readline().strip():
        pass
    st, _, resp = post({"jsonrpc": "2.0", "id": 5, "method": "tools/call",
                        "params": {"name": "progress_tool", "arguments": {},
                                   "_meta": {"progressToken": "tok-2"}}}, sid)
    assert st == 200 and resp["result"]["isError"] is False, resp
    event, payload_line = next_sse_event(stream_file)
    assert event == b"message", event
    note = json.loads(payload_line)
    assert note["method"] == "notifications/progress", note
    assert note["params"]["progressToken"] == "tok-2", note
    stream_sock.close()

    # Closing the SSE stream must leave the server and session usable.
    st, _, resp = post({"jsonrpc": "2.0", "id": 6, "method": "tools/call",
                        "params": {"name": "progress_tool", "arguments": {},
                                   "_meta": {"progressToken": "tok-3"}}}, sid)
    assert st == 200 and resp["result"]["isError"] is False, resp

    # DELETE closes the session; subsequent use is a 404.
    req = urllib.request.Request(BASE, method="DELETE",
                                 headers={"Mcp-Session-Id": sid})
    with urllib.request.urlopen(req, timeout=5) as r:
        assert r.status == 200
    assert post({"jsonrpc": "2.0", "id": 7, "method": "ping"}, sid)[0] == 404
    print("MCP session/cancellation/progress/SSE conformance OK")
finally:
    srv.stop()

print("ALL FUZZ/CONFORMANCE TESTS PASSED")
