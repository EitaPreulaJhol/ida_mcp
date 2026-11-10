"""Trimmed MCP server over stdlib HTTP (adapted from zeromcp 1.3.0).

Provides McpServer / McpRpcRegistry / McpHttpRequestHandler implementing the
MCP Streamable HTTP transport (POST /mcp, GET /mcp SSE, DELETE /mcp) plus the
legacy SSE transport (GET /sse, POST /sse?session=) on top of
ThreadingHTTPServer, so no external ASGI/uvicorn dependency is required.
"""
import inspect
import hashlib
import json
import logging
import os
import secrets
import select
import socket
import sys
import threading
import time
import uuid
import zlib
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer, HTTPServer
from typing import Any, Callable
from urllib.parse import urlparse, parse_qs

from typing import get_type_hints, get_origin, get_args, Annotated, Literal, Union

try:  # Python 3.10+: ``X | None`` annotations have this origin.
    from types import UnionType as _UnionType
except ImportError:  # pragma: no cover - older runtimes only expose typing.Union
    _UnionType = None  # type: ignore[assignment,misc]

from .jsonrpc import (
    JsonRpcRegistry,
    JsonRpcException,
    get_current_request_id,
    register_pending_request,
    unregister_pending_request,
    cancel_request,
    set_current_scope,
)

logger = logging.getLogger(__name__)

# Errors raised when the peer goes away mid-request (client timeout,
# tab closed, agent cancelled). The slow-tool path hits this often:
# dispatch blocks in execute_sync while the client gives up, then
# wfile.write raises. These must never bubble to socketserver (which
# logs "Exception occurred during processing of request" with traceback).
_DISCONNECT_ERRORS = (BrokenPipeError, ConnectionResetError,
                      ConnectionAbortedError, OSError)


class _DisconnectQuietMixin:
    """ Silence client-disconnect noise, keep real bugs loud.

    NOTE: socketserver calls ``server.handle_error``, NOT
    ``handler.handle_error`` -- an override on the handler is dead code.
    This mixin must be applied to the HTTP server classes used in
    ``McpServer.serve``.
    """

    def handle_error(self, request, client_address) -> None:  # noqa: ANN001, ANN202
        exc = sys.exc_info()[1]
        if exc is not None and isinstance(exc, _DISCONNECT_ERRORS):
            logger.debug("[MCP] client disconnected %s: %s", client_address, exc)
            return
        super().handle_error(request, client_address)  # type: ignore[misc]


class _McpThreadingHTTPServer(_DisconnectQuietMixin, ThreadingHTTPServer):
    pass


class _McpHTTPServer(_DisconnectQuietMixin, HTTPServer):
    pass

EXTERNAL_BASE_HEADER = "X-IDA-MCP-External-Base"

# MCP protocol revisions this server speaks, newest first. initialize echoes
# the client's version when it is one of these and otherwise answers with
# the server's preferred one (spec: the client then decides whether to
# continue), instead of blindly echoing whatever string was sent.
SUPPORTED_PROTOCOL_VERSIONS = ("2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05")
PREFERRED_PROTOCOL_VERSION = "2025-06-18"


def _parse_host_header(host_header: str | None) -> str | None:
    """Extract the hostname from a Host header (handles IPv6 + port)."""
    if not host_header:
        return None
    host_header = host_header.strip()
    if not host_header:
        return None
    if host_header.startswith("["):
        end = host_header.find("]")
        if end == -1:
            return None
        return host_header[1:end]
    # Strip port (but not for bare IPv6 without brackets — treat as-is).
    if host_header.count(":") == 1:
        return host_header.rsplit(":", 1)[0]
    return host_header


def _is_loopback_host(host: str | None) -> bool:
    if not host:
        return False
    host = host.strip().lower()
    return host in ("localhost", "127.0.0.1", "::1")


def _host_header_allowed_for_bind(bound_host: str, host_header: str | None) -> bool:
    """Reject DNS-rebinding style Host headers when bound to loopback."""
    if host_header is None:
        return True
    host_name = _parse_host_header(host_header)
    if host_name is None:
        return False
    if not _is_loopback_host(bound_host):
        return True
    return _is_loopback_host(host_name)

# Thread-local storage for request-scoped state (e.g. unsafe flag).
_unsafe_per_thread = threading.local()

# Thread-local set of enabled extension groups, parsed per-request from
# ?ext= (e.g. ?ext=dbg). Empty/absent means no extension tools are visible.
_request_extensions = threading.local()

# Thread-local per-request auth token, parsed from the X-IDA-MCP-Token header
# or ?token= query param. Checked against McpServer.auth_token before any
# unsafe/extension tool is listed or called (see McpServer._auth_ok).
_request_auth = threading.local()


def _enabled_extension_groups() -> set[str]:
    return getattr(_request_extensions, "groups", set()) or set()


try:
    from ..profiles import get_profile as _get_profile_fn
    from ..profiles import list_profiles as _list_profiles_fn
except ImportError:  # standalone zeromcp use (tests) without the ida_mcp package
    _get_profile_fn = None  # type: ignore[assignment]
    _list_profiles_fn = None  # type: ignore[assignment]

# Thread-local active profile: (name, tool-set or None). None set = unknown
# or absent profile -> no filtering (fail-open, documented).
_request_profile = threading.local()


def _active_profile() -> tuple[str | None, set[str] | None]:
    return getattr(_request_profile, "current", (None, None))


def _unknown_profile() -> str | None:
    """The ?profile= value that was requested but does not exist (or None)."""
    return getattr(_request_profile, "unknown", None)


def _unknown_profile_error(name: str) -> str:
    """Reject an unknown profile instead of silently disabling the filter.

    Before this, a typo (``?profile=readonyl``) made ``get_profile()`` return
    None, which the gates read as "no filtering": the client silently got
    every safe tool instead of the requested 16. Naming the valid profiles
    makes the mistake self-correcting for an agent.
    """
    available = ""
    if _list_profiles_fn is not None:
        try:
            available = ", ".join(sorted(_list_profiles_fn()))
        except Exception:
            available = ""
    msg = f"Unknown profile '{name}'."
    if available:
        msg += f" Available profiles: {available}."
    return msg + " Drop ?profile= to use the whole (safe) tool set."


_QUIET_UNRAISABLE = (BrokenPipeError, ConnectionResetError, ConnectionAbortedError)


def _install_unraisable_hook() -> None:
    """Suppress ConnectionResetError / BrokenPipeError from background threads.

    The SSE keep-alive stream runs in its own thread, and a peer closing the
    connection during the sleep can surface ConnectionResetError in Python's
    unraisable hook after the thread has already exited. The per-write
    try/except in ``do_GET`` catches it at the source; this hook is a
    belt-and-suspenders fallback.

    Everything else is forwarded to the hook that was installed before ours
    (IDA's, pytest's, or the default), never to ``sys.unraisablehook`` itself
    (that is *this* hook -> infinite recursion). Installed by ``serve()``,
    not at import, so merely importing zeromcp does not touch the host
    process; idempotent across restarts and package reloads.
    """
    current = sys.unraisablehook
    if getattr(current, "_ida_mcp_quiet", False):
        prev = getattr(current, "_ida_mcp_prev", sys.__unraisablehook__)
    else:
        prev = current

    def _silent_unraisable(unraisable) -> None:
        if isinstance(unraisable.exc_value, _QUIET_UNRAISABLE):
            return  # silent
        prev(unraisable)

    setattr(_silent_unraisable, "_ida_mcp_quiet", True)
    setattr(_silent_unraisable, "_ida_mcp_prev", prev)
    sys.unraisablehook = _silent_unraisable


def _uninstall_unraisable_hook() -> None:
    """Restore the previous hook, but only if ours is still the active one."""
    current = sys.unraisablehook
    if getattr(current, "_ida_mcp_quiet", False):
        sys.unraisablehook = getattr(current, "_ida_mcp_prev", sys.__unraisablehook__)


class McpToolError(Exception):
    def __init__(self, message: str):
        super().__init__(message)


class _McpSseConnection:
    """One legacy-SSE GET stream (server -> client events)."""

    def __init__(self, wfile) -> None:
        self.session_id = str(uuid.uuid4())
        self._wfile = wfile
        self.alive = True
        self._lock = threading.Lock()

    def send_event(self, event: str, data: Any) -> bool:
        payload = (f"event: {event}\n"
                   f"data: {json.dumps(data, separators=(',', ':'))}\n\n")
        try:
            with self._lock:
                if not self.alive:
                    return False
                self._wfile.write(payload.encode("utf-8"))
                self._wfile.flush()
            return True
        except (BrokenPipeError, ConnectionResetError,
                ConnectionAbortedError, OSError):
            self.alive = False
            return False


class McpRpcRegistry(JsonRpcRegistry):
    """JSON-RPC registry with custom error handling for MCP tools."""

    def map_exception(self, e: Exception):
        if isinstance(e, McpToolError):
            return {"code": -32000, "message": e.args[0] or "MCP Tool Error"}
        return super().map_exception(e)


class McpHttpRequestHandler(BaseHTTPRequestHandler):
    server_version = "ida-mcp/1.0"
    protocol_version = "HTTP/1.1"

    def __init__(self, request, client_address, server):
        self.mcp_server: "McpServer" = getattr(server, "mcp_server")
        super().__init__(request, client_address, server)

    def log_message(self, format, *args):
        pass

    def _safe_send_error(self, *args, **kwargs) -> None:
        """ send_error that never raises on a dead peer. """
        try:
            self.send_error(*args, **kwargs)
        except _DISCONNECT_ERRORS:
            logger.debug("[MCP] send_error suppressed (peer gone)")
        except Exception:
            logger.exception("[MCP] send_error failed")

    def _get_query_param(self, path: str, param: str, default: str = "") -> str:
        """Get a single query parameter value from the path."""
        return parse_qs(urlparse(path).query).get(param, [default])[0]

    def _parse_extensions(self, path: str) -> set[str]:
        ext_param = self._get_query_param(path, "ext")
        if not ext_param:
            return set()
        return {e.strip() for e in ext_param.split(",") if e.strip()}

    def send_cors_headers(self, *, preflight: bool = False) -> None:
        origin = self.headers.get("Origin", "")
        if not self.mcp_server._origin_allowed(origin):
            return
        self.send_header("Access-Control-Allow-Origin", origin)
        if preflight:
            self.send_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS, DELETE")
            self.send_header(
                "Access-Control-Allow-Headers",
                "Content-Type, Accept, X-Requested-With, Mcp-Session-Id, Mcp-Protocol-Version, "
                "X-IDA-MCP-Token",
            )

    def _request_token(self) -> str | None:
        token = (self.headers.get("X-IDA-MCP-Token", "")
                 or self._get_query_param(self.path, "token", "")).strip()
        return token or None

    def _check_api_request(self, *, preflight: bool = False) -> bool:
        """Block browser traffic that violates the configured origin policy.

        Browsers can bypass passive CORS-only defenses during DNS rebinding
        because same-origin requests do not need CORS. Rejecting unexpected Host
        and Origin headers closes that gap while keeping direct clients working.

        Off loopback (e.g. IDA_MCP_HOST=0.0.0.0) the Host check cannot apply
        and the network can reach the server, so when auth is enabled EVERY
        request must carry the token, not only unsafe/extension calls.
        CORS preflights are exempt: browsers never attach custom headers to
        them, and they reach no tool.
        """
        bound_host = str(self.server.server_address[0])  # type: ignore[index]
        if not _host_header_allowed_for_bind(bound_host, self.headers.get("Host")):
            self._safe_send_error(403, "Invalid Host")
            return False
        origin = self.headers.get("Origin", "")
        if origin and not self.mcp_server._origin_allowed(origin):
            self._safe_send_error(403, "Invalid Origin")
            return False
        if (not preflight and not _is_loopback_host(bound_host)
                and not self.mcp_server._token_matches(self._request_token())):
            self._safe_send_error(
                401, "Auth token required",
                "This server is bound off-loopback: send the token printed in IDA's "
                "Output window as the X-IDA-MCP-Token header (or ?token=).")
            return False
        return True

    def do_OPTIONS(self):
        if not self._check_api_request(preflight=True):
            return
        try:
            self.send_response(204)
            self.send_cors_headers(preflight=True)
            self.send_header("Content-Length", "0")
            self.end_headers()
        except _DISCONNECT_ERRORS:
            logger.debug("[MCP] OPTIONS reply suppressed (client gone)")

    def _parse_request_flags(self, scope: str | None = None) -> None:
        """Parse per-request ?unsafe= / ?ext= / ?profile= / token into thread-locals.

        ``scope`` is the transport session this request belongs to; it scopes
        request-id bookkeeping so cancellations cannot cross sessions.
        """
        set_current_scope(scope)
        _unsafe_per_thread.allowed = (
            self._get_query_param(self.path, "unsafe", "false").strip().lower() == "true"
        )
        _request_extensions.groups = self._parse_extensions(self.path)
        _request_auth.token = self._request_token()
        profile_name = self._get_query_param(self.path, "profile", "").strip().lower()
        profile_set = None
        if profile_name and _get_profile_fn is not None:
            try:
                profile_set = _get_profile_fn(profile_name)
            except Exception:
                profile_set = None
        _request_profile.current = (profile_name or None, profile_set)
        # A profile that was asked for but does not exist is a client error,
        # not "no filtering" (see _unknown_profile_error).
        _request_profile.unknown = (
            profile_name
            if profile_name and _get_profile_fn is not None and profile_set is None
            else None)

    def _read_body(self) -> bytes | None:
        """Read the POST body honoring limits, chunked framing and encoding."""
        if "chunked" in self.headers.get("Transfer-Encoding", "").lower():
            raw = self._read_chunked()
            if raw is None:
                self._safe_send_error(400, "Malformed chunked body")
                return None
        else:
            try:
                content_length = int(self.headers.get("Content-Length", 0))
            except ValueError:
                content_length = 0
            if content_length > self.mcp_server.post_body_limit:
                self._safe_send_error(
                    413,
                    f"Payload Too Large: exceeds {self.mcp_server.post_body_limit} bytes",
                )
                return None
            raw = self.rfile.read(content_length) if content_length > 0 else b""
        if len(raw) > self.mcp_server.post_body_limit:
            self._safe_send_error(
                413,
                f"Payload Too Large: exceeds {self.mcp_server.post_body_limit} bytes",
            )
            return None
        return self._decompress_body(raw)

    def _read_chunked(self) -> bytes | None:
        """Read a chunked body; returns None on malformed framing."""
        body = b""
        limit = self.mcp_server.post_body_limit
        while True:
            line = self.rfile.readline(1024).split(b";")[0].strip()
            # Strict hex only: int(x, 16) also accepts "-1" / "+f" / "0x1f" /
            # "1_0", and a negative size would turn into rfile.read(-1)
            # (read-until-EOF), bypassing post_body_limit entirely.
            if not line or line.strip(b"0123456789abcdefABCDEF"):
                return None
            chunk_size = int(line, 16)
            if chunk_size == 0:
                while self.rfile.readline().strip():
                    pass  # consume trailers
                break
            body += self.rfile.read(min(chunk_size, limit + 1 - len(body)))
            if len(body) > limit:
                return body
            self.rfile.readline()  # consume trailing CRLF
        return body

    def _decompress_body(self, data: bytes) -> bytes | None:
        encoding = self.headers.get("Content-Encoding", "").lower().strip()
        if not encoding:
            return data
        # Bound the *decompressed* size too: post_body_limit is checked on the
        # compressed bytes, and a ~1 MiB gzip bomb inflates to 1 GiB.
        limit = self.mcp_server.post_body_limit
        try:
            if encoding in ("gzip", "x-gzip"):
                out = zlib.decompressobj(16 + zlib.MAX_WBITS).decompress(data, limit + 1)
            elif encoding == "deflate":
                try:
                    out = zlib.decompressobj(zlib.MAX_WBITS).decompress(data, limit + 1)
                except zlib.error:
                    out = zlib.decompressobj(-zlib.MAX_WBITS).decompress(data, limit + 1)
            else:
                return data
        except Exception:
            self._safe_send_error(400, "Bad Content-Encoding")
            return None
        if len(out) > limit:
            self._safe_send_error(413, f"Payload Too Large: exceeds {limit} bytes")
            return None
        return out

    def do_POST(self):
        if not self._check_api_request():
            return
        parsed = urlparse(self.path)
        if parsed.path == "/mcp":
            self._handle_mcp_post()
        elif parsed.path == "/sse":
            self._handle_sse_post()
        else:
            self._safe_send_error(404)

    def _handle_mcp_post(self) -> None:
        self._parse_request_flags(scope=self.headers.get("Mcp-Session-Id"))
        raw = self._read_body()
        if raw is None:
            return
        body = raw if raw else b"{}"
        mcp_session_id = self.headers.get("Mcp-Session-Id")
        try:
            request = json.loads(body.decode("utf-8"))
        except Exception:
            # Let the registry produce the spec'd -32700 Parse error (it
            # re-parses bytes) instead of masking it as -32600 via {}.
            request = None
            response = self.mcp_server.registry.dispatch(body)
        else:
            response = self.mcp_server.registry.dispatch(request)

        # Session management: create a session id on initialize.
        # (A batch array is answered by dispatch() as invalid-request.)
        if isinstance(request, dict) and request.get("method") == "initialize":
            sid = str(uuid.uuid4())
            self.mcp_server.register_http_session(sid)
            mcp_session_id = sid

        def send(status: int, payload: Any) -> None:
            # The client may have timed out while dispatch() was blocked
            # on the IDA main thread. Every socket op below can then
            # raise BrokenPipe/ConnectionReset -> swallow, never let it
            # reach socketserver (which logs a traceback per request).
            try:
                data = json.dumps(payload).encode("utf-8") if payload is not None else b""
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                if mcp_session_id is not None:
                    self.send_header("Mcp-Session-Id", mcp_session_id)
                self.send_cors_headers()
                self.end_headers()
                if data:
                    self.wfile.write(data)
                    self.wfile.flush()
            except _DISCONNECT_ERRORS:
                logger.debug("[MCP] POST reply suppressed (client gone)")
                return

        if response is None:
            send(202, None)
        else:
            send(200, response)

    def _handle_sse_post(self) -> None:
        """Legacy SSE message post: dispatch and reply on the GET stream."""
        query = parse_qs(urlparse(self.path).query)
        session_id = query.get("session", [None])[0]  # type: ignore[list-item]
        if session_id is None:
            self._safe_send_error(400, "Missing ?session for SSE POST")
            return
        with self.mcp_server._sse_lock:
            conn = self.mcp_server._sse_connections.get(session_id)
        if conn is None or not conn.alive:
            self._safe_send_error(400, f"No active SSE connection for session {session_id}")
            return
        self._parse_request_flags(scope=f"sse:{session_id}")
        raw = self._read_body()
        if raw is None:
            return
        response = self.mcp_server.registry.dispatch(raw if raw else b"{}")
        if response is not None:
            conn.send_event("message", response)
        try:
            self.send_response(202)
            self.send_header("Content-Length", "0")
            self.send_cors_headers()
            self.end_headers()
        except _DISCONNECT_ERRORS:
            logger.debug("[MCP] SSE POST ack suppressed (client gone)")
            return

    def do_GET(self):
        if not self._check_api_request():
            return
        parsed = urlparse(self.path)
        if parsed.path == "/mcp":
            self._handle_mcp_get()
        elif parsed.path == "/sse":
            self._handle_sse_get()
        else:
            self.send_error(404)

    def _handle_mcp_get(self) -> None:
        # Streamable HTTP SSE stream (server -> client notifications).
        try:
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.send_cors_headers()
            self.end_headers()
            self.wfile.write(b": connected\n\n")
            self.wfile.flush()
        except _DISCONNECT_ERRORS:
            logger.debug("[MCP] GET /mcp headers suppressed (client gone)")
            return
        sock = self.connection
        last_ping = time.monotonic()
        try:
            while self.mcp_server._running:
                # Prompt disconnect detection: the kernel reports FIN/RST
                # as readability; without this we only notice the peer is
                # gone on the next 15 s ping write.
                if sock is not None:
                    try:
                        readable, _, _ = select.select([sock], [], [], 1.0)
                        if readable and sock.recv(1, socket.MSG_PEEK) == b"":
                            break
                    except (OSError, socket.error, ConnectionResetError,
                            BrokenPipeError):
                        break
                if time.monotonic() - last_ping >= 15:
                    try:
                        self.wfile.write(b": ping\n\n")
                        self.wfile.flush()
                    except (BrokenPipeError, ConnectionResetError,
                            ConnectionAbortedError, OSError):
                        break
                    last_ping = time.monotonic()
        except (BrokenPipeError, ConnectionResetError,
                ConnectionAbortedError, OSError):
            pass
        try:
            self.wfile.flush()
        except Exception:
            pass

    def _handle_sse_get(self) -> None:
        # Legacy SSE transport: client GETs /sse, receives an `endpoint`
        # event with its session id, then POSTs to /sse?session=<id>.
        conn = _McpSseConnection(self.wfile)
        with self.mcp_server._sse_lock:
            self.mcp_server._sse_connections[conn.session_id] = conn
        try:
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.send_cors_headers()
            self.end_headers()
            if not conn.send_event("endpoint", f"/sse?session={conn.session_id}"):
                return
            sock = self.connection
            if sock is not None:
                try:
                    sock.settimeout(1.0)
                except OSError:
                    pass
            last_ping = time.monotonic()
            while conn.alive and self.mcp_server._running:
                if sock is not None:
                    try:
                        readable, _, _ = select.select([sock], [], [], 1.0)
                        if readable and sock.recv(1, socket.MSG_PEEK) == b"":
                            break
                    except (OSError, socket.error, ConnectionResetError,
                            BrokenPipeError):
                        break
                else:
                    time.sleep(1)
                if time.monotonic() - last_ping > 30:
                    if not conn.send_event("ping", {}):
                        break
                    last_ping = time.monotonic()
        finally:
            conn.alive = False
            with self.mcp_server._sse_lock:
                self.mcp_server._sse_connections.pop(conn.session_id, None)

    def do_DELETE(self):
        if not self._check_api_request():
            return
        try:
            parsed = urlparse(self.path)
            if parsed.path == "/sse":
                query = parse_qs(parsed.query)
                session_id = query.get("session", [None])[0]
                if session_id is not None:
                    with self.mcp_server._sse_lock:
                        conn = self.mcp_server._sse_connections.pop(session_id, None)
                    if conn is not None:
                        conn.alive = False
                self.send_response(200)
                self.send_header("Content-Length", "0")
                self.send_cors_headers()
                self.end_headers()
                return
            if parsed.path != "/mcp":
                self._safe_send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.send_cors_headers()
            self.end_headers()
        except _DISCONNECT_ERRORS:
            logger.debug("[MCP] DELETE reply suppressed (client gone)")


# Agents routinely quote numbers ("64") even when the schema says
# integer/boolean; the tool body then compares str with int and dies with
# "TypeError: '<=' not supported between instances of 'str' and 'int'"
# (cf. get_bytes/size). Normalize such scalars once, at the tools/call
# boundary, using each tool's own annotations as the source of truth.
_TRUE_LITERALS = frozenset({"true", "1", "yes", "y", "on"})
_FALSE_LITERALS = frozenset({"false", "0", "no", "n", "off"})


def _unwrap_annotation(annotation):
    """Reduce an annotation to ``(inner_type, enum_values, description)``.

    Peels ``Annotated[T, "desc", ...]`` (capturing the first string as a
    description), ``Optional[T]`` / ``T | None`` / ``Union[...]`` (keeping the
    single non-``None`` arm) and ``Literal[...]`` (capturing the allowed values
    as an enum and inferring the scalar type). ``inner_type`` is what drives
    the JSON-schema ``type``; ``enum_values``/``description`` are ``None`` when
    absent. Never raises — unknown shapes fall through unchanged.
    """
    desc = None
    enum_values = None
    if get_origin(annotation) is Annotated:
        args = get_args(annotation)
        if args:
            annotation = args[0]
            for extra in args[1:]:
                if isinstance(extra, str):
                    desc = extra
                    break
    # Optional[T] / T | None / Union[...] -> keep the non-None arm.
    if get_origin(annotation) is Union or (
            _UnionType is not None and isinstance(annotation, _UnionType)):
        non_none = [a for a in get_args(annotation) if a is not type(None)]
        if non_none:
            annotation = non_none[0]
    if get_origin(annotation) is Literal:
        enum_values = list(get_args(annotation))
        kinds = {type(v) for v in enum_values}
        annotation = kinds.pop() if len(kinds) == 1 else str
    return annotation, enum_values, desc


def _json_type_for(annotation) -> str:
    """Map a resolved Python type to a JSON-schema primitive type name."""
    if annotation is int:
        return "integer"
    if annotation is float:
        return "number"
    if annotation is bool:
        return "boolean"
    return "string"


def _json_safe_default(value) -> bool:
    """True if ``value`` is safe to emit verbatim as a JSON-schema default."""
    return isinstance(value, (str, int, float, bool, type(None)))


# Tool error convention (see the per-tool docs / README): a tool reports a
# HARD failure by returning a JSON object with a non-empty top-level ``error``
# string. The MCP boundary promotes that to ``isError: true`` so clients can
# detect failures programmatically instead of string-matching the content.
# Deliberately NOT treated as failures: ``error: null`` (a success payload that
# carries the field), soft notes under a different key (e.g. ``warning``), and
# per-item errors nested inside a list/batch result (top-level is then a list).
def _parse_structured(result):
    """Best-effort parse of a tool result into structured form.

    Tool bodies return pre-serialized JSON strings; parse them back so a
    top-level ``error`` can be detected and ``structuredContent`` can carry the
    real object. Returns the parsed object, or the original value when it is
    not JSON text.
    """
    if isinstance(result, (dict, list)):
        return result
    if isinstance(result, str):
        try:
            return json.loads(result)
        except (ValueError, TypeError):
            return result
    return result


def _is_tool_error(parsed) -> bool:
    """True iff ``parsed`` is a dict with a non-empty top-level ``error`` str."""
    if isinstance(parsed, dict):
        err = parsed.get("error")
        return isinstance(err, str) and bool(err.strip())
    return False


_AUDIT_VALUE_MAX = 200
_AUDIT_BLOB_MAX = 2048


def _sanitize_audit_args(args) -> dict:
    """Shallow, size-bounded copy of tool args for the audit log.

    Each value is stringified and truncated (``execute_script`` code /
    ``py_eval`` expressions can be huge); the whole blob is capped too. Marks
    truncation with a trailing ellipsis so a reviewer knows it was clipped.
    """
    out: dict = {}
    if not isinstance(args, dict):
        return {"_args": str(args)[:_AUDIT_VALUE_MAX]}
    total = 0
    for k, v in args.items():
        try:
            s = v if isinstance(v, str) else json.dumps(v, default=str)
        except Exception:
            s = str(v)
        if len(s) > _AUDIT_VALUE_MAX:
            s = s[:_AUDIT_VALUE_MAX] + "\u2026"
        total += len(s)
        if total > _AUDIT_BLOB_MAX:
            out["_truncated"] = True
            break
        out[str(k)] = s
    return out


def _coerce_scalar(value, annotation):
    """Coerce a stringified JSON scalar to ``annotation`` (int/float/bool).

    Returns ``value`` untouched for non-strings, unsupported annotations and
    unparsable text, so the tool keeps reporting its own error message.
    """
    annotation, _enum, _desc = _unwrap_annotation(annotation)
    if not isinstance(value, str):
        return value
    text = value.strip()
    if annotation is bool:
        lowered = text.lower()
        if lowered in _TRUE_LITERALS:
            return True
        if lowered in _FALSE_LITERALS:
            return False
        return value
    if annotation is int:
        try:
            return int(text, 0)
        except (TypeError, ValueError):
            pass
        try:
            num = float(text)
        except (TypeError, ValueError):
            return value
        return int(num) if num.is_integer() else value
    if annotation is float:
        try:
            return float(text)
        except (TypeError, ValueError):
            return value
    return value


class McpServer:
    def __init__(self, name: str, version: str = "1.0.0", *, extensions: dict | None = None):
        self.name = name
        self.version = version
        self.cors_allowed_origins = self.cors_localhost
        self.post_body_limit = 10 * 1024 * 1024
        self.tools = McpRpcRegistry()
        self.resources = McpRpcRegistry()
        self.prompts = McpRpcRegistry()

        self._http_server: Any = None
        self._server_thread: Any = None
        self._running = False
        self._http_sessions: dict[str, float] = {}
        self._http_sessions_lock = threading.Lock()
        self.http_session_ttl_sec = 24 * 60 * 60
        self.http_session_max_count = 4096
        self._enabled_extensions: set[str] = set()  # legacy; per-request groups live in thread-local
        self._extensions_registry = extensions if extensions is not None else {}
        self._sse_connections: dict[str, _McpSseConnection] = {}
        self._sse_lock = threading.Lock()
        self.require_streamable_http_session = False
        self.unsafe_tools: set[str] = set()
        # Auth token gating the dangerous surface (unsafe + extension tools).
        # None = auth disabled (loopback-only, legacy/open); when set, a request
        # must present the matching token (X-IDA-MCP-Token header or ?token=)
        # for unsafe/ext tools to be listed or callable. Read-only tools are
        # unaffected. Set by the host (see server.start_server).
        self.auth_token: str | None = None
        # Output backstop: a tool result whose text exceeds this many chars is
        # refused with an actionable isError instead of flooding the client's
        # context. 0 disables. Tweak via server.start_server / IDA_MCP_MAX_OUTPUT.
        self.max_output_chars: int = 512 * 1024
        # Introspection caches: tool signatures/hints never change after
        # registration, so ``get_type_hints`` + ``inspect.signature`` (and the
        # derived JSON schema) are computed once per tool instead of on every
        # tools/list and tools/call. Keyed by tool name.
        self._introspect_cache: dict[str, tuple] = {}
        self._schema_cache: dict[str, dict] = {}
        # Concurrency gate: IDA tools run serialized on the main thread,
        # so a second concurrent tools/call would only extend the UI
        # freeze. Fail fast with a retryable isError instead of piling up
        # execute_sync waiters. tools/list and ping stay ungated (no IDA).
        # Set max_concurrent_tools to 0/None to disable (unbounded, legacy);
        # assigning N > 0 rebuilds the gate with N slots (see the property).
        self._tool_gate: threading.Semaphore | None = None
        self._max_concurrent_tools: int | None = None
        self.max_concurrent_tools = 1
        # Per-tool metrics (item 07): call/error/busy counts + a bounded window
        # of recent durations for percentiles. Pure Python, no IDA; surfaced
        # via server_health. Updates happen in a tiny locked critical section
        # and never raise into the dispatch path.
        self._stats_lock = threading.Lock()
        self._stats: dict[str, dict] = {}
        self._stats_totals = {"calls": 0, "errors": 0, "busy": 0}
        self._stats_started = time.monotonic()
        # Optional audit trail of mutating (unsafe/ext) tool calls (item 08).
        # IDA_MCP_AUDIT=<path> appends JSONL; unset = disabled (default).
        self.audit_path: str | None = (os.environ.get("IDA_MCP_AUDIT", "").strip() or None)

        self.registry: JsonRpcRegistry = JsonRpcRegistry()
        # Unexpected exceptions return their full traceback to the client by
        # default (it helps agents self-correct). IDA_MCP_REDACT_ERRORS=1
        # sends only "Internal Error: <type>: <msg>" and logs the traceback
        # server-side instead (e.g. when untrusted clients can connect).
        self.redact_exceptions = os.environ.get(
            "IDA_MCP_REDACT_ERRORS", "").strip().lower() in ("1", "true", "yes")
        self.registry.methods["ping"] = self._mcp_ping
        self.registry.methods["initialize"] = self._mcp_initialize
        self.registry.methods["tools/list"] = self._mcp_tools_list
        self.registry.methods["tools/call"] = self._mcp_tools_call
        self.registry.methods["resources/list"] = self._mcp_resources_list
        self.registry.methods["resources/templates/list"] = self._mcp_resource_templates_list
        self.registry.methods["resources/read"] = self._mcp_resources_read
        self.registry.methods["prompts/list"] = self._mcp_prompts_list
        self.registry.methods["prompts/get"] = self._mcp_prompts_get
        self.registry.methods["notifications/initialized"] = self._mcp_notifications_initialized
        self.registry.methods["notifications/cancelled"] = self._mcp_notifications_cancelled

    # ---- concurrency gate ----
    @property
    def max_concurrent_tools(self) -> int | None:
        return self._max_concurrent_tools

    @max_concurrent_tools.setter
    def max_concurrent_tools(self, value: int | None) -> None:
        # A fresh semaphore per setting: in-flight calls keep (and release)
        # the semaphore they acquired, so resizing never corrupts a count.
        n = int(value or 0)
        self._max_concurrent_tools = value
        self._tool_gate = threading.Semaphore(n) if n > 0 else None

    def _try_enter_gate(self) -> tuple[bool, threading.Semaphore | None]:
        """Non-blocking gate entry: ``(admitted, semaphore_to_release)``."""
        gate = self._tool_gate
        if gate is None:
            return True, None
        if gate.acquire(blocking=False):
            return True, gate
        return False, None

    @property
    def redact_exceptions(self) -> bool:
        return self.tools.redact_exceptions

    @redact_exceptions.setter
    def redact_exceptions(self, value: bool) -> None:
        # One switch for every registry that can map an unexpected exception.
        for reg in (self.tools, self.resources, self.prompts, self.registry):
            reg.redact_exceptions = bool(value)

    # ---- decorators ----
    def tool(self, func: Callable) -> Callable:
        return self.tools.method(func)

    def resource(self, uri: str, *, name: str | None = None,
                 mime: str | None = None,
                 tool: str | None = None) -> Callable[[Callable], Callable]:
        """Register a resource reader.

        ``tool`` names the tool whose data the resource serves: the resource
        is then listed/readable only where that tool would be (profile,
        ``?unsafe=``, ``?ext=`` + token), so it can't widen the surface.
        """
        def decorator(func: Callable) -> Callable:
            setattr(func, "__resource_uri__", uri)
            if name:
                setattr(func, "__resource_name__", name)
            if mime:
                setattr(func, "__resource_mime__", mime)
            if tool:
                setattr(func, "__resource_tool__", tool)
            return self.resources.method(func)
        return decorator

    def prompt(self, func: Callable) -> Callable:
        return self.prompts.method(func)

    # ---- hosting ----
    def serve(self, host: str, port: int, *, background: bool = True,
              request_handler: type = McpHttpRequestHandler) -> None:
        if self._running:
            logger.info("[MCP] Server already running")
            return
        assert issubclass(request_handler, McpHttpRequestHandler)
        self._http_server = (_McpThreadingHTTPServer if background else _McpHTTPServer)(
            (host, port), request_handler, bind_and_activate=False
        )
        # Client disconnects during slow tools used to leave zombie
        # request threads that blocked stop() and piled up on the IDA
        # main-thread queue. Daemonize them and bound the backlog.
        try:
            self._http_server.daemon_threads = True  # type: ignore[attr-defined]
        except Exception:
            pass
        try:
            self._http_server.request_queue_size = 32
        except Exception:
            pass
        if sys.platform == "win32":
            self._http_server.allow_reuse_address = False
            self._http_server.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        else:
            self._http_server.allow_reuse_address = True
        setattr(self._http_server, "mcp_server", self)
        try:
            self._http_server.server_bind()
            self._http_server.server_activate()
        except OSError:
            self._http_server.server_close()
            self._http_server = None
            raise
        self._running = True
        _install_unraisable_hook()
        logger.info("[MCP] Server started at http://%s:%s/mcp", host, port)

        def serve_forever() -> None:
            try:
                self._http_server.serve_forever()
            except Exception:
                logger.exception("[MCP] Server error")
            finally:
                self._running = False

        if background:
            self._server_thread = threading.Thread(target=serve_forever, daemon=True)
            self._server_thread.start()
        else:
            serve_forever()

    def stop(self) -> None:
        if not self._running:
            return
        self._running = False
        if self._http_server is not None:
            try:
                self._http_server.shutdown()
                self._http_server.server_close()
            except Exception:
                pass
            self._http_server = None
        if self._server_thread is not None:
            self._server_thread.join(timeout=5)
            self._server_thread = None
        _uninstall_unraisable_hook()
        logger.info("[MCP] Server stopped")

    def stdio(self, stdin=None, stdout=None) -> None:
        stdin = stdin or sys.stdin.buffer
        stdout = stdout or sys.stdout.buffer
        while True:
            try:
                line = stdin.readline()
                if not line:
                    break
                line = line.strip()
                if not line:
                    continue
                response = self.registry.dispatch(line)
                if response is not None:
                    stdout.write(json.dumps(response).encode("utf-8") + b"\n")
                    stdout.flush()
            except (BrokenPipeError, KeyboardInterrupt):
                break

    # ---- session helpers ----
    def register_http_session(self, session_id: str) -> None:
        now = time.monotonic()
        with self._http_sessions_lock:
            self._http_sessions.pop(session_id, None)
            self._http_sessions[session_id] = now
            self._prune_sessions(now)

    def has_http_session(self, session_id: str) -> bool:
        now = time.monotonic()
        with self._http_sessions_lock:
            self._prune_sessions(now)
            if session_id not in self._http_sessions:
                return False
            self._http_sessions.pop(session_id, None)
            self._http_sessions[session_id] = now
            return True

    def _prune_sessions(self, now: float) -> None:
        if self.http_session_ttl_sec > 0:
            cutoff = now - self.http_session_ttl_sec
            expired = [s for s, t in self._http_sessions.items() if t < cutoff]
            for s in expired:
                self._http_sessions.pop(s, None)
        if self.http_session_max_count > 0:
            while len(self._http_sessions) > self.http_session_max_count:
                self._http_sessions.pop(next(iter(self._http_sessions)), None)

    def _auth_ok(self) -> bool:
        """True if the current request may access the unsafe/extension surface.

        Returns True when auth is disabled (``auth_token is None``). Otherwise
        the per-request token (header/query) must match in constant time.
        """
        return self._token_matches(getattr(_request_auth, "token", None))

    def _token_matches(self, provided: str | None) -> bool:
        """Constant-time token check; True when auth is disabled."""
        expected = self.auth_token
        if not expected:
            return True
        if not provided:
            return False
        try:
            return secrets.compare_digest(str(provided), str(expected))
        except Exception:
            return False

    # ---- metrics (item 07) ----
    def _record_call(self, name, *, errored=False, busy=False, duration_ms=None):
        """Update per-tool counters. Never raises into the dispatch path."""
        try:
            with self._stats_lock:
                s = self._stats.get(name)
                if s is None:
                    s = {"calls": 0, "errors": 0, "busy": 0,
                         "durations": deque(maxlen=200)}
                    self._stats[name] = s
                if busy:
                    s["busy"] += 1
                    self._stats_totals["busy"] += 1
                    return
                s["calls"] += 1
                self._stats_totals["calls"] += 1
                if errored:
                    s["errors"] += 1
                    self._stats_totals["errors"] += 1
                if duration_ms is not None:
                    s["durations"].append(duration_ms)
        except Exception:
            pass

    def get_stats(self, top: int = 25) -> dict:
        """Bounded, JSON-able per-tool metrics snapshot (for server_health)."""
        def _pct(sorted_ds, p):
            if not sorted_ds:
                return None
            k = min(len(sorted_ds) - 1, int(round((p / 100.0) * (len(sorted_ds) - 1))))
            return round(sorted_ds[k], 1)
        try:
            with self._stats_lock:
                items = []
                for name, s in self._stats.items():
                    ds = sorted(s["durations"])
                    items.append({
                        "name": name, "calls": s["calls"], "errors": s["errors"],
                        "busy": s["busy"], "p50_ms": _pct(ds, 50), "p95_ms": _pct(ds, 95),
                        "max_ms": round(ds[-1], 1) if ds else None,
                    })
                totals = dict(self._stats_totals)
                uptime = round(time.monotonic() - self._stats_started, 1)
        except Exception:
            return {"error": "stats_unavailable"}
        items.sort(key=lambda x: x["calls"], reverse=True)
        return {
            "uptime_sec": uptime,
            "total_calls": totals["calls"],
            "total_errors": totals["errors"],
            "total_busy": totals["busy"],
            "tools": items[:top] if top else items,
        }

    # ---- audit (item 08) ----
    def _write_audit(self, name, args, ok, error=None):
        """Append one JSONL record for a mutating call. Best-effort, opt-in."""
        path = self.audit_path
        if not path:
            return
        try:
            import datetime
            rec = {
                "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "tool": name,
                "ok": bool(ok),
                "unsafe": True,
                # "unsafe" is kept for log consumers written against it; the
                # level tells the two gated surfaces apart.
                "level": "dbg" if self._get_tool_extension(name) else "unsafe",
                "args": _sanitize_audit_args(args),
            }
            # The args preview is deliberately short, but for the script tools
            # the code IS the record: keep an integrity hash and the real
            # length so "what ran" can still be identified and verified.
            code = args.get("code") if isinstance(args, dict) else None
            if isinstance(code, str):
                rec["code_sha256"] = hashlib.sha256(
                    code.encode("utf-8", "replace")).hexdigest()
                rec["code_len"] = len(code)
            if error:
                rec["error"] = str(error)[:500]
            line = json.dumps(rec, separators=(",", ":"), default=str)
            with open(path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        except Exception:
            pass

    def _origin_allowed(self, origin: str) -> bool:
        if not origin:
            return False
        allowed = self.cors_allowed_origins
        if callable(allowed):
            return allowed(origin)
        if isinstance(allowed, str):
            allowed = [allowed]
        return "*" in allowed or origin in allowed

    def cors_localhost(self, origin: str) -> bool:
        from urllib.parse import urlparse as _up
        return _up(origin).hostname in ("localhost", "127.0.0.1", "::1")

    # ---- MCP protocol methods ----
    def _mcp_ping(self, _meta=None):
        return {}

    def _mcp_initialize(self, protocolVersion=None, capabilities=None, clientInfo=None,
                        _meta=None):
        if protocolVersion not in SUPPORTED_PROTOCOL_VERSIONS:
            protocolVersion = PREFERRED_PROTOCOL_VERSION
        caps: dict = {"tools": {}}
        # Advertise resources/prompts only when some are registered, so a client
        # never sees an empty capability it can't use.
        if self.resources.methods:
            caps["resources"] = {"subscribe": False, "listChanged": False}
        if self.prompts.methods:
            caps["prompts"] = {}
        return {
            "protocolVersion": protocolVersion,
            "capabilities": caps,
            "serverInfo": {"name": self.name, "version": self.version},
        }

    def _mcp_tools_list(self, _meta=None):
        unknown = _unknown_profile()
        if unknown is not None:
            raise JsonRpcException(-32602, _unknown_profile_error(unknown))
        # Without a valid token the dangerous surface (unsafe + extension
        # tools) stays hidden, exactly as if ?unsafe=/?ext= were absent.
        auth_ok = self._auth_ok()
        unsafe_allowed = getattr(_unsafe_per_thread, "allowed", False) and auth_ok
        enabled = _enabled_extension_groups() if auth_ok else set()
        _profile_name, profile_set = _active_profile()
        tools = []
        for func_name, func in self.tools.methods.items():
            group = self._get_tool_extension(func_name)
            if group is not None and group not in enabled:
                continue
            if func_name in self.unsafe_tools and not unsafe_allowed:
                continue
            if profile_set is not None and func_name not in profile_set:
                continue
            tools.append(self._generate_tool_schema(func_name, func))
        return {"tools": tools}

    def _get_tool_extension(self, func_name: str):
        for group, tools in self._extensions_registry.items():
            if func_name in tools:
                return group
        return None

    def _introspect(self, func_name, func):
        """Return cached ``(type_hints, signature_parameters)`` for a tool."""
        cached = self._introspect_cache.get(func_name)
        if cached is not None:
            return cached
        try:
            hints = get_type_hints(func, include_extras=True)
        except Exception:
            hints = {}
        try:
            parameters = inspect.signature(func).parameters
        except (TypeError, ValueError):
            parameters = {}
        self._introspect_cache[func_name] = (hints, parameters)
        return hints, parameters

    def _generate_tool_schema(self, func_name, func):
        cached = self._schema_cache.get(func_name)
        if cached is not None:
            return cached
        hints, parameters = self._introspect(func_name, func)
        props = {}
        required = []
        for pname, param in parameters.items():
            if pname in ("_meta",):
                continue
            annotation = hints.get(pname, param.annotation)
            inner, enum_values, desc = _unwrap_annotation(annotation)
            prop = {"type": _json_type_for(inner)}
            if desc:
                prop["description"] = desc
            if enum_values is not None:
                prop["enum"] = enum_values
            if (param.default is not inspect.Parameter.empty
                    and _json_safe_default(param.default)):
                prop["default"] = param.default
            props[pname] = prop
            if param.default is inspect.Parameter.empty:
                required.append(pname)
        schema = {
            "name": func_name,
            "description": (func.__doc__ or "").strip(),
            "inputSchema": {"type": "object", "properties": props},
        }
        if required:
            schema["inputSchema"]["required"] = required
        self._schema_cache[func_name] = schema
        return schema

    def _coerce_tool_arguments(self, name: str, arguments):
        """Coerce stringified scalars in ``arguments`` to annotated types.

        Best-effort and per-argument: values whose annotation is not
        ``int``/``float``/``bool`` (or that cannot be parsed) are left alone,
        and any introspection failure returns ``arguments`` unchanged.
        """
        if not isinstance(arguments, dict) or not arguments:
            return arguments
        func = self.tools.methods.get(name)
        if func is None:
            return arguments
        hints, parameters = self._introspect(name, func)
        coerced = None
        for pname, value in arguments.items():
            if not isinstance(value, str):
                continue
            annotation = hints.get(pname)
            if annotation is None:
                param = parameters.get(pname)
                annotation = getattr(param, "annotation", None)
            if annotation is None:
                continue
            new_value = _coerce_scalar(value, annotation)
            if new_value is not value:
                if coerced is None:
                    coerced = dict(arguments)
                coerced[pname] = new_value
        return coerced if coerced is not None else arguments

    def _tool_access_error(self, name: str) -> str | None:
        """Why the current request may NOT use tool ``name`` (None = allowed).

        Single source of truth for the unsafe / extension / token / profile
        gates, shared by tools/call and tool-backed resources.
        """
        auth_ok = self._auth_ok()
        unknown = _unknown_profile()
        if unknown is not None:
            return _unknown_profile_error(unknown)
        token_hint = (f"Tool '{name}' requires a valid auth token. Pass it as the "
                      f"X-IDA-MCP-Token header or ?token= (printed to IDA on startup).")
        unsafe_requested = getattr(_unsafe_per_thread, "allowed", False)
        if name in self.unsafe_tools and not (unsafe_requested and auth_ok):
            if unsafe_requested and not auth_ok:
                return token_hint
            return f"Tool '{name}' requires unsafe mode. Add ?unsafe=true to the endpoint URL."
        tool_group = self._get_tool_extension(name)
        enabled_groups = _enabled_extension_groups() if auth_ok else set()
        if tool_group is not None and tool_group not in enabled_groups:
            if tool_group in _enabled_extension_groups() and not auth_ok:
                return token_hint
            return (f"Tool '{name}' requires extension '{tool_group}'. "
                    f"Add ?ext={tool_group} to the endpoint URL.")
        profile_name, profile_set = _active_profile()
        if profile_set is not None and name not in profile_set:
            return (f"Tool '{name}' is not in profile '{profile_name}'. "
                    f"Reconnect with ?profile=readonly (or no profile) to unlock more tools.")
        return None

    def _is_audited(self, name: str) -> bool:
        return name in self.unsafe_tools or self._get_tool_extension(name) is not None

    def _mcp_tools_call(self, name, arguments=None, _meta=None):
        denied = self._tool_access_error(name)
        if denied is not None:
            return {
                "content": [{"type": "text", "text": denied}],
                "isError": True,
            }
        # A list/scalar would reach the registry as positional arguments
        # (`func(*params)`), skipping the schema and the scalar coercion.
        if arguments is not None and not isinstance(arguments, dict):
            raise JsonRpcException(
                -32602, "'arguments' must be a JSON object, got "
                        f"{type(arguments).__name__}")
        admitted, gate = self._try_enter_gate()
        if not admitted:
            logger.debug("[MCP] tools/call %s rejected: server busy", name)
            self._record_call(name, busy=True)
            return {
                "content": [{
                    "type": "text",
                    "text": (f"Server busy: another tool is running on the IDA main thread. "
                             f"Retry '{name}' shortly (sequential calls, no parallel fan-out).")
                }],
                "isError": True,
                "structuredContent": {"busy": True, "tool": name},
            }
        request_id = get_current_request_id()
        if request_id is not None:
            register_pending_request(request_id)
        _t0 = time.perf_counter()
        # Pessimistic defaults: an unexpected exception escaping below is
        # still recorded (and audited) as a failure.
        _errored = True
        _error_text: str | None = "internal error"
        try:
            arguments = self._coerce_tool_arguments(name, arguments)
            tool_response = self.tools.dispatch({
                "jsonrpc": "2.0",
                "method": name,
                "params": arguments,
                "id": None,
            })
            if tool_response and "error" in tool_response:
                error = tool_response["error"]
                _error_text = error.get("message", "Unknown error")
                return {
                    "content": [{"type": "text", "text": _error_text}],
                    "isError": True,
                }
            result = tool_response.get("result") if tool_response else None
            parsed = _parse_structured(result)
            # content.text is model-readable text. Tool bodies already encode
            # structured data to a JSON string, so emit a string result
            # verbatim and only serialize a non-string result (int/dict/...),
            # avoiding the double-encoding json.dumps(str) would produce.
            if isinstance(result, str):
                text = result
            else:
                text = json.dumps(result, separators=(",", ":"))
            cap = self.max_output_chars
            if cap and len(text) > cap:
                _error_text = f"output_too_large ({len(text)} > {cap} chars)"
                return {
                    "content": [{"type": "text", "text": (
                        f"Output too large: {len(text)} chars exceed the {cap}-char cap. "
                        f"Narrow the request (use the tool's limit/offset or a tighter "
                        f"filter), or raise IDA_MCP_MAX_OUTPUT.")}],
                    "structuredContent": {"error": "output_too_large",
                                          "size": len(text), "cap": cap, "tool": name},
                    "isError": True,
                }
            structured = parsed if isinstance(parsed, dict) else {"result": parsed}
            _errored = _is_tool_error(parsed)
            _error_text = parsed["error"] if _errored else None
            return {
                "content": [{"type": "text", "text": text}],
                "structuredContent": structured,
                "isError": _errored,
            }
        finally:
            if request_id is not None:
                unregister_pending_request(request_id)
            if gate is not None:
                try:
                    gate.release()
                except Exception:
                    pass
            # Metrics + optional audit for every executed call (gate on or
            # off), after releasing the gate so file I/O never extends the
            # main-thread hold.
            self._record_call(name, errored=_errored,
                              duration_ms=(time.perf_counter() - _t0) * 1000.0)
            if self.audit_path and self._is_audited(name):
                self._write_audit(name, arguments, ok=not _errored,
                                  error=_error_text if _errored else None)

    def _mcp_notifications_initialized(self):
        return None

    def _mcp_notifications_cancelled(self, requestId=None, _meta=None):
        if requestId is not None:
            cancel_request(requestId)
        return None

    def _resource_access_error(self, func) -> str | None:
        backing = getattr(func, "__resource_tool__", None)
        return self._tool_access_error(backing) if backing else None

    def _mcp_resources_list(self, _meta=None):
        resources = []
        for func in self.resources.methods.values():
            uri = getattr(func, "__resource_uri__", None)
            if not uri:
                continue
            if self._resource_access_error(func) is not None:
                continue
            resources.append({
                "uri": uri,
                "name": getattr(func, "__resource_name__", func.__name__),
                "description": (func.__doc__ or "").strip(),
                "mimeType": getattr(func, "__resource_mime__", "application/json"),
            })
        return {"resources": resources}

    def _mcp_resource_templates_list(self, _meta=None):
        return {"resourceTemplates": []}

    def _mcp_resources_read(self, uri, _meta=None):
        target = None
        for func in self.resources.methods.values():
            if getattr(func, "__resource_uri__", None) == uri:
                target = func
                break
        if target is None:
            raise JsonRpcException(-32602, f"Unknown resource: {uri}")
        denied = self._resource_access_error(target)
        if denied is not None:
            raise JsonRpcException(-32002, f"Resource {uri} unavailable: {denied}")
        # Same admission as tools/call: readers run IDA work on the main
        # thread, so they must not overlap a running tool (UI freeze, and a
        # pumped wait box could re-enter @idasync mid-tool).
        stat_name = f"resource:{uri}"
        admitted, gate = self._try_enter_gate()
        if not admitted:
            self._record_call(stat_name, busy=True)
            raise JsonRpcException(
                -32000, f"Server busy: another tool is running on the IDA main thread. "
                        f"Retry reading {uri} shortly.", {"busy": True})
        t0 = time.perf_counter()
        errored = True
        try:
            result = target()
            errored = False
        finally:
            if gate is not None:
                try:
                    gate.release()
                except Exception:
                    pass
            self._record_call(stat_name, errored=errored,
                              duration_ms=(time.perf_counter() - t0) * 1000.0)
        text = result if isinstance(result, str) else json.dumps(result, default=str)
        cap = self.max_output_chars
        if cap and len(text) > cap:
            raise JsonRpcException(
                -32000, f"Output too large: resource {uri} is {len(text)} chars, over the "
                        f"{cap}-char cap. Use the backing tool with limit/offset, or raise "
                        f"IDA_MCP_MAX_OUTPUT.",
                {"error": "output_too_large", "size": len(text), "cap": cap})
        mime = getattr(target, "__resource_mime__", None)
        if mime is None:
            mime = "application/json"
            try:
                if not isinstance(json.loads(text), (dict, list)):
                    mime = "text/plain"
            except Exception:
                mime = "text/plain"
        return {"contents": [{"uri": uri, "mimeType": mime, "text": text}]}

    def _mcp_prompts_list(self, _meta=None):
        prompts = []
        for name, func in self.prompts.methods.items():
            args = []
            try:
                for p in inspect.signature(func).parameters.values():
                    if p.name.startswith("_"):
                        continue
                    args.append({"name": p.name,
                                 "required": p.default is inspect.Parameter.empty})
            except (TypeError, ValueError):
                pass
            prompts.append({"name": name,
                            "description": (func.__doc__ or "").strip(),
                            "arguments": args})
        return {"prompts": prompts}

    def _mcp_prompts_get(self, name, arguments=None, _meta=None):
        func = self.prompts.methods.get(name)
        if func is None:
            raise JsonRpcException(-32602, f"Unknown prompt: {name}")
        result = func(**(arguments or {}))
        if isinstance(result, dict) and "messages" in result:
            return result
        if isinstance(result, str):
            messages = [{"role": "user",
                         "content": {"type": "text", "text": result}}]
        elif isinstance(result, list):
            messages = result
        else:
            messages = [{"role": "user",
                         "content": {"type": "text",
                                     "text": json.dumps(result, default=str)}}]
        return {"description": (func.__doc__ or "").strip(), "messages": messages}
