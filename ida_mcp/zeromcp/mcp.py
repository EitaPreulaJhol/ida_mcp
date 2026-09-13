"""Trimmed MCP server over stdlib HTTP (adapted from zeromcp 1.3.0).

Provides McpServer / McpRpcRegistry / McpHttpRequestHandler implementing the
MCP Streamable HTTP transport (POST /mcp, GET /mcp SSE, DELETE /mcp) plus the
legacy SSE transport (GET /sse, POST /sse?session=) on top of
ThreadingHTTPServer, so no external ASGI/uvicorn dependency is required.
"""
import gzip
import json
import logging
import select
import socket
import sys
import threading
import time
import uuid
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer, HTTPServer
from typing import Any, Callable
from urllib.parse import urlparse, parse_qs

from typing import get_type_hints, get_origin, get_args, Annotated

from .jsonrpc import (
    JsonRpcRegistry,
    JsonRpcException,
    get_current_request_id,
    register_pending_request,
    unregister_pending_request,
    cancel_request,
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


def _enabled_extension_groups() -> set[str]:
    return getattr(_request_extensions, "groups", set()) or set()


try:
    from ..profiles import get_profile as _get_profile_fn
except ImportError:  # standalone zeromcp use (tests) without the ida_mcp package
    _get_profile_fn = None

# Thread-local active profile: (name, tool-set or None). None set = unknown
# or absent profile -> no filtering (fail-open, documented).
_request_profile = threading.local()


def _active_profile() -> tuple[str | None, set[str] | None]:
    return getattr(_request_profile, "current", (None, None))


def _silent_unraisable(unraisable_args, unraisable_file=None):
    """Suppress ConnectionResetError / BrokenPipeError from background threads.

    The SSE keep-alive stream runs in its own thread, and a peer
    closing the connection during the 15s sleep can cause
    ConnectionResetError to surface in Python's unraisable hook
    after the thread has already exited.  The per-write try/except
    in ``do_GET`` catches it at the source, but this hook is a
    belt-and-suspenders fallback for any background thread that
    might be added later.
    """
    exc = unraisable_args.exc_value
    if isinstance(
        exc,
        (BrokenPipeError, ConnectionResetError, ConnectionAbortedError),
    ):
        return  # silent
    # Fall through to the default handler for anything else.
    sys.unraisablehook(unraisable_args, unraisable_file)


# Install the hook only if we can (i.e. when not under pytest, which
# sets its own unraisable hook).
try:
    sys.unraisablehook = _silent_unraisable
except Exception:
    pass


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
                "Content-Type, Accept, X-Requested-With, Mcp-Session-Id, Mcp-Protocol-Version",
            )

    def _check_api_request(self) -> bool:
        """Block browser traffic that violates the configured origin policy.

        Browsers can bypass passive CORS-only defenses during DNS rebinding
        because same-origin requests do not need CORS. Rejecting unexpected Host
        and Origin headers closes that gap while keeping direct clients working.
        """
        bound_host = self.server.server_address[0]
        if not _host_header_allowed_for_bind(bound_host, self.headers.get("Host")):
            self._safe_send_error(403, "Invalid Host")
            return False
        origin = self.headers.get("Origin", "")
        if origin and not self.mcp_server._origin_allowed(origin):
            self._safe_send_error(403, "Invalid Origin")
            return False
        return True

    def do_OPTIONS(self):
        if not self._check_api_request():
            return
        try:
            self.send_response(204)
            self.send_cors_headers(preflight=True)
            self.send_header("Content-Length", "0")
            self.end_headers()
        except _DISCONNECT_ERRORS:
            logger.debug("[MCP] OPTIONS reply suppressed (client gone)")

    def _parse_request_flags(self) -> None:
        """Parse per-request ?unsafe= / ?ext= / ?profile= into thread-locals."""
        _unsafe_per_thread.allowed = (
            self._get_query_param(self.path, "unsafe", "false").strip().lower() == "true"
        )
        _request_extensions.groups = self._parse_extensions(self.path)
        profile_name = self._get_query_param(self.path, "profile", "").strip().lower()
        profile_set = None
        if profile_name and _get_profile_fn is not None:
            try:
                profile_set = _get_profile_fn(profile_name)
            except Exception:
                profile_set = None
        _request_profile.current = (profile_name or None, profile_set)

    def _read_body(self) -> bytes | None:
        """Read the POST body honoring limits, chunked framing and encoding."""
        if "chunked" in self.headers.get("Transfer-Encoding", "").lower():
            raw = self._read_chunked()
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

    def _read_chunked(self) -> bytes:
        body = b""
        limit = self.mcp_server.post_body_limit
        while True:
            try:
                line = self.rfile.readline().split(b";")[0].strip()
                chunk_size = int(line, 16)
            except ValueError:
                break
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
        try:
            if encoding in ("gzip", "x-gzip"):
                return gzip.decompress(data)
            if encoding == "deflate":
                try:
                    return zlib.decompress(data)
                except zlib.error:
                    return zlib.decompress(data, -15)
        except Exception:
            self._safe_send_error(400, "Bad Content-Encoding")
            return None
        return data

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
        self._parse_request_flags()
        raw = self._read_body()
        if raw is None:
            return
        body = raw if raw else b"{}"
        try:
            request = json.loads(body.decode("utf-8")) if body else {}
        except Exception:
            request = {}

        mcp_session_id = self.headers.get("Mcp-Session-Id")

        # Dispatch
        response = self.mcp_server.registry.dispatch(request)

        # Session management: create a session id on initialize.
        if request.get("method") == "initialize":
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
        session_id = query.get("session", [None])[0]
        if session_id is None:
            self._safe_send_error(400, "Missing ?session for SSE POST")
            return
        with self.mcp_server._sse_lock:
            conn = self.mcp_server._sse_connections.get(session_id)
        if conn is None or not conn.alive:
            self._safe_send_error(400, f"No active SSE connection for session {session_id}")
            return
        self._parse_request_flags()
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


class McpServer:
    def __init__(self, name: str, version: str = "1.0.0", *, extensions: dict | None = None):
        self.name = name
        self.version = version
        self.cors_allowed_origins = self.cors_localhost
        self.post_body_limit = 10 * 1024 * 1024
        self.tools = McpRpcRegistry()
        self.resources = McpRpcRegistry()
        self.prompts = McpRpcRegistry()

        self._http_server = None
        self._server_thread = None
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
        # Concurrency gate: IDA tools run serialized on the main thread,
        # so a second concurrent tools/call would only extend the UI
        # freeze. Fail fast with a retryable isError instead of piling up
        # execute_sync waiters. tools/list and ping stay ungated (no IDA).
        # Set max_concurrent_tools to 0/None to disable (unbounded, legacy).
        self._tool_gate: threading.Semaphore = threading.Semaphore(1)
        self.max_concurrent_tools: int | None = 1

        self.registry = JsonRpcRegistry()
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

    # ---- decorators ----
    def tool(self, func: Callable) -> Callable:
        return self.tools.method(func)

    def resource(self, uri: str) -> Callable[[Callable], Callable]:
        def decorator(func: Callable) -> Callable:
            setattr(func, "__resource_uri__", uri)
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
            self._http_server.daemon_threads = True
        except Exception:
            pass
        try:
            self._http_server.request_queue_size = 32
        except Exception:
            pass
        import sys
        import socket
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
        logger.info("[MCP] Server stopped")

    def stdio(self, stdin=None, stdout=None) -> None:
        import sys
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

    def _mcp_initialize(self, protocolVersion, capabilities, clientInfo, _meta=None):
        return {
            "protocolVersion": protocolVersion,
            "capabilities": {
                "tools": {},
                "resources": {"subscribe": False, "listChanged": False},
                "prompts": {},
            },
            "serverInfo": {"name": self.name, "version": self.version},
        }

    def _mcp_tools_list(self, _meta=None):
        unsafe_allowed = getattr(_unsafe_per_thread, "allowed", False)
        enabled = _enabled_extension_groups()
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

    def _generate_tool_schema(self, func_name, func):
        import inspect
        try:
            hints = get_type_hints(func, include_extras=True)
        except Exception:
            hints = {}
        sig = inspect.signature(func)
        props = {}
        required = []
        for pname, param in sig.parameters.items():
            if pname in ("_meta",):
                continue
            annotation = hints.get(pname, param.annotation)
            typ = "string"
            desc = ""
            if get_origin(annotation) is Annotated:
                args = get_args(annotation)
                annotation = args[0]
                if len(args) > 1 and isinstance(args[1], str):
                    desc = args[1]
            if annotation is int:
                typ = "integer"
            elif annotation is float:
                typ = "number"
            elif annotation is bool:
                typ = "boolean"
            prop = {"type": typ}
            if desc:
                prop["description"] = desc
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
        return schema

    def _mcp_tools_call(self, name, arguments=None, _meta=None):
        unsafe_allowed = getattr(_unsafe_per_thread, "allowed", False)
        # Gate unsafe tools when unsafe mode is not enabled.
        if name in self.unsafe_tools and not unsafe_allowed:
            return {
                "content": [{
                    "type": "text",
                    "text": f"Tool '{name}' requires unsafe mode. Add ?unsafe=true to the endpoint URL."
                }],
                "isError": True,
            }
        tool_group = self._get_tool_extension(name)
        if tool_group is not None and tool_group not in _enabled_extension_groups():
            return {
                "content": [{"type": "text", "text": f"Tool '{name}' requires extension '{tool_group}'. Add ?ext={tool_group} to the endpoint URL."}],
                "isError": True,
            }
        _profile_name, profile_set = _active_profile()
        if profile_set is not None and name not in profile_set:
            hint = "Reconnect with ?profile=readonly (or no profile) to unlock more tools."
            return {
                "content": [{"type": "text", "text": f"Tool '{name}' is not in profile '{_profile_name}'. {hint}"}],
                "isError": True,
            }
        gate = self._tool_gate if (self.max_concurrent_tools or 0) > 0 else None
        gate_acquired = False
        if gate is not None:
            gate_acquired = gate.acquire(blocking=False)
            if not gate_acquired:
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
        try:
            tool_response = self.tools.dispatch({
                "jsonrpc": "2.0",
                "method": name,
                "params": arguments,
                "id": None,
            })
            if tool_response and "error" in tool_response:
                error = tool_response["error"]
                return {
                    "content": [{"type": "text", "text": error.get("message", "Unknown error")}],
                    "isError": True,
                }
            result = tool_response.get("result") if tool_response else None
            return {
                "content": [{"type": "text", "text": json.dumps(result, separators=(",", ":"))}],
                "structuredContent": result if isinstance(result, dict) else {"result": result},
                "isError": False,
            }
        finally:
            if request_id is not None:
                unregister_pending_request(request_id)
            if gate_acquired:
                try:
                    gate.release()
                except Exception:
                    pass

    def _mcp_notifications_initialized(self):
        return None

    def _mcp_notifications_cancelled(self, requestId=None, _meta=None):
        if requestId is not None:
            cancel_request(requestId)
        return None

    def _mcp_resources_list(self, _meta=None):
        return {"resources": []}

    def _mcp_resource_templates_list(self, _meta=None):
        return {"resourceTemplates": []}

    def _mcp_resources_read(self, uri, _meta=None):
        raise JsonRpcException(-32602, f"Unknown resource: {uri}")

    def _mcp_prompts_list(self, _meta=None):
        return {"prompts": []}

    def _mcp_prompts_get(self, name, arguments=None, _meta=None):
        raise JsonRpcException(-32602, f"Unknown prompt: {name}")
