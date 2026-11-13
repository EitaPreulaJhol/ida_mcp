"""MCP tool definitions and server hosting for ida_mcp.

Tools are declared with ``@tool`` + ``@idasync`` so they run on the IDA main
thread via the result-container sync (no deadlock). The server is hosted with
the vendored zeromcp ``McpServer`` over stdlib ``ThreadingHTTPServer``.
"""
import errno
import fnmatch
import json
import logging
import os
import signal
import sys
import threading
import time

import ida_auto
import ida_funcs
import ida_hexrays
import ida_kernwin
import ida_lines
import idaapi
import idc
import idautils

from .rpc import tool, unsafe, MCP_SERVER
from .sync import idasync, IDAError, hard_interrupt
from .sync import ensure_analysis
from .api_python import _run_code
from .api_analysis import parse_addr, _cap_lines, _as_int
from .discovery import (discover_instances, register_instance,
                        unregister_instance)

# Import new API modules to trigger @tool registrations
from . import api_typeinfo   # noqa: F401
from . import api_segments   # noqa: F401
from . import api_functions  # noqa: F401
from . import api_instructions  # noqa: F401
from . import api_info       # noqa: F401
from . import api_comments   # noqa: F401
from . import api_search     # noqa: F401
from . import api_modify     # noqa: F401
from . import api_entries    # noqa: F401
from . import api_names      # noqa: F401
from . import api_composite  # noqa: F401
from . import api_query      # noqa: F401
from . import api_memory     # noqa: F401
from . import api_xrefs      # noqa: F401
from . import api_strings    # noqa: F401
from . import api_hexrays    # noqa: F401
from . import api_debug      # noqa: F401
from . import api_hooks      # noqa: F401
from . import api_sigmaker   # noqa: F401
from . import compat         # noqa: F401


_SERVER_START_TIME = time.monotonic()
_OWN_PORT: int | None = None


def _auto_analysis_ready() -> bool | None:
    fn = getattr(ida_auto, "auto_is_ok", None)
    if not callable(fn):
        return None
    try:
        return bool(fn())
    except Exception:
        return None


def _hexrays_ready() -> bool:
    fn = getattr(ida_hexrays, "init_hexrays_plugin", None)
    if not callable(fn):
        return False
    try:
        return bool(fn())
    except Exception:
        return False


def _format_result(res: dict) -> str:
    parts = []
    if res.get("result"):
        parts.append(res["result"])
    if res.get("stdout"):
        parts.append(res["stdout"])
    if res.get("stderr"):
        parts.append(f"[stderr]\n{res['stderr']}")
    return "\n".join(parts) if parts else "(no output)"


@tool
@idasync
@unsafe
@hard_interrupt
def execute_script(code: str) -> str:
    """Execute arbitrary IDA Python code on the main thread.

    Assign to ``result`` (or ``__result__``) to return a value; stdout/stderr
    and IDA message-window output are captured and returned.

    Runs on the IDA main thread: the IDA UI is frozen and every other tool
    call is refused ("Server busy") until it returns. It is interrupted at the
    tool timeout (default 60s, IDA_MCP_TOOL_TIMEOUT_SEC) with partial output.
    Keep each call short: batch large loops (N items per call, resume from
    the last printed address) and print progress.
    """
    res = _run_code(code)
    if res.get("error"):
        raise IDAError(_format_result(res))
    return _format_result(res)


@tool
@idasync
def get_functions(filter_pattern: str = "*", limit: int = 1000,
                  offset: int = 0) -> str:
    """List functions whose name matches a glob pattern (fnmatch).

    Paginated: returns at most ``limit`` functions starting at ``offset``
    (``limit=0`` means no cap). A full page means more may follow — advance
    ``offset`` to continue. Use ``filter_pattern`` to narrow instead of paging.
    Returns ``{data, total, offset, count, limit}``, the same pagination shape
    as the other listing tools.
    """
    ensure_analysis()
    limit = _as_int(limit, 1000)
    offset = max(_as_int(offset, 0), 0)
    funcs = []
    for ea in idautils.Functions():
        name = ida_funcs.get_func_name(ea)
        if fnmatch.fnmatch(name, filter_pattern):
            funcs.append({"address": hex(ea), "name": name})
    page = funcs[offset:] if limit <= 0 else funcs[offset:offset + limit]
    return json.dumps({"data": page, "total": len(funcs), "offset": offset,
                       "count": len(page), "limit": limit}, indent=2)


@tool
@idasync
def decompile_function(address: str) -> str:
    """Decompile the function at the given address or name using Hex-Rays."""
    ensure_analysis()
    try:
        addr = parse_addr(address)
    except ValueError as e:
        # The wrapper carries the same text; a chained duplicate adds nothing.
        raise IDAError(str(e)) from None
    func = ida_funcs.get_func(addr)
    if not func:
        raise IDAError(f"No function at {hex(addr)}")
    try:
        cfunc = ida_hexrays.decompile(func.start_ea)
    except Exception as e:
        raise IDAError(f"Decompilation failed: {e}") from e
    if cfunc is None:
        raise IDAError(f"Decompilation returned no result for {hex(func.start_ea)}")
    lines = [ida_lines.tag_remove(l.line) for l in cfunc.get_pseudocode()]
    code, total = _cap_lines("\n".join(lines), 2000)
    if total is not None:
        code += f"\n... [truncated {total} total lines; use analyze_function for a compact view]"
    return code


@tool
@idasync
def get_disassembly(address: str, limit: int = 20) -> str:
    """Get disassembly starting at the given address or name.

    ``limit``: maximum number of instructions to return; the deprecated
    ``count`` argument is mapped to ``limit`` by the server.
    """
    ensure_analysis()
    try:
        ea = parse_addr(address)
    except ValueError as e:
        raise IDAError(str(e)) from None
    lines = []
    for _ in range(limit):
        if ea == idaapi.BADADDR:
            break
        lines.append(f"{hex(ea)}: {ida_lines.generate_disasm_line(ea, 0)}")
        ea = idc.next_head(ea)
    return "\n".join(lines)


def _health_payload() -> dict:
    """Plain (non-synced) health dict — called from @idasync contexts.

    Must stay sync-free: ``server_warmup`` calls this from inside its own
    ``@idasync`` body, where a nested ``execute_sync`` would deadlock.
    """
    try:
        get_idb_path = getattr(idc, "get_idb_path", None)
        idb_path = get_idb_path() if callable(get_idb_path) else None
    except Exception:
        idb_path = None
    try:
        import ida_nalt as _nalt
        input_path = _nalt.get_input_file_path()
    except Exception:
        input_path = None
    try:
        imagebase = hex(idaapi.get_imagebase())
    except Exception:
        imagebase = None
    _pkg = sys.modules.get(__package__ or "ida_mcp")
    version = getattr(_pkg, "__version__", "unknown") if _pkg else "unknown"
    stats_fn = getattr(MCP_SERVER, "get_stats", None)
    stats = stats_fn() if callable(stats_fn) else None
    return {
        "status": "ok",
        "version": version,
        "stats": stats,
        "uptime_sec": round(time.monotonic() - _SERVER_START_TIME, 1),
        "idb_path": idb_path,
        "input_path": input_path,
        "imagebase": imagebase,
        "require_token": bool(getattr(MCP_SERVER, "require_token", False)),
        "auto_analysis_ready": _auto_analysis_ready(),
        "hexrays_ready": _hexrays_ready(),
    }


@tool
@idasync
def server_health() -> str:
    """Server and IDB health: uptime, paths, image base, analysis/hexrays status."""
    return json.dumps(_health_payload(), indent=2)


@tool
@idasync
def server_warmup() -> str:
    """Warm up caches (analysis wait, hexrays init, counts) with per-step timing."""
    import ida_nalt
    steps: list[dict] = []

    def _step(name, fn):
        start = time.monotonic()
        try:
            fn()
            steps.append({"step": name, "ok": True,
                          "ms": round((time.monotonic() - start) * 1000, 1)})
        except Exception as e:
            steps.append({"step": name, "ok": False,
                          "ms": round((time.monotonic() - start) * 1000, 1),
                          "error": str(e)})

    _step("auto_wait", ida_auto.auto_wait)
    _step("hexrays_init", _hexrays_ready)
    _step("segments", lambda: sum(1 for _ in idautils.Segments()))
    _step("functions", lambda: sum(1 for _ in idautils.Functions()))
    _step("imports", lambda: ida_nalt.get_import_module_qty())
    ok = all(s["ok"] for s in steps)
    return json.dumps({"ok": ok, "steps": steps,
                       "health": _health_payload()}, indent=2)


# Discovery reads files and probes TCP ports; it never touches the IDA SDK,
# so these two run on the HTTP worker thread (NOT @idasync): the probes
# (up to 1 s each) must not freeze the IDA UI on the main thread.
@tool
def list_instances() -> str:
    """List running IDA MCP instances found via filesystem discovery."""
    try:
        instances = discover_instances()
    except Exception as e:
        return json.dumps({"error": str(e)})
    return json.dumps({"instances": instances, "count": len(instances)}, indent=2)


@tool
def get_instance_info(port: int = 13337) -> str:
    """Get discovery info for the instance on ``port`` (host/pid/binary/idb)."""
    try:
        instances = discover_instances()
    except Exception as e:
        return json.dumps({"error": str(e)})
    for info in instances:
        if info.get("port") == port:
            return json.dumps(info, indent=2)
    return json.dumps({"port": port, "error": "No live instance on this port"})


# Grace period before the deferred stop runs: long enough for the
# close_instance reply to be written and flushed, short enough that the client
# sees the server go away almost immediately. Overridden by tests.
_CLOSE_INSTANCE_GRACE_SEC = 1.0
_CLOSE_PENDING = False


def _deferred_stop(port: int) -> None:
    """Stop the server after the close_instance reply has been delivered.

    The timer callback runs on its own thread, but stop_server() unhooks IDA
    hooks and touches the kernel.  Marshal the actual stop onto the IDA main
    thread when execute_sync is available; the tests' stub lacks it and falls
    back to the direct call.
    """
    global _CLOSE_PENDING
    try:
        stopped_on_main = False
        try:
            execute_sync = getattr(ida_kernwin, "execute_sync", None)
            # idalib has no UI message loop: execute_sync() queued from the
            # timer thread would never run (the host thread is not pumping),
            # so only marshal in the GUI.  The idalib path is safe to stop
            # directly (no hooks/UI to unhook).
            is_gui = True
            is_idaq = getattr(ida_kernwin, "is_idaq", None)
            if callable(is_idaq):
                is_gui = bool(is_idaq())
            if callable(execute_sync) and is_gui:
                def _stop_on_main() -> int:
                    stop_server(port)
                    return 0

                rc = execute_sync(
                    _stop_on_main,
                    getattr(ida_kernwin, "MFF_WRITE",
                            getattr(idaapi, "MFF_WRITE", 2)))
                stopped_on_main = rc != -1
        except Exception:
            stopped_on_main = False
        if not stopped_on_main:
            stop_server(port)
    finally:
        _CLOSE_PENDING = False


@tool
@idasync
@unsafe
def close_instance(port: int = 13337) -> str:
    """Stop the MCP server of the local instance on ``port``.

    **Unsafe** — requires ``?unsafe=true``. Only the local instance (the one
    serving this request) can be closed; other ports return an error since
    each IDA process owns exactly one server. Save the IDB first
    (``idb_save``) — closing does not save.

    Returns before stopping (the server goes away about a second later):
    stopping inline joined the HTTP thread on the IDA main thread, freezing the
    UI before the reply could even be written.
    """
    global _CLOSE_PENDING
    if _OWN_PORT is None or port != _OWN_PORT:
        return json.dumps({"port": port,
                           "error": "Can only close the local instance serving this request"})
    if _CLOSE_PENDING:
        return json.dumps({"ok": True, "port": port, "stopping": True,
                           "note": "already stopping"})
    _CLOSE_PENDING = True
    timer = threading.Timer(_CLOSE_INSTANCE_GRACE_SEC, _deferred_stop,
                            args=(port,))
    timer.daemon = True
    timer.start()
    return json.dumps({"ok": True, "port": port,
                       "stopping_in_ms": int(_CLOSE_INSTANCE_GRACE_SEC * 1000)})


def _env_flag(name: str) -> bool:
    """True for ``1``/``true``/``yes`` (the convention used by every flag)."""
    return os.getenv(name, "").strip().lower() in ("1", "true", "yes")


_LOOPBACK_BINDS = {"127.0.0.1", "::1", "localhost"}


def _is_loopback_bind(host: str) -> bool:
    return (host or "").strip().strip("[]").lower() in _LOOPBACK_BINDS


def _init_auth_token() -> str | None:
    """Resolve the auth token gating unsafe/debugger tools.

    - ``IDA_MCP_NO_AUTH=1`` disables auth (loopback-only, legacy/open).
    - ``IDA_MCP_TOKEN`` sets a stable token (useful for a fixed client config).
    - otherwise a fresh random token is generated each start.

    The token is NEVER written to the discovery file, so a local reader of that
    file cannot escalate to the unsafe surface.
    """
    import secrets
    if _env_flag("IDA_MCP_NO_AUTH"):
        return None
    env_token = os.getenv("IDA_MCP_TOKEN", "").strip()
    return env_token or secrets.token_urlsafe(24)


def _init_logging() -> None:
    """Opt-in logging so tool/main-thread telemetry is visible in IDA.

    Off by default. Set ``IDA_MCP_LOG`` to ``debug``/``info``/``1`` to route
    the ``ida_mcp`` package logs (e.g. per-tool main-thread hold times, server
    lifecycle) to the IDA output window. Useful for diagnosing UI freezes.
    """
    spec = os.getenv("IDA_MCP_LOG", "").strip().lower()
    if not spec:
        return
    level = {"1": logging.INFO, "true": logging.INFO, "info": logging.INFO,
             "debug": logging.DEBUG, "warning": logging.WARNING}.get(spec, logging.INFO)
    pkg_logger = logging.getLogger("ida_mcp")
    pkg_logger.setLevel(level)
    if any(getattr(h, "_ida_mcp", False) for h in pkg_logger.handlers):
        return  # already installed (server restarted in the same process)

    class _IdaMsgHandler(logging.Handler):
        _ida_mcp = True

        def emit(self, record):
            try:
                ida_kernwin.msg(self.format(record) + "\n")
            except Exception:
                pass

    handler = _IdaMsgHandler()
    handler.setFormatter(logging.Formatter("[ida-mcp] %(levelname)s %(name)s: %(message)s"))
    pkg_logger.addHandler(handler)


# How many ports after the requested one start_server tries when it is taken
# (typically by another IDA instance), so a second IDA does not just fail.
PORT_FALLBACK_RANGE = 9
# Windows: WSAEADDRINUSE, and WSAEACCES (what SO_EXCLUSIVEADDRUSE reports).
_ADDR_IN_USE_WINERRORS = (10048, 10013)


def _addr_in_use(exc: OSError) -> bool:
    return (exc.errno == errno.EADDRINUSE
            or getattr(exc, "winerror", None) in _ADDR_IN_USE_WINERRORS)


# SIGPIPE handling is scoped to the running server (not done at package
# import): a client disconnecting mid-write must not kill IDA, but merely
# importing ida_mcp must not change the signal disposition of every other
# plugin in the process either. The HTTP layer additionally swallows
# BrokenPipe/ConnectionReset, so this is belt-and-braces.
_PREV_SIGPIPE: object = None
_SIGPIPE_SAVED = False


def _ignore_sigpipe() -> None:
    global _PREV_SIGPIPE, _SIGPIPE_SAVED
    if _SIGPIPE_SAVED or not hasattr(signal, "SIGPIPE"):
        return
    try:
        _PREV_SIGPIPE = signal.getsignal(signal.SIGPIPE)
        _SIGPIPE_SAVED = True
        signal.signal(signal.SIGPIPE, signal.SIG_IGN)
    except (ValueError, OSError):
        _SIGPIPE_SAVED = False


def _restore_sigpipe() -> None:
    global _PREV_SIGPIPE, _SIGPIPE_SAVED
    if not _SIGPIPE_SAVED or not hasattr(signal, "SIGPIPE"):
        return
    try:
        signal.signal(signal.SIGPIPE, _PREV_SIGPIPE)  # type: ignore[arg-type]
    except (ValueError, OSError):
        pass
    _PREV_SIGPIPE = None
    _SIGPIPE_SAVED = False


def _serve_with_fallback(host: str, port: int) -> int:
    """Bind ``port`` or, if it is in use, the next free one in range.

    Returns the port actually bound. Errors other than "address in use"
    (bad host, permission) are raised at once; exhausting the range raises
    the last "in use" error with a hint.
    """
    last: OSError | None = None
    for candidate in range(port, min(port + PORT_FALLBACK_RANGE, 65535) + 1):
        try:
            MCP_SERVER.serve(host, candidate, background=True)
            return candidate
        except OSError as e:
            if not _addr_in_use(e):
                raise
            last = e
    raise OSError(
        last.errno if last else errno.EADDRINUSE,
        f"ports {port}-{port + PORT_FALLBACK_RANGE} on {host} are all in use "
        f"(other IDA instances?); free one or close an instance") from last


def start_server(host: str = "127.0.0.1", port: int = 13337) -> int:
    """Start the MCP HTTP server and register this instance for discovery.

    If ``port`` is taken (e.g. by another IDA instance) the next free port
    within ``PORT_FALLBACK_RANGE`` is used. Returns the port actually bound;
    callers must use it (not the requested one) for messages and stop.
    """
    global _OWN_PORT
    _init_logging()
    _ignore_sigpipe()
    cap = os.getenv("IDA_MCP_MAX_OUTPUT", "").strip()
    if cap:
        try:
            MCP_SERVER.max_output_chars = max(0, int(cap, 0))
        except ValueError:
            pass
    token = _init_auth_token()
    MCP_SERVER.auth_token = token
    MCP_SERVER.require_token = _env_flag("IDA_MCP_REQUIRE_TOKEN")
    requested = port
    port = _serve_with_fallback(host, requested)
    _OWN_PORT = port
    # A traceback can include source paths and database internals.  When the
    # socket is reachable off-machine, redact by default; an explicit
    # IDA_MCP_REDACT_ERRORS value (including 0) wins.
    if (not _is_loopback_bind(host)
            and os.environ.get("IDA_MCP_REDACT_ERRORS") is None):
        MCP_SERVER.redact_exceptions = True
        try:
            ida_kernwin.msg(
                "[ida-mcp] non-loopback bind: tracebacks are redacted "
                "(set IDA_MCP_REDACT_ERRORS=0 to expose them)\n")
        except Exception:
            pass
    if port != requested:
        ida_kernwin.msg(
            f"[ida-mcp] port {requested} is in use (another IDA instance?); "
            f"using {port} instead. Point clients at http://{host}:{port}/mcp "
            f"(list_instances shows every running instance).\n"
        )
    if token:
        ida_kernwin.msg(
            f"[ida-mcp] auth token for unsafe/debugger tools: {token}\n"
            f"[ida-mcp]   pass it as the X-IDA-MCP-Token header or ?token=<token>\n"
            f"[ida-mcp]   (read-only tools need no token; set IDA_MCP_NO_AUTH=1 to disable)\n"
        )
    else:
        ida_kernwin.msg(
            "[ida-mcp] auth DISABLED (IDA_MCP_NO_AUTH): unsafe tools reachable "
            "by any local client via ?unsafe=true\n"
        )
    if MCP_SERVER.require_token:
        if token:
            ida_kernwin.msg(
                "[ida-mcp] IDA_MCP_REQUIRE_TOKEN: every request needs the token "
                "(read-only tools included)\n"
            )
        else:
            ida_kernwin.msg(
                "[ida-mcp] WARNING: IDA_MCP_REQUIRE_TOKEN is set but auth is "
                "DISABLED (IDA_MCP_NO_AUTH); no token can be required\n"
            )
    try:
        pid = os.getpid()
        get_input_path = getattr(idc, "get_input_file_path", None)
        binary = get_input_path() if callable(get_input_path) else ""
        get_idb_path = getattr(idc, "get_idb_path", None)
        idb_path = get_idb_path() if callable(get_idb_path) else ""
        register_instance(host, port, pid, binary or "", idb_path or "", backend="gui")
    except Exception as e:  # noqa: BLE001 - registration is best-effort
        ida_kernwin.msg(f"[ida-mcp] instance registration failed: {e}\n")
    return port


def stop_server(port: int = 13337) -> None:
    """Stop the MCP HTTP server, remove agent-installed hooks, unregister.

    Runs on the IDA main thread (plugin run/term, or inside close_instance).
    """
    global _OWN_PORT
    MCP_SERVER.stop()
    _restore_sigpipe()
    _OWN_PORT = None
    try:
        removed = api_hooks.remove_all_hooks()
        if removed:
            ida_kernwin.msg(f"[ida-mcp] removed {len(removed)} hook(s) on stop: "
                            f"{', '.join(removed)}\n")
    except Exception as e:  # noqa: BLE001 - never block shutdown
        ida_kernwin.msg(f"[ida-mcp] hook cleanup failed: {e}\n")
    try:
        unregister_instance(port)
    except Exception:  # noqa: BLE001 - unregistration is best-effort
        pass


# ---- MCP resources / prompts (item 13) ----
# Read-only resources backed by existing tools. Readers are plain (NOT
# @idasync) and call the @idasync tool, so there is exactly one main-thread
# marshal and no nested execute_sync deadlock. ``tool=`` ties each resource
# to its backing tool: it is only listed/readable where that tool is
# (profile / unsafe / ext gates), and reads share the tools/call concurrency
# gate and output cap. Capabilities advertise these only because they are
# registered here.

@MCP_SERVER.resource("ida://health", name="server-health", mime="application/json",
                     tool="server_health")
def _resource_health():
    """Live server + IDB health (same payload as the server_health tool)."""
    return server_health()


@MCP_SERVER.resource("ida://triage", name="binary-triage", mime="application/json",
                     tool="survey_binary")
def _resource_triage():
    """One-call binary triage (same payload as the survey_binary tool)."""
    fn = MCP_SERVER.tools.methods.get("survey_binary")
    if fn is None:
        return json.dumps({"error": "survey_binary tool unavailable"})
    return fn()


@MCP_SERVER.prompt
def reverse_engineer(focus: str = "overview"):
    """Drive the connect -> triage -> escalate loop for the binary open in IDA."""
    return (
        "You are reverse-engineering the binary currently open in IDA Pro via "
        "ida_mcp.\n"
        "1. Call server_health to confirm the bridge is up.\n"
        "2. Call survey_binary for a one-shot triage (or read the ida://triage "
        "resource).\n"
        f"3. Focus of this session: {focus}.\n"
        "Escalate the endpoint ladder (triage -> readonly -> full -> unsafe -> "
        "dbg) only as the task needs, and ask before crossing into ?unsafe=true."
    )
