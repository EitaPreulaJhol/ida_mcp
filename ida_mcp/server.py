"""MCP tool definitions and server hosting for ida_mcp.

Tools are declared with ``@tool`` + ``@idasync`` so they run on the IDA main
thread via the result-container sync (no deadlock). The server is hosted with
the vendored zeromcp ``McpServer`` over stdlib ``ThreadingHTTPServer``.
"""
import fnmatch
import json
import logging
import os
import time

import ida_auto
import ida_funcs
import ida_hexrays
import ida_kernwin
import ida_lines
import ida_ua
import idaapi
import idc
import idautils

from .rpc import tool, unsafe, MCP_SERVER
from .sync import idasync, IDAError
from .api_python import _run_code
from .api_analysis import parse_addr, _cap_lines
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
def execute_script(code: str) -> str:
    """Execute arbitrary IDA Python code on the main thread.

    Assign to ``result`` (or ``__result__``) to return a value; stdout/stderr
    and IDA message-window output are captured and returned.
    """
    return _format_result(_run_code(code))


@tool
@idasync
def get_functions(filter_pattern: str = "*") -> str:
    """List functions whose name matches a glob pattern (fnmatch)."""
    ida_auto.auto_wait()
    funcs = []
    for ea in idautils.Functions():
        name = ida_funcs.get_func_name(ea)
        if fnmatch.fnmatch(name, filter_pattern):
            funcs.append({"address": hex(ea), "name": name})
    return json.dumps(funcs, indent=2)


@tool
@idasync
def decompile_function(address: str) -> str:
    """Decompile the function at the given address or name using Hex-Rays."""
    ida_auto.auto_wait()
    try:
        addr = parse_addr(address)
    except ValueError as e:
        raise IDAError(str(e))
    func = ida_funcs.get_func(addr)
    if not func:
        raise IDAError(f"No function at {hex(addr)}")
    try:
        cfunc = ida_hexrays.decompile(func.start_ea)
    except Exception as e:
        raise IDAError(f"Decompilation failed: {e}")
    if cfunc is None:
        raise IDAError(f"Decompilation returned no result for {hex(func.start_ea)}")
    lines = [ida_lines.tag_remove(l.line) for l in cfunc.get_pseudocode()]
    code, total = _cap_lines("\n".join(lines), 2000)
    if total is not None:
        code += f"\n... [truncated {total} total lines; use analyze_function for a compact view]"
    return code


@tool
@idasync
def get_disassembly(address: str, count: int = 20) -> str:
    """Get disassembly starting at the given address or name."""
    ida_auto.auto_wait()
    try:
        ea = parse_addr(address)
    except ValueError as e:
        raise IDAError(str(e))
    lines = []
    for _ in range(count):
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
    return {
        "status": "ok",
        "uptime_sec": round(time.monotonic() - _SERVER_START_TIME, 1),
        "idb_path": idb_path,
        "input_path": input_path,
        "imagebase": imagebase,
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


@tool
@idasync
def list_instances() -> str:
    """List running IDA MCP instances found via filesystem discovery."""
    try:
        instances = discover_instances()
    except Exception as e:
        return json.dumps({"error": str(e)})
    return json.dumps({"instances": instances, "count": len(instances)}, indent=2)


@tool
@idasync
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


@tool
@idasync
@unsafe
def close_instance(port: int = 13337) -> str:
    """Stop the MCP server of the local instance on ``port``.

    **Unsafe** — requires ``?unsafe=true``. Only the local instance (the one
    serving this request) can be closed; other ports return an error since
    each IDA process owns exactly one server. Save the IDB first
    (``idb_save``) — closing does not save.
    """
    if _OWN_PORT is None or port != _OWN_PORT:
        return json.dumps({"port": port,
                           "error": "Can only close the local instance serving this request"})
    stop_server(port)
    return json.dumps({"ok": True, "port": port})


def _init_auth_token() -> str | None:
    """Resolve the auth token gating unsafe/debugger tools.

    - ``IDA_MCP_NO_AUTH=1`` disables auth (loopback-only, legacy/open).
    - ``IDA_MCP_TOKEN`` sets a stable token (useful for a fixed client config).
    - otherwise a fresh random token is generated each start.

    The token is NEVER written to the discovery file, so a local reader of that
    file cannot escalate to the unsafe surface.
    """
    import secrets
    if os.getenv("IDA_MCP_NO_AUTH", "").strip().lower() in ("1", "true", "yes"):
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


def start_server(host: str = "127.0.0.1", port: int = 13337) -> None:
    """Start the MCP HTTP server and register this instance for discovery."""
    global _OWN_PORT
    _init_logging()
    token = _init_auth_token()
    MCP_SERVER.auth_token = token
    MCP_SERVER.serve(host, port, background=True)
    _OWN_PORT = port
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
    try:
        pid = os.getpid()
        get_input_path = getattr(idc, "get_input_file_path", None)
        binary = get_input_path() if callable(get_input_path) else ""
        get_idb_path = getattr(idc, "get_idb_path", None)
        idb_path = get_idb_path() if callable(get_idb_path) else ""
        register_instance(host, port, pid, binary or "", idb_path or "", backend="gui")
    except Exception as e:  # noqa: BLE001 - registration is best-effort
        ida_kernwin.msg(f"[ida-mcp] instance registration failed: {e}\n")


def stop_server(port: int = 13337) -> None:
    """Stop the MCP HTTP server and unregister this instance."""
    global _OWN_PORT
    MCP_SERVER.stop()
    _OWN_PORT = None
    try:
        unregister_instance(port)
    except Exception:  # noqa: BLE001 - unregistration is best-effort
        pass
