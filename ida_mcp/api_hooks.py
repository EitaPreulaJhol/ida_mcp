"""Managed IDA event hooks for ida_mcp.

Unlike the extendedtools variant (which ``py_eval``s arbitrary callback code
into a hook — a crash footgun), this module installs a small set of SAFE
built-in tracers with a managed lifecycle: every installation is tracked in a
registry, events land in a bounded ring buffer, and ``remove_hooks`` always
restores a clean state. Hook callbacks never raise and never veto IDA's
default behavior (all return 0).

Covers the extendedtools surface (``install_hook``, ``install_hexrays_hook``,
``install_idb_hook``, ``remove_hooks``, ``get_hook_info``) with real tracking
instead of the ``\"tracking not available\"`` stub.
"""
import json
import time
from collections import deque

import ida_auto

from .rpc import tool, unsafe
from .sync import idasync


_HOOKS: dict[str, dict] = {}
_HOOK_SEQ = [0]
_EVENTS_PER_HOOK = 200


def _next_hook_id(hook_type: str) -> str:
    _HOOK_SEQ[0] += 1
    return f"{hook_type}_{_HOOK_SEQ[0]}"


def _log(hook_id: str, event: str, detail: dict) -> None:
    entry = _HOOKS.get(hook_id)
    if entry is None:
        return
    try:
        entry["events"].append({"event": event, "detail": detail,
                                "t": round(time.monotonic(), 3)})
        entry["event_count"] = entry.get("event_count", 0) + 1
    except Exception:
        pass


def _hook_base(modname: str, classname: str):
    """Return the hook base class or raise a clean error."""
    try:
        mod = __import__(modname)
    except ImportError as e:
        raise RuntimeError(f"{modname} unavailable: {e}")
    cls = getattr(mod, classname, None)
    if cls is None:
        raise RuntimeError(f"{modname}.{classname} unavailable in this IDA version")
    return cls


# ---------------------------------------------------------------------------
# Built-in tracers (passive: log + return 0, never alter IDA behavior)
# ---------------------------------------------------------------------------

def _make_idb_tracer(hook_id: str):
    base = _hook_base("ida_idp", "IDB_Hooks")

    class _IdbTracer(base):
        def renamed(self, ea, new_name, local_name):
            try:
                _log(hook_id, "renamed",
                     {"addr": hex(ea), "new_name": new_name,
                      "local": bool(local_name)})
            except Exception:
                pass
            return 0

        def byte_patched(self, ea, old_value):
            try:
                _log(hook_id, "byte_patched",
                     {"addr": hex(ea), "old_value": old_value})
            except Exception:
                pass
            return 0

        def cmt_changed(self, ea, cmt, rpt):
            try:
                _log(hook_id, "comment_changed",
                     {"addr": hex(ea), "repeatable": bool(rpt)})
            except Exception:
                pass
            return 0

    return _IdbTracer()


def _make_hexrays_tracer(hook_id: str):
    base = _hook_base("ida_hexrays", "Hexrays_Hooks")

    class _HexraysTracer(base):
        def maturity(self, cfunc, new_maturity):
            try:
                _log(hook_id, "maturity",
                     {"addr": hex(int(getattr(cfunc, "entry_ea", 0))),
                      "maturity": int(new_maturity)})
            except Exception:
                pass
            return 0

    return _HexraysTracer()


def _make_dbg_tracer(hook_id: str):
    base = _hook_base("ida_dbg", "DBG_Hooks")

    class _DbgTracer(base):
        def dbg_bpt(self, tid, ea):
            try:
                _log(hook_id, "breakpoint_hit", {"tid": tid, "addr": hex(ea)})
            except Exception:
                pass
            return 0

        def dbg_process_start(self, pid, tid, ea, name, base, size):
            try:
                _log(hook_id, "process_start",
                     {"pid": pid, "addr": hex(ea), "name": name})
            except Exception:
                pass
            return 0

        def dbg_process_exit(self, pid, tid, ea, exit_code):
            try:
                _log(hook_id, "process_exit", {"pid": pid, "exit_code": exit_code})
            except Exception:
                pass
            return 0

    return _DbgTracer()


_TRACERS = {
    "idb": _make_idb_tracer,
    "hexrays": _make_hexrays_tracer,
    "debugger": _make_dbg_tracer,
}


def _install(hook_type: str) -> dict:
    maker = _TRACERS.get(hook_type)
    if maker is None:
        return {"ok": False, "error": f"Unknown hook type {hook_type!r} (use idb/hexrays/debugger)"}
    hook_id = _next_hook_id(hook_type)
    try:
        hook = maker(hook_id)
    except RuntimeError as e:
        return {"ok": False, "error": str(e)}
    except Exception as e:
        return {"ok": False, "error": f"Could not create tracer: {e}"}
    # Replace any previous hook of the same type.
    for hid, entry in list(_HOOKS.items()):
        if entry.get("type") == hook_type:
            try:
                entry["hook"].unhook()
            except Exception:
                pass
            _HOOKS.pop(hid, None)
    try:
        hooked = hook.hook()
    except Exception as e:
        return {"ok": False, "error": f"hook() failed: {e}"}
    if not hooked:
        return {"ok": False, "error": "hook() returned false"}
    _HOOKS[hook_id] = {"type": hook_type, "hook": hook,
                       "events": deque(maxlen=_EVENTS_PER_HOOK),
                       "event_count": 0, "installed_at": round(time.monotonic(), 3)}
    # Rebind the tracer's closure id (maker used a placeholder).
    return {"ok": True, "hook_id": hook_id, "hook_type": hook_type}


# ===========================================================================
# Tools
# ===========================================================================


@tool
@idasync
@unsafe
def install_hook(hook_type: str) -> str:
    """Install a built-in passive tracer hook (``idb``/``hexrays``/``debugger``).

    **Unsafe** — requires ``?unsafe=true``. The tracer only logs event
    summaries to a bounded ring buffer (see ``get_hook_info``); it never
    alters IDA behavior. Re-installing a type replaces the previous hook.
    """
    ida_auto.auto_wait()
    hook_type = (hook_type or "").strip().lower()
    return json.dumps(_install(hook_type), indent=2)


@tool
@idasync
@unsafe
def install_hexrays_hook() -> str:
    """Install the built-in Hex-Rays maturity tracer (logs decompilations).

    **Unsafe** — requires ``?unsafe=true``.
    """
    ida_auto.auto_wait()
    return json.dumps(_install("hexrays"), indent=2)


@tool
@idasync
@unsafe
def install_idb_hook() -> str:
    """Install the built-in IDB tracer (renames, patches, comment changes).

    **Unsafe** — requires ``?unsafe=true``.
    """
    ida_auto.auto_wait()
    return json.dumps(_install("idb"), indent=2)


@tool
@idasync
def get_hook_info(hook_id: str = "") -> str:
    """Inspect installed hooks: type, event counts and recent events."""
    ida_auto.auto_wait()
    if hook_id:
        entry = _HOOKS.get(hook_id)
        if entry is None:
            return json.dumps({"hook_id": hook_id, "error": "Unknown hook id"})
        return json.dumps({
            "hook_id": hook_id,
            "type": entry["type"],
            "event_count": entry.get("event_count", 0),
            "recent_events": list(entry["events"])[-20:],
        }, indent=2)
    return json.dumps({
        "hooks": [{"hook_id": hid, "type": e["type"],
                   "event_count": e.get("event_count", 0)}
                  for hid, e in _HOOKS.items()],
        "count": len(_HOOKS),
    }, indent=2)


@tool
@idasync
@unsafe
def remove_hooks(hook_id: str = "all") -> str:
    """Remove installed hooks (one id or ``all``).

    **Unsafe** — requires ``?unsafe=true``.
    """
    ida_auto.auto_wait()
    targets = list(_HOOKS.keys()) if hook_id in ("", "all") else [hook_id]
    removed: list[str] = []
    for hid in targets:
        entry = _HOOKS.pop(hid, None)
        if entry is None:
            continue
        try:
            entry["hook"].unhook()
        except Exception:
            pass
        removed.append(hid)
    return json.dumps({"removed": removed, "count": len(removed)}, indent=2)


__all__ = [
    "install_hook",
    "install_hexrays_hook",
    "install_idb_hook",
    "get_hook_info",
    "remove_hooks",
]
