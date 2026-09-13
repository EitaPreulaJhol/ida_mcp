"""Debugger operations for ida_mcp (extension group ``dbg``).

All tools are ``@ext(\"dbg\")`` + ``@unsafe``: hidden unless the endpoint URL
carries ``?unsafe=true&ext=dbg``. Ported from ida-pro-mcp ``api_debug.py``,
adapted to local conventions (JSON-string results, ``parse_addr``).

Requires a configured debugger (Debugger -> Select debugger + target).
``dbg_start`` keeps batch mode on across the ``execute_sync`` boundary via a
``DBG_Hooks`` restorer (official pattern) so startup dialogs never hang the
agent; batch state is always restored on process start/attach/exit/detach
(or a 30 s timer fallback).
"""
import json
import os

import ida_dbg
import ida_idd
import ida_kernwin
import ida_name
import idaapi
import idc

from .rpc import tool, unsafe, ext
from .sync import idasync, tool_timeout, keep_batch, get_pre_call_batch, IDAError
from .api_analysis import parse_addr
from .compat import badaddr, get_entry_qty, get_entry_ordinal, get_entry


GENERAL_PURPOSE_REGISTERS = frozenset({
    # x86-64 / x86
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
    "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp",
    "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d",
    # AArch64
    "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9",
    "x10", "x11", "x12", "x13", "x14", "x15", "x16", "x17", "x18",
    "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27",
    "x28", "fp", "lr", "sp", "w0", "w1", "w2", "w3",
})

_DBG_START_BATCH_FALLBACK_MS = 30_000
_DBG_START_WAIT_TIMEOUT_SEC = 10.0
_DBG_START_WAIT_POLL_MS = 100
_DBG_START_IP_GRACE_POLL_COUNT = 5


# ---------------------------------------------------------------------------
# Internal helpers (no @tool — called from within @idasync context)
# ---------------------------------------------------------------------------

def _process_state() -> str:
    if not ida_dbg.is_debugger_on():
        return "not_running"
    try:
        state = ida_dbg.get_process_state()
    except Exception:
        return "unknown"
    if state == ida_dbg.DSTATE_SUSP:
        return "suspended"
    if state == ida_dbg.DSTATE_RUN:
        return "running"
    if state == ida_dbg.DSTATE_NOTASK:
        return "not_running"
    return f"unknown({state})"


def _state_result() -> dict:
    state = _process_state()
    result: dict = {"state": state}
    if state == "running":
        result["running"] = True
    elif state == "suspended":
        result["suspended"] = True
        try:
            ip = ida_dbg.get_ip_val()
        except Exception:
            ip = None
        if ip is not None:
            result["ip"] = hex(ip)
    return result


def _ensure_active():
    try:
        dbg = ida_idd.get_dbg()
    except Exception:
        dbg = None
    if not dbg or not ida_dbg.is_debugger_on():
        raise IDAError(
            "Debugger not running. Call dbg_start first (debugger + target "
            "must be configured in IDA) before retrying."
        )
    return dbg


def _ensure_suspended():
    dbg = _ensure_active()
    if ida_dbg.get_process_state() != ida_dbg.DSTATE_SUSP:
        raise IDAError("Debugger is running; wait until it suspends before inspecting state")
    return dbg


def _regs_for_thread(dbg, tid: int, only: set | None = None) -> dict:
    try:
        regvals = ida_dbg.get_reg_vals(tid)
    except Exception as e:
        raise IDAError(f"Could not read registers for thread {tid}: {e}")
    regs: list[dict] = []
    for index, rv in enumerate(regvals):
        try:
            info = dbg.regs(index)
            name = info.name
        except Exception:
            continue
        if only is not None and name not in only and name.lower() not in only:
            continue
        try:
            value = rv.pyval(info.dtype)
        except ValueError:
            value = badaddr()
        except Exception:
            value = None
        if isinstance(value, int):
            value = hex(value)
        elif isinstance(value, bytes):
            value = value.hex(" ")
        else:
            value = str(value)
        regs.append({"name": name, "value": value})
    return {"thread_id": tid, "registers": regs}


def _split_addrs(addrs: str) -> list[str]:
    if isinstance(addrs, (list, tuple)):
        return [str(a) for a in addrs]
    return [a.strip() for a in str(addrs).split(",") if a.strip()]


def _list_breakpoints() -> list[dict]:
    out: list[dict] = []
    try:
        qty = ida_dbg.get_bpt_qty()
    except Exception:
        return out
    for i in range(qty):
        try:
            bpt = ida_dbg.bpt_t()
            if not ida_dbg.getn_bpt(i, bpt):
                continue
            lang = getattr(bpt, "elang", None)
            out.append({
                "addr": hex(bpt.ea),
                "enabled": bool(bpt.flags & ida_dbg.BPT_ENABLED),
                "condition": str(bpt.condition) if bpt.condition else None,
                "language": str(lang).strip() or None if lang is not None else None,
            })
        except Exception:
            continue
    return out


def _debug_start_result() -> dict | None:
    if not ida_dbg.is_debugger_on():
        return None
    result = _state_result()
    result["started"] = True
    return result


class _DbgStartBatchHook(ida_dbg.DBG_Hooks):
    """Restore pre-call batch state once debugger startup finishes.

    Startup ends at dbg_process_start / _attach (startup dialogs done, live
    session continues normally). Exit/detach paths also restore so a dying
    process can't leave IDA stuck in batch mode.
    """

    def __init__(self, restore_batch: int):
        super().__init__()
        self._restore_batch = restore_batch
        self._done = False

    def dbg_process_start(self, pid, tid, ea, name, base, size):
        self._restore()

    def dbg_process_attach(self, pid, tid, ea, name, base, size):
        self._restore()

    def dbg_process_exit(self, pid, tid, ea, exit_code):
        self._restore()

    def dbg_process_detach(self, pid, tid, ea):
        self._restore()

    def fallback_restore(self):
        self._restore()

    def _restore(self):
        if self._done:
            return
        self._done = True
        try:
            self.unhook()
        except Exception:
            pass
        try:
            idc.batch(self._restore_batch)
        except Exception:
            pass


_dbg_start_batch_hook = None


def _arm_dbg_start_batch_hook(restore_batch: int) -> None:
    global _dbg_start_batch_hook
    if _dbg_start_batch_hook is not None:
        try:
            _dbg_start_batch_hook.fallback_restore()
        except Exception:
            pass
    hook = _DbgStartBatchHook(restore_batch)
    try:
        hook.hook()
    except Exception:
        pass
    _dbg_start_batch_hook = hook

    def _fallback():
        if _dbg_start_batch_hook is hook and not hook._done:
            hook.fallback_restore()
        return -1  # don't repeat

    try:
        ida_kernwin.register_timer(_DBG_START_BATCH_FALLBACK_MS, _fallback)
    except Exception:
        pass


def _wait_poll(timeout_sec: float = _DBG_START_WAIT_TIMEOUT_SEC):
    ida_dbg.wait_for_next_event(
        ida_dbg.WFNE_ANY | ida_dbg.WFNE_SUSP | ida_dbg.WFNE_SILENT,
        _DBG_START_WAIT_POLL_MS,
    )


# ===========================================================================
# Tools — session control
# ===========================================================================


@ext("dbg")
@unsafe
@tool
@idasync
@keep_batch
@tool_timeout(120.0)
def dbg_start() -> str:
    """Start the debugger session for the current target.

    Requires a selected debugger with a configured target. If this fails, do
    NOT retry in a loop — ask the user to configure the debugger and dismiss
    any IDA dialogs first. Batch mode is kept across startup and restored
    automatically once the process starts/attaches (or exits).
    """
    if not _list_breakpoints():
        for i in range(get_entry_qty()):
            ordinal = get_entry_ordinal(i)
            addr = get_entry(ordinal)
            if addr != badaddr():
                try:
                    ida_dbg.add_bpt(addr, 0, idaapi.BPT_SOFT)
                except Exception:
                    pass

    pre_call_batch = get_pre_call_batch()
    if pre_call_batch is None:
        pre_call_batch = 0
    _arm_dbg_start_batch_hook(restore_batch=pre_call_batch)

    try:
        start_result = idaapi.start_process("", "", "")
    except Exception as e:
        raise IDAError(f"start_process raised: {e}")

    started = _debug_start_result()
    if started is not None:
        if started.get("running") and "ip" not in started:
            for _ in range(_DBG_START_IP_GRACE_POLL_COUNT):
                _wait_poll()
                waited = _debug_start_result()
                if waited is None:
                    continue
                started = waited
                if started.get("suspended") or "ip" in started:
                    break
        return json.dumps(started, indent=2)

    for _ in range(int(_DBG_START_WAIT_TIMEOUT_SEC * 1000 / _DBG_START_WAIT_POLL_MS)):
        _wait_poll()
        started = _debug_start_result()
        if started is not None:
            return json.dumps(started, indent=2)

    if start_result == 0:
        raise IDAError("Debugger start was cancelled. Configure the debugger and dismiss IDA dialogs before retrying.")
    raise IDAError("Failed to start debugger. Verify a debugger is selected and the target is configured.")


@ext("dbg")
@unsafe
@tool
@idasync
def dbg_status() -> str:
    """Return debugger lifecycle state and current IP if suspended."""
    return json.dumps(_state_result(), indent=2)


@ext("dbg")
@unsafe
@tool
@idasync
def dbg_exit() -> str:
    """Terminate the active debugger session."""
    _ensure_active()
    try:
        ok = idaapi.exit_process()
    except Exception as e:
        raise IDAError(f"exit_process raised: {e}")
    if ok:
        return json.dumps({"exited": True, "state": "not_running"})
    raise IDAError("Failed to exit debugger")


@ext("dbg")
@unsafe
@tool
@idasync
def dbg_continue() -> str:
    """Resume execution in the suspended debugger session."""
    _ensure_suspended()
    try:
        ok = idaapi.continue_process()
    except Exception as e:
        raise IDAError(f"continue_process raised: {e}")
    if ok:
        result = _state_result()
        result["continued"] = True
        return json.dumps(result, indent=2)
    raise IDAError("Failed to continue debugger")


@ext("dbg")
@unsafe
@tool
@idasync
def dbg_run_to(address: str) -> str:
    """Run the debuggee until the target address is reached (must be suspended)."""
    _ensure_suspended()
    try:
        ea = parse_addr(address)
    except ValueError as e:
        return json.dumps({"error": str(e)})
    try:
        ok = idaapi.run_to(ea)
    except Exception as e:
        raise IDAError(f"run_to raised: {e}")
    if ok:
        result = _state_result()
        result["continued"] = True
        return json.dumps(result, indent=2)
    raise IDAError(f"Failed to run to address {hex(ea)}")


@ext("dbg")
@unsafe
@tool
@idasync
def dbg_step_into() -> str:
    """Execute one instruction, stepping into calls (must be suspended)."""
    _ensure_suspended()
    try:
        ok = idaapi.step_into()
    except Exception as e:
        raise IDAError(f"step_into raised: {e}")
    if ok:
        result = _state_result()
        result["continued"] = True
        return json.dumps(result, indent=2)
    raise IDAError("Failed to step into")


@ext("dbg")
@unsafe
@tool
@idasync
def dbg_step_over() -> str:
    """Execute one instruction, stepping over calls (must be suspended)."""
    _ensure_suspended()
    try:
        ok = idaapi.step_over()
    except Exception as e:
        raise IDAError(f"step_over raised: {e}")
    if ok:
        result = _state_result()
        result["continued"] = True
        return json.dumps(result, indent=2)
    raise IDAError("Failed to step over")


# ===========================================================================
# Tools — breakpoints
# ===========================================================================


@ext("dbg")
@unsafe
@tool
@idasync
def dbg_bps() -> str:
    """List breakpoints with address, enabled status, condition and language."""
    return json.dumps({"breakpoints": _list_breakpoints()}, indent=2)


@ext("dbg")
@unsafe
@tool
@idasync
def dbg_add_bp(addrs: str) -> str:
    """Add soft breakpoints at comma-separated addresses/names."""
    results: list[dict] = []
    for addr in _split_addrs(addrs):
        try:
            ea = parse_addr(addr)
        except ValueError:
            results.append({"addr": addr, "error": f"Unknown address or name: {addr}"})
            continue
        try:
            ok = idaapi.add_bpt(ea, 0, idaapi.BPT_SOFT)
        except Exception as e:
            results.append({"addr": addr, "error": str(e)})
            continue
        if ok:
            results.append({"addr": hex(ea), "ok": True})
        elif any(b["addr"] == hex(ea) for b in _list_breakpoints()):
            results.append({"addr": hex(ea), "ok": True})
        else:
            results.append({"addr": hex(ea), "error": "Failed to set breakpoint"})
    return json.dumps({"results": results}, indent=2)


@ext("dbg")
@unsafe
@tool
@idasync
def dbg_delete_bp(addrs: str) -> str:
    """Delete breakpoints at comma-separated addresses/names."""
    results: list[dict] = []
    for addr in _split_addrs(addrs):
        try:
            ea = parse_addr(addr)
        except ValueError:
            results.append({"addr": addr, "error": f"Unknown address or name: {addr}"})
            continue
        try:
            ok = idaapi.del_bpt(ea)
        except Exception as e:
            results.append({"addr": hex(ea), "error": str(e)})
            continue
        results.append({"addr": hex(ea), "ok": True} if ok
                       else {"addr": hex(ea), "error": "Failed to delete breakpoint"})
    return json.dumps({"results": results}, indent=2)


@ext("dbg")
@unsafe
@tool
@idasync
def dbg_toggle_bp(items: str) -> str:
    """Enable/disable breakpoints in batch.

    ``items`` is a JSON array of ``{\"addr\": ..., \"enabled\": bool}``.
    """
    try:
        parsed = json.loads(items) if isinstance(items, str) else items
    except Exception as e:
        return json.dumps({"error": f"Invalid items JSON: {e}"})
    if isinstance(parsed, dict):
        parsed = [parsed]
    results: list[dict] = []
    for item in parsed or []:
        addr = item.get("addr", "")
        enable = bool(item.get("enabled", True))
        try:
            ea = parse_addr(addr)
        except ValueError:
            results.append({"addr": addr, "error": f"Unknown address or name: {addr}"})
            continue
        try:
            ok = idaapi.enable_bpt(ea, enable)
        except Exception as e:
            results.append({"addr": hex(ea), "error": str(e)})
            continue
        results.append({"addr": hex(ea), "ok": True} if ok else
                       {"addr": hex(ea),
                        "error": f"Failed to {'enable' if enable else 'disable'} breakpoint"})
    return json.dumps({"results": results}, indent=2)


def _normalize_bp_language(language) -> str | None:
    if language is None:
        return None
    text = str(language).strip()
    if not text:
        return None
    lowered = text.lower()
    if lowered == "idc":
        return "IDC"
    if lowered == "python":
        return "Python"
    return text


@ext("dbg")
@unsafe
@tool
@idasync
def dbg_set_bp_condition(items: str) -> str:
    """Set/clear breakpoint conditions in batch (ported from ida-pro-mcp).

    ``items`` is a JSON array of ``{\"addr\": ..., \"condition\": str|null,
    \"language\": \"IDC\"|\"Python\"|null, \"low_level\": bool}``. Clearing
    (``condition: null``) removes the condition. Responses include the
    validated condition + language read back from IDA.
    """
    try:
        parsed = json.loads(items) if isinstance(items, str) else items
    except Exception as e:
        return json.dumps({"error": f"Invalid items JSON: {e}"})
    if isinstance(parsed, dict):
        parsed = [parsed]
    results: list[dict] = []
    for item in parsed or []:
        addr = item.get("addr", "")
        condition = item.get("condition")
        language = _normalize_bp_language(item.get("language"))
        low_level = bool(item.get("low_level", False))
        try:
            ea = parse_addr(addr)
        except ValueError:
            results.append({"addr": addr, "error": f"Unknown address or name: {addr}"})
            continue
        try:
            bpt = ida_dbg.bpt_t()
            if not ida_dbg.get_bpt(ea, bpt):
                results.append({"addr": hex(ea), "error": "Breakpoint not found"})
                continue
            condition_text = "" if condition is None else str(condition)
            current_language = str(getattr(bpt, "elang", "") or "").strip() or None
            current_condition = str(bpt.condition) if bpt.condition else None
            if language is not None and language != current_language:
                if current_condition and condition_text:
                    if not idc.set_bpt_cond(ea, "", 1 if low_level else 0):
                        results.append({"addr": hex(ea),
                                        "error": "Failed to clear existing condition before language change"})
                        continue
                    if not ida_dbg.get_bpt(ea, bpt):
                        results.append({"addr": hex(ea),
                                        "error": "Condition cleared but breakpoint could not be reloaded"})
                        continue
                setter = getattr(bpt, "set_cnd_elang", None)
                try:
                    if callable(setter):
                        if not setter(language):
                            raise IDAError("set_cnd_elang returned false")
                    else:
                        bpt.elang = language
                    if not ida_dbg.update_bpt(bpt):
                        raise IDAError("update_bpt returned false")
                except Exception as e:
                    results.append({"addr": hex(ea),
                                    "error": f"Failed to apply language {language}: {e}"})
                    continue
            if not idc.set_bpt_cond(ea, condition_text, 1 if low_level else 0):
                results.append({"addr": hex(ea), "error": "Failed to set breakpoint condition"})
                continue
            updated = ida_dbg.bpt_t()
            if not ida_dbg.get_bpt(ea, updated):
                results.append({"addr": hex(ea),
                                "error": "Condition set but breakpoint could not be reloaded"})
                continue
            updated_condition = str(updated.condition) if updated.condition else None
            updated_language = str(getattr(updated, "elang", "") or "").strip() or None
            is_compiled = getattr(updated, "is_compiled", None)
            if condition_text and callable(is_compiled) and not is_compiled():
                results.append({"addr": hex(ea),
                                "error": "Condition stored but did not compile"})
                continue
            results.append({"addr": hex(ea), "ok": True,
                            "condition": updated_condition, "language": updated_language})
        except Exception as e:
            results.append({"addr": addr, "error": str(e)})
    return json.dumps({"results": results}, indent=2)


# ===========================================================================
# Tools — registers / threads / stack
# ===========================================================================


@ext("dbg")
@unsafe
@tool
@idasync
def dbg_regs() -> str:
    """Full register set for the current debugger thread (must be suspended)."""
    dbg = _ensure_suspended()
    tid = ida_dbg.get_current_thread()
    return json.dumps(_regs_for_thread(dbg, tid), indent=2)


@ext("dbg")
@unsafe
@tool
@idasync
def dbg_gpregs() -> str:
    """General-purpose registers for the current thread (must be suspended)."""
    dbg = _ensure_suspended()
    tid = ida_dbg.get_current_thread()
    full = _regs_for_thread(dbg, tid)
    full["registers"] = [r for r in full["registers"]
                         if r["name"] in GENERAL_PURPOSE_REGISTERS
                         or r["name"].lower() in GENERAL_PURPOSE_REGISTERS]
    return json.dumps(full, indent=2)


@ext("dbg")
@unsafe
@tool
@idasync
def dbg_regs_named(register_names: str) -> str:
    """Selected registers of the current thread (comma-separated names)."""
    dbg = _ensure_suspended()
    tid = ida_dbg.get_current_thread()
    names = {n.strip() for n in register_names.split(",") if n.strip()}
    lowered = {n.lower() for n in names}
    full = _regs_for_thread(dbg, tid)
    full["registers"] = [r for r in full["registers"]
                         if r["name"] in names or r["name"].lower() in lowered]
    return json.dumps(full, indent=2)


@ext("dbg")
@unsafe
@tool
@idasync
def dbg_get_threads() -> str:
    """List debugger thread IDs and the current thread (must be suspended)."""
    _ensure_suspended()
    try:
        tids = [ida_dbg.getn_thread(i) for i in range(ida_dbg.get_thread_qty())]
        current = ida_dbg.get_current_thread()
    except Exception as e:
        raise IDAError(f"Could not enumerate threads: {e}")
    return json.dumps({"threads": tids, "current": current,
                       "count": len(tids)}, indent=2)


@ext("dbg")
@unsafe
@tool
@idasync
def dbg_stacktrace() -> str:
    """Current call stack with module and symbol context (must be suspended)."""
    _ensure_suspended()
    frames: list[dict] = []
    try:
        tid = ida_dbg.get_current_thread()
        trace = ida_idd.call_stack_t()
        if not ida_dbg.collect_stack_trace(tid, trace):
            return json.dumps({"frames": []})
        for frame in trace:
            info: dict = {"addr": hex(frame.callea)}
            try:
                modinfo = ida_idd.modinfo_t()
                if ida_dbg.get_module_info(frame.callea, modinfo):
                    info["module"] = os.path.basename(modinfo.name)
                else:
                    info["module"] = "<unknown>"
            except Exception:
                info["module"] = "<unknown>"
            try:
                nice = ida_name.get_nice_colored_name(
                    frame.callea,
                    getattr(ida_name, "GNCN_NOCOLOR", 0)
                    | getattr(ida_name, "GNCN_NOLABEL", 0)
                    | getattr(ida_name, "GNCN_NOSEG", 0)
                    | getattr(ida_name, "GNCN_PREFDBG", 0),
                )
                info["symbol"] = nice or "<unnamed>"
            except Exception:
                try:
                    info["symbol"] = idc.get_name(frame.callea) or "<unnamed>"
                except Exception:
                    info["symbol"] = "<unnamed>"
            frames.append(info)
    except Exception as e:
        raise IDAError(f"Could not collect stack trace: {e}")
    return json.dumps({"frames": frames, "count": len(frames)}, indent=2)


# ===========================================================================
# Tools — debuggee memory
# ===========================================================================


@ext("dbg")
@unsafe
@tool
@idasync
def dbg_read(regions: str) -> str:
    """Read debuggee memory. ``regions``: JSON array of ``{\"addr\", \"size\"}``."""
    try:
        parsed = json.loads(regions) if isinstance(regions, str) else regions
    except Exception as e:
        return json.dumps({"error": f"Invalid regions JSON: {e}"})
    if isinstance(parsed, dict):
        parsed = [parsed]
    _ensure_active()
    read_mem = getattr(idaapi, "dbg_read_memory", None)
    if not callable(read_mem):
        raise IDAError("dbg_read_memory unavailable in this IDA version")
    results: list[dict] = []
    for region in parsed or []:
        try:
            ea = parse_addr(region["addr"])
            size = int(region["size"])
        except (ValueError, KeyError, TypeError) as e:
            results.append({"addr": region.get("addr"), "size": 0,
                            "data": None, "error": str(e)})
            continue
        try:
            data = read_mem(ea, size)
        except Exception as e:
            results.append({"addr": hex(ea), "size": 0, "data": None, "error": str(e)})
            continue
        if data:
            results.append({"addr": hex(ea), "size": len(data),
                            "data": bytes(data).hex(), "error": None})
        else:
            results.append({"addr": hex(ea), "size": 0, "data": None,
                            "error": "Failed to read memory"})
    return json.dumps({"results": results}, indent=2)


@ext("dbg")
@unsafe
@tool
@idasync
def dbg_write(regions: str) -> str:
    """Write debuggee memory. ``regions``: JSON array of ``{\"addr\", \"data\"}`` (hex)."""
    try:
        parsed = json.loads(regions) if isinstance(regions, str) else regions
    except Exception as e:
        return json.dumps({"error": f"Invalid regions JSON: {e}"})
    if isinstance(parsed, dict):
        parsed = [parsed]
    _ensure_active()
    write_mem = getattr(idaapi, "dbg_write_memory", None)
    if not callable(write_mem):
        raise IDAError("dbg_write_memory unavailable in this IDA version")
    results: list[dict] = []
    for region in parsed or []:
        try:
            ea = parse_addr(region["addr"])
            data = bytes.fromhex(region["data"])
        except (ValueError, KeyError, TypeError) as e:
            results.append({"addr": region.get("addr"), "size": 0, "error": str(e)})
            continue
        try:
            ok = write_mem(ea, data)
        except Exception as e:
            results.append({"addr": hex(ea), "size": 0, "error": str(e)})
            continue
        results.append({"addr": hex(ea), "size": len(data) if ok else 0,
                        "ok": bool(ok), "error": None if ok else "Write failed"})
    return json.dumps({"results": results}, indent=2)


__all__ = [
    "dbg_start",
    "dbg_status",
    "dbg_exit",
    "dbg_continue",
    "dbg_run_to",
    "dbg_step_into",
    "dbg_step_over",
    "dbg_bps",
    "dbg_add_bp",
    "dbg_delete_bp",
    "dbg_toggle_bp",
    "dbg_set_bp_condition",
    "dbg_regs",
    "dbg_gpregs",
    "dbg_regs_named",
    "dbg_get_threads",
    "dbg_stacktrace",
    "dbg_read",
    "dbg_write",
]
