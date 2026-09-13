"""Tests for api_debug.py (debugger tools, ext group "dbg").

Stubs IDA modules and loads the source via exec. No live debugger needed:
the fake backend simulates suspended/running states.
"""
import json
import os
import sys
import types

# =========================================================================
# Stub IDA modules — fake debugger backend
# =========================================================================

ida_auto = types.ModuleType("ida_auto")
ida_auto.auto_wait = lambda: None
sys.modules["ida_auto"] = ida_auto

_STATE = {"on": True, "state": "susp", "ip": 0x1000}  # susp | run | off


class FakeBpt:
    def __init__(self, ea=0, enabled=True, condition="", elang=""):
        self.ea = ea
        self.flags = 1 if enabled else 0
        self.condition = condition
        self.elang = elang


_BPTS = {0x1000: FakeBpt(0x1000, True, "", ""),
         0x2000: FakeBpt(0x2000, False, "eax==1", "IDC")}

ida_dbg = types.ModuleType("ida_dbg")
ida_dbg.DSTATE_SUSP = 1
ida_dbg.DSTATE_RUN = 2
ida_dbg.DSTATE_NOTASK = 3
ida_dbg.BPT_ENABLED = 1
ida_dbg.BPT_SOFT = 0
ida_dbg.WFNE_ANY = 1
ida_dbg.WFNE_SUSP = 2
ida_dbg.WFNE_SILENT = 4
ida_dbg.is_debugger_on = lambda: _STATE["on"]
ida_dbg.get_process_state = lambda: {"susp": 1, "run": 2, "off": 3}[_STATE["state"]]
ida_dbg.get_ip_val = lambda: _STATE["ip"]
ida_dbg.get_bpt_qty = lambda: len(_BPTS)
ida_dbg.getn_bpt = lambda i, b: (_fill_bpt(list(_BPTS.values())[i], b), True)[1]
ida_dbg.get_bpt = lambda ea, b: (_fill_bpt(_BPTS[ea], b), True)[1] if ea in _BPTS else False
ida_dbg.add_bpt = lambda ea, size, btype: _BPTS.setdefault(ea, FakeBpt(ea)) is not None
ida_dbg.del_bpt = lambda ea: _BPTS.pop(ea, None) is not None
ida_dbg.get_current_thread = lambda: 111
ida_dbg.get_thread_qty = lambda: 2
ida_dbg.getn_thread = lambda i: [111, 222][i]
ida_dbg.wait_for_next_event = lambda mask, ms: None
ida_dbg.collect_stack_trace = lambda tid, trace: _fill_trace(trace)
ida_dbg.get_module_info = lambda ea, modinfo: _fill_modinfo(modinfo)
ida_dbg.update_bpt = lambda b: (_BPTS.__setitem__(
    b.ea, FakeBpt(b.ea, bool(b.flags & 1), b.condition, b.elang)), True)[1]


class _DbgHooksBase:
    def hook(self):
        return True

    def unhook(self):
        pass


ida_dbg.DBG_Hooks = _DbgHooksBase


def _fill_bpt(src, dst):
    dst.ea, dst.flags, dst.condition, dst.elang = src.ea, src.flags, src.condition, src.elang


def _fill_trace(trace):
    trace.append(types.SimpleNamespace(callea=0x1000))
    trace.append(types.SimpleNamespace(callea=0x2000))
    return True


def _fill_modinfo(modinfo):
    modinfo.name = "/bin/fake"
    return True


ida_dbg.bpt_t = FakeBpt
sys.modules["ida_dbg"] = ida_dbg

ida_idd = types.ModuleType("ida_idd")
ida_idd.get_dbg = lambda: object() if _STATE["on"] else None
ida_idd.call_stack_t = list


class FakeModinfo:
    name = ""


ida_idd.modinfo_t = FakeModinfo
sys.modules["ida_idd"] = ida_idd

ida_kernwin = types.ModuleType("ida_kernwin")
ida_kernwin.register_timer = lambda ms, cb: None
sys.modules["ida_kernwin"] = ida_kernwin

ida_name = types.ModuleType("ida_name")
ida_name.GNCN_NOCOLOR = 0
ida_name.GNCN_NOLABEL = 0
ida_name.GNCN_NOSEG = 0
ida_name.GNCN_PREFDBG = 0
ida_name.get_nice_colored_name = lambda ea, flags: f"main+{ea:x}"
sys.modules["ida_name"] = ida_name


class FakeRV:
    def __init__(self, v):
        self._v = v

    def pyval(self, dtype):
        return self._v


class FakeRegInfo:
    def __init__(self, name):
        self.name = name
        self.dtype = 0


idaapi = types.ModuleType("idaapi")
idaapi.BADADDR = -1
idaapi.BPT_SOFT = 0
idaapi.start_process = lambda a, b, c: _do_start()
idaapi.exit_process = lambda: _do_exit()
idaapi.continue_process = lambda: True
idaapi.run_to = lambda ea: True
idaapi.step_into = lambda: True
idaapi.step_over = lambda: True
idaapi.add_bpt = lambda ea, size, btype: True
idaapi.del_bpt = lambda ea: True
idaapi.enable_bpt = lambda ea, en: True
idaapi.dbg_read_memory = lambda ea, size: bytes(range(size))
idaapi.dbg_write_memory = lambda ea, data: True
idaapi.regs = lambda i: None


def _do_start():
    _STATE["on"] = True
    _STATE["state"] = "susp"
    return 1


def _do_exit():
    _STATE["on"] = False
    _STATE["state"] = "off"
    return True


sys.modules["idaapi"] = idaapi

idc = types.ModuleType("idc")
idc.set_bpt_cond = lambda ea, cond, low: _set_cond(ea, cond)
idc.get_name = lambda ea: f"func_{ea:x}"
idc.batch = lambda v: 0
sys.modules["idc"] = idc


def _set_cond(ea, cond):
    if ea in _BPTS:
        _BPTS[ea].condition = cond
        return True
    return False


# register-value backend
_REGVALS = {111: [("rax", 0x1000), ("rbx", b"\x01\x02"), ("xmm0", "fpval")]}


class _FakeDbg:
    def regs(self, i):
        names = [n for n, _ in _REGVALS[111]]
        return FakeRegInfo(names[i] if i < len(names) else f"r{i}")


_FakeDbgInstance = _FakeDbg()
ida_dbg.get_reg_vals = lambda tid: [FakeRV(v) for _, v in _REGVALS[tid]]

# =========================================================================
# Load api_debug.py
# =========================================================================

EXT_GROUPS = {}

HERE = os.path.dirname(os.path.abspath(__file__))
PKG = os.path.join(HERE, "..", "ida_mcp")
src = open(os.path.join(PKG, "api_debug.py")).read()
src = src.replace(
    "from .rpc import tool, unsafe, ext",
    "tool = lambda f: f\nunsafe = lambda f: f\n"
    "def ext(group):\n"
    "    def deco(fn):\n"
    "        EXT_GROUPS.setdefault(group, set()).add(fn.__name__)\n"
    "        return fn\n"
    "    return deco",
)
src = src.replace(
    "from .sync import idasync, tool_timeout, keep_batch, get_pre_call_batch, IDAError",
    "idasync = lambda f: f\n"
    "def tool_timeout(s):\n"
    "    def deco(fn):\n"
    "        return fn\n"
    "    return deco\n"
    "keep_batch = lambda f: f\n"
    "get_pre_call_batch = lambda: None\n"
    "class IDAError(Exception): pass",
)
src = src.replace(
    "from .api_analysis import parse_addr",
    "def parse_addr(s):\n"
    "    s = str(s).strip()\n"
    "    if s.startswith('0x'): return int(s, 16)\n"
    "    try: return int(s)\n"
    "    except ValueError: raise ValueError(f'Unknown: {s}')",
)
src = src.replace(
    "from .compat import badaddr, get_entry_qty, get_entry_ordinal, get_entry",
    "badaddr = lambda: -1\nget_entry_qty = lambda: 1\n"
    "get_entry_ordinal = lambda i: 1\nget_entry = lambda o: 0x1000",
)
mod = types.ModuleType("debug_test")
mod.__dict__.update({"EXT_GROUPS": EXT_GROUPS, "_FakeDbgInstance": _FakeDbgInstance})
exec(compile(src, "debug_test", "exec"), mod.__dict__)
# point _ensure helpers at the fake dbg object
sys.modules["debug_test"] = mod

# patch: _regs_for_thread needs dbg.regs — our _FakeDbgInstance works via closure
_orig_regs = mod._regs_for_thread


def _patched_regs(dbg, tid, only=None):
    return _orig_regs(_FakeDbgInstance, tid, only)


mod._regs_for_thread = _patched_regs

# =========================================================================
# Tests
# =========================================================================

# --- ext group registration ---
assert EXT_GROUPS.get("dbg") and len(EXT_GROUPS["dbg"]) == 19, EXT_GROUPS
print("ext=dbg registration (19 tools) OK")

# --- status / state ---
r = json.loads(mod.dbg_status())
assert r["state"] == "suspended" and r["ip"] == "0x1000", r
print("dbg_status OK")

# --- breakpoints ---
r = json.loads(mod.dbg_bps())
assert len(r["breakpoints"]) == 2, r
assert r["breakpoints"][0]["addr"] == "0x1000", r
print("dbg_bps OK")

r = json.loads(mod.dbg_add_bp("0x3000, bogus_name"))
assert r["results"][0]["ok"] is True and "error" in r["results"][1], r
r = json.loads(mod.dbg_delete_bp("0x3000"))
assert r["results"][0]["ok"] is True, r
print("dbg_add/delete_bp OK")

r = json.loads(mod.dbg_toggle_bp('[{"addr": "0x1000", "enabled": false}]'))
assert r["results"][0]["ok"] is True, r
r = json.loads(mod.dbg_toggle_bp('not json'))
assert "error" in r, r
print("dbg_toggle_bp OK")

r = json.loads(mod.dbg_set_bp_condition(
    '[{"addr": "0x2000", "condition": "rbx==2", "language": "Python"}]'))
assert r["results"][0]["ok"] is True, r
assert r["results"][0]["condition"] == "rbx==2", r
assert r["results"][0]["language"] == "Python", r
r = json.loads(mod.dbg_set_bp_condition(
    '[{"addr": "0x2000", "condition": null}]'))
assert r["results"][0]["ok"] is True and r["results"][0]["condition"] is None, r
r = json.loads(mod.dbg_set_bp_condition('[{"addr": "0x9999", "condition": "x"}]'))
assert "error" in r["results"][0], r
print("dbg_set_bp_condition OK")

# --- registers / threads / stack ---
r = json.loads(mod.dbg_regs())
assert r["thread_id"] == 111 and len(r["registers"]) == 3, r
assert r["registers"][0] == {"name": "rax", "value": "0x1000"}, r
assert r["registers"][1]["value"] == "01 02", r
r = json.loads(mod.dbg_gpregs())
assert [x["name"] for x in r["registers"]] == ["rax", "rbx"], r
r = json.loads(mod.dbg_regs_named("rax, xmm0"))
assert {x["name"] for x in r["registers"]} == {"rax", "xmm0"}, r
r = json.loads(mod.dbg_get_threads())
assert r == {"threads": [111, 222], "current": 111, "count": 2}, r
r = json.loads(mod.dbg_stacktrace())
assert r["count"] == 2 and r["frames"][0]["module"] == "fake", r
assert r["frames"][0]["symbol"].startswith("main+"), r
print("regs/threads/stacktrace OK")

# --- memory ---
r = json.loads(mod.dbg_read('[{"addr": "0x1000", "size": 4}]'))
assert r["results"][0]["data"] == "00010203", r
r = json.loads(mod.dbg_read('bogus'))
assert "error" in r, r
r = json.loads(mod.dbg_write('[{"addr": "0x1000", "data": "9090"}]'))
assert r["results"][0]["ok"] is True and r["results"][0]["size"] == 2, r
print("dbg_read/write OK")

# --- control flow ---
for fn in (mod.dbg_continue, mod.dbg_step_into, mod.dbg_step_over):
    r = json.loads(fn())
    assert r.get("continued") is True, (fn, r)
r = json.loads(mod.dbg_run_to("0x2000"))
assert r.get("continued") is True, r
print("continue/step/run_to OK")

# --- suspended-required errors ---
_STATE["state"] = "run"
for fn in (mod.dbg_continue, mod.dbg_regs, mod.dbg_get_threads, mod.dbg_stacktrace):
    try:
        fn()
        raise AssertionError(f"{fn} should have raised")
    except mod.IDAError:
        pass
_STATE["state"] = "susp"
print("suspend-guard OK")

# --- exit + start cycle ---
r = json.loads(mod.dbg_exit())
assert r["exited"] is True, r
_STATE["on"] = False
_STATE["state"] = "off"
r = json.loads(mod.dbg_status())
assert r["state"] == "not_running", r
# start with no debugger on: boot path (adds entry bp, polls, boots)
_STATE["on"] = False
r = json.loads(mod.dbg_start())
assert r.get("started") is True and r.get("suspended") is True, r
print("exit/start cycle OK")

print("ALL DEBUG TESTS PASSED")
