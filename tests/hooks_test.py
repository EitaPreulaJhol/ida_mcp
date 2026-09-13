"""Tests for api_hooks.py (managed hook tracers).

Stubs IDA modules and loads the source via exec.
"""
import json
import os
import sys
import types

# =========================================================================
# Stub IDA modules
# =========================================================================

ida_auto = types.ModuleType("ida_auto")
ida_auto.auto_wait = lambda: None
sys.modules["ida_auto"] = ida_auto


class _HookBase:
    def hook(self):
        return True

    def unhook(self):
        pass


ida_idp = types.ModuleType("ida_idp")
ida_idp.IDB_Hooks = _HookBase
sys.modules["ida_idp"] = ida_idp

ida_hexrays = types.ModuleType("ida_hexrays")
ida_hexrays.Hexrays_Hooks = _HookBase
sys.modules["ida_hexrays"] = ida_hexrays

ida_dbg = types.ModuleType("ida_dbg")
ida_dbg.DBG_Hooks = _HookBase
sys.modules["ida_dbg"] = ida_dbg

# =========================================================================
# Load api_hooks.py
# =========================================================================

HERE = os.path.dirname(os.path.abspath(__file__))
PKG = os.path.join(HERE, "..", "ida_mcp")
src = open(os.path.join(PKG, "api_hooks.py")).read()
src = src.replace("from .rpc import tool, unsafe", "tool = lambda f: f\nunsafe = lambda f: f")
src = src.replace("from .sync import idasync", "idasync = lambda f: f")
mod = types.ModuleType("hooks_test")
exec(compile(src, "hooks_test", "exec"), mod.__dict__)
sys.modules["hooks_test"] = mod

# =========================================================================
# Tests
# =========================================================================

r = json.loads(mod.install_hook("bogus"))
assert r["ok"] is False and "Unknown hook type" in r["error"], r
print("bad type OK")

r = json.loads(mod.install_hook("idb"))
assert r["ok"] is True and r["hook_id"].startswith("idb_"), r
idb_id = r["hook_id"]
r = json.loads(mod.get_hook_info())
assert r["count"] == 1, r
print("install idb OK")

# fire the tracer directly (as IDA would) and check the ring buffer
entry = mod._HOOKS[idb_id]
entry["hook"].renamed(0x1000, "main", True)
entry["hook"].byte_patched(0x2000, 0x90)
r = json.loads(mod.get_hook_info(idb_id))
assert r["event_count"] == 2, r
assert r["recent_events"][0]["event"] == "renamed", r
assert r["recent_events"][0]["detail"]["new_name"] == "main", r
print("idb tracer events OK")

r = json.loads(mod.install_hexrays_hook())
hex_id = r["hook_id"]
mod._HOOKS[hex_id]["hook"].maturity(types.SimpleNamespace(entry_ea=0x1000), 5)
r = json.loads(mod.get_hook_info(hex_id))
assert r["recent_events"][0]["detail"]["maturity"] == 5, r
print("hexrays tracer OK")

r = json.loads(mod.install_hook("debugger"))
dbg_id = r["hook_id"]
mod._HOOKS[dbg_id]["hook"].dbg_bpt(111, 0x1000)
r = json.loads(mod.get_hook_info(dbg_id))
assert r["recent_events"][0]["event"] == "breakpoint_hit", r
print("debugger tracer OK")

# reinstalling a type replaces the previous hook
r = json.loads(mod.install_hook("idb"))
assert r["hook_id"] != idb_id, r
assert idb_id not in mod._HOOKS and len(mod._HOOKS) == 3, mod._HOOKS.keys()
print("replace-on-reinstall OK")

r = json.loads(mod.get_hook_info("nope"))
assert "error" in r, r
r = json.loads(mod.remove_hooks(r["hook_id"] if "hook_id" in r else "nope"))
assert r["count"] == 0, r
print("unknown hook handling OK")

new_id = json.loads(mod.install_hook("idb"))["hook_id"]
r = json.loads(mod.remove_hooks(new_id))
assert r == {"removed": [new_id], "count": 1}, r
r = json.loads(mod.remove_hooks("all"))
assert r["count"] == 2 and not mod._HOOKS, r
print("remove one/all OK")

print("ALL HOOKS TESTS PASSED")
