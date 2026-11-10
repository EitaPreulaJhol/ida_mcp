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

from _harness import RPC_STUB, SYNC_STUB, load  # noqa: E402
mod = load("api_hooks", {
    "rpc": RPC_STUB,
    "sync": SYNC_STUB,
}, alias="hooks_test")

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

# remove_all_hooks (used by server.stop_server): plain call, unhooks each
_unhooked = []
_orig_unhook = _HookBase.unhook
_HookBase.unhook = lambda self: _unhooked.append(self)
ids = [json.loads(mod.install_hook(t))["hook_id"] for t in ("idb", "debugger")]
removed = mod.remove_all_hooks()
assert sorted(removed) == sorted(ids) and not mod._HOOKS, (removed, mod._HOOKS)
assert len(_unhooked) == 2, _unhooked
assert mod.remove_all_hooks() == []  # idempotent
_HookBase.unhook = _orig_unhook
print("remove_all_hooks OK")

# 14.25: the registry entry must exist while hook() runs (an event delivered
# inside hook() only reaches the buffer if _log() finds the entry), and a
# hook() that fails must not leave a dead entry behind.
_seen = {}


class _EarlyHook(_HookBase):
    def hook(self):
        _seen["during"] = list(mod._HOOKS)
        return True


class _FailingHook(_HookBase):
    def hook(self):
        return False


_saved_base = ida_idp.IDB_Hooks
ida_idp.IDB_Hooks = _EarlyHook
try:
    _early_id = json.loads(mod.install_hook("idb"))["hook_id"]
finally:
    ida_idp.IDB_Hooks = _saved_base
assert _early_id in _seen.get("during", []), _seen
mod.remove_hooks(_early_id)

ida_idp.IDB_Hooks = _FailingHook
try:
    _failed = json.loads(mod.install_hook("idb"))
finally:
    ida_idp.IDB_Hooks = _saved_base
assert _failed["ok"] is False, _failed
assert mod._HOOKS == {}, mod._HOOKS
print("hook registry ordering + failed hook OK")

print("ALL HOOKS TESTS PASSED")
