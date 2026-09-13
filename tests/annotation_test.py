"""Tests for annotation tools: set_comment, rename_function.

Stubs IDA modules and loads api_analysis.py via exec.
"""
import os
import sys
import types

# =========================================================================
# Stub IDA modules
# =========================================================================

ida_auto = types.ModuleType("ida_auto")
ida_auto.auto_wait = lambda: None
sys.modules["ida_auto"] = ida_auto

ida_ida = types.ModuleType("ida_ida")
ida_ida.BADADDR = -1
sys.modules["ida_ida"] = ida_ida

ida_name = types.ModuleType("ida_name")
ida_name.get_name_ea = lambda badaddr, name: badaddr if name == "unknown" else 0x1000
ida_name.set_name = lambda ea, name, flags: True
ida_name.SN_NOWARN = 1
sys.modules["ida_name"] = ida_name

# --- ida_funcs ---
_class_fake_funcs: dict[int, tuple] = {}


class FakeFuncObj:
    def __init__(self, start, end):
        self.start_ea = start
        self.end_ea = end


def _fake_get_func(ea):
    if ea in _class_fake_funcs:
        start, end = _class_fake_funcs[ea]
        return FakeFuncObj(start, end)
    return None


def _fake_get_func_name(ea):
    for s, (start, _) in _class_fake_funcs.items():
        if start == ea:
            return f"func_{ea:x}"
    return None


ida_funcs = types.ModuleType("ida_funcs")
ida_funcs.get_func = _fake_get_func
ida_funcs.get_func_name = _fake_get_func_name
sys.modules["ida_funcs"] = ida_funcs

# --- ida_bytes ---
_class_set_cmt_results: list[bool] = [True]
_class_set_cmt_calls: list[tuple] = []


def _fake_set_cmt(ea, comment, repeatable):
    _class_set_cmt_calls.append((ea, comment, repeatable))
    return _class_set_cmt_results[len(_class_set_cmt_calls) - 1] if len(_class_set_cmt_calls) <= len(_class_set_cmt_results) else True


ida_bytes = types.ModuleType("ida_bytes")
ida_bytes.set_cmt = _fake_set_cmt
sys.modules["ida_bytes"] = ida_bytes

# --- ida_hexrays ---
_class_hexrays_available = True
_class_decompile_result = None


class FakeCFunc:
    def __init__(self, entry_ea=0x1000):
        self.entry_ea = entry_ea
        self._orphan_cmts = False

    def get_eamap(self):
        return {self.entry_ea: [type("FakeEaMap", (), {"ea": self.entry_ea})()]}

    def set_user_cmt(self, tl, comment):
        pass

    def save_user_cmts(self):
        pass

    def refresh_func_ctext(self):
        pass

    def has_orphan_cmts(self):
        return self._orphan_cmts

    def del_orphan_cmts(self):
        self._orphan_cmts = False


ida_hexrays = types.ModuleType("ida_hexrays")
ida_hexrays.init_hexrays_plugin = lambda: _class_hexrays_available
ida_hexrays.decompile = lambda ea: _class_decompile_result
sys.modules["ida_hexrays"] = ida_hexrays

# --- idc ---
idc = types.ModuleType("idc")
idc.set_func_cmt = lambda ea, comment, repeatable: None
sys.modules["idc"] = idc

# --- idaapi ---
idaapi = types.ModuleType("idaapi")
idaapi.BADADDR = -1
idaapi.ITP_SEMI = 1
idaapi.ITP_COLON = 5
sys.modules["idaapi"] = idaapi

# treeloc_t needs to be iterable (for range(...))
class FakeTreeloc:
    def __init__(self):
        self.ea = 0
        self.itp = 0


idaapi.treeloc_t = FakeTreeloc
idaapi.ITP_SEMI = 1
idaapi.ITP_COLON = 5
sys.modules["idaapi"] = idaapi

# --- other stubs ---
ida_nalt = types.ModuleType("ida_nalt")
sys.modules["ida_nalt"] = ida_nalt

ida_kernwin = types.ModuleType("ida_kernwin")
sys.modules["ida_kernwin"] = ida_kernwin

ida_lines = types.ModuleType("ida_lines")
sys.modules["ida_lines"] = ida_lines

ida_ua = types.ModuleType("ida_ua")
sys.modules["ida_ua"] = ida_ua

idautils = types.ModuleType("idautils")
sys.modules["idautils"] = idautils

ida_entry = types.ModuleType("ida_entry")
sys.modules["ida_entry"] = ida_entry

ida_xref = types.ModuleType("ida_xref")
sys.modules["ida_xref"] = ida_xref

ida_segment = types.ModuleType("ida_segment")
sys.modules["ida_segment"] = ida_segment

ida_frame = types.ModuleType("ida_frame")
sys.modules["ida_frame"] = ida_frame

ida_typeinf = types.ModuleType("ida_typeinf")
sys.modules["ida_typeinf"] = ida_typeinf

ida_dbg = types.ModuleType("ida_dbg")
sys.modules["ida_dbg"] = ida_dbg

# =========================================================================
# Load api_analysis.py
# =========================================================================

HERE = os.path.dirname(os.path.abspath(__file__))
PKG = os.path.join(HERE, "..", "ida_mcp")
src = open(os.path.join(PKG, "api_analysis.py")).read()
src = src.replace("from .rpc import tool, unsafe, MCP_SERVER",
                   "tool = lambda f: f\nunsafe = lambda f: f\nMCP_SERVER = type('FakeMCP', (), {'unsafe_tools': set()})()")
src = src.replace("from .sync import idasync", "idasync = lambda f: f")
mod = types.ModuleType("annotation_test")
exec(compile(src, "annotation_test", "exec"), mod.__dict__)
sys.modules["annotation_test"] = mod


def setup():
    _class_fake_funcs.clear()
    _class_set_cmt_calls.clear()
    _class_hexrays_available = True
    _class_decompile_result = None

# =========================================================================
# Tests
# =========================================================================

# --- set_comment ---

# 1) basic comment set (disassembly only, no hexrays decompile)
setup()
_class_fake_funcs[0x1000] = (0x1000, 0x1100)
_class_hexrays_available = False

r = mod.set_comment("0x1000", "test comment")
assert "comment_set" in r, f"expected comment_set: {r}"
print("set_comment basic OK")

# 2) comment with hexrays decompiler
setup()
_class_fake_funcs[0x2000] = (0x2000, 0x2100)
_class_hexrays_available = True
_class_decompile_result = FakeCFunc(entry_ea=0x2000)

r = mod.set_comment("0x2000", "decomp comment")
assert "comment_set" in r, f"expected comment_set with decomp: {r}"
print("set_comment with decompiler OK")

# 3) bad address
r = mod.set_comment("unknown", "fail")
assert "Unknown address" in r, f"expected error: {r}"
print("set_comment bad address OK")

# --- rename_function ---

# 4) basic rename
setup()
_class_fake_funcs[0x4000] = (0x4000, 0x4100)
ida_name.set_name = lambda ea, name, flags: True

r = mod.rename_function("0x4000", "new_name")
assert "new_name" in r, f"expected new_name: {r}"
assert "old_name" in r, f"expected old_name: {r}"
print("rename_function basic OK")

# 5) rename fails
setup()
_class_fake_funcs[0x5000] = (0x5000, 0x5100)
ida_name.set_name = lambda ea, name, flags: False

r = mod.rename_function("0x5000", "fail_name")
assert "Failed to rename" in r, f"expected failure: {r}"
print("rename_function failure OK")

# 6) no function at address
setup()
r = mod.rename_function("0x9999", "nope")
assert "No function" in r, f"expected no function: {r}"
print("rename_function no function OK")

# 7) bad address
r = mod.rename_function("unknown", "nope")
assert "Unknown address" in r, f"expected error: {r}"
print("rename_function bad address OK")

# ---- restore set_name default behavior ----
ida_name.set_name = lambda ea, name, flags: True

print("\nALL ANNOTATION TESTS PASSED")
