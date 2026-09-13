"""Tests for api_hexrays.py (microcode/flowchart/recompile tools).

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

idaapi = types.ModuleType("idaapi")
idaapi.BADADDR = -1
sys.modules["idaapi"] = idaapi


class FakeFunc:
    def __init__(self, start, end):
        self.start_ea = start
        self.end_ea = end


_FUNCS = {0x1000: FakeFunc(0x1000, 0x1100)}
idaapi.get_func = lambda ea: _FUNCS.get(ea)


class FakeBlock:
    def __init__(self, start, end):
        self.start_ea = start
        self.end_ea = end
        self.type = 0

    def succs(self):
        return []

    def preds(self):
        return []


idaapi.FlowChart = lambda func: [FakeBlock(0x1000, 0x1008), FakeBlock(0x1008, 0x1100)]

ida_funcs = types.ModuleType("ida_funcs")
ida_funcs.get_func = lambda ea: _FUNCS.get(ea)
ida_funcs.get_func_name = lambda ea: "main" if ea == 0x1000 else None
sys.modules["ida_funcs"] = ida_funcs


class FakeLine:
    def __init__(self, line):
        self.line = line


class FakeMblock:
    def __init__(self, start, end):
        self.start = start
        self.end = end


class FakeMba:
    maturity = 5
    qty = 2

    def get_mblock(self, i):
        return FakeMblock(0x1000 + i * 8, 0x1008 + i * 8)


class FakeCFunc:
    mba = FakeMba()

    def get_pseudocode(self):
        return [FakeLine(f"line {i}") for i in range(600)]


_HEXRAYS_AVAILABLE = [True]

ida_hexrays = types.ModuleType("ida_hexrays")
ida_hexrays.init_hexrays_plugin = lambda: _HEXRAYS_AVAILABLE[0]
ida_hexrays.decompile = lambda ea: FakeCFunc()
ida_hexrays.mark_cfunc_dirty = lambda ea: None
sys.modules["ida_hexrays"] = ida_hexrays

ida_lines = types.ModuleType("ida_lines")
ida_lines.tag_remove = lambda s: s
ida_lines.generate_disasm_line = lambda ea, flags: f"insn_{ea:x}"
sys.modules["ida_lines"] = ida_lines

idautils = types.ModuleType("idautils")
idautils.Heads = lambda start, end: iter([start])
sys.modules["idautils"] = idautils

# =========================================================================
# Load api_hexrays.py
# =========================================================================

HERE = os.path.dirname(os.path.abspath(__file__))
PKG = os.path.join(HERE, "..", "ida_mcp")
src = open(os.path.join(PKG, "api_hexrays.py")).read()
src = src.replace("from .rpc import tool", "tool = lambda f: f")
src = src.replace(
    "from .sync import (idasync, tool_timeout, check_cancelled,\n"
    "                   CancelledError, IDASyncError)",
    "idasync = lambda f: f\n"
    "def tool_timeout(s):\n"
    "    def deco(fn):\n"
    "        return fn\n"
    "    return deco\n"
    "def check_cancelled(): return None\n"
    "class CancelledError(Exception): pass\n"
    "class IDASyncError(Exception): pass",
)
src = src.replace(
    "from .api_analysis import parse_addr, _cap_lines",
    "def parse_addr(s):\n"
    "    s = str(s).strip()\n"
    "    if s.startswith('0x'): return int(s, 16)\n"
    "    try: return int(s)\n"
    "    except ValueError: raise ValueError(f'Unknown: {s}')\n"
    "def _cap_lines(text, max_lines):\n"
    "    if text is None: return None, None\n"
    "    lines = text.split(chr(10))\n"
    "    if len(lines) <= max_lines: return text, None\n"
    "    return chr(10).join(lines[:max_lines]), len(lines)",
)
mod = types.ModuleType("hexrays_test")
exec(compile(src, "hexrays_test", "exec"), mod.__dict__)
sys.modules["hexrays_test"] = mod

# =========================================================================
# Tests
# =========================================================================

r = json.loads(mod.get_microcode("0x1000"))
assert r["maturity"] == 5 and r["maturity_name"] == "MMAT_GENERATED", r
assert r["num_blocks"] == 2 and len(r["blocks"]) == 2, r
assert r["blocks"][0]["start"] == "0x1000", r
r = json.loads(mod.get_microcode("0x9999"))
assert "error" in r, r
_HEXRAYS_AVAILABLE[0] = False
r = json.loads(mod.get_microcode("0x1000"))
assert "not available" in r["error"], r
_HEXRAYS_AVAILABLE[0] = True
print("get_microcode OK")

r = json.loads(mod.get_flowchart("0x1000"))
assert r["count"] == 2 and r["truncated"] is False, r
assert r["blocks"][0]["start"] == "0x1000" and r["blocks"][0]["instructions"] == 1, r
r = json.loads(mod.get_flowchart("0x9999"))
assert "error" in r, r
print("get_flowchart OK")

r = json.loads(mod.get_basic_blocks("0x1000"))
assert r["count"] == 2, r
assert r["blocks"][0]["instructions"] == ["0x1000: insn_1000"], r
print("get_basic_blocks OK")

r = json.loads(mod.force_recompile("0x1000"))
assert r["lines"] == 500 and r["truncated"] == 600, r
assert r["name"] == "main", r
print("force_recompile truncation OK")

print("ALL HEXRAYS TESTS PASSED")
