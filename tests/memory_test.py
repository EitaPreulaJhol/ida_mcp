"""Tests for memory reading tools: get_bytes, get_string.

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

_fake_bytes_data: dict[int, bytes] = {}
_fake_string_data: dict[int, bytes | None] = {}


def _fake_get_bytes(ea, size):
    data = _fake_bytes_data.get(ea)
    if data is None:
        # ida_bytes.get_bytes raises on unmapped memory
        raise RuntimeError("Bad address")
    return data[:size]


def _fake_strlit_contents(ea, length=-1, strtype=0):
    return _fake_string_data.get(ea)


ida_bytes = types.ModuleType("ida_bytes")
ida_bytes.get_bytes = _fake_get_bytes
ida_bytes.get_strlit_contents = _fake_strlit_contents
sys.modules["ida_bytes"] = ida_bytes

# --- Modules needed by parse_addr / imports ---
ida_funcs = types.ModuleType("ida_funcs")
ida_funcs.get_func = lambda ea: None
ida_funcs.get_func_name = lambda ea: None
sys.modules["ida_funcs"] = ida_funcs

ida_name = types.ModuleType("ida_name")
ida_name.get_name_ea = lambda badaddr, name: badaddr if name == "unknown" else 0x1000
sys.modules["ida_name"] = ida_name

ida_nalt = types.ModuleType("ida_nalt")
ida_nalt.STRTYPE_C = 0
sys.modules["ida_nalt"] = ida_nalt

ida_hexrays = types.ModuleType("ida_hexrays")
ida_hexrays.init_hexrays_plugin = lambda: False
sys.modules["ida_hexrays"] = ida_hexrays

ida_entry = types.ModuleType("ida_entry")
sys.modules["ida_entry"] = ida_entry

ida_kernwin = types.ModuleType("ida_kernwin")
sys.modules["ida_kernwin"] = ida_kernwin

ida_lines = types.ModuleType("ida_lines")
sys.modules["ida_lines"] = ida_lines

ida_ua = types.ModuleType("ida_ua")
sys.modules["ida_ua"] = ida_ua

idautils = types.ModuleType("idautils")
sys.modules["idautils"] = idautils

idc = types.ModuleType("idc")
sys.modules["idc"] = idc

idaapi = types.ModuleType("idaapi")
idaapi.BADADDR = -1
sys.modules["idaapi"] = idaapi

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

ida_bytes._strlit_contents_hook = None

# =========================================================================
# Load api_analysis.py with patched imports
# =========================================================================

HERE = os.path.dirname(os.path.abspath(__file__))
PKG = os.path.join(HERE, "..", "ida_mcp")
src = open(os.path.join(PKG, "api_analysis.py")).read()
src = src.replace("from .rpc import tool, unsafe, MCP_SERVER",
                   "tool = lambda f: f\nunsafe = lambda f: f\nMCP_SERVER = type('FakeMCP', (), {'unsafe_tools': set()})()")
src = src.replace("from .sync import idasync", "idasync = lambda f: f")
mod = types.ModuleType("memory_test")
exec(compile(src, "memory_test", "exec"), mod.__dict__)
sys.modules["memory_test"] = mod


def setup():
    _fake_bytes_data.clear()
    _fake_string_data.clear()

# =========================================================================
# Tests
# =========================================================================

# --- get_bytes ---

# 1) basic bytes read
setup()
_fake_bytes_data[0x1000] = bytes(range(256))
r = mod.get_bytes("0x1000", size=16)
assert '"addr": "0x1000"' in r, f"missing addr: {r}"
assert "00 01 02 03" in r, f"expected hex prefix: {r}"
assert '"size": 16' in r, f"expected size 16: {r}"
print("get_bytes basic OK")

# 2) ascii representation
assert "...." in r, f"expected ascii dots (non-printable): {r}"
print("get_bytes ascii OK")

# 3) unreachable address
setup()
r = mod.get_bytes("0xDEAD", size=8)
assert "error" in r, f"expected error for bad address: {r}"
print("get_bytes bad address OK")

# 4) invalid name
r = mod.get_bytes("unknown", size=8)
assert "Unknown address" in r, f"expected unknown address error: {r}"
print("get_bytes unknown name OK")

# --- get_string ---

# 5) basic string
setup()
_fake_string_data[0x2000] = b"Hello, World!\x00"
r = mod.get_string("0x2000")
assert "Hello, World!" in r, f"expected string: {r}"
print("get_string basic OK")

# 6) no string
setup()
_fake_string_data[0x3000] = None
r = mod.get_string("0x3000")
assert "No string at address" in r, f"expected no-string: {r}"
print("get_string no string OK")

# 7) bad address
r = mod.get_string("unknown")
assert "Unknown address" in r, f"expected error: {r}"
print("get_string bad address OK")

print("\nALL MEMORY TESTS PASSED")
