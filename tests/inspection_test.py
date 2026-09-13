"""Tests for core inspection tools: list_imports, list_exports.

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
ida_name.get_name_ea = lambda badaddr, name: badaddr if name != "known" else 0x1000
sys.modules["ida_name"] = ida_name

ida_funcs = types.ModuleType("ida_funcs")
ida_funcs.get_func = lambda ea: None
ida_funcs.get_func_name = lambda ea: None
sys.modules["ida_funcs"] = ida_funcs

# --- ida_nalt (imports) ---
_fake_import_modules: list[str] = ["kernel32.dll", "user32.dll"]
_fake_imports_by_module: dict[int, list[tuple[int, str, int]]] = {
    0: [(0x1000, "CreateFileW", 0), (0x1008, "ReadFile", 1)],
    1: [(0x2000, "MessageBoxW", 0)],
}


def _fake_import_module_qty():
    return len(_fake_import_modules)


def _fake_import_module_name(i):
    return _fake_import_modules[i] if i < len(_fake_import_modules) else None


def _fake_enum_import_names(i, callback):
    for ea, name, ordinal in _fake_imports_by_module.get(i, []):
        callback(ea, name, ordinal)


ida_nalt = types.ModuleType("ida_nalt")
ida_nalt.get_import_module_qty = _fake_import_module_qty
ida_nalt.get_import_module_name = _fake_import_module_name
ida_nalt.enum_import_names = _fake_enum_import_names
sys.modules["ida_nalt"] = ida_nalt

# --- ida_entry (exports) ---
_fake_entry_ords: list[int] = [1, 2, 3]
_fake_entry_addrs: dict[int, int] = {1: 0x3000, 2: 0x4000, 3: 0x5000}
_fake_entry_names: dict[int, str] = {1: "DllMain", 2: "StartService", 3: ""}

ida_entry = types.ModuleType("ida_entry")
ida_entry.get_entry_qty = lambda: len(_fake_entry_ords)
ida_entry.get_entry_ordinal = lambda i: _fake_entry_ords[i]
ida_entry.get_entry = lambda ord: _fake_entry_addrs.get(ord, ida_ida.BADADDR)
ida_entry.get_entry_name = lambda ord: _fake_entry_names.get(ord)
sys.modules["ida_entry"] = ida_entry

# --- Other modules needed for imports ---
ida_bytes = types.ModuleType("ida_bytes")
sys.modules["ida_bytes"] = ida_bytes

ida_hexrays = types.ModuleType("ida_hexrays")
ida_hexrays.init_hexrays_plugin = lambda: False
sys.modules["ida_hexrays"] = ida_hexrays

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

# =========================================================================
# Load api_analysis.py
# =========================================================================

HERE = os.path.dirname(os.path.abspath(__file__))
PKG = os.path.join(HERE, "..", "ida_mcp")
src = open(os.path.join(PKG, "api_analysis.py")).read()
src = src.replace("from .rpc import tool, unsafe, MCP_SERVER",
                   "tool = lambda f: f\nunsafe = lambda f: f\nMCP_SERVER = type('FakeMCP', (), {'unsafe_tools': set()})()")
src = src.replace("from .sync import idasync", "idasync = lambda f: f")
mod = types.ModuleType("inspection_test")
exec(compile(src, "inspection_test", "exec"), mod.__dict__)
sys.modules["inspection_test"] = mod

# =========================================================================
# Tests
# =========================================================================

# --- list_imports ---

# 1) all imports
r = mod.list_imports()
import json
data = json.loads(r)
assert data["total"] == 3, f"expected 3 total imports, got {data}"
assert len(data["data"]) == 3, f"expected 3 items: {data}"
print("list_imports all OK")

# 2) filtered imports
r = mod.list_imports(filter_pattern="*Read*")
data = json.loads(r)
assert data["total"] == 1, f"expected 1 filtered: {data}"
assert data["data"][0]["imported_name"] == "ReadFile", f"expected ReadFile: {data}"
print("list_imports filter OK")

# 3) pagination
r = mod.list_imports(offset=1, count=1)
data = json.loads(r)
assert data["count"] == 1, f"expected 1 page item: {data}"
print("list_imports pagination OK")

# --- list_exports ---

# 4) all exports
r = mod.list_exports()
data = json.loads(r)
assert data["total"] == 3, f"expected 3 exports: {data}"
print("list_exports all OK")

# 5) filtered exports
r = mod.list_exports(filter_pattern="*Dll*")
data = json.loads(r)
assert data["total"] == 1, f"expected 1 filtered: {data}"
assert data["data"][0]["name"] == "DllMain", f"expected DllMain: {data}"
print("list_exports filter OK")

# 6) export with empty name gets ordinal fallback
r = mod.list_exports()
data = json.loads(r)
# Entry ordinal 3 has empty name, should fall back to "#3"
names = [e["name"] for e in data["data"]]
assert "#3" in names or any(n.startswith("#") for n in names), f"expected ordinal fallback: {names}"
print("list_exports ordinal fallback OK")

print("\nALL INSPECTION TESTS PASSED")
