"""Tests for api_query.py (advanced query tools).

Stubs IDA modules and loads the source via exec.
"""
import json
import os
import sys
import types

# =========================================================================
# Stub IDA modules — coherent fake world
# =========================================================================

ida_auto = types.ModuleType("ida_auto")
ida_auto.auto_wait = lambda: None
sys.modules["ida_auto"] = ida_auto

idaapi = types.ModuleType("idaapi")
idaapi.BADADDR = -1
idaapi.fl_CF = 16
idaapi.fl_CN = 17
sys.modules["idaapi"] = idaapi


class FakeFunc:
    def __init__(self, start, end):
        self.start_ea = start
        self.end_ea = end


_FUNCS = {0x1000: FakeFunc(0x1000, 0x1100),   # main, size 0x100
          0x2000: FakeFunc(0x2000, 0x2020),   # helper, size 0x20
          0x3000: FakeFunc(0x3000, 0x3500)}   # bigfunc, size 0x500, typed
_FUNC_NAMES = {0x1000: "main", 0x2000: "helper", 0x3000: "bigfunc"}

idaapi.get_func = lambda ea: _FUNCS.get(ea)
idaapi.get_name = lambda ea: _FUNC_NAMES.get(ea, "")

ida_funcs = types.ModuleType("ida_funcs")
ida_funcs.get_func = lambda ea: _FUNCS.get(ea)
ida_funcs.get_func_name = lambda ea: _FUNC_NAMES.get(ea)
sys.modules["ida_funcs"] = ida_funcs

ida_nalt = types.ModuleType("ida_nalt")
ida_nalt.get_tinfo = lambda tif, ea: ea == 0x3000
ida_nalt.STRTYPE_C = 0
_IMPORTS = [("kernel32", [(0x5000, "CreateFileW", 1)]),
            ("ws2_32", [(0x5008, "send", 2)])]
ida_nalt.get_import_module_qty = lambda: len(_IMPORTS)
ida_nalt.get_import_module_name = lambda i: _IMPORTS[i][0]


def _fake_enum(i, cb):
    for ea, name, ordinal in _IMPORTS[i][1]:
        cb(ea, name, ordinal)
    return True


ida_nalt.enum_import_names = _fake_enum
sys.modules["ida_nalt"] = ida_nalt

ida_segment = types.ModuleType("ida_segment")


class FakeSeg:
    def __init__(self, name):
        self._name = name


_SEG_BY_EA = {0x1000: ".text", 0x2000: ".text", 0x3000: ".text",
              0x4000: ".rdata", 0x4010: ".rdata", 0x6000: ".data"}
ida_segment.getseg = lambda ea: FakeSeg(_SEG_BY_EA.get(ea, "")) if ea in _SEG_BY_EA else None
ida_segment.get_segm_name = lambda seg: seg._name
sys.modules["ida_segment"] = ida_segment

ida_typeinf = types.ModuleType("ida_typeinf")
ida_typeinf.tinfo_t = type("tinfo_t", (), {})
sys.modules["ida_typeinf"] = ida_typeinf

ida_lines = types.ModuleType("ida_lines")
ida_lines.tag_remove = lambda s: s
_DISASM = {0x1000: "push rbp", 0x1001: "mov [rbp+buf], rax", 0x1002: "call helper"}
ida_lines.generate_disasm_line = lambda ea, flags: _DISASM.get(ea, "nop")
sys.modules["ida_lines"] = ida_lines

idautils = types.ModuleType("idautils")
idautils.Functions = lambda: iter([0x1000, 0x2000, 0x3000])
idautils.Names = lambda: iter([(0x1000, "main"), (0x2000, "helper"),
                               (0x3000, "bigfunc"), (0x6000, "g_config")])
idautils.FuncItems = lambda ea: iter([0x1000, 0x1001, 0x1002]) if ea == 0x1000 else iter([])


class FakeStr:
    def __init__(self, ea, value):
        self.ea = ea
        self._value = value
        self.length = len(value)

    def __str__(self):
        return self._value


idautils.Strings = lambda: iter([FakeStr(0x4000, "hello"), FakeStr(0x4010, "error: failed")])
sys.modules["idautils"] = idautils

# =========================================================================
# Load api_query.py
# =========================================================================

HERE = os.path.dirname(os.path.abspath(__file__))
PKG = os.path.join(HERE, "..", "ida_mcp")
src = open(os.path.join(PKG, "api_query.py")).read()
src = src.replace("from .rpc import tool", "tool = lambda f: f")
src = src.replace("from .sync import idasync", "idasync = lambda f: f")
src = src.replace(
    "from .api_analysis import parse_addr",
    "def parse_addr(s):\n"
    "    s = str(s).strip()\n"
    "    if s.startswith('0x'): return int(s, 16)\n"
    "    try: return int(s)\n"
    "    except ValueError: pass\n"
    "    table = {'main': 0x1000}\n"
    "    if s in table: return table[s]\n"
    "    raise ValueError(f'Unknown: {s}')",
)
src = src.replace(
    "from .api_functions import _collect_frame_vars",
    "def _collect_frame_vars(func):\n"
    "    if func.start_ea == 0x1000:\n"
    "        return [{'name': 'buf', 'offset': -32, 'size': 64, 'type': 'local', 'type_info': None},\n"
    "                {'name': 'argc', 'offset': 8, 'size': 4, 'type': 'argument', 'type_info': 'int'}]\n"
    "    return []",
)
mod = types.ModuleType("query_test")
exec(compile(src, "query_test", "exec"), mod.__dict__)
sys.modules["query_test"] = mod

# =========================================================================
# Tests
# =========================================================================

# --- func_query ---
r = json.loads(mod.func_query())
assert r["total"] == 3, r
r = json.loads(mod.func_query(name_regex="^(main|helper)$"))
assert r["total"] == 2, r
r = json.loads(mod.func_query(min_size=0x100))
assert {f["name"] for f in r["data"]} == {"main", "bigfunc"}, r
r = json.loads(mod.func_query(max_size=0x20))
assert [f["name"] for f in r["data"]] == ["helper"], r
r = json.loads(mod.func_query(has_type="true"))
assert [f["name"] for f in r["data"]] == ["bigfunc"], r
r = json.loads(mod.func_query(has_type="false"))
assert r["total"] == 2, r
r = json.loads(mod.func_query(sort_by="size", descending=True))
assert r["data"][0]["name"] == "bigfunc", r
r = json.loads(mod.func_query(offset=0, count=1))
assert r["next_offset"] == 1 and len(r["data"]) == 1, r
r = json.loads(mod.func_query(name_regex="(["))
assert "error" in r, r
print("func_query OK")

# --- entity_query: all kinds ---
r = json.loads(mod.entity_query(kind="functions"))
assert r["total"] == 3 and r["error"] is None, r
r = json.loads(mod.entity_query(kind="globals"))
assert r["total"] == 1 and r["data"][0]["name"] == "g_config", r
r = json.loads(mod.entity_query(kind="imports"))
assert r["total"] == 2, r
r = json.loads(mod.entity_query(kind="strings"))
assert r["total"] == 2, r
r = json.loads(mod.entity_query(kind="names"))
assert r["total"] == 4, r
r = json.loads(mod.entity_query(kind="bogus"))
assert "error" in r and r["error"], r
print("entity_query kinds OK")

# --- entity_query: filters ---
r = json.loads(mod.entity_query(kind="functions", filter="*func"))
assert r["total"] == 1 and r["data"][0]["name"] == "bigfunc", r
r = json.loads(mod.entity_query(kind="strings", filter="*error*"))
assert r["total"] == 1, r
r = json.loads(mod.entity_query(kind="imports", module="ws2*"))
assert r["total"] == 1 and r["data"][0]["imported_name"] == "send", r
r = json.loads(mod.entity_query(kind="functions", segment=".text"))
assert r["total"] == 3, r
r = json.loads(mod.entity_query(kind="functions", min_addr="0x2000"))
assert r["total"] == 2, r
r = json.loads(mod.entity_query(kind="functions", max_addr="0x2000"))
assert {f["name"] for f in r["data"]} == {"main", "helper"}, r
r = json.loads(mod.entity_query(kind="functions", fields="addr,name"))
assert set(r["data"][0].keys()) == {"addr", "name"}, r
r = json.loads(mod.entity_query(kind="functions", regex="["))
assert "error" in r and r["error"], r
print("entity_query filters OK")

# --- list_globals / imports_query ---
r = json.loads(mod.list_globals("*", 0, 100))
assert r["total"] == 1 and r["data"][0]["name"] == "g_config", r
r = json.loads(mod.list_globals("nomatch*", 0, 100))
assert r["total"] == 0, r
r = json.loads(mod.imports_query(filter="*send*"))
assert r["total"] == 1, r
r = json.loads(mod.imports_query(module="kernel32"))
assert r["data"][0]["imported_name"] == "CreateFileW", r
print("list_globals/imports_query OK")

# --- local variables ---
r = json.loads(mod.get_local_variable_by_name("0x1000", "buf"))
assert r["var"]["offset"] == -32 and r["var"]["type"] == "local", r
r = json.loads(mod.get_local_variable_by_name("0x1000", "nope"))
assert "error" in r, r
r = json.loads(mod.get_local_variable_by_name("0x9999", "buf"))
assert "error" in r, r
print("get_local_variable_by_name OK")

r = json.loads(mod.get_local_variable_references("0x1000", "buf"))
assert r["count"] == 1 and r["references"][0]["addr"] == "0x1001", r
r = json.loads(mod.get_local_variable_references("0x1000", "argc"))
assert r["count"] == 0, r
r = json.loads(mod.get_local_variable_references("0x1000", "nope"))
assert "error" in r, r
print("get_local_variable_references OK")

print("ALL QUERY TESTS PASSED")
