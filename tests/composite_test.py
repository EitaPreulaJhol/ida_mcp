"""Tests for api_composite.py (composite analysis tools).

Stubs IDA modules and loads the source via exec. Fake world: main@0x1000
calls sub@0x2000; outsider@0x8000 calls main; string "secret"@0x3000;
global g_config@0x4000 referenced by main and sub.
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
idaapi.fl_CF = 16
idaapi.fl_CN = 17
idaapi.FUNC_LIB = 4
idaapi.FUNC_THUNK = 1
idaapi.SEGPERM_READ = 4
idaapi.SEGPERM_WRITE = 2
idaapi.SEGPERM_EXEC = 1
sys.modules["idaapi"] = idaapi


class FakeFunc:
    def __init__(self, start, end, flags=0):
        self.start_ea = start
        self.end_ea = end
        self.flags = flags


_FUNCS = {0x1000: FakeFunc(0x1000, 0x1100),
          0x2000: FakeFunc(0x2000, 0x2050),
          0x8000: FakeFunc(0x8000, 0x8010)}
_FUNC_NAMES = {0x1000: "main", 0x2000: "sub", 0x8000: "outsider",
               0x4000: "g_config"}

def _containing(ea):
    for f in _FUNCS.values():
        if f.start_ea <= ea < f.end_ea:
            return f
    return None


idaapi.get_func = _containing
idaapi.get_name = lambda ea: _FUNC_NAMES.get(ea, "")
idaapi.get_imagebase = lambda: 0x400000


class FakeBlock:
    def __init__(self, start, end, succs):
        self.start_ea = start
        self.end_ea = end
        self._succs = succs

    def succs(self):
        return self._succs


_B0 = FakeBlock(0x1000, 0x1005, [])
_B1 = FakeBlock(0x1005, 0x1008, [])
_B2 = FakeBlock(0x1008, 0x1100, [])
_B0._succs = [_B1, _B2]
_B1._succs = [_B2]
idaapi.FlowChart = lambda func: [_B0, _B1, _B2]


class FakeSeg:
    def __init__(self):
        self.start_ea = 0x1000
        self.end_ea = 0x5000
        self.perm = 5  # r+x


idaapi.getseg = lambda ea: FakeSeg()

ida_funcs = types.ModuleType("ida_funcs")
ida_funcs.get_func = _containing
ida_funcs.get_func_name = lambda ea: (_containing(ea) and _FUNC_NAMES.get(_containing(ea).start_ea)) or _FUNC_NAMES.get(ea)
ida_funcs.get_func_cmt = lambda func, rep: "main func" if func.start_ea == 0x1000 else None
sys.modules["ida_funcs"] = ida_funcs


class FakeLine:
    def __init__(self, line):
        self.line = line


class FakeCFunc:
    def get_pseudocode(self):
        return [FakeLine(f"line {i}") for i in range(150)]


ida_hexrays = types.ModuleType("ida_hexrays")
ida_hexrays.decompile = lambda ea: FakeCFunc()
ida_hexrays.mark_cfunc_dirty = lambda ea: None
sys.modules["ida_hexrays"] = ida_hexrays

ida_lines = types.ModuleType("ida_lines")
ida_lines.tag_remove = lambda s: s
ida_lines.generate_disasm_line = lambda ea, flags: f"insn_{ea:x}"
sys.modules["ida_lines"] = ida_lines

ida_bytes = types.ModuleType("ida_bytes")
ida_bytes.get_cmt = lambda ea, rep: "check this" if (ea == 0x1000 and not rep) else None
ida_bytes.set_cmt = lambda ea, cmt, rep: True
ida_bytes.get_strlit_contents = lambda ea, length=-1, strtype=0: b"secret" if ea == 0x3000 else None
sys.modules["ida_bytes"] = ida_bytes

ida_nalt = types.ModuleType("ida_nalt")
ida_nalt.STRTYPE_C = 0
ida_nalt.get_tinfo = lambda tif, ea: False
ida_nalt.get_root_filename = lambda: "fake.exe"
ida_nalt.get_input_file_path = lambda: ""
ida_nalt.get_import_module_qty = lambda: 1
ida_nalt.get_import_module_name = lambda i: "kernel32"
ida_nalt.enum_import_names = lambda i, cb: (cb(0x5000, "CreateFileW", 1), True)[1]
sys.modules["ida_nalt"] = ida_nalt

ida_typeinf = types.ModuleType("ida_typeinf")
ida_typeinf.tinfo_t = type("tinfo_t", (), {})
ida_typeinf.func_type_data_t = type("func_type_data_t", (), {})
ida_typeinf.parse_decl = lambda tif, til, decl, flags: False
ida_typeinf.get_idati = lambda: None
ida_typeinf.apply_tinfo = lambda ea, tif, flags: False
ida_typeinf.TINFO_DEFINITE = 1
sys.modules["ida_typeinf"] = ida_typeinf

ida_ua = types.ModuleType("ida_ua")
ida_ua.o_void = 0
ida_ua.o_imm = 5


class FakeOp:
    def __init__(self, otype, value=0):
        self.type = otype
        self.value = value


class FakeInsn:
    def __init__(self):
        self.ops = []
        self.size = 0


def _fake_decode(insn, ea):
    if ea == 0x1000:
        insn.ops = [FakeOp(ida_ua.o_imm, 0x1234)]
        insn.size = 5
        return 5
    return 0


ida_ua.insn_t = FakeInsn
ida_ua.decode_insn = _fake_decode
sys.modules["ida_ua"] = ida_ua

ida_segment = types.ModuleType("ida_segment")
ida_segment.getseg = lambda ea: FakeSeg()
ida_segment.get_segm_name = lambda seg: ".text"
sys.modules["ida_segment"] = ida_segment

ida_entry = types.ModuleType("ida_entry")
ida_entry.get_entry_qty = lambda: 1
ida_entry.get_entry_ordinal = lambda i: 1
ida_entry.get_entry = lambda ordinal: 0x1000
ida_entry.get_entry_name = lambda ordinal: "start"
sys.modules["ida_entry"] = ida_entry

ida_name = types.ModuleType("ida_name")
ida_name.SN_NOWARN = 1
ida_name.set_name = lambda ea, name, flags: True
sys.modules["ida_name"] = ida_name


class FakeXref:
    def __init__(self, frm=None, to=None, iscode=True, xtype=16):
        self.frm = frm
        self.to = to
        self.iscode = iscode
        self.type = xtype


_XREFS_FROM = {
    0x1005: [FakeXref(to=0x3000, iscode=False, xtype=1),
             FakeXref(to=0x4000, iscode=False, xtype=1)],
    0x1008: [FakeXref(to=0x2000, iscode=True, xtype=16)],
    0x2000: [FakeXref(to=0x4000, iscode=False, xtype=1),
             FakeXref(to=0x3000, iscode=False, xtype=1)],
}
_XREFS_TO = {
    0x1000: [FakeXref(frm=0x2002, iscode=True, xtype=17),
             FakeXref(frm=0x8000, iscode=True, xtype=17)],
    0x2000: [FakeXref(frm=0x1008, iscode=True, xtype=17)],
    0x3000: [FakeXref(frm=0x1005, iscode=False, xtype=1),
             FakeXref(frm=0x2000, iscode=False, xtype=1)],
    0x3010: [],
    0x8000: [],
}
_CODE_FROM = {0x1008: [0x2000]}

idautils = types.ModuleType("idautils")
idautils.Functions = lambda: iter([0x1000, 0x2000, 0x8000])
idautils.FuncItems = lambda ea: iter(
    {0x1000: [0x1000, 0x1005, 0x1008], 0x2000: [0x2000], 0x8000: [0x8000]}.get(ea, []))
idautils.XrefsFrom = lambda ea, flags: iter(list(_XREFS_FROM.get(ea, [])))
idautils.XrefsTo = lambda ea, flags: iter(list(_XREFS_TO.get(ea, [])))
idautils.CodeRefsFrom = lambda ea, flags: iter(list(_CODE_FROM.get(ea, [])))
idautils.Segments = lambda: iter([0x1000])


class FakeStr:
    def __init__(self, ea, value):
        self.ea = ea
        self._value = value
        self.length = len(value)

    def __str__(self):
        return self._value


idautils.Strings = lambda: iter([FakeStr(0x3000, "secret"), FakeStr(0x3010, "debug-log")])
sys.modules["idautils"] = idautils

idc = types.ModuleType("idc")
idc.GetDisasm = lambda ea: f"insn_{ea:x}"
idc.get_name = lambda ea: _FUNC_NAMES.get(ea, "")
idc.get_idb_path = lambda: "/tmp/fake.i64"
sys.modules["idc"] = idc

# =========================================================================
# Load api_composite.py
# =========================================================================

HERE = os.path.dirname(os.path.abspath(__file__))
PKG = os.path.join(HERE, "..", "ida_mcp")
src = open(os.path.join(PKG, "api_composite.py")).read()
src = src.replace(
    "from .rpc import tool, unsafe",
    "tool = lambda f: f\nunsafe = lambda f: f",
)
src = src.replace(
    "from .sync import idasync, tool_timeout, get_tool_deadline",
    "idasync = lambda f: f\n"
    "def tool_timeout(s):\n"
    "    def deco(fn):\n"
    "        return fn\n"
    "    return deco\n"
    "get_tool_deadline = lambda: None",
)
src = src.replace(
    "from .api_analysis import parse_addr",
    "def parse_addr(s):\n"
    "    s = str(s).strip()\n"
    "    if s.startswith('0x'): return int(s, 16)\n"
    "    try: return int(s)\n"
    "    except ValueError: pass\n"
    "    table = {'main': 0x1000, 'sub': 0x2000}\n"
    "    if s in table: return table[s]\n"
    "    raise ValueError(f'Unknown: {s}')",
)
src = src.replace(
    "from .compat import inf_is_64bit, is_loaded as _is_loaded",
    "inf_is_64bit = lambda: True\n_is_loaded = lambda ea: True",
)
mod = types.ModuleType("composite_test")
exec(compile(src, "composite_test", "exec"), mod.__dict__)
sys.modules["composite_test"] = mod

# =========================================================================
# Tests
# =========================================================================

# --- analyze_function ---
r = json.loads(mod.analyze_function("0x1000"))
assert r["name"] == "main" and r["size"] == 0x100, r
assert r["prototype"] is None, r  # no tinfo in fake world
assert len(r["decompiled"].split("\n")) == 100, len(r["decompiled"].split("\n"))
assert r["decompile_truncated"] == 150, r
assert r["strings"] == ["secret"], r
assert r["constants"][0]["value"] == "0x1234", r
assert r["callees"] == ["sub"], r
assert r["callers"] == ["sub", "outsider"], r
assert r["comments"]["regular"] == "check this", r
assert r["comments"]["function"] == "main func", r
assert r["basic_blocks"] == {"count": 3, "cyclomatic_complexity": 2}, r
assert "assembly" not in r, r
r = json.loads(mod.analyze_function("0x1000", include_asm=True))
assert "insn_1000" in r["assembly"], r
r = json.loads(mod.analyze_function("0x9999"))
assert "error" in r, r
print("analyze_function OK")

# --- func_profile ---
r = json.loads(mod.func_profile("main"))
assert r["size_int"] == 0x100 and r["instruction_count"] == 3, r
assert r["basic_block_count"] == 3 and r["caller_count"] == 2, r
assert r["callee_count"] == 1 and r["string_ref_count"] == 1, r
assert r["constant_count"] == 1 and r["has_type"] is False, r
assert "callers" not in r, r
r = json.loads(mod.func_profile("main", include_lists=True, max_items=1))
assert len(r["callers"]) == 1 and r["callers_truncated"] is True, r
assert len(r["strings"]) == 1 and r["strings_truncated"] is False, r
print("func_profile OK")

# --- analyze_component ---
r = json.loads(mod.analyze_component("main, sub"))
assert len(r["functions"]) == 2, r
assert r["internal_call_graph"]["edges"] == [
    {"from": "0x1000", "to": "0x2000", "name": "sub"}], r
assert r["shared_globals"] == [
    {"addr": "0x3000", "name": "0x3000",
     "accessed_by": ["main", "sub"]},
    {"addr": "0x4000", "name": "g_config",
     "accessed_by": ["main", "sub"]}], r
assert r["interface_functions"] == ["0x1000"], r  # outsider calls main
assert r["internal_only"] == ["0x2000"], r
assert r["string_usage"] == {"secret": ["main", "sub"]}, r
r = json.loads(mod.analyze_component("nope"))
assert "error" in r, r
print("analyze_component OK")

# --- trace_data_flow ---
r = json.loads(mod.trace_data_flow("0x3000", direction="backward"))
addrs = {n["addr"] for n in r["nodes"]}
assert {"0x3000", "0x1005", "0x2000", "0x1008"} <= addrs, addrs
assert r["depth_reached"] == 2 and r["direction"] == "backward", r
node = next(n for n in r["nodes"] if n["addr"] == "0x1005")
assert node["func"] == "main" and node["type"] == "code", node
r = json.loads(mod.trace_data_flow("0x1000", direction="forward"))
assert len(r["nodes"]) == 1 and r["edges"] == [], r
r = json.loads(mod.trace_data_flow("0x3000", direction="sideways"))
assert "error" in r, r
r = json.loads(mod.trace_data_flow("0x3000", direction="backward", max_depth=0))
assert r["depth_reached"] <= 1, r
print("trace_data_flow OK")

# --- callgraph ---
r = json.loads(mod.callgraph("main"))
g = r["graphs"][0]
assert {n["addr"] for n in g["nodes"]} == {"0x1000", "0x2000"}, g
assert g["edges"] == [{"from": "0x1000", "to": "0x2000"}], g
assert g["truncated"] is False, g
r = json.loads(mod.callgraph("main", max_depth=0))
assert len(r["graphs"][0]["nodes"]) == 1, r  # root only; edge still recorded (official parity)
r = json.loads(mod.callgraph("nope"))
assert r["graphs"][0]["error"] == "Function not found", r
print("callgraph OK")

# --- survey_binary ---
r = json.loads(mod.survey_binary("minimal"))
assert r["metadata"]["arch"] == "64", r
assert r["statistics"]["total_functions"] == 3, r
assert len(r["segments"]) == 1 and r["segments"][0]["name"] == ".text", r
assert r["entrypoints"] == [{"addr": "0x1000", "name": "start", "ordinal": 1}], r
assert "interesting_strings" not in r and "call_graph_summary" not in r, r
r = json.loads(mod.survey_binary())
assert r["interesting_strings"] == [
    {"addr": "0x3000", "string": "secret", "xref_count": 2}], r
assert r["interesting_functions"][0]["name"] == "main", r
assert "crypto" in r["imports_by_category"], r
assert r["call_graph_summary"]["total_edges"] == 1, r
assert r["call_graph_summary"]["leaf_functions_count"] == 2, r
assert "outsider" in r["call_graph_summary"]["root_functions"], r
print("survey_binary OK")

# expired deadline -> partial results with flag instead of timeout error
mod.__dict__["get_tool_deadline"] = lambda: 0.0
r = json.loads(mod.survey_binary())
assert r.get("interesting_strings_partial") is True, r
mod.__dict__["get_tool_deadline"] = lambda: None

# --- diff_before_after ---
r = json.loads(mod.diff_before_after("main", "rename_func", '{"name": "newmain"}'))
assert r["action_applied"] == "Renamed to 'newmain'", r
assert r["changes_detected"] is False and r["before"] == r["after"], r
r = json.loads(mod.diff_before_after("main", "set_comment", '{"comment": "hi"}'))
assert "Set comment" in r["action_applied"], r
r = json.loads(mod.diff_before_after("main", "bogus", "{}"))
assert "error" in r, r
r = json.loads(mod.diff_before_after("main", "set_type", '{"type": "int f()"}'))
assert "error" in r, r  # parse_decl stub returns False
r = json.loads(mod.diff_before_after("0x9999", "rename_func", '{"name": "x"}'))
assert "error" in r, r
print("diff_before_after OK")

print("ALL COMPOSITE TESTS PASSED")
