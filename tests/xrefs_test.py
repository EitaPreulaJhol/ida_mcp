"""Tests for api_xrefs.py (directional cross-reference tools).

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
idaapi.fl_CF = 16
idaapi.fl_CN = 17
idaapi.fl_JF = 18
idaapi.fl_JN = 19
idaapi.dr_R = 2
idaapi.dr_W = 1
sys.modules["idaapi"] = idaapi


class FakeFunc:
    def __init__(self, start, end):
        self.start_ea = start
        self.end_ea = end


_FUNCS = {0x1000: FakeFunc(0x1000, 0x1100), 0x2000: FakeFunc(0x2000, 0x2050)}
_FUNC_NAMES = {0x1000: "main", 0x2000: "sub"}


def _containing(ea):
    for f in _FUNCS.values():
        if f.start_ea <= ea < f.end_ea:
            return f
    return None


ida_funcs = types.ModuleType("ida_funcs")
ida_funcs.get_func = _containing
ida_funcs.get_func_name = lambda ea: _FUNC_NAMES.get(ea)
sys.modules["ida_funcs"] = ida_funcs

ida_typeinf = types.ModuleType("ida_typeinf")
ida_typeinf.BTF_STRUCT = 5
ida_typeinf.get_idati = lambda: object()


class FakeTif:
    def get_named_type(self, til, name, *args):
        return name == "Point"

    def get_udm_tid(self, idx):
        return 0x9000


ida_typeinf.tinfo_t = FakeTif
ida_typeinf.get_udm_by_fullname = lambda til, full: 0 if full == "Point.x" else -1
sys.modules["ida_typeinf"] = ida_typeinf


class FakeXref:
    def __init__(self, frm=None, to=None, iscode=True, xtype=16):
        self.frm = frm
        self.to = to
        self.iscode = iscode
        self.type = xtype


_XREFS_TO = {
    0x2000: [FakeXref(frm=0x1008, to=0x2000, iscode=True, xtype=17),
             FakeXref(frm=0x1008, to=0x2000, iscode=True, xtype=17),  # dup caller
             FakeXref(frm=0x8000, to=0x2000, iscode=True, xtype=17),  # no func
             FakeXref(frm=0x3000, to=0x2000, iscode=False, xtype=2),
             FakeXref(frm=0x3004, to=0x2000, iscode=False, xtype=1),
             FakeXref(frm=0x1010, to=0x2000, iscode=True, xtype=19)],
    0x9000: [FakeXref(frm=0x1000, to=0x9000, iscode=False, xtype=2)],
}
_XREFS_FROM = {
    0x1000: [FakeXref(frm=0x1000, to=0x2000, iscode=True, xtype=17),
             FakeXref(frm=0x1005, to=0x4000, iscode=False, xtype=2)],
}

idautils = types.ModuleType("idautils")
idautils.XrefsTo = lambda ea, flags: iter(list(_XREFS_TO.get(ea, [])))
idautils.XrefsFrom = lambda ea, flags: iter(list(_XREFS_FROM.get(ea, [])))
idautils.CodeRefsFrom = lambda ea, flags: iter([0x2000] if ea == 0x1008 else [])
idautils.FuncItems = lambda ea: iter([0x1000, 0x1008]) if ea == 0x1000 else iter([])
sys.modules["idautils"] = idautils

# =========================================================================
# Load api_xrefs.py
# =========================================================================

from _harness import API_ANALYSIS_HELPERS, RPC_STUB, SYNC_STUB, load  # noqa: E402
mod = load("api_xrefs", {
    "rpc": RPC_STUB,
    "sync": SYNC_STUB,
    "api_analysis": "import json as _json\n"
    "def resolve_addr(s):\n"
    "    try: return parse_addr(s), None\n"
    "    except ValueError as e: return None, _json.dumps({'error': str(e)})\n"
    "def paginate(rows, offset, count):\n"
    "    if count <= 0: count = len(rows)\n"
    "    return (rows[offset:offset + count],\n"
    "            offset + count if offset + count < len(rows) else None)\n"
    "def parse_addr(s):\n"
    "    s = str(s).strip()\n"
    "    if s.startswith('0x'): return int(s, 16)\n"
    "    try: return int(s)\n"
    "    except ValueError: raise ValueError(f'Unknown: {s}')" + API_ANALYSIS_HELPERS,
    "compat": "badaddr = lambda: -1",
}, alias="xrefs_test")

# =========================================================================
# Tests
# =========================================================================

r = json.loads(mod.get_xrefs("0x2000", limit=100))
dirs = {x["direction"] for x in r["xrefs"]}
assert r["count"] == 6 and dirs == {"to"}, r  # no outgoing from 0x2000
r = json.loads(mod.get_xrefs("0x1000", limit=100))
assert {x["direction"] for x in r["xrefs"]} == {"from"}, r
print("get_xrefs OK")

r = json.loads(mod.get_xrefs_from("0x1000"))
assert r["count"] == 2 and r["xrefs"][0]["function"] == "main", r
print("get_xrefs_from OK")

r = json.loads(mod.get_code_refs_to("0x2000"))
assert r["count"] == 4 and all(x["type"] == "code" for x in r["xrefs"]), r
r = json.loads(mod.get_data_refs_to("0x2000"))
assert r["count"] == 2 and all(x["type"] == "data" for x in r["xrefs"]), r
r = json.loads(mod.get_code_refs_from("0x1000"))
assert r["count"] == 1, r
r = json.loads(mod.get_data_refs_from("0x1000"))
assert r["count"] == 1 and r["xrefs"][0]["to"] == "0x4000", r
print("code/data refs OK")

r = json.loads(mod.get_calls_to("0x2000"))
assert r["count"] == 3, r  # 3x fl_CN (jump + data excluded)
r = json.loads(mod.get_calls_from("0x1000"))
assert r["count"] == 1, r
r = json.loads(mod.get_jumps_to("0x2000"))
assert r["count"] == 1 and r["xrefs"][0]["from"] == "0x1010", r
print("calls/jumps OK")

r = json.loads(mod.get_reads_of("0x2000"))
assert r["count"] == 1 and r["xrefs"][0]["from"] == "0x3000", r
r = json.loads(mod.get_writes_to("0x2000"))
assert r["count"] == 1 and r["xrefs"][0]["from"] == "0x3004", r
print("reads/writes OK")

r = json.loads(mod.get_xref_count("0x2000"))
assert r == {"addr": "0x2000", "to": 6, "from": 0, "total": 6}, r
print("get_xref_count OK")

r = json.loads(mod.get_caller_count("0x2000"))
assert r["caller_count"] == 1, r  # main only (0x8000 has no func, dup collapsed)
r = json.loads(mod.get_callee_count("0x1000"))
assert r["callee_count"] == 1, r
r = json.loads(mod.get_callee_count("0x9999"))
assert "error" in r, r
print("caller/callee counts OK")

r = json.loads(mod.xrefs_to_field("Point", "x"))
assert r["count"] == 1 and r["xrefs"][0]["from"] == "0x1000", r
r = json.loads(mod.xrefs_to_field("Nope", "x"))
assert "not found" in r["error"], r
r = json.loads(mod.xrefs_to_field("Point", "nope"))
assert "not found" in r["error"], r
print("xrefs_to_field OK")

r = json.loads(mod.get_xrefs("bogus"))
assert "error" in r, r
print("bad address OK")

# --- oversized limit is clamped to the documented maximum, not reset ------
r = json.loads(mod.get_xrefs("0x1000", limit=99999))
assert r["limit"] == 5000, r
r = json.loads(mod.get_xrefs("0x1000", limit=0))
assert r["limit"] == 5000, r
print("xref limit clamped + echoed OK")

print("ALL XREFS TESTS PASSED")
