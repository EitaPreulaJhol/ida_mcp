"""Tests for analysis tools: xrefs, callees, callers, xref_query,
lookup_funcs, int_convert, find_bytes, disasm, basic_blocks.

Stubs all IDA modules and loads the source via exec.
"""
import json
import os
import sys
import types

# =========================================================================
# Stub IDA modules
# =========================================================================

# --- ida_auto ---
ida_auto = types.ModuleType("ida_auto")
ida_auto.auto_wait = lambda: None
sys.modules["ida_auto"] = ida_auto

# --- ida_ida ---
ida_ida = types.ModuleType("ida_ida")
ida_ida.BADADDR = -1
ida_ida.inf_get_min_ea = lambda: 0
ida_ida.inf_get_max_ea = lambda: 0xFFFFFFFF
sys.modules["ida_ida"] = ida_ida

# --- idaapi ---
idaapi = types.ModuleType("idaapi")
idaapi.BADADDR = -1
idaapi.FlowChart = lambda fn: []
idaapi.cvar = type("cvar", (), {
    "inf": type("inf", (), {"min_ea": 0, "max_ea": 0xFFFFFFFF})()
})()
sys.modules["idaapi"] = idaapi

# --- ida_funcs ---
_fake_functions: dict[int, dict] = {}
_fake_func_names: dict[int, str] = {}


class FakeFunc:
    def __init__(self, start, end):
        self.start_ea = start
        self.end_ea = end


ida_funcs = types.ModuleType("ida_funcs")
ida_funcs.get_func = lambda ea: _fake_functions.get(ea, None)
ida_funcs.get_func_name = lambda ea: _fake_func_names.get(ea, None)
sys.modules["ida_funcs"] = ida_funcs

# --- ida_name ---
ida_name = types.ModuleType("ida_name")
ida_name.get_name = lambda ea: _fake_func_names.get(ea, None)
ida_name.get_name_ea = lambda badaddr, name: {
    "known": 0x1000, "func1": 0x1000, "test_func": 0x5000,
}.get(name, badaddr)
ida_name.get_ea_name = lambda ea: _fake_func_names.get(ea, None)
sys.modules["ida_name"] = ida_name

# --- ida_ua ---
_fake_insn_itype: dict[int, int] = {}
_fake_insn_ops: dict[int, list] = {}


class FakeOp():
    def __init__(self, typ, addr=0, value=0):
        self.type = typ
        self.addr = addr
        self.value = value


# Map of address -> "call" / other mnemonic.  The fake insn's
# get_canon_mnem() returns this so the production code can match calls.
_fake_insn_mnems: dict[int, str] = {}


class _FakeInsn:
    def __init__(self):
        self.itype = 0
        self.ops = []

    def get_canon_mnem(self):
        return _fake_insn_mnems.get(getattr(self, "_ea", 0), "")


ida_ua = types.ModuleType("ida_ua")
ida_ua.insn_t = _FakeInsn
ida_ua.decode_insn = lambda insn, ea: (
    setattr(insn, "_ea", ea) or
    setattr(insn, "itype", _fake_insn_itype.get(ea, 0)) or
    setattr(insn, "ops", _fake_insn_ops.get(ea, [])) or
    1
)
ida_ua.NN_call = 100
ida_ua.NN_callfi = 101
ida_ua.NN_callni = 102
ida_ua.o_mem = 2
ida_ua.o_near = 3
ida_ua.o_far = 4
ida_ua.o_imm = 5
sys.modules["ida_ua"] = ida_ua

# --- idautils ---
_fake_xrefs_to: list = []
_fake_xrefs_from: list = []
_fake_code_refs_to: list = []
_fake_strings: list = []


class FakeXref:
    def __init__(self, frm=0, iscode=True, to=0):
        self.frm = frm
        self.iscode = iscode
        self.to = to


class FakeStringItem:
    def __init__(self, ea=0, value="", length=1, strtype=0):
        self.ea = ea
        self._value = value
        self.length = length
        self.strtype = strtype

    def __str__(self):
        return self._value


def _fake_xrefs_to_iter(ea, flags=0):
    yield from _fake_xrefs_to


def _fake_xrefs_from_iter(ea, flags=0):
    yield from _fake_xrefs_from


def _fake_code_refs_to_iter(ea, flags=0):
    yield from _fake_code_refs_to


idautils = types.ModuleType("idautils")
idautils.XrefsTo = _fake_xrefs_to_iter
idautils.XrefsFrom = _fake_xrefs_from_iter
idautils.CodeRefsTo = _fake_code_refs_to_iter
idautils.Strings = lambda: _fake_strings
idautils.FuncItems = lambda start: []
sys.modules["idautils"] = idautils

# --- idc ---
idc = types.ModuleType("idc")
idc.next_head = lambda ea, end: ea + 4 if ea + 4 < end else end
sys.modules["idc"] = idc

# --- ida_bytes ---
ida_bytes = types.ModuleType("ida_bytes")
ida_bytes.is_mapped = lambda ea: True
ida_bytes.find_bytes = lambda pattern, start_ea, range_end=None: idaapi.BADADDR
ida_bytes.get_bytes = lambda ea, size: bytes(range(size))  # default test bytes
ida_bytes.get_strlit_contents = lambda ea, length=-1, strtype=0: None
sys.modules["ida_bytes"] = ida_bytes

# --- ida_hexrays ---
ida_hexrays = types.ModuleType("ida_hexrays")
sys.modules["ida_hexrays"] = ida_hexrays

# --- ida_nalt ---
ida_nalt = types.ModuleType("ida_nalt")
ida_nalt.get_tinfo = lambda tif, ea: False
sys.modules["ida_nalt"] = ida_nalt

# --- ida_entry ---
ida_entry = types.ModuleType("ida_entry")
sys.modules["ida_entry"] = ida_entry

# --- idaapi ---


class FakeBlock:
    def __init__(self, start=0x1000, end=0x1010, btype=0):
        self.start_ea = start
        self.end_ea = end
        self.type = btype

    def succs(self):
        return []

    def preds(self):
        return []
# The early ``idaapi`` stub (with BADADDR) at the top of this file is reused.

# --- ida_kernwin ---
ida_kernwin = types.ModuleType("ida_kernwin")
ida_kernwin.user_cancelled = lambda: False
sys.modules["ida_kernwin"] = ida_kernwin

# --- ida_lines ---
ida_lines = types.ModuleType("ida_lines")
ida_lines.generate_disasm_line = lambda ea, flags: f"{ea:x}: nop"
ida_lines.tag_remove = lambda s: s
sys.modules["ida_lines"] = ida_lines

# --- ida_segment ---
ida_segment = types.ModuleType("ida_segment")
ida_segment.getseg = lambda ea: None
ida_segment.get_segm_name = lambda seg: "test"
sys.modules["ida_segment"] = ida_segment

# --- ida_typeinf ---
ida_typeinf = types.ModuleType("ida_typeinf")
ida_typeinf.tinfo_t = type("tinfo_t", (), {"__bool__": lambda self: False})
ida_typeinf.func_type_data_t = type("func_type_data_t", (), {"__init__": lambda self: None})
ida_typeinf.get_tinfo = lambda tif, ea: False
ida_typeinf.get_func_details = lambda ftd: False
sys.modules["ida_typeinf"] = ida_typeinf

# =========================================================================
# Load api_analysis.py
# =========================================================================

from _harness import RPC_STUB, SYNC_STUB, load  # noqa: E402
mod = load("api_analysis", {
    "rpc": RPC_STUB,
    "sync": SYNC_STUB,
}, alias="analysis_test")


def setup_module():
    _fake_functions.clear()
    _fake_func_names.clear()
    _fake_insn_itype.clear()
    _fake_insn_ops.clear()
    _fake_insn_mnems.clear()
    _fake_xrefs_to.clear()
    _fake_xrefs_from.clear()
    _fake_code_refs_to.clear()
    _fake_strings.clear()


# =========================================================================
# Tests
# =========================================================================

# --- get_xrefs_to ---

setup_module()
_fake_xrefs_to.append(FakeXref(frm=0x401000, iscode=True))
_fake_xrefs_to.append(FakeXref(frm=0x402000, iscode=False))
_fake_func_names[0x401000] = "func1"
_fake_functions[0x401000] = FakeFunc(0x401000, 0x401100)

r = mod.get_xrefs_to("0x1234")
assert "401000" in r and "402000" in r, f"expected xrefs: {r}"
assert "code" in r and "data" in r, f"expected types: {r}"
r = json.loads(mod.get_xrefs_to("0x1234", limit=0))
assert r["limit"] == 5000 and r["count"] == 2, r
print("get_xrefs_to basic OK")

setup_module()
r = mod.get_xrefs_to("0x5678")
assert "No cross-references" in r, f"expected no-xrefs: {r}"
print("get_xrefs_to empty OK")

r = mod.get_xrefs_to("not_an_address")
assert "Unknown address" in r, f"expected error: {r}"
print("get_xrefs_to bad address OK")

# --- xref_query ---

setup_module()
_fake_xrefs_to.append(FakeXref(frm=0x401000, iscode=True))
_fake_xrefs_from.append(FakeXref(to=0x5000, iscode=True))
_fake_func_names[0x401000] = "func1"
_fake_functions[0x401000] = FakeFunc(0x401000, 0x401100)

r = mod.xref_query("0x1234", direction="both")
assert "401000" in r, f"expected xref in xref_query: {r}"
r = json.loads(mod.xref_query("0x1234", direction="both", limit=0))
assert r["limit"] == 5000 and r["count"] >= 1, r
print("xref_query basic OK")

setup_module()
r = mod.xref_query("0x1234", direction="from")
assert r'{"xrefs": []' in r or "No matching" in r, f"expected empty: {r}"
print("xref_query empty OK")

# --- get_callees ---

setup_module()
_fake_functions[0x1000] = FakeFunc(0x1000, 0x1020)
_fake_insn_mnems[0x1000] = "call"
_fake_insn_itype[0x1000] = ida_ua.NN_call
_fake_insn_ops[0x1000] = [FakeOp(ida_ua.o_near, addr=0x2000)]
_fake_insn_mnems[0x1004] = "call"
_fake_insn_itype[0x1004] = ida_ua.NN_call
_fake_insn_ops[0x1004] = [FakeOp(ida_ua.o_near, addr=0x3000)]
_fake_func_names[0x2000] = "target_func"
_fake_func_names[0x3000] = "another_target"
_fake_functions[0x2000] = FakeFunc(0x2000, 0x2100)

r = mod.get_callees("0x1000")
assert "target_func" in r, f"expected target_func: {r}"
assert "another_target" in r, f"expected another_target: {r}"
# pagination: limit/offset bound and page the result list
import json as _json
assert len(_json.loads(mod.get_callees("0x1000", limit=1))) == 1, mod.get_callees("0x1000", limit=1)
full = _json.loads(mod.get_callees("0x1000"))
assert all(c["indirect"] is False for c in full), full
assert _json.loads(mod.get_callees("0x1000", offset=1)) == full[1:], full
# A GOT-style ``call [mem]`` names a pointer slot, not the callee; flag it.
_fake_insn_mnems[0x1008] = "call"
_fake_insn_ops[0x1008] = [FakeOp(ida_ua.o_mem, addr=0x4000)]
mem = [c for c in _json.loads(mod.get_callees("0x1000"))
       if c["addr"] == "0x4000"]
assert mem and mem[0]["indirect"] is True, mem
print("get_callees basic OK")

setup_module()
r = mod.get_callees("0x9999")
assert "No function" in r, f"expected no function: {r}"
print("get_callees no function OK")

# --- get_callers ---

setup_module()
_fake_functions[0x1000] = FakeFunc(0x1000, 0x1020)
_fake_func_names[0x1000] = "caller_func"
_fake_code_refs_to.append(0x1000)
# Set up the instruction mock so get_canon_mnem() returns "call" for the caller address.
_fake_insn_mnems[0x1000] = "call"
_fake_insn_itype[0x1000] = ida_ua.NN_call
_fake_insn_ops[0x1000] = [FakeOp(ida_ua.o_near, addr=0x2000)]

r = mod.get_callers("0x2000")
assert "caller_func" in r, f"expected caller_func: {r}"
print("get_callers basic OK")

setup_module()
_fake_code_refs_to.clear()
r = mod.get_callers("0x2000")
assert r == "[]", f"expected empty list: {r}"
print("get_callers empty OK")

r = mod.get_callers("not_an_address")
assert "Unknown address" in r, f"expected error: {r}"
print("get_callers bad address OK")

# --- lookup_funcs ---

setup_module()
_fake_functions[0x5000] = FakeFunc(0x5000, 0x5100)
_fake_func_names[0x5000] = "test_func"

r = mod.lookup_funcs("0x5000")
assert "test_func" in r, f"expected test_func: {r}"
assert '"size_bytes": 256' in r, f"expected size 256: {r}"
print("lookup_funcs basic OK")

r = mod.lookup_funcs("0x9999")
assert "No function" in r, f"expected no function: {r}"
print("lookup_funcs no function OK")

# --- pagination limit helper: one contract for every paginated tool ---
assert mod.clamp_limit(0, 100, 5000) == 5000
assert mod.clamp_limit(-5, 100, 5000) == 5000
assert mod.clamp_limit(99999, 100, 5000) == 5000
assert mod.clamp_limit("10", 100, 5000) == 10
assert mod.clamp_limit(100, 100, 5000) == 100
print("clamp_limit contract OK")

# --- int_convert ---

r = mod.int_convert("0x7F")
assert '"decimal": "127"' in r, f"expected decimal 127: {r}"
assert '"hexadecimal": "0x7f"' in r or '"hexadecimal": "0x7F"' in r, f"expected hex: {r}"
print("int_convert hex OK")

r = mod.int_convert("42", size=8)
assert '"decimal": "42"' in r, f"expected decimal 42: {r}"
assert '"bytes": "2a 00 00 00 00 00 00 00"' in r, f"expected 8-byte little endian: {r}"
print("int_convert decimal OK")

r = mod.int_convert("0xFF", size=2)
assert '"decimal": "255"' in r, f"expected decimal 255: {r}"
print("int_convert explicit size OK")

# auto-sized values whose top bit is set used to be rejected: the width was
# computed unsigned but to_bytes() was always called with signed=True.
for text, expected in (("128", "80"), ("255", "ff"),
                       ("256", "00 01"), ("-128", "80"),
                       ("-129", "7f ff")):
    r = json.loads(mod.int_convert(text))
    assert r.get("bytes") == expected, (text, r)
print("int_convert signed/unsigned auto-width OK")

r = mod.int_convert("invalid")
assert "Invalid number" in r, f"expected error: {r}"
print("int_convert invalid OK")

# --- find_bytes ---

r = mod.find_bytes("48 8B ??")
assert '"matches": []' in r, f"expected empty matches: {r}"
print("find_bytes basic OK")

r = mod.find_bytes("")
assert "Empty pattern" in r, f"expected empty pattern error: {r}"
print("find_bytes empty pattern OK")

r = mod.find_bytes("ZZ")
# With ida_bytes.find_bytes, invalid hex is passed through to the IDA API
# which returns BADADDR.  The tool should return an empty matches list
# without raising.  In real IDA the API would raise a ValueError, but
# our stub returns BADADDR.
assert '"matches": []' in r, f"expected empty matches: {r}"
print("find_bytes bad pattern OK")

# --- disasm ---

# disasm needs a segment. For now test error path.
r = mod.disasm("0x1000")
assert "No segment" in r or "Could not disassemble" in r, f"expected error (no seg): {r}"
print("disasm error path OK")

# --- basic_blocks ---

setup_module()
_fake_functions[0x6000] = FakeFunc(0x6000, 0x6100)

r = mod.basic_blocks("0x6000")
assert "blocks" in r, f"expected blocks key: {r}"
print("basic_blocks basic OK")

r = mod.basic_blocks("0x9999")
assert "No function" in r, f"expected no function: {r}"
print("basic_blocks no function OK")

# --- type_label (named types keep the name, anonymous get the declaration) ---


class _NamedTif:
    def get_type_name(self):
        return "Point"

    def dstr(self):
        return "struct Point"


class _AnonTif:
    def get_type_name(self):
        return None

    def dstr(self):
        return "unsigned int"


class _BareTif:
    def get_type_name(self):
        return None


assert mod.type_label(_NamedTif()) == "Point"
assert mod.type_label(_AnonTif()) == "unsigned int"
assert mod.type_label(_BareTif()) == "<unnamed>"
print("type_label OK")


# --- get_callers(limit=0) means no cap -----------------------------------
setup_module()
_fake_functions[0x1000] = FakeFunc(0x1000, 0x1020)
_fake_functions[0x1100] = FakeFunc(0x1100, 0x1120)
_fake_func_names[0x1000] = "caller_a"
_fake_func_names[0x1100] = "caller_b"
_fake_code_refs_to.extend([0x1000, 0x1100])
for _ea in (0x1000, 0x1100):
    _fake_insn_mnems[_ea] = "call"
    _fake_insn_itype[_ea] = ida_ua.NN_call
    _fake_insn_ops[_ea] = [FakeOp(ida_ua.o_near, addr=0x2000)]
r = _json.loads(mod.get_callers("0x2000", limit=0))
assert {c["name"] for c in r} == {"caller_a", "caller_b"}, r
print("get_callers limit=0 = no cap OK")

# --- disasm: addr is the requested start, limit clamped to 500 -----------
class _DisasmSeg:
    start_ea = 0x7000
    end_ea = 0x7000 + 500 * 4


_orig_getseg = ida_segment.getseg
ida_segment.getseg = lambda ea: _DisasmSeg() if 0x7000 <= ea < _DisasmSeg.end_ea else None
try:
    r = _json.loads(mod.disasm("0x7000", limit=99999))
finally:
    ida_segment.getseg = _orig_getseg
assert r["limit"] == 500, r
assert r["addr"] == "0x7000", r          # requested address, not the end
assert r["next_ea"] == hex(_DisasmSeg.end_ea), r
assert len(r["instructions"]) == 500, len(r["instructions"])
print("disasm addr/limit OK")

print("\nALL ANALYSIS TESTS PASSED")
