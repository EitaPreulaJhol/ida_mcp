"""Tests for api_sigmaker.py (trimmed signature engine).

Stubs IDA modules and loads the source via exec. Fake world: two similar
code regions where only a longer wildcarded pattern is unique.
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

# Fake memory: similar prefixes, unique tails.
_MEM = {}
_MEM.update({0x1000 + i: b for i, b in enumerate(
    [0x48, 0x8B, 0x05, 0x11, 0x22, 0x33, 0x90])})
_MEM.update({0x2000 + i: b for i, b in enumerate(
    [0x48, 0x8B, 0x05, 0xAA, 0xBB, 0x90])})
# Longer fixture for the chunked uniquess probe (plan 15, item 15.5): 20
# one-byte instructions at 0x6000, the first 12 of which also appear at 0x7000.
_LONG_BASE = 0x6000
_LONG_DUP = 0x7000
_LONG_LEN = 20
_LONG_SHARED = 12
_MEM.update({_LONG_BASE + i: 0x40 + i for i in range(_LONG_LEN)})
_MEM.update({_LONG_DUP + i: 0x40 + i for i in range(_LONG_SHARED)})


class FakeOp:
    def __init__(self, otype, offb=0, dtype=0):
        self.type = otype
        self.offb = offb
        self.dtype = dtype


class FakeInsn:
    def __init__(self, size, ops):
        self.size = size
        self.ops = ops


# insn map: ea -> (size, [(type, offb, dtype)])
_INSNS = {
    0x1000: (5, [("imm", 1, 4)]),
    0x1005: (2, []),
    0x2000: (5, [("imm", 1, 4)]),
    0x2005: (1, []),
}
_INSNS.update({_LONG_BASE + i: (1, []) for i in range(_LONG_LEN)})

ida_ua = types.ModuleType("ida_ua")
ida_ua.o_void = 0
ida_ua.o_imm = 5
ida_ua.o_mem = 2
ida_ua.o_near = 7
ida_ua.o_far = 8
ida_ua.o_displ = 9
ida_ua.get_dtype_size = lambda dtype: dtype if isinstance(dtype, int) else 0


def _fake_decode(insn, ea):
    if ea not in _INSNS:
        return 0
    size, ops = _INSNS[ea]
    type_map = {"imm": ida_ua.o_imm, "mem": ida_ua.o_mem,
                "near": ida_ua.o_near, "far": ida_ua.o_far,
                "displ": ida_ua.o_displ}
    insn.size = size
    insn.ops = [FakeOp(type_map[t], offb, dtype) for t, offb, dtype in ops]
    return size


ida_ua.insn_t = lambda: FakeInsn(0, [])
ida_ua.decode_insn = _fake_decode
sys.modules["ida_ua"] = ida_ua

ida_bytes = types.ModuleType("ida_bytes")


def _fake_find(pattern, ea, range_end=None):
    toks = pattern.split()
    n = len(toks)
    lo = max(ea, 0x1000)
    hi = (range_end or 0x3000) - n + 1
    for base in range(lo, hi):
        ok = True
        for i, tok in enumerate(toks):
            if tok in ("??", "?"):
                continue
            if _MEM.get(base + i, 0x00) != int(tok, 16):
                ok = False
                break
        if ok:
            return base
    return -1


ida_bytes.find_bytes = _fake_find
ida_bytes.is_code_ea = lambda ea: ea == 0x2000
sys.modules["ida_bytes"] = ida_bytes

ida_funcs = types.ModuleType("ida_funcs")


class FakeFunc:
    def __init__(self, start, end):
        self.start_ea = start
        self.end_ea = end


ida_funcs.get_func = lambda ea: FakeFunc(0x1000, 0x1007) if 0x1000 <= ea < 0x1007 else None
ida_funcs.get_func_name = lambda ea: "main" if ea == 0x1000 else None

_APPLIED_SIGS = []
ida_funcs.get_idasgn_qty = lambda: len(_APPLIED_SIGS)
ida_funcs.get_idasgn_desc = lambda i: _APPLIED_SIGS[i]
ida_funcs.get_idasgn_desc_with_matches = lambda i: f"{_APPLIED_SIGS[i]} (3 matches)"
ida_funcs.plan_to_apply_idasgn = lambda path: (_APPLIED_SIGS.append("test"), 1)[1]
sys.modules["ida_funcs"] = ida_funcs


class FakeXref:
    def __init__(self, frm, to, iscode=False):
        self.frm = frm
        self.to = to
        self.iscode = iscode


idautils = types.ModuleType("idautils")
# A code instruction reading a data address (e.g. a string) is a DATA xref:
# ``iscode`` must be False.  The old filter kept only code refs and therefore
# returned nothing for the tool's primary use case.
idautils.XrefsTo = lambda ea, flags: iter(
    [FakeXref(0x2000, 0x3000)] if ea == 0x3000 else [])
sys.modules["idautils"] = idautils

# =========================================================================
# Load api_sigmaker.py
# =========================================================================

from _harness import RPC_STUB, load  # noqa: E402
mod = load("api_sigmaker", {
    "rpc": RPC_STUB,
    "sync": (
        "idasync = lambda f: f\n"
    "def tool_timeout(s):\n"
    "    def deco(fn):\n"
    "        return fn\n"
    "    return deco\n"
    "def check_cancelled(): return None\n"
    "def update_wait_box(t): return None\n"
    "class CancelledError(Exception): pass\n"
    "class IDASyncError(Exception): pass"
        "\n"
        "def ensure_analysis(): return None"
    ),
    "api_analysis": "def parse_addr(s):\n"
    "    s = str(s).strip()\n"
    "    if s.startswith('0x'): return int(s, 16)\n"
    "    try: return int(s)\n"
    "    except ValueError: raise ValueError(f'Unknown: {s}')\n"
    "def read_bytes_bss_safe(ea, size):\n"
    "    out = bytearray()\n"
    "    for i in range(size):\n"
    "        if ea + i not in _MEM: return None\n"
    "        out.append(_MEM[ea + i])\n"
    "    return bytes(out)",
    "compat": "inf_get_max_ea = lambda: 0x8000\ninf_get_min_ea = lambda: 0x1000",
}, alias="sigmaker_test", stub_globals={"_MEM": _MEM})

# =========================================================================
# Tests
# =========================================================================

# "48 ?? ?? ?? ??" matches 0x1000 AND 0x2000 -> engine must extend to the
# 7-byte "48 ?? ?? ?? ?? 33 90" which is unique to 0x1000.
r = json.loads(mod.make_signature("0x1000"))
res = r["results"][0]
assert res["unique"] is True, res
assert res["signature"] == "48 ?? ?? ?? ?? 33 90", res
assert res["length"] == 7, res
print("make_signature shortest-unique OK")

r = json.loads(mod.make_signature("0x1000", format="mask"))
assert r["results"][0]["mask"] == "x????xx", r
assert r["results"][0]["bytes"] == "48000000003390", r
r = json.loads(mod.make_signature("0x1000", format="bitmask"))
assert r["results"][0]["bitmask"] == "1000011", r
r = json.loads(mod.make_signature("0x1000", format="x64dbg"))
assert r["results"][0]["signature"] == "48 ?? ?? ?? ?? 33 90", r
r = json.loads(mod.make_signature("0x1000", format="bogus"))
assert "error" in r, r
print("formats OK")

# no wildcards -> exact bytes; already unique at 5 (shortest wins)
r = json.loads(mod.make_signature("0x1000", wildcard_operands=False))
assert r["results"][0]["signature"] == "48 8B 05 11 22", r
assert r["results"][0]["unique"] is True, r
print("no-wildcard OK")

r = json.loads(mod.make_signature("bogus_addr"))
assert "error" in r["results"][0], r
r = json.loads(mod.make_signature("0x5000"))
assert "error" in r["results"][0], r  # undecodable
print("error paths OK")

r = json.loads(mod.make_signature_for_function("0x1002"))
res = r["results"][0]
assert res["name"] == "main" and res["addr"] == "0x1000", res
assert res["unique"] is True, res
r = json.loads(mod.make_signature_for_function("0x5000"))
assert "No function" in r["results"][0]["error"], r
print("for_function OK")

r = json.loads(mod.make_signature_for_range("0x1000", "0x1007"))
assert r["signature"] == "48 ?? ?? ?? ?? 33 90", r
assert r["unique"] is True, r
r = json.loads(mod.make_signature_for_range("0x1007", "0x1000"))
assert "error" in r, r
print("for_range OK")

r = json.loads(mod.find_xref_signatures("0x3000"))
res = r["results"][0]
assert res["total_xrefs"] == 1, res
assert res["signatures"][0]["xref_addr"] == "0x2000", res
# site 0x2000: "48 ?? ?? ?? ??" matches 0x1000 too, extended with 0x90 byte
assert res["signatures"][0]["signature"] == "48 ?? ?? ?? ?? 90", res
print("find_xref_signatures OK")

# --- FLIRT apply/list ---
r = json.loads(mod.list_flirt_signatures())
assert r == {"signatures": [], "count": 0}, r
r = json.loads(mod.apply_flirt_signatures("/nonexistent/x.sig"))
assert r["ok"] is False and "not found" in r["error"], r
import tempfile
with tempfile.NamedTemporaryFile(suffix=".sig", delete=False) as f:
    sig_path = f.name
r = json.loads(mod.apply_flirt_signatures(sig_path))
assert r["ok"] is True, r
assert r["total_applied"] == 1, r
assert r["new_signatures"][0]["desc"] == "test (3 matches)", r
r = json.loads(mod.list_flirt_signatures())
assert r["count"] == 1, r
# Real IDA returns a tuple (name, libs, matches), not a string.  Storing
# str(tuple) made `desc` unreadable and broke before/after comparisons.
_orig_desc = ida_funcs.get_idasgn_desc_with_matches
ida_funcs.get_idasgn_desc_with_matches = lambda i: ("libc", ["libc.so"], 3)
try:
    r = json.loads(mod.list_flirt_signatures())
    assert r["signatures"][0]["desc"] == "libc", r
    assert r["signatures"][0]["libs"] == ["libc.so"], r
    assert r["signatures"][0]["matches"] == 3, r
finally:
    ida_funcs.get_idasgn_desc_with_matches = _orig_desc
print("apply/list_flirt_signatures OK")

# --- chunked uniqueness probe (plan 15, item 15.5) ---
# 0x6000 holds 20 one-byte instructions whose first 12 bytes repeat at 0x7000,
# so the shortest unique signature is 13 bytes. Probing after EVERY instruction
# needed 13 global scans (26 find_bytes calls); probing every 8 and bisecting
# the last chunk needs 5 (10 calls).
_calls = []
_real_find = mod.ida_bytes.find_bytes


def _counting_find(*args, **kwargs):
    _calls.append(args[0])
    return _real_find(*args, **kwargs)


mod.ida_bytes.find_bytes = _counting_find
try:
    r = json.loads(mod.make_signature("0x6000"))
finally:
    mod.ida_bytes.find_bytes = _real_find
res = r["results"][0]
_expected = " ".join(f"{0x40 + i:02X}" for i in range(_LONG_SHARED + 1))
assert res["unique"] is True, res
assert res["signature"] == _expected, (res["signature"], _expected)
assert len(_calls) <= 12, (
    f"{len(_calls)} find_bytes calls; per-instruction probing needs 26")
print(f"chunked uniqueness probe OK ({len(_calls)} scans, was 26)")

print("ALL SIGMAKER TESTS PASSED")
