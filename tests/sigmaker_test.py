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
    def __init__(self, frm, to, iscode=True):
        self.frm = frm
        self.to = to
        self.iscode = iscode


idautils = types.ModuleType("idautils")
idautils.XrefsTo = lambda ea, flags: iter(
    [FakeXref(0x2000, 0x3000)] if ea == 0x3000 else [])
sys.modules["idautils"] = idautils

# =========================================================================
# Load api_sigmaker.py
# =========================================================================

HERE = os.path.dirname(os.path.abspath(__file__))
PKG = os.path.join(HERE, "..", "ida_mcp")
src = open(os.path.join(PKG, "api_sigmaker.py")).read()
src = src.replace("from .rpc import tool, unsafe", "tool = lambda f: f\nunsafe = lambda f: f")
src = src.replace(
    "from .sync import idasync, tool_timeout",
    "idasync = lambda f: f\n"
    "def tool_timeout(s):\n"
    "    def deco(fn):\n"
    "        return fn\n"
    "    return deco",
)
src = src.replace(
    "from .api_analysis import parse_addr, read_bytes_bss_safe",
    "def parse_addr(s):\n"
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
)
src = src.replace(
    "from .compat import inf_get_max_ea, inf_get_min_ea",
    "inf_get_max_ea = lambda: 0x3000\ninf_get_min_ea = lambda: 0x1000",
)
mod = types.ModuleType("sigmaker_test")
mod.__dict__.update({"_MEM": _MEM})
exec(compile(src, "sigmaker_test", "exec"), mod.__dict__)
sys.modules["sigmaker_test"] = mod

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
print("apply/list_flirt_signatures OK")

print("ALL SIGMAKER TESTS PASSED")
