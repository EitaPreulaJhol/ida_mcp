"""Tests for api_fingerprint.py (fingerprints + portable snapshots).

Stubs the small IDA surface the module uses; no real IDA required.
"""
import json
import os
import sys
import tempfile
import types

# =========================================================================
# Stub IDA modules
# =========================================================================

idaapi = types.ModuleType("idaapi")
idaapi.BADADDR = -1
idaapi.get_imagebase = lambda: 0x400000
idaapi.get_kernel_version = lambda: "9.5-test"
sys.modules["idaapi"] = idaapi


class _Block:
    def __init__(self, start, end, succs):
        self.start_ea = start
        self.end_ea = end
        self._succs = succs

    def succs(self):
        return iter(self._succs)


_BLOCKS = {
    0x1000: [_Block(0x1000, 0x1008, []), _Block(0x1008, 0x1010, [])],
    0x2000: [_Block(0x2000, 0x2008, []), _Block(0x2008, 0x2010, [])],
}
idaapi.FlowChart = lambda func: iter(_BLOCKS.get(func.start_ea, []))


class _Func:
    def __init__(self, start, end):
        self.start_ea = start
        self.end_ea = end


_FUNCS = {0x1000: _Func(0x1000, 0x1010), 0x2000: _Func(0x2000, 0x2010)}
_FUNC_NAMES = {0x1000: "func_a", 0x2000: "func_b"}
ida_funcs = types.ModuleType("ida_funcs")
ida_funcs.get_func = lambda ea: _FUNCS.get(ea)
ida_funcs.get_func_name = lambda ea: _FUNC_NAMES.get(ea)
sys.modules["ida_funcs"] = ida_funcs


class _Op:
    def __init__(self, typ, reg=0, value=0, addr=0):
        self.type = typ
        self.reg = reg
        self.value = value
        self.addr = addr


class _Insn:
    def __init__(self):
        self._ea = 0
        self.size = 4
        self.ops = []

    def get_canon_mnem(self):
        return "mov" if self._ea in (0x1000, 0x2000) else "ret"


_MNEM = {0x1004: "call", 0x1008: "ret", 0x2004: "call", 0x2008: "ret"}
_OPS = {
    0x1000: [_Op(1, reg=0), _Op(2, value=7)],  # o_reg, o_imm
    0x1004: [_Op(3, addr=0x2000)],             # o_near
    0x1008: [],
    0x2000: [_Op(1, reg=1), _Op(2, value=7)],
    0x2004: [_Op(3, addr=0x1000)],
    0x2008: [],
}
ida_ua = types.ModuleType("ida_ua")
ida_ua.o_void = 0
ida_ua.o_reg = 1
ida_ua.o_mem = 2
ida_ua.o_near = 3
ida_ua.o_far = 4
ida_ua.o_imm = 5
ida_ua.o_displ = 6
ida_ua.insn_t = _Insn


def _decode(insn, ea):
    if ea not in _OPS:
        return 0
    insn._ea = ea
    insn.ops = _OPS[ea]
    insn.size = 4
    return 1


ida_ua.decode_insn = _decode
sys.modules["ida_ua"] = ida_ua


def _insn_mnem(ea):
    return _MNEM.get(ea, "mov")


idautils = types.ModuleType("idautils")
idautils.Functions = lambda: iter(sorted(_FUNCS))
idautils.FuncItems = lambda start: iter(sorted(ea for ea in _OPS if start <= ea < start + 0x10))
idautils.CodeRefsFrom = lambda ea, flags=0: iter([0x1004] if ea == 0x1000 else [])


# The stub's get_canon_mnem uses the address; make sure every instruction
# returns the intended mnemonic (including 0x1000/0x2000 as mov).
_Insn.get_canon_mnem = lambda self: _insn_mnem(self._ea)
sys.modules["idautils"] = idautils

ida_bytes = types.ModuleType("ida_bytes")
_BYTES_SALT = {0x1000: 0}


def _get_bytes(ea, size):
    return bytes((((ea >> 8) + i + _BYTES_SALT.get(ea, 0)) & 0xff)
                 for i in range(size))


ida_bytes.get_bytes = _get_bytes
sys.modules["ida_bytes"] = ida_bytes

ida_loader = types.ModuleType("ida_loader")
ida_loader.PATH_TYPE_IDB = 1
ida_loader.get_path = lambda kind: "/tmp/stub.i64"
sys.modules["ida_loader"] = ida_loader

# =========================================================================
# Load api_fingerprint.py
# =========================================================================

from _harness import API_ANALYSIS_HELPERS, RPC_STUB, SYNC_STUB, load  # noqa: E402

mod = load("api_fingerprint", {
    "rpc": RPC_STUB,
    "sync": SYNC_STUB,
    "api_analysis": "def resolve_addr(address):\n"
    "    try:\n"
    "        idx = int(str(address), 0)\n"
    "    except ValueError as e:\n"
    "        return None, '{\"error\": \"Unknown address\"}'\n"
    "    return idx, None\n" + API_ANALYSIS_HELPERS,
}, alias="fingerprint_test")

# --- per-function fingerprint ---
fp = json.loads(mod.fingerprint_function("0x1000"))
assert fp["name"] == "func_a" and fp["size"] == 16, fp
assert len(fp["exact"]) == 64 and len(fp["shape"]) == 64, fp
assert fp["instructions"] == 3 and fp["blocks"] == 2, fp
assert fp["algorithm"] == "ida_mcp_fp_v1", fp
assert fp == json.loads(mod.fingerprint_function("0x1000")), "fingerprint is not deterministic"
other = json.loads(mod.fingerprint_function("0x2000"))
assert other == json.loads(mod.fingerprint_function("0x2000")), "second fingerprint is not deterministic"
assert other["exact"] != fp["exact"], "different bytes must have a different exact hash"
assert "No function" in mod.fingerprint_function("0x9999")
assert "Unknown address" in mod.fingerprint_function("nope")
print("fingerprint_function OK")

# --- snapshot export ---
tmp = tempfile.mkdtemp(prefix="ida_mcp_fp_test_")
try:
    path = os.path.join(tmp, "snapshot.json")
    out = json.loads(mod.export_fingerprints(path))
    assert out == {"ok": True, "path": os.path.abspath(path),
                   "function_count": 2, "algorithm": "ida_mcp_fp_v1"}, out
    assert os.stat(path).st_mode & 0o777 == 0o600
    data = json.load(open(path, encoding="utf-8"))
    assert data["schema"] == "ida-mcp-fingerprints"
    assert data["schema_version"] == 1
    assert data["algorithm"] == "ida_mcp_fp_v1"
    assert data["function_count"] == 2
    assert data["idb"]["imagebase"] == "0x400000"
    assert data["functions"] == [fp, other], data
    diff = json.loads(mod.diff_fingerprints(path))
    assert diff["counts"]["unchanged"] == 2, diff
    assert diff["counts"]["modified"] == 0 and diff["counts"]["removed"] == 0, diff
    # Same shape, different bytes -> modified (not renamed/removed).
    _BYTES_SALT[0x1000] = 1
    diff = json.loads(mod.diff_fingerprints(path))
    assert diff["counts"]["modified"] == 1 and diff["counts"]["unchanged"] == 1, diff
    _BYTES_SALT[0x1000] = 0
    out = json.loads(mod.export_fingerprints(os.path.join(tmp, "one.json"), limit=1))
    assert out["function_count"] == 1, out
    bad_path = os.path.join(tmp, "bad.json")
    open(bad_path, "w", encoding="utf-8").write("{}\n")
    assert "not an ida-mcp fingerprint snapshot" in mod.diff_fingerprints(
        bad_path), "schema-less snapshot must be rejected"
    assert "snapshot not found" in mod.diff_fingerprints(os.path.join(tmp, "missing.json"))
    assert "parent directory" in mod.export_fingerprints(os.path.join(tmp, "no", "x.json"))
    assert "path must not be empty" in mod.export_fingerprints("")
finally:
    import shutil
    shutil.rmtree(tmp, ignore_errors=True)
print("export_fingerprints OK")

print("ALL FINGERPRINT TESTS PASSED")
