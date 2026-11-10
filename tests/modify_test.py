"""Tests for api_modify.py (data definition / patching).

Stubs IDA modules and loads the real module. The IDA stubs mirror the *real*
IDA 9.x signatures: `create_byte(ea, length, force=False)` has no default for
`length`, which is what `make_data` used to omit (review 14.2).
"""
import json
import sys
import types

# =========================================================================
# Stub IDA modules
# =========================================================================

idaapi = types.ModuleType("idaapi")
idaapi.BADADDR = -1
sys.modules["idaapi"] = idaapi

_CREATED = []
_PATCHED = []
_ITEM_SIZE = {"value": 1}


def _maker(size, name):
    def create(ea, length, force=False):  # no default: real IDA 9.x signature
        _CREATED.append((name, ea, length))
        _ITEM_SIZE["value"] = size
        return True
    return create


ida_bytes = types.ModuleType("ida_bytes")
ida_bytes.create_byte = _maker(1, "byte")
ida_bytes.create_word = _maker(2, "word")
ida_bytes.create_dword = _maker(4, "dword")
ida_bytes.create_qword = _maker(8, "qword")
ida_bytes.create_float = _maker(4, "float")
ida_bytes.create_double = _maker(8, "double")
ida_bytes.get_item_size = lambda ea: _ITEM_SIZE["value"]
ida_bytes.is_mapped = lambda ea: ea != 0xBAD
ida_bytes.get_byte = lambda ea: 0x41
ida_bytes.create_strlit = lambda ea, length, strtype: _CREATED.append(
    ("strlit", ea, length))
ida_bytes.patch_bytes = lambda ea, buf: _PATCHED.append((ea, bytes(buf)))
ida_bytes.patch_byte = lambda ea, value: _PATCHED.append((ea, bytes([value])))
ida_bytes.del_items = lambda ea, flags=0, nbytes=1: True
sys.modules["ida_bytes"] = ida_bytes

ida_name = types.ModuleType("ida_name")
ida_name.set_name = lambda ea, name, flags=0: True
sys.modules["ida_name"] = ida_name

ida_nalt = types.ModuleType("ida_nalt")
ida_nalt.STRTYPE_C = 0
sys.modules["ida_nalt"] = ida_nalt

sys.modules["ida_segment"] = types.ModuleType("ida_segment")
sys.modules["idautils"] = types.ModuleType("idautils")

# =========================================================================
# Load api_modify.py
# =========================================================================

from _harness import RPC_STUB, SYNC_STUB, load  # noqa: E402

mod = load("api_modify", {
    "rpc": RPC_STUB,
    "sync": SYNC_STUB,
    "api_analysis": "def parse_addr(s):\n"
    "    s = str(s).strip()\n"
    "    if s.startswith('0x'): return int(s, 16)\n"
    "    try: return int(s)\n"
    "    except ValueError: raise ValueError(f'Unknown: {s}')",
    "compat": "def get_original_bytes(ea, size):\n"
    "    return bytes(size)",
}, alias="modify_test")

# =========================================================================
# make_data: every scalar type must pass `length` to create_* (14.2)
# =========================================================================

_CREATED.clear()
r = json.loads(mod.make_data("0x1000", "byte", 2))
assert r.get("ok") is True, r
assert _CREATED == [("byte", 0x1000, 1), ("byte", 0x1001, 1)], _CREATED
print("make_data byte (length passed, items advanced) OK")

_CREATED.clear()
r = json.loads(mod.make_data("0x2000", "dword", 2))
assert r.get("ok") is True, r
assert _CREATED == [("dword", 0x2000, 4), ("dword", 0x2004, 4)], _CREATED
print("make_data dword (length = item size) OK")

_CREATED.clear()
r = json.loads(mod.make_data("0x3000", "qword", 1))
assert r.get("ok") is True, r
assert _CREATED == [("qword", 0x3000, 8)], _CREATED
print("make_data qword OK")

r = json.loads(mod.make_data("0x4000", "bogus", 1))
assert "error" in r, r
print("make_data unknown type OK")

# =========================================================================
# patch_bytes: input validation (bulk-write assertions land with 14.13)
# =========================================================================

r = json.loads(mod.patch_bytes("0x1000", "zz"))
assert "error" in r, r
print("patch_bytes invalid hex OK")

print("ALL MODIFY TESTS PASSED")
