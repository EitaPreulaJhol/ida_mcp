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
_NUL_AT = {0x6000}
_ORIGINAL_BYTES: dict[int, int] = {}
_CURRENT_BYTES: dict[int, int] = {}
ida_bytes.get_byte = lambda ea: _CURRENT_BYTES.get(ea, 0 if ea in _NUL_AT else 0x41)
ida_bytes.get_original_byte = lambda ea: _ORIGINAL_BYTES.get(ea, 0x41)


def _create_strlit(ea, length, strtype):
    _CREATED.append(("strlit", ea, length))
    _ITEM_SIZE["value"] = 4          # "abc\0"
    return True


ida_bytes.create_strlit = _create_strlit
ida_bytes.patch_bytes = lambda ea, buf: _PATCHED.append((ea, bytes(buf)))
ida_bytes.patch_byte = lambda ea, value: _PATCHED.append((ea, bytes([value])))
ida_bytes.del_items = lambda ea, flags=0, nbytes=1: True
ida_bytes.DELIT_NOTRUNC = 1
ida_bytes.DELIT_SIMPLE = 0
sys.modules["ida_bytes"] = ida_bytes

_NAME_CALLS: list[tuple] = []
_NAME_BY_EA: dict[int, str] = {}
ida_name = types.ModuleType("ida_name")
ida_name.SN_NOWARN = 0
ida_name.set_name = lambda ea, name, flags=0: (
    _NAME_CALLS.append((ea, name)) or _NAME_BY_EA.__setitem__(ea, name) or True)
ida_name.force_name = lambda ea, name: ida_name.set_name(ea, name)
ida_name.get_ea_name = lambda ea: _NAME_BY_EA.get(ea, f"old_{ea:x}")
sys.modules["ida_name"] = ida_name

_CMT_CALLS: list[tuple] = []
ida_bytes.set_cmt = lambda ea, text, repeatable=False: (
    _CMT_CALLS.append((ea, text, repeatable)) or True)

_TYPE_CALLS: list[tuple] = []


class _FakeTif:
    def get_named_type(self, til, name):
        return name in {"probe_t"}


ida_typeinf = types.ModuleType("ida_typeinf")
ida_typeinf.tinfo_t = _FakeTif
ida_typeinf.get_idati = lambda: object()
ida_typeinf.TINFO_DEFINITE = 1
ida_typeinf.apply_tinfo = lambda ea, tif, flags: (
    _TYPE_CALLS.append((ea, flags)) or True)
sys.modules["ida_typeinf"] = ida_typeinf

ida_nalt = types.ModuleType("ida_nalt")
ida_nalt.STRTYPE_C = 0
sys.modules["ida_nalt"] = ida_nalt

ida_segment = types.ModuleType("ida_segment")
_SEG = types.SimpleNamespace(start_ea=0x100000, end_ea=0x100000 + 100005)
ida_segment.getseg = lambda ea: _SEG if _SEG.start_ea <= ea < _SEG.end_ea else None
sys.modules["ida_segment"] = ida_segment

idautils = types.ModuleType("idautils")
idautils.Segments = lambda: iter([_SEG.start_ea])
sys.modules["idautils"] = idautils

# =========================================================================
# Load api_modify.py
# =========================================================================

from _harness import API_ANALYSIS_HELPERS, RPC_STUB, SYNC_STUB, load  # noqa: E402

mod = load("api_modify", {
    "rpc": RPC_STUB,
    "sync": SYNC_STUB,
    "api_analysis": "def parse_addr(s):\n"
    "    s = str(s).strip()\n"
    "    if s.startswith('0x'): return int(s, 16)\n"
    "    try: return int(s)\n"
    "    except ValueError: raise ValueError(f'Unknown: {s}')" + API_ANALYSIS_HELPERS,
    "compat": "def get_original_bytes(ea, size):\n"
    "    return bytes(_ORIGINAL_BYTES.get(ea + i, 0x41) for i in range(size))",
}, alias="modify_test",
   stub_globals={"_ORIGINAL_BYTES": _ORIGINAL_BYTES, "_CURRENT_BYTES": _CURRENT_BYTES})

# =========================================================================
# make_data: every scalar type must pass `length` to create_* (14.2)
# =========================================================================

_CREATED.clear()
r = json.loads(mod.make_data("0x1000", "byte", 2))
assert r.get("ok") is True, r
assert _CREATED == [("byte", 0x1000, 1), ("byte", 0x1001, 1)], _CREATED
assert r["addr"] == "0x1000" and r["next_ea"] == "0x1002", r
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

# the string branch reports the START address (it used to return the advanced
# ea) and stops at a NUL instead of skipping it looking for a string
_CREATED.clear()
r = json.loads(mod.make_data("0x5000", "string", 2))
assert r["addr"] == "0x5000", r
assert r["next_ea"] == "0x5008", r
assert r["created"] == 2, r
assert [c[0] for c in _CREATED] == ["strlit", "strlit"], _CREATED
_CREATED.clear()
r = json.loads(mod.make_data("0x6000", "string", 3))  # NUL at the start
assert r["created"] == 0 and r["next_ea"] == "0x6000", r
assert _CREATED == [], r
print("make_data string start/NUL semantics OK")

# =========================================================================
# patch_bytes: one bulk write, bounded, mapped only (14.13)
# =========================================================================

_PATCHED.clear()
r = json.loads(mod.patch_bytes("0x1000", "90 90 cc"))
assert r.get("ok") is True and r["size"] == 3, r
assert _PATCHED == [(0x1000, b"\x90\x90\xcc")], _PATCHED
print("patch_bytes uses one bulk write OK")

_PATCHED.clear()
big = "90" * (64 * 1024 + 1)
r = json.loads(mod.patch_bytes("0x1000", big))
assert "error" in r and "max" in r["error"], r
assert _PATCHED == [], f"oversized patch was written: {len(_PATCHED)}"
print("patch_bytes size cap OK")

r = json.loads(mod.patch_bytes("0xBAD", "90"))  # is_mapped() -> False
assert "error" in r, r
assert _PATCHED == [], _PATCHED
print("patch_bytes unmapped address OK")

r = json.loads(mod.patch_bytes("0x1000", "zz"))
assert "error" in r, r
print("patch_bytes invalid hex OK")

_PATCHED.clear()
r = json.loads(mod.patch_bytes("0x1000", "90 90", dry_run=True))
assert r["dry_run"] is True and r["size"] == 2, r
assert _PATCHED == [], _PATCHED
print("patch_bytes dry_run OK")

# revert_patch defaults to one byte and supports a range + dry_run
_PATCHED.clear()
r = json.loads(mod.revert_patch("0x1000", size=2, dry_run=True))
assert r["dry_run"] is True and r["size"] == 2 and r["restored_hex"] == "4141", r
assert _PATCHED == [], _PATCHED
r = json.loads(mod.revert_patch("0x1000", size=2))
assert _PATCHED == [(0x1000, b"\x41\x41")], _PATCHED
print("revert_patch range + dry_run OK")

# --- batch annotations: dry-run, per-item errors and stop_on_error ---
_NAME_CALLS.clear()
_CMT_CALLS.clear()
_TYPE_CALLS.clear()
items = json.dumps([
    {"action": "rename", "address": "0x1000", "name": "new_name"},
    {"action": "comment", "address": "0x1004", "comment": "note"},
    {"action": "type", "address": "0x1008", "type": "probe_t"},
])
r = json.loads(mod.apply_annotations(items, dry_run=True))
assert r["dry_run"] is True and r["valid"] == 3 and r["applied"] == 0, r
assert not _NAME_CALLS and not _CMT_CALLS and not _TYPE_CALLS, (_NAME_CALLS, _CMT_CALLS, _TYPE_CALLS)
r = json.loads(mod.apply_annotations(items))
assert r["applied"] == 3 and r["failed"] == 0, r
assert _NAME_CALLS == [(0x1000, "new_name")], _NAME_CALLS
assert _CMT_CALLS == [(0x1004, "note", False)], _CMT_CALLS
assert _TYPE_CALLS == [(0x1008, 1)], _TYPE_CALLS
print("apply_annotations dry-run/apply OK")

_NAME_CALLS.clear()
_CMT_CALLS.clear()
items = json.dumps([
    {"action": "rename", "address": "0xBAD", "name": "bad"},
    {"action": "comment", "address": "0x1000", "comment": "ok"},
])
r = json.loads(mod.apply_annotations(items))
assert r["failed"] == 1 and r["applied"] == 1 and r["count"] == 2, r
assert _CMT_CALLS == [(0x1000, "ok", False)], _CMT_CALLS
r = json.loads(mod.apply_annotations(items, stop_on_error=True))
assert r["failed"] == 1 and r["applied"] == 0 and r["stopped"] is True and r["count"] == 1, r
r = json.loads(mod.apply_annotations("{not json"))
assert "error" in r, r
print("apply_annotations errors/stop_on_error OK")

# list_patches used to scan only the first 100 KB of each segment.  The
# patched byte below is 100001 bytes into .text, so the old code reported
# zero patches.
_PATCHED.clear()
_target = _SEG.start_ea + 100001
_ORIGINAL_BYTES[_target] = 0x41
_CURRENT_BYTES[_target] = 0x90
_CURRENT_BYTES[_target + 1] = 0x91
r = json.loads(mod.list_patches())
assert any(int(p["addr"], 16) == _target for p in r["patches"]), r
assert r["count"] >= 2 and r["truncated"] is False, r
assert any(ra["start"] == hex(_target) and ra["end"] == hex(_target + 2)
           for ra in r["ranges"]), r
assert r["scanned_bytes"] == _SEG.end_ea - _SEG.start_ea, r
r = json.loads(mod.list_patches(max_scan_bytes=1000))
assert r["scanned_bytes"] == 1000 and r["truncated"] is True, r
print("list_patches scans past the first 100 KB / ranges / cap OK")

print("ALL MODIFY TESTS PASSED")
