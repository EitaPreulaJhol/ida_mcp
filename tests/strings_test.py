"""Tests for api_strings.py (paginated string enumeration).

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

ida_bytes = types.ModuleType("ida_bytes")
ida_bytes.get_strlit_contents = lambda ea, length=-1, strtype=0: b"hello" if ea == 0x1000 else None
sys.modules["ida_bytes"] = ida_bytes

ida_nalt = types.ModuleType("ida_nalt")
ida_nalt.STRTYPE_C = 0
ida_nalt.STRTYPE_C_16 = 1
ida_nalt.STRTYPE_C_32 = 2
sys.modules["ida_nalt"] = ida_nalt

idaapi = types.ModuleType("idaapi")
idaapi.BADADDR = -1
sys.modules["idaapi"] = idaapi

idautils = types.ModuleType("idautils")


class FakeStr:
    def __init__(self, ea, value, strtype=0):
        self.ea = ea
        self._value = value
        self.length = len(value)
        self.strtype = strtype

    def __str__(self):
        return self._value


_STRS = [FakeStr(0x1000, "hello"),
         FakeStr(0x1010, "error: failed"),
         FakeStr(0x1020, "wide", strtype=1),
         FakeStr(0x1030, "x")]
idautils.Strings = lambda: iter(list(_STRS))
sys.modules["idautils"] = idautils

# =========================================================================
# Load api_strings.py
# =========================================================================

from _harness import API_ANALYSIS_HELPERS, RPC_STUB, SYNC_STUB, load  # noqa: E402
mod = load("api_strings", {
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
}, alias="strings_test")

# =========================================================================
# Tests
# =========================================================================

r = json.loads(mod.list_strings())
assert r["total"] == 4 and r["count"] == 4, r
r = json.loads(mod.list_strings(limit=2, offset=0))
assert r["count"] == 2 and r["next_offset"] == 2, r
r = json.loads(mod.list_strings(limit=2, offset=2))
assert r["count"] == 2 and r["next_offset"] is None, r
r = json.loads(mod.list_strings(filter_pattern="*error*"))
assert r["total"] == 1 and r["data"][0]["value"] == "error: failed", r
print("list_strings OK")

r = json.loads(mod.get_strings_in_range("0x1000", "0x1020"))
assert [s["value"] for s in r["data"]] == ["hello", "error: failed"], r
assert r["truncated"] is False, r
# exactly `limit` matches must not be reported as truncated
r = json.loads(mod.get_strings_in_range("0x1000", "0x1020", limit=2))
assert r["count"] == 2 and r["truncated"] is False, r
print("get_strings_in_range OK")

assert json.loads(mod.get_string_count()) == {"total": 4}
print("get_string_count OK")

r = json.loads(mod.get_string_at("0x1000"))
assert r["value"] == "hello" and r["exact"] is True, r
r = json.loads(mod.get_string_at("0x1002"))  # inside "hello"
assert r["value"] == "hello" and r["exact"] is False, r
r = json.loads(mod.get_string_at("0x9999"))
assert "error" in r, r
print("get_string_at OK")

r = json.loads(mod.search_strings("ERROR"))
assert r["count"] == 1, r  # case-insensitive by default
r = json.loads(mod.search_strings("ERROR", case_sensitive=True))
assert r["count"] == 0, r
r = json.loads(mod.search_strings("e", limit=1))
assert r["count"] == 1 and r["truncated"] is True, r
r = json.loads(mod.search_strings("hello", limit=1))
assert r["count"] == 1 and r["truncated"] is False, r
print("search_strings OK")

r = json.loads(mod.get_strings_by_length(min_length=5))
assert {s["value"] for s in r["data"]} == {"hello", "error: failed"}, r
r = json.loads(mod.get_strings_by_length(min_length=1, max_length=1))
assert [s["value"] for s in r["data"]] == ["x"], r
print("get_strings_by_length OK")

r = json.loads(mod.get_ascii_strings())
assert r["total"] == 3 and all(s["value"] != "wide" for s in r["data"]), r
r = json.loads(mod.get_unicode_strings())
assert r["total"] == 1 and r["data"][0]["value"] == "wide", r
# 16/32-bit Pascal and length-prefixed strings are unicode too.
_STRS.append(FakeStr(0x1040, "widep", strtype=5))  # STRTYPE_PASCAL_16
try:
    r = json.loads(mod.get_unicode_strings())
    assert {s["value"] for s in r["data"]} == {"wide", "widep"}, r
    r = json.loads(mod.get_ascii_strings())
    assert r["total"] == 3 and all(s["value"] != "widep" for s in r["data"]), r
finally:
    _STRS.pop()
print("ascii/unicode OK (incl. Pascal 16-bit)")

# --- oversized pagination is clamped and reported, not reset (14.11) ---
r = json.loads(mod.list_strings(limit=99999))
assert r["limit"] == 5000, r          # clamped to the cap
assert r["count"] == 4, r            # all four fake strings fit
r = json.loads(mod.list_strings(limit=0))
assert r["limit"] == 5000, r          # non-positive -> documented maximum
r = json.loads(mod.get_ascii_strings(limit=99999))
assert r["limit"] == 5000, r
r = json.loads(mod.get_strings_by_length(limit=99999))
assert r["limit"] == 5000, r
r = json.loads(mod.get_strings_in_range("0x1000", "0x2000", limit=99999))
assert r["limit"] == 10000, r
print("string limits clamped OK")

# --- iteration cap + cancellation poll (14.14) ---
_cancel_polls = []
mod.check_cancelled = lambda: _cancel_polls.append(1)
try:
    _STRS.extend(FakeStr(0x20000 + i, "s%d" % i) for i in range(60_000))
    assert len(_STRS) > mod._MAX_STRINGS
    r = json.loads(mod.list_strings(limit=5))
    assert r["count"] == 5, r
    assert r["iterated_cap_reached"] is True, r
    assert _cancel_polls, "check_cancelled() was never polled"
    r = json.loads(mod.get_strings_in_range("0xDEAD0000", "0xDEAD1000", limit=5))
    assert r["iterated_cap_reached"] is True, r
    r = json.loads(mod.search_strings("no-such-string", limit=5))
    assert r["iterated_cap_reached"] is True, r
    r = json.loads(mod.get_string_count())
    assert r["total"] == len(_STRS), r
finally:
    del _STRS[4:]
print("string iteration cap + cancel poll OK")

# --- cancellation is reported as partial data, not a traceback -----------
_orig_check = mod.check_cancelled


def _cancel_now():
    raise mod.CancelledError("cancelled")


mod.check_cancelled = _cancel_now
try:
    r = json.loads(mod.get_strings_in_range("0x1000", "0x2000"))
    assert r["partial"] is True, r
    r = json.loads(mod.search_strings("hello"))
    assert r["partial"] is True, r
    r = json.loads(mod.get_string_count())
    assert r["partial"] is True and r["total"] == 0, r
    r = json.loads(mod.get_string_at("0xDEAD"))
    assert r["partial"] is True and "cancelled" in r["error"].lower(), r
finally:
    mod.check_cancelled = _orig_check
print("string scan cancellation -> partial OK")

# --- oversized search limit is clamped to 5000 ---------------------------
r = json.loads(mod.search_strings("e", limit=99999))
assert r["limit"] == 5000, r
print("search_strings limit clamped + echoed OK")

print("ALL STRINGS TESTS PASSED")
