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

from _harness import RPC_STUB, SYNC_STUB, load  # noqa: E402
mod = load("api_strings", {
    "rpc": RPC_STUB,
    "sync": SYNC_STUB,
    "api_analysis": "def parse_addr(s):\n"
    "    s = str(s).strip()\n"
    "    if s.startswith('0x'): return int(s, 16)\n"
    "    try: return int(s)\n"
    "    except ValueError: raise ValueError(f'Unknown: {s}')",
}, alias="strings_test")

# =========================================================================
# Tests
# =========================================================================

r = json.loads(mod.get_strings())
assert r["total"] == 4 and r["count"] == 4, r
r = json.loads(mod.get_strings(limit=2, offset=0))
assert r["count"] == 2 and r["next_offset"] == 2, r
r = json.loads(mod.get_strings(limit=2, offset=2))
assert r["count"] == 2 and r["next_offset"] is None, r
r = json.loads(mod.get_strings(filter_pattern="*error*"))
assert r["total"] == 1 and r["data"][0]["value"] == "error: failed", r
print("get_strings OK")

r = json.loads(mod.get_strings_in_range("0x1000", "0x1020"))
assert [s["value"] for s in r["data"]] == ["hello", "error: failed"], r
assert r["truncated"] is False, r
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
print("ascii/unicode OK")

print("ALL STRINGS TESTS PASSED")
