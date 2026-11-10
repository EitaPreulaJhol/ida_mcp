"""Tests for search_text / find_text_between flag bits (review 14.1).

`SEARCH_UP == 0`, so `ida_search.find_text()` without `SEARCH_DOWN` walks
towards *lower* addresses, and `SEARCH_CASE == 4` means case-SENSITIVE. The
tools used to send `0` for `case_sensitive=True` and `SEARCH_CASE` for
`case_sensitive=False`: both the direction bit and the case bit were wrong, so
the search never moved forward from the start address.

Loads the real api_search.py with stubbed IDA modules (no IDA needed).
"""
import json
import sys
import types

# =========================================================================
# IDA stubs — constants use the real IDA 9.x values (verified against
# python/lib-dynload/_ida_search.so: UP=0, DOWN=1, NEXT=2, CASE=4).
# =========================================================================

ida_idaapi = types.ModuleType("ida_idaapi")
ida_idaapi.BADADDR = -1
sys.modules["ida_idaapi"] = ida_idaapi

ida_bytes = types.ModuleType("ida_bytes")
sys.modules["ida_bytes"] = ida_bytes

ida_search = types.ModuleType("ida_search")
ida_search.SEARCH_UP = 0
ida_search.SEARCH_DOWN = 1
ida_search.SEARCH_NEXT = 2
ida_search.SEARCH_CASE = 4

_CALLS = []
_MATCHES = [0x1010]
_FORCE = []  # addresses to return verbatim, one per call (out-of-range cases)


def _find_text(start_ea, y, x, ustr, sflag):
    _CALLS.append(sflag)
    if _FORCE:
        return _FORCE.pop(0)
    if not (sflag & ida_search.SEARCH_DOWN):
        # Upward search from 0 finds nothing: the pre-fix behavior, and the
        # reason the tool returned 0 matches for every query.
        return ida_idaapi.BADADDR
    for ea in _MATCHES:
        if ea >= start_ea:
            return ea
    return ida_idaapi.BADADDR


ida_search.find_text = _find_text
sys.modules["ida_search"] = ida_search

# =========================================================================
# Load api_search.py
# =========================================================================

from _harness import RPC_STUB, SYNC_STUB, load  # noqa: E402

mod = load("api_search", {
    "rpc": RPC_STUB,
    "sync": SYNC_STUB,
    "api_analysis": "def parse_addr(s):\n"
    "    s = str(s).strip()\n"
    "    if s.startswith('0x'): return int(s, 16)\n"
    "    try: return int(s)\n"
    "    except ValueError: raise ValueError(f'Unknown: {s}')",
}, alias="search_flags_test")

# =========================================================================
# Tests
# =========================================================================

# 1) default (case-insensitive): SEARCH_DOWN only -- never SEARCH_CASE
_CALLS.clear()
r = json.loads(mod.search_text("hello"))
assert r["count"] == 1 and r["matches"] == ["0x1010"], r
assert _CALLS == [1, 1], _CALLS  # first hit, then the follow-up probe
print("search_text default -> SEARCH_DOWN only OK")

# 2) case_sensitive=True: SEARCH_DOWN | SEARCH_CASE
_CALLS.clear()
r = json.loads(mod.search_text("Hello", case_sensitive=True))
assert r["count"] == 1, r
assert _CALLS == [5, 5], _CALLS
print("search_text case_sensitive -> SEARCH_DOWN|SEARCH_CASE OK")

# 3) find_text_between: same flags, and results stay inside [start, end)
_CALLS.clear()
r = json.loads(mod.find_text_between("hello", "0x1000", "0x2000"))
assert r["count"] == 1 and r["matches"] == ["0x1010"], r
assert all(flags == 1 for flags in _CALLS), _CALLS

_CALLS.clear()
r = json.loads(mod.find_text_between("Hello", "0x1000", "0x2000",
                                     case_sensitive=True))
assert r["count"] == 1, r
assert all(flags == 5 for flags in _CALLS), _CALLS

# a match at/above `end` must be dropped, and the loop must terminate
_FORCE[:] = [0x9000]
_CALLS.clear()
r = json.loads(mod.find_text_between("hello", "0x1000", "0x2000"))
assert r["count"] == 0 and r["matches"] == [], r
assert len(_CALLS) == 1, _CALLS
print("find_text_between flags + range guard OK")

print("ALL SEARCH FLAG TESTS PASSED")
