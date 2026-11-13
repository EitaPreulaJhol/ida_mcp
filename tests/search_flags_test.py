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

# IDA 9.x returns ``(ea, matched_value)`` from find_imm; older bindings
# returned the address. The stub describes the 9.x shape by default.
_IMM_MATCHES: list[int] = [0x1010, 0x1020, 0x1030]
_IMM_TUPLE = [True]
_IMM_CALLS: list[tuple] = []


def _find_imm(ea, sflag, search_value):
    _IMM_CALLS.append((ea, sflag, search_value))
    for match in _IMM_MATCHES:
        if match >= ea:
            return (match, search_value) if _IMM_TUPLE[0] else match
    return (ida_idaapi.BADADDR, search_value) if _IMM_TUPLE[0] else ida_idaapi.BADADDR


ida_search.find_imm = _find_imm
sys.modules["ida_search"] = ida_search

# =========================================================================
# Load api_search.py
# =========================================================================

from _harness import RPC_STUB, SYNC_STUB, load  # noqa: E402

mod = load("api_search", {
    "rpc": RPC_STUB,
    "sync": SYNC_STUB,
    "compat": "inf_get_min_ea = lambda: 0x1000\ninf_get_max_ea = lambda: 0x3000",
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

# --- search_bytes scans the image, not the whole address space (6.1) ---
_FIND_CALLS = []


def _fake_find(pattern, start, range_end=None):
    _FIND_CALLS.append((start, range_end))
    return ida_idaapi.BADADDR


ida_bytes.find_bytes = _fake_find
r = json.loads(mod.search_bytes("55 48"))
assert r["count"] == 0, r
assert _FIND_CALLS == [(0x1000, 0x3000)], _FIND_CALLS
print("search_bytes uses the image range OK")

# --- immediate search: find_imm returns a tuple on IDA 9.x (16.3) --------
_IMM_CALLS.clear()
_IMM_TUPLE[0] = True
r = json.loads(mod.search_immediate_value(7))
assert r["matches"] == ["0x1010", "0x1020", "0x1030"], r
assert r["count"] == 3, r
assert all(call[1] == ida_search.SEARCH_DOWN for call in _IMM_CALLS), _IMM_CALLS
assert _IMM_CALLS[-1][0] == 0x1031, _IMM_CALLS
print("search_immediate_value accepts the find_imm tuple OK")

# same shape for the ranged variant, and the end bound is honoured
_IMM_CALLS.clear()
r = json.loads(mod.find_immediate_between(7, "0x1000", "0x1025"))
assert r["matches"] == ["0x1010", "0x1020"], r
print("find_immediate_between tuple + range OK")

# old bindings that returned a bare address still work
_IMM_CALLS.clear()
_IMM_TUPLE[0] = False
r = json.loads(mod.search_immediate_value(7))
assert r["matches"] == ["0x1010", "0x1020", "0x1030"], r
_IMM_TUPLE[0] = True
print("search_immediate_value accepts a bare address (older IDA) OK")

print("ALL SEARCH FLAG TESTS PASSED")
