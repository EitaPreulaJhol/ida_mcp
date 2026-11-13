"""Tests for the bookmark tools (review 16, phase 2).

``idc.put_bookmark`` is ``ida_idc.mark_position(ea, lnnum, x, y, slot,
comment)``. The old call passed the free slot as ``lnnum`` and 0 as the slot,
so every bookmark landed in slot 0 -- overwriting the previous one -- and a
nonzero line number raised IDA's "Internal error 1312".

Deleting looked for ``idc.del_bookmark``, which IDA 9.x no longer exposes; the
entry is removed by marking it at BADADDR instead. IDB marks are a DENSE
array, so removing index N shifts the following entries down -- the stub
mirrors both behaviours, and therefore also catches a verification that
assumes the slot itself becomes empty.
"""
import json
import sys
import types

# =========================================================================
# IDA stubs
# =========================================================================

BADADDR = 0xFFFFFFFFFFFFFFFF
SLOTS: list[tuple[int, str]] = []   # dense, like the IDB marks array
CALLS: list[tuple] = []
DESC_CALLS: list[int] = []


def _get_bookmark(slot):
    return SLOTS[slot][0] if 0 <= slot < len(SLOTS) else BADADDR


def _get_bookmark_desc(slot):
    DESC_CALLS.append(slot)
    return SLOTS[slot][1] if 0 <= slot < len(SLOTS) else ""


def _put_bookmark(ea, lnnum, x, y, slot, comment):
    """Real ``mark_position`` semantics: slot is the 5th argument."""
    CALLS.append((ea, lnnum, x, y, slot, comment))
    if ea == BADADDR:
        if 0 <= slot < len(SLOTS):
            del SLOTS[slot]              # dense array: indices compact
        return
    if lnnum != 0:
        raise RuntimeError("Internal error 1312 occurred when running a script.")
    if not comment:
        # 9.5 rejects an empty comment for a real (non-deleting) mark too.
        raise RuntimeError("Internal error 1312 occurred when running a script.")
    if 0 <= slot < len(SLOTS):
        SLOTS[slot] = (ea, comment)
    else:
        SLOTS.append((ea, comment))


idc = types.ModuleType("idc")
idc.BADADDR = BADADDR
idc.get_bookmark = _get_bookmark
idc.get_bookmark_desc = _get_bookmark_desc
idc.put_bookmark = _put_bookmark
sys.modules["idc"] = idc

for _name in ("ida_bytes", "ida_lines", "idautils"):
    sys.modules[_name] = types.ModuleType(_name)

# =========================================================================
# Load api_comments.py (siblings stubbed)
# =========================================================================

from _harness import API_ANALYSIS_HELPERS, RPC_STUB, SYNC_STUB, load  # noqa: E402

mod = load("api_comments", {
    "rpc": RPC_STUB,
    "sync": SYNC_STUB,
    "api_analysis": "def parse_addr(s):\n"
    "    s = str(s).strip()\n"
    "    if s.startswith('0x'):\n"
    "        return int(s, 16)\n"
    "    try:\n"
    "        return int(s, 0)\n"
    "    except ValueError:\n"
    "        raise ValueError(f'Unknown address or name: {s}')" + API_ANALYSIS_HELPERS,
    "compat": "def badaddr():\n"
    "    return 0xFFFFFFFFFFFFFFFF\n"
    "def get_extra_cmt(ea, what, index=0):\n"
    "    return None\n"
    "def get_extra_cmt_qty(ea, what):\n"
    "    return 0",
}, alias="bookmark_test")

# =========================================================================
# Tests
# =========================================================================


def reset():
    SLOTS.clear()
    CALLS.clear()
    DESC_CALLS.clear()


def listed():
    return json.loads(mod.get_bookmarks())


# 1) the slot is the 5th positional argument, lnnum stays 0 ----------------
reset()
r = json.loads(mod.add_bookmark("0x2000", "first"))
assert r == {"addr": "0x2000", "slot": 0, "description": "first"}, r
assert CALLS == [(0x2000, 0, 0, 0, 0, "first")], CALLS
print("add_bookmark passes (ea, 0, 0, 0, slot, comment) OK")

# 2) a second bookmark uses the NEXT slot (the old code overwrote slot 0)
r = json.loads(mod.add_bookmark("0x3000", "second"))
assert r["slot"] == 1, r
r = listed()
assert r["count"] == 2, r
assert [b["address"] for b in r["bookmarks"]] == ["0x2000", "0x3000"], r
print("two bookmarks coexist in slots 0 and 1 OK")

# 3) deleting compacts the array: the survivor moves down to slot 0 -------
r = json.loads(mod.delete_bookmark("0"))
assert r == {"ok": True, "slot": 0}, r
assert [ea for ea, _ in SLOTS] == [0x3000], SLOTS
r = listed()
assert r["count"] == 1 and r["bookmarks"][0]["slot"] == 0, r
print("delete compacts the marks array OK")

# 4) the first free index is reused after compaction ---------------------
r = json.loads(mod.add_bookmark("0x4000", "third"))
assert r["slot"] == 1, r
assert [ea for ea, _ in SLOTS] == [0x3000, 0x4000], SLOTS
print("first free index after compaction OK")

# 5) delete by address, then by slot -------------------------------------
r = json.loads(mod.delete_bookmark("0x3000"))
assert r == {"ok": True, "slot": 0}, r
r = json.loads(mod.delete_bookmark("0"))
assert r == {"ok": True, "slot": 0}, r
assert SLOTS == []
print("delete by address and by slot OK")

# 6) deleting something that is not there is an error, not a silent success
r = json.loads(mod.delete_bookmark("0"))
assert "No bookmark in slot 0" in r["error"], r
r = json.loads(mod.delete_bookmark("0x9999"))
assert "No bookmark at" in r["error"], r
print("delete of a missing bookmark errors OK")

# 7) a bookmark at address 0 is a real bookmark, not an empty slot ---------
reset()
r = json.loads(mod.add_bookmark("0", "zero"))
assert r["slot"] == 0, r
r = listed()
assert r["count"] == 1 and r["bookmarks"][0]["address"] == "0x0", r
r = json.loads(mod.add_bookmark("0x5000", "next"))
assert r["slot"] == 1, r
print("address 0 is not treated as a free slot OK")

# 7b) no description: 9.5 rejects an empty comment, so a space is sent and
#     stripped back to "" when listing
reset()
r = json.loads(mod.add_bookmark("0x6000"))
assert r == {"addr": "0x6000", "slot": 0, "description": ""}, r
assert CALLS[-1] == (0x6000, 0, 0, 0, 0, " "), CALLS
r = listed()
assert r["count"] == 1 and r["bookmarks"][0]["name"] == "", r
print("empty description survives the 9.5 mark_position quirk OK")

# 8) a full marks table (256 entries) is refused ---------------------------
reset()
SLOTS.extend((0x1000 + i, "") for i in range(256))
r = json.loads(mod.add_bookmark("0x9000", "full"))
assert "No free bookmark slots" in r["error"], r
print("full bookmark table refused OK")

# 9) legacy path: idc.del_bookmark (pre-9.x) is used when present ----------
reset()
SLOTS.extend([(0x1000, "a"), (0x2000, "b"), (0x3000, "c"), (0x4000, "d")])
idc.del_bookmark = lambda slot: SLOTS.pop(slot)
try:
    r = json.loads(mod.delete_bookmark("1"))
    assert r == {"ok": True, "slot": 1}, r
    assert [ea for ea, _ in SLOTS] == [0x1000, 0x3000, 0x4000], SLOTS
finally:
    del idc.del_bookmark
print("legacy idc.del_bookmark path OK")

print("ALL BOOKMARK TESTS PASSED")
