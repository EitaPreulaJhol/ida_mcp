"""Tests for api_entries.py (entry points, forwarders, add/rename).

Stubs the IDA entry API and loads the real module via the harness.
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

_state = {
    "ords": [1, 2, 3, 4],
    "addrs": {1: 0x1000, 2: 0x2000, 3: -1, 4: 0x4000},
    "names": {1: "main", 2: "", 3: "unmapped", 4: "exported"},
    "forwarders": {1: None, 2: "LIB.func", 3: None, 4: None},
    "next_ordinal": 5,
}


def _qty():
    return len(_state["ords"])


def _ordinal(index):
    return _state["ords"][index]


def _entry(ordinal):
    return _state["addrs"].get(ordinal, idaapi.BADADDR)


def _name(ordinal):
    return _state["names"].get(ordinal)


def _forwarder(ordinal):
    return _state["forwarders"].get(ordinal)


def _add(ordinal, ea, name, make_public):
    assert make_public is True
    if ordinal in _state["addrs"]:
        return False
    _state["ords"].append(ordinal)
    _state["addrs"][ordinal] = ea
    _state["names"][ordinal] = name
    _state["forwarders"][ordinal] = None
    return True


def _rename(ordinal, name):
    if ordinal not in _state["names"]:
        return False
    _state["names"][ordinal] = name
    return True


ida_entry = types.ModuleType("ida_entry")
ida_entry.get_entry_qty = _qty
ida_entry.get_entry_ordinal = _ordinal
ida_entry.get_entry = _entry
ida_entry.get_entry_name = _name
ida_entry.get_entry_forwarder = _forwarder
ida_entry.add_entry = _add
ida_entry.rename_entry = _rename
sys.modules["ida_entry"] = ida_entry

# =========================================================================
# Load api_entries.py
# =========================================================================

from _harness import RPC_STUB, SYNC_STUB, load  # noqa: E402

mod = load("api_entries", {
    "rpc": RPC_STUB,
    "sync": SYNC_STUB,
    "api_analysis": """
def parse_addr(value):
    if isinstance(value, int):
        return value
    text = str(value).strip()
    try:
        return int(text, 0)
    except ValueError:
        raise ValueError(f"Unknown address or name: {value}") from None
""",
}, alias="entries_test")


def _reset():
    _state.update({
        "ords": [1, 2, 3, 4],
        "addrs": {1: 0x1000, 2: 0x2000, 3: -1, 4: 0x4000},
        "names": {1: "main", 2: "", 3: "unmapped", 4: "exported"},
        "forwarders": {1: None, 2: "LIB.func", 3: None, 4: None},
        "next_ordinal": 5,
    })


# --- listing / pagination / count ---
_reset()
rows = json.loads(mod.get_entry_points())
assert len(rows) == 3, rows  # BADADDR ordinal is skipped
assert rows[0] == {
    "ordinal": 1, "addr": "0x1000", "name": "main", "forwarder": None}, rows
assert rows[1]["name"] == "#2" and rows[1]["forwarder"] == "LIB.func", rows
page = json.loads(mod.get_entry_points(limit=1, offset=1))
assert page == [rows[1]], page
assert len(json.loads(mod.get_entry_points(limit=0))) == 3
assert json.loads(mod.get_entry_points(offset=99)) == []
assert json.loads(mod.get_entry_point_count()) == {"count": 4}
print("entry listing/pagination/count OK")

# --- point lookups ---
assert json.loads(mod.get_entry_point_by_ordinal(1))["name"] == "main"
assert json.loads(mod.get_entry_point_by_ordinal(999))["error"].startswith(
    "No entry point with ordinal")
assert json.loads(mod.get_entry_point_by_name("exported"))["addr"] == "0x4000"
assert "No entry point named" in mod.get_entry_point_by_name("missing")
assert json.loads(mod.get_entry_point_at("0x2000"))["name"] == "#2"
assert "No entry point at" in mod.get_entry_point_at("0x9999")
assert "Unknown address" in mod.get_entry_point_at("not-an-address")
fwd = json.loads(mod.get_entry_forwarders())
assert fwd == [{
    "ordinal": 2, "addr": "0x2000", "name": "#2", "forwarder": "LIB.func"}], fwd
print("entry point lookups/forwarders OK")

# --- add / rename (unsafe tools, decorated identity in the harness) ---
_reset()
added = json.loads(mod.add_entry_point("0x5000", "new_entry"))
assert added == {
    "ok": True, "ordinal": 5, "addr": "0x5000", "name": "new_entry"}, added
assert json.loads(mod.get_entry_point_by_name("new_entry"))["ordinal"] == 5
added = json.loads(mod.add_entry_point("0x6000", "explicit", ordinal=7))
assert added["ordinal"] == 7 and added["ok"] is True, added
assert "Unknown address" in mod.add_entry_point("bad", "x")
# A duplicate ordinal is rejected by the SDK.
assert "Failed to add entry point" in mod.add_entry_point("0x7000", "dup", ordinal=1)
renamed = json.loads(mod.rename_entry_point(1, "renamed_main"))
assert renamed == {"ok": True, "ordinal": 1, "name": "renamed_main"}, renamed
assert json.loads(mod.get_entry_point_by_ordinal(1))["name"] == "renamed_main"
assert "Failed to rename" in mod.rename_entry_point(999, "nope")
print("entry add/rename OK")

print("ALL ENTRY-POINT TESTS PASSED")
