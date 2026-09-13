"""Entry point tools — list, query, and manage entry points.

Tools ported from idamcp-extendedtools api_entries.py, adapted for direct
in-process IDA SDK access.
"""

import json

import ida_auto
import ida_entry
import idaapi

from .rpc import tool, unsafe
from .sync import idasync
from .api_analysis import parse_addr


# ===========================================================================
# Tools
# ===========================================================================


@tool
@idasync
def get_entry_points() -> str:
    """List all entry points (main, DllMain, TLS callbacks, exports, etc.)
    with ordinals and addresses.

    Returns a JSON array of ``{ordinal, addr, name}`` objects.
    """
    ida_auto.auto_wait()
    results: list[dict] = []

    for i in range(ida_entry.get_entry_qty()):
        ordinal = ida_entry.get_entry_ordinal(i)
        ea = ida_entry.get_entry(ordinal)
        if ea == idaapi.BADADDR:
            continue
        name = ida_entry.get_entry_name(ordinal)
        forwarder = ida_entry.get_entry_forwarder(ordinal)
        results.append({
            "ordinal": ordinal,
            "addr": hex(ea),
            "name": name if name else f"#{ordinal}",
            "forwarder": forwarder if forwarder else None,
        })

    return json.dumps(results, indent=2)


@tool
@idasync
def get_entry_point_count() -> str:
    """Get the number of entry points."""
    ida_auto.auto_wait()
    count = ida_entry.get_entry_qty()
    return json.dumps({"count": count})


@tool
@idasync
def get_entry_point_by_ordinal(ordinal: int) -> str:
    """Get an entry point by its ordinal."""
    ida_auto.auto_wait()
    ea = ida_entry.get_entry(int(ordinal))
    if ea == idaapi.BADADDR:
        return json.dumps({"error": f"No entry point with ordinal {ordinal}"})

    name = ida_entry.get_entry_name(int(ordinal))
    forwarder = ida_entry.get_entry_forwarder(int(ordinal))
    return json.dumps({
        "ordinal": int(ordinal),
        "addr": hex(ea),
        "name": name if name else f"#{ordinal}",
        "forwarder": forwarder if forwarder else None,
    }, indent=2)


@tool
@idasync
def get_entry_point_by_name(name: str) -> str:
    """Get an entry point by its name."""
    ida_auto.auto_wait()

    for i in range(ida_entry.get_entry_qty()):
        ordinal = ida_entry.get_entry_ordinal(i)
        entry_name = ida_entry.get_entry_name(ordinal)
        if entry_name == name:
            ea = ida_entry.get_entry(ordinal)
            return json.dumps({
                "ordinal": ordinal,
                "addr": hex(ea),
                "name": name,
                "forwarder": ida_entry.get_entry_forwarder(ordinal) or None,
            }, indent=2)

    return json.dumps({"error": f"No entry point named '{name}'"})


@tool
@idasync
def get_entry_point_at(address: str) -> str:
    """Get the entry point at the given address."""
    ida_auto.auto_wait()
    try:
        ea = parse_addr(address)
    except ValueError as e:
        return json.dumps({"error": str(e)})

    for i in range(ida_entry.get_entry_qty()):
        ordinal = ida_entry.get_entry_ordinal(i)
        entry_ea = ida_entry.get_entry(ordinal)
        if entry_ea == ea:
            name = ida_entry.get_entry_name(ordinal)
            return json.dumps({
                "ordinal": ordinal,
                "addr": hex(ea),
                "name": name if name else f"#{ordinal}",
                "forwarder": ida_entry.get_entry_forwarder(ordinal) or None,
            }, indent=2)

    return json.dumps({"error": f"No entry point at {hex(ea)}"})


@tool
@idasync
def get_entry_forwarders() -> str:
    """Get all entry points that have forwarders."""
    ida_auto.auto_wait()
    results: list[dict] = []

    for i in range(ida_entry.get_entry_qty()):
        ordinal = ida_entry.get_entry_ordinal(i)
        forwarder = ida_entry.get_entry_forwarder(ordinal)
        if forwarder:
            ea = ida_entry.get_entry(ordinal)
            name = ida_entry.get_entry_name(ordinal)
            results.append({
                "ordinal": ordinal,
                "addr": hex(ea),
                "name": name if name else f"#{ordinal}",
                "forwarder": forwarder,
            })

    return json.dumps(results, indent=2)


@tool
@idasync
@unsafe
def add_entry_point(
    address: str,
    name: str,
    ordinal: int = 0,
) -> str:
    """Add a new entry point at the given address.

    ``ordinal``: set to 0 for auto-assignment.
    **Unsafe** — requires ``?unsafe=true``.
    """
    ida_auto.auto_wait()
    try:
        ea = parse_addr(address)
    except ValueError as e:
        return json.dumps({"error": str(e)})

    ordinal = int(ordinal)
    if ordinal <= 0:
        ordinal = ida_entry.get_entry_qty() + 1

    if ida_entry.add_entry(ordinal, ea, name, True):
        return json.dumps({
            "ok": True,
            "ordinal": ordinal,
            "addr": hex(ea),
            "name": name,
        }, indent=2)
    else:
        return json.dumps({"error": "Failed to add entry point"})


@tool
@idasync
@unsafe
def rename_entry_point(
    ordinal: int,
    name: str,
) -> str:
    """Rename an entry point by its ordinal.

    **Unsafe** — requires ``?unsafe=true``.
    """
    ida_auto.auto_wait()
    if ida_entry.rename_entry(int(ordinal), name):
        return json.dumps({
            "ok": True,
            "ordinal": int(ordinal),
            "name": name,
        }, indent=2)
    else:
        return json.dumps({"error": f"Failed to rename entry point {ordinal}"})
