"""Comment management tools — get, set, delete comments and bookmarks.

Tools ported from idamcp-extendedtools api_comments.py, adapted for direct
in-process IDA SDK access.
"""

import json

import ida_auto
import ida_bytes
import ida_lines
import idautils
import idc

from .rpc import tool, unsafe
from .sync import idasync
from .api_analysis import parse_addr


# ===========================================================================
# Tools
# ===========================================================================


@tool
@idasync
def get_comment(address: str) -> str:
    """Get the regular (non-repeatable) comment at the given address."""
    ida_auto.auto_wait()
    try:
        ea = parse_addr(address)
    except ValueError as e:
        return json.dumps({"error": str(e)})

    comment = ida_bytes.get_cmt(ea, False)
    return json.dumps({"addr": hex(ea), "comment": comment if comment else None})


@tool
@idasync
def delete_comment(address: str) -> str:
    """Delete the regular comment at the given address.

    Note: this is a write operation but does not require unsafe mode
    since it only affects annotations.
    """
    ida_auto.auto_wait()
    try:
        ea = parse_addr(address)
    except ValueError as e:
        return json.dumps({"error": str(e)})

    if not ida_bytes.set_cmt(ea, "", False):
        return json.dumps({"error": f"Failed to delete comment at {hex(ea)}"})

    return json.dumps({"ok": True, "addr": hex(ea)})


@tool
@idasync
def get_repeatable_comment(address: str) -> str:
    """Get the repeatable comment at the given address."""
    ida_auto.auto_wait()
    try:
        ea = parse_addr(address)
    except ValueError as e:
        return json.dumps({"error": str(e)})

    comment = ida_bytes.get_cmt(ea, True)
    return json.dumps({"addr": hex(ea), "repeatable_comment": comment if comment else None})


@tool
@idasync
def get_all_comments() -> str:
    """Get all comments (regular and repeatable) in the binary.

    Returns up to 500 comment entries.
    """
    ida_auto.auto_wait()
    results: list[dict] = []

    for ea in idautils.Heads():
        cmt = ida_bytes.get_cmt(ea, False)
        if cmt:
            results.append({"address": hex(ea), "comment": cmt, "type": "regular"})

        rpt = ida_bytes.get_cmt(ea, True)
        if rpt:
            results.append({"address": hex(ea), "comment": rpt, "type": "repeatable"})

        if len(results) >= 500:
            break

    return json.dumps({"comments": results, "count": len(results)}, indent=2)


@tool
@idasync
def get_extra_comments(address: str) -> str:
    """Get extra comments (anterior/before lines) at the given address."""
    ida_auto.auto_wait()
    try:
        ea = parse_addr(address)
    except ValueError as e:
        return json.dumps({"error": str(e)})

    # Anterior (0) extra comments
    results: list[str] = []
    count = ida_lines.get_extra_cmt_qty(ea, 0)
    for i in range(count):
        cmt = ida_lines.get_extra_cmt(ea, 0, i)
        if cmt:
            results.append(cmt)

    return json.dumps({"addr": hex(ea), "extra_comments": results, "count": len(results)})


@tool
@idasync
@unsafe
def set_repeatable_comment(address: str, comment: str) -> str:
    """Set the repeatable comment at the given address.

    **Unsafe** — requires ``?unsafe=true``.
    """
    ida_auto.auto_wait()
    try:
        ea = parse_addr(address)
    except ValueError as e:
        return json.dumps({"error": str(e)})

    if not ida_bytes.set_cmt(ea, comment, True):
        return json.dumps({"error": f"Failed to set repeatable comment at {hex(ea)}"})
    return json.dumps({"addr": hex(ea), "repeatable_comment": comment})


@tool
@idasync
@unsafe
def set_extra_comment(address: str, comment: str, position: str = "before") -> str:
    """Add an extra (multi-line anterior/posterior) comment line at an address.

    **Unsafe** — requires ``?unsafe=true``. ``position`` is ``"before"``
    (anterior lines, shown above the item) or ``"after"`` (posterior lines).
    Appends a line; repeat calls to stack multiple lines.
    """
    ida_auto.auto_wait()
    try:
        ea = parse_addr(address)
    except ValueError as e:
        return json.dumps({"error": str(e)})

    pos = (position or "before").strip().lower()
    if pos in ("before", "anterior", "prev", "previous"):
        isprev = True
    elif pos in ("after", "posterior", "next"):
        isprev = False
    else:
        return json.dumps({"error": f"Invalid position {position!r} (use 'before' or 'after')"})

    add_extra = getattr(ida_lines, "add_extra_cmt", None)
    if add_extra is None:
        return json.dumps({"error": "add_extra_cmt unavailable in this IDA version"})
    try:
        ok = add_extra(ea, isprev, comment)
    except Exception as e:
        return json.dumps({"error": str(e)})
    if ok is False:
        return json.dumps({"error": f"Failed to add extra comment at {hex(ea)}"})
    return json.dumps({"addr": hex(ea), "position": position, "comment": comment})


# ===========================================================================
# Bookmarks
# ===========================================================================


@tool
@idasync
def get_bookmarks() -> str:
    """Get all bookmarks in the binary."""
    ida_auto.auto_wait()
    results: list[dict] = []

    for i in range(256):
        ea = idc.get_bookmark(i)
        if ea != idc.BADADDR and ea != 0xFFFFFFFF and ea != 0:
            desc = idc.get_bookmark_desc(i) or ""
            results.append({"address": hex(ea), "name": desc, "slot": i})

    return json.dumps({"bookmarks": results, "count": len(results)}, indent=2)


@tool
@idasync
@unsafe
def add_bookmark(address: str, description: str = "") -> str:
    """Add a bookmark at the given address with an optional description.

    **Unsafe** — requires ``?unsafe=true``. Uses the first free slot (0-255).
    """
    ida_auto.auto_wait()
    try:
        ea = parse_addr(address)
    except ValueError as e:
        return json.dumps({"error": str(e)})

    put = getattr(idc, "put_bookmark", None)
    if put is None:
        return json.dumps({"error": "put_bookmark unavailable in this IDA version"})

    free_slot: int | None = None
    for slot in range(256):
        try:
            cur = idc.get_bookmark(slot)
        except Exception:
            continue
        if cur in (idc.BADADDR, 0xFFFFFFFF, 0):
            free_slot = slot
            break
    if free_slot is None:
        return json.dumps({"error": "No free bookmark slots (0-255 all used)"})
    try:
        put(ea, free_slot, 0, 0, 0, description or "")
    except Exception as e:
        return json.dumps({"error": str(e)})
    return json.dumps({"addr": hex(ea), "slot": free_slot, "description": description or ""})


@tool
@idasync
@unsafe
def delete_bookmark(target: str) -> str:
    """Delete a bookmark by slot index or by address.

    **Unsafe** — requires ``?unsafe=true``. ``target`` accepts a slot number
    (``"3"``) or an address/symbol (the bookmark at that address is removed).
    """
    ida_auto.auto_wait()
    delete = getattr(idc, "del_bookmark", None)
    if delete is None:
        return json.dumps({"error": "del_bookmark unavailable in this IDA version"})

    slot: int | None = None
    try:
        slot = int(target, 0)
        if not 0 <= slot <= 255:
            slot = None
    except (ValueError, TypeError):
        slot = None
    if slot is None:
        try:
            ea = parse_addr(target)
        except ValueError as e:
            return json.dumps({"error": str(e)})
        for i in range(256):
            try:
                if idc.get_bookmark(i) == ea:
                    slot = i
                    break
            except Exception:
                continue
        if slot is None:
            return json.dumps({"error": f"No bookmark at {target}"})
    try:
        delete(slot)
    except Exception as e:
        return json.dumps({"error": str(e)})
    return json.dumps({"ok": True, "slot": slot})
