"""Comment management tools — get, set, delete comments and bookmarks.

Tools ported from idamcp-extendedtools api_comments.py, adapted for direct
in-process IDA SDK access.
"""

import json

import ida_bytes
import ida_lines
import idautils
import idc

from .rpc import tool, unsafe
from .sync import (idasync, check_cancelled, CancelledError, IDASyncError)
from .sync import ensure_analysis
from .api_analysis import _as_int, parse_addr
from .compat import badaddr, get_extra_cmt, get_extra_cmt_qty


# ===========================================================================
# Tools
# ===========================================================================


@tool
@idasync
def get_comment(address: str) -> str:
    """Get the regular (non-repeatable) comment at the given address."""
    ensure_analysis()
    try:
        ea = parse_addr(address)
    except ValueError as e:
        return json.dumps({"error": str(e)})

    comment = ida_bytes.get_cmt(ea, False)
    return json.dumps({"addr": hex(ea), "comment": comment if comment else None})


@tool
@idasync
@unsafe
def delete_comment(address: str) -> str:
    """Delete the regular comment at the given address.

    **Unsafe** — requires ``?unsafe=true``.
    """
    ensure_analysis()
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
    ensure_analysis()
    try:
        ea = parse_addr(address)
    except ValueError as e:
        return json.dumps({"error": str(e)})

    comment = ida_bytes.get_cmt(ea, True)
    return json.dumps({"addr": hex(ea), "repeatable_comment": comment if comment else None})


@tool
@idasync
def get_all_comments(limit: int = 500, offset: int = 0) -> str:
    """Get all comments (regular and repeatable) in the binary.

    Paginated: returns at most ``limit`` comments starting at ``offset``
    (``limit=0`` = no cap). When ``next_offset`` is present, more comments
    follow — advance ``offset`` to continue. The scan stops once a full page is
    collected, so it stays cheap on large databases, and polls
    ``check_cancelled()`` so the walk can be interrupted.
    """
    ensure_analysis()
    limit = _as_int(limit, 500)
    offset = max(_as_int(offset, 0), 0)
    results: list[dict] = []
    # Collect one past the page end (when capped) to detect whether more exist.
    hard = None if limit <= 0 else offset + limit + 1

    partial = False
    for i, ea in enumerate(idautils.Heads()):
        if i % 4096 == 0:
            try:
                check_cancelled()
            except (CancelledError, IDASyncError):
                partial = True
                break
        cmt = ida_bytes.get_cmt(ea, False)
        if cmt:
            results.append({"address": hex(ea), "comment": cmt, "type": "regular"})

        rpt = ida_bytes.get_cmt(ea, True)
        if rpt:
            results.append({"address": hex(ea), "comment": rpt, "type": "repeatable"})

        if hard is not None and len(results) >= hard:
            break

    page = results[offset:] if limit <= 0 else results[offset:offset + limit]
    out = {"comments": page, "count": len(page), "offset": offset}
    if limit > 0:
        out["limit"] = limit
    if limit > 0 and len(results) > offset + limit:
        out["next_offset"] = offset + limit
    if partial:
        out["partial"] = True
    return json.dumps(out, indent=2)


@tool
@idasync
def get_extra_comments(address: str) -> str:
    """Get extra comments (anterior/before lines) at the given address."""
    ensure_analysis()
    try:
        ea = parse_addr(address)
    except ValueError as e:
        return json.dumps({"error": str(e)})

    # Anterior (E_PREV) extra comments: IDA 9.4 removed get_extra_cmt_qty, so
    # compat derives the count from the first free slot index.
    results: list[str] = []
    count = get_extra_cmt_qty(ea, ida_lines.E_PREV)
    for i in range(count):
        cmt = get_extra_cmt(ea, ida_lines.E_PREV, i)
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
    ensure_analysis()
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
    ensure_analysis()
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

_BOOKMARK_SLOTS = 256


def _bookmark_at(slot: int) -> int | None:
    """Address bookmarked in ``slot`` (None when the slot is empty).

    ``idc.get_bookmark`` is ``ida_idc.get_marked_pos`` and reports an empty
    slot as ``BADADDR``. The old code also treated address 0 as "free", so a
    bookmark at address 0 was invisible and got overwritten.
    """
    try:
        ea = idc.get_bookmark(slot)
    except Exception:
        return None
    return None if ea == badaddr() else ea


def _bookmark_addresses() -> list[int]:
    """Addresses currently bookmarked, in slot order (dense array)."""
    return [ea for ea in (_bookmark_at(slot) for slot in range(_BOOKMARK_SLOTS))
            if ea is not None]


def _clear_bookmark(slot: int) -> bool:
    """Remove the bookmark in ``slot``; True only when one disappeared.

    IDA 9.x removed ``idc.del_bookmark`` (the binding only exposes
    ``get_bookmark``/``get_bookmark_desc``/``put_bookmark``). The remaining
    deletion path is ``mark_position`` with ``BADADDR`` as the address, which
    removes the entry at that index; older IDAs keep ``del_bookmark``.

    The IDB marks are a DENSE array: removing index N shifts the following
    entries down, so the slot itself is not empty afterwards. The check is
    therefore on the number of marks (must drop by exactly one), not on
    ``slot`` being ``BADADDR``.
    """
    if _bookmark_at(slot) is None:
        return False
    before = len(_bookmark_addresses())
    delete = getattr(idc, "del_bookmark", None)
    if callable(delete):
        try:
            delete(slot)
        except Exception:
            pass
    else:
        mark = getattr(idc, "put_bookmark", None)
        if not callable(mark):
            return False
        try:
            mark(badaddr(), 0, 0, 0, slot, "")
        except Exception:
            return False
    return len(_bookmark_addresses()) == before - 1


@tool
@idasync
def get_bookmarks() -> str:
    """Get all bookmarks in the binary."""
    ensure_analysis()
    results: list[dict] = []

    for i in range(_BOOKMARK_SLOTS):
        ea = _bookmark_at(i)
        if ea is None:
            continue
        # A bookmark added without a description was stored as a single space
        # (see add_bookmark); report it as empty again.
        desc = (idc.get_bookmark_desc(i) or "").strip()
        results.append({"address": hex(ea), "name": desc, "slot": i})

    return json.dumps({"bookmarks": results, "count": len(results)}, indent=2)


@tool
@idasync
@unsafe
def add_bookmark(address: str, description: str = "") -> str:
    """Add a bookmark at the given address with an optional description.

    **Unsafe** — requires ``?unsafe=true``. Uses the first free slot (0-255).
    """
    ensure_analysis()
    try:
        ea = parse_addr(address)
    except ValueError as e:
        return json.dumps({"error": str(e)})

    mark = getattr(idc, "put_bookmark", None)
    if mark is None:
        return json.dumps({"error": "put_bookmark unavailable in this IDA version"})

    free_slot = next((slot for slot in range(_BOOKMARK_SLOTS)
                      if _bookmark_at(slot) is None), None)
    if free_slot is None:
        return json.dumps({"error": "No free bookmark slots (0-255 all used)"})
    try:
        # idc.put_bookmark is ida_idc.mark_position, whose signature is
        # (ea, lnnum, x, y, slot, comment): the slot is the FIFTH argument.
        # Passing it as ``lnnum`` (the old bug) wrote every bookmark to slot
        # 0 -- overwriting the previous one -- and raised IDA's
        # "Internal error 1312" whenever lnnum was not 0.
        #
        # 9.5 also rejects an EMPTY comment with the same "Internal error
        # 1312", so the no-description case sends a single space, which
        # get_bookmarks() strips back to "".
        mark(ea, 0, 0, 0, free_slot, description or " ")
    except Exception as e:
        return json.dumps({"error": str(e)})
    if _bookmark_at(free_slot) != ea:
        return json.dumps({"addr": hex(ea), "slot": free_slot,
                           "error": "Bookmark was not stored; the slot did not take the address"})
    return json.dumps({"addr": hex(ea), "slot": free_slot, "description": description or ""})


@tool
@idasync
@unsafe
def delete_bookmark(target: str) -> str:
    """Delete a bookmark by slot index or by address.

    **Unsafe** — requires ``?unsafe=true``. ``target`` accepts a slot number
    (``"3"``) or an address/symbol (the bookmark at that address is removed).
    """
    ensure_analysis()

    slot: int | None = None
    try:
        candidate = int(target, 0)
        if 0 <= candidate < _BOOKMARK_SLOTS:
            slot = candidate
    except (ValueError, TypeError):
        slot = None
    if slot is None:
        try:
            ea = parse_addr(target)
        except ValueError as e:
            return json.dumps({"error": str(e)})
        slot = next((i for i in range(_BOOKMARK_SLOTS)
                     if _bookmark_at(i) == ea), None)
        if slot is None:
            return json.dumps({"error": f"No bookmark at {target}"})
    elif _bookmark_at(slot) is None:
        return json.dumps({"error": f"No bookmark in slot {slot}"})

    if not _clear_bookmark(slot):
        return json.dumps({"error": f"Could not clear bookmark slot {slot}"})
    return json.dumps({"ok": True, "slot": slot})
