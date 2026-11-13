"""Paginated string enumeration tools for ida_mcp.

``list_strings`` is the canonical listing (glob + offset/limit, bounded
enumeration with cancellation); the rest are at/range/length/ascii/unicode/
substring variants. Follows idamcp-extendedtools ``api_strings.py`` naming.
"""
import fnmatch
import json

import ida_bytes
import ida_nalt
import idautils

from .rpc import tool
from .sync import idasync
from .sync import ensure_analysis
from .sync import check_cancelled, CancelledError, IDASyncError
from .api_analysis import clamp_limit, paginate, parse_addr


# Upper bound on how many entries a single enumeration may scan. Big binaries
# have millions of strings; the tools paginate, so there is no reason to
# materialize the whole table (that froze the main thread with no cancel).
_MAX_STRINGS = 50000
_SCAN_CANCEL_EVERY = 2048


def _iter_strings():
    try:
        yield from idautils.Strings()
    except Exception:
        return




def _iter_strings_checked():
    """Yield ``(index, StringItem)`` with periodic cancellation polling."""
    for i, si in enumerate(_iter_strings()):
        if i % _SCAN_CANCEL_EVERY == 0:
            check_cancelled()
        yield i, si
def _collect_rows(keep=None) -> tuple[list[dict], bool]:
    """Rows for the indexed strings, optionally filtered, bounded.

    Polls ``check_cancelled()`` so a huge table can be interrupted, and stops
    at ``_MAX_STRINGS``, reporting that the scan was capped. Returns
    ``(rows, capped)``.
    """
    rows: list[dict] = []
    capped = False
    for i, si in enumerate(_iter_strings()):
        if i % _SCAN_CANCEL_EVERY == 0:
            check_cancelled()
        if i >= _MAX_STRINGS:
            capped = True
            break
        row = _row(si)
        if keep is not None and not keep(row):
            continue
        rows.append(row)
    return rows, capped


def _row(si) -> dict:
    try:
        value = str(si)
    except Exception:
        value = ""
    try:
        length = si.length
    except Exception:
        length = len(value)
    return {"addr": hex(si.ea), "value": value, "length": length,
            "strtype": getattr(si, "strtype", None)}


# Every 16/32-bit-character string type, not just the C-style ones.  The
# Pascal/LEN2/LEN4 variants were being shown by get_ascii_strings and hidden
# from get_unicode_strings.
_UNICODE_STRTYPE_CONSTANTS = (
    ("STRTYPE_C_16", 1), ("STRTYPE_C_32", 2),
    ("STRTYPE_PASCAL_16", 5), ("STRTYPE_PASCAL_32", 6),
    ("STRTYPE_LEN2_16", 9), ("STRTYPE_LEN2_32", 10),
    ("STRTYPE_LEN4_16", 13), ("STRTYPE_LEN4_32", 14),
)


def _unicode_types() -> set:
    types = set()
    for attr, fallback in _UNICODE_STRTYPE_CONSTANTS:
        val = getattr(ida_nalt, attr, fallback)
        if isinstance(val, int):
            types.add(val)
    return types


# ===========================================================================
# Tools
# ===========================================================================


@tool
@idasync
def list_strings(filter_pattern: str = "*", offset: int = 0,
                 limit: int = 100) -> str:
    """List strings with glob filtering and pagination.

    ``filter_pattern`` uses fnmatch (e.g. ``"*error*"``). ``limit`` is clamped
    to [1, 5000] (0/negative -> 5000; oversized -> 5000); the deprecated ``count``
    argument is mapped to ``limit`` by the server.
    """
    ensure_analysis()
    limit = clamp_limit(limit, 100, 5000)

    def _match(row, pattern=filter_pattern):
        return pattern in ("", "*") or fnmatch.fnmatch(row["value"], pattern)

    rows, capped = _collect_rows(_match)
    total = len(rows)
    page, nxt = paginate(rows, offset, limit)
    out = {"data": page, "total": total, "offset": offset,
           "count": len(page), "next_offset": nxt, "limit": limit}
    if capped:
        out["iterated_cap_reached"] = True
    return json.dumps(out, indent=2)


@tool
@idasync
def get_strings_in_range(start: str, end: str, limit: int = 500) -> str:
    """List strings with addresses in ``[start, end)`` (capped)."""
    ensure_analysis()
    try:
        start_ea = parse_addr(start)
        end_ea = parse_addr(end)
    except ValueError as e:
        return json.dumps({"error": str(e)})
    limit = clamp_limit(limit, 500, 10000)
    rows = []
    more = False
    capped = False
    partial = False
    try:
        for i, si in _iter_strings_checked():
            if i >= _MAX_STRINGS:
                capped = True
                break
            if start_ea <= si.ea < end_ea:
                if len(rows) >= limit:
                    # A limit-th match was found; probe once more so exactly
                    # ``limit`` total results are not reported as truncated.
                    more = True
                    break
                rows.append(_row(si))
    except (CancelledError, IDASyncError):
        partial = True
    out: dict = {"start": hex(start_ea), "end": hex(end_ea),
                 "data": rows, "count": len(rows), "limit": limit,
                 "truncated": more}
    if capped:
        out["iterated_cap_reached"] = True
    if partial:
        out["partial"] = True
    return json.dumps(out, indent=2)


@tool
@idasync
def get_string_count() -> str:
    """Count all strings indexed in the binary (no item lists)."""
    ensure_analysis()
    total = 0
    partial = False
    try:
        for _i, _si in _iter_strings_checked():
            total += 1
    except (CancelledError, IDASyncError):
        partial = True
    except Exception as e:
        return json.dumps({"error": str(e)})
    out: dict = {"total": total}
    if partial:
        out["partial"] = True
    return json.dumps(out)


@tool
@idasync
def get_string_at(address: str) -> str:
    """Get the string at (or containing) the given address.

    Falls back to the indexed string whose range contains ``address`` when no
    string starts exactly there.
    """
    ensure_analysis()
    try:
        ea = parse_addr(address)
    except ValueError as e:
        return json.dumps({"error": str(e)})
    try:
        raw = ida_bytes.get_strlit_contents(ea, -1, ida_nalt.STRTYPE_C)
    except Exception:
        raw = None
    if raw:
        try:
            value = bytes(raw).decode("utf-8", errors="replace")
        except Exception:
            value = bytes(raw).hex()
        return json.dumps({"addr": hex(ea), "value": value, "exact": True})
    try:
        for i, si in _iter_strings_checked():
            if i >= _MAX_STRINGS:
                return json.dumps({
                    "addr": hex(ea), "value": None,
                    "iterated_cap_reached": True,
                    "error": "No string found in the first "
                             f"{_MAX_STRINGS} indexed strings",
                })
            try:
                if si.ea <= ea < si.ea + si.length:
                    row = _row(si)
                    row["exact"] = False
                    return json.dumps(row)
            except Exception:
                continue
    except (CancelledError, IDASyncError):
        return json.dumps({"addr": hex(ea), "value": None,
                           "partial": True,
                           "error": "String search was cancelled"})
    return json.dumps({"addr": hex(ea), "value": None, "error": "No string at address"})


@tool
@idasync
def search_strings(query: str, case_sensitive: bool = False,
                   limit: int = 100) -> str:
    """Substring search across all indexed strings (capped).

    ``limit`` is clamped to [1, 5000] (0/negative -> 5000; oversized -> 5000) and the
    applied value is echoed as ``limit``.
    """
    ensure_analysis()
    limit = clamp_limit(limit, 100, 5000)
    needle = query if case_sensitive else query.lower()
    rows = []
    more = False
    capped = False
    partial = False
    try:
        for i, si in _iter_strings_checked():
            if i >= _MAX_STRINGS:
                capped = True
                break
            try:
                value = str(si)
            except Exception:
                continue
            hay = value if case_sensitive else value.lower()
            if needle in hay:
                if len(rows) >= limit:
                    more = True
                    break
                rows.append(_row(si))
    except (CancelledError, IDASyncError):
        partial = True
    out: dict = {"query": query, "data": rows, "count": len(rows),
                 "limit": limit, "truncated": more}
    if capped:
        out["iterated_cap_reached"] = True
    if partial:
        out["partial"] = True
    return json.dumps(out, indent=2)


@tool
@idasync
def get_strings_by_length(min_length: int = 1, max_length: int = 0,
                          offset: int = 0, limit: int = 100) -> str:
    """List strings filtered by length (``max_length`` 0 = no limit).

    Paginated by ``offset`` / ``limit``; the deprecated ``count`` argument is
    mapped to ``limit`` by the server.
    """
    ensure_analysis()
    limit = clamp_limit(limit, 100, 5000)
    rows, capped = _collect_rows(
        lambda row: row["length"] >= min_length
        and (max_length <= 0 or row["length"] <= max_length))
    total = len(rows)
    page, nxt = paginate(rows, offset, limit)
    out = {"data": page, "total": total, "offset": offset,
           "count": len(page), "next_offset": nxt, "limit": limit}
    if capped:
        out["iterated_cap_reached"] = True
    return json.dumps(out, indent=2)


@tool
@idasync
def get_ascii_strings(limit: int = 200, offset: int = 0) -> str:
    """List non-Unicode (C-type) strings with pagination."""
    ensure_analysis()
    limit = clamp_limit(limit, 200, 5000)
    uni = _unicode_types()
    rows, capped = _collect_rows(
        lambda row: row["strtype"] not in uni)
    total = len(rows)
    page, nxt = paginate(rows, offset, limit)
    out = {"data": page, "total": total, "offset": offset,
           "count": len(page), "next_offset": nxt, "limit": limit}
    if capped:
        out["iterated_cap_reached"] = True
    return json.dumps(out, indent=2)


@tool
@idasync
def get_unicode_strings(limit: int = 200, offset: int = 0) -> str:
    """List UTF-16/32 strings with pagination."""
    ensure_analysis()
    limit = clamp_limit(limit, 200, 5000)
    uni = _unicode_types()
    rows, capped = _collect_rows(
        lambda row: row["strtype"] in uni)
    total = len(rows)
    page, nxt = paginate(rows, offset, limit)
    out = {"data": page, "total": total, "offset": offset,
           "count": len(page), "next_offset": nxt, "limit": limit}
    if capped:
        out["iterated_cap_reached"] = True
    return json.dumps(out, indent=2)


__all__ = [
    "list_strings",
    "get_strings_in_range",
    "get_string_count",
    "get_string_at",
    "search_strings",
    "get_strings_by_length",
    "get_ascii_strings",
    "get_unicode_strings",
]
