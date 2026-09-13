"""Paginated string enumeration tools for ida_mcp.

``list_strings`` (glob + offset/count) stays in ``api_analysis.py``; this
module adds count/at/range/length/ascii/unicode/substring variants.
Follows idamcp-extendedtools ``api_strings.py`` naming.
"""
import fnmatch
import json

import ida_auto
import ida_bytes
import ida_nalt
import idaapi
import idautils

from .rpc import tool
from .sync import idasync
from .api_analysis import parse_addr


_MAX_STRINGS = 50000


def _iter_strings():
    try:
        yield from idautils.Strings()
    except Exception:
        return


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


def _paginate(rows: list, offset: int, count: int) -> tuple[list, int | None]:
    if count <= 0:
        count = len(rows)
    page = rows[offset:offset + count]
    nxt = offset + count if offset + count < len(rows) else None
    return page, nxt


def _unicode_types() -> set:
    types = set()
    for attr, fallback in (("STRTYPE_C_16", 1), ("STRTYPE_C_32", 2)):
        val = getattr(ida_nalt, attr, fallback)
        if isinstance(val, int):
            types.add(val)
    return types


# ===========================================================================
# Tools
# ===========================================================================


@tool
@idasync
def get_strings(limit: int = 100, offset: int = 0, filter_pattern: str = "*") -> str:
    """List strings with limit/offset pagination and optional glob filter."""
    ida_auto.auto_wait()
    if limit <= 0 or limit > 5000:
        limit = 100
    rows = [_row(si) for si in _iter_strings()]
    if filter_pattern not in ("", "*"):
        rows = [r for r in rows if fnmatch.fnmatch(r["value"], filter_pattern)]
    total = len(rows)
    page, nxt = _paginate(rows, offset, limit)
    return json.dumps({"data": page, "total": total, "offset": offset,
                       "count": len(page), "next_offset": nxt}, indent=2)


@tool
@idasync
def get_strings_in_range(start: str, end: str, limit: int = 500) -> str:
    """List strings with addresses in ``[start, end)`` (capped)."""
    ida_auto.auto_wait()
    try:
        start_ea = parse_addr(start)
        end_ea = parse_addr(end)
    except ValueError as e:
        return json.dumps({"error": str(e)})
    if limit <= 0 or limit > 10000:
        limit = 500
    rows = []
    for si in _iter_strings():
        if start_ea <= si.ea < end_ea:
            rows.append(_row(si))
            if len(rows) >= limit:
                break
    return json.dumps({"start": hex(start_ea), "end": hex(end_ea),
                       "data": rows, "count": len(rows),
                       "truncated": len(rows) >= limit}, indent=2)


@tool
@idasync
def get_string_count() -> str:
    """Count all strings indexed in the binary (no item lists)."""
    ida_auto.auto_wait()
    try:
        total = sum(1 for _ in _iter_strings())
    except Exception as e:
        return json.dumps({"error": str(e)})
    return json.dumps({"total": total})


@tool
@idasync
def get_string_at(address: str) -> str:
    """Get the string at (or containing) the given address.

    Falls back to the indexed string whose range contains ``address`` when no
    string starts exactly there.
    """
    ida_auto.auto_wait()
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
    for si in _iter_strings():
        try:
            if si.ea <= ea < si.ea + si.length:
                row = _row(si)
                row["exact"] = False
                return json.dumps(row)
        except Exception:
            continue
    return json.dumps({"addr": hex(ea), "value": None, "error": "No string at address"})


@tool
@idasync
def search_strings(query: str, case_sensitive: bool = False,
                   limit: int = 100) -> str:
    """Substring search across all indexed strings (capped)."""
    ida_auto.auto_wait()
    if limit <= 0 or limit > 5000:
        limit = 100
    needle = query if case_sensitive else query.lower()
    rows = []
    for si in _iter_strings():
        try:
            value = str(si)
        except Exception:
            continue
        hay = value if case_sensitive else value.lower()
        if needle in hay:
            rows.append(_row(si))
            if len(rows) >= limit:
                break
    return json.dumps({"query": query, "data": rows, "count": len(rows),
                       "truncated": len(rows) >= limit}, indent=2)


@tool
@idasync
def get_strings_by_length(min_length: int = 1, max_length: int = 0,
                          offset: int = 0, count: int = 100) -> str:
    """List strings filtered by length (``max_length`` 0 = no limit)."""
    ida_auto.auto_wait()
    rows = []
    for si in _iter_strings():
        try:
            length = si.length
        except Exception:
            continue
        if length >= min_length and (max_length <= 0 or length <= max_length):
            rows.append(_row(si))
    total = len(rows)
    page, nxt = _paginate(rows, offset, count if count > 0 else len(rows))
    return json.dumps({"data": page, "total": total, "offset": offset,
                       "count": len(page), "next_offset": nxt}, indent=2)


@tool
@idasync
def get_ascii_strings(limit: int = 200, offset: int = 0) -> str:
    """List non-Unicode (C-type) strings with pagination."""
    ida_auto.auto_wait()
    if limit <= 0 or limit > 5000:
        limit = 200
    uni = _unicode_types()
    rows = [_row(si) for si in _iter_strings()
            if getattr(si, "strtype", ida_nalt.STRTYPE_C) not in uni]
    total = len(rows)
    page, nxt = _paginate(rows, offset, limit)
    return json.dumps({"data": page, "total": total, "offset": offset,
                       "count": len(page), "next_offset": nxt}, indent=2)


@tool
@idasync
def get_unicode_strings(limit: int = 200, offset: int = 0) -> str:
    """List UTF-16/32 strings with pagination."""
    ida_auto.auto_wait()
    if limit <= 0 or limit > 5000:
        limit = 200
    uni = _unicode_types()
    rows = [_row(si) for si in _iter_strings()
            if getattr(si, "strtype", None) in uni]
    total = len(rows)
    page, nxt = _paginate(rows, offset, limit)
    return json.dumps({"data": page, "total": total, "offset": offset,
                       "count": len(page), "next_offset": nxt}, indent=2)


__all__ = [
    "get_strings",
    "get_strings_in_range",
    "get_string_count",
    "get_string_at",
    "search_strings",
    "get_strings_by_length",
    "get_ascii_strings",
    "get_unicode_strings",
]
