"""Advanced query tools for ida_mcp.

Richer filtering than the flat list tools: regex + size/type filters with
sorting and pagination (``func_query``), a generic cross-entity query
(``entity_query``), global listing (``list_globals``), import queries
(``imports_query``) and stack-variable lookup (``get_local_variable_by_name``,
``get_local_variable_references``).

Modeled on ida-pro-mcp ``api_core.py`` (func_query, entity_query,
list_globals, imports_query), adapted to flat MCP-friendly parameters and
JSON-string results.
"""
import fnmatch
import json
import re

import ida_auto
import ida_funcs
import ida_lines
import ida_nalt
import ida_segment
import ida_typeinf
import idaapi
import idautils

from .rpc import tool
from .sync import idasync
from .api_analysis import parse_addr
from .api_functions import _collect_frame_vars


_MAX_ENTITY_STRINGS = 50000


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _paginate(rows: list, offset: int, count: int) -> tuple[list, int | None]:
    if count <= 0:
        count = len(rows)
    page = rows[offset:offset + count]
    nxt = offset + count if offset + count < len(rows) else None
    return page, nxt


def _seg_name(ea: int) -> str:
    try:
        seg = ida_segment.getseg(ea)
        if seg is not None:
            return ida_segment.get_segm_name(seg) or ""
    except Exception:
        pass
    return ""


def _collect_imports() -> list[dict]:
    out: list[dict] = []
    try:
        nimps = ida_nalt.get_import_module_qty()
    except Exception:
        return out
    for i in range(nimps):
        try:
            module = ida_nalt.get_import_module_name(i) or "<unnamed>"
        except Exception:
            module = "<unnamed>"
        collected: list[tuple[int, str]] = []

        def _cb(ea: int, sym, ordinal: int) -> bool:
            collected.append((ea, sym or f"#{ordinal}"))
            return True

        try:
            ida_nalt.enum_import_names(i, _cb)
        except Exception:
            continue
        for ea, sym in collected:
            out.append({"addr": hex(ea), "imported_name": sym, "module": module})
    return out


def _collect_entities(kind: str) -> list[dict]:
    """Collect raw rows for ``entity_query`` kinds."""
    rows: list[dict] = []
    if kind == "functions":
        for ea in idautils.Functions():
            func = idaapi.get_func(ea)
            if not func:
                continue
            size = func.end_ea - func.start_ea
            tif = ida_typeinf.tinfo_t()
            try:
                has_type = bool(ida_nalt.get_tinfo(tif, func.start_ea))
            except Exception:
                has_type = False
            rows.append({
                "addr": hex(func.start_ea),
                "name": ida_funcs.get_func_name(func.start_ea) or "<unnamed>",
                "size": hex(size),
                "size_int": size,
                "has_type": has_type,
                "segment": _seg_name(func.start_ea),
            })
    elif kind == "globals":
        for ea, name in idautils.Names():
            if name and idaapi.get_func(ea) is None:
                rows.append({"addr": hex(ea), "name": name, "segment": _seg_name(ea)})
    elif kind == "imports":
        rows = _collect_imports()
    elif kind == "strings":
        for si in idautils.Strings():
            rows.append({
                "addr": hex(si.ea),
                "value": str(si),
                "length": si.length,
                "segment": _seg_name(si.ea),
            })
            if len(rows) >= _MAX_ENTITY_STRINGS:
                break
    elif kind == "names":
        for ea, name in idautils.Names():
            if name:
                rows.append({"addr": hex(ea), "name": name, "segment": _seg_name(ea)})
    return rows


def _match_glob(value: str, pattern: str) -> bool:
    """Glob match where ``*``/empty means all; supports ``/regex/flags``."""
    if not pattern or pattern == "*":
        return True
    if pattern.startswith("/") and pattern.count("/") >= 2:
        last = pattern.rfind("/")
        body, flags_str = pattern[1:last], pattern[last + 1:]
        flags = 0
        if "i" in flags_str:
            flags |= re.IGNORECASE
        if "m" in flags_str:
            flags |= re.MULTILINE
        if "s" in flags_str:
            flags |= re.DOTALL
        try:
            return re.compile(body, flags or re.IGNORECASE).search(value) is not None
        except re.error:
            return False
    return fnmatch.fnmatch(value, pattern)


# ===========================================================================
# Tools
# ===========================================================================


@tool
@idasync
def func_query(filter_pattern: str = "", name_regex: str = "",
               min_size: int = -1, max_size: int = -1, has_type: str = "",
               sort_by: str = "addr", descending: bool = False,
               offset: int = 0, count: int = 50) -> str:
    """Query functions with richer filtering than ``list_funcs``.

    ``filter_pattern`` is a glob on the name; ``name_regex`` a Python regex.
    ``min_size``/``max_size`` filter byte size (-1 = unset). ``has_type`` is
    ``\"true\"``/``\"false\"``/``\"\"`` (any). ``sort_by`` is one of
    ``addr``/``name``/``size``.
    """
    ida_auto.auto_wait()
    rows: list[dict] = []
    for ea in idautils.Functions():
        func = idaapi.get_func(ea)
        if not func:
            continue
        size = func.end_ea - func.start_ea
        name = ida_funcs.get_func_name(func.start_ea) or "<unnamed>"
        tif = ida_typeinf.tinfo_t()
        try:
            typed = bool(ida_nalt.get_tinfo(tif, func.start_ea))
        except Exception:
            typed = False
        rows.append({
            "addr": hex(func.start_ea),
            "name": name,
            "size": hex(size),
            "size_int": size,
            "has_type": typed,
        })

    if filter_pattern:
        rows = [r for r in rows if fnmatch.fnmatch(r["name"], filter_pattern)]
    if name_regex:
        try:
            rx = re.compile(name_regex)
            rows = [r for r in rows if rx.search(r["name"])]
        except re.error as e:
            return json.dumps({"error": f"Invalid name_regex: {e}"})
    if min_size is not None and min_size >= 0:
        rows = [r for r in rows if r["size_int"] >= min_size]
    if max_size is not None and max_size >= 0:
        rows = [r for r in rows if r["size_int"] <= max_size]
    if has_type in ("true", "false"):
        want = has_type == "true"
        rows = [r for r in rows if r["has_type"] is want]

    if sort_by == "name":
        rows.sort(key=lambda r: r["name"].lower(), reverse=bool(descending))
    elif sort_by == "size":
        rows.sort(key=lambda r: r["size_int"], reverse=bool(descending))
    else:
        rows.sort(key=lambda r: int(r["addr"], 16), reverse=bool(descending))

    page, nxt = _paginate(rows, offset, count)
    page = [{k: v for k, v in r.items() if k != "size_int"} for r in page]
    return json.dumps({
        "data": page, "total": len(rows),
        "offset": offset, "next_offset": nxt,
    }, indent=2)


@tool
@idasync
def entity_query(kind: str = "functions", filter: str = "", regex: str = "",
                 segment: str = "", module: str = "",
                 min_addr: str = "", max_addr: str = "",
                 sort_by: str = "addr", descending: bool = False,
                 fields: str = "", offset: int = 0, count: int = 100) -> str:
    """Generic IDB entity query with filtering, projection and pagination.

    ``kind`` is one of ``functions``/``globals``/``imports``/``strings``/
    ``names``. ``filter`` is a glob (or ``/regex/flags``) on the primary text
    field; ``regex`` a plain Python regex on the same field; ``segment`` a
    glob on the segment name (imports have ``module`` instead); ``min_addr``/
    ``max_addr`` bound the address range; ``fields`` is a comma-separated
    projection (empty = all fields).
    """
    ida_auto.auto_wait()
    kind = (kind or "functions").lower()
    if kind not in ("functions", "globals", "imports", "strings", "names"):
        return json.dumps({"kind": kind, "error": f"Unsupported kind: {kind}"})

    rows = _collect_entities(kind)
    primary = {"functions": "name", "globals": "name", "imports": "imported_name",
               "strings": "value", "names": "name"}[kind]
    if filter:
        rows = [r for r in rows if _match_glob(str(r.get(primary, "")), filter)]
    if regex:
        try:
            rx = re.compile(regex)
            rows = [r for r in rows if rx.search(str(r.get(primary, "")))]
        except re.error as e:
            return json.dumps({"kind": kind, "error": f"Invalid regex: {e}"})
    if segment and kind != "imports":
        rows = [r for r in rows if _match_glob(r.get("segment", ""), segment)]
    if module and kind == "imports":
        rows = [r for r in rows if _match_glob(r.get("module", ""), module)]
    for bound, key in ((min_addr, "min"), (max_addr, "max")):
        if bound:
            try:
                bound_ea = parse_addr(bound)
            except ValueError as e:
                return json.dumps({"kind": kind, "error": str(e)})
            rows = [r for r in rows
                    if (int(r["addr"], 16) >= bound_ea if key == "min"
                        else int(r["addr"], 16) <= bound_ea)]

    if sort_by == "addr":
        rows.sort(key=lambda r: int(r.get("addr", "0x0"), 16), reverse=bool(descending))
    elif sort_by in ("size", "length"):
        rows.sort(key=lambda r: r.get("size_int", r.get("length", 0) or 0),
                  reverse=bool(descending))
    else:
        rows.sort(key=lambda r: str(r.get(sort_by, "")).lower(), reverse=bool(descending))

    total = len(rows)
    page, nxt = _paginate(rows, offset, count)
    page = [{k: v for k, v in r.items() if k != "size_int"} for r in page]
    if fields:
        wanted = [f.strip() for f in fields.split(",") if f.strip()]
        page = [{k: r[k] for k in wanted if k in r} for r in page]
    return json.dumps({
        "kind": kind, "data": page, "total": total,
        "offset": offset, "next_offset": nxt, "error": None,
    }, indent=2)


@tool
@idasync
def list_globals(filter_pattern: str = "*", offset: int = 0, count: int = 100) -> str:
    """List global (non-function) names with glob filtering and pagination."""
    ida_auto.auto_wait()
    rows: list[dict] = []
    for ea, name in idautils.Names():
        if name and idaapi.get_func(ea) is None:
            if filter_pattern in ("", "*") or fnmatch.fnmatch(name, filter_pattern):
                rows.append({"addr": hex(ea), "name": name})
    page, nxt = _paginate(rows, offset, count)
    return json.dumps({
        "data": page, "total": len(rows),
        "offset": offset, "next_offset": nxt,
    }, indent=2)


@tool
@idasync
def imports_query(filter: str = "", module: str = "",
                  offset: int = 0, count: int = 100) -> str:
    """Query imports with name and module glob filters plus pagination."""
    ida_auto.auto_wait()
    rows = _collect_imports()
    if filter:
        rows = [r for r in rows if fnmatch.fnmatch(r["imported_name"], filter)]
    if module:
        rows = [r for r in rows if fnmatch.fnmatch(r["module"], module)]
    page, nxt = _paginate(rows, offset, count)
    return json.dumps({
        "data": page, "total": len(rows),
        "offset": offset, "next_offset": nxt,
    }, indent=2)


@tool
@idasync
def get_local_variable_by_name(address: str, name: str) -> str:
    """Find a stack-frame variable by name in the function at ``address``."""
    ida_auto.auto_wait()
    try:
        ea = parse_addr(address)
    except ValueError as e:
        return json.dumps({"error": str(e)})

    func = ida_funcs.get_func(ea)
    if not func:
        return json.dumps({"error": f"No function at {address}"})
    for var in _collect_frame_vars(func):
        if var.get("name") == name:
            return json.dumps({
                "function": ida_funcs.get_func_name(func.start_ea) or "",
                "var": var,
            }, indent=2)
    return json.dumps({
        "function": ida_funcs.get_func_name(func.start_ea) or "",
        "var": None,
        "error": f"No variable named {name!r}",
    })


@tool
@idasync
def get_local_variable_references(address: str, var_name: str) -> str:
    """Find instructions in the function whose disassembly mentions ``var_name``.

    Stack-variable uses render as ``[rbp+var_X]``-style text in the disassembly
    line, so a text scan over the function items reliably locates references.
    """
    ida_auto.auto_wait()
    try:
        ea = parse_addr(address)
    except ValueError as e:
        return json.dumps({"error": str(e)})

    func = ida_funcs.get_func(ea)
    if not func:
        return json.dumps({"error": f"No function at {address}"})
    if not any(v.get("name") == var_name for v in _collect_frame_vars(func)):
        return json.dumps({"error": f"No variable named {var_name!r} in function"})

    refs: list[dict] = []
    for head in idautils.FuncItems(func.start_ea):
        try:
            line = ida_lines.tag_remove(ida_lines.generate_disasm_line(head, 0) or "")
        except Exception:
            continue
        if var_name in line:
            refs.append({"addr": hex(head), "disasm": line.strip()})
    return json.dumps({
        "function": ida_funcs.get_func_name(func.start_ea) or "",
        "var": var_name,
        "references": refs,
        "count": len(refs),
    }, indent=2)


__all__ = [
    "func_query",
    "entity_query",
    "list_globals",
    "imports_query",
    "get_local_variable_by_name",
    "get_local_variable_references",
]
