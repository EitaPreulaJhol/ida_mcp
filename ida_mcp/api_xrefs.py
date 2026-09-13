"""Directional cross-reference tools for ida_mcp.

Splits xrefs by direction (to/from) and by kind (code/data/calls/jumps/
reads/writes), with counting helpers. ``get_xrefs_to`` /
``xref_query`` stay in ``api_analysis.py``; everything directional that needs
more than a glob lives here. Follows idamcp-extendedtools ``api_xrefs.py``.
"""
import json

import ida_auto
import ida_funcs
import ida_typeinf
import idaapi
import idautils

from .rpc import tool
from .sync import idasync
from .api_analysis import parse_addr
from .compat import badaddr


def _resolve(address: str) -> tuple[int | None, str | None]:
    try:
        return parse_addr(address), None
    except ValueError as e:
        return None, json.dumps({"error": str(e)})


def _fmt(xref, include_fn: bool = True) -> dict:
    d: dict = {
        "from": hex(xref.frm),
        "to": hex(xref.to),
        "type": "code" if xref.iscode else "data",
    }
    if include_fn:
        try:
            func = ida_funcs.get_func(xref.frm)
            d["function"] = ida_funcs.get_func_name(func.start_ea) if func else None
        except Exception:
            d["function"] = None
    return d


def _collect_to(ea: int, limit: int, code_only: bool = False,
                data_only: bool = False, types: tuple = ()) -> list[dict]:
    out: list[dict] = []
    for xref in idautils.XrefsTo(ea, 0):
        if code_only and not xref.iscode:
            continue
        if data_only and xref.iscode:
            continue
        if types and xref.type not in types:
            continue
        out.append(_fmt(xref))
        if len(out) >= limit:
            break
    return out


def _collect_from(ea: int, limit: int, code_only: bool = False,
                  data_only: bool = False, types: tuple = ()) -> list[dict]:
    out: list[dict] = []
    for xref in idautils.XrefsFrom(ea, 0):
        if code_only and not xref.iscode:
            continue
        if data_only and xref.iscode:
            continue
        if types and xref.type not in types:
            continue
        out.append(_fmt(xref))
        if len(out) >= limit:
            break
    return out


def _call_types() -> tuple:
    return (idaapi.fl_CF, idaapi.fl_CN)


def _jump_types() -> tuple:
    return (getattr(idaapi, "fl_JF", None), getattr(idaapi, "fl_JN", None))


def _data_read_type():
    try:
        import ida_xref
        for attr in ("DR_R", "dr_R"):
            val = getattr(ida_xref, attr, None)
            if isinstance(val, int):
                return val
    except ImportError:
        pass
    val = getattr(idaapi, "dr_R", None)
    return val if isinstance(val, int) else 2


def _data_write_type():
    try:
        import ida_xref
        for attr in ("DR_W", "dr_W"):
            val = getattr(ida_xref, attr, None)
            if isinstance(val, int):
                return val
    except ImportError:
        pass
    val = getattr(idaapi, "dr_W", None)
    return val if isinstance(val, int) else 1


# ===========================================================================
# Tools — raw directional xrefs
# ===========================================================================


@tool
@idasync
def get_xrefs(address: str, limit: int = 100) -> str:
    """Get all xrefs (both to and from) for an address, each tagged with direction."""
    ida_auto.auto_wait()
    ea, err = _resolve(address)
    if err:
        return err
    if limit <= 0 or limit > 5000:
        limit = 100
    out = [{"direction": "to", **x} for x in _collect_to(ea, limit)]
    out += [{"direction": "from", **x} for x in _collect_from(ea, max(0, limit - len(out)))]
    return json.dumps({"addr": hex(ea), "xrefs": out, "count": len(out)}, indent=2)


@tool
@idasync
def get_xrefs_from(address: str, limit: int = 100) -> str:
    """Get all cross-references FROM an address (outgoing)."""
    ida_auto.auto_wait()
    ea, err = _resolve(address)
    if err:
        return err
    if limit <= 0 or limit > 5000:
        limit = 100
    out = _collect_from(ea, limit)
    return json.dumps({"addr": hex(ea), "xrefs": out, "count": len(out)}, indent=2)


@tool
@idasync
def get_code_refs_to(address: str, limit: int = 200) -> str:
    """Get code references TO an address (excludes data refs)."""
    ida_auto.auto_wait()
    ea, err = _resolve(address)
    if err:
        return err
    if limit <= 0 or limit > 5000:
        limit = 200
    out = _collect_to(ea, limit, code_only=True)
    return json.dumps({"addr": hex(ea), "xrefs": out, "count": len(out)}, indent=2)


@tool
@idasync
def get_code_refs_from(address: str, limit: int = 200) -> str:
    """Get code references FROM an address (excludes data refs)."""
    ida_auto.auto_wait()
    ea, err = _resolve(address)
    if err:
        return err
    if limit <= 0 or limit > 5000:
        limit = 200
    out = _collect_from(ea, limit, code_only=True)
    return json.dumps({"addr": hex(ea), "xrefs": out, "count": len(out)}, indent=2)


@tool
@idasync
def get_data_refs_to(address: str, limit: int = 200) -> str:
    """Get data references TO an address (excludes code refs)."""
    ida_auto.auto_wait()
    ea, err = _resolve(address)
    if err:
        return err
    if limit <= 0 or limit > 5000:
        limit = 200
    out = _collect_to(ea, limit, data_only=True)
    return json.dumps({"addr": hex(ea), "xrefs": out, "count": len(out)}, indent=2)


@tool
@idasync
def get_data_refs_from(address: str, limit: int = 200) -> str:
    """Get data references FROM an address (excludes code refs)."""
    ida_auto.auto_wait()
    ea, err = _resolve(address)
    if err:
        return err
    if limit <= 0 or limit > 5000:
        limit = 200
    out = _collect_from(ea, limit, data_only=True)
    return json.dumps({"addr": hex(ea), "xrefs": out, "count": len(out)}, indent=2)


@tool
@idasync
def get_calls_to(address: str, limit: int = 200) -> str:
    """Get call-type xrefs TO a function (fl_CF/fl_CN only, no plain jumps)."""
    ida_auto.auto_wait()
    ea, err = _resolve(address)
    if err:
        return err
    if limit <= 0 or limit > 5000:
        limit = 200
    out = _collect_to(ea, limit, types=_call_types())
    return json.dumps({"addr": hex(ea), "xrefs": out, "count": len(out)}, indent=2)


@tool
@idasync
def get_calls_from(address: str, limit: int = 200) -> str:
    """Get call-type xrefs FROM an address (fl_CF/fl_CN only)."""
    ida_auto.auto_wait()
    ea, err = _resolve(address)
    if err:
        return err
    if limit <= 0 or limit > 5000:
        limit = 200
    out = _collect_from(ea, limit, types=_call_types())
    return json.dumps({"addr": hex(ea), "xrefs": out, "count": len(out)}, indent=2)


@tool
@idasync
def get_jumps_to(address: str, limit: int = 200) -> str:
    """Get jump-type xrefs TO an address (fl_JF/fl_JN only, no calls)."""
    ida_auto.auto_wait()
    ea, err = _resolve(address)
    if err:
        return err
    if limit <= 0 or limit > 5000:
        limit = 200
    out = _collect_to(ea, limit, types=tuple(t for t in _jump_types() if t is not None))
    return json.dumps({"addr": hex(ea), "xrefs": out, "count": len(out)}, indent=2)


@tool
@idasync
def get_reads_of(address: str, limit: int = 200) -> str:
    """Get data-read xrefs of an address (dr_R)."""
    ida_auto.auto_wait()
    ea, err = _resolve(address)
    if err:
        return err
    if limit <= 0 or limit > 5000:
        limit = 200
    out = _collect_to(ea, limit, types=(_data_read_type(),))
    return json.dumps({"addr": hex(ea), "xrefs": out, "count": len(out)}, indent=2)


@tool
@idasync
def get_writes_to(address: str, limit: int = 200) -> str:
    """Get data-write xrefs of an address (dr_W)."""
    ida_auto.auto_wait()
    ea, err = _resolve(address)
    if err:
        return err
    if limit <= 0 or limit > 5000:
        limit = 200
    out = _collect_to(ea, limit, types=(_data_write_type(),))
    return json.dumps({"addr": hex(ea), "xrefs": out, "count": len(out)}, indent=2)


# ===========================================================================
# Tools — counts
# ===========================================================================


@tool
@idasync
def get_xref_count(address: str) -> str:
    """Count incoming and outgoing xrefs for an address (no item lists)."""
    ida_auto.auto_wait()
    ea, err = _resolve(address)
    if err:
        return err
    try:
        to_count = sum(1 for _ in idautils.XrefsTo(ea, 0))
        from_count = sum(1 for _ in idautils.XrefsFrom(ea, 0))
    except Exception as e:
        return json.dumps({"error": str(e)})
    return json.dumps({"addr": hex(ea), "to": to_count, "from": from_count,
                       "total": to_count + from_count})


@tool
@idasync
def get_caller_count(address: str) -> str:
    """Count call-type callers of the function at an address."""
    ida_auto.auto_wait()
    ea, err = _resolve(address)
    if err:
        return err
    try:
        callers = {ida_funcs.get_func(x.frm).start_ea
                   for x in idautils.XrefsTo(ea, 0)
                   if x.type in _call_types() and ida_funcs.get_func(x.frm) is not None}
    except Exception as e:
        return json.dumps({"error": str(e)})
    return json.dumps({"addr": hex(ea), "caller_count": len(callers)})


@tool
@idasync
def get_callee_count(address: str) -> str:
    """Count distinct functions called by the function at an address."""
    ida_auto.auto_wait()
    ea, err = _resolve(address)
    if err:
        return err
    try:
        func = ida_funcs.get_func(ea)
        if not func:
            return json.dumps({"error": f"No function at {address}"})
        callees = {ida_funcs.get_func(ref).start_ea
                   for item in idautils.FuncItems(func.start_ea)
                   for ref in idautils.CodeRefsFrom(item, 0)
                   if ida_funcs.get_func(ref) is not None}
    except Exception as e:
        return json.dumps({"error": str(e)})
    return json.dumps({"addr": hex(func.start_ea), "callee_count": len(callees)})


# ===========================================================================
# Tools — struct field xrefs
# ===========================================================================


@tool
@idasync
def xrefs_to_field(struct_name: str, field_name: str, limit: int = 200) -> str:
    """Get cross-references to a struct/union field by ``Struct.field`` name.

    Resolves the field via the local type library (``get_udm_by_fullname``)
    and enumerates xrefs to its type id. Ported from ida-pro-mcp.
    """
    ida_auto.auto_wait()
    if limit <= 0 or limit > 5000:
        limit = 200
    try:
        til = ida_typeinf.get_idati()
    except Exception as e:
        return json.dumps({"struct": struct_name, "field": field_name,
                           "xrefs": [], "error": str(e)})
    if not til:
        return json.dumps({"struct": struct_name, "field": field_name,
                           "xrefs": [], "error": "Failed to retrieve type library"})
    try:
        tif = ida_typeinf.tinfo_t()
        if not tif.get_named_type(til, struct_name, ida_typeinf.BTF_STRUCT, True, False):
            return json.dumps({"struct": struct_name, "field": field_name,
                               "xrefs": [], "error": f"Struct '{struct_name}' not found"})
        idx = ida_typeinf.get_udm_by_fullname(None, struct_name + "." + field_name)
        if idx == -1:
            return json.dumps({"struct": struct_name, "field": field_name,
                               "xrefs": [], "error": f"Field '{field_name}' not found"})
        tid = tif.get_udm_tid(idx)
        if tid == badaddr():
            return json.dumps({"struct": struct_name, "field": field_name,
                               "xrefs": [], "error": "Unable to get tid"})
        xrefs: list[dict] = []
        for xref in idautils.XrefsTo(tid, 0):
            xrefs.append(_fmt(xref))
            if len(xrefs) >= limit:
                break
    except Exception as e:
        return json.dumps({"struct": struct_name, "field": field_name,
                           "xrefs": [], "error": str(e)})
    result: dict = {"struct": struct_name, "field": field_name, "xrefs": xrefs,
                    "count": len(xrefs)}
    if not xrefs:
        result["message"] = "No cross-references to this struct field"
    return json.dumps(result, indent=2)


__all__ = [
    "get_xrefs",
    "get_xrefs_from",
    "get_code_refs_to",
    "get_code_refs_from",
    "get_data_refs_to",
    "get_data_refs_from",
    "get_calls_to",
    "get_calls_from",
    "get_jumps_to",
    "get_reads_of",
    "get_writes_to",
    "get_xref_count",
    "get_caller_count",
    "get_callee_count",
    "xrefs_to_field",
]
