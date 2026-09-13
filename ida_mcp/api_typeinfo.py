"""Type system tools — query, inspect, declare, and apply types in IDA Pro.

Tools ported from idamcp-extendedtools api_types.py, adapted for direct
in-process IDA SDK access (no router indirection).
"""

import json

import ida_auto
import ida_bytes
import ida_funcs
import ida_nalt
import ida_typeinf

from .rpc import tool, unsafe
from .sync import idasync
from .api_analysis import parse_addr


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_idati():
    """Return the current type info library descriptor."""
    return ida_typeinf.get_idati()

def _format_tinfo(tif: ida_typeinf.tinfo_t) -> dict:
    """Format a type info object into a JSON-serializable dict."""
    result = {}
    name = tif.get_type_name()
    result["name"] = name or "<unnamed>"
    result["size"] = tif.get_size()
    result["is_func"] = tif.is_func()
    result["is_struct"] = tif.is_struct()
    result["is_enum"] = tif.is_enum()
    result["is_union"] = tif.is_union()
    result["is_ptr"] = tif.is_ptr()
    result["is_array"] = tif.is_array()

    # Get the full C declaration
    try:
        decl = tif._print(None, ida_typeinf.PRTYPE_DEF | ida_typeinf.PRTYPE_TYPE)
        result["declaration"] = decl if decl else None
    except Exception:
        result["declaration"] = None

    if tif.is_struct() or tif.is_union():
        members = []
        udt = ida_typeinf.udt_type_data_t()
        if tif.get_udt_details(udt):
            for m in udt:
                offset = m.offset // 8 if hasattr(m, 'offset') else m.soff
                mtype = ida_typeinf.tinfo_t()
                if m.type.get(mtype):
                    mname = m.name if m.name else f"field_{hex(offset)}"
                    members.append({
                        "name": mname,
                        "offset": offset,
                        "size": mtype.get_size(),
                        "type": mtype.get_type_name() or "<unnamed>",
                    })
        result["members"] = members

    if tif.is_enum():
        members = []
        edt = ida_typeinf.enum_type_data_t()
        if tif.get_enum_details(edt):
            for member in edt:
                members.append({
                    "name": member.name,
                    "value": member.value,
                })
        result["members"] = members

    if tif.is_func():
        ftd = ida_typeinf.func_type_data_t()
        if tif.get_func_details(ftd):
            args = []
            for a in ftd:
                args.append({
                    "name": a.name,
                    "type": a.type.get_type_name() if a.type.get_type_name() else "<unnamed>",
                })
            result["return_type"] = str(ftd.rettype)
            result["arguments"] = args
            result["cc"] = ftd.cc

    return result


# ===========================================================================
# Tools
# ===========================================================================


@tool
@idasync
def type_query(
    filter: str = "",
) -> str:
    """Query the type catalog for all registered local types.

    Optionally filter by a case-insensitive substring match on type names.
    Returns type names, sizes, and kinds.
    """
    ida_auto.auto_wait()
    results: list[dict] = []
    idati = _get_idati()
    til = ida_typeinf.get_idati()

    # Enumerate ordinal-based types from the type library
    for ordinal in range(1, ida_typeinf.get_ordinal_qty(til) + 1):
        tif = ida_typeinf.tinfo_t()
        if tif.get_numbered_type(til, ordinal):
            info = _format_tinfo(tif)
            if not filter or filter.lower() in info.get("name", "").lower():
                results.append({
                    "ordinal": ordinal,
                    **info,
                })

    return json.dumps(results, indent=2)


@tool
@idasync
def type_inspect(
    name: str,
) -> str:
    """Inspect a named type (size, kind, declaration, members).

    Returns detailed information about a type including its
    size, kind, declaration string, struct/union members, or enum values.
    """
    ida_auto.auto_wait()
    tif = ida_typeinf.tinfo_t()
    if not tif.get_named_type(_get_idati(), name):
        return json.dumps({"error": f"Type '{name}' not found"})

    info = _format_tinfo(tif)
    return json.dumps(info, indent=2)


@tool
@idasync
def get_type_at(
    address: str,
) -> str:
    """Get the type information applied at a given address.

    Checks for function prototype types and data item types.
    """
    ida_auto.auto_wait()
    try:
        ea = parse_addr(address)
    except ValueError as e:
        return json.dumps({"error": str(e)})

    result: dict = {"addr": hex(ea)}

    # Check for function with known prototype
    func = ida_funcs.get_func(ea)
    if func:
        tif = ida_typeinf.tinfo_t()
        if ida_typeinf.guess_tinfo(tif, ea) or ida_typeinf.get_tinfo(tif, ea):
            info = _format_tinfo(tif)
            result["type"] = info
        else:
            result["type"] = None
    else:
        # Check for data type
        tif = ida_typeinf.tinfo_t()
        if ida_typeinf.get_tinfo(tif, ea):
            info = _format_tinfo(tif)
            result["type"] = info
        else:
            result["type"] = None

    return json.dumps(result, indent=2)


@tool
@idasync
@unsafe
def set_type(
    address: str,
    type_name: str,
) -> str:
    """Apply a type (function signature, struct, etc.) at a given address.

    Looks up the type by name and applies it to the address.
    **Unsafe** — requires ``?unsafe=true``.
    """
    ida_auto.auto_wait()
    try:
        ea = parse_addr(address)
    except ValueError as e:
        return json.dumps({"error": str(e)})

    tif = ida_typeinf.tinfo_t()
    if not tif.get_named_type(_get_idati(), type_name):
        return json.dumps({"error": f"Type '{type_name}' not found"})

    if ida_typeinf.apply_tinfo(ea, tif, ida_typeinf.TINFO_DEFINITE):
        return json.dumps({"addr": hex(ea), "type_applied": type_name, "ok": True}, indent=2)
    else:
        return json.dumps({"addr": hex(ea), "error": f"Failed to apply type '{type_name}'"})


@tool
@idasync
@unsafe
def declare_type(
    declaration: str,
) -> str:
    """Parse and store C type declaration(s) in the local type library.

    Accepts C type declarations (struct, typedef, enum, etc.) and
    parses them into IDA's type system.
    **Unsafe** — requires ``?unsafe=true``.
    """
    ida_auto.auto_wait()
    return json.dumps(_declare_type_impl(declaration), indent=2)


def _declare_type_impl(declaration: str) -> dict:
    """Plain (non-synced) declare logic — called from @idasync contexts.

    ``enum_upsert`` calls this directly; calling the ``declare_type`` tool
    from inside another ``@idasync`` body would nest ``execute_sync``.
    """
    errors = ida_typeinf.print_decls(declaration, None, 0)
    count = ida_typeinf.idc_parse_types(declaration, 0)

    if count == 0:
        return {
            "declaration": declaration,
            "ok": False,
            "parsed_count": 0,
            "errors": errors if errors else "Failed to parse declaration",
        }

    return {
        "declaration": declaration,
        "ok": True,
        "parsed_count": count,
        "errors": errors if errors else None,
    }


@tool
@idasync
def search_structs(
    filter: str = "",
) -> str:
    """Search local structs/unions by name pattern (case-insensitive substring).

    Returns matching struct type names and basic info.
    """
    ida_auto.auto_wait()
    results: list[dict] = []
    til = _get_idati()

    for ordinal in range(1, ida_typeinf.get_ordinal_qty(til) + 1):
        tif = ida_typeinf.tinfo_t()
        if tif.get_numbered_type(til, ordinal):
            if tif.is_struct() or tif.is_union():
                info = _format_tinfo(tif)
                name = info.get("name", "")
                if not filter or filter.lower() in name.lower():
                    results.append({
                        "ordinal": ordinal,
                        **info,
                    })

    return json.dumps(results, indent=2)


@tool
@idasync
def read_struct(
    address: str,
    type_name: str,
) -> str:
    """Read struct fields from memory at the given address.

    Interprets memory at the address as the specified struct/union type
    and returns field names, offsets, types, and values.
    """
    ida_auto.auto_wait()
    try:
        ea = parse_addr(address)
    except ValueError as e:
        return json.dumps({"error": str(e)})

    tif = ida_typeinf.tinfo_t()
    if not tif.get_named_type(_get_idati(), type_name):
        return json.dumps({"error": f"Type '{type_name}' not found"})
    if not (tif.is_struct() or tif.is_union()):
        return json.dumps({"error": f"Type '{type_name}' is not a struct or union"})

    udt = ida_typeinf.udt_type_data_t()
    if not tif.get_udt_details(udt):
        return json.dumps({"error": f"Could not get members of '{type_name}'"})

    fields: list[dict] = []
    for m in udt:
        offset = m.offset // 8 if hasattr(m, 'offset') else m.soff
        size = m.type.get_size() if hasattr(m.type, 'get_size') else 0
        mname = m.name or f"field_{hex(offset)}"

        raw = ida_bytes.get_bytes(ea + offset, size) if size > 0 and size <= 4096 else None
        value = raw.hex() if raw else None

        mtype = ida_typeinf.tinfo_t()
        mtype_name = "<unknown>"
        if hasattr(m, 'type') and m.type and hasattr(m.type, 'get'):
            if m.type.get(mtype):
                mtype_name = mtype.get_type_name() or "<unnamed>"

        fields.append({
            "name": mname,
            "offset": offset,
            "size": size,
            "type": mtype_name,
            "value_hex": value,
        })

    return json.dumps({"addr": hex(ea), "type": type_name, "fields": fields}, indent=2)


@tool
@idasync
@unsafe
def enum_upsert(
    enum_name: str,
    members: str,
) -> str:
    """Create or update an enum type with the given members.

    ``members`` is a JSON array of ``{name, value}`` objects.
    If the enum doesn't exist, it's created. If it does, members are upserted.
    **Unsafe** — requires ``?unsafe=true``.
    """
    ida_auto.auto_wait()

    try:
        member_list = json.loads(members)
    except json.JSONDecodeError as e:
        return json.dumps({"error": f"Invalid JSON for members: {e}"})

    if not isinstance(member_list, list):
        return json.dumps({"error": "members must be a JSON array of {name, value} dicts"})

    # Build a C enum declaration
    member_strs = []
    for m in member_list:
        if isinstance(m, dict) and "name" in m and "value" in m:
            member_strs.append(f"{m['name']} = {m['value']}")
        else:
            return json.dumps({"error": "Each member must be {name, value}"})

    declaration = f"enum {enum_name} {{ {', '.join(member_strs)} }};"
    return json.dumps(_declare_type_impl(declaration), indent=2)


@tool
@idasync
def get_type_by_name(
    name: str,
) -> str:
    """Get full type information by exact type name.

    Looks the name up in the local type library and returns size, kind,
    declaration and members. Unlike ``type_inspect`` (substring-oriented),
    this resolves one exact name — including struct field layouts.
    """
    ida_auto.auto_wait()
    tif = ida_typeinf.tinfo_t()
    try:
        found = tif.get_named_type(_get_idati(), name)
    except Exception as e:
        return json.dumps({"error": str(e)})
    if not found:
        return json.dumps({"error": f"Type '{name}' not found"})
    info = _format_tinfo(tif)
    info["requested_name"] = name
    return json.dumps(info, indent=2)


def _guess_tinfo(ea: int):
    """Best-effort type guess at ``ea``; returns (tif|None, method)."""
    tif = ida_typeinf.tinfo_t()
    guess = getattr(ida_typeinf, "guess_tinfo", None)
    if callable(guess):
        try:
            if guess(tif, ea):
                return tif, "hexrays"
        except Exception:
            pass
    try:
        import ida_hexrays
        init = getattr(ida_hexrays, "init_hexrays_plugin", None)
        hguess = getattr(ida_hexrays, "guess_tinfo", None)
        if callable(init) and callable(hguess) and init():
            try:
                if hguess(tif, ea):
                    return tif, "hexrays"
            except Exception:
                pass
    except ImportError:
        pass
    try:
        if ida_nalt.get_tinfo(tif, ea):
            return tif, "existing"
    except Exception:
        pass
    return None, None


@tool
@idasync
def infer_types(addresses: str) -> str:
    """Infer (not apply) likely types at target addresses.

    ``addresses`` is a comma-separated list of addresses/symbols. For each,
    tries Hex-Rays inference, then existing type info, then a size-based
    integer guess — reporting method and confidence per address.
    Read-only: use ``set_type`` to apply a result. Ported from ida-pro-mcp.
    """
    ida_auto.auto_wait()
    results: list[dict] = []
    for raw in (a.strip() for a in addresses.split(",") if a.strip()):
        try:
            ea = parse_addr(raw)
        except ValueError:
            results.append({"addr": raw, "inferred_type": None,
                            "method": None, "confidence": "none",
                            "error": f"Unknown address or name: {raw}"})
            continue
        try:
            tif, method = _guess_tinfo(ea)
            if tif is not None:
                try:
                    inferred = str(tif)
                except Exception:
                    inferred = None
                results.append({"addr": hex(ea), "inferred_type": inferred,
                                "method": method, "confidence": "high"})
                continue
            size = 0
            try:
                size = ida_bytes.get_item_size(ea)
            except Exception:
                pass
            if size and size > 0:
                guess = {1: "uint8_t", 2: "uint16_t",
                         4: "uint32_t", 8: "uint64_t"}.get(size, f"uint8_t[{size}]")
                results.append({"addr": hex(ea), "inferred_type": guess,
                                "method": "size_based", "confidence": "low"})
                continue
            results.append({"addr": hex(ea), "inferred_type": None,
                            "method": None, "confidence": "none"})
        except Exception as e:
            results.append({"addr": raw, "inferred_type": None,
                            "method": None, "confidence": "none", "error": str(e)})
    return json.dumps({"results": results}, indent=2)
