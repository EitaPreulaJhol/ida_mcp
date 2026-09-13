"""Enhanced function query tools — listing, inspecting, and managing functions.

Tools ported from idamcp-extendedtools api_query.py and api_flow.py,
adapted for direct in-process IDA SDK access.
"""

import json

import ida_auto
import ida_bytes
import ida_frame
import ida_funcs
import ida_gdl
import ida_name
import ida_nalt
import ida_typeinf
import idaapi
import idautils
import idc

from .rpc import tool, unsafe
from .sync import idasync
from .api_analysis import parse_addr


# ===========================================================================
# Tools — Listing & Counting
# ===========================================================================


@tool
@idasync
def list_funcs(
    offset: int = 0,
    count: int = 100,
) -> str:
    """List functions with pagination support.

    ``offset``: starting position (0-based).
    ``count``: number of functions to return (max 1000).
    Returns JSON array of ``{addr, name, size}`` objects.
    """
    ida_auto.auto_wait()
    count = min(int(count), 1000)
    offset = max(int(offset), 0)

    # Single pass: the old code walked Functions() twice (page + total),
    # doubling main-thread hold time on large binaries.
    funcs: list[dict] = []
    total = 0
    for ea in idautils.Functions():
        if total >= offset and len(funcs) < count:
            name = ida_funcs.get_func_name(ea)
            fn = ida_funcs.get_func(ea)
            funcs.append({
                "addr": hex(ea),
                "name": name or "",
                "size": fn.end_ea - fn.start_ea if fn else 0,
            })
        total += 1

    return json.dumps({"data": funcs, "total": total, "offset": offset, "count": len(funcs)}, indent=2)


@tool
@idasync
def func_count() -> str:
    """Get the total number of functions in the binary."""
    ida_auto.auto_wait()
    total = len(list(idautils.Functions()))
    return json.dumps({"count": total})


# ===========================================================================
# Tools — Function Metadata
# ===========================================================================


def _get_function_bounds_impl(address: str) -> str:
    """Plain (non-synced) bounds logic — shared by bounds/size/end tools.

    Calling the ``get_function_bounds`` tool from inside another ``@idasync``
    body would nest ``execute_sync`` (guarded by ``call_stack``), so the
    sibling tools call this impl directly.
    """
    try:
        ea = parse_addr(address)
    except ValueError as e:
        return json.dumps({"error": str(e)})

    func = ida_funcs.get_func(ea)
    if not func:
        return json.dumps({"error": f"No function at {address}"})

    return json.dumps({
        "name": ida_funcs.get_func_name(func.start_ea) or "",
        "start_ea": hex(func.start_ea),
        "end_ea": hex(func.end_ea),
        "size": func.end_ea - func.start_ea,
    }, indent=2)


@tool
@idasync
def get_function_bounds(address: str) -> str:
    """Get function start/end addresses and size.

    Returns JSON with ``start_ea``, ``end_ea``, and ``size``.
    """
    ida_auto.auto_wait()
    return _get_function_bounds_impl(address)


def _get_function_signature_impl(address: str) -> str:
    """Plain (non-synced) signature logic — shared with get_function_type."""
    try:
        ea = parse_addr(address)
    except ValueError as e:
        return json.dumps({"error": str(e)})

    func = ida_funcs.get_func(ea)
    if not func:
        return json.dumps({"error": f"No function at {address}"})

    tif = ida_typeinf.tinfo_t()
    if not ida_nalt.get_tinfo(tif, func.start_ea):
        return json.dumps({
            "name": ida_funcs.get_func_name(func.start_ea) or "",
            "signature": None,
            "error": "No type information available",
        })

    if not tif.is_func():
        return json.dumps({"name": ida_funcs.get_func_name(func.start_ea) or "", "signature": None})

    ftd = ida_typeinf.func_type_data_t()
    if not tif.get_func_details(ftd):
        return json.dumps({"error": "Could not get function details"})

    fn_name = ida_funcs.get_func_name(func.start_ea) or "<unnamed>"
    prototype = str(ftd.rettype) + " " + fn_name + "("
    args = []
    for a in ftd:
        args.append(f"{a.type} {a.name if a.name else ''}")
    prototype += ", ".join(args) + ")"
    cc_str = ida_typeinf.get_cc_name(ftd.cc)

    return json.dumps({
        "name": fn_name,
        "signature": prototype,
        "calling_convention": cc_str,
        "return_type": str(ftd.rettype),
        "arguments": [{"name": a.name, "type": str(a.type)} for a in ftd],
    }, indent=2)


@tool
@idasync
def get_function_signature(address: str) -> str:
    """Get the C function signature/prototype (e.g., 'int __cdecl main(int argc, char **argv)').

    Returns the signature string if type info is available.
    """
    ida_auto.auto_wait()
    return _get_function_signature_impl(address)


def _get_function_flags_impl(address: str) -> str:
    """Plain (non-synced) flags logic — shared with thunk/library/noreturn."""
    try:
        ea = parse_addr(address)
    except ValueError as e:
        return json.dumps({"error": str(e)})

    func = ida_funcs.get_func(ea)
    if not func:
        return json.dumps({"error": f"No function at {address}"})

    flags = func.flags
    return json.dumps({
        "name": ida_funcs.get_func_name(func.start_ea) or "",
        "is_thunk": bool(flags & ida_funcs.FUNC_THUNK),
        "is_library": bool(flags & ida_funcs.FUNC_LIB),
        "is_noreturn": bool(flags & ida_funcs.FUNC_NORET),
        "is_far": bool(flags & ida_funcs.FUNC_FAR),
        "is_static": bool(flags & ida_funcs.FUNC_STATIC),
        "is_frame_pointer": bool(flags & ida_funcs.FUNC_FRAME),
        "is_bp_frame": bool(flags & ida_funcs.FUNC_BOTTOMBP),
        "is_hidden": bool(flags & ida_funcs.FUNC_HIDDEN),
        "is_tail": bool(flags & ida_funcs.FUNC_TAIL),
        "flags_raw": flags,
    }, indent=2)


@tool
@idasync
def get_function_flags(address: str) -> str:
    """Get function flags (thunk, library, noreturn, far, static, etc.)."""
    ida_auto.auto_wait()
    return _get_function_flags_impl(address)


@tool
@idasync
def get_function_comment(address: str) -> str:
    """Get the comment on a function."""
    ida_auto.auto_wait()
    try:
        ea = parse_addr(address)
    except ValueError as e:
        return json.dumps({"error": str(e)})

    func = ida_funcs.get_func(ea)
    if not func:
        return json.dumps({"error": f"No function at {address}"})

    comment = ida_funcs.get_func_cmt(func, True)
    return json.dumps({
        "name": ida_funcs.get_func_name(func.start_ea) or "",
        "comment": comment if comment else None,
    })


@tool
@idasync
def get_function_type(address: str) -> str:
    """Get the function type/prototype (alias for get_function_signature)."""
    return _get_function_signature_impl(address)


@tool
@idasync
def get_function_size(address: str) -> str:
    """Get the size of a function in bytes."""
    result = _get_function_bounds_impl(address)
    data = json.loads(result)
    if "error" in data:
        return result
    return json.dumps({"name": data.get("name"), "size": data.get("size")})


@tool
@idasync
def get_function_start(address: str) -> str:
    """Get the start address of the function containing the given address."""
    ida_auto.auto_wait()
    try:
        ea = parse_addr(address)
    except ValueError as e:
        return json.dumps({"error": str(e)})

    func = ida_funcs.get_func(ea)
    if not func:
        return json.dumps({"error": f"No function containing {hex(ea)}"})

    return json.dumps({
        "query": hex(ea),
        "name": ida_funcs.get_func_name(func.start_ea) or "",
        "start_ea": hex(func.start_ea),
    })


@tool
@idasync
def get_function_end(address: str) -> str:
    """Get the end address of the function containing the given address."""
    result = _get_function_bounds_impl(address)
    data = json.loads(result)
    if "error" in data:
        return result
    return json.dumps({"name": data.get("name"), "end_ea": data.get("end_ea")})


# ===========================================================================
# Tools — Function Predicates
# ===========================================================================


@tool
@idasync
def is_function_thunk(address: str) -> str:
    """Check if a function is a thunk function."""
    result = _get_function_flags_impl(address)
    data = json.loads(result)
    if "error" in data:
        return result
    return json.dumps({"is_thunk": data.get("is_thunk", False)})


@tool
@idasync
def is_function_library(address: str) -> str:
    """Check if a function is a library function."""
    result = _get_function_flags_impl(address)
    data = json.loads(result)
    if "error" in data:
        return result
    return json.dumps({"is_library": data.get("is_library", False)})


@tool
@idasync
def is_function_noreturn(address: str) -> str:
    """Check if a function does not return."""
    result = _get_function_flags_impl(address)
    data = json.loads(result)
    if "error" in data:
        return result
    return json.dumps({"is_noreturn": data.get("is_noreturn", False)})


# ===========================================================================
# Tools — Stack Frame
# ===========================================================================


@tool
@idasync
def get_function_frame_size(address: str) -> str:
    """Get the stack frame size of a function."""
    ida_auto.auto_wait()
    try:
        ea = parse_addr(address)
    except ValueError as e:
        return json.dumps({"error": str(e)})

    func = ida_funcs.get_func(ea)
    if not func:
        return json.dumps({"error": f"No function at {address}"})

    frame = ida_frame.get_frame(func)
    if not frame:
        return json.dumps({"error": "No frame for function"})

    return json.dumps({
        "name": ida_funcs.get_func_name(func.start_ea) or "",
        "frame_size": frame.get_frame_size(),
        "args_size": frame.get_args_size(),
        "saved_regs_size": frame.get_saved_regs_size(),
    }, indent=2)


@tool
@idasync
def get_function_args_size(address: str) -> str:
    """Get the arguments size of a function's stack frame."""
    ida_auto.auto_wait()
    try:
        ea = parse_addr(address)
    except ValueError as e:
        return json.dumps({"error": str(e)})

    func = ida_funcs.get_func(ea)
    if not func:
        return json.dumps({"error": f"No function at {address}"})

    frame = ida_frame.get_frame(func)
    if not frame:
        return json.dumps({"error": "No frame for function"})

    return json.dumps({
        "name": ida_funcs.get_func_name(func.start_ea) or "",
        "args_size": frame.get_args_size(),
    })


def _collect_frame_vars(func) -> list[dict]:
    """Collect stack frame variables for ``func`` as plain dicts.

    Shared by ``get_local_variables`` and ``api_query`` local-variable tools.
    Returns [] when the function has no frame.
    """
    frame = ida_frame.get_frame(func)
    if not frame:
        return []

    variables: list[dict] = []
    for i in range(frame.get_member_qty()):
        member = frame.get_member(i)
        if not member:
            continue
        name = ida_frame.get_member_name(member.id) or ""
        soff = member.soff
        size = member.get_size()
        var_type = "local"
        if soff > 0:
            var_type = "argument"

        tif = ida_typeinf.tinfo_t()
        type_name = None
        if ida_frame.get_member_type(member.id, tif):
            type_name = tif.get_type_name() or None

        variables.append({
            "name": name,
            "offset": soff,
            "size": size,
            "type": var_type,
            "type_info": type_name,
        })
    return variables


@tool
@idasync
def get_local_variables(address: str) -> str:
    """Get local variables (stack and register) for a function.

    Returns names, types, offsets, and sizes.
    """
    ida_auto.auto_wait()
    try:
        ea = parse_addr(address)
    except ValueError as e:
        return json.dumps({"error": str(e)})

    func = ida_funcs.get_func(ea)
    if not func:
        return json.dumps({"error": f"No function at {address}"})

    variables = _collect_frame_vars(func)
    if not variables and ida_frame.get_frame(func) is None:
        return json.dumps({"vars": [], "message": "No frame for function"})

    return json.dumps({
        "name": ida_funcs.get_func_name(func.start_ea) or "",
        "vars": variables,
        "count": len(variables),
    }, indent=2)


@tool
@idasync
def get_register_variables(address: str) -> str:
    """Get register variables (regvars) for a function."""
    ida_auto.auto_wait()
    try:
        ea = parse_addr(address)
    except ValueError as e:
        return json.dumps({"error": str(e)})

    func = ida_funcs.get_func(ea)
    if not func:
        return json.dumps({"error": f"No function at {address}"})

    frame = ida_frame.get_frame(func)
    if not frame:
        return json.dumps({"regvars": [], "message": "No frame for function"})

    regvars: list[dict] = []
    for i in range(frame.get_member_qty()):
        member = frame.get_member(i)
        if not member:
            continue
        # Regvars have flag bit 0x100 (FF_IVL)
        if member.flag & 0x100:
            name = ida_frame.get_member_name(member.id) or ""
            soff = member.soff
            size = member.get_size()
            regvars.append({
                "name": name,
                "offset": soff,
                "size": size,
            })

    return json.dumps({
        "name": ida_funcs.get_func_name(func.start_ea) or "",
        "regvars": regvars,
        "count": len(regvars),
    }, indent=2)


# ===========================================================================
# Tools — Complexity & Flow
# ===========================================================================


@tool
@idasync
def get_function_edges(address: str) -> str:
    """Get basic block count, edge count, and cyclomatic complexity for a function."""
    ida_auto.auto_wait()
    try:
        ea = parse_addr(address)
    except ValueError as e:
        return json.dumps({"error": str(e)})

    func = ida_funcs.get_func(ea)
    if not func:
        return json.dumps({"error": f"No function at {address}"})

    flow = ida_gdl.qflow_chart_t()
    flow.create("flowchart", func, func.start_ea, func.end_ea, 0)
    nodes = flow.size()
    edges = 0
    for i in range(nodes):
        edges += flow.nsucc(i)

    return json.dumps({
        "name": ida_funcs.get_func_name(func.start_ea) or "",
        "nodes": nodes,
        "edges": edges,
        "cyclomatic_complexity": edges - nodes + 2,
    }, indent=2)


@tool
@idasync
def get_function_instructions_count(address: str) -> str:
    """Get the number of instructions in a function."""
    ida_auto.auto_wait()
    try:
        ea = parse_addr(address)
    except ValueError as e:
        return json.dumps({"error": str(e)})

    func = ida_funcs.get_func(ea)
    if not func:
        return json.dumps({"error": f"No function at {address}"})

    count = len(list(idautils.FuncItems(func.start_ea)))
    return json.dumps({"name": ida_funcs.get_func_name(func.start_ea) or "", "instruction_count": count})


# ===========================================================================
# Tools — Range & Navigation
# ===========================================================================


@tool
@idasync
def get_functions_in_range(
    start: str,
    end: str,
) -> str:
    """Get all functions in an address range.

    ``start`` and ``end`` can be hex addresses or symbol names.
    """
    ida_auto.auto_wait()
    try:
        start_ea = parse_addr(start)
        end_ea = parse_addr(end)
    except ValueError as e:
        return json.dumps({"error": str(e)})

    funcs: list[dict] = []
    for ea in idautils.Functions(start_ea, end_ea):
        name = ida_funcs.get_func_name(ea)
        fn = ida_funcs.get_func(ea)
        funcs.append({
            "addr": hex(ea),
            "name": name or "",
            "size": fn.end_ea - fn.start_ea if fn else 0,
        })

    return json.dumps({"functions": funcs, "count": len(funcs)}, indent=2)


@tool
@idasync
def get_next_function(address: str) -> str:
    """Get the next function after the given address."""
    ida_auto.auto_wait()
    try:
        ea = parse_addr(address)
    except ValueError as e:
        return json.dumps({"error": str(e)})

    # Find the next function whose start_ea > ea
    for func_ea in idautils.Functions():
        if func_ea > ea:
            name = ida_funcs.get_func_name(func_ea)
            fn = ida_funcs.get_func(func_ea)
            return json.dumps({
                "addr": hex(func_ea),
                "name": name or "",
                "size": fn.end_ea - fn.start_ea if fn else 0,
            }, indent=2)

    return json.dumps({"message": "No next function found"})


# ===========================================================================
# Tools — Modification (unsafe)
# ===========================================================================


@tool
@idasync
@unsafe
def create_function(
    address: str,
) -> str:
    """Create/define a function at the given address. IDA infers bounds.

    **Unsafe** — requires ``?unsafe=true``.
    """
    ida_auto.auto_wait()
    try:
        ea = parse_addr(address)
    except ValueError as e:
        return json.dumps({"error": str(e)})

    if ida_funcs.add_func(ea):
        func = ida_funcs.get_func(ea)
        name = ida_funcs.get_func_name(func.start_ea) if func else ""
        return json.dumps({"ok": True, "addr": hex(ea), "name": name}, indent=2)
    else:
        return json.dumps({"ok": False, "error": f"Failed to create function at {hex(ea)}"})


@tool
@idasync
@unsafe
def delete_function(
    address: str,
) -> str:
    """Delete/undefine a function at the given address.

    **Unsafe** — requires ``?unsafe=true``.
    """
    ida_auto.auto_wait()
    try:
        ea = parse_addr(address)
    except ValueError as e:
        return json.dumps({"error": str(e)})

    func = ida_funcs.get_func(ea)
    if not func:
        return json.dumps({"error": f"No function at {address}"})

    if ida_funcs.del_func(func.start_ea):
        return json.dumps({"ok": True, "addr": hex(func.start_ea)}, indent=2)
    else:
        return json.dumps({"ok": False, "error": "Failed to delete function"})


@tool
@idasync
@unsafe
def set_function_name(
    address: str,
    name: str,
) -> str:
    """Rename a function.

    **Unsafe** — requires ``?unsafe=true``.
    """
    ida_auto.auto_wait()
    try:
        ea = parse_addr(address)
    except ValueError as e:
        return json.dumps({"error": str(e)})

    func = ida_funcs.get_func(ea)
    if not func:
        return json.dumps({"error": f"No function at {address}"})

    old_name = ida_funcs.get_func_name(func.start_ea)
    if ida_name.set_name(func.start_ea, name, ida_name.SN_NOWARN):
        return json.dumps({
            "addr": hex(func.start_ea),
            "old_name": old_name,
            "new_name": name,
        }, indent=2)
    else:
        return json.dumps({"error": f"Failed to rename function at {hex(func.start_ea)}"})


@tool
@idasync
@unsafe
def set_function_comment(
    address: str,
    comment: str,
) -> str:
    """Set a comment on a function.

    **Unsafe** — requires ``?unsafe=true``.
    """
    ida_auto.auto_wait()
    try:
        ea = parse_addr(address)
    except ValueError as e:
        return json.dumps({"error": str(e)})

    func = ida_funcs.get_func(ea)
    if not func:
        return json.dumps({"error": f"No function at {address}"})

    ida_funcs.set_func_cmt(func, comment, True)
    return json.dumps({"addr": hex(func.start_ea), "comment_set": True}, indent=2)
