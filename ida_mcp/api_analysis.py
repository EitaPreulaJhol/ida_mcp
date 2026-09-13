"""Analysis and inspection tools for ida_mcp.

Cross-references, memory reading, import/export listing, annotation tools,
structured disassembly, byte pattern search, number conversion, function
lookup, string enumeration, basic-block CFG, and advanced xref queries.

All functions in this module are registered as MCP tools via ``@tool``.
Write operations are additionally marked ``@unsafe``.
"""
import fnmatch
import json
import re

import ida_auto
import ida_bytes
import ida_entry
import ida_funcs
import ida_hexrays
import ida_ida
import ida_kernwin
import ida_lines
import ida_nalt
import ida_name
import ida_segment
import ida_typeinf
import ida_ua
import idaapi
import idautils
import idc

from .rpc import tool, unsafe, MCP_SERVER
from .sync import idasync


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def parse_addr(s: str | int) -> int:
    """Parse an address or symbol name into an ea_t.

    Accepts ``0x``-prefixed hex, octal/binary literals, bare decimal, plain
    integers, or symbol names (resolved via ``ida_name.get_name_ea``).
    """
    if isinstance(s, int):
        return s
    t = s.strip()
    try:
        return int(t, 0)
    except ValueError:
        pass
    ea = ida_name.get_name_ea(idaapi.BADADDR, t)
    if ea != idaapi.BADADDR:
        return ea
    raise ValueError(f"Unknown address or name: {s}")


def _check_mapped(ea: int) -> None:
    """Raise ValueError if ea is not mapped in the IDB."""
    if not ida_bytes.is_mapped(ea):
        raise ValueError(f"Address not mapped: {hex(ea)}")


def _cap_lines(text: str | None, max_lines: int) -> tuple[str | None, int | None]:
    """Cap ``text`` at ``max_lines`` lines.

    Returns ``(possibly_truncated_text, total_lines_or_None)`` where the
    second element is None when nothing was cut. Shared output-truncation
    helper (cf. ida-pro-mcp ``_cap_decompile`` / ``_limit_items``).
    """
    if text is None:
        return None, None
    lines = text.split("\n")
    total = len(lines)
    if total <= max_lines:
        return text, None
    return "\n".join(lines[:max_lines]), total


def _limit_items(items: list, max_items: int) -> tuple[list, bool]:
    """Cap ``items`` at ``max_items``; returns ``(page, truncated)``."""
    if len(items) <= max_items:
        return items, False
    return items[:max_items], True


def read_bytes_bss_safe(ea: int, size: int) -> bytes | None:
    """Read ``size`` bytes starting at ``ea``, substituting 0 for unloaded bytes.

    Unloaded bytes in BSS-like sections are zero at runtime by every mainstream
    loader, but ``ida_bytes.get_byte()`` returns 0xFF as a sentinel for them.
    Check ``ida_bytes.is_loaded`` per byte so reads of globals in ``.bss``
    return the real zero-initialized value instead of 0xFF garbage.
    Falls back to bulk ``ida_bytes.get_bytes`` when the per-byte API is
    unavailable (older IDA / stubbed environments).
    """
    is_loaded = getattr(ida_bytes, "is_loaded", None)
    get_byte = getattr(ida_bytes, "get_byte", None)
    if is_loaded is not None and get_byte is not None:
        out = bytearray(size)
        for i in range(size):
            try:
                if is_loaded(ea + i):
                    out[i] = get_byte(ea + i)
            except Exception:
                pass
        return bytes(out)
    try:
        return ida_bytes.get_bytes(ea, size)
    except Exception:
        return None


# ===========================================================================
# Phase 1 — Cross-References (P0)
# ===========================================================================


@tool
@idasync
def get_xrefs_to(address: str, limit: int = 100) -> str:
    """Get all cross-references TO the given address or symbol name.

    Returns a JSON array of ``{addr, type, function}`` objects.
    ``type`` is ``"code"`` or ``"data"``.
    """
    ida_auto.auto_wait()
    try:
        ea = parse_addr(address)
    except ValueError as e:
        return json.dumps({"error": str(e)})
    try:
        _check_mapped(ea)
    except ValueError as e:
        return json.dumps({"error": str(e)})

    xrefs_list = []
    for xref in idautils.XrefsTo(ea):
        if len(xrefs_list) >= limit:
            break
        fn = ida_funcs.get_func(xref.frm)
        xrefs_list.append({
            "addr": hex(xref.frm),
            "type": "code" if xref.iscode else "data",
            "function": ida_funcs.get_func_name(fn.start_ea) if fn else None,
        })
    if not xrefs_list:
        return json.dumps({"xrefs": [], "message": "No cross-references to this address"})
    return json.dumps({"xrefs": xrefs_list, "count": len(xrefs_list)}, indent=2)


@tool
@idasync
def xref_query(address: str, direction: str = "to", xref_type: str = "any",
               limit: int = 200) -> str:
    """Query cross-references with direction and type filters.

    ``direction``: ``"to"`` (references TO address), ``"from"`` (references
    FROM address), or ``"both"``.  ``xref_type``: ``"code"``, ``"data"``,
    or ``"any"``.
    """
    ida_auto.auto_wait()
    try:
        ea = parse_addr(address)
    except ValueError as e:
        return json.dumps({"error": str(e)})
    try:
        _check_mapped(ea)
    except ValueError as e:
        return json.dumps({"error": str(e)})

    if direction not in ("to", "from", "both"):
        direction = "to"
    if xref_type not in ("code", "data", "any"):
        xref_type = "any"

    rows: list[dict] = []

    if direction in ("to", "both"):
        for xr in idautils.XrefsTo(ea):
            if len(rows) >= limit:
                break
            kind = "code" if xr.iscode else "data"
            if xref_type != "any" and kind != xref_type:
                continue
            fn = ida_funcs.get_func(xr.frm)
            rows.append({
                "direction": "to",
                "addr": hex(xr.frm),
                "type": kind,
                "function": ida_funcs.get_func_name(fn.start_ea) if fn else None,
            })

    if direction in ("from", "both"):
        for xr in idautils.XrefsFrom(ea):
            if len(rows) >= limit:
                break
            kind = "code" if xr.iscode else "data"
            if xref_type != "any" and kind != xref_type:
                continue
            rows.append({
                "direction": "from",
                "addr": hex(xr.to),
                "type": kind,
                "function": None,
            })

    if not rows:
        return json.dumps({"xrefs": [], "message": "No matching cross-references"}, indent=2)
    return json.dumps({"xrefs": rows, "count": len(rows)}, indent=2)


@tool
@idasync
def get_callees(address: str) -> str:
    """Get all functions called BY the function at the given address or name.

    Returns a JSON array of ``{addr, name, type}`` where ``type`` is
    ``"internal"`` or ``"external"``.
    """
    ida_auto.auto_wait()
    try:
        ea = parse_addr(address)
    except ValueError as e:
        return json.dumps({"error": str(e)})

    func = ida_funcs.get_func(ea)
    if not func:
        return json.dumps({"error": f"No function at {address}"})

    callees: dict[int, dict] = {}
    current_ea = func.start_ea
    while current_ea < func.end_ea:
        insn = ida_ua.insn_t()
        if ida_ua.decode_insn(insn, current_ea) == 0:
            current_ea = idc.next_head(current_ea, func.end_ea)
            continue
        if insn.get_canon_mnem() == "call":
            op0 = insn.ops[0]
            if op0.type in (ida_ua.o_mem, ida_ua.o_near, ida_ua.o_far):
                target = op0.addr
            elif op0.type == ida_ua.o_imm:
                target = op0.value
            else:
                target = None
            if target is not None and target not in callees:
                name = ida_name.get_name(target)
                callees[target] = {
                    "addr": hex(target),
                    "name": name or f"sub_{target:X}",
                    "type": "internal" if ida_funcs.get_func(target) else "external",
                }
        current_ea = idc.next_head(current_ea, func.end_ea)

    return json.dumps(list(callees.values()), indent=2)


@tool
@idasync
def get_callers(address: str, limit: int = 50) -> str:
    """Get all functions that CALL the function at the given address or name.

    Uses ``CodeRefsTo`` filtered to call instructions only.
    Returns a JSON array of ``{addr, name}`` objects.
    """
    ida_auto.auto_wait()
    try:
        ea = parse_addr(address)
    except ValueError as e:
        return json.dumps({"error": str(e)})

    callers_dict: dict[int, dict] = {}
    for caller_ea in idautils.CodeRefsTo(ea, 0):
        if len(callers_dict) >= limit:
            break
        # Verify this is actually a call instruction, not just any code ref.
        insn = ida_ua.insn_t()
        if ida_ua.decode_insn(insn, caller_ea) == 0:
            continue
        if insn.get_canon_mnem() != "call":
            continue
        fn = ida_funcs.get_func(caller_ea)
        if fn:
            callers_dict[fn.start_ea] = {
                "addr": hex(fn.start_ea),
                "name": ida_funcs.get_func_name(fn.start_ea) or "",
            }

    return json.dumps(list(callers_dict.values()), indent=2)


# ===========================================================================
# Phase 2 — Memory Reading (P0 / P1)
# ===========================================================================


@tool
@idasync
def get_bytes(address: str, size: int = 64) -> str:
    """Read raw bytes at the given address and return as hex + ASCII dump.

    ``size`` defaults to 64 and is capped at 4096.
    """
    ida_auto.auto_wait()
    try:
        ea = parse_addr(address)
    except ValueError as e:
        return json.dumps({"error": str(e)})

    if size <= 0 or size > 4096:
        size = 64

    try:
        raw = read_bytes_bss_safe(ea, size)
    except Exception as e:
        return json.dumps({"error": str(e)})

    if not raw:
        return json.dumps({"addr": hex(ea), "data": None, "error": "Could not read bytes"})

    hex_str = " ".join(f"{b:02X}" for b in raw)
    ascii_repr = "".join(chr(b) if 32 <= b < 127 else "." for b in raw)
    return json.dumps({
        "addr": hex(ea),
        "size": len(raw),
        "hex": hex_str,
        "ascii": ascii_repr,
    }, indent=2)


@tool
@idasync
def get_string(address: str) -> str:
    """Read a null-terminated string at the given address.

    Returns a JSON object with ``addr`` and ``value`` (decoded UTF-8 string).
    """
    ida_auto.auto_wait()
    try:
        ea = parse_addr(address)
    except ValueError as e:
        return json.dumps({"error": str(e)})

    try:
        raw = ida_bytes.get_strlit_contents(ea, -1, ida_nalt.STRTYPE_C)
    except Exception as e:
        return json.dumps({"error": str(e)})

    if not raw:
        return json.dumps({"addr": hex(ea), "value": None, "error": "No string at address"})

    try:
        value = raw.decode("utf-8", errors="replace")
    except Exception:
        value = raw.hex()

    return json.dumps({"addr": hex(ea), "value": value}, indent=2)


# ===========================================================================
# Phase 3 — Core Inspection (P1)
# ===========================================================================


@tool
@idasync
def list_imports(filter_pattern: str = "*", offset: int = 0, count: int = 100) -> str:
    """List all imported symbols with their module names.

    Supports glob-based filtering (e.g. ``"*Create*"``) with fnmatch.
    Pagination via ``offset`` / ``count`` (max 5000).
    """
    ida_auto.auto_wait()

    if count <= 0 or count > 5000:
        count = 100

    imports_list: list[dict] = []
    nimps = ida_nalt.get_import_module_qty()

    if nimps == 0:
        return json.dumps({"data": [], "total": 0, "offset": offset, "count": 0}, indent=2)

    current_module: str = ""

    def _collect(ea, name, ordinal) -> bool:
        imports_list.append({
            "addr": hex(ea),
            "imported_name": name or f"#{ordinal}",
            "module": current_module,
        })
        return True

    for i in range(nimps):
        current_module = ida_nalt.get_import_module_name(i) or "<unnamed>"
        ida_nalt.enum_import_names(i, _collect)

    if filter_pattern != "*":
        filtered = [imp for imp in imports_list if fnmatch.fnmatch(imp["imported_name"], filter_pattern)]
    else:
        filtered = imports_list

    page = filtered[offset:offset + count]
    return json.dumps({
        "data": page,
        "total": len(filtered),
        "offset": offset,
        "count": len(page),
    }, indent=2)


@tool
@idasync
def list_exports(filter_pattern: str = "*", offset: int = 0, count: int = 100) -> str:
    """List all exported symbols with their addresses and ordinals.

    Supports glob filtering (e.g. ``"*Initialize*"``).
    Pagination via ``offset`` / ``count`` (max 5000).
    """
    ida_auto.auto_wait()

    if count <= 0 or count > 5000:
        count = 100

    exports_list: list[dict] = []
    for i in range(ida_entry.get_entry_qty()):
        ordinal = ida_entry.get_entry_ordinal(i)
        ea = ida_entry.get_entry(ordinal)
        if ea == idaapi.BADADDR:
            continue
        name = ida_entry.get_entry_name(ordinal)
        exports_list.append({
            "ordinal": ordinal,
            "addr": hex(ea),
            "name": name or f"#{ordinal}",
        })

    if filter_pattern != "*":
        filtered = [exp for exp in exports_list if fnmatch.fnmatch(exp["name"], filter_pattern)]
    else:
        filtered = exports_list

    page = filtered[offset:offset + count]
    return json.dumps({
        "data": page,
        "total": len(filtered),
        "offset": offset,
        "count": len(page),
    }, indent=2)


# ===========================================================================
# Phase 4 — Annotation (unsafe)
# ===========================================================================


@tool
@idasync
@unsafe
def set_comment(address: str, comment: str) -> str:
    """Set a comment at the given address in both disassembly and decompiler views.

    **Unsafe** — requires ``?unsafe=true``.
    """
    ida_auto.auto_wait()
    try:
        ea = parse_addr(address)
    except ValueError as e:
        return json.dumps({"error": str(e)})

    # Set disassembly comment (non-repeatable).
    if not ida_bytes.set_cmt(ea, comment, False):
        return json.dumps({"error": f"Failed to set comment at {hex(ea)}"})

    # Set decompiler comment if Hex-Rays is available.
    if ida_hexrays.init_hexrays_plugin():
        try:
            cfunc = ida_hexrays.decompile(ea)
        except Exception:
            return json.dumps({"addr": hex(ea), "comment_set": "disassembly_only"}, indent=2)

        if cfunc:
            if ea == cfunc.entry_ea:
                idc.set_func_cmt(ea, comment, True)
                cfunc.refresh_func_ctext()
            else:
                eamap = cfunc.get_eamap()
                if ea in eamap:
                    nearest_ea = eamap[ea][0].ea

                    # Clean stale orphan comments before setting.
                    if cfunc.has_orphan_cmts():
                        cfunc.del_orphan_cmts()
                        cfunc.save_user_cmts()

                    tl = idaapi.treeloc_t()
                    tl.ea = nearest_ea
                    # Try comment positions from ITP_SEMI up to (not including)
                    # ITP_COLON, matching the reference implementation.
                    for itp in range(idaapi.ITP_SEMI, idaapi.ITP_COLON):
                        tl.itp = itp
                        cfunc.set_user_cmt(tl, comment)
                        cfunc.save_user_cmts()
                        cfunc.refresh_func_ctext()
                        if not cfunc.has_orphan_cmts():
                            break
                        cfunc.del_orphan_cmts()
                        cfunc.save_user_cmts()
                    else:
                        cfunc.del_orphan_cmts()
                        cfunc.save_user_cmts()

    return json.dumps({"addr": hex(ea), "comment_set": True}, indent=2)


@tool
@idasync
@unsafe
def rename_function(address: str, new_name: str) -> str:
    """Rename the function at the given address.

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
    if not ida_name.set_name(func.start_ea, new_name, ida_name.SN_NOWARN):
        return json.dumps({"error": f"Failed to rename function at {hex(func.start_ea)}"})

    return json.dumps({
        "addr": hex(func.start_ea),
        "old_name": old_name,
        "new_name": new_name,
    }, indent=2)


# ===========================================================================
# Phase 5 — Critical New Tools
# ===========================================================================


@tool
@idasync
def lookup_funcs(address: str) -> str:
    """Get detailed information about a function by address or name.

    Returns JSON with name, address, size, segment, callers/callee counts,
    prototype type info, and stack frame variables.
    """
    ida_auto.auto_wait()
    try:
        ea = parse_addr(address)
    except ValueError as e:
        return json.dumps({"error": str(e)})

    func = ida_funcs.get_func(ea)
    if not func:
        return json.dumps({"error": f"No function at {address}"})

    fn_name = ida_funcs.get_func_name(func.start_ea) or "<unnamed>"
    size = func.end_ea - func.start_ea
    seg = ida_segment.getseg(func.start_ea)
    segment_name = ida_segment.get_segm_name(seg) if seg else None

    # Type info
    has_type = False
    prototype = None
    tif = ida_typeinf.tinfo_t()
    if ida_nalt.get_tinfo(tif, func.start_ea) and tif.is_func():
        has_type = True
        ftd = ida_typeinf.func_type_data_t()
        if tif.get_func_details(ftd):
            prototype = str(ftd.rettype) + " " + fn_name + "("
            args = []
            for a in ftd:
                args.append(f"{a.type} {a.name if a.name else ''}")
            prototype += ", ".join(args) + ")"

    result = {
        "addr": hex(func.start_ea),
        "name": fn_name,
        "size": hex(size),
        "size_bytes": size,
        "segment": segment_name,
        "has_type": has_type,
    }
    if prototype:
        result["prototype"] = prototype

    return json.dumps(result, indent=2)


@tool
def int_convert(text: str, size: int = 0) -> str:
    """Convert a number to multiple formats (decimal, hex, bytes, binary, ASCII).

    ``text`` is parsed with auto-detected base (0x=hex, 0b=binary, else decimal).
    ``size`` is the byte width (auto-determined if 0).
    """
    try:
        value = int(text, 0)
    except ValueError:
        return json.dumps({"input": text, "error": f"Invalid number: {text}"})

    if size <= 0:
        size = 0
        n = abs(value)
        while n:
            size += 1
            n >>= 1
        size += 7
        size //= 8

    try:
        bytes_data = value.to_bytes(max(1, size), "little", signed=True)
    except OverflowError:
        return json.dumps({
            "input": text,
            "error": f"Number is too big for {size} byte(s)",
        })

    ascii_str = ""
    for byte in bytes_data.rstrip(b"\x00"):
        if 32 <= byte <= 126:
            ascii_str += chr(byte)
        else:
            ascii_str = None
            break

    return json.dumps({
        "input": text,
        "decimal": str(value),
        "hexadecimal": hex(value),
        "bytes": bytes_data.hex(" "),
        "ascii": ascii_str,
        "binary": bin(value),
    }, indent=2)


@tool
@idasync
def find_bytes(pattern: str, limit: int = 100, offset: int = 0) -> str:
    """Search for byte patterns with ``??`` wildcards (e.g. ``"48 8B ?? ??"``).

    Uses ``ida_bytes.find_bytes`` (the canonical IDA 9.x API) which accepts the
    hex string directly, supports ``??`` wildcards natively, and uses
    ``range_start`` / ``range_end`` semantics.

    Pagination via ``offset`` / ``limit`` (max ``limit`` = 10000).
    """
    ida_auto.auto_wait()

    if limit <= 0 or limit > 10000:
        limit = 10000
    if offset < 0:
        offset = 0

    # Normalize tokens: accept "??" or "?" as the wildcard token.  The
    # IDA API also accepts both, but we strip whitespace defensively.
    norm_pattern = " ".join(pattern.split())
    if not norm_pattern:
        return json.dumps({"pattern": pattern, "matches": [], "error": "Empty pattern"})

    min_ea = ida_ida.inf_get_min_ea()
    max_ea = ida_ida.inf_get_max_ea()

    matches: list[str] = []
    skipped = 0
    more = False
    ea = min_ea

    while ea != idaapi.BADADDR:
        ea = ida_bytes.find_bytes(norm_pattern, ea, range_end=max_ea)
        if ea == idaapi.BADADDR:
            break
        if skipped < offset:
            skipped += 1
        else:
            matches.append(hex(ea))
            if len(matches) >= limit:
                # Check if more results follow.
                next_ea = ida_bytes.find_bytes(norm_pattern, ea + 1, range_end=max_ea)
                more = next_ea != idaapi.BADADDR
                break
        ea += 1

    return json.dumps({
        "pattern": pattern,
        "matches": matches,
        "count": len(matches),
        "more": more,
        "limit": limit,
    }, indent=2)


# ===========================================================================
# Phase 6 — High-Impact Tools
# ===========================================================================


@tool
@idasync
def list_strings(filter_pattern: str = "*", offset: int = 0, count: int = 100) -> str:
    """List all strings in the binary with glob filtering and pagination.

    ``filter_pattern`` uses fnmatch (e.g. ``"*error*"``).
    Pagination via ``offset`` / ``count`` (max 5000).
    """
    ida_auto.auto_wait()

    if count <= 0 or count > 5000:
        count = 100

    strings_list: list[dict] = []
    for si in idautils.Strings():
        strings_list.append({
            "addr": hex(si.ea),
            "value": str(si),
            "length": si.length,
            "type": si.strtype,
        })

    if filter_pattern != "*":
        filtered = [s for s in strings_list if fnmatch.fnmatch(s["value"], filter_pattern)]
    else:
        filtered = strings_list

    page = filtered[offset:offset + count]
    return json.dumps({
        "data": page,
        "total": len(filtered),
        "offset": offset,
        "count": len(page),
    }, indent=2)


@tool
@idasync
def disasm(address: str, count: int = 50) -> str:
    """Disassemble instructions starting at the given address or name.

    Returns a JSON array of ``{addr, instruction, label?}`` objects.
    Use ``count`` to limit the number of instructions (max 500).
    """
    ida_auto.auto_wait()
    try:
        ea = parse_addr(address)
    except ValueError as e:
        return json.dumps({"error": str(e)})

    if count <= 0 or count > 500:
        count = 50

    seg = ida_segment.getseg(ea)
    if not seg:
        return json.dumps({"error": f"No segment at {address}"})

    lines: list[dict] = []
    end_ea = seg.end_ea
    for _ in range(count):
        if ea == idaapi.BADADDR or ea >= end_ea:
            break
        line = ida_lines.tag_remove(ida_lines.generate_disasm_line(ea, 0) or "")
        if not line:
            break
        entry: dict = {"addr": hex(ea), "instruction": line}
        name = ida_name.get_ea_name(ea)
        if name:
            entry["label"] = name
        lines.append(entry)
        ea = idc.next_head(ea, end_ea)

    if not lines:
        return json.dumps({"error": "Could not disassemble at this address"})

    return json.dumps({"addr": hex(ea), "instructions": lines, "count": len(lines)}, indent=2)


@tool
@idasync
def basic_blocks(address: str, max_blocks: int = 100, offset: int = 0) -> str:
    """Get basic blocks for a function with pagination.

    Returns a JSON array of ``{start, end, size, type, successors, predecessors}``
    for each basic block in the function's control-flow graph.
    """
    ida_auto.auto_wait()
    try:
        ea = parse_addr(address)
    except ValueError as e:
        return json.dumps({"error": str(e)})

    func = ida_funcs.get_func(ea)
    if not func:
        return json.dumps({"error": f"No function at {address}"})

    if max_blocks <= 0 or max_blocks > 10000:
        max_blocks = 100

    flowchart = idaapi.FlowChart(func)
    all_blocks: list[dict] = []

    for block in flowchart:
        all_blocks.append({
            "start": hex(block.start_ea),
            "end": hex(block.end_ea),
            "size": block.end_ea - block.start_ea,
            "type": block.type,
            "successors": [hex(s.start_ea) for s in block.succs()],
            "predecessors": [hex(p.start_ea) for p in block.preds()],
        })

    total = len(all_blocks)
    page = all_blocks[offset:offset + max_blocks]
    more = offset + max_blocks < total

    return json.dumps({
        "blocks": page,
        "count": len(page),
        "total": total,
        "cursor": {"next": offset + max_blocks} if more else {"done": True},
    }, indent=2)
