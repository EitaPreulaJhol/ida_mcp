"""Modification tools — patch bytes, assemble instructions, define data items.

Tools ported from idamcp-extendedtools api_modify.py and api_patch.py,
adapted for direct in-process IDA SDK access.

All tools in this module are **unsafe** — they modify the IDA database.
"""

import json

import ida_bytes
import ida_name
import ida_nalt
import ida_segment
import idautils

from .rpc import tool, unsafe
from .sync import idasync
from .sync import ensure_analysis
from .sync import check_cancelled
from .api_analysis import parse_addr
# aliased: this module's own ``get_original_bytes`` tool would shadow it
from .compat import get_original_bytes as _compat_original_bytes


# ===========================================================================
# Tools — Data Definition
# ===========================================================================


@tool
@idasync
@unsafe
def make_data(
    address: str,
    data_type: str = "byte",
    count: int = 1,
) -> str:
    """Create a typed data item at the given address.

    ``data_type``: ``"byte"``, ``"word"``, ``"dword"``, ``"qword"``, ``"float"``,
    ``"double"``, or ``"string"``.
    ``count``: number of elements for arrays.

    **Unsafe** — requires ``?unsafe=true``.
    """
    ensure_analysis()
    try:
        ea = parse_addr(address)
    except ValueError as e:
        return json.dumps({"error": str(e)})

    if not ida_bytes.is_mapped(ea):
        return json.dumps({"error": f"Address not mapped: {hex(ea)}"})

    type_map = {
        "byte": (ida_bytes.create_byte, 1),
        "word": (ida_bytes.create_word, 2),
        "dword": (ida_bytes.create_dword, 4),
        "qword": (ida_bytes.create_qword, 8),
        "float": (ida_bytes.create_float, 4),
        "double": (ida_bytes.create_double, 8),
    }

    if data_type == "string":
        # Create a string type
        for _ in range(min(int(count), 1000)):
            if ida_bytes.get_byte(ea) == 0:
                ea += 1
                continue
            ida_bytes.create_strlit(ea, 0, ida_nalt.STRTYPE_C)
            ea += ida_bytes.get_item_size(ea) if ida_bytes.get_item_size(ea) > 0 else 1
        return json.dumps({"ok": True, "addr": hex(ea)}, indent=2)

    if data_type not in type_map:
        return json.dumps({"error": f"Unknown data type: {data_type}"})

    # ``create_byte(ea, length, force=False)`` (and friends) take the byte
    # count as a REQUIRED second argument in IDA 9.x: calling ``create_fn(ea)``
    # raised TypeError before the byte was ever created.
    create_fn, item_size = type_map[data_type]
    for _ in range(min(int(count), 1000)):
        check_cancelled()
        create_fn(ea, item_size)
        sz = ida_bytes.get_item_size(ea)
        ea += sz if sz > 0 else item_size

    return json.dumps({"ok": True, "addr": address}, indent=2)


# ===========================================================================
# Tools — Patching
# ===========================================================================

# Upper bound for a single patch_bytes call: the whole write runs on the IDA
# main thread, and a hex string arrives from a model (no natural limit).
_MAX_PATCH_BYTES = 64 * 1024


@tool
@idasync
@unsafe
def patch_bytes(
    address: str,
    data: str,
) -> str:
    """Patch bytes at a memory address with hex data.

    ``data`` is a hex string, with or without spaces
    (e.g., ``"9090"`` or ``"90 90"``). Capped at ``_MAX_PATCH_BYTES``.

    **Unsafe** — requires ``?unsafe=true``.
    """
    ensure_analysis()
    try:
        ea = parse_addr(address)
    except ValueError as e:
        return json.dumps({"error": str(e)})

    data = data.replace(" ", "")
    try:
        raw = bytes.fromhex(data)
    except ValueError as e:
        return json.dumps({"error": f"Invalid hex data: {e}"})

    size = len(raw)
    if size == 0:
        return json.dumps({"error": "Empty patch"})
    if size > _MAX_PATCH_BYTES:
        return json.dumps({"addr": hex(ea), "error":
                           f"Patch too large: {size} bytes (max {_MAX_PATCH_BYTES})"})
    if not ida_bytes.is_mapped(ea):
        return json.dumps({"error": f"Address not mapped: {hex(ea)}"})

    # One bulk write: the per-byte loop was O(n) Python calls on the main
    # thread for arbitrarily large input (patch_asm already did it this way).
    ida_bytes.patch_bytes(ea, raw)

    # Invalidate caches
    ida_bytes.del_items(ea, ida_bytes.DELIT_NOTRUNC, size)

    return json.dumps({
        "ok": True,
        "addr": hex(ea),
        "size": size,
        "patched_hex": data,
    }, indent=2)


@tool
@idasync
@unsafe
def patch_asm(
    address: str,
    asm: str,
) -> str:
    """Assemble and patch assembly instruction(s) at an address.

    ``asm``: assembly text (e.g., ``"nop; nop"`` or ``"mov eax, 1"``).

    **Unsafe** — requires ``?unsafe=true``.
    """
    ensure_analysis()
    try:
        ea = parse_addr(address)
    except ValueError as e:
        return json.dumps({"error": str(e)})

    # idautils.Assemble (IDA 9.x; idc.Assemble was removed) assembles to bytes
    # but does NOT write them, so patch the result ourselves. It returns
    # (False, errmsg) or (True, buf) or (True, [buf, ...]).
    ok, data = idautils.Assemble(ea, asm)
    if not ok:
        return json.dumps({"error": f"Failed to assemble instruction: {asm} ({data})"})
    blob = data if isinstance(data, (bytes, bytearray)) else b"".join(data)
    blob = bytes(blob)
    ida_bytes.patch_bytes(ea, blob)

    return json.dumps({
        "ok": True,
        "addr": hex(ea),
        "asm": asm,
        "size": len(blob),
    }, indent=2)


@tool
@idasync
@unsafe
def undefine(
    address: str,
) -> str:
    """Undefine the item at the given address, converting back to raw bytes.

    **Unsafe** — requires ``?unsafe=true``.
    """
    ensure_analysis()
    try:
        ea = parse_addr(address)
    except ValueError as e:
        return json.dumps({"error": str(e)})

    if not ida_bytes.is_mapped(ea):
        return json.dumps({"error": f"Address not mapped: {hex(ea)}"})

    if ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, 1):
        return json.dumps({"ok": True, "addr": hex(ea)}, indent=2)
    else:
        return json.dumps({"error": f"Failed to undefine at {hex(ea)}"})


# ===========================================================================
# Tools — Renaming (also available in api_names via rename_function)
# ===========================================================================


@tool
@idasync
@unsafe
def rename_address(
    address: str,
    name: str,
) -> str:
    """Set a name at the given address (non-function locations, data items, etc.).

    **Unsafe** — requires ``?unsafe=true``.
    """
    ensure_analysis()
    try:
        ea = parse_addr(address)
    except ValueError as e:
        return json.dumps({"error": str(e)})

    old_name = ida_name.get_ea_name(ea)
    if ida_name.set_name(ea, name, ida_name.SN_NOWARN):
        return json.dumps({
            "addr": hex(ea),
            "old_name": old_name or None,
            "new_name": name,
        }, indent=2)
    else:
        return json.dumps({"error": f"Failed to set name at {hex(ea)}"})


# ===========================================================================
# Tools — Patch Management
# ===========================================================================


@tool
@idasync
def get_original_bytes(
    address: str,
    size: int = 16,
) -> str:
    """Get the original bytes (before patching) at an address."""
    ensure_analysis()
    try:
        ea = parse_addr(address)
    except ValueError as e:
        return json.dumps({"error": str(e)})

    raw = _compat_original_bytes(ea, size)
    return json.dumps({
        "addr": hex(ea),
        "size": len(raw) if raw else 0,
        "hex": raw.hex() if raw else None,
    }, indent=2)


@tool
@idasync
@unsafe
def revert_patch(
    address: str,
) -> str:
    """Revert a patch at the given address, restoring the original byte.

    **Unsafe** — requires ``?unsafe=true``.
    """
    ensure_analysis()
    try:
        ea = parse_addr(address)
    except ValueError as e:
        return json.dumps({"error": str(e)})

    if not ida_bytes.is_mapped(ea):
        return json.dumps({"error": f"Address not mapped: {hex(ea)}"})

    orig = ida_bytes.get_original_byte(ea)
    ida_bytes.patch_byte(ea, orig)
    return json.dumps({
        "ok": True,
        "addr": hex(ea),
        "restored_byte": hex(orig),
    }, indent=2)


@tool
@idasync
def list_patches() -> str:
    """List all patches in the database (where current byte differs from original).

    Returns up to 1000 patches.
    """
    ensure_analysis()
    results: list[dict] = []

    for i in range(ida_segment.get_segm_qty()):
        seg = ida_segment.getnseg(i)
        if not seg:
            continue
        for ea in range(seg.start_ea, min(seg.end_ea, seg.start_ea + 100000)):
            try:
                orig = ida_bytes.get_original_byte(ea)
                curr = ida_bytes.get_byte(ea)
                if orig != curr:
                    results.append({
                        "addr": hex(ea),
                        "original": hex(orig),
                        "current": hex(curr),
                    })
                    if len(results) >= 1000:
                        break
            except Exception:
                continue
        if len(results) >= 1000:
            break

    return json.dumps({"patches": results, "count": len(results)}, indent=2)
