"""Modification tools — patch bytes, assemble instructions, define data items.

Tools ported from idamcp-extendedtools api_modify.py and api_patch.py,
adapted for direct in-process IDA SDK access.

All tools in this module are **unsafe** — they modify the IDA database.
"""

import json

import ida_auto
import ida_bytes
import ida_funcs
import ida_name
import ida_nalt
import ida_segment
import idaapi
import idc

from .rpc import tool, unsafe
from .sync import idasync
from .api_analysis import parse_addr


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
    ida_auto.auto_wait()
    try:
        ea = parse_addr(address)
    except ValueError as e:
        return json.dumps({"error": str(e)})

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

    create_fn, item_size = type_map[data_type]
    for _ in range(min(int(count), 1000)):
        create_fn(ea)
        sz = ida_bytes.get_item_size(ea)
        ea += sz if sz > 0 else item_size

    return json.dumps({"ok": True, "addr": address}, indent=2)


# ===========================================================================
# Tools — Patching
# ===========================================================================


@tool
@idasync
@unsafe
def patch_bytes(
    address: str,
    data: str,
) -> str:
    """Patch bytes at a memory address with hex data.

    ``data`` is a hex string, with or without spaces
    (e.g., ``"9090"`` or ``"90 90"``).

    **Unsafe** — requires ``?unsafe=true``.
    """
    ida_auto.auto_wait()
    try:
        ea = parse_addr(address)
    except ValueError as e:
        return json.dumps({"error": str(e)})

    data = data.replace(" ", "")
    try:
        raw = bytes.fromhex(data)
    except ValueError as e:
        return json.dumps({"error": f"Invalid hex data: {e}"})

    for i, b in enumerate(raw):
        ida_bytes.patch_byte(ea + i, b)

    size = len(raw)
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
    ida_auto.auto_wait()
    try:
        ea = parse_addr(address)
    except ValueError as e:
        return json.dumps({"error": str(e)})

    # Use idc.Assemble which returns the number of bytes assembled
    assembled_size = idc.Assemble(ea, 0, asm)
    if assembled_size == 0:
        return json.dumps({"error": f"Failed to assemble instruction: {asm}"})

    return json.dumps({
        "ok": True,
        "addr": hex(ea),
        "asm": asm,
        "size": assembled_size,
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
    ida_auto.auto_wait()
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
    ida_auto.auto_wait()
    try:
        ea = parse_addr(address)
    except ValueError as e:
        return json.dumps({"error": str(e)})

    import ida_name
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
    ida_auto.auto_wait()
    try:
        ea = parse_addr(address)
    except ValueError as e:
        return json.dumps({"error": str(e)})

    raw = ida_bytes.get_original_bytes(ea, size)
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
    ida_auto.auto_wait()
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
    ida_auto.auto_wait()
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
