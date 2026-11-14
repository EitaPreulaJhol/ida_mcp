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
import ida_typeinf
import idautils

from .rpc import tool, unsafe
from .sync import idasync
from .sync import ensure_analysis
from .sync import check_cancelled, CancelledError, IDASyncError
from .api_analysis import _as_int, clamp_int, parse_addr
# aliased: this module's own ``get_original_bytes`` tool would shadow it
from .compat import del_name as _compat_del_name
from .compat import get_original_bytes as _compat_original_bytes


# ===========================================================================
# Batch annotations
# ===========================================================================

_MAX_BATCH_ITEMS = 1000


def _batch_apply_item(item: dict, dry_run: bool) -> dict:
    """Validate/apply one annotation item; returns a per-item result dict."""
    if not isinstance(item, dict):
        return {"ok": False, "error": "item must be a JSON object"}
    action = str(item.get("action", "")).strip().lower()
    address = item.get("address")
    if address is None:
        return {"ok": False, "action": action, "error": "missing 'address'"}
    try:
        ea = parse_addr(address)
    except ValueError as e:
        return {"ok": False, "action": action, "address": address,
                "error": str(e)}
    if not ida_bytes.is_mapped(ea):
        return {"ok": False, "action": action, "address": hex(ea),
                "error": f"Address not mapped: {hex(ea)}"}

    if action in ("rename", "set_name", "name"):
        name = item.get("name")
        if not isinstance(name, str) or not name.strip():
            return {"ok": False, "action": "rename", "address": hex(ea),
                    "error": "rename requires a non-empty 'name'"}
        old_name = ida_name.get_ea_name(ea)
        if dry_run:
            return {"ok": True, "action": "rename", "address": hex(ea),
                    "dry_run": True, "old_name": old_name or None,
                    "new_name": name}
        try:
            force = bool(item.get("force", False))
            setter = getattr(ida_name, "force_name", None) if force else None
            ok = (setter(ea, name) if callable(setter)
                  else ida_name.set_name(ea, name, ida_name.SN_NOWARN))
        except Exception as e:
            return {"ok": False, "action": "rename", "address": hex(ea),
                    "error": str(e)}
        if not ok:
            return {"ok": False, "action": "rename", "address": hex(ea),
                    "error": f"Failed to set name {name!r}"}
        return {"ok": True, "action": "rename", "address": hex(ea),
                "old_name": old_name or None, "new_name": name}

    if action in ("comment", "set_comment"):
        if "comment" not in item:
            return {"ok": False, "action": "comment", "address": hex(ea),
                    "error": "comment requires 'comment'"}
        comment = item.get("comment")
        if not isinstance(comment, str):
            return {"ok": False, "action": "comment", "address": hex(ea),
                    "error": "'comment' must be a string"}
        repeatable = bool(item.get("repeatable", False))
        if dry_run:
            return {"ok": True, "action": "comment", "address": hex(ea),
                    "dry_run": True, "comment": comment,
                    "repeatable": repeatable}
        try:
            ok = ida_bytes.set_cmt(ea, comment, repeatable)
        except Exception as e:
            return {"ok": False, "action": "comment", "address": hex(ea),
                    "error": str(e)}
        if not ok:
            return {"ok": False, "action": "comment", "address": hex(ea),
                    "error": "Failed to set comment"}
        return {"ok": True, "action": "comment", "address": hex(ea),
                "comment": comment, "repeatable": repeatable}

    if action in ("type", "set_type"):
        type_name = item.get("type")
        if not isinstance(type_name, str) or not type_name.strip():
            return {"ok": False, "action": "type", "address": hex(ea),
                    "error": "type requires a non-empty 'type'"}
        tif = ida_typeinf.tinfo_t()
        try:
            if not tif.get_named_type(ida_typeinf.get_idati(), type_name):
                return {"ok": False, "action": "type", "address": hex(ea),
                        "error": f"Type {type_name!r} not found"}
        except Exception as e:
            return {"ok": False, "action": "type", "address": hex(ea),
                    "error": str(e)}
        if dry_run:
            return {"ok": True, "action": "type", "address": hex(ea),
                    "dry_run": True, "type": type_name}
        try:
            ok = ida_typeinf.apply_tinfo(
                ea, tif, ida_typeinf.TINFO_DEFINITE)
        except Exception as e:
            return {"ok": False, "action": "type", "address": hex(ea),
                    "error": str(e)}
        if not ok:
            return {"ok": False, "action": "type", "address": hex(ea),
                    "error": f"Failed to apply type {type_name!r}"}
        return {"ok": True, "action": "type", "address": hex(ea),
                "type": type_name}

    return {"ok": False, "action": action, "address": hex(ea),
            "error": f"Unknown action {action!r} (rename/comment/type)"}


@tool
@idasync
@unsafe
def apply_annotations(
    items: str,
    dry_run: bool = False,
    stop_on_error: bool = False,
) -> str:
    """Apply rename/comment/type annotations as a batch.

    ``items`` is a JSON array of objects:
    ``{"action": "rename", "address": "0x401000", "name": "decrypt"}``,
    ``{"action": "comment", "address": "...", "comment": "...",
    "repeatable": false}``, or
    ``{"action": "type", "address": "...", "type": "struct name"}``.
    ``dry_run`` validates and reports without changing the IDB.
    ``stop_on_error`` stops at the first failed item; otherwise the rest are
    still attempted. At most 1000 items are accepted.

    **Unsafe** — requires ``?unsafe=true``.
    """
    ensure_analysis()
    try:
        parsed = json.loads(items) if isinstance(items, str) else items
    except (TypeError, ValueError) as e:
        return json.dumps({"error": f"Invalid items JSON: {e}"})
    if not isinstance(parsed, list):
        return json.dumps({"error": "items must be a JSON array"})
    if len(parsed) > _MAX_BATCH_ITEMS:
        return json.dumps({"error": f"Too many items ({len(parsed)} > {_MAX_BATCH_ITEMS})"})

    results: list[dict] = []
    stopped = False
    cancelled = False
    for i, item in enumerate(parsed):
        try:
            check_cancelled()
        except (CancelledError, IDASyncError):
            cancelled = True
            break
        result = _batch_apply_item(item, bool(dry_run))
        result["index"] = i
        results.append(result)
        if not result.get("ok") and stop_on_error:
            stopped = True
            break

    failed = sum(1 for r in results if not r.get("ok"))
    valid = len(results) - failed
    out: dict = {
        "dry_run": bool(dry_run),
        "results": results,
        "count": len(results),
        "valid": valid,
        "applied": 0 if dry_run else valid,
        "failed": failed,
        "stopped": stopped,
    }
    if cancelled:
        out["cancelled"] = True
        out["partial"] = True
    return json.dumps(out, indent=2)


# ===========================================================================
# Pipelines
# ===========================================================================

_PIPELINE_ACTIONS = {
    "delete_name", "make_name_public", "make_name_non_public",
}


def _pipeline_apply_step(step: dict, dry_run: bool) -> dict:
    """Validate/apply one pipeline step without calling another @idasync tool."""
    if not isinstance(step, dict):
        return {"ok": False, "error": "step must be a JSON object"}
    action = str(step.get("op", step.get("action", ""))).strip().lower()
    if action in ("rename", "set_name", "name", "comment", "set_comment",
                  "type", "set_type"):
        item = dict(step)
        item["action"] = action
        result = _batch_apply_item(item, dry_run)
        result["op"] = action
        return result
    if action not in _PIPELINE_ACTIONS:
        return {"ok": False, "op": action,
                "error": (f"Unknown pipeline op {action!r}; use rename/comment/"
                          "type/delete_name/make_name_public/"
                          "make_name_non_public")}
    address = step.get("address")
    if address is None:
        return {"ok": False, "op": action, "error": "missing 'address'"}
    try:
        ea = parse_addr(address)
    except ValueError as e:
        return {"ok": False, "op": action, "address": address,
                "error": str(e)}
    if not ida_bytes.is_mapped(ea):
        return {"ok": False, "op": action, "address": hex(ea),
                "error": f"Address not mapped: {hex(ea)}"}
    old_name = ida_name.get_ea_name(ea) or None
    if dry_run:
        return {"ok": True, "op": action, "address": hex(ea), "dry_run": True,
                "old_name": old_name}
    try:
        if action == "delete_name":
            ok = bool(_compat_del_name(ea))
        else:
            fn = getattr(ida_name, action, None)
            if not callable(fn):
                return {"ok": False, "op": action, "address": hex(ea),
                        "error": f"{action} is not available on this IDA version"}
            result = fn(ea)
            # IDA's visibility setters may return None on success and older
            # tools ignore the return value; only an explicit False is a fail.
            ok = result is not False
    except Exception as e:
        return {"ok": False, "op": action, "address": hex(ea),
                "error": str(e)}
    if not ok:
        return {"ok": False, "op": action, "address": hex(ea),
                "error": f"Failed to {action} at {hex(ea)}"}
    return {"ok": True, "op": action, "address": hex(ea),
            "old_name": old_name,
            "current_name": ida_name.get_ea_name(ea) or None}


@tool
@idasync
@unsafe
def apply_pipeline(
    steps: str,
    dry_run: bool = False,
    stop_on_error: bool = False,
) -> str:
    """Apply a short sequence of annotation/name operations in one call.

    ``steps`` is a JSON array of objects; each step uses ``op`` (``action`` is
    accepted as an alias). Supported ops: ``rename``/``set_name``,
    ``comment``/``set_comment``, ``type``/``set_type``, ``delete_name``,
    ``make_name_public`` and ``make_name_non_public``. ``dry_run`` validates
    every step without changing the IDB; ``stop_on_error`` stops after the
    first failed step. At most 1000 steps are accepted.

    This is deliberately an operation pipeline, not a way to nest MCP tool
    calls: the steps run directly inside one synchronized tool body.

    **Unsafe** — requires ``?unsafe=true``.
    """
    ensure_analysis()
    try:
        parsed = json.loads(steps) if isinstance(steps, str) else steps
    except (TypeError, ValueError) as e:
        return json.dumps({"error": f"Invalid steps JSON: {e}"})
    if not isinstance(parsed, list):
        return json.dumps({"error": "steps must be a JSON array"})
    if len(parsed) > _MAX_BATCH_ITEMS:
        return json.dumps({"error": f"Too many steps ({len(parsed)} > {_MAX_BATCH_ITEMS})"})

    results: list[dict] = []
    stopped = False
    cancelled = False
    for i, step in enumerate(parsed):
        try:
            check_cancelled()
        except (CancelledError, IDASyncError):
            cancelled = True
            break
        result = _pipeline_apply_step(step, bool(dry_run))
        result["index"] = i
        results.append(result)
        if not result.get("ok") and stop_on_error:
            stopped = True
            break

    failed = sum(1 for r in results if not r.get("ok"))
    valid = len(results) - failed
    out: dict = {
        "dry_run": bool(dry_run),
        "steps": results,
        "count": len(results),
        "valid": valid,
        "applied": 0 if dry_run else valid,
        "failed": failed,
        "stopped": stopped,
    }
    if cancelled:
        out["cancelled"] = True
        out["partial"] = True
    return json.dumps(out, indent=2)


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

    start_ea = ea

    if data_type == "string":
        created = 0
        for _ in range(min(int(count), 1000)):
            check_cancelled()
            # A NUL where a string would start means there is nothing left to
            # convert: skipping it kept walking and created literals *after* a
            # terminator.
            if ida_bytes.get_byte(ea) == 0:
                break
            ida_bytes.create_strlit(ea, 0, ida_nalt.STRTYPE_C)
            size = ida_bytes.get_item_size(ea)
            ea += size if size > 0 else 1
            created += 1
        return json.dumps({"ok": True, "addr": hex(start_ea),
                           "next_ea": hex(ea), "created": created}, indent=2)

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

    # ``addr`` is the address that was asked for; ``next_ea`` is where the
    # conversion ended (the string branch used to return only the latter).
    return json.dumps({"ok": True, "addr": hex(start_ea),
                       "next_ea": hex(ea)}, indent=2)


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
    dry_run: bool = False,
) -> str:
    """Patch bytes at a memory address with hex data.

    ``data`` is a hex string, with or without spaces
    (e.g., ``"9090"`` or ``"90 90"``). Capped at ``_MAX_PATCH_BYTES``.
    ``dry_run=True`` validates the address/hex/size and previews the write
    without changing the database.

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

    if not dry_run:
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
        "dry_run": bool(dry_run),
    }, indent=2)


@tool
@idasync
@unsafe
def patch_asm(
    address: str,
    asm: str,
    dry_run: bool = False,
) -> str:
    """Assemble and patch assembly instruction(s) at an address.

    ``asm``: assembly text (e.g., ``"nop; nop"`` or ``"mov eax, 1"``).
    ``dry_run=True`` assembles and validates without writing.

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
    if len(blob) > _MAX_PATCH_BYTES:
        return json.dumps({"addr": hex(ea), "error":
                           f"Assembled patch too large: {len(blob)} bytes "
                           f"(max {_MAX_PATCH_BYTES})"})
    if not ida_bytes.is_mapped(ea):
        return json.dumps({"error": f"Address not mapped: {hex(ea)}"})
    if not dry_run:
        ida_bytes.patch_bytes(ea, blob)
        ida_bytes.del_items(ea, ida_bytes.DELIT_NOTRUNC, len(blob))

    return json.dumps({
        "ok": True,
        "addr": hex(ea),
        "asm": asm,
        "size": len(blob),
        "bytes": blob.hex(),
        "dry_run": bool(dry_run),
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
    size: int = 1,
    dry_run: bool = False,
) -> str:
    """Revert a patch, restoring ``size`` original bytes.

    Defaults to one byte for backwards compatibility; ``size`` is clamped to
    ``_MAX_PATCH_BYTES``. ``dry_run=True`` previews the restore.

    **Unsafe** — requires ``?unsafe=true``.
    """
    ensure_analysis()
    try:
        ea = parse_addr(address)
    except ValueError as e:
        return json.dumps({"error": str(e)})

    size = clamp_int(size, 1, _MAX_PATCH_BYTES)
    if not ida_bytes.is_mapped(ea):
        return json.dumps({"error": f"Address not mapped: {hex(ea)}"})

    orig = _compat_original_bytes(ea, size)
    if not orig or len(orig) < size:
        return json.dumps({"error": f"Could not read {size} original byte(s) at {hex(ea)}"})
    if not dry_run:
        ida_bytes.patch_bytes(ea, orig)
        ida_bytes.del_items(ea, ida_bytes.DELIT_NOTRUNC, size)
    return json.dumps({
        "ok": True,
        "addr": hex(ea),
        "size": size,
        "restored_byte": hex(orig[0]),
        "restored_hex": orig.hex(),
        "dry_run": bool(dry_run),
    }, indent=2)


@tool
@idasync
def list_patches(max_scan_bytes: int = 0) -> str:
    """List patches in the database (current byte differs from original).

    Scans every byte of every segment in chunks, coalesces adjacent patched
    bytes into ``ranges`` (the flat ``patches`` list is kept for
    compatibility), and stops after 1000 patches. ``max_scan_bytes=0`` scans
    the whole image; a positive value caps the scan and sets ``truncated``.
    """
    ensure_analysis()
    results: list[dict] = []
    ranges: list[dict] = []
    truncated = False
    partial = False
    scanned = 0
    scan_cap = max(0, _as_int(max_scan_bytes, 0))
    chunk_size = 4096

    for seg_ea in idautils.Segments():
        seg = ida_segment.getseg(seg_ea)
        if not seg:
            continue
        pos = int(seg.start_ea)
        end = int(seg.end_ea)
        while pos < end:
            if scan_cap and scanned >= scan_cap:
                truncated = True
                break
            size = min(chunk_size, end - pos)
            if scan_cap:
                size = min(size, scan_cap - scanned)
            try:
                check_cancelled()
            except (CancelledError, IDASyncError):
                partial = True
                truncated = True
                break
            current = None
            try:
                current = ida_bytes.get_bytes(pos, size)
            except Exception:
                current = None
            original = _compat_original_bytes(pos, size)
            for i in range(size):
                try:
                    orig = (original[i] if original and i < len(original)
                            else ida_bytes.get_original_byte(pos + i))
                    curr = (current[i] if current and i < len(current)
                            else ida_bytes.get_byte(pos + i))
                except Exception:
                    continue
                if orig == curr:
                    continue
                ea = pos + i
                results.append({"addr": hex(ea), "original": hex(orig),
                                "current": hex(curr)})
                if ranges and int(ranges[-1]["end"], 16) == ea:
                    ranges[-1]["end"] = hex(ea + 1)
                    ranges[-1]["size"] += 1
                else:
                    ranges.append({"start": hex(ea), "end": hex(ea + 1),
                                   "size": 1})
                if len(results) >= 1000:
                    truncated = True
                    break
            scanned += size
            pos += size
            if truncated:
                break
        if truncated:
            break

    out: dict = {
        "patches": results,
        "ranges": ranges,
        "count": len(results),
        "range_count": len(ranges),
        "scanned_bytes": scanned,
        "truncated": truncated,
    }
    if partial:
        out["partial"] = True
    if scan_cap:
        out["max_scan_bytes"] = scan_cap
    return json.dumps(out, indent=2)
