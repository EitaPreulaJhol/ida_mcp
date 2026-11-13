"""Segment tools — query memory segments, their metadata, and permissions.

Tools ported from idamcp-extendedtools api_segments.py, adapted for direct
in-process IDA SDK access.
"""

import json

import ida_segment
import idautils

from .rpc import tool
from .sync import idasync
from .sync import ensure_analysis
from .api_analysis import parse_addr
# aliased: this module's own ``get_segment_comment`` tool would shadow it
from .compat import get_segment_comment as _compat_segment_comment
from .compat import segment_class as _segment_class


def _segments():
    """Yield every segment (``getnseg`` was deprecated in 9.5).

    ``idautils.Segments()`` yields start addresses through the current
    ``get_segment_info_by_num``; ``getseg`` is the long-standing accessor
    (silenced centrally in compat).
    """
    for seg_ea in idautils.Segments():
        seg = ida_segment.getseg(seg_ea)
        if seg:
            yield seg


def _find_segment(address: str):
    """Segment at ``address`` (hex/symbol) or with that exact name, else None."""
    try:
        ea = parse_addr(address)
    except ValueError:
        ea = None
    if ea is not None:
        seg = ida_segment.getseg(ea)
        if seg:
            return seg
    for seg in _segments():
        if ida_segment.get_segm_name(seg) == address:
            return seg
    return None


def _seg_to_dict(seg) -> dict:
    """Convert an IDA segment to a JSON-serializable dict."""
    return {
        "name": ida_segment.get_segm_name(seg),
        "start_ea": hex(seg.start_ea),
        "end_ea": hex(seg.end_ea),
        "size": seg.end_ea - seg.start_ea,
        "class": _segment_class(seg),
        "bitness": seg.bitness,
    }


# ===========================================================================
# Tools
# ===========================================================================


@tool
@idasync
def get_segments() -> str:
    """List all memory segments with start/end addresses, names, sizes, and classes.

    Returns a JSON array of segment metadata objects.
    """
    ensure_analysis()
    results: list[dict] = []

    for seg in _segments():
        results.append(_seg_to_dict(seg))

    return json.dumps(results, indent=2)


@tool
@idasync
def get_segment_at(address: str) -> str:
    """Get the segment containing the given address.

    Returns segment metadata or an error if no segment found.
    """
    ensure_analysis()
    try:
        ea = parse_addr(address)
    except ValueError as e:
        return json.dumps({"error": str(e)})

    seg = ida_segment.getseg(ea)
    if not seg:
        return json.dumps({"error": f"No segment at {hex(ea)}"})

    return json.dumps(_seg_to_dict(seg), indent=2)


@tool
@idasync
def get_segment_by_name(name: str) -> str:
    """Get a segment by its name (e.g., '.text', '.data').

    Returns segment metadata or error if not found.
    """
    ensure_analysis()

    for seg in _segments():
        if ida_segment.get_segm_name(seg) == name:
            return json.dumps(_seg_to_dict(seg), indent=2)

    return json.dumps({"error": f"Segment '{name}' not found"})


@tool
@idasync
def get_segment_count() -> str:
    """Get the total number of segments in the binary."""
    ensure_analysis()
    count = ida_segment.get_segm_qty()
    return json.dumps({"count": count})


@tool
@idasync
def get_segment_size(address: str) -> str:
    """Get the size of the segment containing or named by the given address/name."""
    ensure_analysis()
    seg = _find_segment(address)
    if not seg:
        return json.dumps({"error": f"Segment not found: {address}"})

    return json.dumps({"name": ida_segment.get_segm_name(seg), "size": seg.end_ea - seg.start_ea, "size_hex": hex(seg.end_ea - seg.start_ea)})


@tool
@idasync
def get_segment_start(address: str) -> str:
    """Get the start address of the segment containing or named by the given address/name."""
    ensure_analysis()
    seg = _find_segment(address)
    if not seg:
        return json.dumps({"error": f"Segment not found: {address}"})
    return json.dumps({"name": ida_segment.get_segm_name(seg), "start_ea": hex(seg.start_ea)})


@tool
@idasync
def get_segment_end(address: str) -> str:
    """Get the end address of the segment containing or named by the given address/name."""
    ensure_analysis()
    seg = _find_segment(address)
    if not seg:
        return json.dumps({"error": f"Segment not found: {address}"})
    return json.dumps({"name": ida_segment.get_segm_name(seg), "end_ea": hex(seg.end_ea)})


@tool
@idasync
def get_segment_class(address: str) -> str:
    """Get the class of a segment (CODE, DATA, BSS, etc.)."""
    ensure_analysis()
    seg = _find_segment(address)
    if not seg:
        return json.dumps({"error": f"Segment not found: {address}"})
    return json.dumps({"name": ida_segment.get_segm_name(seg), "class": _segment_class(seg)})


@tool
@idasync
def get_segment_bitness(address: str) -> str:
    """Get the bitness of a segment (16, 32, or 64)."""
    ensure_analysis()
    seg = _find_segment(address)
    if not seg:
        return json.dumps({"error": f"Segment not found: {address}"})
    return json.dumps({"name": ida_segment.get_segm_name(seg), "bitness": seg.bitness})


@tool
@idasync
def get_segment_permissions(address: str) -> str:
    """Get the permissions of a segment (read, write, execute)."""
    ensure_analysis()
    seg = _find_segment(address)
    if not seg:
        return json.dumps({"error": f"Segment not found: {address}"})

    perm = seg.perm
    return json.dumps({
        "name": ida_segment.get_segm_name(seg),
        "readable": bool(perm & ida_segment.SEGPERM_READ),
        "writable": bool(perm & ida_segment.SEGPERM_WRITE),
        "executable": bool(perm & ida_segment.SEGPERM_EXEC),
        "permissions_raw": perm,
    }, indent=2)


@tool
@idasync
def get_code_segments() -> str:
    """Get all executable (code) segments."""
    ensure_analysis()
    results: list[dict] = []
    for seg in _segments():
        if _segment_class(seg) == "CODE":
            results.append(_seg_to_dict(seg))
    return json.dumps(results, indent=2)


@tool
@idasync
def get_data_segments() -> str:
    """Get all non-code (data/BSS) segments."""
    ensure_analysis()
    results: list[dict] = []
    for seg in _segments():
        if _segment_class(seg) != "CODE":
            results.append(_seg_to_dict(seg))
    return json.dumps(results, indent=2)


@tool
@idasync
def get_segment_comment(address: str) -> str:
    """Get the comment on a segment."""
    ensure_analysis()
    seg = _find_segment(address)
    if not seg:
        return json.dumps({"error": f"Segment not found: {address}"})

    comment = _compat_segment_comment(seg, False)
    return json.dumps({
        "name": ida_segment.get_segm_name(seg),
        "comment": comment if comment else None,
    })
