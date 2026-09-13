"""Search tools — search bytes, text, immediates, and regex patterns.

Tools ported from idamcp-extendedtools api_search.py, adapted for direct
in-process IDA SDK access.
"""

import json
import re

import ida_auto
import ida_bytes
import ida_idaapi
import ida_search

from .rpc import tool
from .sync import idasync
from .api_analysis import parse_addr


# ===========================================================================
# Tools
# ===========================================================================


@tool
@idasync
def search_bytes(pattern: str) -> str:
    """Search for byte sequences in the binary.

    ``pattern`` is a hex string, with or without spaces (e.g., ``"55 48 89 E5"``
    or ``"554889E5"``). Supports ``??`` wildcards.

    Returns a list of matching addresses.
    """
    ida_auto.auto_wait()
    pattern = pattern.replace(" ", "")
    if not pattern:
        return json.dumps({"error": "Empty pattern"})

    norm = " ".join(pattern[i:i+2] for i in range(0, len(pattern), 2))

    matches: list[str] = []
    ea = ida_bytes.find_bytes(norm, 0x00000000, range_end=0xFFFFFFFFFFFFFFFF)
    while ea != ida_idaapi.BADADDR and len(matches) < 200:
        matches.append(hex(ea))
        ea = ida_bytes.find_bytes(norm, ea + 1, range_end=0xFFFFFFFFFFFFFFFF)

    return json.dumps({"pattern": pattern, "matches": matches, "count": len(matches)}, indent=2)


@tool
@idasync
def search_text(
    text: str,
    case_sensitive: bool = False,
) -> str:
    """Search for text in the binary's disassembly and data sections.

    Returns a list of addresses where the text appears.
    """
    ida_auto.auto_wait()
    results: list[str] = []
    flags = 0 if case_sensitive else ida_search.SEARCH_CASE

    ea = ida_search.find_text(0, 0, 0, text, flags)
    while ea != ida_idaapi.BADADDR and len(results) < 200:
        results.append(hex(ea))
        ea = ida_search.find_text(ea + 1, 0, 0, text, flags)

    return json.dumps({"text": text, "matches": results, "count": len(results)}, indent=2)


@tool
@idasync
def search_immediate_value(value: int) -> str:
    """Search for immediate values in instructions.

    Returns addresses of instructions that reference the given immediate value.
    """
    ida_auto.auto_wait()
    results: list[str] = []

    try:
        value = int(value)
    except (ValueError, TypeError):
        return json.dumps({"error": f"Invalid immediate value: {value}"})

    ea = ida_search.find_imm(0, ida_search.SEARCH_DOWN, value)
    while ea != ida_idaapi.BADADDR and len(results) < 200:
        results.append(hex(ea))
        ea = ida_search.find_imm(ea + 1, ida_search.SEARCH_DOWN, value)

    return json.dumps({"value": value, "matches": results, "count": len(results)}, indent=2)


@tool
@idasync
def find_regex(
    pattern: str,
    limit: int = 30,
) -> str:
    """Search all strings in the binary by case-insensitive regex pattern.

    ``limit`` caps the number of returned matches (default 30, max 500).
    """
    ida_auto.auto_wait()
    limit = min(max(int(limit), 1), 500)

    try:
        regex = re.compile(pattern, re.IGNORECASE)
    except re.error as e:
        return json.dumps({"error": f"Invalid regex: {e}"})

    results: list[dict] = []
    import idautils
    for si in idautils.Strings():
        value = str(si)
        if regex.search(value):
            results.append({"addr": hex(si.ea), "value": value, "length": si.length})
            if len(results) >= limit:
                break

    return json.dumps({"pattern": pattern, "matches": results, "count": len(results)}, indent=2)


@tool
@idasync
def find_bytes_between(
    pattern: str,
    start: str,
    end: str,
) -> str:
    """Search for byte pattern within a specific address range.

    ``pattern``: hex string (e.g., ``"55 48 89 E5"``).
    ``start``, ``end``: address bounds (hex or symbol names).
    """
    ida_auto.auto_wait()
    try:
        start_ea = parse_addr(start)
        end_ea = parse_addr(end)
    except ValueError as e:
        return json.dumps({"error": str(e)})

    pattern = pattern.replace(" ", "")
    norm = " ".join(pattern[i:i+2] for i in range(0, len(pattern), 2))

    results: list[str] = []
    ea = start_ea
    while ea < end_ea and len(results) < 200:
        ea = ida_bytes.find_bytes(norm, ea, range_end=end_ea)
        if ea == ida_idaapi.BADADDR or ea >= end_ea:
            break
        results.append(hex(ea))
        ea += 1

    return json.dumps({"pattern": pattern, "start": hex(start_ea), "end": hex(end_ea), "matches": results, "count": len(results)}, indent=2)


@tool
@idasync
def find_text_between(
    text: str,
    start: str,
    end: str,
    case_sensitive: bool = False,
) -> str:
    """Search for text within a specific address range.

    ``start``, ``end``: address bounds (hex or symbol names).
    """
    ida_auto.auto_wait()
    try:
        start_ea = parse_addr(start)
        end_ea = parse_addr(end)
    except ValueError as e:
        return json.dumps({"error": str(e)})

    flags = 0 if case_sensitive else ida_search.SEARCH_CASE
    results: list[str] = []
    ea = start_ea
    while ea < end_ea and len(results) < 200:
        ea = ida_search.find_text(ea, 0, 0, text, flags)
        if ea == ida_idaapi.BADADDR or ea >= end_ea:
            break
        results.append(hex(ea))
        ea += 1

    return json.dumps({"text": text, "start": hex(start_ea), "end": hex(end_ea), "matches": results, "count": len(results)}, indent=2)


@tool
@idasync
def find_immediate_between(
    value: int,
    start: str,
    end: str,
) -> str:
    """Search for immediate values within a specific address range.

    ``start``, ``end``: address bounds (hex or symbol names).
    """
    ida_auto.auto_wait()
    try:
        start_ea = parse_addr(start)
        end_ea = parse_addr(end)
    except ValueError as e:
        return json.dumps({"error": str(e)})

    try:
        value = int(value)
    except (ValueError, TypeError):
        return json.dumps({"error": f"Invalid immediate value: {value}"})

    results: list[str] = []
    ea = ida_search.find_imm(start_ea, ida_search.SEARCH_DOWN, value)
    while ea != ida_idaapi.BADADDR and ea < end_ea and len(results) < 200:
        results.append(hex(ea))
        ea = ida_search.find_imm(ea + 1, ida_search.SEARCH_DOWN, value)

    return json.dumps({"value": value, "start": hex(start_ea), "end": hex(end_ea), "matches": results, "count": len(results)}, indent=2)
