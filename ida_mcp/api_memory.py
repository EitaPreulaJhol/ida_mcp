"""Memory scalar readers and code/data head navigation for ida_mcp.

Complements ``api_analysis.get_bytes`` / ``get_string`` (bulk reads) with
typed scalar readers (``get_byte`` … ``get_int``), data-item introspection
(``get_data_size``, ``get_data_flags``), address navigation
(``get_next/prev_head/addr``), head enumeration (``get_heads``,
``is_code``/``is_data``) and plain-text disassembly (``get_disassembly_text``).

Follows idamcp-extendedtools ``api_memory.py`` / ``api_heads.py`` naming.
All reads are BSS-safe (unloaded bytes read as zero).
"""
import json
import struct

import ida_bytes
import ida_ida
import ida_lines
import idaapi
import idautils

from .rpc import tool
from .sync import idasync
from .sync import ensure_analysis
from .api_analysis import parse_addr, read_bytes_bss_safe, resolve_addr
from .api_analysis import clamp_int
from .compat import inf_get_max_ea, inf_get_min_ea, is_loaded


def _int_value(ea: int, size: int, signed: bool) -> int | None:
    raw = read_bytes_bss_safe(ea, size)
    if not raw or len(raw) < size:
        return None
    be = False
    try:
        be = bool(ida_ida.inf_is_be())
    except Exception:
        pass
    fmt = (">" if be else "<") + {1: "b", 2: "h", 4: "i", 8: "q"}[size]
    if not signed:
        fmt = fmt.upper()
    try:
        return struct.unpack(fmt, raw[:size])[0]
    except Exception:
        return None


# ===========================================================================
# Tools — scalar readers
# ===========================================================================


@tool
@idasync
def get_byte(address: str) -> str:
    """Read a single byte at the given address (BSS-safe: unloaded → 0)."""
    ensure_analysis()
    ea, err = resolve_addr(address)
    if err:
        return err
    val = _int_value(ea, 1, False)
    if val is None:
        return json.dumps({"addr": hex(ea), "value": None, "error": "Could not read byte"})
    return json.dumps({"addr": hex(ea), "value": val, "hex": hex(val)})


@tool
@idasync
def get_word(address: str) -> str:
    """Read an unsigned 16-bit word at the given address (BSS-safe)."""
    ensure_analysis()
    ea, err = resolve_addr(address)
    if err:
        return err
    val = _int_value(ea, 2, False)
    if val is None:
        return json.dumps({"addr": hex(ea), "value": None, "error": "Could not read word"})
    return json.dumps({"addr": hex(ea), "value": val, "hex": hex(val)})


@tool
@idasync
def get_dword(address: str) -> str:
    """Read an unsigned 32-bit dword at the given address (BSS-safe)."""
    ensure_analysis()
    ea, err = resolve_addr(address)
    if err:
        return err
    val = _int_value(ea, 4, False)
    if val is None:
        return json.dumps({"addr": hex(ea), "value": None, "error": "Could not read dword"})
    return json.dumps({"addr": hex(ea), "value": val, "hex": hex(val)})


@tool
@idasync
def get_qword(address: str) -> str:
    """Read an unsigned 64-bit qword at the given address (BSS-safe)."""
    ensure_analysis()
    ea, err = resolve_addr(address)
    if err:
        return err
    val = _int_value(ea, 8, False)
    if val is None:
        return json.dumps({"addr": hex(ea), "value": None, "error": "Could not read qword"})
    return json.dumps({"addr": hex(ea), "value": val, "hex": hex(val)})


@tool
@idasync
def get_float(address: str) -> str:
    """Read a 32-bit IEEE-754 float at the given address (BSS-safe)."""
    ensure_analysis()
    ea, err = resolve_addr(address)
    if err:
        return err
    raw = read_bytes_bss_safe(ea, 4)
    if not raw or len(raw) < 4:
        return json.dumps({"addr": hex(ea), "value": None, "error": "Could not read float"})
    be = False
    try:
        be = bool(ida_ida.inf_is_be())
    except Exception:
        pass
    try:
        val = struct.unpack(">f" if be else "<f", raw[:4])[0]
    except Exception as e:
        return json.dumps({"error": str(e)})
    return json.dumps({"addr": hex(ea), "value": val})


@tool
@idasync
def get_double(address: str) -> str:
    """Read a 64-bit IEEE-754 double at the given address (BSS-safe)."""
    ensure_analysis()
    ea, err = resolve_addr(address)
    if err:
        return err
    raw = read_bytes_bss_safe(ea, 8)
    if not raw or len(raw) < 8:
        return json.dumps({"addr": hex(ea), "value": None, "error": "Could not read double"})
    be = False
    try:
        be = bool(ida_ida.inf_is_be())
    except Exception:
        pass
    try:
        val = struct.unpack(">d" if be else "<d", raw[:8])[0]
    except Exception as e:
        return json.dumps({"error": str(e)})
    return json.dumps({"addr": hex(ea), "value": val})


@tool
@idasync
def get_int(address: str, ty: str = "u32") -> str:
    """Read a typed integer at the given address (BSS-safe).

    ``ty`` is one of ``u8``/``u16``/``u32``/``u64``/``i8``/``i16``/``i32``/``i64``.
    """
    ensure_analysis()
    ea, err = resolve_addr(address)
    if err:
        return err
    spec = {"u8": (1, False), "u16": (2, False), "u32": (4, False), "u64": (8, False),
            "i8": (1, True), "i16": (2, True), "i32": (4, True), "i64": (8, True)}
    if ty not in spec:
        return json.dumps({"error": f"Invalid ty {ty!r} (use u8/u16/u32/u64/i8/i16/i32/i64)"})
    size, signed = spec[ty]
    val = _int_value(ea, size, signed)
    if val is None:
        return json.dumps({"addr": hex(ea), "ty": ty, "value": None,
                           "error": "Could not read integer"})
    return json.dumps({"addr": hex(ea), "ty": ty, "value": val, "hex": hex(val & 0xFFFFFFFFFFFFFFFF)})


@tool
@idasync
def get_cstring(address: str, max_len: int = 4096) -> str:
    """Read a C string at the given address with an explicit length cap.

    Unlike ``get_string`` (unbounded), stops after ``max_len`` bytes.
    """
    ensure_analysis()
    ea, err = resolve_addr(address)
    if err:
        return err
    if max_len <= 0 or max_len > 65536:
        max_len = 4096
    try:
        raw = ida_bytes.get_strlit_contents(ea, max_len, 0)
    except Exception as e:
        return json.dumps({"error": str(e)})
    if not raw:
        return json.dumps({"addr": hex(ea), "value": None, "error": "No string at address"})
    try:
        value = bytes(raw).decode("utf-8", errors="replace")
    except Exception:
        value = bytes(raw).hex()
    return json.dumps({"addr": hex(ea), "value": value, "length": len(raw)})


@tool
@idasync
def get_global_value(address: str, size: int = 0) -> str:
    """Read a global variable's integer value (BSS-safe: unloaded → 0).

    ``size`` defaults to the data item size at the address (min 1).
    """
    ensure_analysis()
    ea, err = resolve_addr(address)
    if err:
        return err
    if size <= 0:
        try:
            size = ida_bytes.get_item_size(ea) or 1
        except Exception:
            size = 1
    if size not in (1, 2, 4, 8):
        return json.dumps({"error": f"Unsupported size {size} (use 1/2/4/8)"})
    val = _int_value(ea, size, False)
    if val is None:
        return json.dumps({"addr": hex(ea), "value": None, "error": "Could not read value"})
    return json.dumps({"addr": hex(ea), "size": size, "value": val, "hex": hex(val)})


@tool
@idasync
def get_data_size(address: str) -> str:
    """Get the data item size in bytes at the given address."""
    ensure_analysis()
    ea, err = resolve_addr(address)
    if err:
        return err
    try:
        size = ida_bytes.get_item_size(ea)
    except Exception as e:
        return json.dumps({"error": str(e)})
    return json.dumps({"addr": hex(ea), "size": size})


# FF_* bits worth naming (the low nibble of the type field is decoded
# separately as ``data_type``).
_FLAG_NAMES = ("FF_CODE", "FF_DATA", "FF_TAIL", "FF_COMM", "FF_REF", "FF_LABL",
               "FF_NAME", "FF_LINE", "FF_FLOW", "FF_SIGN", "FF_BNOT", "FF_UNUSED")
_DATA_TYPE_NAMES = (
    ("FF_0NUMH", "hex"), ("FF_0NUMD", "decimal"), ("FF_0CHAR", "char"),
    ("FF_0SEG", "segment"), ("FF_0OFF", "offset"), ("FF_0NUMB", "binary"),
    ("FF_0NUMO", "octal"), ("FF_0ENUM", "enum"), ("FF_0FOP", "float-op"),
    ("FF_0STRO", "struct-offset"), ("FF_0STK", "stack"), ("FF_0FLT", "float"),
    ("FF_0CUST", "custom"),
)
_DATA_TYPE_MASK = 0xF00000


def _flag_bits(flags: int) -> list[str]:
    """Names of the common FF_* bits set in ``flags``."""
    value = int(flags) & 0xFFFFFFFF
    out = []
    for name in _FLAG_NAMES:
        mask = getattr(ida_bytes, name, None)
        if isinstance(mask, int) and (value & int(mask) & 0xFFFFFFFF):
            out.append(name[3:].lower())
    return out


def _data_type_name(flags: int) -> str | None:
    """Readable name of the FF_0* data-type nibble (None when unset)."""
    value = int(flags) & _DATA_TYPE_MASK
    if not value:
        return None
    for name, label in _DATA_TYPE_NAMES:
        mask = getattr(ida_bytes, name, None)
        if isinstance(mask, int) and (value & int(mask) & _DATA_TYPE_MASK) == value:
            return label
    return None


@tool
@idasync
def get_data_flags(address: str) -> str:
    """Get the IDA flags at the given address, decoded into names."""
    ensure_analysis()
    ea, err = resolve_addr(address)
    if err:
        return err
    try:
        flags = int(ida_bytes.get_flags(ea))
    except Exception as e:
        return json.dumps({"error": str(e)})
    return json.dumps({
        "addr": hex(ea),
        "flags": hex(flags),
        "bits": _flag_bits(flags),
        "data_type": _data_type_name(flags),
    })


# ===========================================================================
# Tools — head / address navigation
# ===========================================================================


@tool
@idasync
def get_next_head(address: str) -> str:
    """Get the next defined item (head) after the given address."""
    ensure_analysis()
    ea, err = resolve_addr(address)
    if err:
        return err
    try:
        nxt = ida_bytes.next_head(ea, inf_get_max_ea())
    except Exception as e:
        return json.dumps({"error": str(e)})
    if nxt == idaapi.BADADDR:
        return json.dumps({"addr": hex(ea), "next": None})
    return json.dumps({"addr": hex(ea), "next": hex(nxt)})


@tool
@idasync
def get_prev_head(address: str) -> str:
    """Get the previous defined item (head) before the given address."""
    ensure_analysis()
    ea, err = resolve_addr(address)
    if err:
        return err
    try:
        prev = ida_bytes.prev_head(ea, inf_get_min_ea())
    except Exception as e:
        return json.dumps({"error": str(e)})
    if prev == idaapi.BADADDR:
        return json.dumps({"addr": hex(ea), "prev": None})
    return json.dumps({"addr": hex(ea), "prev": hex(prev)})


@tool
@idasync
def get_next_addr(address: str) -> str:
    """Get the next address (head or tail) after the given address."""
    ensure_analysis()
    ea, err = resolve_addr(address)
    if err:
        return err
    try:
        nxt = ida_bytes.next_addr(ea)
    except Exception as e:
        return json.dumps({"error": str(e)})
    if nxt == idaapi.BADADDR:
        return json.dumps({"addr": hex(ea), "next": None})
    return json.dumps({"addr": hex(ea), "next": hex(nxt)})


@tool
@idasync
def get_prev_addr(address: str) -> str:
    """Get the previous address (head or tail) before the given address."""
    ensure_analysis()
    ea, err = resolve_addr(address)
    if err:
        return err
    try:
        prev = ida_bytes.prev_addr(ea)
    except Exception as e:
        return json.dumps({"error": str(e)})
    if prev == idaapi.BADADDR:
        return json.dumps({"addr": hex(ea), "prev": None})
    return json.dumps({"addr": hex(ea), "prev": hex(prev)})


@tool
@idasync
def get_heads(start: str, end: str, limit: int = 200) -> str:
    """Enumerate defined items (heads) in ``[start, end)`` (capped).

    ``limit`` is clamped to [1, 10000] (0/oversized -> the default 200) and the
    applied value is echoed in the payload.
    """
    ensure_analysis()
    try:
        start_ea = parse_addr(start)
        end_ea = parse_addr(end)
    except ValueError as e:
        return json.dumps({"error": str(e)})
    limit = clamp_int(limit, 200, 10000)
    heads: list[str] = []
    try:
        for ea in idautils.Heads(start_ea, end_ea):
            heads.append(hex(ea))
            if len(heads) >= limit:
                break
    except Exception as e:
        return json.dumps({"error": str(e)})
    return json.dumps({"start": hex(start_ea), "end": hex(end_ea),
                       "heads": heads, "count": len(heads), "limit": limit,
                       "truncated": len(heads) >= limit})


@tool
@idasync
def is_code(address: str) -> str:
    """Check if the given address holds code."""
    ensure_analysis()
    ea, err = resolve_addr(address)
    if err:
        return err
    is_code_fn = getattr(ida_bytes, "is_code", None)
    if not callable(is_code_fn):
        return json.dumps({"error": "is_code unavailable in this IDA version"})
    try:
        code = bool(is_code_fn(ida_bytes.get_flags(ea)))
    except Exception as e:
        return json.dumps({"error": str(e)})
    return json.dumps({"addr": hex(ea), "is_code": code})


@tool
@idasync
def is_data(address: str) -> str:
    """Check if the given address holds data."""
    ensure_analysis()
    ea, err = resolve_addr(address)
    if err:
        return err
    is_data_fn = getattr(ida_bytes, "is_data", None)
    if not callable(is_data_fn):
        return json.dumps({"error": "is_data unavailable in this IDA version"})
    try:
        data = bool(is_data_fn(ida_bytes.get_flags(ea)))
    except Exception as e:
        return json.dumps({"error": str(e)})
    return json.dumps({"addr": hex(ea), "is_data": data})


@tool
@idasync
def get_disassembly_text(address: str, limit: int = 50) -> str:
    """Plain-text disassembly (``addr: text`` lines) from an address.

    Lighter than ``disasm`` (no JSON structure) for token-efficient reads.
    ``limit`` is clamped to [1, 500] (0/oversized -> the default 50) and the
    applied value is echoed in the payload; the deprecated ``count`` argument
    is mapped to ``limit`` by the server.
    """
    ensure_analysis()
    ea, err = resolve_addr(address)
    if err:
        return err
    limit = clamp_int(limit, 50, 500)
    lines: list[str] = []
    try:
        for _ in range(limit):
            if ea == idaapi.BADADDR or not is_loaded(ea):
                break
            text = ida_lines.tag_remove(ida_lines.generate_disasm_line(ea, 0) or "")
            lines.append(f"{hex(ea)}: {text.strip()}")
            ea = ida_bytes.next_head(ea, inf_get_max_ea())
    except Exception as e:
        return json.dumps({"error": str(e)})
    return json.dumps({"lines": lines, "count": len(lines), "limit": limit})


__all__ = [
    "get_byte",
    "get_word",
    "get_dword",
    "get_qword",
    "get_float",
    "get_double",
    "get_int",
    "get_cstring",
    "get_global_value",
    "get_data_size",
    "get_data_flags",
    "get_next_head",
    "get_prev_head",
    "get_next_addr",
    "get_prev_addr",
    "get_heads",
    "is_code",
    "is_data",
    "get_disassembly_text",
]
