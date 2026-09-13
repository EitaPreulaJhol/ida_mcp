"""Byte-signature tools for ida_mcp (trimmed sigmaker).

Generates the SHORTEST unique signature starting at an address by walking
instructions, wildcarding operand bytes, and verifying uniqueness with
``ida_bytes.find_bytes`` after each instruction. Covers the ida-pro-mcp
surface (``make_signature``, ``make_signature_for_function``,
``make_signature_for_range``, ``find_xref_signatures``) with a compact
engine (~200 lines) instead of the 1600-line FLIRT ``.sig`` pipeline:
output is IDA/x64dbg/mask/bitmask *patterns* ready for ``find_bytes``.
Generating ``.sig``/``.pat`` files via ``sigmake`` remains out of scope.
"""
import json
import os
import time

import ida_auto
import ida_bytes
import ida_funcs
import ida_ua
import idaapi
import idautils

from .rpc import tool, unsafe
from .sync import (idasync, tool_timeout, check_cancelled, update_wait_box,
                   CancelledError, IDASyncError)
from .api_analysis import parse_addr, read_bytes_bss_safe
from .compat import inf_get_max_ea, inf_get_min_ea


_FORMATS = ("ida", "x64dbg", "mask", "bitmask")
_WILDCARD_TYPES = None  # resolved lazily (needs ida_ua constants)


def _operand_value_types() -> tuple:
    global _WILDCARD_TYPES
    if _WILDCARD_TYPES is None:
        _WILDCARD_TYPES = (
            ida_ua.o_imm, ida_ua.o_mem, ida_ua.o_near, ida_ua.o_far,
            getattr(ida_ua, "o_displ", -1),
        )
    return _WILDCARD_TYPES


def _dtype_size(dtype) -> int:
    try:
        return int(ida_ua.get_dtype_size(dtype))
    except Exception:
        return 0


def _insn_sig_bytes(ea: int, wildcard_operands: bool) -> list | None:
    """Signature bytes for the instruction at ``ea`` (None = keep byte).

    Returns None when ``ea`` is not decodable code.
    """
    insn = ida_ua.insn_t()
    try:
        if ida_ua.decode_insn(insn, ea) <= 0 or insn.size <= 0:
            return None
    except Exception:
        return None
    try:
        raw = read_bytes_bss_safe(ea, insn.size)
    except Exception:
        return None
    if not raw or len(raw) < insn.size:
        return None
    sig: list = list(raw[:insn.size])
    if not wildcard_operands:
        return sig
    for op in insn.ops:
        try:
            if op.type == ida_ua.o_void or op.type not in _operand_value_types():
                continue
            off = int(getattr(op, "offb", 0))
            size = _dtype_size(getattr(op, "dtype", 0))
            if size <= 0 or not 0 < off < insn.size or off + size > insn.size:
                continue
            for i in range(off, off + size):
                sig[i] = None
        except Exception:
            continue
    return sig


def _to_ida_pattern(sig: list) -> str:
    return " ".join(f"{b:02X}" if b is not None else "??" for b in sig)


def _render(sig: list, fmt: str) -> dict:
    pattern = _to_ida_pattern(sig)
    out: dict = {"signature": pattern, "length": len(sig)}
    if fmt in ("mask", "bitmask"):
        raw = bytes(b if b is not None else 0 for b in sig)
        out["bytes"] = raw.hex().upper()
        if fmt == "mask":
            out["mask"] = "".join("x" if b is not None else "?" for b in sig)
        else:
            out["bitmask"] = "".join("1" if b is not None else "0" for b in sig)
    return out


def _find_nth(pattern: str, start_ea: int, n: int):
    """n-th (1-based) match of ``pattern`` at/after ``start_ea`` or BADADDR."""
    try:
        min_ea = inf_get_min_ea()
        max_ea = inf_get_max_ea()
        ea = max(start_ea, min_ea)
        for _ in range(n):
            ea = ida_bytes.find_bytes(pattern, ea, range_end=max_ea)
            if ea == idaapi.BADADDR:
                return idaapi.BADADDR
            if _ != n - 1:
                ea += 1
        return ea
    except Exception:
        return idaapi.BADADDR


def _is_unique(pattern: str, expect_ea: int) -> bool:
    first = _find_nth(pattern, inf_get_min_ea(), 1)
    if first != expect_ea:
        return False
    return _find_nth(pattern, first + 1, 1) == idaapi.BADADDR


def _make_unique(start_ea: int, max_length: int,
                 wildcard_operands: bool) -> tuple:
    """Returns (sig|None, unique, end_ea, error|None)."""
    sig: list = []
    ea = start_ea
    steps = 0
    while len(sig) < max_length:
        steps += 1
        if steps % 8 == 0:
            try:
                check_cancelled()
            except (CancelledError, IDASyncError):
                if not sig:
                    return None, False, start_ea, "Cancelled (no signature built yet)"
                return sig, False, ea, "Cancelled: signature is partial, uniqueness unverified"
        part = _insn_sig_bytes(ea, wildcard_operands)
        if part is None:
            break
        sig.extend(part)
        if _is_unique(_to_ida_pattern(sig), start_ea):
            return sig, True, ea + len(part), None
        ea += len(part)
    if not sig:
        return None, False, start_ea, "No decodable instruction at address"
    unique = _is_unique(_to_ida_pattern(sig), start_ea)
    if unique:
        return sig, True, ea, None
    return sig, False, ea, f"No unique signature within {max_length} bytes"


def _split_addrs(addrs: str) -> list[str]:
    if isinstance(addrs, (list, tuple)):
        return [str(a) for a in addrs]
    return [a.strip() for a in str(addrs).split(",") if a.strip()]


def _check_format(fmt: str) -> str | None:
    f = (fmt or "ida").strip().lower()
    if f not in _FORMATS:
        return None
    return f


# ===========================================================================
# Tools
# ===========================================================================


@idasync
@tool_timeout(120.0)
def _fetch_one_signature(query: str, max_length: int, wildcard_operands: bool,
                         fmt: str, progress: str = "") -> dict:
    """Single-address signature hop (bounded main-thread hold)."""
    ida_auto.auto_wait()
    if progress:
        update_wait_box(f"make_signature {progress}")
    try:
        ea = parse_addr(query)
    except ValueError:
        return {"query": query, "addr": None, "signature": None,
                "format": fmt, "error": f"Unknown address or name: {query}"}
    try:
        sig, unique, _end, err = _make_unique(ea, max_length, bool(wildcard_operands))
    except Exception as e:
        return {"query": query, "addr": hex(ea), "signature": None,
                "format": fmt, "error": str(e)}
    if sig is None:
        return {"query": query, "addr": hex(ea), "signature": None,
                "format": fmt, "unique": False, "error": err}
    rendered = _render(sig, fmt)
    rendered.update({"query": query, "addr": hex(ea),
                     "format": fmt, "unique": unique})
    if err:
        rendered["error"] = err
    return rendered


_SIG_BUDGET_SEC = 120.0


@tool
def make_signature(addresses: str, format: str = "ida",
                   wildcard_operands: bool = True,
                   max_length: int = 1000) -> str:
    """Create the shortest unique byte signature starting at each address.

    ``addresses`` is comma-separated. Walks instructions wildcarding operand
    bytes (``ida``/``x64dbg`` share the ``??`` syntax; ``mask``/``bitmask``
    add explicit masks). ``max_length`` caps the walk (clamped to 10000).

    Two-phase: each address is collected in its own bounded main-thread hop
    so the UI breathes between addresses; JSON rendering runs on the HTTP
    worker thread under a 120 s budget.
    """
    fmt = _check_format(format)
    if fmt is None:
        return json.dumps({"error": f"Unknown format {format!r} (use ida/x64dbg/mask/bitmask)"})
    max_length = max(1, min(int(max_length), 10000))
    queries = _split_addrs(addresses)
    results: list[dict] = []
    start = time.monotonic()
    for i, query in enumerate(queries):
        if time.monotonic() - start >= _SIG_BUDGET_SEC:
            results.append({"query": query, "addr": None, "signature": None,
                            "format": fmt,
                            "error": f"Tool budget exceeded ({_SIG_BUDGET_SEC:.0f}s); "
                                     "retry with fewer addresses"})
            continue
        label = f"{i + 1}/{len(queries)}" if len(queries) > 1 else ""
        results.append(_fetch_one_signature(query, max_length,
                                            bool(wildcard_operands), fmt,
                                            progress=label))
    return json.dumps({"results": results}, indent=2)


@idasync
@tool_timeout(120.0)
def _fetch_function_signature(query: str, max_length: int,
                              wildcard_operands: bool, fmt: str,
                              progress: str = "") -> dict:
    """Single-function signature hop (bounded main-thread hold)."""
    ida_auto.auto_wait()
    if progress:
        update_wait_box(f"make_signature {progress}")
    try:
        ea = parse_addr(query)
    except ValueError:
        return {"query": query, "addr": None, "name": None,
                "signature": None, "format": fmt,
                "error": f"Unknown address or name: {query}"}
    func = ida_funcs.get_func(ea)
    if not func:
        return {"query": query, "addr": hex(ea), "name": None,
                "signature": None, "format": fmt,
                "error": f"No function at {hex(ea)}"}
    try:
        sig, unique, _end, err = _make_unique(func.start_ea, max_length,
                                              bool(wildcard_operands))
    except Exception as e:
        return {"query": query, "addr": hex(func.start_ea),
                "name": ida_funcs.get_func_name(func.start_ea) or None,
                "signature": None, "format": fmt, "error": str(e)}
    if sig is None:
        return {"query": query, "addr": hex(func.start_ea),
                "name": ida_funcs.get_func_name(func.start_ea) or None,
                "signature": None, "format": fmt, "unique": False,
                "error": err}
    rendered = _render(sig, fmt)
    rendered.update({"query": query, "addr": hex(func.start_ea),
                     "name": ida_funcs.get_func_name(func.start_ea) or None,
                     "format": fmt, "unique": unique})
    if err:
        rendered["error"] = err
    return rendered


@tool
def make_signature_for_function(addresses: str, format: str = "ida",
                                wildcard_operands: bool = True,
                                max_length: int = 1000) -> str:
    """Create unique signatures for function entry points.

    Resolves each address/name to its function, then signatures the start.
    Same formats and semantics as ``make_signature``.

    Two-phase: one bounded main-thread hop per address (see make_signature).
    """
    fmt = _check_format(format)
    if fmt is None:
        return json.dumps({"error": f"Unknown format {format!r} (use ida/x64dbg/mask/bitmask)"})
    max_length = max(1, min(int(max_length), 10000))
    queries = _split_addrs(addresses)
    results: list[dict] = []
    start = time.monotonic()
    for i, query in enumerate(queries):
        if time.monotonic() - start >= _SIG_BUDGET_SEC:
            results.append({"query": query, "addr": None, "name": None,
                            "signature": None, "format": fmt,
                            "error": f"Tool budget exceeded ({_SIG_BUDGET_SEC:.0f}s); "
                                     "retry with fewer addresses"})
            continue
        label = f"{i + 1}/{len(queries)}" if len(queries) > 1 else ""
        results.append(_fetch_function_signature(query, max_length,
                                                 bool(wildcard_operands), fmt,
                                                 progress=label))
    return json.dumps({"results": results}, indent=2)


@tool
@idasync
@tool_timeout(120.0)
def make_signature_for_range(start: str, end: str, format: str = "ida",
                             wildcard_operands: bool = True) -> str:
    """Encode ``[start, end)`` as a signature (no uniqueness guarantee).

    Walks instructions with operand wildcarding; undecodable bytes are
    embedded raw. Reports whether the result happens to be unique.
    Range is capped at 10000 bytes.
    """
    ida_auto.auto_wait()
    fmt = _check_format(format)
    if fmt is None:
        return json.dumps({"error": f"Unknown format {format!r} (use ida/x64dbg/mask/bitmask)"})
    try:
        start_ea = parse_addr(start)
        end_ea = parse_addr(end)
    except ValueError as e:
        return json.dumps({"error": str(e)})
    if end_ea <= start_ea or end_ea - start_ea > 10000:
        return json.dumps({"error": "Invalid range (must be 1-10000 bytes)"})
    sig: list = []
    ea = start_ea
    truncated = False
    while ea < end_ea:
        part = _insn_sig_bytes(ea, bool(wildcard_operands))
        if part is None:
            try:
                raw = read_bytes_bss_safe(ea, 1)
                sig.append(raw[0] if raw else None)
            except Exception:
                sig.append(None)
            ea += 1
            continue
        room = end_ea - ea
        sig.extend(part[:room])
        ea += len(part)
        if len(sig) >= 10000:
            truncated = True
            break
    pattern = _to_ida_pattern(sig)
    rendered = _render(sig, fmt)
    rendered.update({"query": f"{start}-{end}", "addr": hex(start_ea),
                     "format": fmt, "unique": _is_unique(pattern, start_ea)})
    if truncated:
        rendered["truncated"] = True
    return json.dumps(rendered, indent=2)


@idasync
@tool_timeout(180.0)
def _fetch_xref_signatures(query: str, top: int, max_length: int,
                           fmt: str, progress: str = "") -> dict:
    """Single-address xref-signature hop (bounded main-thread hold)."""
    ida_auto.auto_wait()
    if progress:
        update_wait_box(f"find_xref_signatures {progress}")
    try:
        ea = parse_addr(query)
    except ValueError:
        return {"query": query, "addr": None, "signatures": None,
                "error": f"Unknown address or name: {query}"}
    try:
        sites = [x.frm for x in idautils.XrefsTo(ea, 0) if x.iscode][:50]
    except Exception as e:
        return {"query": query, "addr": hex(ea), "signatures": None,
                "error": str(e)}
    sigs: list[dict] = []
    for site in sites:
        try:
            sig, unique, _end, _err = _make_unique(site, max_length, True)
        except Exception:
            continue
        if sig is None or not unique:
            continue
        rendered = _render(sig, fmt)
        sigs.append({"xref_addr": hex(site),
                     "signature": rendered["signature"],
                     "length": len(sig)})
    sigs.sort(key=lambda s: s["length"])
    return {"query": query, "addr": hex(ea),
            "signatures": sigs[:top], "total_xrefs": len(sites)}


_XREF_BUDGET_SEC = 180.0


@tool
def find_xref_signatures(addresses: str, format: str = "ida",
                         top: int = 5, max_length: int = 250) -> str:
    """Signatures for code sites referencing each address (for data/string refs).

    Generates a unique signature at every code xref source, returns the
    shortest ``top`` per address. At most 50 xref sites per address are tried.

    Two-phase: one bounded main-thread hop per address (see make_signature).
    """
    fmt = _check_format(format)
    if fmt is None:
        return json.dumps({"error": f"Unknown format {format!r} (use ida/x64dbg/mask/bitmask)"})
    top = max(1, min(int(top), 50))
    max_length = max(1, min(int(max_length), 10000))
    queries = _split_addrs(addresses)
    results: list[dict] = []
    start = time.monotonic()
    for i, query in enumerate(queries):
        if time.monotonic() - start >= _XREF_BUDGET_SEC:
            results.append({"query": query, "addr": None, "signatures": None,
                            "error": f"Tool budget exceeded ({_XREF_BUDGET_SEC:.0f}s); "
                                     "retry with fewer addresses"})
            continue
        label = f"{i + 1}/{len(queries)}" if len(queries) > 1 else ""
        results.append(_fetch_xref_signatures(query, top, max_length, fmt,
                                              progress=label))
    return json.dumps({"results": results}, indent=2)


__all__ = [
    "make_signature",
    "make_signature_for_function",
    "make_signature_for_range",
    "find_xref_signatures",
    "apply_flirt_signatures",
    "list_flirt_signatures",
]


def _plan_apply_sig(sig_path: str) -> None:
    """Queue a .sig file for FLIRT application (getattr ladder).

    ``plan_to_apply_idasgn`` is a C++-side API with inconsistent Python
    exposure across versions; try each known location and raise a clean
    error when none exists.
    """
    import ida_funcs
    for mod in (ida_funcs,):
        fn = getattr(mod, "plan_to_apply_idasgn", None)
        if callable(fn):
            try:
                if int(fn(sig_path)) <= 0:
                    raise ValueError(f"IDA refused signature file {sig_path!r}")
                return
            except ValueError:
                raise
            except Exception as e:
                raise ValueError(f"plan_to_apply_idasgn failed: {e}")
    try:
        import idaapi
        fn = getattr(idaapi, "plan_to_apply_idasgn", None)
    except ImportError:
        fn = None
    if callable(fn):
        try:
            if int(fn(sig_path)) <= 0:
                raise ValueError(f"IDA refused signature file {sig_path!r}")
            return
        except ValueError:
            raise
        except Exception as e:
            raise ValueError(f"plan_to_apply_idasgn failed: {e}")
    raise ValueError("plan_to_apply_idasgn unavailable in this IDA version "
                     "(cannot queue .sig files for FLIRT)")


def _applied_sigs() -> list[dict]:
    """List applied signatures via ida_funcs.get_idasgn_* (public API)."""
    import ida_funcs
    qty_fn = getattr(ida_funcs, "get_idasgn_qty", None)
    if not callable(qty_fn):
        raise ValueError("get_idasgn_qty unavailable in this IDA version")
    try:
        qty = int(qty_fn())
    except Exception as e:
        raise ValueError(f"get_idasgn_qty failed: {e}")
    desc_fn = getattr(ida_funcs, "get_idasgn_desc_with_matches", None)
    plain_fn = getattr(ida_funcs, "get_idasgn_desc", None)
    out: list[dict] = []
    for i in range(qty):
        entry: dict = {"index": i}
        try:
            if callable(desc_fn):
                entry["desc"] = str(desc_fn(i))
            elif callable(plain_fn):
                entry["desc"] = str(plain_fn(i))
            else:
                entry["desc"] = None
        except Exception as e:
            entry["desc"] = None
            entry["error"] = str(e)
        out.append(entry)
    return out


@tool
@idasync
@unsafe
@tool_timeout(180.0)
def apply_flirt_signatures(sig_path: str) -> str:
    """Apply a FLIRT ``.sig`` file for library function recognition.

    **Unsafe** — requires ``?unsafe=true`` (renames functions in the IDB).
    Queues the file via ``plan_to_apply_idasgn``, waits for analysis, then
    verifies via the applied-signature list. Returns match info when IDA
    reports it. Generate ``.sig`` files from ``.pat`` with ``sigmake`` (ships
    with IDA); ``.pat`` generation itself is out of scope.
    """
    ida_auto.auto_wait()
    if not sig_path or not os.path.isfile(sig_path):
        return json.dumps({"sig_path": sig_path, "ok": False,
                           "error": f"File not found: {sig_path!r}"})
    try:
        before = _applied_sigs()
    except ValueError as e:
        return json.dumps({"sig_path": sig_path, "ok": False, "error": str(e)})
    try:
        _plan_apply_sig(sig_path)
    except ValueError as e:
        return json.dumps({"sig_path": sig_path, "ok": False, "error": str(e)})
    try:
        ida_auto.auto_wait()
    except Exception:
        pass
    try:
        after = _applied_sigs()
    except ValueError as e:
        return json.dumps({"sig_path": sig_path, "ok": False,
                           "error": f"Applied but could not verify: {e}"})
    before_descs = {s.get("desc") for s in before}
    new = [s for s in after if s.get("desc") not in before_descs]
    return json.dumps({"sig_path": sig_path, "ok": True,
                       "new_signatures": new, "total_applied": len(after)},
                      indent=2)


@tool
@idasync
def list_flirt_signatures() -> str:
    """List applied FLIRT signatures (library recognition state)."""
    ida_auto.auto_wait()
    try:
        sigs = _applied_sigs()
    except ValueError as e:
        return json.dumps({"error": str(e)})
    return json.dumps({"signatures": sigs, "count": len(sigs)}, indent=2)
