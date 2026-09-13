"""Composite analysis tools for ida_mcp.

Each tool aggregates multiple data sources into a single compact response so
the agent needs one call instead of chaining 6-8 atomic tools. Ported from
ida-pro-mcp ``api_composite.py`` / ``api_survey.py`` / ``api_analysis.py``
(func_profile, callgraph), adapted to the local conventions
(``@tool`` + ``@idasync``, JSON-string results, ``parse_addr``).
"""
import hashlib
import json
import re
import time
from collections import defaultdict, deque

import ida_auto
import ida_bytes
import ida_entry
import ida_funcs
import ida_hexrays
import ida_lines
import ida_nalt
import ida_typeinf
import ida_ua
import idaapi
import idautils
import idc

from .rpc import tool, unsafe
from .sync import (idasync, tool_timeout, get_tool_deadline, check_cancelled,
                   update_wait_box, CancelledError, IDASyncError)
from .api_analysis import parse_addr
from .compat import inf_is_64bit, is_loaded as _is_loaded


_DECOMPILE_LINE_CAP = 100
_TOP_STRINGS = 10
_TOP_CONSTANTS = 10
_BORING_CONSTANTS = frozenset({0, 1, -1, 0xFF, 0xFFFF, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF})
_MAX_TRACE_NODES = 200
_MAX_TRACE_EDGES = 500
_MAX_FUNC_ITER = 10_000
_MAX_STRING_ITER = 5_000
_MAX_XREFS_PER_STRING = 200

_IMPORT_CATEGORIES: list[tuple[str, re.Pattern]] = [
    ("crypto", re.compile(r"crypt|aes|sha[^r]|md5|hash|rsa|\bssl\b|\btls\b|\bcert", re.IGNORECASE)),
    ("network", re.compile(r"socket|connect|send|recv|http|url|internet|ws2|winsock", re.IGNORECASE)),
    ("process", re.compile(r"process|thread|terminate|execute|shell|pipe|virtual", re.IGNORECASE)),
    ("registry", re.compile(r"reg|registry|hkey", re.IGNORECASE)),
    ("file_io", re.compile(r"file|path|directory|fopen|fclose|fread|fwrite|readfile|writefile|deletefile|createfile", re.IGNORECASE)),
]


# ---------------------------------------------------------------------------
# Internal helpers (no @tool — called from within @idasync context)
# ---------------------------------------------------------------------------

def _func_prototype(func) -> str | None:
    """C prototype string for ``func`` or None when no type info exists."""
    tif = ida_typeinf.tinfo_t()
    if not ida_nalt.get_tinfo(tif, func.start_ea):
        return None
    if not tif.is_func():
        return None
    ftd = ida_typeinf.func_type_data_t()
    if not tif.get_func_details(ftd):
        return None
    fn_name = ida_funcs.get_func_name(func.start_ea) or "<unnamed>"
    args = ", ".join(f"{a.type} {a.name if a.name else ''}".strip() for a in ftd)
    return f"{ftd.rettype} {fn_name}({args})"


def _decompile_capped(ea: int, cap: int = _DECOMPILE_LINE_CAP) -> tuple:
    """Decompile ``ea``; returns (code|None, total_lines|None, error|None)."""
    try:
        cfunc = ida_hexrays.decompile(ea)
    except Exception as e:
        return None, None, f"Decompilation failed: {e}"
    if cfunc is None:
        return None, None, "Decompilation returned no result"
    lines = [ida_lines.tag_remove(line.line) for line in cfunc.get_pseudocode()]
    total = len(lines)
    if total <= cap:
        return "\n".join(lines), None, None
    return "\n".join(lines[:cap]), total, None


def _func_strings(ea: int, limit: int = _TOP_STRINGS) -> list[str]:
    """String values referenced by the function at ``ea`` (dedup, capped)."""
    func = ida_funcs.get_func(ea)
    if not func:
        return []
    seen: set[str] = set()
    out: list[str] = []
    for head in idautils.FuncItems(func.start_ea):
        for xref in idautils.XrefsFrom(head, 0):
            if xref.iscode:
                continue
            try:
                raw = ida_bytes.get_strlit_contents(xref.to, -1, ida_nalt.STRTYPE_C)
            except Exception:
                continue
            if not raw:
                continue
            try:
                val = raw.decode("utf-8", errors="replace")
            except Exception:
                continue
            if val and val not in seen:
                seen.add(val)
                out.append(val)
                if len(out) >= limit:
                    return out
    return out


def _func_constants(ea: int, limit: int = _TOP_CONSTANTS) -> list[dict]:
    """Non-trivial immediate constants used by the function at ``ea``."""
    func = ida_funcs.get_func(ea)
    if not func:
        return []
    found: dict[int, int] = {}
    for head in idautils.FuncItems(func.start_ea):
        insn = ida_ua.insn_t()
        if ida_ua.decode_insn(insn, head) <= 0:
            continue
        for op in insn.ops:
            if op.type == ida_ua.o_void:
                continue
            if op.type == ida_ua.o_imm:
                val = op.value & ((1 << (insn.size * 8)) - 1) if insn.size else op.value
                # Sign-extend to 64 bits for filtering/sorting.
                if val >= (1 << 63):
                    val -= 1 << 64
                if abs(val) < 0x100 or val in _BORING_CONSTANTS:
                    continue
                found[val] = head
    top = sorted(found, key=abs, reverse=True)[:limit]
    return [{"value": hex(v & 0xFFFFFFFFFFFFFFFF), "first_seen_at": hex(found[v])} for v in top]


def _callee_list(func) -> list[dict]:
    """``[{addr, name}]`` callees of ``func`` (code refs to functions)."""
    seen: dict[int, str] = {}
    for head in idautils.FuncItems(func.start_ea):
        for ref in idautils.CodeRefsFrom(head, 0):
            callee = ida_funcs.get_func(ref)
            if callee and callee.start_ea not in seen:
                seen[callee.start_ea] = ida_funcs.get_func_name(callee.start_ea) or ""
    return [{"addr": hex(ea), "name": name} for ea, name in sorted(seen.items())]


def _caller_list(func) -> list[dict]:
    """``[{addr, name}]`` callers of ``func``."""
    seen: dict[int, str] = {}
    for xref in idautils.XrefsTo(func.start_ea, 0):
        if xref.type not in (idaapi.fl_CF, idaapi.fl_CN):
            continue
        caller = ida_funcs.get_func(xref.frm)
        if caller and caller.start_ea not in seen:
            seen[caller.start_ea] = ida_funcs.get_func_name(caller.start_ea) or ""
    return [{"addr": hex(ea), "name": name} for ea, name in sorted(seen.items())]


def _block_info(func) -> dict:
    """``{count, cyclomatic_complexity}`` for ``func``."""
    try:
        nodes = 0
        edges = 0
        for block in idaapi.FlowChart(func):
            nodes += 1
            for _ in block.succs():
                edges += 1
        return {"count": nodes, "cyclomatic_complexity": edges - nodes + 2}
    except Exception:
        return {"count": 0, "cyclomatic_complexity": 0}


def _func_comments(ea: int) -> dict:
    func = ida_funcs.get_func(ea)
    out: dict = {"regular": None, "repeatable": None, "function": None}
    try:
        out["regular"] = ida_bytes.get_cmt(ea, False) or None
        out["repeatable"] = ida_bytes.get_cmt(ea, True) or None
    except Exception:
        pass
    if func:
        try:
            out["function"] = ida_funcs.get_func_cmt(func, False) or None
        except Exception:
            pass
    return out


def _normalize_addr_list(value) -> list[str]:
    if isinstance(value, str):
        return [a.strip() for a in value.split(",") if a.strip()]
    if isinstance(value, (list, tuple)):
        return [str(a) for a in value]
    return [str(value)]


# ===========================================================================
# Tools
# ===========================================================================


@tool
@idasync
@tool_timeout(120.0)
def analyze_function(address: str, include_asm: bool = False) -> str:
    """Compact single-function analysis: pseudocode (capped), strings, constants, callers, callees, xrefs, blocks.

    Prefer this over chaining ``decompile_function`` + ``get_callees`` +
    ``get_callers`` + ``basic_blocks``. Pass ``include_asm=True`` to also
    include full disassembly (costs tokens).
    """
    ida_auto.auto_wait()
    try:
        ea = parse_addr(address)
    except ValueError as e:
        return json.dumps({"addr": address, "error": str(e)})

    func = ida_funcs.get_func(ea)
    if not func:
        return json.dumps({"addr": hex(ea), "error": f"No function at {hex(ea)}"})

    code, total_lines, decompile_err = _decompile_capped(func.start_ea)
    result: dict = {
        "addr": hex(func.start_ea),
        "name": ida_funcs.get_func_name(func.start_ea) or "",
        "prototype": _func_prototype(func),
        "size": func.end_ea - func.start_ea,
        "decompiled": code,
        "strings": _func_strings(func.start_ea),
        "constants": _func_constants(func.start_ea),
        "callees": [c["name"] or c["addr"] for c in _callee_list(func)],
        "callers": [c["name"] or c["addr"] for c in _caller_list(func)],
        "comments": _func_comments(func.start_ea),
        "basic_blocks": _block_info(func),
        "error": None,
    }
    if decompile_err:
        result["decompile_error"] = decompile_err
    if total_lines is not None:
        result["decompile_truncated"] = total_lines
    if include_asm:
        try:
            result["assembly"] = "\n".join(
                f"{hex(h)}: {ida_lines.tag_remove(ida_lines.generate_disasm_line(h, 0) or '')}"
                for h in idautils.FuncItems(func.start_ea)
            )
        except Exception:
            result["assembly"] = None
    return json.dumps(result, indent=2)


@tool
@idasync
@tool_timeout(120.0)
def func_profile(address: str, include_lists: bool = False,
                 max_items: int = 20, include_prototype: bool = True) -> str:
    """Numeric profile of a function: sizes, counts, lists (no decompilation).

    Cheaper than ``analyze_function`` when pseudocode is not needed.
    ``max_items`` caps each list when ``include_lists`` is true.
    """
    ida_auto.auto_wait()
    try:
        ea = parse_addr(address)
    except ValueError as e:
        return json.dumps({"addr": address, "error": str(e)})

    func = ida_funcs.get_func(ea)
    if not func:
        return json.dumps({"addr": hex(ea), "error": "Function not found"})

    tif = ida_typeinf.tinfo_t()
    has_type = bool(ida_nalt.get_tinfo(tif, func.start_ea))
    callees = _callee_list(func)
    callers = _caller_list(func)
    strings = _func_strings(func.start_ea, limit=100000)
    constants = _func_constants(func.start_ea, limit=100000)
    size = func.end_ea - func.start_ea

    out: dict = {
        "addr": hex(func.start_ea),
        "name": ida_funcs.get_func_name(func.start_ea) or "<unnamed>",
        "size": hex(size),
        "size_int": size,
        "instruction_count": sum(1 for _ in idautils.FuncItems(func.start_ea)),
        "basic_block_count": _block_info(func)["count"],
        "caller_count": len(callers),
        "callee_count": len(callees),
        "string_ref_count": len(strings),
        "constant_count": len(constants),
        "has_type": has_type,
        "prototype": _func_prototype(func) if include_prototype else None,
        "error": None,
    }
    if include_lists:
        if max_items <= 0:
            max_items = 20
        out["callers"] = callers[:max_items]
        out["callers_truncated"] = len(callers) > max_items
        out["callees"] = callees[:max_items]
        out["callees_truncated"] = len(callees) > max_items
        out["strings"] = strings[:max_items]
        out["strings_truncated"] = len(strings) > max_items
        out["constants"] = constants[:max_items]
        out["constants_truncated"] = len(constants) > max_items
    return json.dumps(out, indent=2)


@tool
@idasync
@tool_timeout(180.0)
def analyze_component(addresses: str) -> str:
    """Analyze related functions as a group: per-function summaries, internal call graph, shared data.

    ``addresses`` is a comma-separated list of function addresses/names.
    No decompilation — compact output with prototypes, callees, strings,
    block counts, internal edges, shared globals, interface vs internal
    classification and cross-function string usage.
    """
    ida_auto.auto_wait()
    raw = _normalize_addr_list(addresses)
    if not raw:
        return json.dumps({"error": "Empty address list"})

    ea_set: set[int] = set()
    for a in raw:
        try:
            ea = parse_addr(a)
        except ValueError:
            return json.dumps({"error": f"Cannot resolve address: {a!r}"})
        func = ida_funcs.get_func(ea)
        ea_set.add(func.start_ea if func else ea)

    functions: list[dict] = []
    for ea in sorted(ea_set):
        func = ida_funcs.get_func(ea)
        if func is None:
            functions.append({"addr": hex(ea), "error": "No function"})
            continue
        callees = _callee_list(func)
        bb = _block_info(func)
        functions.append({
            "addr": hex(ea),
            "name": ida_funcs.get_func_name(ea) or "",
            "prototype": _func_prototype(func),
            "size": func.end_ea - func.start_ea,
            "callees": [c["name"] or c["addr"] for c in callees],
            "strings": _func_strings(ea, limit=5),
            "basic_blocks": bb["count"],
            "complexity": bb["cyclomatic_complexity"],
        })

    edges: list[dict] = []
    for ea in sorted(ea_set):
        func = ida_funcs.get_func(ea)
        if not func:
            continue
        for callee in _callee_list(func):
            try:
                callee_ea = int(callee["addr"], 16)
            except (ValueError, TypeError):
                continue
            if callee_ea in ea_set:
                edges.append({"from": hex(ea), "to": hex(callee_ea), "name": callee["name"]})

    func_globals: dict[int, set[int]] = {}
    for ea in sorted(ea_set):
        accessed: set[int] = set()
        func = ida_funcs.get_func(ea)
        if func is not None:
            for head in idautils.FuncItems(func.start_ea):
                for xref in idautils.XrefsFrom(head, 0):
                    if xref.iscode:
                        continue
                    if ida_funcs.get_func(xref.to) is None and _is_loaded(xref.to):
                        accessed.add(xref.to)
        func_globals[ea] = accessed

    refcount: dict[int, list[str]] = defaultdict(list)
    for ea, gset in func_globals.items():
        fname = ida_funcs.get_func_name(ea) or hex(ea)
        for g in gset:
            refcount[g].append(fname)
    shared_globals = [
        {"addr": hex(g), "name": idaapi.get_name(g) or hex(g), "accessed_by": sorted(fns)}
        for g, fns in sorted(refcount.items()) if len(fns) >= 2
    ]

    interface_functions: list[str] = []
    internal_only: list[str] = []
    for ea in sorted(ea_set):
        func = ida_funcs.get_func(ea)
        callers = _caller_list(func) if func is not None else []
        external = False
        for c in callers:
            try:
                if int(c["addr"], 16) not in ea_set:
                    external = True
                    break
            except (ValueError, TypeError, KeyError):
                external = True
                break
        (interface_functions if external else internal_only).append(hex(ea))

    string_funcs: dict[str, set[str]] = defaultdict(set)
    for ea in sorted(ea_set):
        fname = ida_funcs.get_func_name(ea) or hex(ea)
        for s in _func_strings(ea, limit=100000):
            string_funcs[s].add(fname)
    string_usage = {s: sorted(fns) for s, fns in sorted(string_funcs.items()) if len(fns) >= 2}

    return json.dumps({
        "functions": functions,
        "internal_call_graph": {
            "nodes": [hex(ea) for ea in sorted(ea_set)],
            "edges": edges,
        },
        "shared_globals": shared_globals,
        "interface_functions": interface_functions,
        "internal_only": internal_only,
        "string_usage": string_usage,
    }, indent=2)


@tool
@idasync
@unsafe
@tool_timeout(120.0)
def diff_before_after(address: str, action: str, action_args: str = "{}") -> str:
    """Apply a rename/type/comment and immediately see before/after decompilation.

    **Unsafe** — requires ``?unsafe=true``. ``action`` is one of
    ``rename_func`` (``action_args``: ``{\"name\": ...}``),
    ``set_comment`` (``{\"comment\": ...}``) or ``set_type``
    (``{\"type\": \"int __cdecl f(int)\"}``). ``action_args`` is a JSON object
    string. Returns ``{before, after, action_applied, changes_detected}``.
    """
    ida_auto.auto_wait()
    if action not in ("rename_func", "set_type", "set_comment"):
        return json.dumps({"error": f"Invalid action {action!r}"})
    try:
        ea = parse_addr(address)
    except ValueError as e:
        return json.dumps({"error": str(e)})
    func = ida_funcs.get_func(ea)
    if not func:
        return json.dumps({"error": f"No function at {hex(ea)}"})
    try:
        args = json.loads(action_args) if isinstance(action_args, str) else dict(action_args)
    except Exception as e:
        return json.dumps({"error": f"Invalid action_args JSON: {e}"})

    before, _, before_err = _decompile_capped(func.start_ea)
    if before is None:
        return json.dumps({"error": before_err or "Could not decompile before state"})

    try:
        if action == "rename_func":
            name = args.get("name")
            if not name:
                return json.dumps({"error": "action_args must contain 'name'"})
            import ida_name
            if not ida_name.set_name(func.start_ea, name, ida_name.SN_NOWARN):
                return json.dumps({"error": f"set_name failed for {name!r}"})
            applied = f"Renamed to {name!r}"
        elif action == "set_comment":
            if "comment" not in args:
                return json.dumps({"error": "action_args must contain 'comment'"})
            ida_bytes.set_cmt(func.start_ea, args["comment"], False)
            applied = f"Set comment: {args['comment']!r}"
        else:  # set_type
            type_str = args.get("type")
            if not type_str:
                return json.dumps({"error": "action_args must contain 'type'"})
            tif = ida_typeinf.tinfo_t()
            til = ida_typeinf.get_idati()
            try:
                ok = ida_typeinf.parse_decl(tif, til, str(type_str), 0)
            except Exception as e:
                return json.dumps({"error": f"Failed to parse type: {e}"})
            if not ok:
                return json.dumps({"error": f"Failed to parse type {type_str!r}"})
            if not ida_typeinf.apply_tinfo(func.start_ea, tif, ida_typeinf.TINFO_DEFINITE):
                return json.dumps({"error": f"Failed to apply type at {hex(func.start_ea)}"})
            applied = f"Set type to {type_str!r}"
    except Exception as e:
        return json.dumps({"error": f"Action {action!r} failed: {e}"})

    try:
        ida_hexrays.mark_cfunc_dirty(func.start_ea)
    except Exception:
        pass
    after, _, _ = _decompile_capped(func.start_ea)
    return json.dumps({
        "before": before,
        "after": after,
        "action_applied": applied,
        "changes_detected": before != after,
    }, indent=2)


@tool
@idasync
@tool_timeout(120.0)
def trace_data_flow(address: str, direction: str = "forward", max_depth: int = 5) -> str:
    """Follow xrefs from/to an address across multiple hops (BFS).

    ``direction`` is ``forward`` (xrefs-from: where data flows TO) or
    ``backward`` (xrefs-to: where data flows FROM). ``max_depth`` is clamped
    to [1, 20]; traversal is capped at 200 nodes / 500 edges. Each node
    carries function, instruction, code/data type and depth.
    """
    ida_auto.auto_wait()
    if direction not in ("forward", "backward"):
        return json.dumps({"error": f"direction must be 'forward' or 'backward', got {direction!r}"})
    try:
        start_ea = parse_addr(address)
    except ValueError as e:
        return json.dumps({"error": str(e)})
    max_depth = max(1, min(int(max_depth), 20))

    visited: set[int] = {start_ea}
    nodes: list[dict] = []
    edges: list[dict] = []
    depth_reached = 0
    partial = False
    queue: deque = deque([(start_ea, 0)])
    pops = 0

    try:
        while queue and len(nodes) < _MAX_TRACE_NODES:
            ea, depth = queue.popleft()
            pops += 1
            if pops % 32 == 0:
                check_cancelled()
            if depth > max_depth:
                continue
            depth_reached = max(depth_reached, depth)
            func = ida_funcs.get_func(ea)
            try:
                insn_text = idc.GetDisasm(ea) if _is_loaded(ea) else None
            except Exception:
                insn_text = None
            try:
                name_at = idaapi.get_name(ea) or None
            except Exception:
                name_at = None
            nodes.append({
                "addr": hex(ea),
                "func": ida_funcs.get_func_name(ea) if func else None,
                "instruction": insn_text,
                "type": "code" if func is not None or not _is_loaded(ea) else "data",
                "name": name_at,
                "depth": depth,
            })
            if depth >= max_depth:
                continue
            try:
                xrefs = list(idautils.XrefsFrom(ea, 0) if direction == "forward" else idautils.XrefsTo(ea, 0))
            except Exception:
                continue
            for xref in xrefs:
                if len(edges) >= _MAX_TRACE_EDGES:
                    break
                target = xref.to if direction == "forward" else xref.frm
                xtype = "code" if xref.iscode else "data"
                if direction == "forward":
                    edges.append({"from": hex(ea), "to": hex(target), "type": xtype})
                else:
                    edges.append({"from": hex(target), "to": hex(ea), "type": xtype})
                if target not in visited and len(nodes) + len(queue) < _MAX_TRACE_NODES:
                    visited.add(target)
                    queue.append((target, depth + 1))
    except (CancelledError, IDASyncError):
        partial = True

    out: dict = {
        "start": hex(start_ea),
        "direction": direction,
        "depth_reached": depth_reached,
        "nodes": nodes,
        "edges": edges,
    }
    if partial:
        out["partial"] = True
    return json.dumps(out, indent=2)


@idasync
@tool_timeout(120.0)
def _fetch_callgraph_root(root: str, max_depth: int, max_nodes: int,
                          max_edges: int, max_edges_per_func: int,
                          progress: str = "") -> dict:
    """Single-root call-graph collection (one bounded main-thread hop)."""
    ida_auto.auto_wait()
    if progress:
        update_wait_box(f"callgraph {progress}")
    try:
        ea = parse_addr(root)
    except ValueError:
        return {"root": root, "error": "Function not found", "nodes": [], "edges": []}
    if not ida_funcs.get_func(ea):
        return {"root": root, "error": "Function not found", "nodes": [], "edges": []}

    nodes: dict[str, dict] = {}
    edges: list[dict] = []
    visited: set[int] = set()
    truncated = False
    limit_reason: str | None = None
    per_func_capped = False
    visit_count = [0]

    def traverse(addr: int, depth: int) -> None:
        nonlocal truncated, limit_reason, per_func_capped
        if truncated or depth > max_depth or addr in visited:
            return
        if len(nodes) >= max_nodes:
            truncated = True
            limit_reason = "nodes"
            return
        visit_count[0] += 1
        if visit_count[0] % 64 == 0:
            check_cancelled()
        visited.add(addr)
        f = ida_funcs.get_func(addr)
        if not f:
            return
        nodes[hex(addr)] = {
            "addr": hex(addr),
            "name": ida_funcs.get_func_name(f.start_ea) or "",
            "depth": depth,
        }
        added = 0
        for item_ea in idautils.FuncItems(f.start_ea):
            if truncated:
                break
            for ref in idautils.CodeRefsFrom(item_ea, 0):
                if truncated:
                    break
                if added >= max_edges_per_func:
                    per_func_capped = True
                    break
                callee = ida_funcs.get_func(ref)
                if not callee:
                    continue
                if len(edges) >= max_edges:
                    truncated = True
                    limit_reason = "edges"
                    break
                edges.append({"from": hex(addr), "to": hex(callee.start_ea)})
                added += 1
                traverse(callee.start_ea, depth + 1)

    try:
        traverse(ea, 0)
    except (CancelledError, IDASyncError):
        truncated = True
        limit_reason = "cancelled"
    return {
        "root": root,
        "nodes": list(nodes.values()),
        "edges": edges,
        "truncated": truncated,
        "limit_reason": limit_reason,
        "per_func_capped": per_func_capped,
    }


_CALLGRAPH_BUDGET_SEC = 120.0


@tool
def callgraph(roots: str, max_depth: int = 5, max_nodes: int = 1000,
              max_edges: int = 5000, max_edges_per_func: int = 200) -> str:
    """Build a bounded call graph from root functions.

    ``roots`` is a comma-separated list of function addresses/names.
    Limits (clamped to the official maxima): depth, 100k nodes, 200k edges,
    5k edges per function. Returns per-root ``{nodes, edges}`` with depth
    annotations plus truncation flags.

    Two-phase: each root is collected in its own bounded main-thread hop
    (_fetch_callgraph_root) so the UI breathes between roots; JSON
    rendering runs here on the HTTP worker thread. A 120 s worker-side
    budget bounds the whole call (previously the single-hop timeout).
    """
    max_depth = max(0, int(max_depth))
    max_nodes = min(max(int(max_nodes), 1), 100000)
    max_edges = min(max(int(max_edges), 1), 200000)
    max_edges_per_func = min(max(int(max_edges_per_func), 1), 5000)

    names = _normalize_addr_list(roots)
    graphs: list[dict] = []
    start = time.monotonic()
    for i, root in enumerate(names):
        if time.monotonic() - start >= _CALLGRAPH_BUDGET_SEC:
            graphs.append({"root": root, "error":
                           f"Tool budget exceeded ({_CALLGRAPH_BUDGET_SEC:.0f}s); "
                           "retry with fewer roots",
                           "nodes": [], "edges": []})
            continue
        label = f"{i + 1}/{len(names)}" if len(names) > 1 else ""
        graphs.append(_fetch_callgraph_root(root, max_depth, max_nodes,
                                            max_edges, max_edges_per_func,
                                            progress=label))
    return json.dumps({"graphs": graphs}, indent=2)


@idasync
@tool_timeout(120.0)
def _fetch_survey_raw(detail_level: str) -> dict:
    """Main-thread collection half of survey_binary (IDA SDK only).

    Must stay free of disk I/O and heavy pure-Python work: file hashing,
    import categorization and JSON rendering run on the HTTP worker thread
    in survey_binary(). Returns a plain dict (not JSON); keys starting with
    ``_`` are private and consumed by the outer tool.
    """
    ida_auto.auto_wait()
    minimal = detail_level == "minimal"

    all_func_eas = list(idautils.Functions())
    truncated = len(all_func_eas) > _MAX_FUNC_ITER
    func_eas = all_func_eas[:_MAX_FUNC_ITER] if truncated else all_func_eas

    try:
        idb_path = idc.get_idb_path() or ""
    except Exception:
        idb_path = ""
    try:
        input_path = ida_nalt.get_input_file_path() or ""
    except Exception:
        input_path = ""
    try:
        module = ida_nalt.get_root_filename() or ""
    except Exception:
        module = ""
    # NOTE: file hashing is deferred to the worker thread (survey_binary).
    # Reading + hashing a large binary is pure I/O with zero IDA calls and
    # must not hold the main thread (UI freeze).
    md5 = sha256 = "unavailable"
    try:
        base = idaapi.get_imagebase()
    except Exception:
        base = 0

    total = len(all_func_eas)
    named = library = unnamed = 0
    for ea in all_func_eas:
        try:
            name = idc.get_name(ea) or ""
        except Exception:
            name = ""
        func = ida_funcs.get_func(ea)
        flags = func.flags if func else 0
        if name.startswith("sub_"):
            unnamed += 1
        elif flags & idaapi.FUNC_LIB:
            library += 1
        else:
            named += 1

    segments: list[dict] = []
    try:
        import ida_segment
        for seg_ea in idautils.Segments():
            seg = idaapi.getseg(seg_ea)
            if not seg:
                continue
            perms = "".join([
                "r" if seg.perm & idaapi.SEGPERM_READ else "-",
                "w" if seg.perm & idaapi.SEGPERM_WRITE else "-",
                "x" if seg.perm & idaapi.SEGPERM_EXEC else "-",
            ])
            segments.append({
                "name": ida_segment.get_segm_name(seg) or "",
                "start": hex(seg.start_ea),
                "end": hex(seg.end_ea),
                "size": hex(seg.end_ea - seg.start_ea),
                "permissions": perms,
            })
    except Exception:
        pass

    entrypoints: list[dict] = []
    try:
        qty = ida_entry.get_entry_qty()
        for i in range(qty):
            ordinal = ida_entry.get_entry_ordinal(i)
            entrypoints.append({
                "addr": hex(ida_entry.get_entry(ordinal)),
                "name": ida_entry.get_entry_name(ordinal) or "",
                "ordinal": ordinal,
            })
    except Exception:
        pass

    result: dict = {
        "metadata": {
            "path": idb_path,
            "module": module,
            "arch": "64" if inf_is_64bit() else "32",
            "base_address": hex(base),
            "md5": md5,
            "sha256": sha256,
        },
        "statistics": {
            "total_functions": total,
            "named_functions": named,
            "library_functions": library,
            "unnamed_functions": unnamed,
            "total_segments": len(segments),
        },
        "segments": segments,
        "entrypoints": entrypoints,
    }

    if not minimal:
        str_cache: list[tuple[int, str]] = []
        try:
            for si in idautils.Strings():
                str_cache.append((si.ea, str(si)))
                if len(str_cache) >= _MAX_STRING_ITER:
                    break
        except Exception:
            pass
        result["statistics"]["total_strings"] = len(str_cache)
        scored: list[tuple[int, int, str]] = []
        strings_partial = False
        deadline = get_tool_deadline()
        for i, (ea, s) in enumerate(str_cache):
            if deadline is not None and time.monotonic() >= deadline:
                strings_partial = True
                break
            if i % 64 == 0:
                try:
                    check_cancelled()
                except (CancelledError, IDASyncError):
                    strings_partial = True
                    break
            try:
                n = sum(1 for _ in idautils.XrefsTo(ea, 0))
            except Exception:
                n = 0
            if n:
                scored.append((n, ea, s))
        scored.sort(key=lambda t: t[0], reverse=True)
        result["interesting_strings"] = [
            {"addr": hex(ea), "string": s, "xref_count": n} for n, ea, s in scored[:15]
        ]
        if strings_partial:
            result["interesting_strings_partial"] = True

        survey_cancelled = False
        candidates: list[tuple[int, int, str, int]] = []
        for i, ea in enumerate(func_eas):
            if i % 64 == 0:
                try:
                    check_cancelled()
                except (CancelledError, IDASyncError):
                    survey_cancelled = True
                    break
            func = ida_funcs.get_func(ea)
            if not func or (func.flags & idaapi.FUNC_LIB):
                continue
            try:
                name = idc.get_name(ea) or ""
            except Exception:
                name = ""
            try:
                nx = sum(1 for _ in idautils.XrefsTo(ea, 0))
            except Exception:
                nx = 0
            candidates.append((nx, ea, name, func.end_ea - func.start_ea))
        candidates.sort(key=lambda t: t[0], reverse=True)
        interesting: list[dict] = []
        for nx, ea, name, size in candidates[:15]:
            func = ida_funcs.get_func(ea)
            n_callees = len(_callee_list(func)) if func else 0
            if func is not None and (func.flags & idaapi.FUNC_THUNK or size <= 8):
                kind = "thunk"
            elif n_callees == 1 and size < 100:
                kind = "wrapper"
            elif n_callees == 0:
                kind = "leaf"
            elif n_callees > 10:
                kind = "dispatcher"
            else:
                kind = "complex"
            interesting.append({
                "addr": hex(ea), "name": name, "size": size,
                "xref_count": nx, "callee_count": n_callees, "type": kind,
            })
        result["interesting_functions"] = interesting

        # Raw import rows only; the regex categorization is pure Python and
        # runs on the worker thread (survey_binary) to free the main thread.
        imports_raw: list[tuple[str, list[tuple[int, str]]]] = []
        try:
            nimps = ida_nalt.get_import_module_qty()
            for i in range(nimps):
                mod_name = ida_nalt.get_import_module_name(i) or "<unnamed>"
                collected: list[tuple[int, str]] = []

                def _cb(ea: int, sym: str | None, ordinal: int) -> bool:
                    collected.append((ea, sym or f"#{ordinal}"))
                    return True

                ida_nalt.enum_import_names(i, _cb)
                imports_raw.append((mod_name, collected))
        except Exception:
            pass
        result["_imports_raw"] = imports_raw

        total_edges = 0
        roots: list[str] = []
        leaves = 0
        for i, ea in enumerate(func_eas):
            if i % 64 == 0:
                try:
                    check_cancelled()
                except (CancelledError, IDASyncError):
                    survey_cancelled = True
                    break
            has_callers = has_callees = False
            try:
                for xref in idautils.XrefsTo(ea, 0):
                    if xref.type in (idaapi.fl_CF, idaapi.fl_CN):
                        has_callers = True
                        break
                func = ida_funcs.get_func(ea)
                if func:
                    for item in idautils.FuncItems(func.start_ea):
                        for xref in idautils.XrefsFrom(item, 0):
                            if xref.type in (idaapi.fl_CF, idaapi.fl_CN):
                                total_edges += 1
                                has_callees = True
            except Exception:
                pass
            if not has_callers:
                try:
                    roots.append(idc.get_name(ea) or hex(ea))
                except Exception:
                    roots.append(hex(ea))
            if not has_callees:
                leaves += 1
        result["call_graph_summary"] = {
            "total_edges": total_edges,
            "max_depth_estimate": None,
            "root_functions": roots[:100],
            "leaf_functions_count": leaves,
        }
        if survey_cancelled:
            result["partial"] = True

    if truncated:
        result["_note"] = (
            f"Binary has {len(all_func_eas)} functions; "
            f"xref analysis was limited to the first {_MAX_FUNC_ITER} for performance."
        )
    result["_input_path"] = input_path
    return result


def _hash_file_chunked(path: str) -> tuple[str, str] | None:
    """MD5 + SHA-256 of ``path`` in 1 MiB chunks (worker thread, no IDA)."""
    try:
        h_md5, h_sha = hashlib.md5(), hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h_md5.update(chunk)
                h_sha.update(chunk)
        return h_md5.hexdigest(), h_sha.hexdigest()
    except Exception:
        return None


def _categorize_imports(
    imports_raw: list[tuple[str, list[tuple[int, str]]]],
) -> dict[str, list[dict]]:
    """Bucket raw import rows into categories (worker thread, pure Python)."""
    categories: dict[str, list[dict]] = {
        "crypto": [], "network": [], "file_io": [],
        "process": [], "registry": [], "other": [],
    }
    for mod_name, collected in imports_raw:
        for ea, sym in collected:
            cat = "other"
            for cname, rx in _IMPORT_CATEGORIES:
                if rx.search(sym):
                    cat = cname
                    break
            categories[cat].append({"addr": hex(ea), "name": sym, "module": mod_name})
    return categories


@tool
def survey_binary(detail_level: str = "standard") -> str:
    """Complete binary triage in one call — use as the FIRST tool when starting analysis.

    Returns metadata (path, arch, base, hashes), statistics, segments, entry
    points plus, unless ``detail_level='minimal'``: top-15 strings/functions
    by xref count (with thunk/wrapper/leaf/dispatcher/complex classification),
    imports by category (crypto/network/file_io/process/registry/other) and a
    call-graph summary. Do not call ``list_funcs``/``list_imports`` separately
    for triage — this covers them.

    Two-phase: IDA SDK collection runs on the main thread
    (_fetch_survey_raw); file hashing, import categorization and JSON
    rendering run here on the HTTP worker thread so the UI stays free.
    """
    data = _fetch_survey_raw(detail_level)
    input_path = data.pop("_input_path", "")
    imports_raw = data.pop("_imports_raw", None)
    if input_path:
        hashes = _hash_file_chunked(input_path)
        if hashes is not None:
            data["metadata"]["md5"], data["metadata"]["sha256"] = hashes
    if imports_raw is not None:
        data["imports_by_category"] = _categorize_imports(imports_raw)
    return json.dumps(data, indent=2)


__all__ = [
    "analyze_function",
    "func_profile",
    "analyze_component",
    "diff_before_after",
    "trace_data_flow",
    "callgraph",
    "survey_binary",
]
