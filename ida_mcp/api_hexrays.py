"""Hex-Rays microcode / flowchart / recompile tools for ida_mcp.

``decompile_function`` (pseudocode) stays in ``server.py``; this module adds
the lower-level decompiler views: microcode maturity summary
(``get_microcode``), full flowcharts (``get_flowchart``), basic blocks with
instructions (``get_basic_blocks``) and cache-busting recompilation
(``force_recompile`` — the correct call after ``set_type`` instead of
re-calling decompile and hoping for a refresh).
"""
import json

import ida_auto
import ida_funcs
import ida_hexrays
import ida_lines
import idaapi
import idautils

from .rpc import tool
from .sync import (idasync, tool_timeout, check_cancelled,
                   CancelledError, IDASyncError)
from .api_analysis import parse_addr, _cap_lines


_MATURITY_NAMES = {
    0: "MMAT_ZERO",
    1: "MMAT_VARS",
    2: "MMAT_LVARS",
    3: "MMAT_BBLVARS",
    4: "MMAT_XMM",
    5: "MMAT_GENERATED",
}


def _resolve(address: str) -> tuple[int | None, str | None]:
    try:
        return parse_addr(address), None
    except ValueError as e:
        return None, json.dumps({"error": str(e)})


# ===========================================================================
# Tools
# ===========================================================================


@tool
@idasync
@tool_timeout(90.0)
def get_microcode(address: str) -> str:
    """Get a Hex-Rays microcode summary for the function at an address.

    Returns maturity level (how far the microcode pipeline got) and block
    count plus best-effort per-block bounds. Needs the Hex-Rays decompiler;
    returns a clean error otherwise. For full C pseudocode use
    ``decompile_function``.
    """
    ida_auto.auto_wait()
    ea, err = _resolve(address)
    if err:
        return err
    func = ida_funcs.get_func(ea)
    if not func:
        return json.dumps({"error": f"No function at {hex(ea)}"})
    try:
        available = ida_hexrays.init_hexrays_plugin()
    except Exception:
        available = False
    if not available:
        return json.dumps({"error": "Hex-Rays decompiler not available"})
    try:
        cfunc = ida_hexrays.decompile(func.start_ea)
    except Exception as e:
        return json.dumps({"error": f"Decompilation failed: {e}"})
    if cfunc is None:
        return json.dumps({"error": "Decompilation returned no result"})
    mba = getattr(cfunc, "mba", None)
    if mba is None:
        return json.dumps({"error": "Microcode (mba) unavailable for this function"})
    try:
        maturity = int(getattr(mba, "maturity", 0))
    except Exception:
        maturity = 0
    blocks: list[dict] = []
    try:
        nblocks = int(getattr(mba, "qty", 0))
    except Exception:
        nblocks = 0
    get_mblock = getattr(mba, "get_mblock", None)
    if callable(get_mblock):
        for i in range(min(nblocks, 5000)):
            try:
                mb = get_mblock(i)
            except Exception:
                break
            entry: dict = {"index": i}
            for attr in ("start", "end"):
                try:
                    val = getattr(mb, attr, None)
                    entry[attr] = hex(int(val)) if isinstance(val, int) else None
                except Exception:
                    entry[attr] = None
            blocks.append(entry)
    return json.dumps({
        "addr": hex(func.start_ea),
        "name": ida_funcs.get_func_name(func.start_ea) or "",
        "maturity": maturity,
        "maturity_name": _MATURITY_NAMES.get(maturity, f"MMAT_{maturity}"),
        "num_blocks": nblocks,
        "blocks": blocks,
    }, indent=2)


@tool
@idasync
@tool_timeout(90.0)
def get_flowchart(address: str) -> str:
    """Get the full control-flow graph (bounds + successors/predecessors + sizes).

    Uncapped-pagination alternative to ``basic_blocks``: returns every block
    up to 2000 (with a truncation flag) including per-block instruction counts.
    """
    ida_auto.auto_wait()
    ea, err = _resolve(address)
    if err:
        return err
    func = ida_funcs.get_func(ea)
    if not func:
        return json.dumps({"error": f"No function at {address}"})
    blocks: list[dict] = []
    truncated = False
    partial = False
    try:
        for i, block in enumerate(idaapi.FlowChart(func)):
            if i % 128 == 0:
                check_cancelled()
            if len(blocks) >= 2000:
                truncated = True
                break
            try:
                ninsns = sum(1 for _ in idautils.Heads(block.start_ea, block.end_ea))
            except Exception:
                ninsns = 0
            blocks.append({
                "start": hex(block.start_ea),
                "end": hex(block.end_ea),
                "size": block.end_ea - block.start_ea,
                "instructions": ninsns,
                "type": getattr(block, "type", None),
                "successors": [hex(s.start_ea) for s in block.succs()],
                "predecessors": [hex(p.start_ea) for p in block.preds()],
            })
    except (CancelledError, IDASyncError):
        partial = True
    except Exception as e:
        return json.dumps({"error": str(e)})
    out: dict = {"addr": hex(func.start_ea), "blocks": blocks,
               "count": len(blocks), "truncated": truncated}
    if partial:
        out["partial"] = True
    return json.dumps(out, indent=2)


@tool
@idasync
@tool_timeout(90.0)
def get_basic_blocks(address: str) -> str:
    """Get basic blocks with their disassembled instructions.

    Unlike ``basic_blocks`` (bounds + edges, paginated), each block carries
    its instruction lines (capped at 200 blocks × 100 instructions).
    """
    ida_auto.auto_wait()
    ea, err = _resolve(address)
    if err:
        return err
    func = ida_funcs.get_func(ea)
    if not func:
        return json.dumps({"error": f"No function at {address}"})
    blocks: list[dict] = []
    truncated = False
    partial_bb = False
    try:
        for i, block in enumerate(idaapi.FlowChart(func)):
            if i % 64 == 0:
                check_cancelled()
            if len(blocks) >= 200:
                truncated = True
                break
            insns: list[str] = []
            try:
                for head in idautils.Heads(block.start_ea, block.end_ea):
                    if len(insns) >= 100:
                        break
                    try:
                        text = ida_lines.tag_remove(
                            ida_lines.generate_disasm_line(head, 0) or "")
                    except Exception:
                        text = ""
                    insns.append(f"{hex(head)}: {text.strip()}")
            except Exception:
                pass
            blocks.append({"start": hex(block.start_ea), "end": hex(block.end_ea),
                           "instructions": insns})
    except (CancelledError, IDASyncError):
        partial_bb = True
    except Exception as e:
        return json.dumps({"error": str(e)})
    out_bb: dict = {"addr": hex(func.start_ea), "blocks": blocks,
                  "count": len(blocks), "truncated": truncated}
    if partial_bb:
        out_bb["partial"] = True
    return json.dumps(out_bb, indent=2)


@tool
@idasync
@tool_timeout(90.0)
def force_recompile(address: str) -> str:
    """Force Hex-Rays to discard cached pseudocode and recompile a function.

    Call this after ``set_type`` / renames instead of re-calling
    ``decompile_function`` and hoping the cache was invalidated. Output is
    capped at 500 lines (with ``truncated`` total when cut).
    """
    ida_auto.auto_wait()
    ea, err = _resolve(address)
    if err:
        return err
    func = ida_funcs.get_func(ea)
    if not func:
        return json.dumps({"error": f"No function at {hex(ea)}"})
    try:
        ida_hexrays.mark_cfunc_dirty(func.start_ea)
    except Exception:
        pass
    try:
        cfunc = ida_hexrays.decompile(func.start_ea)
    except Exception as e:
        return json.dumps({"error": f"Decompilation failed: {e}"})
    if cfunc is None:
        return json.dumps({"error": "Decompilation returned no result"})
    try:
        lines = [ida_lines.tag_remove(line.line) for line in cfunc.get_pseudocode()]
    except Exception as e:
        return json.dumps({"error": f"Could not read pseudocode: {e}"})
    code, total = _cap_lines("\n".join(lines), 500)
    result: dict = {"addr": hex(func.start_ea),
                    "name": ida_funcs.get_func_name(func.start_ea) or "",
                    "decompiled": code, "lines": len((code or '').split("\n"))}
    if total is not None:
        result["truncated"] = total
    return json.dumps(result, indent=2)


__all__ = [
    "get_microcode",
    "get_flowchart",
    "get_basic_blocks",
    "force_recompile",
]
