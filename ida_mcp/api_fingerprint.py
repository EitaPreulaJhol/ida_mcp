"""Function fingerprints and portable diff snapshots.

The exact hash is over the function's bytes; the shape hash normalizes
addresses/names so identical compiler output can be matched across copies.
The snapshot is intentionally a plain JSON file: IDA can only have one
database open per process, so a diff between two IDBs is produced from two
snapshots, never by opening the second IDB beside the live one.
"""
import hashlib
import json
import os
import tempfile
from collections import defaultdict

import ida_bytes
import ida_funcs
import ida_loader
import ida_ua
import idaapi
import idautils

from .api_analysis import resolve_addr, _as_int
from .rpc import tool, unsafe
from .sync import idasync, ensure_analysis, check_cancelled, CancelledError, IDASyncError


SCHEMA = "ida-mcp-fingerprints"
SCHEMA_VERSION = 1
ALGORITHM = "ida_mcp_fp_v1"
MAX_FUNCTIONS = 100000


def _hash_bytes(func) -> str:
    h = hashlib.sha256()
    size = max(0, int(func.end_ea - func.start_ea))
    for off in range(0, size, 4096):
        chunk = ida_bytes.get_bytes(func.start_ea + off, min(4096, size - off))
        h.update(chunk or b"")
    return h.hexdigest()


def _shape_for(func) -> tuple[str, int, int, int]:
    """Return ``(shape_hash, instructions, blocks, edges)`` for one func."""
    h = hashlib.sha256()
    instructions = calls = 0
    for ea in idautils.FuncItems(func.start_ea):
        instructions += 1
        insn = ida_ua.insn_t()
        if ida_ua.decode_insn(insn, ea) == 0:
            h.update(b"?|")
            continue
        mnem = insn.get_canon_mnem()
        if mnem == "call":
            calls += 1
        h.update(mnem.encode("utf-8", "replace"))
        h.update(b"|")
        h.update(str(insn.size).encode())
        h.update(b"|")
        for op in insn.ops:
            if op.type == ida_ua.o_void:
                break
            h.update(str(op.type).encode())
            if op.type == ida_ua.o_reg:
                h.update(b"r" + str(getattr(op, "reg", 0)).encode())
            elif op.type == ida_ua.o_imm:
                h.update(b"i" + str(getattr(op, "value", 0) & 0xffffffff).encode())
            elif op.type == ida_ua.o_displ:
                h.update(b"d" + str(getattr(op, "addr", 0) & 0xffffffff).encode())
            # o_mem / o_near / o_far are intentionally address-independent.
        h.update(b";")
        try:
            for ref in idautils.CodeRefsFrom(ea, 0):
                if func.start_ea <= ref < func.end_ea:
                    h.update(b"@" + str(ref - func.start_ea).encode())
        except Exception:
            pass
    blocks = edges = 0
    try:
        for block in idaapi.FlowChart(func):
            blocks += 1
            h.update(b"B" + str(block.start_ea - func.start_ea).encode()
                     + b"-" + str(block.end_ea - func.start_ea).encode())
            for succ in block.succs():
                edges += 1
                h.update(b">" + str(succ.start_ea - func.start_ea).encode())
    except Exception:
        pass
    return h.hexdigest(), instructions, blocks, edges


def _fingerprint(func) -> dict:
    shape, instructions, blocks, edges = _shape_for(func)
    name = ida_funcs.get_func_name(func.start_ea) or f"sub_{func.start_ea:X}"
    return {
        "start": hex(func.start_ea),
        "end": hex(func.end_ea),
        "name": name,
        "size": max(0, int(func.end_ea - func.start_ea)),
        "exact": _hash_bytes(func),
        "shape": shape,
        "algorithm": ALGORITHM,
        "instructions": instructions,
        "blocks": blocks,
        "edges": edges,
    }


def _idb_metadata() -> dict:
    try:
        path = ida_loader.get_path(ida_loader.PATH_TYPE_IDB) or None
    except Exception:
        path = None
    try:
        imagebase = idaapi.get_imagebase()
    except Exception:
        imagebase = 0
    try:
        kernel = idaapi.get_kernel_version()
    except Exception:
        kernel = None
    return {"path": path, "imagebase": hex(imagebase), "kernel_version": kernel}


def _collect_fingerprints(max_functions: int = MAX_FUNCTIONS):
    """Return ``(rows, cancelled)`` for up to ``max_functions`` functions."""
    rows = []
    cancelled = False
    for i, ea in enumerate(idautils.Functions()):
        if i >= max_functions:
            break
        try:
            check_cancelled()
        except (CancelledError, IDASyncError):
            cancelled = True
            break
        func = ida_funcs.get_func(ea)
        if func is not None:
            rows.append(_fingerprint(func))
    return rows, cancelled


def _read_snapshot(path: str):
    target = (path or "").strip()
    if not target:
        return None, "path must not be empty"
    target = os.path.abspath(target)
    if not os.path.isfile(target):
        return None, f"snapshot not found: {target}"
    try:
        if os.path.getsize(target) > 64 * 1024 * 1024:
            return None, "snapshot is larger than 64 MiB"
        with open(target, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError) as e:
        return None, f"could not read snapshot: {e}"
    if not isinstance(data, dict) or data.get("schema") != SCHEMA:
        return None, "not an ida-mcp fingerprint snapshot"
    if data.get("schema_version") != SCHEMA_VERSION:
        return None, f"unsupported snapshot schema version: {data.get('schema_version')!r}"
    if not isinstance(data.get("functions"), list):
        return None, "snapshot has no functions list"
    return data, None


def _match(cur: dict, ref: dict, kind: str) -> dict:
    return {
        "match": kind,
        "current": cur,
        "snapshot": ref,
        "start_moved": cur.get("start") != ref.get("start"),
        "name_changed": cur.get("name") != ref.get("name"),
    }


@tool
@idasync
def diff_fingerprints(path: str, limit: int = 200) -> str:
    """Compare the current IDB with a fingerprint snapshot from another process.

    The snapshot is produced by ``export_fingerprints`` in a separate IDA
    process. Matching proceeds by exact location, exact hash, unique shape
    hash, then unique name; duplicates are reported as ambiguous instead of
    guessed. ``limit`` caps each result category (0 = maximum 1000).
    """
    ensure_analysis()
    data, err = _read_snapshot(path)
    if err:
        return json.dumps({"error": err})
    limit = _as_int(limit, 200)
    limit = 1000 if limit <= 0 else min(limit, 1000)

    current, cancelled = _collect_fingerprints(MAX_FUNCTIONS)
    snapshot = [row for row in data["functions"] if isinstance(row, dict)]
    by_exact = defaultdict(list)
    by_shape = defaultdict(list)
    by_name = defaultdict(list)
    for i, row in enumerate(snapshot):
        by_exact[row.get("exact")].append(i)
        by_shape[row.get("shape")].append(i)
        by_name[row.get("name")].append(i)

    used = set()
    categories = {key: [] for key in (
        "unchanged", "moved", "modified", "renamed", "added", "removed",
        "ambiguous")}
    counts = dict.fromkeys(categories, 0)

    def take(indices, cur, kind):
        free = [i for i in indices if i not in used]
        if not free:
            return False
        if len(free) > 1:
            categories["ambiguous"].append(_match(cur, snapshot[free[0]], "ambiguous"))
            counts["ambiguous"] += 1
            used.update(free)
            return True
        i = free[0]
        used.add(i)
        categories[kind].append(_match(cur, snapshot[i], kind))
        counts[kind] += 1
        return True

    for cur in current:
        # Exact code at the same address is the strongest signal.
        exact = by_exact.get(cur.get("exact"), [])
        same_start = [i for i in exact if snapshot[i].get("start") == cur.get("start")
                      and i not in used]
        if same_start:
            i = same_start[0]
            used.add(i)
            categories["unchanged"].append(_match(cur, snapshot[i], "unchanged"))
            counts["unchanged"] += 1
            continue
        if exact and take(exact, cur, "moved"):
            continue
        if take(by_shape.get(cur.get("shape"), []), cur, "modified"):
            continue
        if take(by_name.get(cur.get("name"), []), cur, "renamed"):
            continue
        categories["added"].append({"match": "added", "current": cur})
        counts["added"] += 1

    for i, ref in enumerate(snapshot):
        if i not in used:
            categories["removed"].append({"match": "removed", "snapshot": ref})
            counts["removed"] += 1

    truncated = False
    for key, rows in categories.items():
        if len(rows) > limit:
            categories[key] = rows[:limit]
            truncated = True
    out = {
        "snapshot": os.path.abspath(path),
        "algorithm": ALGORITHM,
        "snapshot_function_count": len(snapshot),
        "current_function_count": len(current),
        "counts": counts,
        "limit": limit,
        "truncated": truncated,
    }
    if cancelled:
        out["cancelled"] = True
        out["partial"] = True
    out.update(categories)
    return json.dumps(out, indent=2)


@tool
@idasync
def fingerprint_function(address: str) -> str:
    """Return exact/shape fingerprints and CFG statistics for one function."""
    ensure_analysis()
    ea, err = resolve_addr(address)
    if err:
        return err
    func = ida_funcs.get_func(ea)
    if not func:
        return json.dumps({"error": f"No function at {address}"})
    return json.dumps(_fingerprint(func), indent=2)


@tool
@idasync
@unsafe
def export_fingerprints(path: str, limit: int = 0) -> str:
    """Write a JSON fingerprint snapshot for offline IDB-to-IDB comparison.

    ``path`` is required; ``limit=0`` exports every function (hard cap 100000).
    The snapshot contains exact and normalized shape hashes, names, addresses,
    function sizes and CFG statistics. IDA is single-database per process, so
    the other IDB's snapshot must be produced by a separate process.

    **Unsafe** — writes a file at ``path``.
    """
    ensure_analysis()
    target = (path or "").strip()
    if not target:
        return json.dumps({"error": "path must not be empty"})
    target = os.path.abspath(target)
    if not os.path.isdir(os.path.dirname(target)):
        return json.dumps({"error": f"parent directory does not exist: {os.path.dirname(target)}"})
    max_functions = _as_int(limit, 0)
    if max_functions <= 0:
        max_functions = MAX_FUNCTIONS
    max_functions = min(max_functions, MAX_FUNCTIONS)

    functions, cancelled = _collect_fingerprints(max_functions)

    snapshot = {
        "schema": SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "algorithm": ALGORITHM,
        "idb": _idb_metadata(),
        "function_count": len(functions),
        "functions": functions,
    }
    tmp_path = None
    try:
        fd, tmp_path = tempfile.mkstemp(prefix=".ida_mcp_fp_", suffix=".json",
                                        dir=os.path.dirname(target))
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(snapshot, f, ensure_ascii=False, indent=2)
            f.write("\n")
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, target)
        tmp_path = None
    except Exception as e:
        return json.dumps({"error": f"Could not write snapshot: {e}"})
    finally:
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
    out = {"ok": True, "path": target, "function_count": len(functions),
           "algorithm": ALGORITHM}
    if cancelled:
        out["cancelled"] = True
        out["partial"] = True
    return json.dumps(out, indent=2)
