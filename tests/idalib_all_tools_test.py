"""Opt-in live sweep: run every read-only tool against a real IDB.

Stubbed harnesses validate our logic, but they cannot see IDA API drift: a
renamed function, a changed return shape or a new deprecation only shows up
against a real kernel. This harness loads the plugin into ``idalib`` and calls
each safe tool once with its signature defaults (plus a small filler table for
required arguments), failing on:

  - a tool that raises (AttributeError/TypeError/API misuse), and
  - a DeprecationWarning from our own files that ``compat`` does not already
    classify as benign.

Error payloads are reported but do not fail: the filler arguments are generic,
so some tools legitimately answer "not found".

Opt-in. Skips (green) unless ALL of:
  - env ``IDA_MCP_IDALIB=1``
  - ``import idapro`` succeeds (idalib present + licensed)
  - env ``IDA_MCP_IDALIB_BINARY=/path/to/binary`` points at a real file

Run:
  IDA_MCP_IDALIB=1 IDA_MCP_IDALIB_BINARY=/bin/ls \
      python3 tests/idalib_all_tools_test.py

Not part of CI (no IDA there); ``make idalib`` passes the environment through.
"""
import inspect
import json
import os
import re
import shutil
import sys
import tempfile
import traceback
import warnings

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

# Required-argument fillers: generic but valid values on a typical binary.
FILL = {
    "address": None, "addresses": None, "addr": None, "start": None,
    "end": None, "name": ".text", "type_name": "idamcp_probe",
    "declaration": "struct idamcp_probe { int a; };",
    "value": 0, "text": "GLIBC", "pattern": "48 89 e5",
    "enum_name": "idamcp_enum", "members": '[{"name":"A","value":1}]',
    "kind": "imports", "hook_type": "idb", "port": 13337,
    "filter_pattern": "*", "file_path": "/nonexistent.py",
    "query": "GLIBC", "struct_name": "idamcp_probe", "field_name": "a",
    "format": "ida", "data": "90 90", "asm": "nop", "action": "set_comment",
}


def _skip(reason):
    print(f"SKIP: {reason}")
    sys.exit(0)


def _tool_kwargs(fn, first_ea):
    """Arguments for one call: defaults plus fillers, or None when unsure."""
    fill = dict(FILL)
    fill.update({"address": hex(first_ea), "addresses": hex(first_ea),
                 "addr": hex(first_ea), "start": hex(first_ea),
                 "end": hex(first_ea + 0x40)})
    try:
        sig = inspect.signature(fn)
    except (TypeError, ValueError):
        return None
    kwargs = {}
    for p in sig.parameters.values():
        if p.default is not inspect.Parameter.empty:
            continue
        if p.name in fill and fill[p.name] is not None:
            kwargs[p.name] = fill[p.name]
        else:
            return None
    return kwargs


def main():
    if os.environ.get("IDA_MCP_IDALIB", "").strip() not in ("1", "true", "yes"):
        _skip("IDA_MCP_IDALIB not set (local-only idalib gate).")

    binary = os.environ.get("IDA_MCP_IDALIB_BINARY", "").strip()
    if not binary or not os.path.isfile(binary):
        _skip(f"IDA_MCP_IDALIB_BINARY missing or not a file: {binary!r}")

    try:
        import idapro  # noqa: F401  (idalib entry point)
    except Exception as e:  # noqa: BLE001
        _skip(f"import idapro failed ({e}); idalib not available/licensed.")

    # idalib prepends its own paths on import: inserting the repo afterwards
    # makes the working tree win over an older copy in ~/.idapro/plugins.
    sys.path.insert(0, ROOT)

    tmp = tempfile.mkdtemp(prefix="ida_mcp_idalib_")
    binary_copy = os.path.join(tmp, os.path.basename(binary))
    shutil.copyfile(binary, binary_copy)

    rc = idapro.open_database(binary_copy, run_auto_analysis=True)
    if rc != 0:
        shutil.rmtree(tmp, ignore_errors=True)
        print(f"FAILED: open_database returned {rc}")
        return 1

    import idautils  # noqa: E402

    import ida_mcp  # noqa: E402,F401
    from ida_mcp.compat import _SILENCED_DEPRECATIONS  # noqa: E402
    from ida_mcp.rpc import MCP_SERVER  # noqa: E402

    tools = MCP_SERVER.tools.methods
    ext_tools = set().union(*MCP_SERVER._extensions_registry.values())
    first_ea = int(next(iter(idautils.Functions()), 0x1000))

    def benign(message):
        return any(re.search(p, message) for p in _SILENCED_DEPRECATIONS)

    ran = skipped = 0
    failures = []
    payload_errors = []
    deprecations = []

    try:
        for name in sorted(tools):
            if name in MCP_SERVER.unsafe_tools or name in ext_tools:
                skipped += 1
                continue
            fn = tools[name]
            kwargs = _tool_kwargs(fn, first_ea)
            if kwargs is None:
                print(f"  skip {name}: unfillable required argument")
                skipped += 1
                continue
            try:
                with warnings.catch_warnings(record=True) as rec:
                    warnings.simplefilter("always")
                    out = fn(**kwargs)
            except Exception as e:  # noqa: BLE001 - the point is to report it
                failures.append(f"{name}: {type(e).__name__}: {e}")
                traceback.print_exc()
                continue
            ran += 1
            for w in rec:
                if ROOT in str(w.filename) and not benign(str(w.message)):
                    deprecations.append(f"{name}: {w.message} [{w.filename}:{w.lineno}]")
            try:
                parsed = json.loads(out)
            except (TypeError, ValueError):
                continue
            if isinstance(parsed, dict) and parsed.get("error"):
                payload_errors.append(f"{name}: {parsed['error']!r}")

    finally:
        try:
            idapro.close_database(save=False)
        except Exception:
            pass
        shutil.rmtree(tmp, ignore_errors=True)

    print(f"\nran {ran} safe tools, skipped {skipped}")
    if payload_errors:
        print(f"error payloads (generic fillers; informational) ({len(payload_errors)}):")
        for item in payload_errors[:10]:
            print(f"  {item}")
    if deprecations:
        print(f"unexpected deprecations ({len(deprecations)}):")
        for item in deprecations:
            print(f"  {item}")
    if failures:
        print(f"FAILED ({len(failures)}):")
        for item in failures:
            print(f"  {item}")
        return 1
    if deprecations:
        print(f"FAILED: {len(deprecations)} deprecation(s) from our own code")
        return 1
    print("ALL LIVE TOOL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
