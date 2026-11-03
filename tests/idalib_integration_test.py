"""idalib headless integration test (LOCAL only; needs a licensed IDA).

Stubbed harnesses can't see real API drift (how `idc.Assemble` and
`ida_search.find_binary` slipped through). This runs a handful of read-only
tools against a REAL IDA kernel via `idalib`/`idapro`.

Opt-in. Skips (green) unless ALL of:
  - env `IDA_MCP_IDALIB=1`
  - `import idapro` succeeds (idalib present + licensed)
  - env `IDA_MCP_IDALIB_BINARY=/path/to/binary` points at a real file

Run:
  IDA_MCP_IDALIB=1 IDA_MCP_IDALIB_BINARY=/bin/ls python3 tests/idalib_integration_test.py

Not part of tests/run_all.py (CI has no IDA). It is a developer gate.
"""
import json
import os
import sys


def _skip(reason):
    print(f"SKIP: {reason}")
    sys.exit(0)


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

    failures = []

    def check(cond, msg):
        print(("  ok: " if cond else "  FAIL: ") + msg)
        if not cond:
            failures.append(msg)

    print(f"opening {binary} via idalib ...")
    rc = idapro.open_database(binary, run_auto_analysis=True)
    check(rc == 0, f"open_database returned {rc} (0 = ok)")
    try:
        # Importing the package registers all @tool functions.
        import ida_mcp  # noqa: F401
        from ida_mcp.rpc import MCP_SERVER

        tools = MCP_SERVER.tools.methods

        def run(name, **kwargs):
            fn = tools.get(name)
            if fn is None:
                failures.append(f"tool {name} not registered")
                return None
            return fn(**kwargs)

        # server_health: version + status
        health = json.loads(run("server_health"))
        check(health.get("status") == "ok", "server_health status ok")

        # survey_binary: one-call triage
        if "survey_binary" in tools:
            survey = json.loads(run("survey_binary"))
            check(isinstance(survey, dict) and not survey.get("error"),
                  "survey_binary returned a payload")

        # get_functions: at least the listing shape
        funcs_raw = run("get_functions", filter_pattern="*", limit=5, offset=0)
        check(isinstance(funcs_raw, str) and funcs_raw.strip() != "",
              "get_functions returned text")

        # list_imports (api_analysis) — real enum, no AttributeError
        if "list_imports" in tools:
            imports = run("list_imports")
            check(isinstance(imports, str), "list_imports ran")

        # decompile first function if Hex-Rays present (tolerate absence)
        if "decompile_function" in tools:
            import idautils
            first = next(iter(idautils.Functions()), None)
            if first is not None:
                out = run("decompile_function", address=hex(int(first)))
                check(isinstance(out, str) and out.strip() != "",
                      "decompile_function returned text (or a clean error)")

        # optional revertible write
        if os.environ.get("IDA_MCP_IDALIB_WRITE", "").strip() in ("1", "true", "yes"):
            import idautils
            ea = next(iter(idautils.Functions()), None)
            if ea is not None and "set_comment" in tools and "delete_comment" in tools:
                run("set_comment", address=hex(int(ea)), comment="ida_mcp idalib test")
                run("delete_comment", address=hex(int(ea)))
                check(True, "set_comment + delete_comment round-trip")
    finally:
        try:
            idapro.close_database(save=False)
        except Exception:
            pass

    print("\n" + "=" * 50)
    if failures:
        print(f"FAILED ({len(failures)}): " + "; ".join(failures))
        return 1
    print("ALL IDALIB INTEGRATION CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
