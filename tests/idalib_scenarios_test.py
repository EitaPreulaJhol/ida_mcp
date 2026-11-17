"""Scenario-based integration checks against a disposable real IDB.

Run through ``idalib_matrix_test.py`` or directly with:

    IDA_MCP_IDALIB=1 IDA_MCP_IDALIB_BINARY=/path/to/binary \
      python tests/idalib_scenarios_test.py

Unlike the generic tool sweep, these checks assert useful response contracts
and verify selected mutations against a temporary copy of the input binary.
"""
import json
import os
import re
import shutil
import sys
import tempfile


def _skip(reason):
    print(f"SKIP: {reason}")
    return 0


def _json_tool(tools, tool_name, **kwargs):
    value = tools[tool_name](**kwargs)
    if not isinstance(value, str):
        raise AssertionError(f"{tool_name} returned {type(value).__name__}, expected JSON text")
    try:
        return json.loads(value)
    except json.JSONDecodeError as exc:
        raise AssertionError(f"{tool_name} returned invalid JSON: {value[:200]!r}") from exc


def main():
    if os.environ.get("IDA_MCP_IDALIB", "").strip().lower() not in ("1", "true", "yes"):
        return _skip("IDA_MCP_IDALIB not set (local-only idalib gate).")

    binary = os.environ.get("IDA_MCP_IDALIB_BINARY", "").strip()
    if not binary or not os.path.isfile(binary):
        return _skip(f"IDA_MCP_IDALIB_BINARY missing or not a file: {binary!r}")

    try:
        import idapro
    except Exception as exc:  # noqa: BLE001 - missing install/license is an opt-in skip
        return _skip(f"import idapro failed ({exc}); idalib not available/licensed.")

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    # IDA may have autoloaded a user-installed plugin before this script runs.
    # The integration gate must exercise the checkout under test, not that copy.
    for module_name in list(sys.modules):
        if module_name == "ida_mcp" or module_name.startswith("ida_mcp."):
            del sys.modules[module_name]
    sys.path.insert(0, root)
    tmp = tempfile.mkdtemp(prefix="ida_mcp_scenarios_")
    binary_copy = os.path.join(tmp, os.path.basename(binary))
    shutil.copyfile(binary, binary_copy)
    opened = False
    failures = []
    try:
        rc = idapro.open_database(binary_copy, run_auto_analysis=True)
        if rc != 0:
            raise AssertionError(f"open_database returned {rc}")
        opened = True

        import idaapi
        import idautils
        import ida_funcs
        import ida_name
        import ida_bytes
        import ida_mcp  # noqa: F401 - register all tools
        from ida_mcp.rpc import MCP_SERVER
        if not os.path.realpath(ida_mcp.__file__).startswith(os.path.realpath(root) + os.sep):
            raise AssertionError(f"loaded ida_mcp outside checkout: {ida_mcp.__file__}")

        tools = MCP_SERVER.tools.methods
        first_ea = next(iter(idautils.Functions()), None)
        if first_ea is None:
            raise AssertionError("scenario binary has no functions")
        first_ea = int(first_ea)
        address = hex(first_ea)
        print(f"IDA kernel: {idaapi.get_kernel_version() if hasattr(idaapi, 'get_kernel_version') else 'unknown'}")
        print(f"scenario function: {address} ({ida_funcs.get_func_name(first_ea)})")

        # Page shape, offset semantics and positive-limit clamp on the legacy
        # get_functions tool. Use the same IDB for a deterministic comparison.
        page = _json_tool(tools, "get_functions", filter_pattern="*", limit=2)
        assert isinstance(page.get("data"), list) and len(page["data"]) <= 2, page
        assert page.get("count") == len(page["data"]), page
        assert isinstance(page.get("total"), int) and page["total"] >= len(page["data"]), page
        assert page.get("limit") == 2, page
        if page["total"] > 1:
            second = _json_tool(tools, "get_functions", filter_pattern="*", limit=1, offset=1)
            assert second["data"] == page["data"][1:2], (page, second)
        print("  PASS get_functions page/offset contract")

        # Disassembly returns the requested number of instructions and caps
        # extreme limits rather than letting the caller monopolize IDA.
        disasm = tools["get_disassembly"](address=address, limit=3)
        assert isinstance(disasm, str) and disasm, repr(disasm)
        instruction_lines = re.findall(r"(?m)^0x[0-9a-fA-F]+:", disasm)
        assert len(instruction_lines) <= 3, (len(instruction_lines), repr(disasm[:300]))
        capped = tools["get_disassembly"](address=address, limit=100000)
        assert "requested instruction limit capped at 5000" in capped, capped[-160:]
        print("  PASS get_disassembly normal/extreme limits")

        # Segment and type tools have stable structured response shapes even
        # for binaries with few/no local types.
        segments = json.loads(tools["get_segments"]())
        assert isinstance(segments, list) and segments, segments
        type_page = _json_tool(tools, "type_query", limit=5)
        assert isinstance(type_page, list) and len(type_page) <= 5, type_page
        print("  PASS segment/type query contracts")

        # Xrefs and text search may legitimately be empty; validate their
        # envelopes instead of asserting binary-specific findings.
        xrefs = _json_tool(tools, "get_xrefs_to", address=address, limit=5)
        assert "error" not in xrefs, xrefs
        assert isinstance(xrefs.get("xrefs"), list), xrefs
        search = _json_tool(tools, "search_text", text="IDA_MCP_SCENARIO_SENTINEL")
        assert search.get("text") == "IDA_MCP_SCENARIO_SENTINEL", search
        assert isinstance(search.get("matches"), list), search
        print("  PASS xref/search response contracts")

        # Mutations are executed only against binary_copy in this temp folder;
        # closing with save=False discards the test IDB and its annotations.
        old_name = ida_name.get_ea_name(first_ea) or ""
        probe_name = f"ida_mcp_scenario_{first_ea:x}"
        renamed = _json_tool(tools, "set_name", address=address, name=probe_name)
        assert renamed.get("new_name") == probe_name, renamed
        named = _json_tool(tools, "get_name", address=address)
        assert probe_name in json.dumps(named), named

        comment = "ida_mcp disposable integration scenario"
        commented = _json_tool(tools, "set_comment", address=address, comment=comment)
        assert "error" not in commented, commented
        read_comment = _json_tool(tools, "get_comment", address=address)
        assert read_comment.get("comment") == comment, read_comment
        print("  PASS name/comment mutation and read-back on disposable IDB")

        # Sanity check the SDK writes landed in the in-memory copy as well.
        assert ida_name.get_ea_name(first_ea) == probe_name
        assert ida_bytes.get_cmt(first_ea, False) == comment
        print(f"  original name was {old_name!r}; mutations are discarded on close")

    except Exception as exc:  # noqa: BLE001 - report scenario assertion failures
        failures.append(f"{type(exc).__name__}: {exc}")
        print(f"FAILED scenario: {failures[-1]}")
        return 1
    finally:
        if opened:
            try:
                idapro.close_database(save=False)
            except Exception as exc:  # noqa: BLE001 - cleanup must be visible
                failures.append(f"close_database: {type(exc).__name__}: {exc}")
        shutil.rmtree(tmp, ignore_errors=True)

    if failures:
        print("FAILED scenarios:")
        for failure in failures:
            print(f"  {failure}")
        return 1
    print("ALL IDALIB SCENARIOS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
