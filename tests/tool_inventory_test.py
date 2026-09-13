"""Tool inventory test — guards registry/docs drift (Lote 2.5).

Parses ``ida_mcp/*.py`` via AST (no IDA needed), counts ``@tool``-decorated
functions per module and compares against the EXPECTED sets below. Also
asserts every tool is documented in README.md (backtick-quoted).

When adding a tool: implement it, document it in README.md, then update
EXPECTED here. When only refactoring internals, this test must stay green
untouched.

Usage:
    python tests/tool_inventory_test.py
"""
import ast
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PKG = os.path.join(HERE, "..", "ida_mcp")
ROOT = os.path.dirname(HERE)

# module stem -> sorted list of @tool function names
EXPECTED = {
    "server": [
        "close_instance",
        "decompile_function",
        "execute_script",
        "get_disassembly",
        "get_functions",
        "get_instance_info",
        "list_instances",
        "server_health",
        "server_warmup",
    ],
    "api_analysis": [
        "basic_blocks",
        "disasm",
        "find_bytes",
        "get_bytes",
        "get_callees",
        "get_callers",
        "get_string",
        "get_xrefs_to",
        "int_convert",
        "list_exports",
        "list_imports",
        "list_strings",
        "lookup_funcs",
        "rename_function",
        "set_comment",
        "xref_query",
    ],
    "api_comments": [
        "add_bookmark",
        "delete_bookmark",
        "delete_comment",
        "get_all_comments",
        "get_bookmarks",
        "get_comment",
        "get_extra_comments",
        "get_repeatable_comment",
        "set_extra_comment",
        "set_repeatable_comment",
    ],
    "api_debug": [
        "dbg_add_bp",
        "dbg_bps",
        "dbg_continue",
        "dbg_delete_bp",
        "dbg_exit",
        "dbg_get_threads",
        "dbg_gpregs",
        "dbg_read",
        "dbg_regs",
        "dbg_regs_named",
        "dbg_run_to",
        "dbg_set_bp_condition",
        "dbg_stacktrace",
        "dbg_start",
        "dbg_status",
        "dbg_step_into",
        "dbg_step_over",
        "dbg_toggle_bp",
        "dbg_write",
    ],
    "api_composite": [
        "analyze_component",
        "analyze_function",
        "callgraph",
        "diff_before_after",
        "func_profile",
        "survey_binary",
        "trace_data_flow",
    ],
    "api_hooks": [
        "get_hook_info",
        "install_hexrays_hook",
        "install_hook",
        "install_idb_hook",
        "remove_hooks",
    ],
    "api_hexrays": [
        "force_recompile",
        "get_basic_blocks",
        "get_flowchart",
        "get_microcode",
    ],
    "api_entries": [
        "add_entry_point",
        "get_entry_forwarders",
        "get_entry_point_at",
        "get_entry_point_by_name",
        "get_entry_point_by_ordinal",
        "get_entry_point_count",
        "get_entry_points",
        "rename_entry_point",
    ],
    "api_functions": [
        "create_function",
        "delete_function",
        "func_count",
        "get_function_args_size",
        "get_function_bounds",
        "get_function_comment",
        "get_function_edges",
        "get_function_end",
        "get_function_flags",
        "get_function_frame_size",
        "get_function_instructions_count",
        "get_function_signature",
        "get_function_size",
        "get_function_start",
        "get_function_type",
        "get_functions_in_range",
        "get_local_variables",
        "get_next_function",
        "get_register_variables",
        "is_function_library",
        "is_function_noreturn",
        "is_function_thunk",
        "list_funcs",
        "set_function_comment",
        "set_function_name",
    ],
    "api_info": [
        "get_analysis_prompt",
        "get_analysis_status",
        "get_architecture_info",
        "get_base_address",
        "get_binary_info",
        "get_compiler_info",
        "get_current_binary_name",
        "get_hexrays_version",
        "get_image_size",
        "get_input_file_md5",
        "get_input_file_path",
        "get_input_file_sha256",
        "get_problems",
        "get_processor_info",
        "get_version_info",
        "idb_meta",
        "idb_save",
        "wait_for_analysis",
    ],
    "api_instructions": [
        "breaks_flow",
        "get_instruction",
        "get_instruction_bytes",
        "get_instruction_size",
        "get_instructions",
        "get_instructions_in_range",
        "get_mnemonic",
        "get_operand",
        "get_operand_info",
        "get_operands",
        "get_operands_count",
        "is_call_instruction",
        "is_conditional_jump",
        "is_indirect_jump",
        "is_jump_instruction",
        "is_ret_instruction",
    ],
    "api_memory": [
        "get_byte",
        "get_cstring",
        "get_data_flags",
        "get_data_size",
        "get_disassembly_text",
        "get_double",
        "get_dword",
        "get_float",
        "get_global_value",
        "get_heads",
        "get_int",
        "get_next_addr",
        "get_next_head",
        "get_prev_addr",
        "get_prev_head",
        "get_qword",
        "get_word",
        "is_code",
        "is_data",
    ],
    "api_modify": [
        "get_original_bytes",
        "list_patches",
        "make_data",
        "patch_asm",
        "patch_bytes",
        "rename_address",
        "revert_patch",
        "undefine",
    ],
    "api_names": [
        "delete_name",
        "demangle_name",
        "force_name",
        "get_all_names",
        "get_demangled_name",
        "get_name",
        "is_name_public",
        "is_name_weak",
        "make_name_non_public",
        "make_name_public",
        "set_name",
        "validate_name",
    ],
    "api_python": [
        "py_eval",
        "py_exec_file",
    ],
    "api_query": [
        "entity_query",
        "func_query",
        "get_local_variable_by_name",
        "get_local_variable_references",
        "imports_query",
        "list_globals",
    ],
    "api_sigmaker": [
        "apply_flirt_signatures",
        "find_xref_signatures",
        "list_flirt_signatures",
        "make_signature",
        "make_signature_for_function",
        "make_signature_for_range",
    ],
    "api_search": [
        "find_bytes_between",
        "find_immediate_between",
        "find_regex",
        "find_text_between",
        "search_bytes",
        "search_immediate_value",
        "search_text",
    ],
    "api_strings": [
        "get_ascii_strings",
        "get_string_at",
        "get_string_count",
        "get_strings",
        "get_strings_by_length",
        "get_strings_in_range",
        "get_unicode_strings",
        "search_strings",
    ],
    "api_segments": [
        "get_code_segments",
        "get_data_segments",
        "get_segment_at",
        "get_segment_bitness",
        "get_segment_by_name",
        "get_segment_class",
        "get_segment_comment",
        "get_segment_count",
        "get_segment_end",
        "get_segment_permissions",
        "get_segment_size",
        "get_segment_start",
        "get_segments",
    ],
    "api_typeinfo": [
        "declare_type",
        "enum_upsert",
        "get_type_at",
        "get_type_by_name",
        "infer_types",
        "read_struct",
        "search_structs",
        "set_type",
        "type_inspect",
        "type_query",
    ],
    "api_xrefs": [
        "get_callee_count",
        "get_caller_count",
        "get_calls_from",
        "get_calls_to",
        "get_code_refs_from",
        "get_code_refs_to",
        "get_data_refs_from",
        "get_data_refs_to",
        "get_jumps_to",
        "get_reads_of",
        "get_writes_to",
        "get_xref_count",
        "get_xrefs",
        "get_xrefs_from",
        "xrefs_to_field",
    ],
}


def collect_tools(path):
    """Return sorted @tool function names in a source file via AST."""
    with open(path, "r", encoding="utf-8") as f:
        tree = ast.parse(f.read())
    tools = []
    for node in tree.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for dec in node.decorator_list:
            name = ast.unparse(dec).strip()
            if name == "tool" or name.startswith("tool("):
                tools.append(node.name)
                break
    return sorted(tools)


def main() -> int:
    failures = []

    # 1) Per-module inventory vs EXPECTED.
    actual_total = 0
    expected_total = sum(len(v) for v in EXPECTED.values())
    for module, expected in sorted(EXPECTED.items()):
        path = os.path.join(PKG, module + ".py")
        if not os.path.isfile(path):
            failures.append(f"{module}: FILE NOT FOUND")
            continue
        actual = collect_tools(path)
        actual_total += len(actual)
        if actual != sorted(expected):
            missing = sorted(set(expected) - set(actual))
            extra = sorted(set(actual) - set(expected))
            failures.append(
                f"{module}: mismatch (missing={missing}, extra={extra})"
            )
        else:
            print(f"[{module}] {len(actual)} tools OK")

    print(f"\nTotal: {actual_total} tools across {len(EXPECTED)} modules "
          f"(expected {expected_total})")
    if actual_total != expected_total:
        failures.append("total count mismatch")

    # 2) Every tool must be documented in README.md (backtick-quoted).
    readme_path = os.path.join(ROOT, "README.md")
    with open(readme_path, "r", encoding="utf-8") as f:
        readme = f.read()
    undocumented = []
    for module, tools in sorted(EXPECTED.items()):
        for tool in tools:
            # README documents tools as `name` or `name(args)` in tables/prose.
            if f"`{tool}`" not in readme and f"`{tool}(" not in readme:
                undocumented.append(f"{module}.{tool}")
    if undocumented:
        failures.append(f"undocumented in README.md: {undocumented}")
    else:
        print(f"README.md documents all {actual_total} tools OK")

    # 3) server.py must import every api_* module (registration trigger).
    server_path = os.path.join(PKG, "server.py")
    with open(server_path, "r", encoding="utf-8") as f:
        server_src = f.read()
    unimported = [m for m in EXPECTED
                  if m.startswith("api_")
                  and f"from . import {m}" not in server_src
                  and f"from .{m} import" not in server_src]
    if unimported:
        failures.append(f"server.py missing imports: {unimported}")
    else:
        print("server.py imports all api_* modules OK")

    # 4) profiles/*.txt must reference real tools only, stay privilege-clean,
    #    and nest (triage c= readonly). Also cross-checks profiles.py loader.
    import importlib.util as _ilu
    _pspec = _ilu.spec_from_file_location(
        "profiles_under_test", os.path.join(PKG, "profiles.py"))
    _pmod = _ilu.module_from_spec(_pspec)
    _pspec.loader.exec_module(_pmod)
    all_tools = set()
    unsafe_tools = set()
    ext_tools = set()
    for _tools in EXPECTED.values():
        all_tools.update(_tools)
    for module, _tools in EXPECTED.items():
        path = os.path.join(PKG, module + ".py")
        with open(path, "r", encoding="utf-8") as f:
            tree = ast.parse(f.read())
        for node in tree.body:
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            decs = [ast.unparse(d).strip() for d in node.decorator_list]
            if node.name in _tools and "unsafe" in decs:
                unsafe_tools.add(node.name)
            for d in decs:
                if d.startswith("ext(") and node.name in _tools:
                    ext_tools.add(node.name)
    prof_dir = os.path.join(PKG, "profiles")
    prof_files = sorted(f for f in os.listdir(prof_dir) if f.endswith(".txt"))
    if "triage.txt" not in prof_files or "readonly.txt" not in prof_files:
        failures.append(f"profiles/ must ship triage.txt + readonly.txt: {prof_files}")
    else:
        loaded = {name: _pmod.get_profile(name) for name in ("triage", "readonly")}
        if any(v is None for v in loaded.values()):
            failures.append("profiles.py loader returned None for a shipped profile")
        else:
            triage, readonly = loaded["triage"], loaded["readonly"]
            before = len(failures)
            unknown = (triage | readonly) - all_tools
            if unknown:
                failures.append(f"profiles reference unknown tools: {sorted(unknown)}")
            privileged = (triage | readonly) & (unsafe_tools | ext_tools)
            if privileged:
                failures.append(f"triage/readonly must be privilege-free: {sorted(privileged)}")
            if not triage < readonly:
                failures.append("triage must be a strict subset of readonly")
            if len(failures) == before:
                print(f"profiles OK (triage={len(triage)}, readonly={len(readonly)})")
    if _pmod.get_profile("nope") is not None:
        failures.append("get_profile('nope') must return None")
    else:
        print("unknown profile -> None OK")

    print("\n" + "=" * 50)
    if failures:
        print("FAILED:")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    print("ALL TOOL INVENTORY TESTS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
