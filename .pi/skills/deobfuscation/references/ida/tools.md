# IDA Pro Deobfuscation Tools (ida_mcp native)

All calls below are real ida_mcp tools against the binary open in IDA Pro.
Start at `?profile=triage`; annotate/patch/script need `?unsafe=true`.

## Reading

- `decompile_function` — Read decompiled pseudocode. After each modification, `force_recompile` to verify improvement.
- `get_microcode` — Read a Hex-Rays microcode summary for a function (maturity level + block bounds). Lower maturity exposes obfuscation patterns; higher levels show optimized output.
- `get_disassembly_text` / `disasm` — Read raw assembly. Useful for byte-level pattern detection and verifying patches.
- `get_xrefs_to` / `get_xrefs_from` / `callgraph` — Trace cross-references. Essential for finding decode stub call sites during string decryption.
- `list_strings` / `search_strings` — Find readable strings. Few strings in a large binary → strings are encrypted.
- `get_functions` / `func_query` / `lookup_funcs` — Find functions by name or pattern. Locate decode stubs, VM handlers, dispatchers.
- `get_binary_info` / `get_segments` / `list_imports` — Binary metadata. Identify packed sections, unusual segments, import obfuscation.

## Writing (Microcode Level, via `execute_script` + `ida_hexrays`)

There is no microcode-write tool — write through IDAPython run with `execute_script`
(all `ida_*` modules available; assign `result`, `print()` is captured):

- Suppress junk instructions by patching bytes (`patch_bytes`) and re-decompiling,
  or walk the ctree with an `ida_hexrays.ctree_visitor_t` inside `execute_script` and
  rewrite matched expressions (opaque predicates, MBA folds, instruction substitution).
- For CFF unflattening, map dispatcher → handler with `get_flowchart` + `get_microcode`,
  then rewire control flow with `patch_bytes` (jump targets) and `force_recompile`.
- Always call `ida_hexrays.mark_cfunc_dirty(ea)` inside the script before re-decompiling
  a function you modified, then `force_recompile` to see the effect.

## Writing (Annotation & Database, `?unsafe=true`)

- `set_name` (+ `set_function_name`, `rename_function`, `rename_address`) — Annotate deobfuscated code with meaningful names.
- `set_comment` — Add comments (e.g., decrypted string values at call sites).
- `set_type` / `declare_type` — Apply recovered types after deobfuscation (`infer_types`, `read_struct` to verify).

## Scripting (Catch-All)

- `execute_script` — Run arbitrary IDAPython code. Use when built-in tools are insufficient:
  - Bulk operations across hundreds of functions
  - Complex computations (z3 solver, crypto reimplementation)
  - Direct `ida_hexrays` access (`mba_t`/`mblock_t`/`minsn_t`, ctree visitors, hooks)
  - `idb_save()` before any patching session.

## Choosing the Right Approach

| Task | Preferred Tool | Why |
|---|---|---|
| Spot obfuscation patterns | `get_microcode` | See raw structure before optimization removes evidence |
| NOP known junk addresses | `patch_bytes` (`0x90` fill) + `force_recompile` | Byte-precise, immediately verifiable |
| Pattern-match across functions | `execute_script` with `ida_hexrays` visitors | Full ctree/mba access |
| CFF unflattening | `get_flowchart` + `patch_bytes` + `force_recompile` | Rewire dispatcher bypasses at byte level |
| Opaque predicate removal | `execute_script` (match constant-conditioned jumps) | Conditional logic needs code |
| MBA constant folding | `execute_script` (match binary ops on two constants) | Constant math needs code |
| String decryption (xref-based) | `get_xrefs_to` + `decompile_function` + `set_comment` | Built-in tools cover the workflow |
| Complex decode reimplementation | `execute_script` | Need full Python for crypto logic |
| Hook-based tracing | `install_idb_hook` / `install_hexrays_hook` + `get_hook_info` | Passive tracers, no patching |
