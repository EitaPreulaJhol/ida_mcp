---
name: ida
description: Connect to IDA Pro through the ida_mcp plugin and reverse engineer the open binary with lazy-loaded tools. Use this whenever the user wants to analyze, decompile, trace, annotate, debug, or signature-scan a binary currently open in IDA Pro, or says "/ida". Starts with a 16-tool triage profile and escalates (readonly, full, unsafe, debugger) only as needed.
license: MIT
compatibility: any MCP client + IDA Pro 8.3+ with the ida_mcp plugin
metadata:
  audience: reverse-engineers
  workflow: ida-pro-mcp-lazy
  domain: security
---

## What I do

I connect to IDA Pro lazily: verify the bridge is up, triage with a minimal
toolset, then progressively unlock more tools (profiles → unsafe → debugger)
only when the task demands it. I never preload all 243 tools into context —
most MCP clients cap tool slots, and a 16-tool triage set keeps small models
on-task.

## Trigger

Activate when the user types `/ida`, mentions analyzing a binary in
IDA Pro, or asks about a binary/driver that is open in IDA. Ask ONE
clarifying question only if it is unclear whether write tools (`?unsafe=true`)
are available — otherwise assume read-only and escalate later.

## Endpoint ladder (escalate top-down, stop at the first that suffices)

| Step | Endpoint suffix | Tools visible | Use when |
|------|----------------|---------------|----------|
| 1 | `?profile=triage` | 16 (health, survey, list, decompile, xrefs) | **Always start here** |
| 2 | `?profile=readonly` | 188 (all safe reads) | Triage is insufficient |
| 3 | _(no profile)_ | 224 (safe + gated) | Need a specific safe tool outside readonly (rare) |
| 4 | `?unsafe=true` | + renames, comments, types, patches, scripts | Annotating / modifying the IDB |
| 5 | `?unsafe=true&ext=dbg` | + 19 debugger tools | Live debugging session |

If the MCP client was configured with a fixed URL, state which step you need
and ask the user to reconnect with the suffix (or reconfigure). Never
request step 4–5 "just in case" — justify each escalation in one sentence.

## Methodology

### 0. Connect (verify the bridge)

- Call `server_health()`. If it fails, the IDA plugin is not serving:
  tell the user to open IDA Pro with a binary and confirm the
  `[ida-mcp] listening on http://127.0.0.1:13337/mcp` message in the IDA
  output window, then retry. Do NOT proceed to analysis without health `ok`.
- If a tool call errors with `requires extension` or `requires unsafe mode`
  or `is not in profile`, treat it as a routing signal: map it to the ladder
  row above and escalate (asking the user when it crosses step 3→4).

### 1. Triage (one call)

- Call `survey_binary()` FIRST (`detail_level="minimal"` on huge binaries).
  It returns metadata, top strings/functions by xref count, imports by
  category (crypto/network/file_io/process/registry), and call-graph summary.
  Do not call `list_funcs`/`list_imports` separately for triage.

### 2. Understand (per function of interest)

- `analyze_function(address)` — capped pseudocode + strings, constants,
  callers, callees, comments, blocks in one call. Prefer over chaining.
- `decompile_function(address)` — full uncapped pseudocode when needed
  (capped at 2000 lines with a notice).
- `func_query(...)` / `entity_query(kind, ...)` — find functions, globals,
  strings, imports by glob/regex/size without dumping thousands of rows.
- `trace_data_flow(address, direction="backward")` — multi-hop xref BFS from
  a string, constant, or global. `callgraph(roots)` for call structure.

### 3. Go deeper (readonly profile)

- `get_bytes` / `get_int` / `get_cstring` for data; `read_struct` with a
  known type; `get_operand_info` / `get_disassembly_text` for instructions.
- `make_signature(addresses)` for byte patterns; `find_xref_signatures` for
  data/string references; `xrefs_to_field` for struct fields.
- `get_microcode` / `get_flowchart` / `force_recompile` for decompiler views
  (recompile after type changes, never re-call decompile hoping for refresh).

### 4. Annotate (unsafe only)

- `set_name` (canonical rename), `set_comment`, `set_type` + `declare_type`,
  `diff_before_after` to verify a rename/type/comment improved readability.
- `idb_save()` before any patching session; `patch_bytes`/`patch_asm` for
  bytes, `execute_script` for batch work.

### 5. Debug (unsafe + ext=dbg only)

- `dbg_start()` (configured debugger required — never retry-loop; ask the
  user to configure IDA on failure), `dbg_bps`/`dbg_add_bp`,
  `dbg_continue`/`dbg_step_into`/`dbg_step_over`, `dbg_regs`/`dbg_stacktrace`/
  `dbg_read`. Session must be suspended for inspection tools.
- No session? Use hook tracers instead: `install_idb_hook()`,
  `install_hexrays_hook()`, read with `get_hook_info()`, clean with
  `remove_hooks()`.

### 6. Report

- Write `re/summary.md` (overview), `re/analysis.md` (per-function),
  `re/findings.md` (passwords, algorithms, vulnerabilities). Hex addresses
  (`0x401000`) throughout, with the tool that produced each claim.

## Critical rules

- **Never hand-compute number bases.** Use `int_convert` for any conversion.
- **Derive, don't assume.** Every claim needs decompilation, xref, or
  data-flow evidence behind it.
- **Addresses and symbols are interchangeable** (`"main"`, `"0x401000"`).
- **`decompile_function`/`get_disassembly` return plain text**; every other
  tool returns a JSON string.
- **Do not brute-force.** Static analysis + `execute_script` only.
- **Respect the ladder.** A step-4/5 tool failing means the endpoint lacks
  the flag — explain and ask, don't work around it.
