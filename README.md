# ida_mcp - IDA Pro MCP Plugin
`ida_mcp` exposes a running IDA Pro session to AI coding agents through the [Model Context Protocol (MCP)](https://modelcontextprotocol.io/). An agent connected to the plugin can inspect the open binary, decompile functions, walk cross-references, query types, strings, segments and metadata. When explicitly permitted, annotate the database, patch bytes, run scripts, and drive the debugger.

It is built specifically for reverse-engineering workflows: read-first, lazy tool loading so small models stay on-task, and a strict opt-in gate for anything that mutates the IDB.

## What it does
- **Decompilation & disassembly**: Hex-Rays pseudocode, linear and structured disassembly, microcode summaries, flowcharts and CFG blocks.
- **Binary triage in one call**: `survey_binary()` returns metadata, stats, segments, entry points, notable strings/functions, categorized imports and a call-graph summary.
- **Function & component analysis**: per-function summaries, data-flow traces, bounded call-graphs, numeric profiles, and before/after diffs for rename/type/comment actions.
- **Deep queries**: filterable queries over functions, globals, imports, strings and names, plus typed memory readers, head navigation, and directional xrefs (code/data, calls/jumps, reads/writes).
- **Types, segments, metadata**: local type catalog, struct/enum management, segment permissions, compiler/arch info, file hashes, analysis status.
- **Search & signatures**: byte patterns with `??` wildcards, text/immediate/regex search, and shortest-unique signatures in `ida` / `x64dbg` / `mask` / `bitmask` formats.
- **Annotations & patches (gated)**: comments, renames, bookmarks, FLIRT signatures, data definition, asm/byte patching with revert support, and arbitrary IDA Python execution.
- **Debugger & tracers (gated)**: breakpoints, registers, stack, memory reads/writes, plus passive IDB / Hex-Rays / debugger hooks.

## Design
- **Zero dependencies.** The MCP transport is a vendored, trimmed server (`ida_mcp/zeromcp`) on top of stdlib `ThreadingHTTPServer`. No `mcp`, `uvicorn`, `fastapi` or `pip` packages at runtime.
- **Main-thread safety.** All IDA API calls are marshalled to the IDA main thread via `idaapi.execute_sync` through an `@idasync` layer with a queue-based result container, timeouts and cancellation support.
- **Simple tool model.** Tools are plain Python functions registered with `@tool` into a single `MCP_SERVER` registry. Unsafe tools are marked with `@unsafe` and hidden/refused unless the client opts in.
- **Lazy profiles.** Clients start with a 16-tool `triage` profile and escalate to `readonly` and then the full set only as needed, keeping agent context small.
- **Multi-instance aware.** Running instances register themselves on disk so tooling can discover and address several open IDA sessions.
- **IDA 9.x native.** Uses current APIs (`idaapi.BADADDR`, `insn.get_canon_mnem()`, `ida_bytes.find_bytes()`, `inf_get_min_ea/max_ea`) with shims for 8.3+ in `compat.py`.

## Safety model
By default the server is **read-only**. Mutating tools (renames, comments, type application, patching, script execution, IDB hooks) are invisible and rejected unless the endpoint is opened with `?unsafe=true`. Debugger tools additionally require the `dbg` extension group (`?unsafe=true&ext=dbg`). Profiles (`?profile=triage` / `?profile=readonly`) further restrict which tools are listed, so an agent only sees what the task requires.

## Tool surface
The plugin exposes ~240 tools across ~20 modules:

| Area | Examples |
|------|----------|
| Core analysis | `decompile_function`, `get_disassembly`, `disasm`, `lookup_funcs`, `basic_blocks` |
| Composite | `survey_binary`, `analyze_function`, `analyze_component`, `trace_data_flow`, `callgraph`, `func_profile` |
| Queries | `func_query`, `entity_query`, `imports_query`, `list_globals` |
| Xrefs & graphs | `get_xrefs_to`, `xref_query`, `get_callers`, `get_callees`, directional reads/writes/calls/jumps |
| Memory & data | `get_bytes`, `get_string`, scalar readers (`get_byte`…`get_qword`, floats), `get_heads`, BSS-safe reads |
| Strings / imports / exports | paginated listing, search, counts, range queries |
| Types | `type_query`, `type_inspect`, `read_struct`, `declare_type`, `enum_upsert` |
| Segments / functions / instructions | bounds, signatures, flags, locals, operands, predicates |
| Metadata | binary info, arch/compiler, hashes, Hex-Rays version, analysis status, IDB meta |
| Comments & bookmarks | regular/repeatable/extra comments, bookmarks |
| Search | bytes, text, immediates, regex, ranged search |
| Signatures | `make_signature*`, `find_xref_signatures`, FLIRT apply/list |
| Entries | listing, ordinal/name/address lookup, add/rename |
| Server | `server_health`, `server_warmup`, `list_instances` |
| Unsafe (opt-in) | `set_name`, `set_comment`, `patch_bytes`, `patch_asm`, `execute_script`, `py_eval` |
| Debugger (opt-in) | `dbg_start`, `dbg_continue`, `dbg_step_into/over`, breakpoints, `dbg_regs`, `dbg_stacktrace`, `dbg_read/write` |
| Hooks (tracers) | `install_hook`, `install_hexrays_hook`, `install_idb_hook`, `get_hook_info` |

All addresses accept hex (`0x401000`), decimal, or symbol names.

## How it works
```
MCP client -> HTTP POST /mcp -> request handler
                                     |
                          unsafe/profile gate (per-request)
                                     |
                                     v
                           MCP_SERVER.dispatch
                                     |
                                     v
                        tool function (@tool + @idasync)
                                     |
                                     v
                 idaapi.execute_sync --> IDA main thread
```

The handler parses `?unsafe=` / `?profile=` / `?ext=` per request (thread-local, no races), dispatches JSON-RPC `tools/list` and `tools/call` against the registry, and marshals IDA-touching calls onto the main thread with a timeout that can cancel stuck operations.

## Layout
| Path | Purpose |
|------|---------|
| `ida_mcp_loader.py` | IDA plugin entry point (`PLUGIN_ENTRY`) |
| `ida_mcp/server.py` | Core tools, server lifecycle, module wiring |
| `ida_mcp/api_*.py` | Tool modules (analysis, functions, xrefs, memory, strings, types, segments, instructions, info, comments, names, composite, query, hexrays, debug, hooks, sigmaker, search, modify, entries) |
| `ida_mcp/rpc.py` | `@tool` / `@unsafe` decorators and registry |
| `ida_mcp/sync.py` | `@idasync` main-thread bridge |
| `ida_mcp/profiles.py` + `profiles/` | Lazy-loading tool allowlists (`triage`, `readonly`) |
| `ida_mcp/compat.py` | IDA 8.3 to 9.x API shims |
| `ida_mcp/discovery.py` | Multi-instance registration/discovery |
| `ida_mcp/zeromcp/` | Vendored stdlib MCP transport |
| `skills/ida/` | Generic agent skill (`/ida-connect`): connect -> triage -> escalate methodology |
| `.pi/skills/ida/SKILL.md` | Pi Agent skill (`/ida`): lazy triage -> readonly -> full -> unsafe -> debugger methodology, auto-loaded by pi |
| `.pi/extensions/ida-mcp.ts` | Pi Agent extension: MCP bridge, `/ida` command, `ida_profile` / `ida_status` tools, footer status indicator |
| `tests/` | Standalone test scripts (run outside IDA with stubbed IDA modules) |

## Pi Agent integration
This repo includes a ready-to-use skill and extension for the [Pi Agent](https://github.com/earendil-works/pi). Just copy the contents of the `.pi` folder to your user's Pi Agent folder.

| Path | What it provides |
|------|------------------|
| `.pi/skills/ida/SKILL.md` | `/ida` skill: verify the bridge (`server_health`), triage with `survey_binary()`, then escalate `triage (16 tools) -> readonly (188) -> full (224) -> unsafe (+writes) -> dbg (+19 debugger tools)` only as needed |
| `.pi/extensions/ida-mcp.ts` | Extension bridge: proxies the plugin's Streamable-HTTP server (`http://127.0.0.1:13337/mcp`) into pi tools with lazy loading, `/ida [status\|triage\|readonly\|full\|unsafe\|dbg\|tools]` command, `ida_profile` / `ida_status` management tools, and a live `IDA:online/offline` footer indicator (polling + session-event refresh) |

- Endpoint ladder mirrors `INSTALL.md`: `?profile=triage` (default) -> `?profile=readonly` -> full -> `?unsafe=true` -> `?unsafe=true&ext=dbg`.
- Override the server URL with `IDA_MCP_URL` (default `http://127.0.0.1:13337/mcp`).
- Just type `/ida` in pi and start reversing the binary open in IDA Pro.

## Notes
- `decompile_function` output is plain text capped at 2000 lines. Everything else returns JSON.
- `get_bytes` is BSS-safe (unloaded bytes read as `0x00`).
- Oversized request bodies, non-loopback `Host` headers and foreign `Origin` values are rejected.
- Timeouts, host/port and autostart are configurable; per-IDB settings persist via netnodes.
- Requires IDA Pro 8.3+ (9.3 recommended) with Python 3.11+; IDA Free is not supported and Hex-Rays is needed for decompiler-backed tools.