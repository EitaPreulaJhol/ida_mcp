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
The plugin exposes 243 tools across 22 modules:

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

## Tool inventory

Every registered tool, grouped by module (names match `tools/list` exactly).

### `api_analysis` (16)

`basic_blocks`, `disasm`, `find_bytes`, `get_bytes`, `get_callees`, `get_callers`, `get_string`, `get_xrefs_to`, `int_convert`, `list_exports`, `list_imports`, `list_strings`, `lookup_funcs`, `rename_function`, `set_comment`, `xref_query`

### `api_comments` (10)

`add_bookmark`, `delete_bookmark`, `delete_comment`, `get_all_comments`, `get_bookmarks`, `get_comment`, `get_extra_comments`, `get_repeatable_comment`, `set_extra_comment`, `set_repeatable_comment`

### `api_composite` (7)

`analyze_component`, `analyze_function`, `callgraph`, `diff_before_after`, `func_profile`, `survey_binary`, `trace_data_flow`

### `api_debug` (19)

`dbg_add_bp`, `dbg_bps`, `dbg_continue`, `dbg_delete_bp`, `dbg_exit`, `dbg_get_threads`, `dbg_gpregs`, `dbg_read`, `dbg_regs`, `dbg_regs_named`, `dbg_run_to`, `dbg_set_bp_condition`, `dbg_stacktrace`, `dbg_start`, `dbg_status`, `dbg_step_into`, `dbg_step_over`, `dbg_toggle_bp`, `dbg_write`

### `api_entries` (8)

`add_entry_point`, `get_entry_forwarders`, `get_entry_point_at`, `get_entry_point_by_name`, `get_entry_point_by_ordinal`, `get_entry_point_count`, `get_entry_points`, `rename_entry_point`

### `api_functions` (25)

`create_function`, `delete_function`, `func_count`, `get_function_args_size`, `get_function_bounds`, `get_function_comment`, `get_function_edges`, `get_function_end`, `get_function_flags`, `get_function_frame_size`, `get_function_instructions_count`, `get_function_signature`, `get_function_size`, `get_function_start`, `get_function_type`, `get_functions_in_range`, `get_local_variables`, `get_next_function`, `get_register_variables`, `is_function_library`, `is_function_noreturn`, `is_function_thunk`, `list_funcs`, `set_function_comment`, `set_function_name`

### `api_hexrays` (4)

`force_recompile`, `get_basic_blocks`, `get_flowchart`, `get_microcode`

### `api_hooks` (5)

`get_hook_info`, `install_hexrays_hook`, `install_hook`, `install_idb_hook`, `remove_hooks`

### `api_info` (18)

`get_analysis_prompt`, `get_analysis_status`, `get_architecture_info`, `get_base_address`, `get_binary_info`, `get_compiler_info`, `get_current_binary_name`, `get_hexrays_version`, `get_image_size`, `get_input_file_md5`, `get_input_file_path`, `get_input_file_sha256`, `get_problems`, `get_processor_info`, `get_version_info`, `idb_meta`, `idb_save`, `wait_for_analysis`

### `api_instructions` (16)

`breaks_flow`, `get_instruction`, `get_instruction_bytes`, `get_instruction_size`, `get_instructions`, `get_instructions_in_range`, `get_mnemonic`, `get_operand`, `get_operand_info`, `get_operands`, `get_operands_count`, `is_call_instruction`, `is_conditional_jump`, `is_indirect_jump`, `is_jump_instruction`, `is_ret_instruction`

### `api_memory` (19)

`get_byte`, `get_cstring`, `get_data_flags`, `get_data_size`, `get_disassembly_text`, `get_double`, `get_dword`, `get_float`, `get_global_value`, `get_heads`, `get_int`, `get_next_addr`, `get_next_head`, `get_prev_addr`, `get_prev_head`, `get_qword`, `get_word`, `is_code`, `is_data`

### `api_modify` (8)

`get_original_bytes`, `list_patches`, `make_data`, `patch_asm`, `patch_bytes`, `rename_address`, `revert_patch`, `undefine`

### `api_names` (12)

`delete_name`, `demangle_name`, `force_name`, `get_all_names`, `get_demangled_name`, `get_name`, `is_name_public`, `is_name_weak`, `make_name_non_public`, `make_name_public`, `set_name`, `validate_name`

### `api_python` (2)

`py_eval`, `py_exec_file`

### `api_query` (6)

`entity_query`, `func_query`, `get_local_variable_by_name`, `get_local_variable_references`, `imports_query`, `list_globals`

### `api_search` (7)

`find_bytes_between`, `find_immediate_between`, `find_regex`, `find_text_between`, `search_bytes`, `search_immediate_value`, `search_text`

### `api_segments` (13)

`get_code_segments`, `get_data_segments`, `get_segment_at`, `get_segment_bitness`, `get_segment_by_name`, `get_segment_class`, `get_segment_comment`, `get_segment_count`, `get_segment_end`, `get_segment_permissions`, `get_segment_size`, `get_segment_start`, `get_segments`

### `api_sigmaker` (6)

`apply_flirt_signatures`, `find_xref_signatures`, `list_flirt_signatures`, `make_signature`, `make_signature_for_function`, `make_signature_for_range`

### `api_strings` (8)

`get_ascii_strings`, `get_string_at`, `get_string_count`, `get_strings`, `get_strings_by_length`, `get_strings_in_range`, `get_unicode_strings`, `search_strings`

### `api_typeinfo` (10)

`declare_type`, `enum_upsert`, `get_type_at`, `get_type_by_name`, `infer_types`, `read_struct`, `search_structs`, `set_type`, `type_inspect`, `type_query`

### `api_xrefs` (15)

`get_callee_count`, `get_caller_count`, `get_calls_from`, `get_calls_to`, `get_code_refs_from`, `get_code_refs_to`, `get_data_refs_from`, `get_data_refs_to`, `get_jumps_to`, `get_reads_of`, `get_writes_to`, `get_xref_count`, `get_xrefs`, `get_xrefs_from`, `xrefs_to_field`

### `server` (9)

`close_instance`, `decompile_function`, `execute_script`, `get_disassembly`, `get_functions`, `get_instance_info`, `list_instances`, `server_health`, `server_warmup`

<!-- total: 243 tools -->

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

## Agent skills
`/ida` is the orchestrator (connect → `survey_binary()` triage → escalate `triage → readonly → full → unsafe → dbg` → route). After triage, load exactly one domain skill below (progressive disclosure). Full catalog with ceilings: `skills/INDEX.md` (generic) / `.pi/skills/INDEX.md` (pi). Both trees ship the same 62 domain skills + `ida` (`skills/` for Claude Code/Cursor/Copilot, `.pi/skills/` for Pi Agent).

### Reverse engineering & triage
| Skill | What it does |
|-------|--------------|
| `generic-re` | General-purpose binary analysis — functionality, architecture, behavior |
| `reverse-engineering` | Binary analysis, decompilation, control/data flow, reconstruction |
| `ctf` | CTF reverse engineering — find the flag fast |
| `firmware-re` | Firmware / embedded / blobs, unknown arch, hardware interfaces |
| `protocol-analysis` | Network protocols, packet structures, state machines |
| `crypto-analysis` | Crypto identification — algorithms, constants, math ops |
| `ai-features` | Semantic search, similarity detection, auto-documentation |
| `code-quality-metrics` | Complexity, maintainability, and security metrics |
| `ida-scripting` | Write and execute IDAPython scripts (full API reference) |

### Vulnerability discovery & exploitation
| Skill | What it does |
|-------|--------------|
| `vuln-audit` | Security audit — overflows, format strings, integer issues, memory safety |
| `0day-find` | Novel 0day classes — allocator bugs, compiler-induced bugs, SIMD/JIT, ASLR/kASLR bypass |
| `code-vulnerability-analysis` | Source-level 0day discovery & exploit development |
| `memory-corruption` | UAF/OOB + PAC/ASLR/CFI/CET bypass, binary exploitation |
| `rce-detection` | RCE vectors — command injection, deserialization, template/eval injection |
| `race-condition` | TOCTOU, double-fetch, thread-safety races |
| `crypto-vuln` | Crypto implementation bugs — weak algorithms, side-channels, padding oracles, RNG failures |
| `lpe-detection` | LPE enumeration — kernel exploits, services, SUID/GUID, path hijack, cron |
| `rop-builder` | ROP chain construction — gadgets, ASLR/DEP bypass |
| `shellcode-generator` | Position-independent shellcode (Linux/Windows) |
| `auto-exploit` / `automated-exploit-gen` | Automatic exploit generation from vuln analysis |
| `core-vulnerability-pipeline` | Shared pipeline — discovery, FP filtering, exploit generation |
| `triage-validation` | 7-Question Gate + pre-submit gates before reporting (run BEFORE `report-writing`) |
| `report-writing` | H1/Bugcrowd/Intigriti/Immunefi reports — tone, CVSS 3.1, impact-first |
| `deobfuscation` | String decryption, CFF removal, opaque predicates, MBA, anti-disassembly |
| `vm-obfuscation-detection` | VM/packer detection — VMProtect, Themida, UPX, CFF |
| `smart-patch-ida` | Natural-language patching — read, assemble, write, verify |
| `modify` | Explore → plan → patch → save loop |

### Malware
| Skill | What it does |
|-------|--------------|
| `malware-analysis` | Windows PE — kill chain, IOC extraction, MITRE ATT&CK |
| `linux-malware` | ELF — packing, toolchain ID, persistence, C2, rootkits, miners, Go/Rust/Mirai |
| `mobile-malware-analysis` | Android/iOS malware behavior analysis |

### Kernel & drivers
| Skill | What it does |
|-------|--------------|
| `driver-analysis` | Windows drivers — DriverEntry, dispatch table, IOCTL audit |
| `kernel-mode-analysis` | Kernel driver vulns — IOCTL handlers, dangerous APIs, primitives |
| `kernel-exploit` | Kernel exploitation — drivers, syscalls, privesc |
| `linux-driver-exploit` | Linux kmod — ioctl bugs, heap overflow, cred escalation |
| `windows-driver-exploit` | Windows kmod — IOCTL bugs, pool overflow, token theft |
| `macos-driver-exploit` | macOS kext — IOKit bugs, heap overflow, task credentials |

### Mobile & apps
| Skill | What it does |
|-------|--------------|
| `apk-analysis` | APK RE — structure, strings, native libs, manifest |
| `android-exploit` | Android native/IPC exploitation |
| `ios-exploit` | iOS IPA/kernel/sandbox escape |
| `mobile-pentest` | Mobile pentest — ADB/SSH automation, device control |
| `ssl-pinning-bypass` | SSL pinning detection and bypass |
| `app-shielding-bypass` | Root/JB detection, anti-debug, obfuscation bypass |
| `owasp-mobile-top10` | OWASP Mobile Top 10 2024 |
| `cloud-mobile-security` | Mobile backends — Firebase, AWS, Azure, GCP misconfigs |

### Web, smart contract & bounty
| Skill | What it does |
|-------|--------------|
| `web-app-security` | OWASP web apps — auth, input validation, API security |
| `owasp-web-top10` | OWASP Web Top 10 (A01–A10) patterns and remediation |
| `web-csharp-php-vuln` | PHP/C# scanner — POP chains, RCE, SQLi, XSS, SSRF, IDOR |
| `web2-recon` | Subdomain enum → live hosts → URL crawl → JS secrets → fuzzing |
| `web2-vuln-classes` | 20 web2 bug classes + bypass tables + paid examples |
| `bug-bounty` / `bb-methodology` | Master bounty workflow / 5-phase orchestrator — start here when lost |
| `web3-audit` | Solidity/Rust DeFi audit — 10 bug classes, Foundry PoC, Immunefi examples |
| `web3-vuln` | Smart contracts, bridges, NFTs/tokens, reentrancy, MEV/flash loans |
| `meme-coin-audit` | Token/rug-pull diligence — honeypots, mint/freeze authority, LP drains |

### Infra, ICS & cross-cutting
| Skill | What it does |
|-------|--------------|
| `container-escape` | Docker/K8s/runtime escapes, namespace bypass |
| `vm-escape` | Hypervisor escapes, device emulation, cross-VM side-channels |
| `iot-vuln` | IoT — firmware extraction, RTOS, protocols, update mechanisms |
| `scada-vuln` | ICS/SCADA — Modbus, DNP3, IEC 104, PLC logic manipulation |
| `security-arsenal` | Payloads, bypass tables, wordlists, reject/chain tables — what (not) to submit |
| `prompt-injection` | Embedded prompt-injection in binaries/apps/docs — hijack markers, Unicode evasion |
| `collaborative-analysis` | Team workflows — share findings, merge analysis, reports |

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
| `skills/ida/` | Generic agent skill (`/ida`): connect -> triage -> escalate methodology + routing table for the 62 domain skills |
| `skills/<slug>/` (62 domain + `ida`) + `skills/INDEX.md` | Generic domain skills (RE, vuln audit, exploit, malware, kernel/drivers, mobile, web/web3, ICS/infra), IDA-native throughout; ceilings in `INDEX.md` |
| `.pi/skills/ida/SKILL.md` | Pi Agent skill (`/ida`): lazy triage -> readonly -> full -> unsafe -> debugger methodology + `/skill:<slug>` routing, auto-loaded by pi |
| `.pi/skills/<slug>/` (same 62 domain + `ida`) + `.pi/skills/INDEX.md` | Pi domain skills (same content as `skills/`, pi-formatted frontmatter, progressive disclosure) |
| `.pi/extensions/ida-mcp.ts` | Pi Agent extension: MCP bridge, `/ida` command, `ida_profile` / `ida_status` tools, footer status indicator |
| `tests/` | Standalone test scripts (run outside IDA with stubbed IDA modules) |

## Pi Agent integration
This repo includes a ready-to-use skill and extension for the [Pi Agent](https://github.com/earendil-works/pi). Just copy the contents of the `.pi` folder to your user's Pi Agent folder.

| Path | What it provides |
|------|------------------|
| `.pi/skills/ida/SKILL.md` | `/ida` skill: verify the bridge (`server_health`), triage with `survey_binary()`, then escalate `triage (16 tools) -> readonly (188) -> full (224) -> unsafe (+writes) -> dbg (+19 debugger tools)` only as needed |
| `.pi/skills/<slug>/` (62 domain skills) + `.pi/skills/INDEX.md` | Domain skills invoked as `/skill:<slug>` after triage — RE, vuln/exploit, malware, kernel/drivers, mobile, web/web3/bounty, ICS/infra (see Agent skills above for the full list) |
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