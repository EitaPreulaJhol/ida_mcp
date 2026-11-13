# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Bounded `tools/call` admission queue (`IDA_MCP_TOOL_QUEUE`, default 8;
  `IDA_MCP_TOOL_QUEUE_WAIT_SEC`, default 15) so agents that fan out parallel
  calls wait for IDA's main thread instead of failing every call after the
  first. Queue wait is reported separately and does not consume the tool
  timeout; a full/timeout queue still returns a retryable `Server busy`.
- `initialize.instructions` tells clients that IDA is single-threaded and that
  tools must be called one at a time.
- Queue metrics in `server_health`: depth, p50/p95 wait, timeouts, full and
  cancelled counts.

### Changed
- Paginated tools now share one `limit` contract: `limit=0` (or negative)
  means "no client-side cap" — the tool applies its documented maximum, or all
  rows where no maximum is documented. `list_funcs(0)` uses its 1000 cap,
  `get_xrefs_to`/`xref_query` use 5000, `get_instructions`/`find_regex` use 500,
  and the previously defaulting/clamped tools return their maximum instead of
  the old default page. Applied limits are echoed where the payload has a
  `limit` field.
- String scans are interruptible and bounded: `get_strings_in_range`,
  `search_strings`, `get_string_count` and the fallback in `get_string_at`
  poll cancellation and return `partial`/`iterated_cap_reached` instead of
  freezing the IDA main thread until the full string table is walked.

## [0.3.0] - 2026-11-13

### Added
- `ida-plugin.json` (IDA metadata descriptor v1, plugin id `ida-mcp-bridge`)
  so IDA 8.5+ / HCLI / the Plugin Manager recognize the plugin and load it
  from a single folder.
- `dist/ida_mcp-<version>.zip` now contains one top-level `ida-mcp-bridge/` folder
  with the manifest, entry point, `ida_mcp/` package and docs.
- `dist/ida-mcp-legacy-<version>.zip` keeps the old root layout for IDA
  8.3/8.4 (no manifest).

### Changed
- The recommended install is now `$IDAUSR/plugins/ida-mcp-bridge/`; remove the old
  `plugins/ida_mcp/` + root `ida_mcp_loader.py` before upgrading.
- `ida_mcp_loader.py` publishes the bare `ida_mcp_loader` alias when IDA loads
  it under a generated `__plugins__...` namespace, so `ida_mcp/plugin.py`
  re-exports the same class instead of importing a second copy.
- `scripts/package.py` builds both ZIPs and checks `__version__` against
  `ida-plugin.json`; the release guard uses the same version.

## [0.2.4] - 2026-11-13

### Fixed
- Multi-byte reads are correct on IDA 9.5 again: `get_bytes_and_mask()`
  returns a **bit-packed** mask (one bit per byte), but `read_bytes_bss_safe()`
  indexed it as one mask byte per data byte. `get_bytes`, `get_word`,
  `get_dword`, `get_qword`, `get_int`, `get_float`, `get_double`,
  `get_global_value` and every SigMaker signature were reading zeros for all
  bytes after the first `ceil(size/8)`. Unmapped addresses (masked-out but not
  mapped) are now rejected with `is_mapped()` instead of being returned as a
  valid zero-filled block.
- `find_xref_signatures` keeps data xrefs from code (`iscode=False`); it used
  to filter exactly the string/global references it exists to signature.
- `_IdbTracer.cmt_changed` uses IDA 9.5's `(ea, repeatable_cmt)` signature;
  the old three-argument form raised `TypeError` on every comment change.
- `int_convert` auto-sizes positive values unsigned and negatives signed, so
  `128`, `255`, `-129` and similar values no longer report "too big".
- `get_microcode` maps `mba_maturity_t` to the real IDA 9.x names
  (`MMAT_LVARS`/`MMAT_GLBOPT*`), not the obsolete pre-9 enum.
- `list_patches` scans every byte of every segment (with cancellation and a
  1000-result cap); the old first-100 KB-per-segment limit silently missed
  patches further into large `.text` segments.
- `survey_binary` counts all strings in `statistics.total_strings`; the value
  used to be capped at 5000 by the interesting-string cache.
- `analyze_component` includes BSS globals (`is_mapped`, not `is_loaded`), and
  `trace_data_flow` labels uninitialized/BSS nodes as data instead of code.
- `_run_code` prefers an explicit `result`/`__result__` over a trailing
  expression, preserves a result of `0`/`False`, and reports the last real
  assignment (including reassignments and loop variables).
- A malformed non-scalar JSON-RPC `id` is rejected with `-32600` and cannot
  leak the tools/call gate; pending-request cleanup is also guarded in the
  `finally` path.
- SSE streams (`GET /mcp`, legacy `/sse`) send `Connection: close` and set
  `close_connection`, so clients receive EOF after `stop()`/`close_instance`
  instead of hanging on a kept-alive socket. Oversized/malformed request
  bodies also close the connection instead of leaving unread bytes for a
  pipelined request.
- `close_instance` marshals the deferred stop onto the GUI main thread via
  `execute_sync`; idalib (no message pump) keeps the direct path.
- `discovery` validates instance files (pid/port/host types) and skips a
  corrupt entry instead of aborting the whole scan; malformed `pid` values no
  longer reach `os.kill`.
- `delete_bookmark` prefers the address interpretation for low numeric values
  (`0x10`, `16`, ...) and accepts an explicit `slot:N`, so firmware/low-address
  bookmarks are deletable.
- `get_callees` reports `indirect` for `o_mem` call operands (GOT slots) rather
  than presenting the pointer slot as a resolved callee.
- `get_unicode_strings` covers the Pascal/LEN2/LEN4 16/32-bit string types.
- `get_strings_in_range`, `search_strings` and `get_heads` no longer report
  `truncated: true` when the result count is exactly `limit`.
- FLIRT listings unpack IDA's `(name, libs, matches)` tuples instead of
  stringifying them.

## [0.2.3] - 2026-11-13

### Added
- `tests/idalib_all_tools_test.py` (`make idalib`): opt-in live sweep that
  runs every safe tool once against a real IDB (temp DB copy) and fails on
  exceptions or on a deprecation warning from our own files. This is the
  sweep that found the 9.5 breakages.
- The docs cross-check now also scans `ida_mcp_loader.py` (the file IDA
  actually loads) and `getattr(module, "name")` fallbacks, with the
  intentional pre-9.x fallbacks allowlisted.
- The Pi bridge speaks the MCP session protocol: it runs `initialize` once
  (protocol `2025-06-18`), keeps the `Mcp-Session-Id` and sends it on every
  request; a `404` for an unknown id (IDA restarted) triggers a fresh
  initialize and one retry.
- `ida_profile` deactivates the IDA tools that are no longer visible when the
  ladder goes down, so escalating to `dbg` does not leave the whole tool set
  active for the rest of the session. Built-in tools are untouched.

### Changed
- Pagination arguments are `limit` everywhere (`list_imports`,
  `list_exports`, `list_strings`, `get_all_names`, `list_funcs`,
  `list_globals`, `func_query`, `entity_query`, `imports_query`,
  `get_strings_by_length`, `get_instructions`, `disasm`,
  `get_disassembly_text`, `get_disassembly`). The old `count` spelling still
  works: the server maps it before the call. Tools with a genuine `count`
  argument (`make_data`) are untouched.
- `get_local_variable_references` takes `name` instead of `var_name`; the
  server maps the old spelling.
- `get_functions` returns the standard pagination object
  `{data,total,offset,count,limit}` instead of a bare list.
- `list_strings` is the single string listing: the duplicate `get_strings`
  was removed and the surviving implementation bounds the enumeration, caps
  the scan and polls cancellation.
- Every tool schema carries MCP annotations: `readOnlyHint`/`idempotentHint`
  for reads and `destructiveHint` for the unsafe/mutating surface.

### Fixed
- The plugin never auto-started: `IdaMcp.init()` called
  `ida_kernwin.install_ui_hook()`, which does not exist (the UI hook is
  installed with `UI_Hooks.hook()` / removed with `unhook()`). The
  `AttributeError` was swallowed, so `ready_to_run()` never fired and the
  server only came up when the plugin was picked from the menu.
- `add_bookmark` passed the free slot as `mark_position()`'s `lnnum` argument
  and always used slot 0: a second bookmark overwrote the first, and a
  nonzero line number raised IDA's "Internal error 1312".
- `delete_bookmark` looked for `idc.del_bookmark`, removed in IDA 9.x, so it
  always answered "unavailable". The entry is now cleared through
  `mark_position(BADADDR, ...)` (or `del_bookmark` on older IDAs) and the
  marks array is re-read to confirm one entry disappeared.
- Bookmarks at address 0 were treated as empty slots and overwritten;
  emptiness is `BADADDR` only.
- `search_immediate_value` and `find_immediate_between` raised `TypeError` on
  the first call: `ida_search.find_imm()` returns an `(ea, value)` tuple on
  IDA 9.x (its SWIG annotation and the reference both say `int *`), and the
  tools used the result as an address. Both shapes are accepted now.
- `read_struct` reported every field type as `<unknown>`: it only knew the
  pre-9.x `udm_t.type.get(out)` accessor, while 9.x exposes `udm_t.type` as a
  `tinfo_t` property. `_udm_member_type()` now handles both shapes and feeds
  the same helper used by `_format_tinfo`.
- `add_bookmark` with the default (empty) description raised IDA's "Internal
  error 1312": `mark_position` rejects an empty comment. A single space is
  sent instead and stripped back to `""` when the bookmarks are listed.
- The IDA 9.5 deprecations no longer fire from our call sites: the frame,
  function-comment and segment helpers prefer the `_ea` variants
  (`get_func_frame_ea`, `soff_to_fpoff_ea`, `is_funcarg_off_ea`,
  `get_frame_size_ea`, `get_func_cmt_ea`, `get_segment_cmt_by_ea`,
  `get_segment_class`) and keep the old spellings as fallbacks, while segment
  iteration uses `idautils.Segments()` instead of the deprecated `getnseg`.
  The two warnings emitted by `idautils`' own `Functions()`/`FuncItems()`
  iterators are filtered in `compat`, the only place that installs warning
  filters.
- Pagination limits are clamped to each tool's documented maximum instead of
  being silently reset to the default (xref, head, name, string, search and
  disassembly tools); the applied value is echoed as `limit`. `disasm` now
  reports the requested address in `addr` and the stop address in `next_ea`
  (it used to report the end address in `addr`).
- `limit=0` consistently means "no cap": `get_callers` returned an empty list
  and `list_funcs(limit=0)` an empty page; `list_funcs` also clamps oversized
  limits to 1000.
- `func_count` uses `ida_funcs.get_func_qty()` (O(1)) instead of walking the
  whole function list.
- `type_query` stops as soon as the requested page is full (it formatted every
  type in the til first), `search_structs` filters on the name before
  formatting, and both poll `check_cancelled()`. `get_all_comments` polls it
  too and reports `partial` when interrupted.
- `get_data_flags` decodes the FF_* bits and the data type instead of
  returning only the raw value.
- `get_segment_bitness` (and the segment listings) report 16/32/64 instead
  of IDA's internal 0/1/2 code; the raw code is kept under `raw`.
- `get_analysis_prompt` no longer says "1 import modules".
- `pyproject.toml` ships `ida_mcp_loader.py` as a top-level module, so a
  wheel carries both halves of the plugin instead of just the package.

## [0.2.2] - 2026-11-10

### Added
- `IDA_MCP_AUDIT_FULL=1`: with the audit log enabled, the *untruncated* tool
  arguments are appended to `<audit_path>.args.jsonl` and the main record points
  at it (`args_full`). The short preview stays where it is; the full script body
  is now recoverable instead of only its hash and length.

### Changed
- `resolve_addr` / `paginate` replace the byte-identical private copies that
  `api_memory`, `api_hexrays`, `api_xrefs` and `api_query`/`api_strings` each
  carried: the address-error convention and the offset/count slicing have one
  definition now.
- `search_bytes` scans `inf_get_min_ea()..inf_get_max_ea()` like the other
  search tools, instead of the fixed `0..2^64-1` window that relied on IDA
  clamping it to the database.

### Fixed
- Hooks installed by an agent no longer record events from *another* database:
  IDA keeps the process (and the hook) alive across File > Open, so a tracer
  used to mix the next binary's renames and patches into the previous one's
  buffer. Each hook remembers its idb, drops foreign events and reports
  `stale`, and the idb is listed in `get_hook_info`.
- Instance discovery probes only addresses that can be this machine (loopback,
  the wildcard bind, or one of this host's own addresses). It used to pass the
  instance file's `host` straight to `socket.create_connection()`, so a file
  naming any address made IDA open a connection there; such entries are now
  listed with `unverified: true` and hostnames are never resolved.

## [0.2.1] - 2026-11-10

### Added
- Regression tests for the review batch: `tests/search_flags_test.py`
  (`search_text`/`find_text_between` flag bits), `tests/modify_test.py`
  (`make_data` arity, bounded `patch_bytes`), `tests/packaging_test.py`
  (profile files in a wheel), `tests/profile_http_test.py` (profile contract
  and `arguments` type over live HTTP), plus new cases in
  `tests/query_test.py` (deep-nesting regex), `tests/composite_test.py`
  (`callgraph` depth clamp), `tests/sync_test.py` (`IDASyncError` mapping,
  cross-thread request cancellation), `tests/memory_test.py` (clamped reads,
  BSS vs unmapped) and `tests/strings_test.py` (clamped limits, bounded scan).
- MCP **session enforcement**: a request that carries an `Mcp-Session-Id` the
  server did not issue (stale, expired, pruned, or from a previous IDA run) is
  answered `404`, the Streamable HTTP signal to `initialize` again; `DELETE
  /mcp` terminates the session and `GET /mcp` validates the id too. Requests
  without an id (the `curl` examples, stateless clients) are unaffected.
- `IDA_MCP_REQUIRE_TOKEN=1` requires the auth token on **every** request,
  read-only tools and loopback included, without binding off-loopback. Off by
  default; `server_health` reports the mode.
- A connection cap (`McpServer.max_connections`, default 64, `503` beyond it)
  and an idle timeout (`idle_timeout_sec`, default 30 s) on the threaded HTTP
  server, bounding a local process that opens sockets to exhaust IDA's threads.

### Changed
- Lint now enforces all of flake8-bugbear (**B**), not just B904. The findings
  split in three groups: the 18 sites that raise inside an `except` state their
  cause explicitly (`from e` where the wrapper adds context -- debugger, FLIRT
  and hook errors; `from None` where it carries the whole message and a chained
  duplicate would only add noise -- the `parse_addr` translations and the
  dropped-`execute_sync` sync error); the import enumeration in
  `api_query`/`api_composite` no longer defines its callback inside the loop
  (it only works today because `enum_import_names` is synchronous); and the
  `@tool_timeout`/`@keep_batch`/`@hard_interrupt` decorators set their
  attribute directly instead of through `setattr`.
- CI and `.pre-commit-config.yaml` move to ruff 0.17.4 (from 0.6.9), the version
  the rule set was re-verified with; the `dev` extra now requires `ruff>=0.17`.
  `F`/`E`/`W`/`C4` report nothing on the tree under either version.
- CI and release workflows move to Node 24 actions (`actions/checkout@v7`,
  `actions/setup-python@v7`, `softprops/action-gh-release@v3`); the Node 20
  versions were deprecated and already being forced onto Node 24.
- `tests/run_all.py` gives every harness a 300 s wall-clock limit and counts a
  timeout as a failure; the CI and release jobs set `timeout-minutes`, so a
  stuck harness can no longer hold a runner.
- `close_instance` replies before stopping: the server now goes away about a
  second later instead of joining the HTTP thread on the IDA main thread
  (which froze the UI before the reply was written).
- The SigMaker uniqueness probe runs every 8 instructions and bisects the last
  chunk instead of after every instruction: building a signature no longer
  costs one database-wide scan per instruction, with an identical result.

### Removed
- `idasync_read` (MFF_READ) and the dead `EXTERNAL_BASE_HEADER`,
  `_enabled_extensions`, `require_streamable_http_session` and
  `has_http_session` members. No tool can run under MFF_READ (every read tool
  calls `ensure_analysis()`, which mutates the database), and the rest had no
  readers. Unused until now, so no client is affected.

### Fixed
- `search_text` and `find_text_between` sent `0` (= `SEARCH_UP`) for
  `case_sensitive=True` and `SEARCH_CASE` for `case_sensitive=False`: they
  searched towards lower addresses (so `search_text` returned no matches at
  all) and had the case flag inverted. Both now OR `SEARCH_DOWN` in and only
  add `SEARCH_CASE` when requested; `find_text_between` also drops matches
  outside `[start, end)`.
- `make_data` called `create_byte(ea)` (and friends) without the byte count,
  which is a required argument on IDA 9.x: every scalar type raised
  `TypeError` before creating the item. It now passes the item size and also
  refuses unmapped addresses.
- `callgraph` clamps `max_depth` to 20 like `trace_data_flow` instead of
  accepting an unbounded depth that recursed into `RecursionError`.
- Sync-layer failures (timeouts, dropped `execute_sync` requests, aborted
  tools) map to a clean JSON-RPC `-32000` with the plain message instead of
  `-32603` with the sync wrapper's traceback.
- `check_cancelled()` now sees request cancellation: the cancel event is
  published into the main-thread state by `sync_wrapper`, instead of being
  read from an HTTP-thread-local that is empty on the IDA main thread.
- `compile_client_regex` turns a `RecursionError` from deeply nested client
  patterns into a `re.error`, so the query tools answer `Invalid regex`
  instead of returning a traceback.
- A packaged wheel now includes `ida_mcp/profiles/*.txt`
  (`[tool.setuptools.package-data]`); without them `?profile=` was silently
  ignored after `pip install`, widening the tool list from 16 to 186.
- An unknown `?profile=` is rejected with `-32602` naming the requested and the
  available profiles. It used to fail open (no filtering), so a typo widened
  the listed tool set instead of showing the requested one.
- A non-object `arguments` (`["0x1000", 16]`) is rejected with `-32602` instead
  of reaching the tool positionally (`func(*params)`), which bypassed the JSON
  schema and the scalar coercion.
- Oversized pagination parameters are clamped to the documented maximum and the
  applied value is reported (`limit`, or `requested`/`truncated` on
  `get_bytes`) instead of being reset to the default: `size=8192` used to read
  64 bytes and `limit=10000` returned 100 entries, which reads as end-of-data.
- `get_bytes`/`get_byte`/`get_dword`/… on an unmapped address return an error
  instead of a zero-filled block: `read_bytes_bss_safe` now uses
  `get_bytes_and_mask()` to tell uninitialized (BSS) bytes from an address that
  is not in the program at all.
- `patch_bytes` validates the address is mapped, caps the write at 64 KiB and
  issues one bulk `ida_bytes.patch_bytes()` call; it used to loop per byte over
  unbounded input on the IDA main thread.
- The string enumerators honour `_MAX_STRINGS` and poll `check_cancelled()`
  every 2048 entries instead of materializing the whole string table before
  paginating, which froze the main thread on a large binary.
- `make_data` reports the requested address (`addr`) plus where the conversion
  ended (`next_ea`); the string branch used to return only the end address, and
  skipped a NUL byte looking for strings *after* a terminator.
- `discovery` no longer raises `KeyError` when `%APPDATA%` is missing (service
  contexts, stripped Windows profiles): it falls back to `~/AppData/Roaming`.
- `SIGPIPE` is ignored only while the HTTP server runs and the previous handler
  is restored on stop. Importing `ida_mcp` used to change the signal
  disposition of the whole IDA process, for every other plugin.
- A tool body that replaces `sys.setprofile()` (e.g. a script) is detected: the
  soft timeout is no longer silently unenforced there, a warning is logged and
  the host's pre-call profiler is restored instead of leaking the script's.
- The audit log distinguishes the `unsafe` and `dbg` surfaces (`level`) and
  keeps `code_sha256`/`code_len` for the script tools, whose code was otherwise
  cut off by the 200-char args preview.
- The managed hook registry now stores a tracer *before* calling `hook()`, so
  an event delivered from inside `hook()` is no longer dropped, and a `hook()`
  that fails removes its entry instead of leaving a dead one behind.
- `list_profiles()` returns copies of the cached sets: mutating the result used
  to change the profile gate for every later request.

## [0.2.0] - 2026-11-08

### Added
- GitHub Actions CI: standalone test suite on Python 3.11/3.12 + ruff lint,
  mypy (pure modules, enforced) and an informational coverage job.
- `pyproject.toml` with project metadata, dynamic version, ruff + mypy +
  coverage config.
- `__version__` (surfaced in `server_health`).
- MIT `LICENSE`.
- `CONTRIBUTING.md`: architecture, drift-guard invariants, add-a-tool flow.
- `Makefile` and `.pre-commit-config.yaml` for standardized dev tasks.
- `CHANGELOG.md`, `scripts/package.py` (plugin zip) and a tag-triggered
  `release.yml` workflow.
- Request-flow architecture diagram in the README.
- README "Configuration" section documenting every `IDA_MCP_*` env var.
- Docstring presence check in the tool-inventory drift guard.
- Per-tool metrics (call/error/busy counts + p50/p95/max timing) surfaced via
  `server_health` `stats`.
- Opt-in JSONL audit trail of mutating calls (`IDA_MCP_AUDIT`).
- `IDA_MCP_REDACT_ERRORS=1`: unexpected tool exceptions reach the client as a
  one-line `Internal Error` (traceback logged server-side instead).
- MCP **resources** (`ida://triage`, `ida://health`) and a **prompt**
  (`reverse-engineer`); capabilities advertised only when registered.
- Tests: metrics/audit, resources/prompts, a skip-if-absent IDAPython-docs
  cross-check, and an opt-in idalib headless integration gate.
- `compat.badaddr()` gains a type-checked, documented pre-9.3 fallback.

### Changed
- Test harnesses load the real `ida_mcp` modules through `tests/_harness.py`
  (stubbed siblings, true file paths) instead of `exec`-ing string-rewritten
  source under fake names. Same assertions; coverage now attributes the
  executed lines: the report went from ~10% to ~68% (`sync.py` 0% -> 64%,
  `server.py` 0% -> 81%), and new import lines no longer break harnesses.
- A second IDA instance no longer fails to start when its port is taken:
  `start_server` falls back to the next free port (up to +9), prints it, and
  returns it; the loader uses the bound port for stop while the IDB keeps the
  requested one.
- Bound off-loopback (`IDA_MCP_HOST`) with auth on, the server now requires
  the token on every request (401 otherwise), not only for unsafe/debugger
  tools; CORS preflights are exempt and now allow `X-IDA-MCP-Token`.
- The per-tool profile hook (timeouts/cancel/wait-box pump) now runs its
  checks only on a 50 ms tick instead of on every call/return event:
  call-heavy tool code went from ~9.6x to ~5x the unhooked time and a
  typical list/JSON tool from ~1.9x to ~1.4x, with cancel/timeout latency
  still bounded by time.
- `skills/` is the single source of truth for the agent skills; `.pi/skills/`
  is a byte-for-byte mirror refreshed by `make skills`, and
  `tests/skills_sync_test.py` fails on drift or on an unquoted (non-strict
  YAML) frontmatter value. The two copies had already diverged.
- Lint enforces `F`, `E`, `W` and `C4` (all clean); CI pins ruff 0.6.9 like
  pre-commit, and runs the suite on Windows as a required job.
- `[dev]` extras now install mypy and coverage too.
- Tools now start with `ensure_analysis()` instead of a bare
  `ida_auto.auto_wait()` (~200 call sites): an immediate return once analysis
  is done, and a clean retryable "Auto-analysis still in progress" error
  instead of holding the IDA main thread until the tool timeout.
  `wait_for_analysis` keeps its plain wait.
- `_mcp_initialize` advertises `resources`/`prompts` capabilities only when
  something is registered (previously always).

### Fixed
- Discovery treated a live instance owned by another user as dead (EPERM /
  access denied) and deleted its registration. On Windows it also counted
  exited-but-still-referenced processes as alive, and truncated the
  process handle on x64 (default `c_int` restype).
- The release workflow no longer publishes a tag whose version differs from
  `__version__` (e.g. `v0.2.0` shipping `ida_mcp-0.1.0.zip`):
  `scripts/package.py --expect-version` refuses before building.
- `list_instances` / `get_instance_info` no longer run on the IDA main
  thread: discovery never touches the SDK, and its TCP probes (up to 1 s
  each) froze the UI and held the tool gate.
- `unload_package` (manual hot reload) now stops the server started from the
  modules it drops. With the port fallback, the next `run(0)` would
  otherwise start a second server while the stale one kept serving.
- Hooks installed by agents (`install_hook` & co.) are now removed when the
  server stops (plugin toggle/term, `close_instance`); they used to stay
  hooked into IDA with no owner, running orphaned code after a hot reload.
- `execute_script` / `py_eval` / `py_exec_file` ran scripts with separate
  globals and locals dicts, so any function or comprehension using a name
  defined at the script's top level (a constant, a helper, a variable)
  failed with `NameError`. Scripts now run in one namespace, like a module
  or the IDA console; result selection is unchanged.
- `make lint` / `typecheck` / `coverage` printed "not installed" and exited 0
  when the tool *failed*, so they never failed. They now propagate errors,
  exit 1 when the tool is missing, and also find tools installed as
  `python -m <tool>` modules without a script on PATH.
- pi extension: could not send the auth token, so its `unsafe`/`dbg` levels
  failed with the default (random-token) setup. It now sends `IDA_MCP_TOKEN`
  as `X-IDA-MCP-Token`, explains token errors, and joins the ladder query
  with `&` when `IDA_MCP_URL` already has one.
- `patch_asm`: `idc.Assemble` (removed in IDA 9.x) replaced with
  `idautils.Assemble` + `ida_bytes.patch_bytes` so the tool still patches.
- `ida-scripting` skill: `ida_search.find_binary` (removed in 9.x) replaced
  with `ida_bytes.find_bytes` using the correct argument order.
- `compat.badaddr()`: dead `ida_bytes.BADADDR` fallback replaced with the real
  pre-9.3 `ida_ida.BADADDR`.
- Removed unused imports flagged by ruff across `api_*` and `server`.
- `INSTALL.md`: documents the unsafe/debugger auth token (no longer claims "no
  auth") and corrects the harness count.
- The transport's unraisable-exception hook called itself for anything that
  was not a client disconnect (infinite recursion, swallowing every such error
  in the IDA process). It now forwards to the previous hook, is installed by
  `serve()` instead of at import, and is restored by `stop()`.
- `@idasync` no longer blocks forever when IDA drops an `execute_sync` request
  (e.g. while the database closes); it raises a retryable `IDASyncError`
  instead of holding the tool gate ("Server busy" until restart). An abandoned
  request that IDA starts late does not run the tool body.
- `resources/read` now shares the `tools/call` concurrency gate, output cap
  and metrics, and a resource registered with `tool=` is only listed/readable
  where its backing tool is (profile / `?unsafe=` / `?ext=` + token).
- Metrics and the audit log are recorded even with the concurrency gate
  disabled; failed audited calls record their error text.
  `max_concurrent_tools = N` now actually admits N concurrent calls.
- `notifications/cancelled` is scoped to the caller's session
  (`Mcp-Session-Id` / legacy SSE session): a client can no longer cancel
  another client's request that happens to share its JSON-RPC id.
- `initialize` negotiates `protocolVersion` against the revisions the server
  speaks (unknown/missing -> `2025-06-18`) instead of echoing any string, and
  a malformed JSON body now gets `-32700 Parse error` instead of `-32600`.
- `get_analysis_status` no longer waits for auto-analysis first (it always
  reported "complete" or hit the timeout); `get_version_info` no longer waits.

## [0.1.0] - 2026-11-03

Initial versioned baseline: 243 tools across 22 modules, zero-dependency
vendored MCP transport, main-thread-safe `@idasync` layer, lazy `triage` /
`readonly` profiles, token-gated unsafe/debugger surface, and the `/ida` +
`ida-scripting` agent skills.

[Unreleased]: https://github.com/EitaPreulaJhol/ida_mcp/compare/v0.2.2...HEAD
[0.2.2]: https://github.com/EitaPreulaJhol/ida_mcp/releases/tag/v0.2.2
[0.2.1]: https://github.com/EitaPreulaJhol/ida_mcp/releases/tag/v0.2.1
[0.2.0]: https://github.com/EitaPreulaJhol/ida_mcp/releases/tag/v0.2.0
[0.1.0]: https://github.com/EitaPreulaJhol/ida_mcp/tree/5d12fb0
