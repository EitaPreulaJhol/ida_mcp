# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

### Changed
- CI and release workflows move to Node 24 actions (`actions/checkout@v7`,
  `actions/setup-python@v7`, `softprops/action-gh-release@v3`); the Node 20
  versions were deprecated and already being forced onto Node 24.
- `tests/run_all.py` gives every harness a 300 s wall-clock limit and counts a
  timeout as a failure; the CI and release jobs set `timeout-minutes`, so a
  stuck harness can no longer hold a runner.

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

[Unreleased]: https://github.com/EitaPreulaJhol/ida_mcp/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/EitaPreulaJhol/ida_mcp/releases/tag/v0.2.0
[0.1.0]: https://github.com/EitaPreulaJhol/ida_mcp/tree/5d12fb0
