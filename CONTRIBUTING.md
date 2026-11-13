# Contributing to ida_mcp

Thanks for helping improve `ida_mcp`. This guide covers the architecture, the
invariants the test suite enforces, and the exact flow for adding a tool so you
don't trip CI without knowing why.

## Ground rules

- **Zero third-party runtime dependencies.** The MCP transport is vendored in
  `ida_mcp/zeromcp` on top of the stdlib. Dev-only tools (ruff, mypy, coverage,
  pre-commit) are fine — they must never be imported at runtime.
- **IDA 9.x native, 8.3+ via shims.** Put version-sensitive API differences in
  `ida_mcp/compat.py`, not scattered across modules.
- **LF line endings** (`.gitattributes` enforces it).
- **Supervised, read-first.** Mutating tools are gated; keep it that way.

## Dev setup

No install is needed to run the suite (every harness stubs IDA):

```bash
python3 tests/run_all.py              # all harnesses (no IDA required)
python3 tests/tool_inventory_test.py  # registry <-> README <-> profiles drift guard
```

For linting/type-checking:

```bash
pip install -e ".[dev]"   # ruff, mypy, coverage
ruff check .
make test lint            # if you use the Makefile
pre-commit install        # optional: run lint + inventory on every commit
```

## Architecture (where things live)

| Path | Responsibility |
|------|----------------|
| `ida_mcp_loader.py` | Thin IDA entry shim; re-exports `IdaMcp`/`PLUGIN_ENTRY` from `ida_mcp/plugin.py` |
| `ida_mcp/zeromcp/` | Vendored MCP transport (HTTP + JSON-RPC). No IDA imports. |
| `ida_mcp/rpc.py` | `@tool` / `@unsafe` / `@ext` decorators + `MCP_SERVER` registry |
| `ida_mcp/plugin.py` | `IdaMcp`, `MCPUIHooks`, netnode-backed host/port/autostart |
| `ida_mcp/sync.py` | `@idasync` main-thread marshal, timeouts, cancellation |
| `ida_mcp/server.py` | Core tools + server lifecycle + module wiring |
| `ida_mcp/api_*.py` | Tool modules (analysis, functions, xrefs, debug, …) |
| `ida_mcp/profiles/` | `triage`/`readonly` plus `malware`/`ctf`/`annotate`/`debug` allowlists |
| `ida_mcp/compat.py` | 8.3 ↔ 9.x API shims |
| `tests/` | Standalone harnesses (IDA stubbed) + drift guards |

### The main-thread rule

Every IDA SDK call must run on the IDA main thread. Decorate tool functions
with `@idasync` (and they are registered with `@tool`). Never block, never run
unbounded loops — the UI is frozen while a tool runs and all other calls get a
retryable `Server busy`. Keep tools short; paginate large listings; print
progress in scripts.

### Error convention

- Plain-text tools raise `IDAError(msg)` → JSON-RPC `-32000`, no traceback leak.
- JSON tools return a dict with a non-empty top-level `error` string → promoted
  to `isError: true`. `error: null` and per-item errors are NOT failures.

## Adding a tool (follow all steps or CI fails)

The suite guards registry ↔ docs ↔ profiles drift. To add a tool:

1. **Implement** it in the right `api_*.py` with `@tool` + `@idasync`, a
   **non-empty docstring** (clients pick tools from it), and `@unsafe` if it
   mutates the IDB, or `@ext("dbg")` (+ `@unsafe`) for debugger tools.
   If it reads analysis-derived data (functions, xrefs, names, types,
   decompilation), start the body with `ensure_analysis()` from `.sync`, not
   a bare `ida_auto.auto_wait()`: it returns at once when analysis is done
   and fails with a clean, retryable error instead of holding the main thread
   until the timeout. Tools that only report state must not wait at all.
2. **Register**: make sure `server.py` imports the module (`from . import
   api_x  # noqa: F401`) so the `@tool` side effect runs.
3. **Document** it in `README.md` (backtick-quoted, e.g. `` `my_tool` ``) and
   bump the per-module count header (`### \`api_x\` (N)`).
4. **Inventory**: add the name to `EXPECTED` in
   `tests/tool_inventory_test.py`.
5. **Profiles**: if it is read-safe and broadly useful, add it to
   `ida_mcp/profiles/readonly.txt` (and `triage.txt` for core triage tools).
   Triage must stay a strict subset of readonly, both privilege-free.
6. **Test** it: add/extend a `tests/*_test.py` following an existing harness.
   Stub the IDA modules it touches in `sys.modules`, then load the REAL module
   with `tests/_harness.py`, e.g.
   `mod = load("api_x", {"rpc": RPC_STUB, "sync": SYNC_STUB, "api_analysis": "def parse_addr(s): ..."})`.
   Siblings it imports relatively become stub modules; the file itself runs
   from its true path, so coverage counts it. Never `exec` rewritten source.

### What the guards enforce (`tool_inventory_test.py`)

- Per-module tool counts match `EXPECTED`.
- Every tool is documented in README and has a non-empty docstring.
- `server.py` imports every `api_*` module.
- Profiles reference only real tools, stay privilege-free, and triage ⊂ readonly.
- A tool calling a write sink (patch/rename/define/…) must be `@unsafe`/ext-gated.

### Agent skills (`skills_sync_test.py`)

Edit the skills only under `skills/` (the source of truth), then run
`make skills` to mirror them into `.pi/skills/` for Pi. The test fails if the
mirror drifts or a frontmatter value is neither double-quoted nor a plain
identifier (Cline and the `skills` CLI use a strict YAML parser).

## Local-only checks (not in CI)

- **Lint**: `ruff check .` (CI enforces `F`, `E`, `W`, `C4`; see `[tool.ruff.lint]`).
- **Types** (optional): `mypy` on the pure modules (zeromcp, discovery,
  profiles, regex_guard) — see `[tool.mypy]`. Verified clean, so CI enforces
  it; run `mypy` before pushing changes to those modules.
- **idalib integration** (`tests/idalib_integration_test.py`): needs a licensed
  IDA. Run with `IDA_MCP_IDALIB=1 IDA_MCP_IDALIB_BINARY=/path/to/bin`. Catches
  real API drift the stubbed suite can't (how `idc.Assemble` /
  `ida_search.find_binary` slipped through before).
- **idalib all-tools sweep** (`tests/idalib_all_tools_test.py`, `make idalib`):
  same environment; copies the binary to a temp dir, calls every safe tool
  once with signature defaults, and fails on exceptions or on a new
  deprecation warning from our files. This is the sweep that found the
  9.5 tool breakages.
- **idalib version matrix** (`tests/idalib_matrix_test.py`, `make idalib-matrix`):
  discovers installations with `idalib/python` (override with
  `IDA_MCP_IDALIB_MATRIX=/opt/ida-8.5:/opt/ida-9.5`), then runs the safe-tool
  sweep and the extracted modern `ida-mcp-bridge/` folder-loader check in a
  separate subprocess per version. Use this before a release when 8.5, 9.0,
  9.5 and 10.0 trees are installed; one process per version avoids idalib
  cross-version initialization.
- **IDAPython docs cross-check** (`tests/idadocs_crosscheck_test.py`): point
  `IDAPYTHON_DOCS_DIR` at a local copy of the official reference; it fails on
  new drift against an allowlist of known false positives. Skips if absent.

## Releasing

1. Bump `ida_mcp/__version__` **and** `ida-plugin.json` (`plugin.version`)
   and add a `CHANGELOG.md` entry under a new `## [X.Y.Z]` heading.
2. Run `make package`. It builds both layouts:
   - `dist/ida_mcp-X.Y.Z.zip` — `ida-mcp-bridge/` folder with `ida-plugin.json`
     (IDA 8.5+ / HCLI);
   - `dist/ida-mcp-legacy-X.Y.Z.zip` — root layout for IDA 8.3/8.4.
   - `dist/SHA256SUMS` — checksums for both ZIPs.
   Optionally validate the modern ZIP with
   `hcli plugin lint dist/ida_mcp-X.Y.Z.zip`.
3. Tag and push: `git tag vX.Y.Z && git push origin vX.Y.Z`.
4. `release.yml` runs the suite, builds both ZIPs via
   `scripts/package.py --expect-version X.Y.Z` (which fails if the tag,
   `__version__` and manifest disagree), and attaches them to the GitHub
   Release.

## Commit / PR etiquette

- Keep the runtime dependency-free.
- Run `tests/run_all.py` + `ruff check .` before pushing.
- Small, focused commits; explain *why* in the body.
