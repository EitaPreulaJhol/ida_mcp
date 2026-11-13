# Backlog — post-review work

Tracking for the items found while validating against a real **IDA 9.5.261026**
kernel. The fixes already shipped are in `CHANGELOG.md`; the local working
notes for that batch live in `plans/16-post-review-fixes.md` (gitignored).

Priority order: **P1** (documented behavior / robustness) → **P2** (agent-facing
consistency) → **P3** (test & tooling gaps) → **P4** (Pi bridge).

---

## P1 — documented behavior and robustness

- [x] Oversized `limit`/`count` is clamped to the tool's documented maximum
      instead of being reset to the default (17 sites across `api_xrefs.py`,
      `api_memory.py`, `api_names.py`, `api_strings.py`, `api_analysis.py`);
      the applied value is echoed in the payload.
- [x] `disasm` reports the requested address in `addr` (it used to report the
      address *after* the last instruction) and exposes `next_ea`.
- [x] `limit=0` means "no cap" consistently: `get_callers` used to return an
      empty list, `list_funcs(count=0)` used to return an empty page.
- [x] `func_count` uses `ida_funcs.get_func_qty()` instead of materializing
      the whole function list.
- [x] `type_query` stops as soon as the requested page is full (it formatted
      every type in the til first) and polls `check_cancelled()`.
- [x] `search_structs` filters on the type name before formatting the type
      and polls `check_cancelled()`.
- [x] `get_all_comments` polls `check_cancelled()` and reports a `partial`
      result on timeout/cancel.

## P2 — agent-facing consistency

- [x] Unify `limit` vs `count` across the tool surface (14 tools renamed;
      the server maps the legacy `count` spelling) and
      `get_local_variable_references(name=)`.
- [x] Consolidate the duplicate listings: `get_strings` merged into
      `list_strings` (242 tools now). `get_ascii_strings`/`get_unicode_strings`
      stay (they are type filters, not duplicates) and `get_comment` /
      `get_function_comment` read different data.
- [x] Standardize the pagination payload (`get_functions` returns
      `{data,total,offset,count,limit}`).
- [x] Emit MCP tool annotations (`readOnlyHint`, `destructiveHint`,
      `idempotentHint`, `openWorldHint` derived from `@unsafe`/`@ext`).
      `outputSchema` is deferred: every tool returns text, so there is no
      uniform structured result to document.
- [x] Polish the metadata gaps: `get_data_flags` decodes FF_* bits and the
      data type, `get_segment_*` report 16/32/64, `get_analysis_prompt`
      pluralises the import module count.

## P3 — test and tooling gaps

- [x] `tools/idadocs_crosscheck.py` also scans `ida_mcp_loader.py` and
      `getattr(mod, "literal")` lookups. Both gaps were proven by mutation:
      the first catches the old `install_ui_hook`, the second a missing
      symbol behind a guarded `getattr`; the intentional pre-9.x fallbacks
      are allowlisted with a comment each.
- [x] `tests/idalib_all_tools_test.py` (opt-in, `IDA_MCP_IDALIB=1`,
      `make idalib`): runs every safe tool against a temp IDB through
      `idalib`, fails on exceptions and on new deprecations from our files.
      This sweep found four of the shipped bugs and the empty-description one.
- [x] `pyproject.toml` ships `ida_mcp_loader.py` via `py-modules`, so a wheel
      carries both halves of the plugin.

## P4 — Pi bridge (`.pi/extensions/ida-mcp.ts`)

- [x] Call `initialize` (protocol `2025-06-18`) and keep the
      `Mcp-Session-Id`; 404 on an unknown id re-initializes and retries once.
      `notifications/initialized` is sent after the handshake.
- [x] Deactivate tools when the ladder goes down: `pi.setActiveTools()` drops
      the registered IDA tools that are not visible at the new level while
      keeping the built-in tools untouched. (Registering has no inverse, so
      the active set is the lever.)

---

## Operational notes

- The copy in `~/.idapro/plugins/ida_mcp/` predates these fixes and wins on
  IDA's `sys.path`: re-copy the repo (or `make package`) before testing in the
  GUI.
- `CHANGELOG.md` keeps everything under `[Unreleased]`; cut a `0.3.0` when a
  batch is declared done.
