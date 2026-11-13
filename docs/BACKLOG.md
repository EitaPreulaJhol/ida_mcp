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

- [ ] `tools/idadocs_crosscheck.py`: also scan `ida_mcp_loader.py` (the file
      IDA actually loads) and `getattr(mod, "literal")` string lookups.
      Both gaps are proven: the first flags the old `install_ui_hook`, the
      second the removed `idc.del_bookmark`.
- [ ] Add `tests/idalib_all_tools_test.py` (opt-in, `IDA_MCP_IDALIB=1`): run
      every tool against a real IDB with signature defaults. This sweep found
      four of the shipped bugs and the empty-bookmark-description one.
- [ ] `pyproject.toml` does not ship `ida_mcp_loader.py`, so a wheel install
      is not loadable by IDA (only `scripts/package.py` builds a usable zip).

## P4 — Pi bridge (`.pi/extensions/ida-mcp.ts`)

- [ ] Call `initialize` and keep the `Mcp-Session-Id` (protocol negotiation,
      `serverInfo`); today it relies on the server accepting session-less
      requests.
- [ ] Deactivate tools when the ladder goes down (`setActiveTools` if
      available): `registered` only grows, so after escalating to `dbg` the
      model keeps ~243 tools.

---

## Operational notes

- The copy in `~/.idapro/plugins/ida_mcp/` predates these fixes and wins on
  IDA's `sys.path`: re-copy the repo (or `make package`) before testing in the
  GUI.
- `CHANGELOG.md` keeps everything under `[Unreleased]`; cut a `0.2.3` when a
  batch is declared done.
