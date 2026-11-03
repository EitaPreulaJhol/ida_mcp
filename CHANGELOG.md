# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- GitHub Actions CI: standalone test suite on Python 3.11/3.12 + ruff lint,
  non-blocking mypy (pure modules) and informational coverage jobs.
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
- MCP **resources** (`ida://triage`, `ida://health`) and a **prompt**
  (`reverse-engineer`); capabilities advertised only when registered.
- Tests: metrics/audit, resources/prompts, a skip-if-absent IDAPython-docs
  cross-check, and an opt-in idalib headless integration gate.
- `compat.badaddr()` gains a type-checked, documented pre-9.3 fallback.

### Changed
- `_mcp_initialize` advertises `resources`/`prompts` capabilities only when
  something is registered (previously always).

### Fixed
- `patch_asm`: `idc.Assemble` (removed in IDA 9.x) replaced with
  `idautils.Assemble` + `ida_bytes.patch_bytes` so the tool still patches.
- `ida-scripting` skill: `ida_search.find_binary` (removed in 9.x) replaced
  with `ida_bytes.find_bytes` using the correct argument order.
- `compat.badaddr()`: dead `ida_bytes.BADADDR` fallback replaced with the real
  pre-9.3 `ida_ida.BADADDR`.
- Removed unused imports flagged by ruff across `api_*` and `server`.
- `INSTALL.md`: documents the unsafe/debugger auth token (no longer claims "no
  auth") and corrects the harness count.

## [0.1.0] - 2025-11-03

Initial versioned baseline: 243 tools across 22 modules, zero-dependency
vendored MCP transport, main-thread-safe `@idasync` layer, lazy `triage` /
`readonly` profiles, token-gated unsafe/debugger surface, and the `/ida` +
`ida-scripting` agent skills.

[Unreleased]: https://github.com/EitaPreulaJhol/ida_mcp/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/EitaPreulaJhol/ida_mcp/releases/tag/v0.1.0
