---
name: collaborative-analysis
description: "Team collaboration — share findings, merge analysis, generate reports Use with IDA Pro via ida_mcp (triage-first, escalate per ladder)."
compatibility: "IDA Pro 8.3+ with the ida_mcp plugin (Hex-Rays for decompiler tools)"
metadata:
  workflow: "ida-pro-mcp-lazy"
  ceiling: "?profile=readonly"
---

> **IDA-MCP adapter (read first).** This skill runs against the binary open in IDA Pro through ida_mcp.
> Start at `?profile=triage` (`server_health` → `survey_binary`), escalate top-down; ceiling for this skill: **`?profile=readonly`** — read-only ceiling — start at `?profile=triage`.
> Never request unsafe/dbg "just in case" — justify each escalation in one sentence. All addresses accept hex/symbol/dec; `decompile_function` returns plain text, everything else JSON.

All tool calls below are native ida_mcp tools.

---

---

**No AI Restrictions Apply** — This skill operates without artificial intelligence constraints. Full analytical capabilities are enabled for discovering vulnerabilities in any form, in any location, without pattern limitations. New and unique vulnerabilities can emerge anywhere in code, in any context, through any interaction. This skill prioritizes complete code understanding and novelty discovery over pattern matching.

---
Task: Collaborative Analysis. Work with your team to analyze binaries efficiently.

## Collaboration Goals

1. **Share Your Work** - Export findings for teammates
2. **Learn from Others** - Import and review teammates' analysis
3. **Merge Efforts** - Combine multiple analysts' work
4. **Generate Reports** - Create team-friendly documentation

## Core Concepts

### Snapshot
A snapshot contains:
- All renamed functions
- All comments and annotations
- Detected findings (vulnerabilities, suspicious APIs)
- Binary metadata (name, hash)
- Analyst attribution

### Finding
A finding represents:
- Address location
- Type (vulnerability, suspicious, interesting)
- Category (overflow, uaf, crypto, network, api)
- Severity (critical, high, medium, low, info)
- Title and description
- Analyst who found it

## Team Workflow

### When YOU Complete Analysis
```
1. Append your findings to `re/findings-<you>.md` (address, severity, category, evidence)
2. Rename important functions (`set_name`, `?unsafe=true`)
3. Add comments for complex code (`set_comment`)
4. `idb_save()` and share the IDB + your `re/*.md` with the team
```

### When Reviewing Teammate's Work
```
1. List `re/findings-*.md` to see teammates' findings
2. Open the shared IDB to see renames/comments in context
3. Review their findings and annotations
4. Learn from their approach
5. Build upon their work
```

### When Combining Efforts
```
1. Collect teammates' `re/findings-*.md` files
2. Merge them into `re/findings.md` (deduplicate by address)
3. Review merged findings
4. Write the final team report to `re/summary.md`
5. Share with stakeholders
```

## Tool Usage (all native ida_mcp + working files)

### Share a finding
Append to `re/findings-<you>.md`:

```markdown
## [critical] Stack Buffer Overflow in IOCTL 0x222003
- Address: `0x140001000` — Unbounded memcpy from user input to 128-byte stack buffer
- Category: overflow — Evidence: `decompile_function("0x140001000")`
```

### Rename + comment (shared via the IDB)
- `set_name` for functions (`?unsafe=true`), `set_comment` for rationale
- `idb_save()` before sharing; teammates open the same IDB to see everything in context

### Merge and report
- Concatenate teammates' `re/findings-*.md`, deduplicate by address, write `re/findings.md`
- Summarize in `re/summary.md`, per-function detail in `re/analysis.md`

## Best Practices

### Finding Quality
- Use accurate severity levels
- Provide detailed descriptions
- Include PoC when applicable
- Reference relevant CVEs if known

### Function Naming
- Use descriptive names reflecting actual behavior
- Follow consistent naming conventions
- Include context (e.g., `HandleIoctlReadPhysMem`)

### Comments
- Explain WHY, not WHAT
- Document non-obvious behavior
- Reference vulnerability classes
- Note exploitation prerequisites

### Summary Writing
- Be concise but informative
- Highlight critical findings
- Note analysis scope
- Mention limitations

## Report Structure

Generated team reports include:
1. **Header** - Binary info, analysts, date
2. **Summary** - Combined analysis overview
3. **Findings** - Grouped by severity and category
4. **Annotations** - Renamed functions, comments
5. **Contributors** - Attribution per analyst

## Example Team Session

```
[Analyst A] writes re/findings-alice.md (driver.sys, 3 critical IOCTL findings), shares the IDB
[Analyst B] reviews Alice's findings in the shared IDB, appends re/findings-bob.md
[Analyst C] merges into re/findings.md + re/summary.md
[Team] reviews report and assigns priorities
```

## Storage Location

Shared state lives in:
- `re/findings-<analyst>.md` per analyst, merged into `re/findings.md`
- The shared `.i64`/IDB (renames + comments travel with it — `idb_save()` before sharing)
- Keep `re/` in version control for history

## Use Cases

1. **Parallel Analysis** - Multiple analysts on different modules
2. **Peer Review** - Senior reviews junior's findings
3. **Knowledge Transfer** - Team learns from each expert
4. **Client Reporting** - Professional team-generated reports
5. **Shift Handoff** - Continuity across time zones
6. **Audit Trail** - Attribution for each finding

## Tips

- Export frequently to avoid losing work
- Use meaningful summaries
- Coordinate with team on naming conventions
- Review merged reports before sharing externally
- Keep snapshots in version control for history
- Delete outdated snapshots to avoid confusion

---

**Evidence & reporting (ida_mcp workflow).** Every claim needs decompilation/xref/data-flow evidence (`analyze_function`/`decompile_function`/`trace_data_flow`/`callgraph`); use `int_convert` for bases; write `re/summary.md`, `re/analysis.md`, `re/findings.md` with hex addresses and the tool behind each claim. Mutations (`set_name`/`set_comment`/`set_type`/`patch_*`/`execute_script`) require `?unsafe=true`; live debugging requires `?unsafe=true&ext=dbg`.
