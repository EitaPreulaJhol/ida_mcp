# INSTALL - ida_mcp: IDA Pro MCP Server for AI Agents

Connects an AI coding agent to IDA Pro through the Model Context Protocol
(243 tools: static analysis, decompilation, search, annotation, debugging,
signatures). Installation has two halves:

- **A. IDA side** - copy the plugin, restart IDA.
- **B. Agent side** - register the MCP endpoint.

> The server exposes 243 tools, but your agent should not
> load them all: most MCP clients cap tool slots (often 40–128), and a huge
> tool list burns context and confuses small models. This guide wires the
> agent with the **`/ida` orchestrator skill** (`skills/ida/SKILL.md` for generic agents,
> `.pi/skills/ida/SKILL.md` for Pi) **plus 62 domain skills**
> (`skills/<slug>/` / `.pi/skills/<slug>/`, cataloged in `skills/INDEX.md` /
> `.pi/skills/INDEX.md` - RE, vuln/exploit, malware, kernel/drivers, mobile,
> web/web3/bounty, ICS/infra; see `README.md` -> Agent skills for the full list):
> the agent starts on a 16-tool **triage profile**, runs `survey_binary()`,
> then escalates (`readonly` -> full -> `?unsafe=true` -> `?unsafe=true&ext=dbg`)
> and routes to exactly one `/skill:<slug>` only when the task demands it.
> Server-side enforcement lives in `?profile=` / `?unsafe=` / `?ext=` query
> parameters (see _Endpoint ladder_).

---

## Prerequisites

| Requirement | Notes |
|---|---|
| IDA Pro 8.3+ (9.3 recommended) | IDA Free is **not** supported |
| Python 3.11+ inside IDA | Run `idapyswitch` if IDA uses an older Python |
| Hex-Rays Decompiler | Only needed for decompilation tools; disassembly works without it |
| An MCP-capable agent | Pi, Claude Code, Cursor, Windsurf, VS Code Copilot, Cline/Zoo Code, … |
| This repo (or at least `ida_mcp/` + `ida_mcp_loader.py`) | No `pip install` - stdlib only |

---

## A. Install the IDA plugin

1. Copy **both** items into the IDA plugins directory:
   - the `ida_mcp/` folder 
   - `ida_mcp_loader.py` (this is the file IDA actually loads)

   | OS | Plugins directory |
   |---|---|
   | Windows | `%APPDATA%\Hex-Rays\IDA Pro\plugins` |
   | Linux / macOS | `~/.idapro/plugins` |

2. Restart IDA Pro and open any binary. Click on Edit, then Plugins, then IDA MCP. In the **Output window** you should see:

   ```
   [ida-mcp] listening on http://127.0.0.1:13337/mcp (append ?unsafe=true for write tools)
   ```

3. Verify the bridge (any terminal):

   ```bash
   curl -s -X POST http://127.0.0.1:13337/mcp \
     -H 'Content-Type: application/json' \
     -d '{"jsonrpc":"2.0","method":"tools/list","id":1}' | head -c 200
   ```

   You should get a JSON tool list. With the triage profile (16 tools):

   ```bash
   curl -s -X POST 'http://127.0.0.1:13337/mcp?profile=triage' \
     -H 'Content-Type: application/json' \
     -d '{"jsonrpc":"2.0","method":"tools/list","id":1}' \
     | python3 -c "import json,sys; print(len(json.load(sys.stdin)['result']['tools']), 'tools')"
   # -> 16 tools
   ```

> The server binds **127.0.0.1 only**. It's only reachable from your machine.

Host, port and autostart persist per-IDB via
netnodes (defaults `127.0.0.1:13337`, autostart on). Running instances
register on disk. `list_instances()` from any connected client shows every
open IDA session.

---

## B. Register the server in your agent

Point the agent at the HTTP endpoint. Start with the **triage profile**;
the skill (part C) drives escalation from there.

### Endpoint ladder

| Step | URL | Tools |
|---|---|---|
| 1 - triage (default) | `http://127.0.0.1:13337/mcp?profile=triage` | 16: health, survey, list, decompile, xrefs |
| 2 - readonly | `http://127.0.0.1:13337/mcp?profile=readonly` | 188: all safe reads |
| 3 - full (safe) | `http://127.0.0.1:13337/mcp` | 188: same safe set, no profile filter |
| 4 - unsafe | `http://127.0.0.1:13337/mcp?unsafe=true` | 224: + renames, comments, types, patches, scripts, hooks, FLIRT apply |
| 5 - debugger | `http://127.0.0.1:13337/mcp?unsafe=true&ext=dbg` | 243: + 19 `dbg_*` tools |

Steps 2 and 3 expose the same 188 safe tools. `readonly` is just the
explicit allowlist, while bare `/mcp` is the unfiltered safe set. Step 4
unhides the 36 non-debugger write tools (total 224); step 5 adds the 19
debugger tools (total 243, the full registry).

### Pi Agent

Copy the repo's `.pi/` contents into your Pi folder, restart the agent then type `/ida`. This installs the `/ida` orchestrator **plus all 62 domain skills** (`/skill:<slug>`) and the `INDEX.md` catalog:

```bash
cp -r .pi/skills/* ~/.pi/agent/skills/
cp .pi/extensions/ida-mcp.ts ~/.pi/agent/extensions/ida-mcp.ts
```

Verify with `ls ~/.pi/agent/skills/ | wc -l` (expect 63 dirs - `ida` + 62 domain - plus `INDEX.md`). After `/ida` triages with `survey_binary()`, invoke a domain skill as `/skill:<slug>` (e.g. `/skill:vuln-audit`, `/skill:deobfuscation`); ceilings per skill are listed in `.pi/skills/INDEX.md`.

The extension proxies the Streamable-HTTP server with lazy loading:
`/ida [status|triage|readonly|full|unsafe|dbg|tools]` switches ladder
levels, `ida_profile` / `ida_status` manage scope, and a footer indicator
shows `IDA:online/offline`. Override the URL with `IDA_MCP_URL`
(default `http://127.0.0.1:13337/mcp`).

### Claude Code

Project scope (`.mcp.json` in your repo root):

```json
{
  "mcpServers": {
    "ida": {
      "type": "http",
      "url": "http://127.0.0.1:13337/mcp?profile=triage"
    }
  }
}
```

Or via CLI (user scope; check `claude mcp --help` if flags differ by version):

```bash
claude mcp add --transport http ida http://127.0.0.1:13337/mcp?profile=triage
```

Escalate later by editing the URL (`?profile=readonly`, `?unsafe=true`, …)
and restarting the session.

### Cursor

`.cursor/mcp.json` in the project root (or global `~/.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "ida": {
      "url": "http://127.0.0.1:13337/mcp?profile=triage"
    }
  }
}
```

Then enable the `ida` server under Cursor Settings -> MCP.

### Windsurf

`~/.codeium/windsurf/mcp_config.json`:

```json
{
  "mcpServers": {
    "ida": {
      "serverUrl": "http://127.0.0.1:13337/mcp?profile=triage"
    }
  }
}
```

### VS Code (GitHub Copilot)

`.vscode/mcp.json` in the workspace:

```json
{
  "servers": {
    "ida": {
      "type": "http",
      "url": "http://127.0.0.1:13337/mcp?profile=triage"
    }
  }
}
```

### Cline/Zoo Code

MCP settings (`cline_mcp_settings.json`, or `.roo/mcp.json` for Roo):

```json
{
  "mcpServers": {
    "ida": {
      "type": "streamableHttp",
      "url": "http://127.0.0.1:13337/mcp?profile=triage"
    }
  }
}
```

### Any other MCP client

Any client speaking Streamable HTTP works:

```json
{
  "mcpServers": {
    "ida": {
      "type": "remote",
      "url": "http://127.0.0.1:13337/mcp?profile=triage"
    }
  }
}
```

> Config key names vary per client (`url` vs `serverUrl`, `servers` vs
> `mcpServers`, `http` vs `remote` vs `streamableHttp`). If your client
> rejects the snippet, keep the URL and adapt the keys to its docs.

---

## C. Install the skills (lazy loading)

The `/ida` orchestrator skill teaches the agent the connect -> triage -> escalate -> route loop so the
243 tools never flood its context. The 62 domain skills (`/skill:<slug>`) are loaded one-at-a-time after triage (progressive disclosure). Two mirrored trees ship with this repo -
same methodology and skill bodies, different frontmatter/trigger word:

| Agent | Files | Install as |
|---|---|---|
| Pi | `.pi/skills/ida/SKILL.md` (orchestrator) + `.pi/skills/<slug>/` (62 domain) + `.pi/skills/INDEX.md` (ceilings catalog) | Copy the whole `.pi/` folder, or `cp -r .pi/skills/* ~/.pi/agent/skills/` - invoke orchestrator with `/ida`, domain skills with `/skill:<slug>` (e.g. `/skill:reverse-engineering`, `/skill:memory-corruption`) |
| Generic (Claude Code, Cursor, …) | `skills/ida/SKILL.md` (orchestrator) + `skills/<slug>/` (62 domain) + `skills/INDEX.md` (ceilings catalog) | `~/.claude/skills/ida/SKILL.md` (personal) or `<repo>/.claude/skills/ida/SKILL.md` (shared); copy domain skills the same way (`~/.claude/skills/<slug>/`); Cursor: import as rule/command or paste into Project Rules with the trigger "analyzing a binary in IDA"; Copilot: custom instruction; Cline/Roo: `.clinerules` / `.roo/rules/` - invoke with `/ida`, then route to one domain skill |
| Generic fallback | either tree | Paste into the agent's system prompt or project instructions |

Domain skill groups (full list in `README.md` -> Agent skills, ceilings in `skills/INDEX.md` / `.pi/skills/INDEX.md`): RE & triage (`generic-re`, `reverse-engineering`, `ctf`, `firmware-re`, `protocol-analysis`, `crypto-analysis`, `ai-features`, `ida-scripting`), vuln/exploit (`vuln-audit`, `0day-find`, `memory-corruption`, `rce-detection`, `race-condition`, `rop-builder`, `shellcode-generator`, `auto-exploit`, `deobfuscation`, `smart-patch-ida`, `modify`, … + `triage-validation` before `report-writing`), malware (`malware-analysis`, `linux-malware`, `mobile-malware-analysis`), kernel/drivers (`driver-analysis`, `kernel-exploit`, `linux-driver-exploit`, `windows-driver-exploit`, `macos-driver-exploit`), mobile (`apk-analysis`, `android-exploit`, `ios-exploit`, `mobile-pentest`, `ssl-pinning-bypass`, `owasp-mobile-top10`), web/bounty/web3 (`web2-recon`, `web2-vuln-classes`, `bug-bounty`/`bb-methodology`, `web3-audit`, `web3-vuln`, `meme-coin-audit`), infra/ICS (`container-escape`, `vm-escape`, `iot-vuln`, `scada-vuln`, `security-arsenal`, `prompt-injection`, `collaborative-analysis`).

After installing, type **`/ida`** or just "analyze the binary open in IDA" and the agent will: check `server_health` -> run `survey_binary` -> work through the ladder, asking before crossing into `?unsafe=true` -> load exactly one domain skill for the task.

---

## Verification checklist

- [ ] IDA Output window shows the `[ida-mcp] listening…` line.
- [ ] `curl` tools/list (part A, step 3) returns JSON.
- [ ] Agent lists the `ida` MCP server as connected.
- [ ] `/ida` -> agent calls `server_health`, then `survey_binary`, then routes to one `/skill:<slug>` (e.g. `/skill:generic-re`).
- [ ] Escalation works: ask for something needing writes (e.g. "rename
      `main`") -> agent explains the `?unsafe=true` step instead of failing
      silently.

(Optional) run the offline test suite - no IDA needed, IDA modules are stubbed:

```bash
python3 tests/run_all.py              # all 24 harnesses
python3 tests/tool_inventory_test.py  # registry <-> README <-> profiles drift guard
```

---

## Troubleshooting

| Symptom | Cause -> Fix |
|---|---|
| `curl` connection refused | IDA not running, or plugin not loaded. Re-check part A; look for load errors in IDA's Output window at startup. |
| `All 243 tools loaded` / client complains about tool limits | Endpoint missing `?profile=triage`. Reconnect with the triage URL (ladder step 1). |
| `requires unsafe mode` error | Endpoint lacks `?unsafe=true`. Reconnect with step 4 URL (writes) - confirm with the user first. |
| `requires extension 'dbg'` error | Endpoint lacks `?ext=dbg` (debugger tools also need `?unsafe=true`). Reconnect with step 5 URL - debugger must also be configured in IDA. |
| `is not in profile 'triage'` error | Normal lazy-loading signal: the tool exists but triage hides it. Reconnect with `?profile=readonly` (or drop the profile). |
| `Invalid Host` (403) | Something reached the server with a non-loopback `Host` (DNS-rebinding guard). Direct MCP clients are unaffected; check proxies. |
| `Payload Too Large` (413) | A 10 MiB request cap tripped (usually a runaway script). Narrow the query. |
| Port 13337 already in use | A second IDA (or stale instance) holds it. `list_instances()` via any connected client, or change port in IDA and reconnect. |
| Tools work but decompilation fails | Hex-Rays not installed/enabled. Disassembly tools still work; install the decompiler for `decompile_function` & co. |
| IDA loads the wrong Python | Use `idapyswitch` to point IDA at Python 3.11+. |

---

## Security notes

- The server binds loopback only and has no auth. Treat it like IDA itself:
  anyone who can run code on your machine can drive it.
- `?unsafe=true` enables function renames, comment/type changes, byte
  patching, and **arbitrary IDAPython execution** (`execute_script`).
  Only enable it for sessions you supervise.
- `?ext=dbg` drives a live debugger (process start/stop, memory writes).
- Profiles are a *focus* mechanism, not a security boundary: `readonly`
  hides mutating tools from `tools/list`, but the safety guarantee comes
  from leaving `?unsafe=true` off.

---

## Further reading

- [`README.md`](README.md) - full tool reference (243 tools), design, safety model, Agent skills catalog (62 domain skills), layout.
- [`skills/ida/SKILL.md`](skills/ida/SKILL.md) - generic `/ida` orchestrator skill; [`skills/INDEX.md`](skills/INDEX.md) + [`skills/<slug>/`](skills/) - 62 generic domain skills (`/skill:<slug>`).
- [`.pi/skills/ida/SKILL.md`](.pi/skills/ida/SKILL.md) - Pi skill (`/ida`); [`.pi/skills/INDEX.md`](.pi/skills/INDEX.md) + [`.pi/skills/<slug>/`](.pi/skills/) - 62 Pi domain skills.
- [`.pi/extensions/ida-mcp.ts`](.pi/extensions/ida-mcp.ts) - Pi extension (bridge, `/ida` command, footer indicator, `IDA_MCP_URL` override).
- [`ida_mcp/profiles/triage.txt`](ida_mcp/profiles/triage.txt) / [`readonly.txt`](ida_mcp/profiles/readonly.txt) - the 16/188-tool allowlists.
- [`tests/`](tests/) - (Almost) complete test suite (`run_all.py`, `tool_inventory_test.py` guards registry <-> docs drift).
