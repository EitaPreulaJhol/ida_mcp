/**
 * IDA Pro MCP bridge for pi.
 *
 * Proxies the IDA plugin's Streamable-HTTP MCP server
 * (http://127.0.0.1:13337/mcp, stdlib only, no auth, loopback-only)
 * into pi tools. Lazy-loading by default: starts on the 16-tool
 * triage profile and escalates only via the `ida_profile` tool
 * or `/ida <level>`.
 *
 * Endpoint ladder (mirrors INSTALL.md):
 *   triage   ?profile=triage            16 tools (default)
 *   readonly ?profile=readonly         188 safe reads
 *   full     (no suffix)               224 non-mutating
 *   unsafe   ?unsafe=true              + renames/comments/types/patches/scripts
 *   dbg      ?unsafe=true&ext=dbg      + 19 debugger tools
 *
 * Env override: IDA_MCP_URL (default http://127.0.0.1:13337/mcp)
 *
 * Dynamic indicator: the footer status (IDA:online/offline) is updated
 * via polling + refresh on session events, so opening IDA *after*
 * pi is reflected automatically, without /reload.
 */

import type { ExtensionAPI, ExtensionUIContext } from "@earendil-works/pi-coding-agent";
import { StringEnum } from "@earendil-works/pi-ai";
import { Type } from "typebox";

const BASE_URL = (process.env.IDA_MCP_URL ?? "http://127.0.0.1:13337/mcp").replace(/\/$/, "");

type Level = "triage" | "readonly" | "full" | "unsafe" | "dbg";

const LADDER: Record<Level, { suffix: string; hint: string }> = {
	triage: { suffix: "?profile=triage", hint: "16 tools (default)" },
	readonly: { suffix: "?profile=readonly", hint: "188 safe reads" },
	full: { suffix: "", hint: "224 non-mutating" },
	unsafe: { suffix: "?unsafe=true", hint: "+ writes (rename/comment/patch/script)" },
	dbg: { suffix: "?unsafe=true&ext=dbg", hint: "+ 19 debugger tools" },
};

const LEVELS: Level[] = ["triage", "readonly", "full", "unsafe", "dbg"];

let currentLevel: Level = "triage";
const registered = new Set<string>();

// --- dynamic indicator: polling state ---
let lastOnline: boolean | undefined = undefined;
let lastStatusText: string | undefined = undefined;
let currentUi: ExtensionUIContext | undefined = undefined;
let pollTimer: ReturnType<typeof setInterval> | undefined = undefined;
let checking = false;
let lastCheckAt = 0;

const POLL_INTERVAL_MS = 10_000;
const PING_TIMEOUT_MS = 5_000;
const MIN_EVENT_INTERVAL_MS = 8_000;

function endpoint(level: Level = currentLevel): string {
	return `${BASE_URL}${LADDER[level].suffix}`;
}

interface McpToolDef {
	name: string;
	description?: string;
	inputSchema?: {
		type?: string;
		properties?: Record<string, { type?: string; description?: string }>;
		required?: string[];
	};
}

async function rpc(
	method: string,
	params: Record<string, unknown> | undefined,
	signal: AbortSignal | undefined,
	level: Level = currentLevel,
	timeoutMs = 60000,
): Promise<any> {
	const ctrl = new AbortController();
	const timer = setTimeout(() => ctrl.abort(new Error(`IDA MCP timeout after ${timeoutMs}ms`)), timeoutMs);
	const onAbort = () => ctrl.abort(signal?.reason);
	signal?.addEventListener("abort", onAbort, { once: true });
	try {
		const res = await fetch(endpoint(level), {
			method: "POST",
			headers: { "Content-Type": "application/json", Accept: "application/json, text/event-stream" },
			body: JSON.stringify({ jsonrpc: "2.0", method, params: params ?? {}, id: 1 }),
			signal: ctrl.signal,
		});
		if (!res.ok) {
			const text = await res.text().catch(() => "");
			throw new Error(`IDA MCP HTTP ${res.status} at ${endpoint(level)}: ${text.slice(0, 300)}`);
		}
		const data = (await res.json()) as { result?: any; error?: { message?: string; code?: number } };
		if (data.error) throw new Error(`IDA MCP error: ${data.error.message ?? JSON.stringify(data.error)}`);
		return data.result;
	} catch (e: any) {
		if (e?.name === "AbortError" || /aborted/i.test(String(e?.message))) {
			if (signal?.aborted) throw new Error("Cancelled");
			throw new Error(
				`IDA MCP request timed out. Is IDA Pro running with a binary open? ` +
					`Look for "[ida-mcp] listening on http://127.0.0.1:13337/mcp" in IDA's Output window.`,
			);
		}
		if (/fetch failed|ECONNREFUSED|ENOTFOUND|EHOST/i.test(String(e?.message ?? e))) {
			throw new Error(
				`Cannot reach IDA MCP at ${endpoint(level)} (connection refused). ` +
					`Open IDA Pro with a binary and confirm the "[ida-mcp] listening…" line in the Output window, then retry.`,
			);
		}
		throw e;
	} finally {
		clearTimeout(timer);
		signal?.removeEventListener("abort", onAbort);
	}
}

async function listRemoteTools(level: Level, signal?: AbortSignal): Promise<McpToolDef[]> {
	const result = await rpc("tools/list", {}, signal, level, 15000);
	return (result?.tools ?? []) as McpToolDef[];
}

/** Lightweight ping: only checks whether the bridge responds (any response = online). */
async function pingIda(timeoutMs = PING_TIMEOUT_MS): Promise<boolean> {
	await rpc("tools/call", { name: "server_health", arguments: {} }, undefined, "triage", timeoutMs);
	return true;
}

async function callRemoteTool(
	name: string,
	args: Record<string, unknown>,
	signal: AbortSignal | undefined,
): Promise<string> {
	const result = await rpc("tools/call", { name, arguments: args ?? {} }, signal);
	if (result?.isError) {
		const text = result?.content?.map((c: any) => c?.text ?? "").join("\n") ?? "Unknown IDA error";
		// Routing signals (ladder escalation) are normal flow — return as text,
		// don't throw, so the model can read the "reconnect with …" hint.
		if (/requires unsafe|requires extension|not in profile/i.test(text)) return text;
		return `[IDA error] ${text}`;
	}
	const content = result?.content;
	if (Array.isArray(content)) {
		const text = content.map((c: any) => (typeof c?.text === "string" ? c.text : JSON.stringify(c))).join("\n");
		return truncate(text);
	}
	return truncate(typeof result === "string" ? result : JSON.stringify(result ?? null));
}

function truncate(text: string, maxBytes = 50000, maxLines = 2000): string {
	const lines = text.split("\n");
	let out = text;
	let note = "";
	if (lines.length > maxLines) {
		out = lines.slice(0, maxLines).join("\n");
		note = ` [truncated ${lines.length} total lines]`;
	}
	if (Buffer.byteLength(out, "utf8") > maxBytes) {
		let cut = out.slice(0, maxBytes);
		cut = cut.slice(0, cut.lastIndexOf("\n") > 0 ? cut.lastIndexOf("\n") : maxBytes);
		note += ` [truncated to ~${Math.round(maxBytes / 1024)}KB of ${Math.round(Buffer.byteLength(text, "utf8") / 1024)}KB]`;
		out = cut;
	}
	return out + note;
}

function toTypeBox(schema: McpToolDef["inputSchema"]) {
	const props = schema?.properties ?? {};
	const required = new Set(schema?.required ?? []);
	const out: Record<string, any> = {};
	for (const [key, def] of Object.entries(props)) {
		const desc = def?.description ? { description: def.description } : {};
		let t: any;
		switch (def?.type) {
			case "integer":
				t = Type.Integer(desc);
				break;
			case "number":
				t = Type.Number(desc);
				break;
			case "boolean":
				t = Type.Boolean(desc);
				break;
			default:
				t = Type.String(desc);
				break;
		}
		out[key] = required.has(key) ? t : Type.Optional(t);
	}
	return Type.Object(out);
}

function registerRemoteTool(pi: ExtensionAPI, def: McpToolDef): boolean {
	if (registered.has(def.name)) return false;
	registered.add(def.name);
	pi.registerTool({
		name: def.name,
		label: `IDA ${def.name}`,
		description: def.description?.trim() || `IDA Pro tool ${def.name} (via ida_mcp)`,
		// No promptSnippet/promptGuidelines on lazy tools: keeps the system
		// prompt stable when profiles escalate (see extensions.md).
		parameters: toTypeBox(def.inputSchema),
		async execute(_toolCallId, params, signal) {
			const text = await callRemoteTool(def.name, (params ?? {}) as Record<string, unknown>, signal);
			return { content: [{ type: "text", text }], details: { idaTool: def.name } };
		},
	});
	return true;
}

// --- dynamic indicator: helpers ---

function setIdaStatus(ui: ExtensionUIContext | undefined, text: string): void {
	if (!ui) return;
	try {
		ui.setStatus("ida", text);
	} catch {
		// UI may have been discarded (session switch) — the next event restores it.
	}
	lastStatusText = text;
}

function onlineStatusText(): string {
	const n = registered.size;
	return n > 0 ? `IDA:${currentLevel} (${n})` : `IDA:${currentLevel}`;
}

/** Ensure triage tools exist when the bridge comes back (without them the status lights up but nothing works). */
async function ensureTriageTools(pi: ExtensionAPI): Promise<number> {
	if (registered.size > 0) return registered.size;
	const tools = await listRemoteTools("triage", undefined);
	for (const t of tools) registerRemoteTool(pi, t);
	return tools.length;
}

/**
 * Check the bridge and update the footer. Never throws (poller/events must not break the session).
 * Returns true when online.
 */
async function refreshIdaStatus(
	pi: ExtensionAPI,
	ui: ExtensionUIContext | undefined,
	opts?: { force?: boolean; notifyOnReconnect?: boolean },
): Promise<boolean> {
	if (checking && !opts?.force) return lastOnline ?? false;
	checking = true;
	lastCheckAt = Date.now();
	try {
		await pingIda();
		// online — register triage on demand (in case pi started before IDA)
		try {
			await ensureTriageTools(pi);
		} catch {
			// ping ok but list failed: still consider online, status lights up anyway
		}
		const text = onlineStatusText();
		const wasOffline = lastOnline === false || lastOnline === undefined;
		lastOnline = true;
		setIdaStatus(ui ?? currentUi, text); // always restore: the footer may have been recreated
		if (wasOffline && opts?.notifyOnReconnect !== false && registered.size > 0) {
			try {
				(ui ?? currentUi)?.notify(`IDA Pro detected — ${registered.size} triage tools available`, "info");
			} catch {
				// notify is fire-and-forget
			}
		}
		return true;
	} catch {
		if (lastOnline !== false) setIdaStatus(ui ?? currentUi, "IDA:offline");
		lastOnline = false;
		return false;
	} finally {
		checking = false;
	}
}

/** Non-blocking version for event hooks (turn/input/agent): never delays the turn. */
function refreshInBackground(pi: ExtensionAPI, ui: ExtensionUIContext | undefined): void {
	const now = Date.now();
	if (checking || now - lastCheckAt < MIN_EVENT_INTERVAL_MS) {
		// Only restore the last known status (cheap, synchronous) if the footer was recreated.
		if (lastStatusText) setIdaStatus(ui, lastStatusText);
		return;
	}
	void refreshIdaStatus(pi, ui, { notifyOnReconnect: true }).catch(() => {});
}

function startPoller(pi: ExtensionAPI): void {
	stopPoller();
	pollTimer = setInterval(() => {
		void refreshIdaStatus(pi, currentUi, { notifyOnReconnect: true }).catch(() => {});
	}, POLL_INTERVAL_MS);
	// Don't keep the process alive on its own.
	(pollTimer as unknown as { unref?: () => void })?.unref?.();
}

function stopPoller(): void {
	if (pollTimer) {
		clearInterval(pollTimer);
		pollTimer = undefined;
	}
}

export default async function (pi: ExtensionAPI) {
	// --- management tool: profile ladder ---
	pi.registerTool({
		name: "ida_profile",
		label: "IDA profile",
		description:
			"Switch the IDA MCP endpoint ladder level and lazily register the newly visible tools. " +
			"Levels: triage (16, default) < readonly (188) < full (224) < unsafe (+writes) < dbg (+debugger). " +
			"Use when a tool errors with 'not in profile', 'requires unsafe mode' or 'requires extension'.",
		promptSnippet: "Switch IDA analysis scope with ida_profile (triage/readonly/full/unsafe/dbg)",
		promptGuidelines: [
			"Use ida_profile to escalate IDA tool visibility (triage → readonly → full → unsafe → dbg) only when the task needs tools beyond the current level; justify unsafe/dbg escalation in one sentence.",
		],
		parameters: Type.Object({
			level: StringEnum(LEVELS as unknown as [string, ...string[]], {
				description: "Ladder level to switch to",
			}),
		}),
		async execute(_toolCallId, params, signal) {
			const level = (params as any).level as Level;
			if (!LADDER[level]) throw new Error(`Unknown level: ${level}. Use one of: ${LEVELS.join(", ")}`);
			const tools = await listRemoteTools(level, signal);
			let added = 0;
			for (const t of tools) if (registerRemoteTool(pi, t)) added++;
			currentLevel = level;
			lastOnline = true;
			setIdaStatus(currentUi, onlineStatusText());
			return {
				content: [
					{
						type: "text",
						text:
							`IDA endpoint → ${endpoint(level)} (${LADDER[level].hint}). ` +
							`${tools.length} tools visible, ${added} newly registered this session.`,
					},
				],
				details: { level, count: tools.length, added },
			};
		},
	});

	// --- management tool: health ---
	pi.registerTool({
		name: "ida_status",
		label: "IDA status",
		description: "Check whether the IDA Pro MCP bridge is reachable (server_health) and show the current endpoint/level.",
		parameters: Type.Object({}),
		async execute(_toolCallId, _params, signal) {
			try {
				const text = await callRemoteTool("server_health", {}, signal);
				lastOnline = true;
				setIdaStatus(currentUi, onlineStatusText());
				return {
					content: [{ type: "text", text: `endpoint: ${endpoint()}\nlevel: ${currentLevel}\n${text}` }],
					details: { level: currentLevel, endpoint: endpoint(), unreachable: false },
				};
			} catch (e: any) {
				lastOnline = false;
				setIdaStatus(currentUi, "IDA:offline");
				return {
					content: [{ type: "text", text: `endpoint: ${endpoint()}\nlevel: ${currentLevel}\nUNREACHABLE: ${e?.message ?? e}` }],
					details: { level: currentLevel, endpoint: endpoint(), unreachable: true },
				};
			}
		},
	});

	// --- /ida command ---
	pi.registerCommand("ida", {
		description: "IDA Pro bridge: /ida [status|triage|readonly|full|unsafe|dbg|tools] — check health, switch ladder level, or list visible tools",
		handler: async (args, ctx) => {
			const sub = (args ?? "").trim().split(/\s+/)[0]?.toLowerCase() as Level | "status" | "tools" | "";
			if ((LEVELS as string[]).includes(sub)) {
				const level = sub as Level;
				try {
					const tools = await listRemoteTools(level);
					let added = 0;
					for (const t of tools) if (registerRemoteTool(pi, t)) added++;
					currentLevel = level;
					lastOnline = true;
					setIdaStatus(ctx.ui, onlineStatusText());
					ctx.ui.notify(`IDA → ${endpoint()} — ${tools.length} tools (${added} new)`, "info");
				} catch (e: any) {
					lastOnline = false;
					setIdaStatus(ctx.ui, "IDA:offline");
					ctx.ui.notify(`IDA unreachable: ${e?.message ?? e}`, "error");
				}
				return;
			}
			if (sub === "tools" || sub === "") {
				try {
					const tools = await listRemoteTools(currentLevel);
					lastOnline = true;
					// Register on demand in case the bridge came up after pi.
					let added = 0;
					for (const t of tools) if (registerRemoteTool(pi, t)) added++;
					setIdaStatus(ctx.ui, onlineStatusText());
					const names = tools.map((t) => t.name).sort().join(", ");
					ctx.ui.notify(`IDA [${currentLevel}] ${tools.length} tools: ${names.slice(0, 2000)}`, "info");
				} catch (e: any) {
					lastOnline = false;
					setIdaStatus(ctx.ui, "IDA:offline");
					ctx.ui.notify(`IDA unreachable at ${endpoint()}: ${e?.message ?? e}`, "error");
				}
				if (sub === "") {
					ctx.ui.notify(
						`Ladder: triage (?profile=triage) → readonly → full → unsafe (?unsafe=true) → dbg (?unsafe=true&ext=dbg). Current: ${currentLevel} — /ida <level> to switch.`,
						"info",
					);
				}
				return;
			}
			// status (or unknown → status)
			try {
				const text = await callRemoteTool("server_health", {}, undefined);
				lastOnline = true;
				try {
					await ensureTriageTools(pi);
				} catch {
					// status ok even without listing
				}
				setIdaStatus(ctx.ui, onlineStatusText());
				ctx.ui.notify(`IDA ok [${currentLevel}] ${endpoint()}\n${text.slice(0, 1500)}`, "info");
			} catch (e: any) {
				lastOnline = false;
				setIdaStatus(ctx.ui, "IDA:offline");
				ctx.ui.notify(`IDA unreachable at ${endpoint()}: ${e?.message ?? e}`, "error");
			}
		},
	});

	// --- dynamic indicator lifecycle ---
	pi.on("session_start", (_event, ctx) => {
		currentUi = ctx.ui;
		// Paint something immediately (non-blocking), then confirm in the background.
		setIdaStatus(ctx.ui, lastStatusText ?? (lastOnline === false ? "IDA:offline" : `IDA:${currentLevel}`));
		startPoller(pi);
		refreshInBackground(pi, ctx.ui);
	});

	pi.on("session_shutdown", () => {
		stopPoller();
		// Intentionally don't clear currentUi here: shutdown→start is sequential
		// and the next session_start restores the new reference.
	});

	// Opportunistic refresh (throttled + non-blocking): covers IDA opened
	// after pi as soon as the user keeps interacting.
	pi.on("turn_start", (_event, ctx) => {
		currentUi = ctx.ui;
		refreshInBackground(pi, ctx.ui);
	});
	pi.on("before_agent_start", (_event, ctx) => {
		currentUi = ctx.ui;
		refreshInBackground(pi, ctx.ui);
	});
	pi.on("input", (_event, ctx) => {
		currentUi = ctx.ui;
		refreshInBackground(pi, ctx.ui);
		return { action: "continue" as const };
	});
	pi.on("tool_execution_end", (_event, ctx) => {
		currentUi = ctx.ui;
		refreshInBackground(pi, ctx.ui);
	});

	// --- initial load (triage): try once, the poller/events handle the rest ---
	try {
		const tools = await listRemoteTools("triage", undefined);
		for (const t of tools) registerRemoteTool(pi, t);
		currentLevel = "triage";
		lastOnline = true;
		lastStatusText = onlineStatusText();
	} catch {
		// IDA is not running yet — the poller + event refresh detects
		// when it opens (previously it stayed stuck on "IDA:offline" forever).
		lastOnline = false;
		lastStatusText = "IDA:offline";
	}
}
