"""Tests for tool metrics (item 07) and the optional audit log (item 08).

Pure zeromcp — no IDA. Drives a background McpServer over in-process HTTP so
the real request path (thread-local ?unsafe parsing, dispatch, metrics, audit)
is exercised.
"""
import hashlib
import json
import os
import sys
import tempfile
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
PKG = os.path.join(HERE, "..", "ida_mcp")
if PKG not in sys.path:
    sys.path.insert(0, PKG)

from zeromcp import McpServer  # noqa: E402

AUDIT = os.path.join(tempfile.mkdtemp(prefix="idamcp_audit_"), "audit.jsonl")

server = McpServer("metrics-test")
server.audit_path = AUDIT


@server.tool
def ping_ok() -> str:
    """Safe tool returning a plain string."""
    return "pong"


@server.tool
def boom() -> str:
    """Raises -> counted as an error."""
    raise ValueError("kaboom")


@server.tool
def mutate(code: str) -> str:
    """Unsafe tool; its call must be audited."""
    return json.dumps({"ok": True, "n": len(code)})


server.unsafe_tools.add("mutate")
server.serve("127.0.0.1", 13402, background=True)
time.sleep(0.4)

BASE = "http://127.0.0.1:13402/mcp"


def post(payload, query=""):
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        BASE + query, data=data, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req) as r:
        return r.status, json.loads(r.read())


def call(name, args=None, query=""):
    return post({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                 "params": {"name": name, "arguments": args or {}}}, query)


failures = []


def check(cond, msg):
    if not cond:
        failures.append(msg)
        print(f"  FAIL: {msg}")
    else:
        print(f"  ok: {msg}")


# --- exercise ---
call("ping_ok")
call("ping_ok")
_, boom_resp = call("boom")
check(boom_resp["result"]["isError"] is True, "boom returns isError")

# unsafe call needs ?unsafe=true (no auth token set -> allowed)
big = "A" * 5000
_, mut_resp = call("mutate", {"code": big}, query="?unsafe=true")
check(mut_resp["result"]["isError"] is False, "mutate ran (unsafe allowed)")

# unsafe call WITHOUT ?unsafe=true is gated -> not counted as a run, not audited
call("mutate", {"code": "x"})

# --- metrics ---
stats = server.get_stats()
by = {t["name"]: t for t in stats["tools"]}
check(by.get("ping_ok", {}).get("calls") == 2, "ping_ok counted twice")
check(by.get("boom", {}).get("errors") == 1, "boom error counted")
check(by.get("mutate", {}).get("calls") == 1, "mutate counted once (gated call excluded)")
check(stats["total_calls"] >= 4, "total_calls aggregated")
check(by.get("ping_ok", {}).get("p50_ms") is not None, "percentiles populated")
check("uptime_sec" in stats, "stats carries uptime")

# --- audit ---
time.sleep(0.1)
with open(AUDIT, encoding="utf-8") as f:
    lines = [json.loads(ln) for ln in f if ln.strip()]
audited = [r for r in lines if r["tool"] == "mutate"]
check(len(audited) == 1, "exactly one mutate audit record")
if audited:
    rec = audited[0]
    check(rec["ok"] is True, "audit ok=True")
    check(rec["unsafe"] is True, "audit marks unsafe")
    check(rec["level"] == "unsafe", "audit records the level (unsafe vs dbg)")
    check(rec["args"]["code"].endswith("\u2026"), "audit truncates large arg")
    check(len(rec["args"]["code"]) < 5000, "audit arg is bounded")
    check(rec.get("code_len") == len(big),
          "audit records the full code length (preview is truncated)")
    check(rec.get("code_sha256") == hashlib.sha256(big.encode()).hexdigest(),
          "audit records the code hash")
check(all(r["tool"] != "ping_ok" for r in lines), "safe tool not audited")

# --- audit disabled by default (no path) ---
server2 = McpServer("no-audit")
check(server2.audit_path is None or os.environ.get("IDA_MCP_AUDIT"),
      "audit disabled by default when IDA_MCP_AUDIT unset")

server.stop()

print("\n" + "=" * 50)
if failures:
    print(f"FAILED ({len(failures)}): " + "; ".join(failures))
    sys.exit(1)
print("ALL METRICS/AUDIT TESTS PASSED")
