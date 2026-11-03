"""Tests for MCP resources/prompts wiring (item 13). Pure zeromcp, no IDA.

Drives the JSON-RPC registry directly (no HTTP) to exercise initialize
capabilities, resources/list+read and prompts/list+get, plus error paths and
the "advertise only when registered" rule.
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PKG = os.path.join(HERE, "..", "ida_mcp")
if PKG not in sys.path:
    sys.path.insert(0, PKG)

from zeromcp import McpServer  # noqa: E402

failures = []


def check(cond, msg):
    print(("  ok: " if cond else "  FAIL: ") + msg)
    if not cond:
        failures.append(msg)


def rpc(server, method, params=None):
    return server.registry.dispatch({
        "jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}})


# --- server with resources + prompts registered ---
srv = McpServer("res-test")


@srv.resource("demo://thing", name="the-thing", mime="application/json")
def thing():
    """A demo JSON resource."""
    return json.dumps({"hello": "world"})


@srv.resource("demo://plain")
def plain():
    """A plain-text resource (mime inferred)."""
    return "just text"


@srv.prompt
def greet(who: str = "world", _hidden: int = 0):
    """Greet someone."""
    return f"Hello, {who}!"


# initialize advertises resources + prompts (because registered)
init = rpc(srv, "initialize", {"protocolVersion": "2025-06-18",
                               "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}})
caps = init["result"]["capabilities"]
check("resources" in caps, "initialize advertises resources when registered")
check("prompts" in caps, "initialize advertises prompts when registered")

# resources/list
rl = rpc(srv, "resources/list")["result"]["resources"]
uris = {r["uri"]: r for r in rl}
check("demo://thing" in uris and "demo://plain" in uris, "resources/list returns both")
check(uris["demo://thing"]["name"] == "the-thing", "resource custom name honored")
check(uris["demo://thing"]["mimeType"] == "application/json", "resource mime honored")

# resources/read (explicit mime)
rr = rpc(srv, "resources/read", {"uri": "demo://thing"})["result"]["contents"][0]
check(json.loads(rr["text"]) == {"hello": "world"}, "resources/read returns content")
check(rr["mimeType"] == "application/json", "read carries mime")

# resources/read (inferred mime for plain text)
rr2 = rpc(srv, "resources/read", {"uri": "demo://plain"})["result"]["contents"][0]
check(rr2["text"] == "just text", "plain resource content")
check(rr2["mimeType"] == "text/plain", "plain resource mime inferred")

# unknown resource -> error
err = rpc(srv, "resources/read", {"uri": "demo://nope"})
check("error" in err, "unknown resource -> JSON-RPC error")

# prompts/list (arguments derived from signature, _hidden excluded)
pl = rpc(srv, "prompts/list")["result"]["prompts"]
gp = next((p for p in pl if p["name"] == "greet"), None)
check(gp is not None, "prompts/list returns greet")
argnames = {a["name"] for a in (gp or {}).get("arguments", [])}
check(argnames == {"who"}, "prompt args derived, private param excluded")
check(all(a["required"] is False for a in gp["arguments"]), "defaulted arg marked optional")

# prompts/get with argument
pg = rpc(srv, "prompts/get", {"name": "greet", "arguments": {"who": "IDA"}})["result"]
msg = pg["messages"][0]
check(msg["role"] == "user" and msg["content"]["text"] == "Hello, IDA!", "prompts/get renders message")

# unknown prompt -> error
check("error" in rpc(srv, "prompts/get", {"name": "nope"}), "unknown prompt -> error")

# --- bare server: nothing registered -> no resources/prompts capability ---
bare = McpServer("bare")
caps2 = rpc(bare, "initialize", {"protocolVersion": "2025-06-18",
                                 "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}})["result"]["capabilities"]
check("resources" not in caps2, "bare server hides resources capability")
check("prompts" not in caps2, "bare server hides prompts capability")
check(rpc(bare, "resources/list")["result"]["resources"] == [], "bare resources/list empty")

print("\n" + "=" * 50)
if failures:
    print(f"FAILED ({len(failures)}): " + "; ".join(failures))
    sys.exit(1)
print("ALL RESOURCES/PROMPTS TESTS PASSED")
