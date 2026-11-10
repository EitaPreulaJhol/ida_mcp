"""Request-contract tests: ?profile= and tools/call arguments (14.9, 14.10).

An unknown `?profile=` used to fail open: `get_profile()` returns None and the
server treated that as "no filter", so a typo silently widened the surface from
the 16-tool triage set to every safe tool. A non-object `arguments` used to be
forwarded to the JSON-RPC registry, which calls `func(*params)` for a list --
bypassing the schema and the scalar coercion.

Both are client errors the agent can act on, so they are rejected explicitly
(-32602) instead of doing something else. Runs over live HTTP because the
profile is parsed per request into thread-local state.
"""
import json
import sys
import urllib.request

# zeromcp is IDA-free: import the real modules (true paths for coverage).
from _harness import real  # noqa: E402

jsonrpc = real("zeromcp.jsonrpc")
mcp = real("zeromcp.mcp")
profiles = real("profiles")

TRIAGE = profiles.get_profile("triage")
READONLY = profiles.get_profile("readonly")
assert TRIAGE and READONLY, "profile files must ship with the package"

srv = mcp.McpServer("profile-contract-test")

_CALLS = []


@srv.tool
def survey_binary(detail_level: str = "standard") -> str:
    """Stand-in for the real triage tool (same name)."""
    return json.dumps({"detail_level": detail_level})


@srv.tool
def echo(addr: str, size: int = 4) -> str:
    """Not in any profile; echoes its arguments."""
    _CALLS.append((addr, size))
    return json.dumps({"addr": addr, "size": size})


srv.serve("127.0.0.1", 18996, background=True)
BASE = "http://127.0.0.1:18996/mcp"


def _rpc(method, params=None, query=""):
    body = json.dumps({"jsonrpc": "2.0", "method": method,
                       "params": params or {}, "id": 1}).encode()
    req = urllib.request.Request(BASE + query, data=body,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req) as r:
        return json.loads(r.read().decode())


def _listed(query=""):
    resp = _rpc("tools/list", {}, query)
    assert "result" in resp, (query, resp)
    return {t["name"] for t in resp["result"]["tools"]}


# =========================================================================
# 14.9 -- profile filtering, and an error for an unknown profile
# =========================================================================

assert "survey_binary" in TRIAGE and "echo" not in TRIAGE
assert _listed() == {"survey_binary", "echo"}, _listed()
assert _listed("?profile=triage") == {"survey_binary"}, _listed("?profile=triage")
assert _listed("?profile=readonly") == {"survey_binary"}, _listed("?profile=readonly")
print("profile filtering OK")

resp = _rpc("tools/list", {}, "?profile=readonyl")  # typo, was fail-open
err = resp.get("error") or {}
assert err.get("code") == -32602, resp
assert "readonyl" in err.get("message", ""), resp
assert "triage" in err.get("message", ""), resp  # actionable: list the names
print("unknown profile -> -32602 OK")

_CALLS.clear()
resp = _rpc("tools/call", {"name": "echo", "arguments": {"addr": "x"}},
            "?profile=nope")
res = resp.get("result") or {}
assert res.get("isError") is True, resp
assert "nope" in res["content"][0]["text"], resp
assert _CALLS == [], f"tool ran under an unknown profile: {_CALLS}"
print("unknown profile blocks tools/call OK")

# =========================================================================
# 14.10 -- arguments must be a JSON object
# =========================================================================

_CALLS.clear()
resp = _rpc("tools/call", {"name": "echo", "arguments": ["0x1000", 16]})
err = resp.get("error") or {}
assert err.get("code") == -32602, resp
assert "arguments" in err.get("message", ""), resp
assert _CALLS == [], f"tool ran with positional args: {_CALLS}"
print("non-object arguments -> -32602 (tool not called) OK")

# a proper object still works and is coerced as before
resp = _rpc("tools/call", {"name": "echo",
                           "arguments": {"addr": "0x1000", "size": "16"}})
res = resp.get("result") or {}
assert res.get("isError") is False, resp
assert _CALLS == [("0x1000", 16)], _CALLS
print("object arguments still work (string scalar coerced) OK")

print("ALL PROFILE/CONTRACT TESTS PASSED")
