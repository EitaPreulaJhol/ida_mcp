import os
import sys
import types

# --- Stub all IDA modules referenced by api_python.py ---
ida_names = [
    "idaapi", "idc", "ida_bytes", "ida_dbg", "ida_entry", "ida_frame",
    "ida_funcs", "ida_hexrays", "ida_ida", "ida_kernwin", "ida_lines",
    "ida_nalt", "ida_name", "ida_segment", "ida_typeinf", "ida_xref", "idautils",
]
for n in ida_names:
    sys.modules.setdefault(n, types.ModuleType(n))

# ida_kernwin.msg_get_lines: returns different content on 1st vs 2nd call so we
# can verify the NEW messages are captured (the original bug captured the oldest).
calls = {"n": 0}


def fake_msg_get_lines(count=-1):
    # Each _run_code() calls this twice (pre/post). Return the "before" state on
    # the odd (first) call and the "after" state (with 2 new lines) on the even call.
    calls["n"] += 1
    if calls["n"] % 2 == 1:
        return ["line1"]
    return ["line1", "line2", "line3"]


sys.modules["ida_kernwin"].msg_get_lines = fake_msg_get_lines

# --- Load api_python.py with relative imports patched to no-ops ---
from _harness import RPC_STUB, load  # noqa: E402
mod = load("api_python", {
    "rpc": RPC_STUB,
    "sync": "idasync = lambda f: f\nhard_interrupt = lambda f: f\n"
    "class ToolInterrupt(BaseException):\n"
    "    def __init__(self, reason='timeout', message='t'):\n"
    "        super().__init__(message); self.reason = reason; self.message = message",
}, alias="api_test")

# 1) single expression
r = mod._run_code("1 + 1")
assert r["result"] == "2", r
print("single expression OK:", r["result"])

# 2) assignment to result
r = mod._run_code("result = 40 + 2")
assert r["result"] == "42", r
print("result= OK:", r["result"])

# 3) __result__ still supported (backward compat)
r = mod._run_code("__result__ = 'hi'")
assert r["result"] == "hi", r
print("__result__ OK:", r["result"])

# 4) statements + trailing expression (Jupyter-style)
r = mod._run_code("x = 5\nx * 10")
assert r["result"] == "50", r
print("trailing expr OK:", r["result"])

# 5) msg_get_lines FIX: new messages captured (line2, line3), not the oldest
r = mod._run_code("pass")
assert "line2\nline3" in r["stderr"], r
print("msg_get_lines fix OK -> captured:", repr(r["stderr"]))

# 6) exception never escapes; returned in stderr
r = mod._run_code("raise ValueError('boom')")
assert "boom" in r["stderr"], r
assert r["result"] == "", r
print("exception captured OK")

# 7) timeout/cancel inside the script: partial stdout kept, error flagged,
#    and `except Exception` in the script cannot swallow it.
def _fire_interrupt():
    raise mod.ToolInterrupt("timeout", "Tool timed out after 1.00s")


sys.modules["idc"].slow_sdk_call = _fire_interrupt
r = mod._run_code(
    "print('done 1')\n"
    "try:\n"
    "    idc.slow_sdk_call()\n"
    "except Exception:\n"
    "    print('swallowed!')\n"
)
assert "done 1" in r["stdout"], r
assert "swallowed!" not in r["stdout"], r
assert r["error"] == "Tool timed out after 1.00s", r
assert "smaller batches" in r["stderr"], r
print("ToolInterrupt -> partial output + error OK")

# 8) exit() in a script must not escape (would wedge the server).
r = mod._run_code("print('before')\nimport sys\nsys.exit(3)")
assert "before" in r["stdout"] and "exit(3)" in r["stderr"], r
assert not r.get("error"), r
print("SystemExit contained OK")

# 8) one namespace: functions/comprehensions see the script's top-level names
#    (with separate globals/locals dicts every case below raised NameError)
cases = [
    ("def f():\n    return helper()\ndef helper():\n    return 41\nresult = f() + 1", "42"),
    ("BASE = 0x1000\ndef addr(i):\n    return BASE + i\nresult = hex(addr(5))", "0x1005"),
    ("names = ['a', 'b']\nprefix = 'sub_'\nresult = [prefix + n for n in names]",
     "['sub_a', 'sub_b']"),
    ("K = 2\ndef g(x):\n    return x * K\ng(21)", "42"),
    ("class C:\n    pass\nobj = C()\nresult = type(obj).__name__", "C"),
]
for code, want in cases:
    r = mod._run_code(code)
    assert r["result"] == want and not r["stderr"], (code, r)
print("single namespace (helpers/constants/comprehensions) OK")

# 9) without `result`, the last variable the script bound is returned, and
#    pre-loaded modules never count as script bindings
r = mod._run_code("a = 1\nb = 2")
assert r["result"] == "2", r
r = mod._run_code("import os\nfirst = 'x'\nsecond = 'y'")
assert r["result"] == "y", r
r = mod._run_code("for i in range(3):\n    pass")
assert r["result"] == "2", r  # the loop variable is the last binding
print("last-binding result OK")

print("ALL API_PYTHON _run_code TESTS PASSED")
