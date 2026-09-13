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
HERE = os.path.dirname(os.path.abspath(__file__))
PKG = os.path.join(HERE, "..", "ida_mcp")
src = open(os.path.join(PKG, "api_python.py")).read()
src = src.replace("from .rpc import tool, unsafe", "tool = lambda f: f\nunsafe = lambda f: f")
src = src.replace("from .sync import idasync", "idasync = lambda f: f")
mod = types.ModuleType("api_test")
exec(compile(src, "api_test", "exec"), mod.__dict__)
sys.modules["api_test"] = mod

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

print("ALL API_PYTHON _run_code TESTS PASSED")
