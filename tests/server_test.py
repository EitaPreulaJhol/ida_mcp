"""Tests for server.py core tools (decompile/disassembly/listing/lifecycle).

Stubs IDA modules and loads the source via exec with all relative imports
replaced by fakes. (Rewritten in the server_extra_test.py style; the old
regex-stripping version rotted after server.py grew new imports.)
"""
import json
import os
import re
import sys
import types

# =========================================================================
# Stub IDA modules used by server.py
# =========================================================================

BADADDR = 0xFFFFFFFFFFFFFFFF


def make(modname, **attrs):
    m = types.ModuleType(modname)
    for k, v in attrs.items():
        setattr(m, k, v)
    sys.modules[modname] = m
    return m


make("ida_auto", auto_wait=lambda: True, auto_is_ok=lambda: True)
make("ida_funcs",
     get_func_name=lambda ea: f"func_{ea:x}",
     get_func=lambda ea: None if ea == 0x9999 else types.SimpleNamespace(start_ea=ea))
make("ida_hexrays",
     init_hexrays_plugin=lambda: True,
     decompile=lambda ea: None if ea == 0x8888 else types.SimpleNamespace(
         get_pseudocode=lambda: [types.SimpleNamespace(line="int main() {"),
                                 types.SimpleNamespace(line="  return 0;"),
                                 types.SimpleNamespace(line="}")]),
     mark_cfunc_dirty=lambda ea: None)
make("ida_kernwin", msg=lambda *a, **k: None)
make("ida_lines", tag_remove=lambda s: s,
     generate_disasm_line=lambda ea, flags: f"asm_{ea:x}")
make("ida_name", get_name_ea=lambda bad, name: 0x5000 if name == "myfunc" else BADADDR)
make("ida_ua")
make("idaapi", BADADDR=BADADDR, get_imagebase=lambda: 0x400000)
make("idc", next_head=lambda ea: ea + 1,
     get_idb_path=lambda: "/tmp/f.idb",
     get_input_file_path=lambda: "")
make("ida_nalt", get_import_module_qty=lambda: 0,
     get_input_file_path=lambda: "")
make("idautils", Functions=lambda: [0x1000, 0x2000],
     Segments=lambda: [0x1000])

_REGISTERED = []
_UNREGISTERED = []

# =========================================================================
# Load server.py
# =========================================================================

HERE = os.path.dirname(os.path.abspath(__file__))
PKG = os.path.join(HERE, "..", "ida_mcp")
src = open(os.path.join(PKG, "server.py")).read()

FAKE_PREAMBLE = '''
class _FakeTools:
    def __init__(self):
        self.methods = {}
    def method(self, func, name=None):
        self.methods[name or func.__name__] = func
        return func

class _FakeMCP:
    def __init__(self):
        self.tools = _FakeTools()
        self.unsafe_tools = set()
        self._running = False
    def serve(self, h, p, background=True):
        self._running = True
    def stop(self):
        self._running = False

MCP_SERVER = _FakeMCP()
def tool(func):
    return MCP_SERVER.tools.method(func)
_UNSAFE_NAMES = []
def unsafe(func):
    _UNSAFE_NAMES.append(func.__name__)
    return func
idasync = lambda f: f
def _run_code(code):
    return {"result": code, "stdout": "", "stderr": ""}
def parse_addr(s):
    s = str(s).strip()
    if s.startswith("0x"): return int(s, 16)
    try: return int(s)
    except ValueError: pass
    if s == "myfunc": return 0x5000
    raise ValueError(f"Unknown: {s}")
def _cap_lines(text, max_lines):
    if text is None: return None, None
    lines = text.split(chr(10))
    if len(lines) <= max_lines: return text, None
    return chr(10).join(lines[:max_lines]), len(lines)
def discover_instances():
    return []
def register_instance(*a, **k):
    _REGISTERED.append(a)
def unregister_instance(port):
    _UNREGISTERED.append(port)
    return True
'''

src = re.sub(r"from \.rpc import .*", "", src)
src = re.sub(r"from \.sync import .*", "", src)
src = re.sub(r"from \.api_python import .*", "", src)
src = re.sub(r"from \.api_analysis import .*", "", src)
src = re.sub(r"from \.discovery import \([^)]*\)", "", src, flags=re.DOTALL)
src = re.sub(r"from \. import \w+.*", "", src)
src = FAKE_PREAMBLE + src

mod = types.ModuleType("server_test")
mod.__dict__.update({"_REGISTERED": _REGISTERED,
                     "_UNREGISTERED": _UNREGISTERED})
exec(compile(src, "server_test", "exec"), mod.__dict__)
sys.modules["server_test"] = mod

# =========================================================================
# Tests
# =========================================================================

# 1) parse_addr behavior through get_functions-style paths
out = mod.get_functions("*")
data = json.loads(out)
assert {f["name"] for f in data} == {"func_1000", "func_2000"}, data
print("get_functions OK", data)

# 2) decompile_function success
out = mod.decompile_function("0x1000")
assert "int main()" in out and "return 0;" in out, out
print("decompile_function OK")

# 3) decompile_function: no function
out = mod.decompile_function("0x9999")
assert "No function at" in out, out
print("decompile no-func OK:", out)

# 4) decompile_function: decompile returns None
out = mod.decompile_function("0x8888")
assert "returned no result" in out, out
print("decompile None OK:", out)

# 5) get_disassembly
out = mod.get_disassembly("0x1000", 2)
assert "asm_1000" in out and "asm_1001" in out, out
print("get_disassembly OK:", out)

# 6) execute_script delegates to _run_code
out = mod.execute_script("print('hi')")
assert out == "print('hi')", out
print("execute_script OK")

# 7) start/stop lifecycle + registration + own-port tracking
assert mod._OWN_PORT is None
mod.start_server("127.0.0.1", 13337)
assert mod.MCP_SERVER._running is True
assert mod._OWN_PORT == 13337, mod._OWN_PORT
assert _REGISTERED and _REGISTERED[0][1] == 13337, _REGISTERED
mod.stop_server(13337)
assert mod.MCP_SERVER._running is False
assert mod._OWN_PORT is None
assert 13337 in _UNREGISTERED, _UNREGISTERED
print("start/stop OK")

# 8) core unsafe marking survived the rewrite
assert "execute_script" in mod._UNSAFE_NAMES, mod._UNSAFE_NAMES
assert "close_instance" in mod._UNSAFE_NAMES, mod._UNSAFE_NAMES
print("unsafe marking OK")

print("ALL SERVER TOOL TESTS PASSED")
