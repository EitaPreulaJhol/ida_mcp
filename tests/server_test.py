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
    def resource(self, uri, *, name=None, mime=None, tool=None):
        return lambda fn: fn
    def prompt(self, fn):
        return fn

MCP_SERVER = _FakeMCP()
def tool(func):
    return MCP_SERVER.tools.method(func)
_UNSAFE_NAMES = []
def unsafe(func):
    _UNSAFE_NAMES.append(func.__name__)
    return func
idasync = lambda f: f
ensure_analysis = lambda: None
hard_interrupt = lambda f: f
class IDAError(Exception):
    pass
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

from _harness import load_with_preamble  # noqa: E402
mod = load_with_preamble("server", FAKE_PREAMBLE, alias="server_test",
                         stub_globals={"_REGISTERED": _REGISTERED,
                     "_UNREGISTERED": _UNREGISTERED})

# =========================================================================
# Tests
# =========================================================================

# 1) parse_addr behavior through get_functions-style paths
out = mod.get_functions("*")
data = json.loads(out)
assert {f["name"] for f in data} == {"func_1000", "func_2000"}, data
# pagination: limit/offset page the function list
assert len(json.loads(mod.get_functions("*", limit=1))) == 1, out
assert json.loads(mod.get_functions("*", offset=1)) == data[1:], data
print("get_functions OK", data)

# 2) decompile_function success
out = mod.decompile_function("0x1000")
assert "int main()" in out and "return 0;" in out, out
print("decompile_function OK")

# 3) decompile_function: no function -> raises IDAError (isError:true at MCP boundary)
try:
    mod.decompile_function("0x9999")
    assert False, "expected IDAError for missing function"
except mod.IDAError as e:
    assert "No function at" in str(e), e
print("decompile no-func OK")

# 4) decompile_function: decompile returns None -> raises IDAError
try:
    mod.decompile_function("0x8888")
    assert False, "expected IDAError when decompilation returns None"
except mod.IDAError as e:
    assert "returned no result" in str(e), e
print("decompile None OK")

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

# 7b) requested port in use -> next free port; other bind errors propagate
import errno as _errno
_real_serve = mod.MCP_SERVER.serve
_tried = []


def _serve_busy_until(free_port):
    def serve(h, p, background=True):
        _tried.append(p)
        if p < free_port:
            raise OSError(_errno.EADDRINUSE, "Address already in use")
        return _real_serve(h, p, background)
    return serve


mod.MCP_SERVER.serve = _serve_busy_until(13339)
bound = mod.start_server("127.0.0.1", 13337)
assert bound == 13339 and _tried == [13337, 13338, 13339], (bound, _tried)
assert mod._OWN_PORT == 13339, mod._OWN_PORT
assert _REGISTERED[-1][1] == 13339, _REGISTERED
mod.stop_server(13339)

_tried.clear()
mod.MCP_SERVER.serve = _serve_busy_until(10**6)  # whole range busy
try:
    mod.start_server("127.0.0.1", 13337)
    raise AssertionError("exhausted range must raise")
except OSError as e:
    assert "13337-13346" in str(e) and len(_tried) == 10, (e, _tried)
assert mod._OWN_PORT is None


def _serve_bad_host(h, p, background=True):
    _tried.append(p)
    raise OSError(_errno.EADDRNOTAVAIL, "Cannot assign requested address")


_tried.clear()
mod.MCP_SERVER.serve = _serve_bad_host
try:
    mod.start_server("10.255.255.1", 13337)
    raise AssertionError("non-EADDRINUSE errors must propagate")
except OSError as e:
    assert e.errno == _errno.EADDRNOTAVAIL and _tried == [13337], (e, _tried)
mod.MCP_SERVER.serve = _real_serve
print("port fallback OK")

# 7c) stop_server removes agent-installed hooks (they must not outlive the
#     server, nor run orphaned code after a hot reload)
_hook_cleanups = []
mod.__dict__["api_hooks"] = types.SimpleNamespace(
    remove_all_hooks=lambda: _hook_cleanups.append(True) or ["idb_1"])
mod.start_server("127.0.0.1", 13337)
mod.stop_server(13337)
assert _hook_cleanups == [True], _hook_cleanups
mod.__dict__["api_hooks"] = types.SimpleNamespace(
    remove_all_hooks=lambda: (_ for _ in ()).throw(RuntimeError("boom")))
mod.start_server("127.0.0.1", 13337)
mod.stop_server(13337)  # a failing cleanup must not break shutdown
assert mod._OWN_PORT is None and mod.MCP_SERVER._running is False
print("stop_server hook cleanup OK")

# 8) core unsafe marking survived the rewrite
assert "execute_script" in mod._UNSAFE_NAMES, mod._UNSAFE_NAMES
assert "close_instance" in mod._UNSAFE_NAMES, mod._UNSAFE_NAMES
print("unsafe marking OK")

print("ALL SERVER TOOL TESTS PASSED")
