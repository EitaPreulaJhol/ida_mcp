"""Tests for server.py additions (health/warmup/instances/decompile cap).

Stubs IDA modules and loads the source via exec with all relative imports
replaced by fakes.
"""
import json
import os
import re
import sys
import types

# =========================================================================
# Stub IDA modules
# =========================================================================

ida_auto = types.ModuleType("ida_auto")
ida_auto.auto_wait = lambda: None
ida_auto.auto_is_ok = lambda: True
sys.modules["ida_auto"] = ida_auto

idaapi = types.ModuleType("idaapi")
idaapi.BADADDR = -1
idaapi.get_imagebase = lambda: 0x400000
sys.modules["idaapi"] = idaapi


class FakeFunc:
    def __init__(self, start):
        self.start_ea = start


ida_funcs = types.ModuleType("ida_funcs")
ida_funcs.get_func = lambda ea: FakeFunc(ea) if ea == 0x1000 else None
ida_funcs.get_func_name = lambda ea: f"func_{ea:x}"
sys.modules["ida_funcs"] = ida_funcs


class FakeLine:
    def __init__(self, line):
        self.line = line


class FakeCFunc:
    LINES = 3

    def get_pseudocode(self):
        return [FakeLine(f"line {i}") for i in range(self.LINES)]


ida_hexrays = types.ModuleType("ida_hexrays")
ida_hexrays.init_hexrays_plugin = lambda: True
ida_hexrays.decompile = lambda ea: FakeCFunc()
ida_hexrays.mark_cfunc_dirty = lambda ea: None
sys.modules["ida_hexrays"] = ida_hexrays

ida_kernwin = types.ModuleType("ida_kernwin")
ida_kernwin.msg = lambda *a, **k: None
sys.modules["ida_kernwin"] = ida_kernwin

ida_lines = types.ModuleType("ida_lines")
ida_lines.tag_remove = lambda s: s
ida_lines.generate_disasm_line = lambda ea, flags: f"insn_{ea:x}"
sys.modules["ida_lines"] = ida_lines

ida_ua = types.ModuleType("ida_ua")
sys.modules["ida_ua"] = ida_ua

idc = types.ModuleType("idc")
idc.get_idb_path = lambda: "/tmp/f.idb"
idc.get_input_file_path = lambda: ""
idc.next_head = lambda ea: ea + 1
sys.modules["idc"] = idc

ida_nalt = types.ModuleType("ida_nalt")
ida_nalt.get_import_module_qty = lambda: 1
ida_nalt.get_input_file_path = lambda: ""
sys.modules["ida_nalt"] = ida_nalt

idautils = types.ModuleType("idautils")
idautils.Functions = lambda: iter([0x1000])
idautils.Segments = lambda: iter([0x1000])
sys.modules["idautils"] = idautils

# fake discovery backend
_FAKE_INSTANCES = [
    {"host": "127.0.0.1", "port": 13337, "pid": 111,
     "binary": "a.exe", "idb_path": "/tmp/a.i64", "backend": "gui"},
    {"host": "127.0.0.1", "port": 13338, "pid": 222,
     "binary": "b.exe", "idb_path": "/tmp/b.i64", "backend": "gui"},
]
_REGISTERED: list = []
_UNREGISTERED: list = []

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
        self.serve_calls = []
    def serve(self, h, p, background=True):
        self.serve_calls.append((h, p))
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
    except ValueError: raise ValueError(f"Unknown: {s}")
def _cap_lines(text, max_lines):
    if text is None: return None, None
    lines = text.split(chr(10))
    if len(lines) <= max_lines: return text, None
    return chr(10).join(lines[:max_lines]), len(lines)
def discover_instances():
    return list(_FAKE_INSTANCES)
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

mod = types.ModuleType("server_extra_test")
mod.__dict__.update({"_FAKE_INSTANCES": _FAKE_INSTANCES,
                     "_REGISTERED": _REGISTERED,
                     "_UNREGISTERED": _UNREGISTERED})
exec(compile(src, "server_extra_test", "exec"), mod.__dict__)
sys.modules["server_extra_test"] = mod

# =========================================================================
# Tests
# =========================================================================

r = json.loads(mod.server_health())
assert r["status"] == "ok" and r["idb_path"] == "/tmp/f.idb", r
assert r["imagebase"] == "0x400000", r
assert r["auto_analysis_ready"] is True and r["hexrays_ready"] is True, r
assert r["uptime_sec"] >= 0, r
print("server_health OK")

r = json.loads(mod.server_warmup())
assert r["ok"] is True and len(r["steps"]) == 5, r
assert all(s["ok"] for s in r["steps"]), r
assert r["health"]["status"] == "ok", r
print("server_warmup OK")

r = json.loads(mod.list_instances())
assert r["count"] == 2, r
r = json.loads(mod.get_instance_info(13338))
assert r["binary"] == "b.exe", r
r = json.loads(mod.get_instance_info(9999))
assert "error" in r, r
print("instances OK")

r = json.loads(mod.close_instance(13337))
assert "error" in r, r  # nothing started yet
mod.start_server("127.0.0.1", 13337)
assert mod.MCP_SERVER._running is True
r = json.loads(mod.close_instance(9999))
assert "error" in r and mod.MCP_SERVER._running is True, r
r = json.loads(mod.close_instance(13337))
assert r["ok"] is True and mod.MCP_SERVER._running is False, r
assert 13337 in _UNREGISTERED, _UNREGISTERED
print("close_instance OK")

out = mod.decompile_function("0x1000")
assert out == "line 0\nline 1\nline 2", out
FakeCFunc.LINES = 2500
out = mod.decompile_function("0x1000")
assert "[truncated 2500 total lines" in out, out[-80:]
assert len(out.split("\n")) == 2001, len(out.split("\n"))
FakeCFunc.LINES = 3
out = mod.decompile_function("0x9999")
assert "No function" in out, out
print("decompile cap OK")

out = mod.get_disassembly("0x1000", 2)
assert "insn_1000" in out, out
out = mod.execute_script("1+1")
assert out == "1+1", out
print("core tools still OK")

assert "close_instance" in mod._UNSAFE_NAMES, mod._UNSAFE_NAMES
print("unsafe marking OK")

print("ALL SERVER EXTRA TESTS PASSED")
