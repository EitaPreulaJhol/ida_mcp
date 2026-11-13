"""Tests for the IDA plugin controller and its thin entry-point shim.

The controller (``IdaMcp``, ``MCPUIHooks`` and the netnode helpers) lives in
``ida_mcp/plugin.py``; ``ida_mcp_loader.py`` only puts the install folder on
``sys.path`` and re-exports the public symbols. These tests load the loader the
way IDA does and verify the package class is the same object (no duplicate
copy, no emergency stub).
"""
import importlib.util
import os
import sys
import types

# =========================================================================
# Stub IDA modules BEFORE importing anything from the package.
# =========================================================================

class _FakePluginT:
    pass


PLUGIN_KEEP = 1

# --- idaapi ---
idaapi = types.ModuleType("idaapi")
idaapi.PLUGIN_KEEP = PLUGIN_KEEP
idaapi.plugin_t = _FakePluginT
sys.modules["idaapi"] = idaapi

# --- ida_kernwin ---
hooks_installed = []


class UI_Hooks:
    """Mirror of ida_kernwin.UI_Hooks: hook()/unhook(), no module helpers."""

    def __init__(self):
        self.hooked = False

    def hook(self):
        self.hooked = True
        if self not in hooks_installed:
            hooks_installed.append(self)
        return True

    def unhook(self):
        self.hooked = False
        if self in hooks_installed:
            hooks_installed.remove(self)
        return True


def is_idaq():
    return True


ida_kernwin = types.ModuleType("ida_kernwin")
ida_kernwin.UI_Hooks = UI_Hooks
ida_kernwin.is_idaq = is_idaq
ida_kernwin.msg = lambda text: None
sys.modules["ida_kernwin"] = ida_kernwin

# --- other IDA stubs (kept for parity with a real IDA import) ---
for mod_name in [
    "idc", "idautils", "ida_bytes", "ida_dbg", "ida_entry", "ida_frame",
    "ida_funcs", "ida_hexrays", "ida_ida", "ida_lines", "ida_nalt",
    "ida_name", "ida_segment", "ida_typeinf", "ida_xref", "ida_ua",
    "ida_auto",
]:
    if mod_name not in sys.modules:
        m = types.ModuleType(mod_name)
        m.BADADDR = -1
        if mod_name == "ida_lines":
            m.generate_disasm_line = lambda ea, flags: f"{ea:x}: nop"
            m.tag_remove = lambda s: s
        if mod_name == "ida_segment":
            m.getseg = lambda ea: None
            m.get_segm_name = lambda seg: "test"
        if mod_name == "ida_typeinf":
            m.tinfo_t = type("tinfo_t", (), {"__bool__": lambda self: False})
            m.func_type_data_t = type("func_type_data_t", (), {"__init__": lambda self: None})
        if mod_name == "ida_nalt":
            m.get_tinfo = lambda tif, ea: False
            m.STRTYPE_C = 0
        sys.modules[mod_name] = m

# =========================================================================
# Build the package and the lazy server/rpc imports the plugin expects.
# =========================================================================

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

pkg = types.ModuleType("ida_mcp")
pkg.__path__ = [os.path.join(_PROJECT_ROOT, "ida_mcp")]
pkg.__package__ = "ida_mcp"
sys.modules["ida_mcp"] = pkg

fake_rpc = types.ModuleType("ida_mcp.rpc")
fake_rpc.__package__ = "ida_mcp"
fake_rpc.MCP_SERVER = type("_MCP", (), {"_running": False, "auth_token": None})()
sys.modules["ida_mcp.rpc"] = fake_rpc

start_calls = []
stop_calls = []


def start_server(host, port):
    start_calls.append((host, port))


def stop_server(port):
    stop_calls.append(port)


fake_server = types.ModuleType("ida_mcp.server")
fake_server.__package__ = "ida_mcp"
fake_server.start_server = start_server
fake_server.stop_server = stop_server
sys.modules["ida_mcp.server"] = fake_server

# =========================================================================
# Load the LOADER (what IDA Pro executes) and its package controller.
# =========================================================================

_loader_path = os.path.join(_PROJECT_ROOT, "ida_mcp_loader.py")
spec = importlib.util.spec_from_file_location("ida_mcp_loader", _loader_path)
loader_mod = importlib.util.module_from_spec(spec)
sys.modules["ida_mcp_loader"] = loader_mod
spec.loader.exec_module(loader_mod)
plugin_mod = sys.modules["ida_mcp.plugin"]

# =========================================================================
# Tests
# =========================================================================

# 0) The shim exports the real package symbols; the package owns the class.
assert hasattr(loader_mod, "IdaMcp"), "IdaMcp must be re-exported by the loader"
assert hasattr(loader_mod, "PLUGIN_ENTRY"), "PLUGIN_ENTRY must be re-exported"
assert loader_mod.IdaMcp is plugin_mod.IdaMcp
assert loader_mod.PLUGIN_ENTRY is plugin_mod.PLUGIN_ENTRY
assert loader_mod.unload_package is plugin_mod.unload_package
print("loaders re-export the package class + PLUGIN_ENTRY OK")

# 1) Plugin class has all required attributes
cls = loader_mod.IdaMcp
assert hasattr(cls, "flags"), "missing flags"
assert hasattr(cls, "comment"), "missing comment"
assert hasattr(cls, "help"), "missing help"
assert hasattr(cls, "wanted_name"), "missing wanted_name"
assert hasattr(cls, "wanted_hotkey"), "missing wanted_hotkey"
print("Plugin class has all required attributes OK")

# 2) flags is PLUGIN_KEEP (1) or idaapi.PLUGIN_KEEP
assert cls.flags in (1, PLUGIN_KEEP), f"unexpected flags: {cls.flags}"
print(f"Plugin flags value OK: {cls.flags}")

# 3) Inheritance from idaapi.plugin_t
assert issubclass(cls, _FakePluginT), "must inherit from idaapi.plugin_t"
print("Plugin class inherits from plugin_t OK")

# 4) PLUGIN_ENTRY returns an instance
p = loader_mod.PLUGIN_ENTRY()
assert isinstance(p, cls)
print("PLUGIN_ENTRY returns instance OK")

# 5) init installs (hooks) the UI hook and returns PLUGIN_KEEP
rc = p.init()
assert rc == PLUGIN_KEEP
assert len(hooks_installed) == 1, "init() must hook the UI_Hooks instance"
assert p.ui_hook.hooked is True, "UI_Hooks.hook() was not called"
assert p.autostart is True
print("init OK")

# 6) ready_to_run autostarts (consumes 1 start call)
hook = hooks_installed[0]
hook.ready_to_run()
assert len(start_calls) == 1, f"expected 1 start, got {start_calls}"
# Now toggle: server running -> stop
rpc_mod = fake_rpc
rpc_mod.MCP_SERVER._running = True
p.run(0)
assert len(stop_calls) == 1, f"expected 1 stop, got {stop_calls}"
# And again: server stopped -> start
rpc_mod.MCP_SERVER._running = False
p.run(0)
assert len(start_calls) == 2, f"expected 2 starts total, got {start_calls}"
print("run toggle OK")

# 6b) the server fell back to another port (requested one in use): the
#     controller must track the bound port for stop, but keep the requested
#     one as the IDB setting.
fake_server.start_server = lambda host, port: (start_calls.append((host, port)), port + 3)[1]
rpc_mod.MCP_SERVER._running = False
p.run(0)
assert start_calls[-1][1] == 13337, start_calls
assert p.port == 13340 and p.requested_port == 13337, (p.port, p.requested_port)
rpc_mod.MCP_SERVER._running = True
p.run(0)
assert stop_calls[-1] == 13340, stop_calls
rpc_mod.MCP_SERVER._running = False
fake_server.start_server = start_server
print("port fallback tracked by controller OK")

# 6c) unload_package stops a server started from the modules it drops, so a
#     following run(0) cannot start a second server beside the stale one.
_stopped = []
_fake_srv = type("Srv", (), {"_running": True, "stop": lambda self: _stopped.append("srv")})()
_rpc = types.ModuleType("hotpkg.rpc")
_rpc.MCP_SERVER = _fake_srv
_srvmod = types.ModuleType("hotpkg.server")
_srvmod._OWN_PORT = 13341
_srvmod.stop_server = lambda port: _stopped.append(port)
sys.modules.update({"hotpkg": types.ModuleType("hotpkg"),
                    "hotpkg.rpc": _rpc, "hotpkg.server": _srvmod})
loader_mod.unload_package("hotpkg")
assert _stopped == [13341], _stopped
assert not any(m == "hotpkg" or m.startswith("hotpkg.") for m in sys.modules)
# not running -> nothing to stop, modules still dropped
_fake_srv._running = False
sys.modules.update({"hotpkg": types.ModuleType("hotpkg"), "hotpkg.rpc": _rpc})
loader_mod.unload_package("hotpkg")
assert _stopped == [13341] and "hotpkg.rpc" not in sys.modules, _stopped
print("unload_package stops the stale server OK")

# 7) term() stops and unhooks
p.term()
assert hooks_installed == [], "term() must unhook the UI hook"
assert p.ui_hook.hooked is False, "UI_Hooks.unhook() was not called"
print("term OK")

# 8) IDB-persisted host: only loopback is honored; IDA_MCP_HOST overrides.
class _FakeNetnode:
    host = ""

    def __init__(self, *args):
        pass

    def supstr(self, idx):
        return _FakeNetnode.host


_msgs = []
_saved_nn, _saved_msg = plugin_mod.ida_netnode, ida_kernwin.msg
_saved_env = os.environ.pop("IDA_MCP_HOST", None)
plugin_mod.ida_netnode = types.SimpleNamespace(netnode=_FakeNetnode)
ida_kernwin.msg = _msgs.append
try:
    _FakeNetnode.host = "0.0.0.0"
    assert plugin_mod._get_host("127.0.0.1") == "127.0.0.1"
    assert any("ignoring non-loopback host '0.0.0.0'" in m for m in _msgs), _msgs
    _FakeNetnode.host = "::1"
    assert plugin_mod._get_host("127.0.0.1") == "::1"
    os.environ["IDA_MCP_HOST"] = "0.0.0.0"
    assert plugin_mod._get_host("127.0.0.1") == "0.0.0.0"
finally:
    plugin_mod.ida_netnode, ida_kernwin.msg = _saved_nn, _saved_msg
    os.environ.pop("IDA_MCP_HOST", None)
    if _saved_env is not None:
        os.environ["IDA_MCP_HOST"] = _saved_env
print("IDB host restricted to loopback OK")


print("ALL PLUGIN TESTS PASSED")
