"""Tests for the IDA plugin entry point.

The plugin class now lives in ``ida_mcp_loader.py`` (matching
the canonical ida-pro-mcp pattern).  ``ida_mcp/plugin.py``
re-exports the symbols for backwards compatibility.

These tests verify both the loader file (which is what IDA Pro actually
loads) and the backwards-compat re-exports.
"""
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
idaapi.cvar = type("cvar", (), {"inf": type("inf", (), {"min_ea": 0, "max_ea": 0xFFFFFFFF})()})()
sys.modules["idaapi"] = idaapi

# --- ida_kernwin ---
hooks_installed = []


class UI_Hooks:
    def __init__(self):
        pass
    def unhook(self):
        pass


def is_idaq():
    return True


def install_ui_hook(h):
    hooks_installed.append(h)


def remove_ui_hook(h):
    if h in hooks_installed:
        hooks_installed.remove(h)


ida_kernwin = types.ModuleType("ida_kernwin")
ida_kernwin.UI_Hooks = UI_Hooks
ida_kernwin.is_idaq = is_idaq
ida_kernwin.install_ui_hook = install_ui_hook
ida_kernwin.remove_ui_hook = remove_ui_hook
ida_kernwin.msg = lambda text: None
sys.modules["ida_kernwin"] = ida_kernwin

# --- other IDA stubs ---
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
# Inject a fake server module so the loader can import it.
# =========================================================================

start_calls = []
stop_calls = []


def start_server(host, port):
    start_calls.append((host, port))


def stop_server(port):
    stop_calls.append(port)


fake_server = types.ModuleType("ida_mcp.server")
fake_server.start_server = start_server
fake_server.stop_server = stop_server
fake_server.__package__ = "ida_mcp"
sys.modules["ida_mcp.server"] = fake_server

# =========================================================================
# Load the LOADER (the file IDA Pro actually loads)
# =========================================================================

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

# Use importlib to load the loader by file path.
import importlib.util
_loader_path = os.path.join(_PROJECT_ROOT, "ida_mcp_loader.py")
spec = importlib.util.spec_from_file_location("ida_mcp_loader", _loader_path)
loader_mod = importlib.util.module_from_spec(spec)
sys.modules["ida_mcp_loader"] = loader_mod
spec.loader.exec_module(loader_mod)

# Build a stub package and load the real ida_mcp package so that
# ida_mcp.plugin can re-export the loader's symbols.
pkg = types.ModuleType("ida_mcp")
pkg.__path__ = [os.path.join(_PROJECT_ROOT, "ida_mcp")]
pkg.__package__ = "ida_mcp"
sys.modules["ida_mcp"] = pkg
sys.modules["ida_mcp.rpc"] = types.ModuleType("ida_mcp.rpc")
sys.modules["ida_mcp.rpc"].MCP_SERVER = type("_MCP", (), {"_running": False})()
sys.modules["ida_mcp.rpc"].__package__ = "ida_mcp"

# Load the real ida_mcp package.
spec_pkg = importlib.util.spec_from_file_location(
    "ida_mcp", os.path.join(_PROJECT_ROOT, "ida_mcp", "__init__.py")
)
# Skip __init__ side-effects (tool registrations etc.) — just import classes.
spec_plugin = importlib.util.spec_from_file_location(
    "ida_mcp.plugin", os.path.join(_PROJECT_ROOT, "ida_mcp", "plugin.py")
)
plugin_mod = importlib.util.module_from_spec(spec_plugin)
spec_plugin.loader.exec_module(plugin_mod)
sys.modules["ida_mcp.plugin"] = plugin_mod

# =========================================================================
# Tests
# =========================================================================

# 0) Plugin class is defined at module level in the LOADER
assert hasattr(loader_mod, "IdaMcp"), "IdaMcp must be in loader"
assert hasattr(loader_mod, "PLUGIN_ENTRY"), "PLUGIN_ENTRY must be in loader"
print("Loader exports class + PLUGIN_ENTRY OK")

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

# 5) init installs UI hook and returns PLUGIN_KEEP
rc = p.init()
assert rc == PLUGIN_KEEP
assert len(hooks_installed) == 1
assert p.autostart is True
print("init OK")

# 6) ready_to_run autostarts (consumes 1 start call)
hook = hooks_installed[0]
hook.ready_to_run()
assert len(start_calls) == 1, f"expected 1 start, got {start_calls}"
# Now toggle: server running -> stop
import ida_mcp.rpc as rpc_mod
rpc_mod.MCP_SERVER._running = True
p.run(0)
assert len(stop_calls) == 1, f"expected 1 stop, got {stop_calls}"
# And again: server stopped -> start
rpc_mod.MCP_SERVER._running = False
p.run(0)
assert len(start_calls) == 2, f"expected 2 starts total, got {start_calls}"
print("run toggle OK")

# 7) term() stops and removes hook
p.term()
assert hooks_installed == []
print("term OK")

# 8) plugin.py re-exports the loader's symbols (backwards-compat)
assert plugin_mod.PLUGIN_ENTRY is loader_mod.PLUGIN_ENTRY
assert plugin_mod.IdaMcp is loader_mod.IdaMcp
print("plugin.py backwards-compat re-exports OK")

# 9) PLUGIN_ENTRY is callable when the loader import fails (emergency stub)
#    Simulate by making the loader import fail.
import builtins
real_import = builtins.__import__

def _failing_import(name, *args, **kwargs):
    if name == "ida_mcp_loader":
        raise ImportError("simulated loader import failure")
    return real_import(name, *args, **kwargs)

# Simulate the failure by loading plugin.py with the loader module absent.
# We just verify the try/except in plugin.py handles ImportError.
# Reload plugin with the import broken.
import importlib
builtins.__import__ = _failing_import
try:
    # Re-create plugin module with broken import.
    if "ida_mcp.plugin_test_isolated" in sys.modules:
        del sys.modules["ida_mcp.plugin_test_isolated"]
    spec2 = importlib.util.spec_from_file_location(
        "ida_mcp.plugin_test_isolated",
        os.path.join(_PROJECT_ROOT, "ida_mcp", "plugin.py"),
    )
    iso = importlib.util.module_from_spec(spec2)
    spec2.loader.exec_module(iso)
    # Should have emergency stub
    assert hasattr(iso, "PLUGIN_ENTRY")
    epi = iso.PLUGIN_ENTRY()
    assert epi is not None
    rc = epi.init()
    assert rc in (1, PLUGIN_KEEP)
    print("Emergency stub fallback OK")
finally:
    builtins.__import__ = real_import


print("ALL PLUGIN TESTS PASSED")
