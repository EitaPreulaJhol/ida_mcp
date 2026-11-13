"""The IDA 8.5+ folder loader is imported under a generated namespace.

IDA may execute ``ida-plugin.json``'s entryPoint as
``__plugins__<plugin-name>.ida_mcp_loader``.  The package's
``ida_mcp.plugin`` re-exports the class via ``from ida_mcp_loader import ...``,
so the entry point must publish that bare alias or the package imports a
second copy / falls into the emergency stub.
"""
import importlib.util
import os
import sys
import types

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

idaapi = types.ModuleType("idaapi")
idaapi.PLUGIN_KEEP = 1


class _PluginT:
    pass


idaapi.plugin_t = _PluginT
sys.modules["idaapi"] = idaapi


class _UIHooks:
    def hook(self):
        return True

    def unhook(self):
        pass


ida_kernwin = types.ModuleType("ida_kernwin")
ida_kernwin.UI_Hooks = _UIHooks
ida_kernwin.is_idaq = lambda: True
ida_kernwin.msg = lambda *a, **k: None
sys.modules["ida_kernwin"] = ida_kernwin

# No ida_netnode: the loader's config helpers are documented no-ops then.
assert "ida_netnode" not in sys.modules

NS = "__plugins__ida_mcp.ida_mcp_loader"
spec = importlib.util.spec_from_file_location(
    NS, os.path.join(ROOT, "ida_mcp_loader.py"))
mod = importlib.util.module_from_spec(spec)
sys.modules[NS] = mod
spec.loader.exec_module(mod)

assert sys.modules.get("ida_mcp_loader") is mod, (
    "entry point loaded under a namespace must publish the bare alias")
assert hasattr(mod, "IdaMcp") and hasattr(mod, "PLUGIN_ENTRY")
print("namespaced loader publishes the bare ida_mcp_loader alias OK")

# The package re-export must resolve to that same class, not an emergency stub
# or a second execution of the entry point.
pkg = types.ModuleType("ida_mcp")
pkg.__path__ = [os.path.join(ROOT, "ida_mcp")]
pkg.__package__ = "ida_mcp"
sys.modules["ida_mcp"] = pkg
pspec = importlib.util.spec_from_file_location(
    "ida_mcp.plugin", os.path.join(ROOT, "ida_mcp", "plugin.py"))
plugin_mod = importlib.util.module_from_spec(pspec)
sys.modules["ida_mcp.plugin"] = plugin_mod
pspec.loader.exec_module(plugin_mod)
assert plugin_mod.IdaMcp is mod.IdaMcp, "plugin.py re-exported a different class"
assert plugin_mod.PLUGIN_ENTRY is mod.PLUGIN_ENTRY
print("ida_mcp.plugin re-exports the namespaced loader class OK")

print("ALL LOADER NAMESPACE TESTS PASSED")
