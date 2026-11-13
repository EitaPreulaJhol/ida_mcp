"""The entry point under a generated namespace must not duplicate the plugin.

IDA 8.5+ may execute ``ida-plugin.json``'s entryPoint as
``__plugins__<plugin-name>.ida_mcp_loader``. The loader is now a thin shim:
it imports ``ida_mcp.plugin`` and re-exports the class. Loading it under a
namespace must therefore resolve to the same package class, with no bare
``ida_mcp_loader`` alias and no second execution of the entry point.
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

# No ida_netnode: the config helpers are documented no-ops then.
assert "ida_netnode" not in sys.modules

# The package must exist before the loader imports ``ida_mcp.plugin``; this is
# deliberately a stub package so the test exercises the real plugin.py without
# executing ida_mcp/__init__.py and its tool registrations.
pkg = types.ModuleType("ida_mcp")
pkg.__path__ = [os.path.join(ROOT, "ida_mcp")]
pkg.__package__ = "ida_mcp"
sys.modules["ida_mcp"] = pkg

NS = "__plugins__ida_mcp.ida_mcp_loader"
spec = importlib.util.spec_from_file_location(
    NS, os.path.join(ROOT, "ida_mcp_loader.py"))
mod = importlib.util.module_from_spec(spec)
sys.modules[NS] = mod
spec.loader.exec_module(mod)
plugin_mod = sys.modules["ida_mcp.plugin"]

assert "ida_mcp_loader" not in sys.modules, (
    "the thin loader must not publish a bare ida_mcp_loader alias")
assert hasattr(mod, "IdaMcp") and hasattr(mod, "PLUGIN_ENTRY")
assert mod.IdaMcp is plugin_mod.IdaMcp, "loader and package have different classes"
assert mod.PLUGIN_ENTRY is plugin_mod.PLUGIN_ENTRY
assert mod.IdaMcp.__module__ == "ida_mcp.plugin"
assert "EMERGENCY" not in mod.IdaMcp.help
print("namespaced loader imports the package class without an alias OK")

# A second namespaced load reuses the same package module/class too.
NS2 = "__plugins__other.ida_mcp_loader"
spec2 = importlib.util.spec_from_file_location(
    NS2, os.path.join(ROOT, "ida_mcp_loader.py"))
mod2 = importlib.util.module_from_spec(spec2)
sys.modules[NS2] = mod2
spec2.loader.exec_module(mod2)
assert sys.modules["ida_mcp.plugin"] is plugin_mod
assert mod2.IdaMcp is mod.IdaMcp
print("second namespaced load reuses the package class OK")

print("ALL LOADER NAMESPACE TESTS PASSED")
