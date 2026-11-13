"""Opt-in live check of the installed folder layout and namespaced loader.

The matrix harness extracts the modern ``ida-mcp-bridge/`` folder into a
temporary ``$IDAUSR/plugins`` and runs this file with the selected IDA's
``idalib/python`` on ``PYTHONPATH``. It verifies that the entry point loads the
package from that folder (not from the repository), under the generated
``__plugins__...`` name, and that the loader and package expose one class.

Opt-in. Skips green unless ``IDA_MCP_FOLDER_ROOT`` points at the extracted
``ida-mcp-bridge`` folder.
"""
import importlib.util
import json
import os
import sys

try:
    import idapro  # noqa: F401  (puts IDA's Python modules on sys.path)
except Exception as e:  # noqa: BLE001
    print(f"SKIP: import idapro failed ({e}); idalib not available/licensed.")
    sys.exit(0)

FOLDER = os.environ.get("IDA_MCP_FOLDER_ROOT", "").strip()
if not FOLDER:
    print("SKIP: IDA_MCP_FOLDER_ROOT not set (folder-loader gate).")
    sys.exit(0)
if not os.path.isdir(FOLDER):
    print(f"FAILED: IDA_MCP_FOLDER_ROOT is not a folder: {FOLDER!r}")
    sys.exit(1)

manifest_path = os.path.join(FOLDER, "ida-plugin.json")
loader_path = os.path.join(FOLDER, "ida_mcp_loader.py")
package_dir = os.path.join(FOLDER, "ida_mcp")
for path in (manifest_path, loader_path, package_dir):
    if not os.path.exists(path):
        print(f"FAILED: missing installed path: {path}")
        sys.exit(1)

with open(manifest_path, encoding="utf-8") as f:
    manifest = json.load(f)
plugin = manifest.get("plugin", {})
assert plugin.get("entryPoint") == "ida_mcp_loader.py", plugin
assert plugin.get("name") == "ida-mcp-bridge", plugin
assert os.path.isfile(os.path.join(FOLDER, plugin["entryPoint"]))

# Load the entry point exactly as IDA's generated namespace does. A fresh
# subprocess (the matrix runs one) ensures the repository copy cannot shadow it.
ns = "__plugins__ida_mcp_bridge.ida_mcp_loader"
spec = importlib.util.spec_from_file_location(ns, loader_path)
loader = importlib.util.module_from_spec(spec)
sys.modules[ns] = loader
spec.loader.exec_module(loader)
assert sys.modules.get("ida_mcp_loader") is None, (
    "the thin loader must not publish a bare alias")
assert loader.IdaMcp is not None and loader.PLUGIN_ENTRY is not None

import ida_mcp  # noqa: E402  (imported after the loader put FOLDER on sys.path)
import ida_mcp.plugin as plugin_mod  # noqa: E402

real_folder = os.path.realpath(FOLDER)
assert os.path.realpath(ida_mcp.__file__).startswith(real_folder + os.sep), \
    (ida_mcp.__file__, real_folder)
assert os.path.realpath(plugin_mod.__file__).startswith(real_folder + os.sep)
assert loader.IdaMcp is plugin_mod.IdaMcp
assert loader.PLUGIN_ENTRY is plugin_mod.PLUGIN_ENTRY
assert loader.IdaMcp.__module__ == "ida_mcp.plugin"
assert "EMERGENCY" not in loader.IdaMcp.help

print(f"folder loader OK: {real_folder}")
print("ALL IDALIB FOLDER-LOADER CHECKS PASSED")
