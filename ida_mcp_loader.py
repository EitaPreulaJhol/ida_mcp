"""IDA Pro entry point for ida-mcp-bridge.

IDA loads this file (``ida-plugin.json`` ``entryPoint`` or the legacy root
layout) and calls ``PLUGIN_ENTRY``. The controller itself lives in
``ida_mcp/plugin.py``; this shim only makes the install folder importable and
re-exports the public symbols, so loading the entry point under a generated
``__plugins__...`` namespace cannot create a second plugin class.
"""
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from ida_mcp.plugin import IdaMcp, PLUGIN_ENTRY, unload_package  # noqa: E402,F401

__all__ = ["IdaMcp", "PLUGIN_ENTRY", "unload_package"]
