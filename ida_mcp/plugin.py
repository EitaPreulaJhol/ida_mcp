"""Backwards-compat re-exports.

The actual plugin class lives in ``ida_mcp_loader.py`` (so IDA
Pro can load it directly).  This module re-exports the symbols so any
existing import path (``from ida_mcp.plugin import PLUGIN_ENTRY``)
continues to work.
"""
try:
    from ida_mcp_loader import IdaMcp, PLUGIN_ENTRY
except Exception:
    # Last-resort emergency stub.  If even the loader can't be imported,
    # define a minimal inline plugin so PLUGIN_ENTRY always exists.
    PLUGIN_KEEP = 1

    class IdaMcp:
        flags = PLUGIN_KEEP
        comment = "IDA MCP Plugin (EMERGENCY)"
        help = "Plugin loaded in emergency stub mode."
        wanted_name = "IDA MCP"
        wanted_hotkey = ""

        def init(self):
            return self.flags

        def run(self, arg):
            pass

        def term(self):
            pass

    def PLUGIN_ENTRY():
        return IdaMcp()


__all__ = ["IdaMcp", "PLUGIN_ENTRY"]
