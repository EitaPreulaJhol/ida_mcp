"""IDA Pro MCP Plugin.

This is the **plugin entry point** that IDA Pro loads.  It must define the
plugin class directly (with ``flags``, ``comment``, ``help``,
``wanted_name``, ``wanted_hotkey``) and ``PLUGIN_ENTRY`` at module level,
following the canonical pattern from ``ida-pro-mcp``.

The actual MCP server is in the ``ida_mcp`` package; we import
its controller lazily inside ``run()`` so this file is always importable
and the plugin class is always defined.
"""
import os
import sys
import traceback

# Make the package importable from the plugin file's location.
_PLUGIN_DIR = os.path.dirname(os.path.abspath(__file__))
if _PLUGIN_DIR not in sys.path:
    sys.path.insert(0, _PLUGIN_DIR)

# ---------------------------------------------------------------------------
# Try to import the plugin base class.  If the import fails (very old IDA,
# broken install, etc.) we fall back to a minimal stub so the plugin can
# still load and report the error to the user.
# ---------------------------------------------------------------------------
try:
    import idaapi
except ImportError:
    idaapi = None

_PLUGIN_KEEP = 1
if idaapi is not None:
    _PLUGIN_KEEP = getattr(idaapi, "PLUGIN_KEEP", 1)

# Plugin base class: inherit from idaapi.plugin_t if available, else use a
# bare class (this only matters when running in IDA; for tests we don't
# care about isinstance).
if idaapi is not None and hasattr(idaapi, "plugin_t"):
    _PluginBase = idaapi.plugin_t
else:
    class _PluginBase:
        pass


# ---------------------------------------------------------------------------
# UI hook helper — defers server autostart until the UI is fully ready.
# ---------------------------------------------------------------------------

try:
    import ida_kernwin
except ImportError:
    ida_kernwin = None


try:
    import ida_netnode
except ImportError:
    ida_netnode = None


# ---------------------------------------------------------------------------
# Persisted configuration (per-IDB, via netnodes — canonical ida-pro-mcp
# pattern). All helpers are no-ops when ida_netnode is unavailable (e.g.
# outside IDA), in which case defaults are used.
# ---------------------------------------------------------------------------

NETNODE_AUTOSTART = "$ ida_mcp.autostart"
NETNODE_CONFIG = "$ ida_mcp.config"
_ALT_PORT = 0  # altval index for the persisted port (0 = not set)
_ALT_PERSIST = 1  # altval index for the "save host/port" preference
_SUP_HOST = 0  # supval index for the persisted host


def _get_autostart() -> bool:
    """Read the autostart preference from the IDB. Defaults to True."""
    if ida_netnode is None:
        return True
    try:
        val = ida_netnode.netnode(NETNODE_AUTOSTART).altval(0)  # 0 = unset, 1 = off, 2 = on
    except Exception:
        return True
    return val != 1


def _set_autostart(enabled: bool) -> None:
    """Persist the autostart preference into the IDB."""
    if ida_netnode is None:
        return
    try:
        ida_netnode.netnode(NETNODE_AUTOSTART, 0, True).altset(0, 2 if enabled else 1)
    except Exception:
        pass


def _get_port(default: int) -> int:
    """Read the persisted server port from the IDB. Defaults to ``default``."""
    if ida_netnode is None:
        return default
    try:
        val = ida_netnode.netnode(NETNODE_CONFIG).altval(_ALT_PORT)  # 0 = unset
    except Exception:
        return default
    return val if val != 0 else default


def _set_port(port: int) -> None:
    """Persist the server port into the IDB."""
    if ida_netnode is None:
        return
    try:
        ida_netnode.netnode(NETNODE_CONFIG, 0, True).altset(_ALT_PORT, port)
    except Exception:
        pass


def _get_host(default: str) -> str:
    """Read the persisted server host from the IDB. Defaults to ``default``."""
    if ida_netnode is None:
        return default
    try:
        val = ida_netnode.netnode(NETNODE_CONFIG).supstr(_SUP_HOST)
    except Exception:
        return default
    return val if val else default


def _set_host(host: str) -> None:
    """Persist the server host into the IDB."""
    if ida_netnode is None:
        return
    try:
        ida_netnode.netnode(NETNODE_CONFIG, 0, True).supset(_SUP_HOST, host)
    except Exception:
        pass


def unload_package(package_name: str) -> None:
    """Remove every module belonging to ``package_name`` from ``sys.modules``.

    Manual hot-reload helper: call ``unload_package("ida_mcp")`` from the IDA
    console and then ``run(0)`` on the plugin to pick up edited sources
    without restarting IDA. Never called automatically (the running server
    holds references to the loaded modules).
    """
    to_remove = [
        mod_name
        for mod_name in sys.modules
        if mod_name == package_name or mod_name.startswith(package_name + ".")
    ]
    for mod_name in to_remove:
        del sys.modules[mod_name]


if ida_kernwin is not None:
    class MCPUIHooks(ida_kernwin.UI_Hooks):
        """Defers server autostart until the UI is fully ready."""

        def __init__(self, plugin):
            super().__init__()
            self.plugin = plugin

        def ready_to_run(self):
            if self.plugin.autostart and ida_kernwin.is_idaq():
                try:
                    self.plugin.run(0)
                except Exception as e:
                    try:
                        ida_kernwin.msg(
                            f"[ida-mcp] Server auto-start failed: {e}\n"
                        )
                    except Exception:
                        pass
            self.unhook()
else:
    class MCPUIHooks:
        def __init__(self, plugin):
            self.plugin = plugin

        def ready_to_run(self):
            pass

        def unhook(self):
            pass


# ---------------------------------------------------------------------------
# MCP server controller — imported lazily so this module loads even when
# the package has internal issues.
# ---------------------------------------------------------------------------

def _start_server(host, port):
    """Start the MCP server.  Imported lazily."""
    from ida_mcp.server import start_server
    start_server(host, port)


def _stop_server(port):
    """Stop the MCP server.  Imported lazily."""
    from ida_mcp.server import stop_server
    stop_server(port)


def _get_mcp_server():
    """Return the shared MCP_SERVER instance.  Imported lazily."""
    from ida_mcp.rpc import MCP_SERVER
    return MCP_SERVER


# ---------------------------------------------------------------------------
# Main plugin class — defined at module level with all required attributes.
# ---------------------------------------------------------------------------

class IdaMcp(_PluginBase):
    """IDA Pro MCP plugin."""

    flags = _PLUGIN_KEEP
    comment = "IDA MCP Plugin"
    help = "Bridges IDA Pro with AI coding agents via MCP"
    wanted_name = "IDA MCP"
    wanted_hotkey = "Ctrl-Shift-O"

    DEFAULT_HOST = "127.0.0.1"
    DEFAULT_PORT = 13337

    def init(self):
        if ida_kernwin is None:
            return self.flags
        self.host = _get_host(self.DEFAULT_HOST)
        self.port = _get_port(self.DEFAULT_PORT)
        self.autostart = _get_autostart()
        self.ui_hook = MCPUIHooks(self)
        try:
            ida_kernwin.install_ui_hook(self.ui_hook)
        except Exception:
            pass
        try:
            if ida_kernwin.is_idaq():
                print("[ida-mcp] Plugin loaded (idaq mode)")
            else:
                print("[ida-mcp] Plugin loaded (idalib mode)")
        except Exception:
            pass
        return self.flags

    def run(self, arg):
        if ida_kernwin is None:
            return
        try:
            mcp = _get_mcp_server()
        except Exception as e:
            try:
                ida_kernwin.msg(
                    f"[ida-mcp] Cannot load MCP server: {e}\n"
                )
            except Exception:
                pass
            return
        try:
            if getattr(mcp, "_running", False):
                _stop_server(self.port)
            else:
                _start_server(self.host, self.port)
                _set_host(self.host)
                _set_port(self.port)
                try:
                    ida_kernwin.msg(
                        f"[ida-mcp] listening on http://{self.host}:{self.port}/mcp"
                        f" (append ?unsafe=true for write tools)\n"
                    )
                except Exception:
                    pass
        except Exception as e:
            try:
                ida_kernwin.msg(
                    f"[ida-mcp] Server start/stop failed: {e}\n"
                    f"{traceback.format_exc()}\n"
                )
            except Exception:
                pass

    def term(self):
        if ida_kernwin is None:
            return
        try:
            _stop_server(self.port)
        except Exception:
            pass
        try:
            if getattr(self, "ui_hook", None) is not None:
                ida_kernwin.remove_ui_hook(self.ui_hook)
        except Exception:
            pass


# ---------------------------------------------------------------------------
# PLUGIN_ENTRY at module level — returns a real instance.
# ---------------------------------------------------------------------------

def PLUGIN_ENTRY():
    return IdaMcp()
