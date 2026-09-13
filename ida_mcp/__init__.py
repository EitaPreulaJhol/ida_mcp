"""IDA Pro MCP Plugin.

Architecture (aligned with ida-pro-mcp / idalib-mcp):
- zeromcp/: vendored MCP server over stdlib ThreadingHTTPServer (no uvicorn)
- sync.py: @idasync main-thread synchronization (result-container, no deadlock)
- rpc.py: tool/unsafe/ext decorators + MCP_SERVER registry
- api_python.py: IDA Python script execution
- api_analysis.py: analysis tools (lazy-loaded by server.py on first use)
- server.py: tool definitions + hosting
- plugin.py: IDA plugin entry point
"""
import signal

# Ignore SIGPIPE so the HTTP server writing a response doesn't kill IDA when a
# client disconnects mid-stream.
if hasattr(signal, "SIGPIPE"):
    try:
        signal.signal(signal.SIGPIPE, signal.SIG_IGN)
    except (ValueError, OSError):
        pass

# Import order is carefully chosen:
#   1. Core infrastructure (rpc, sync) — no IDA-version-specific imports.
#   2. api_python — depends only on rpc / sync.
#   3. plugin — depends on rpc only (server is lazy-imported inside
#      run/term/ready).  Loading plugin early guarantees PLUGIN_ENTRY is
#      always defined.
#   4. server — may fail to import (e.g. if an IDA module in api_analysis
#      is unavailable); the error is printed to the IDA message window
#      and the server's @tool functions are simply unavailable.
#
# server.py lazy-imports api_analysis.py, which triggers the @tool
# registrations for analysis tools as a side effect.
from . import rpc
from . import sync
from . import api_python
from . import plugin

try:
    from . import server
except Exception:
    import traceback
    import ida_kernwin
    ida_kernwin.msg(
        "[ida-mcp] WARNING: server module failed to import.\n"
        "Most analysis tools will be unavailable.\n"
        f"{traceback.format_exc()}\n"
    )

from .sync import idasync
from .rpc import MCP_SERVER, tool, unsafe

__all__ = [
    "rpc",
    "sync",
    "api_python",
    "server",
    "plugin",
    "idasync",
    "MCP_SERVER",
    "tool",
    "unsafe",
]
