"""MCP tool registration (ported from ida-pro-mcp rpc.py, trimmed)."""
from .zeromcp import McpServer, McpToolError

MCP_SERVER = McpServer("ida-mcp")
MCP_UNSAFE: set[str] = set()

# Link the unsafe-tool set back to the server so _mcp_tools_list and
# _mcp_tools_call can gate on it without a circular import.
MCP_SERVER.unsafe_tools = MCP_UNSAFE


def tool(func):
    return MCP_SERVER.tool(func)


def unsafe(func):
    MCP_UNSAFE.add(func.__name__)
    return func


def ext(group: str):
    """Mark a tool as belonging to an extension group (e.g. ``"dbg"``).

    Extension tools are hidden from ``tools/list`` and refused by
    ``tools/call`` unless the endpoint URL carries ``?ext=<group>``
    (parsed per-request into thread-local state). Combines with ``@unsafe``:
    debugger tools need ``?unsafe=true&ext=dbg``.
    """

    def decorator(func):
        MCP_SERVER._extensions_registry.setdefault(group, set()).add(func.__name__)
        return func

    return decorator


__all__ = ["MCP_SERVER", "MCP_UNSAFE", "tool", "unsafe", "ext", "McpToolError"]
