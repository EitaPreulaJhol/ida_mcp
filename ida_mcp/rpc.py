"""MCP tool registration (ported from ida-pro-mcp rpc.py, trimmed)."""
from typing import Any, Callable, TypeVar, cast

from .zeromcp import McpServer, McpToolError


_F = TypeVar("_F", bound=Callable[..., Any])

MCP_SERVER = McpServer("ida-mcp")
MCP_UNSAFE: set[str] = set()

# Link the unsafe-tool set back to the server so _mcp_tools_list and
# _mcp_tools_call can gate on it without a circular import.
MCP_SERVER.unsafe_tools = MCP_UNSAFE


def tool(func: _F) -> _F:
    return cast(_F, MCP_SERVER.tool(func))


def unsafe(func: _F) -> _F:
    MCP_UNSAFE.add(func.__name__)
    return func


def report_progress(
    progress: int | float,
    total: int | float | None = None,
    message: str | None = None,
) -> bool:
    """Publish MCP progress for the current tool call (no-op without a token)."""
    return MCP_SERVER.report_progress(progress, total=total, message=message)


def ext(group: str) -> Callable[[_F], _F]:
    """Mark a tool as belonging to an extension group (e.g. ``"dbg"``).

    Extension tools are hidden from ``tools/list`` and refused by
    ``tools/call`` unless the endpoint URL carries ``?ext=<group>``
    (parsed per-request into thread-local state). Combines with ``@unsafe``:
    debugger tools need ``?unsafe=true&ext=dbg``.
    """

    def decorator(func: _F) -> _F:
        MCP_SERVER._extensions_registry.setdefault(group, set()).add(func.__name__)
        return func

    return decorator


__all__ = ["MCP_SERVER", "MCP_UNSAFE", "tool", "unsafe", "ext", "report_progress", "McpToolError"]
