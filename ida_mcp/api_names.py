"""Name management tools for ida_mcp.

Centralizes all naming operations (the canonical ``set_name`` plus query,
validation, demangling, visibility flags and bulk enumeration). Ported from
idamcp-extendedtools ``api_names.py``, adapted for direct in-process IDA SDK
access.

Compatibility note: ``rename_function`` (api_analysis), ``set_function_name``
(api_functions) and ``rename_address`` (api_modify) are kept as aliases for
backwards compatibility; new workflows should use ``set_name`` here.
"""
import fnmatch
import json
import re

import ida_auto
import ida_name
import idaapi
import idautils

from .rpc import tool, unsafe
from .sync import idasync
from .api_analysis import parse_addr


_VALID_NAME_RE = re.compile(r"^[A-Za-z_?$][\w?$@#]*$")


def _demangle(name: str) -> str | None:
    """Demangle ``name``; return None when it is not mangled / on failure."""
    try:
        dem = ida_name.demangle_name(name)
    except TypeError:
        try:
            dem = ida_name.demangle_name(name, 0)
        except Exception:
            return None
    except Exception:
        return None
    if not dem or dem == name:
        return None
    return dem


# ===========================================================================
# Tools — query
# ===========================================================================


@tool
@idasync
def get_name(address: str) -> str:
    """Get the name at the given address (function, data, or auto-generated)."""
    ida_auto.auto_wait()
    try:
        ea = parse_addr(address)
    except ValueError as e:
        return json.dumps({"error": str(e)})

    name = ida_name.get_ea_name(ea)
    demangled = _demangle(name) if name else None
    return json.dumps({
        "addr": hex(ea),
        "name": name or None,
        "demangled": demangled,
    })


@tool
@idasync
def get_all_names(filter_pattern: str = "*", offset: int = 0, count: int = 100) -> str:
    """List all names in the IDB with glob filtering and pagination."""
    ida_auto.auto_wait()

    if count <= 0 or count > 5000:
        count = 100

    names_list: list[dict] = []
    for ea, name in idautils.Names():
        if name and (filter_pattern == "*" or fnmatch.fnmatch(name, filter_pattern)):
            names_list.append({"addr": hex(ea), "name": name})

    page = names_list[offset:offset + count]
    return json.dumps({
        "data": page,
        "total": len(names_list),
        "offset": offset,
        "count": len(page),
    }, indent=2)


@tool
@idasync
def get_demangled_name(address: str) -> str:
    """Get the demangled (human-readable) name at the given address."""
    ida_auto.auto_wait()
    try:
        ea = parse_addr(address)
    except ValueError as e:
        return json.dumps({"error": str(e)})

    name = ida_name.get_ea_name(ea)
    if not name:
        return json.dumps({"addr": hex(ea), "name": None, "demangled": None})
    return json.dumps({
        "addr": hex(ea),
        "name": name,
        "demangled": _demangle(name),
    })


@tool
@idasync
def demangle_name(name: str) -> str:
    """Demangle a mangled symbol string (e.g. ``_Z3foov`` → ``foo()``)."""
    ida_auto.auto_wait()
    return json.dumps({"name": name, "demangled": _demangle(name)})


@tool
@idasync
def validate_name(name: str) -> str:
    """Validate a candidate IDA name (syntax heuristic).

    Returns ``valid`` plus a ``reason`` when invalid. Mirrors the IDA
    restrictions: must start with a letter, ``_``, ``?`` or ``$`` and contain
    only word characters plus ``?``, ``$``, ``@``, ``#``.
    """
    if not name:
        return json.dumps({"name": name, "valid": False, "reason": "empty name"})
    if len(name) > 1024:
        return json.dumps({"name": name, "valid": False, "reason": "name too long (>1024)"})
    if not _VALID_NAME_RE.match(name):
        return json.dumps({"name": name, "valid": False, "reason": "invalid characters or start"})
    return json.dumps({"name": name, "valid": True, "reason": None})


@tool
@idasync
def is_name_public(address: str) -> str:
    """Check if the name at the given address is public (exported/global)."""
    ida_auto.auto_wait()
    try:
        ea = parse_addr(address)
    except ValueError as e:
        return json.dumps({"error": str(e)})

    try:
        public = bool(ida_name.is_public_name(ea))
    except Exception as e:
        return json.dumps({"error": str(e)})
    return json.dumps({
        "addr": hex(ea),
        "name": ida_name.get_ea_name(ea) or None,
        "is_public": public,
    })


@tool
@idasync
def is_name_weak(address: str) -> str:
    """Check if the name at the given address is weak."""
    ida_auto.auto_wait()
    try:
        ea = parse_addr(address)
    except ValueError as e:
        return json.dumps({"error": str(e)})

    try:
        weak = bool(ida_name.is_weak_name(ea))
    except Exception as e:
        return json.dumps({"error": str(e)})
    return json.dumps({
        "addr": hex(ea),
        "name": ida_name.get_ea_name(ea) or None,
        "is_weak": weak,
    })


# ===========================================================================
# Tools — modification (unsafe)
# ===========================================================================


@tool
@idasync
@unsafe
def set_name(address: str, name: str) -> str:
    """Set a name at the given address (canonical rename tool).

    **Unsafe** — requires ``?unsafe=true``. Works for functions, data items
    and any other address. Use ``force_name`` when the name already exists
    elsewhere, ``validate_name`` to pre-check syntax.
    """
    ida_auto.auto_wait()
    try:
        ea = parse_addr(address)
    except ValueError as e:
        return json.dumps({"error": str(e)})

    old_name = ida_name.get_ea_name(ea)
    try:
        ok = ida_name.set_name(ea, name, ida_name.SN_NOWARN)
    except Exception as e:
        return json.dumps({"error": str(e)})
    if not ok:
        return json.dumps({
            "error": f"Failed to set name {name!r} at {hex(ea)} "
                     f"(name may already exist — try force_name)",
        })
    return json.dumps({
        "addr": hex(ea),
        "old_name": old_name or None,
        "new_name": name,
    })


@tool
@idasync
@unsafe
def force_name(address: str, name: str) -> str:
    """Force-set a name, auto-generating ``name_0``-style variants on collision.

    **Unsafe** — requires ``?unsafe=true``.
    """
    ida_auto.auto_wait()
    try:
        ea = parse_addr(address)
    except ValueError as e:
        return json.dumps({"error": str(e)})

    old_name = ida_name.get_ea_name(ea)
    try:
        ok = ida_name.force_name(ea, name)
    except Exception as e:
        return json.dumps({"error": str(e)})
    if not ok:
        return json.dumps({"error": f"Failed to force name {name!r} at {hex(ea)}"})
    return json.dumps({
        "addr": hex(ea),
        "old_name": old_name or None,
        "new_name": ida_name.get_ea_name(ea) or name,
    })


@tool
@idasync
@unsafe
def delete_name(address: str) -> str:
    """Delete the user-defined name at the given address.

    **Unsafe** — requires ``?unsafe=true``.
    """
    ida_auto.auto_wait()
    try:
        ea = parse_addr(address)
    except ValueError as e:
        return json.dumps({"error": str(e)})

    old_name = ida_name.get_ea_name(ea)
    try:
        ida_name.del_name(ea)
    except Exception as e:
        return json.dumps({"error": str(e)})
    return json.dumps({
        "ok": True,
        "addr": hex(ea),
        "old_name": old_name or None,
        "current_name": ida_name.get_ea_name(ea) or None,
    })


@tool
@idasync
@unsafe
def make_name_public(address: str) -> str:
    """Mark the name at the given address as public.

    **Unsafe** — requires ``?unsafe=true``.
    """
    ida_auto.auto_wait()
    try:
        ea = parse_addr(address)
    except ValueError as e:
        return json.dumps({"error": str(e)})

    try:
        ida_name.make_name_public(ea)
    except Exception as e:
        return json.dumps({"error": str(e)})
    return json.dumps({
        "ok": True,
        "addr": hex(ea),
        "name": ida_name.get_ea_name(ea) or None,
    })


@tool
@idasync
@unsafe
def make_name_non_public(address: str) -> str:
    """Mark the name at the given address as non-public.

    **Unsafe** — requires ``?unsafe=true``.
    """
    ida_auto.auto_wait()
    try:
        ea = parse_addr(address)
    except ValueError as e:
        return json.dumps({"error": str(e)})

    try:
        ida_name.make_name_non_public(ea)
    except Exception as e:
        return json.dumps({"error": str(e)})
    return json.dumps({
        "ok": True,
        "addr": hex(ea),
        "name": ida_name.get_ea_name(ea) or None,
    })


__all__ = [
    "get_name",
    "get_all_names",
    "get_demangled_name",
    "demangle_name",
    "validate_name",
    "is_name_public",
    "is_name_weak",
    "set_name",
    "force_name",
    "delete_name",
    "make_name_public",
    "make_name_non_public",
]
