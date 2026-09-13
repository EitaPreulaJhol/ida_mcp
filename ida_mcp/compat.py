"""IDA version compatibility shims (cf. idamcp-extendedtools compat.py).

Centralizes every IDA-version-dependent access so the plugin runs on
IDA 8.3+ while using the IDA 9.x APIs when available:

- ``idaapi.BADADDR`` (IDA 9.3 removed ``ida_ida.BADADDR``)
- ``ida_ida.inf_get_min_ea()`` / ``inf_get_max_ea()`` (replaced ``cvar.inf``)
- ``ida_bytes.is_loaded`` (absent on very old versions)
- entry-point enumeration (moved to ``ida_entry``)

No ``ida_mcp`` imports here — only ``ida_*`` — so this module can be
imported first and exec'd standalone in tests with stubbed IDA modules.
"""
import re

try:
    import ida_ida
except ImportError:
    ida_ida = None

try:
    import ida_entry
except ImportError:
    ida_entry = None

try:
    import ida_bytes
except ImportError:
    ida_bytes = None

try:
    import idaapi
except ImportError:
    idaapi = None


IDA_VERSION: str | None = None
IDA_MAJOR: int = 0
IDA_MINOR: int = 0


def _parse_kernel_version(v: str) -> tuple[int, int, int]:
    # Parse formats like "9.3", "9.2.0", "9.2sp1".
    nums = [int(x) for x in re.findall(r"\d+", v or "")]
    major = nums[0] if len(nums) > 0 else 0
    minor = nums[1] if len(nums) > 1 else 0
    patch = nums[2] if len(nums) > 2 else 0
    return (major, minor, patch)


def detect_ida_version() -> str:
    """Detect the current IDA Pro version (cached in IDA_MAJOR/IDA_MINOR)."""
    global IDA_VERSION, IDA_MAJOR, IDA_MINOR
    ver = "0.0"
    if ida_ida is not None:
        try:
            ver = ida_ida.get_kernel_version() or ver
        except Exception:
            pass
    IDA_VERSION = ver
    IDA_MAJOR, IDA_MINOR, _ = _parse_kernel_version(ver)
    return ver


def is_ida_available() -> bool:
    """Check if IDA Pro modules are importable (running inside IDA)."""
    return ida_ida is not None


def is_ida_ge(major: int, minor: int = 0) -> bool:
    """Check if the IDA version is >= ``major.minor``."""
    if IDA_MAJOR == 0:
        detect_ida_version()
    return (IDA_MAJOR, IDA_MINOR) >= (major, minor)


def is_ida_lt(major: int, minor: int = 0) -> bool:
    """Check if the IDA version is < ``major.minor``."""
    if IDA_MAJOR == 0:
        detect_ida_version()
    return (IDA_MAJOR, IDA_MINOR) < (major, minor)


# ---------------------------------------------------------------------------
# Address / range helpers
# ---------------------------------------------------------------------------

def badaddr() -> int:
    """BADADDR across versions (``ida_ida.BADADDR`` was removed in IDA 9.3)."""
    if idaapi is not None and hasattr(idaapi, "BADADDR"):
        return idaapi.BADADDR
    if ida_bytes is not None and hasattr(ida_bytes, "BADADDR"):
        return ida_bytes.BADADDR
    return 0xFFFFFFFFFFFFFFFF


def inf_get_min_ea() -> int:
    """Image low address (``cvar.inf.min_ea`` was removed in IDA 9.3)."""
    if ida_ida is not None:
        for attr in ("inf_get_min_ea",):
            fn = getattr(ida_ida, attr, None)
            if callable(fn):
                try:
                    return fn()
                except Exception:
                    pass
    if idaapi is not None:
        cvar = getattr(idaapi, "cvar", None)
        inf = getattr(cvar, "inf", None)
        for attr in ("min_ea", "mine_ea"):
            val = getattr(inf, attr, None)
            if isinstance(val, int):
                return val
    return 0


def inf_get_max_ea() -> int:
    """Image high address (``cvar.inf.max_ea`` was removed in IDA 9.3)."""
    if ida_ida is not None:
        fn = getattr(ida_ida, "inf_get_max_ea", None)
        if callable(fn):
            try:
                return fn()
            except Exception:
                pass
    if idaapi is not None:
        cvar = getattr(idaapi, "cvar", None)
        inf = getattr(cvar, "inf", None)
        val = getattr(inf, "max_ea", None)
        if isinstance(val, int):
            return val
    return 0


def inf_is_64bit() -> bool:
    """True when the database is 64-bit."""
    if ida_ida is not None:
        fn = getattr(ida_ida, "inf_is_64bit", None)
        if callable(fn):
            try:
                return bool(fn())
            except Exception:
                pass
    if idaapi is not None:
        get_inf = getattr(idaapi, "get_inf_structure", None)
        if callable(get_inf):
            try:
                return bool(get_inf().is_64bit())
            except Exception:
                pass
    return False


def get_imagebase() -> int:
    """Image base address."""
    if idaapi is not None:
        fn = getattr(idaapi, "get_imagebase", None)
        if callable(fn):
            try:
                return fn()
            except Exception:
                pass
    return 0


def is_loaded(ea: int) -> bool:
    """True when ``ea`` has a loaded value (False for BSS/unloaded bytes).

    Falls back to ``is_mapped`` on IDA versions without
    ``ida_bytes.is_loaded``.
    """
    if ida_bytes is not None:
        fn = getattr(ida_bytes, "is_loaded", None)
        if callable(fn):
            try:
                return bool(fn(ea))
            except Exception:
                pass
        mapped = getattr(ida_bytes, "is_mapped", None)
        if callable(mapped):
            try:
                return bool(mapped(ea))
            except Exception:
                pass
    return False


# ---------------------------------------------------------------------------
# Function names
# ---------------------------------------------------------------------------

def get_func_name(ea: int) -> str | None:
    """Function name at ``ea`` (``ida_funcs`` with ``idaapi`` fallback)."""
    try:
        import ida_funcs
        fn = getattr(ida_funcs, "get_func_name", None)
        if callable(fn):
            return fn(ea)
    except ImportError:
        pass
    if idaapi is not None:
        fn = getattr(idaapi, "get_func_name", None)
        if callable(fn):
            try:
                return fn(ea)
            except Exception:
                pass
    return None


# ---------------------------------------------------------------------------
# Entry points (moved to ida_entry on modern IDA)
# ---------------------------------------------------------------------------

def get_entry_qty() -> int:
    for mod in (ida_entry, idaapi):
        if mod is not None:
            fn = getattr(mod, "get_entry_qty", None)
            if callable(fn):
                try:
                    return int(fn())
                except Exception:
                    pass
    return 0


def get_entry_ordinal(idx: int) -> int:
    for mod in (ida_entry, idaapi):
        if mod is not None:
            fn = getattr(mod, "get_entry_ordinal", None)
            if callable(fn):
                try:
                    return int(fn(idx))
                except Exception:
                    pass
    return -1


def get_entry(ordinal: int) -> int:
    for mod in (ida_entry, idaapi):
        if mod is not None:
            fn = getattr(mod, "get_entry", None)
            if callable(fn):
                try:
                    return int(fn(ordinal))
                except Exception:
                    pass
    return badaddr()


def get_entry_name(ordinal: int) -> str:
    for mod in (ida_entry, idaapi):
        if mod is not None:
            fn = getattr(mod, "get_entry_name", None)
            if callable(fn):
                try:
                    return fn(ordinal) or ""
                except Exception:
                    pass
    return ""


__all__ = [
    "IDA_VERSION",
    "IDA_MAJOR",
    "IDA_MINOR",
    "detect_ida_version",
    "is_ida_available",
    "is_ida_ge",
    "is_ida_lt",
    "badaddr",
    "inf_get_min_ea",
    "inf_get_max_ea",
    "inf_is_64bit",
    "get_imagebase",
    "is_loaded",
    "get_func_name",
    "get_entry_qty",
    "get_entry_ordinal",
    "get_entry",
    "get_entry_name",
]
