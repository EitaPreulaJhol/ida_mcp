"""IDA version compatibility shims (cf. idamcp-extendedtools compat.py).

Centralizes every IDA-version-dependent access so the plugin runs on
IDA 8.3+ while using the IDA 9.x APIs when available:

- ``idaapi.BADADDR`` (IDA 9.3 removed ``ida_ida.BADADDR``)
- ``ida_ida.inf_get_min_ea()`` / ``inf_get_max_ea()`` (replaced ``cvar.inf``)
- ``ida_bytes.is_loaded`` (absent on very old versions)
- entry-point enumeration (moved to ``ida_entry``)
- ``ida_typeinf.get_ordinal_limit`` (IDA 9.4 renamed ``get_ordinal_qty``)
- ``ida_name.del_global_name()`` / ``del_local_name()`` (IDA 9.4 removed
  ``ida_name.del_name``)
- ``ida_funcs.FUNC_STATICDEF`` (IDA 9.4 renamed ``FUNC_STATIC``)
- ``ida_typeinf.get_cc_name`` / ``func_type_data_t.cc`` (IDA 9.4 exposes
  ``func_type_data_t.get_cc()`` only)
- ``ida_frame.get_func_frame`` (IDA 9.4 removed ``frame_t``/``get_frame``)
- ``ida_bytes.get_original_bytes``, ``ida_lines.get_extra_cmt_qty``,
  ``ida_segment.get_segm_cmt``, ``ida_ua.get_reg_name`` (removed or moved in
  IDA 9.4)

No ``ida_mcp`` imports here — only ``ida_*`` — so this module can be
imported first and exec'd standalone in tests with stubbed IDA modules.
"""
import re
import warnings


# ---------------------------------------------------------------------------
# Deprecation-warning suppression (IDA 9.x)
# ---------------------------------------------------------------------------
# IDA 9.x (9.4+) emits Python DeprecationWarnings for several core accessors
# that are still fully functional and that this plugin -- and the IDAPython
# scripts it runs -- rely on heavily:
#     get_func()      -> "use get_func_start or get_func_entry_info()"
#     getseg()        -> "use get_segment_info()"
#     get_segm_name() -> "use get_segment_name()"
# The suggested replacements are NOT drop-in (e.g. get_func_start returns an
# ea_t, not the func_t whose .flags/.start_ea/.end_ea we need), so we keep the
# proven accessors -- centralized in the wrappers below -- and silence just
# these specific, benign warnings instead of spamming every tool's output.
#
# Filtering by message keeps it narrow (unrelated deprecations still surface)
# and installing it once at import means zero per-call cost in hot loops
# (survey_binary touches every function).
_SILENCED_DEPRECATIONS = (
    r"get_func\(\) is deprecated",
    r"getseg\(\) is deprecated",
    r"get_segm_name\(\) is deprecated",
    # Emitted by idautils' own helpers (Functions/FuncItems), not by our
    # call sites: IDA 9.5 deprecated the iterator types they build on.
    r"get_next_func\(\) is deprecated",
    r"func_item_iterator_t is deprecated",
)


def silence_known_deprecations() -> None:
    """Install (idempotent) filters for the benign IDA 9.x deprecations in
    ``_SILENCED_DEPRECATIONS``. Prepended, so they win over any 'always'
    filter IDA may have installed."""
    for pattern in _SILENCED_DEPRECATIONS:
        warnings.filterwarnings(
            "ignore", message=pattern, category=DeprecationWarning)


silence_known_deprecations()


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
    import ida_frame
except ImportError:
    ida_frame = None

try:
    import ida_funcs
except ImportError:
    ida_funcs = None

try:
    import ida_idp
except ImportError:
    ida_idp = None

try:
    import ida_lines
except ImportError:
    ida_lines = None

try:
    import ida_name
except ImportError:
    ida_name = None

try:
    import ida_segment
except ImportError:
    ida_segment = None

try:
    import ida_typeinf
except ImportError:
    ida_typeinf = None

try:
    import ida_ua
except ImportError:
    ida_ua = None

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
    # ida_ida carried get_kernel_version() up to 9.3; 9.4 only has the idaapi one.
    for mod in (ida_ida, idaapi):
        getter = getattr(mod, "get_kernel_version", None) if mod is not None else None
        if not callable(getter):
            continue
        try:
            found = getter() or ""
        except Exception:
            found = ""
        if found:
            ver = found
            break
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
    # Pre-9.3 fallback: ida_ida carried BADADDR before it was removed there.
    if ida_ida is not None and hasattr(ida_ida, "BADADDR"):
        return ida_ida.BADADDR
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

# ---------------------------------------------------------------------------
# Function / segment accessors (deprecation-free; see silence_known_deprecations)
# ---------------------------------------------------------------------------

def get_func(ea: int):
    """``func_t`` containing ``ea`` (or ``None``).

    Thin wrapper over ``ida_funcs.get_func`` so the IDA 9.x deprecation is
    centralized in one place. The suggested replacements (``get_func_start`` /
    ``get_func_entry_info``) don't return a ``func_t`` -- callers need
    ``.flags`` / ``.start_ea`` / ``.end_ea`` -- so the classic accessor stays
    and its (benign) warning is silenced at import.
    """
    if ida_funcs is None:
        return None
    return ida_funcs.get_func(ea)


def getseg(ea: int):
    """``segment_t`` containing ``ea`` (or ``None``); ``ida_segment`` with an
    ``idaapi`` fallback."""
    for mod in (ida_segment, idaapi):
        fn = getattr(mod, "getseg", None) if mod is not None else None
        if callable(fn):
            try:
                return fn(ea)
            except Exception:
                return None
    return None


def get_segm_name(seg) -> str:
    """Name of segment ``seg`` ("" if unavailable)."""
    if ida_segment is not None:
        fn = getattr(ida_segment, "get_segm_name", None)
        if callable(fn):
            try:
                return fn(seg) or ""
            except Exception:
                return ""
    return ""


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
# Names (ida_name.del_name was split in IDA 9.4)
# ---------------------------------------------------------------------------

def del_name(ea: int) -> bool:
    """Delete the name at ``ea``, whatever its scope (global or local).

    IDA 9.4 removed ``ida_name.del_name`` and exposed the two name lists it
    used to dispatch to: ``del_global_name`` (global list) and
    ``del_local_name`` (lists owned by the enclosing function). Both are
    attempted because each is a no-op for names living in the other list, and
    on 9.4 they report success even when there was nothing to delete — so
    callers must read the name back to know what really happened (cf. the
    ``delete_name`` tool). Older IDAs keep the single ``del_name`` call.
    """
    if ida_name is None:
        return False
    removed = False
    for fn_name in ("del_global_name", "del_local_name"):
        fn = getattr(ida_name, fn_name, None)
        if not callable(fn):
            continue
        try:
            if fn(ea):
                removed = True
        except Exception:
            continue
    if removed:
        return True
    legacy = getattr(ida_name, "del_name", None)
    if callable(legacy):
        try:
            return bool(legacy(ea))
        except Exception:
            pass
    return False


# ---------------------------------------------------------------------------
# Type library ordinals (get_ordinal_qty was renamed in IDA 9.4)
# ---------------------------------------------------------------------------

# uint32(-1) is the "ordinals are not enabled for this til" sentinel; any
# bound that large must never drive an enumeration loop.
_ORDINAL_LIMIT_MAX = 0x1000000


def get_type_ordinal_limit(til=None) -> int:
    """Exclusive upper bound for enumerating ``til``'s type ordinals.

    IDA 9.4 renamed ``ida_typeinf.get_ordinal_qty`` to ``get_ordinal_limit``
    (allocated ordinals + 1) and added ``get_ordinal_count``. IDA's own
    documentation for ``get_ordinal_limit`` says to enumerate with
    ``for ( uint32 i = 1; i < limit; ++i )`` — hence the exclusive bound::

        for ordinal in range(1, get_type_ordinal_limit(til)):
            ...

    Returns 0 when the til has no ordinals at all, so such loops do not run.
    """
    if ida_typeinf is None:
        return 0
    limit_fn = getattr(ida_typeinf, "get_ordinal_limit", None)
    if callable(limit_fn):
        try:
            limit = int(limit_fn(til))
        except Exception:
            limit = 0
        if 1 <= limit <= _ORDINAL_LIMIT_MAX:
            return limit
    count_fn = getattr(ida_typeinf, "get_ordinal_count", None)
    if callable(count_fn):
        try:
            return int(count_fn(til)) + 1
        except Exception:
            pass
    legacy = getattr(ida_typeinf, "get_ordinal_qty", None)
    if callable(legacy):
        try:
            return int(legacy(til))
        except Exception:
            pass
    return 0


# ---------------------------------------------------------------------------
# Function flags (FUNC_STATIC was renamed in IDA 9.4)
# ---------------------------------------------------------------------------

# ``FUNC_STATIC`` was renamed to ``FUNC_STATICDEF`` ("static function").
FUNC_STATIC: int = getattr(ida_funcs, "FUNC_STATIC", 0) or getattr(ida_funcs, "FUNC_STATICDEF", 0)


# ---------------------------------------------------------------------------
# Calling conventions (ida_typeinf.get_cc_name is gone in IDA 9.4)
# ---------------------------------------------------------------------------

# CM_CC_* value -> name, as reported by the removed get_cc_name().
_CC_NAMES = {
    "CM_CC_INVALID": "invalid",
    "CM_CC_UNKNOWN": "unknown",
    "CM_CC_VOIDARG": "voidarg",
    "CM_CC_CDECL": "cdecl",
    "CM_CC_ELLIPSIS": "ellipsis",
    "CM_CC_STDCALL": "stdcall",
    "CM_CC_PASCAL": "pascal",
    "CM_CC_FASTCALL": "fastcall",
    "CM_CC_THISCALL": "thiscall",
    "CM_CC_SWIFT": "swift",
    "CM_CC_GOLANG": "golang",
    "CM_CC_SPECIALE": "special",
    "CM_CC_SPECIALP": "special",
    "CM_CC_SPECIAL": "special",
    "CM_CC_GOSTK": "gostk",
    "CM_CC_RUST": "rust",
}


def get_func_cc(ftd) -> int | None:
    """Calling convention (a CM_CC_* value) of a ``func_type_data_t``.

    IDA 9.4 replaced the ``cc`` attribute with ``get_cc()``.
    """
    getter = getattr(ftd, "get_cc", None)
    if callable(getter):
        try:
            return int(getter())
        except Exception:
            pass
    try:
        return int(ftd.cc)
    except Exception:
        return None


def get_cc_name(cc: int | None) -> str | None:
    """Name of the calling convention ``cc`` (None in, None out).

    ``ida_typeinf.get_cc_name`` was removed in IDA 9.4: the type system only
    exposes the numeric value, so the CM_CC_* constants are mapped here.
    """
    if cc is None:
        return None
    if ida_typeinf is not None:
        legacy = getattr(ida_typeinf, "get_cc_name", None)
        if callable(legacy):
            try:
                name = legacy(cc)
            except Exception:
                name = None
            if name:
                return name
        for const_name, label in _CC_NAMES.items():
            if getattr(ida_typeinf, const_name, None) == cc:
                return label
        usercall = getattr(ida_typeinf, "CM_CC_LAST_USERCALL", None)
        if usercall is not None and cc <= usercall:
            return "usercall"
    return "unknown(0x%X)" % cc


# ---------------------------------------------------------------------------
# Stack frames (IDA 9.4 removed frame_t / ida_frame.get_frame)
# ---------------------------------------------------------------------------

def _func_ea(pfn) -> int | None:
    """``pfn.start_ea`` when ``pfn`` looks like a ``func_t``, else None."""
    ea = getattr(pfn, "start_ea", None)
    return ea if isinstance(ea, int) else None


def get_frame_tinfo(pfn):
    """Stack frame of ``pfn`` as a ``tinfo_t``, or None when it has none.

    IDA 9.4 replaced ``frame_t`` with the ``struct __fixed(...)`` type built by
    ``get_func_frame``; its members expose ``name``, ``offset`` (frame offset in
    bits), ``size`` and ``type``. 9.5 deprecated the ``func_t`` form in favour
    of ``get_func_frame_ea``, so the address variant is preferred.
    """
    if ida_frame is None or ida_typeinf is None:
        return None
    tif = ida_typeinf.tinfo_t()
    ea = _func_ea(pfn)
    getter_ea = getattr(ida_frame, "get_func_frame_ea", None)
    if callable(getter_ea) and ea is not None:
        try:
            return tif if getter_ea(tif, ea) else None
        except Exception:
            return None
    getter = getattr(ida_frame, "get_func_frame", None)
    if not callable(getter):
        return None
    try:
        if not getter(tif, pfn):
            return None
    except Exception:
        return None
    return tif


def frame_udt_members(tif) -> list[dict]:
    """Snapshot of a frame tinfo's members: ``name``/``offset``/``size``/``type``.

    ``offset``/``size`` are in bytes (``udm_t`` stores bits) and ``type`` is a
    copy of the member tinfo. Everything is read while the
    ``udt_type_data_t`` is alive on purpose: its entries reference storage owned
    by that vector, so a detached entry reads back empty names and types.
    """
    if ida_typeinf is None or tif is None:
        return []
    udt = ida_typeinf.udt_type_data_t()
    try:
        if not tif.get_udt_details(udt):
            return []
    except Exception:
        return []
    out: list[dict] = []
    for m in udt:
        mtype = None
        if m.type is not None:
            try:
                mtype = ida_typeinf.tinfo_t(m.type)
            except Exception:
                mtype = None
        out.append({
            "name": m.name or "",
            "offset": int(m.offset) // 8,
            "size": int(m.size) // 8 if m.size else 0,
            "type": mtype,
        })
    return out


def frame_soff(pfn, frameoff: int) -> int:
    """Classic (fp-relative) frame offset for a frame-tinfo offset.

    ``soff_to_fpoff`` converts a struct offset into the fp-relative offset the
    stack-frame window (and the old ``frame_t``) used: negative for locals, 0 at
    the return address, positive for arguments. 9.5 deprecated the ``func_t``
    form in favour of ``soff_to_fpoff_ea``.
    """
    if ida_frame is not None:
        ea = _func_ea(pfn)
        fn_ea = getattr(ida_frame, "soff_to_fpoff_ea", None)
        if callable(fn_ea) and ea is not None:
            try:
                return int(fn_ea(ea, frameoff))
            except Exception:
                pass
        fn = getattr(ida_frame, "soff_to_fpoff", None)
        if callable(fn):
            try:
                return int(fn(pfn, frameoff))
            except Exception:
                pass
    return frameoff


def is_frame_arg(pfn, frameoff: int) -> bool:
    """True when ``frameoff`` (a frame-tinfo offset) belongs to the arguments."""
    if ida_frame is not None:
        ea = _func_ea(pfn)
        fn_ea = getattr(ida_frame, "is_funcarg_off_ea", None)
        if callable(fn_ea) and ea is not None:
            try:
                return bool(fn_ea(ea, frameoff))
            except Exception:
                pass
        fn = getattr(ida_frame, "is_funcarg_off", None)
        if callable(fn):
            try:
                return bool(fn(pfn, frameoff))
            except Exception:
                pass
    return False


def get_frame_size(pfn) -> int:
    """Full stack-frame size of ``pfn`` in bytes (0 when it has no frame).

    ``ida_frame.get_frame_size`` was deprecated in 9.5; ``get_frame_size_ea``
    takes the function address instead.
    """
    if ida_frame is None:
        return 0
    ea = _func_ea(pfn)
    fn_ea = getattr(ida_frame, "get_frame_size_ea", None)
    if callable(fn_ea) and ea is not None:
        try:
            return int(fn_ea(ea))
        except Exception:
            pass
    fn = getattr(ida_frame, "get_frame_size", None)
    if callable(fn):
        try:
            return int(fn(pfn))
        except Exception:
            pass
    return 0


def get_func_comment(pfn, repeatable: bool = False) -> str | None:
    """Comment of ``pfn`` (``get_func_cmt`` was deprecated in 9.5).

    ``get_func_cmt_ea`` takes the function address; the ``func_t`` form is the
    fallback for older bindings.
    """
    if ida_funcs is None or pfn is None:
        return None
    ea = _func_ea(pfn)
    fn_ea = getattr(ida_funcs, "get_func_cmt_ea", None)
    if callable(fn_ea) and ea is not None:
        try:
            return fn_ea(ea, repeatable)
        except Exception:
            pass
    fn = getattr(ida_funcs, "get_func_cmt", None)
    if callable(fn):
        try:
            return fn(pfn, repeatable)
        except Exception:
            pass
    return None


def get_func_regvars(ea: int) -> list:
    """Register variables (``regvar_t``) of the function at ``ea``."""
    if ida_frame is None:
        return []
    qty_fn = getattr(ida_frame, "get_func_regvar_qty", None)
    vec_fn = getattr(ida_frame, "get_func_regvars", None)
    vec_cls = getattr(ida_frame, "regvars_t", None)
    if not (callable(qty_fn) and callable(vec_fn) and vec_cls is not None):
        return []
    try:
        if qty_fn(ea) <= 0:
            return []
    except Exception:
        return []
    out = vec_cls()
    try:
        if not vec_fn(out, ea):
            return []
        return list(out)
    except Exception:
        return []


# ---------------------------------------------------------------------------
# Bytes / comments / registers (renamed or moved in IDA 9.4)
# ---------------------------------------------------------------------------

def get_original_bytes(ea: int, size: int) -> bytes | None:
    """Original (pre-patch) bytes at ``ea``.

    IDA 9.4 removed the bulk ``ida_bytes.get_original_bytes``; only the
    per-width readers survive, so assemble the range byte by byte.
    """
    if ida_bytes is None or size <= 0:
        return None
    bulk = getattr(ida_bytes, "get_original_bytes", None)
    if callable(bulk):
        try:
            return bulk(ea, size)
        except Exception:
            pass
    get_byte = getattr(ida_bytes, "get_original_byte", None)
    if not callable(get_byte):
        return None
    out = bytearray()
    for i in range(size):
        try:
            out.append(int(get_byte(ea + i)) & 0xFF)
        except Exception:
            break
    return bytes(out) if out else None


def get_extra_cmt_qty(ea: int, what: int) -> int:
    """Number of extra comment lines at ``ea``, starting at slot ``what``."""
    if ida_lines is None:
        return 0
    legacy = getattr(ida_lines, "get_extra_cmt_qty", None)
    if callable(legacy):
        try:
            return int(legacy(ea, what))
        except Exception:
            pass
    first_free = getattr(ida_lines, "get_first_free_extra_cmtidx", None)
    if callable(first_free):
        try:
            return max(0, int(first_free(ea, what)) - what)
        except Exception:
            pass
    return 0


def get_extra_cmt(ea: int, what: int, index: int = 0) -> str | None:
    """``index``-th extra comment line at ``ea``, starting at slot ``what``.

    IDA 9.4 folds the line index into ``what`` (``get_extra_cmt(ea, what + i)``)
    while older bindings took it as a third argument.
    """
    if ida_lines is None:
        return None
    fn = getattr(ida_lines, "get_extra_cmt", None)
    if not callable(fn):
        return None
    for args in ((ea, what + index), (ea, what, index)):
        try:
            return fn(*args)
        except Exception:
            continue
    return None


def get_segment_comment(seg, repeatable: bool = False) -> str | None:
    """Comment of ``seg`` (``get_segment_cmt`` replaced ``get_segm_cmt``).

    9.5 deprecated ``get_segment_cmt(seg, ...)`` in favour of
    ``get_segment_cmt_by_ea(ea, ...)``; the address form is tried first.
    """
    if ida_segment is None:
        return None
    ea = getattr(seg, "start_ea", None)
    fn_ea = getattr(ida_segment, "get_segment_cmt_by_ea", None)
    if callable(fn_ea) and isinstance(ea, int):
        try:
            return fn_ea(ea, repeatable)
        except Exception:
            pass
    for fn_name in ("get_segment_cmt", "get_segm_cmt"):
        fn = getattr(ida_segment, fn_name, None)
        if not callable(fn):
            continue
        try:
            return fn(seg, repeatable)
        except Exception:
            continue
    return None


def segment_class(seg) -> str | None:
    """Class of ``seg`` (``get_segm_class`` was deprecated in 9.5).

    ``get_segment_class`` takes the segment's start address rather than the
    ``segment_t``, so both spellings are supported.
    """
    if ida_segment is None or seg is None:
        return None
    ea = getattr(seg, "start_ea", None)
    fn_ea = getattr(ida_segment, "get_segment_class", None)
    if callable(fn_ea) and isinstance(ea, int):
        try:
            return fn_ea(ea)
        except Exception:
            pass
    fn = getattr(ida_segment, "get_segm_class", None)
    if callable(fn):
        try:
            return fn(seg)
        except Exception:
            pass
    return None


def get_reg_name(reg: int, width: int = 0) -> str | None:
    """Text representation of the register ``reg`` (moved to ``ida_idp``)."""
    for mod in (ida_idp, ida_ua):
        fn = getattr(mod, "get_reg_name", None) if mod is not None else None
        if not callable(fn):
            continue
        for args in ((reg, width), (reg,)):
            try:
                return fn(*args)
            except Exception:
                continue
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
    "get_func",
    "getseg",
    "get_segm_name",
    "silence_known_deprecations",
    "del_name",
    "get_type_ordinal_limit",
    "FUNC_STATIC",
    "get_func_cc",
    "get_cc_name",
    "get_frame_tinfo",
    "frame_udt_members",
    "frame_soff",
    "is_frame_arg",
    "get_frame_size",
    "get_func_comment",
    "get_segment_comment",
    "segment_class",
    "get_func_regvars",
    "get_original_bytes",
    "get_extra_cmt_qty",
    "get_extra_cmt",
    "get_reg_name",
    "get_entry_qty",
    "get_entry_ordinal",
    "get_entry",
    "get_entry_name",
]
