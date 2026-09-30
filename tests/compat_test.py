"""Tests for the IDA 9.4 shims in compat.py (type ordinals + name deletion).

Runs standalone: it stubs the ``ida_*`` modules and execs ``compat.py`` once
per simulated IDA version, so every fallback branch is exercised even though
a single IDA install can only ever provide one of them.
"""
import os
import sys
import types

HERE = os.path.dirname(os.path.abspath(__file__))
PKG = os.path.join(HERE, "..", "ida_mcp")

IDA_MODULES = ("ida_ida", "ida_entry", "ida_bytes", "ida_name", "ida_typeinf", "idaapi",
               "ida_frame", "ida_funcs", "ida_idp", "ida_lines", "ida_segment", "ida_ua")


def _install(stubs: dict) -> None:
    """(Re)install the stubbed ida_* modules for one simulated version."""
    for name in IDA_MODULES:
        sys.modules.pop(name, None)
    for name, attrs in stubs.items():
        mod = types.ModuleType(name)
        for key, value in attrs.items():
            setattr(mod, key, value)
        sys.modules[name] = mod


def _load_compat():
    """Exec compat.py against the ida_* stubs installed right now."""
    src = open(os.path.join(PKG, "compat.py"), encoding="utf-8").read()
    mod = types.ModuleType("compat_test_mod")
    exec(compile(src, "compat_test_mod", "exec"), mod.__dict__)
    return mod


# =========================================================================
# IDA 9.4: get_ordinal_limit + del_global_name/del_local_name, no legacy API
# =========================================================================

_names: dict[int, str] = {0x1000: "main"}
_scope_calls: list[str] = []


def _del_global_name(ea):
    _scope_calls.append("del_global_name")
    _names.pop(ea, None)
    return True  # 9.4 reports success even when nothing had to be deleted


def _del_local_name(ea):
    _scope_calls.append("del_local_name")
    return False


_install({
    "idaapi": {},
    "ida_name": {"del_global_name": _del_global_name,
                 "del_local_name": _del_local_name},
    # count is deliberately not limit - 1, to prove which branch won
    "ida_typeinf": {"get_ordinal_limit": lambda ti=None: 736,
                    "get_ordinal_count": lambda ti=None: 1000},
})
compat = _load_compat()

assert compat.get_type_ordinal_limit(object()) == 736, "get_ordinal_limit must win"
assert compat.del_name(0x1000) is True
assert 0x1000 not in _names, _names
assert set(_scope_calls) == {"del_global_name", "del_local_name"}, _scope_calls
print("compat 9.4 ordinals + scoped name deletion OK")

# =========================================================================
# 8.3..9.3: legacy get_ordinal_qty / del_name, no scoped deleters
# =========================================================================

_legacy_names = {0x2000: "legacy"}
_legacy_calls: list[int] = []


def _del_name(ea):
    _legacy_calls.append(ea)
    return _legacy_names.pop(ea, None) is not None


_install({
    "idaapi": {},
    "ida_name": {"del_name": _del_name},
    "ida_typeinf": {"get_ordinal_qty": lambda ti=None: 4},
})
compat = _load_compat()

assert compat.get_type_ordinal_limit(None) == 4, "legacy get_ordinal_qty"
assert compat.del_name(0x2000) is True and _legacy_calls == [0x2000], _legacy_calls
assert compat.del_name(0xDEAD) is False, "legacy failure must surface"
assert compat.is_ida_available() is False, "ida_ida is stubbed out here"
print("compat legacy (get_ordinal_qty + del_name) OK")

# =========================================================================
# 9.4 with ordinals disabled for the til: uint32(-1) sentinel
# =========================================================================

_install({
    "idaapi": {},
    "ida_name": {},
    "ida_typeinf": {"get_ordinal_limit": lambda ti=None: 0xFFFFFFFF,
                    "get_ordinal_count": lambda ti=None: 0},
})
compat = _load_compat()

# the sentinel must not drive a loop: count + 1 == 1 (empty enumeration)
assert compat.get_type_ordinal_limit(None) == 1, "sentinel must be rejected"
print("compat uint32(-1) ordinal sentinel OK")

# =========================================================================
# No ordinal/name API at all (old or partially stubbed environment)
# =========================================================================

_install({"idaapi": {}, "ida_name": {}, "ida_typeinf": {}})
compat = _load_compat()

assert compat.get_type_ordinal_limit(None) == 0
assert compat.del_name(0x3000) is False
print("compat missing-API fallbacks OK")

# =========================================================================
# IDA 9.4: renamed/moved helpers (frames, cc, bytes, comments, registers)
# =========================================================================


class _FakeMemberType:
    def get_type_name(self):
        return "_QWORD"


class _FakeUdm:
    """``udm_t`` shim: frame offset and size in bits, type as a tinfo_t."""

    def __init__(self, name, offset_bits, size_bits):
        self.name = name
        self.offset = offset_bits
        self.size = size_bits
        self.type = _FakeMemberType()


class _FakeUdt:
    def __init__(self, members=None):
        self._members = members or []

    def __iter__(self):
        return iter(self._members)


class _FakeFrameTif:
    def __init__(self, other=None):
        self._other = other

    def get_type_name(self):
        return self._other.get_type_name() if self._other is not None else None

    def get_udt_details(self, udt):
        udt._members = [_FakeUdm("DestinationString", 256, 128),
                        _FakeUdm("arg_0", 512, 64)]
        return True


class _FakeFtd:
    def get_cc(self):
        return 80  # CM_CC_STDCALL


class _FakeRegvar:
    canon, user, cmt = "rax", "i", "loop counter"
    start_ea, end_ea = 0x1000, 0x1100


class _FakeRegvars:
    def __init__(self):
        self._items = []

    def push_back(self, item):
        self._items.append(item)

    def __iter__(self):
        return iter(self._items)


_install({
    "idaapi": {"get_kernel_version": lambda: "9.4"},
    "ida_typeinf": {"tinfo_t": _FakeFrameTif, "udt_type_data_t": _FakeUdt,
                    "CM_CC_STDCALL": 80, "CM_CC_LAST_USERCALL": 255},
    "ida_frame": {"get_func_frame": lambda tif, pfn: True,
                  "soff_to_fpoff": lambda pfn, frameoff: frameoff - 0x38,
                  "is_funcarg_off": lambda pfn, frameoff: frameoff >= 0x40,
                  "get_func_regvar_qty": lambda ea: 1,
                  "get_func_regvars": lambda out, ea: out.push_back(_FakeRegvar()) or True,
                  "regvars_t": _FakeRegvars},
    "ida_bytes": {"get_original_byte": lambda ea: ea & 0xFF},
    "ida_lines": {"E_PREV": 1000,
                  "get_first_free_extra_cmtidx": lambda ea, start: start + 2,
                  "get_extra_cmt": lambda ea, what: "line@%d" % what},
    "ida_segment": {"get_segment_cmt": lambda seg, rep: "seg comment"},
    "ida_idp": {"get_reg_name": lambda reg, width: "rax"},
    "ida_funcs": {"FUNC_STATICDEF": 0x100},
})
compat = _load_compat()

assert compat.FUNC_STATIC == 0x100, compat.FUNC_STATIC
assert compat.get_cc_name(80) == "stdcall", compat.get_cc_name(80)
assert compat.get_cc_name(0x20) == "usercall", compat.get_cc_name(0x20)
assert compat.get_cc_name(None) is None
assert compat.get_func_cc(_FakeFtd()) == 80
print("compat 9.4 cc/flags OK")

tif = compat.get_frame_tinfo(object())
assert tif is not None
members = compat.frame_udt_members(tif)
assert [m["name"] for m in members] == ["DestinationString", "arg_0"], members
assert [m["offset"] for m in members] == [32, 64], members   # bytes, not bits
assert [m["size"] for m in members] == [16, 8], members
assert members[0]["type"].get_type_name() == "_QWORD", members
assert compat.frame_soff(object(), 0x20) == -24
assert compat.is_frame_arg(object(), 0x40) is True
assert compat.is_frame_arg(object(), 0x20) is False
regvars = compat.get_func_regvars(0x1000)
assert len(regvars) == 1 and regvars[0].canon == "rax", regvars
print("compat 9.4 frame helpers OK")

assert compat.get_original_bytes(0x10, 3) == bytes([0x10, 0x11, 0x12])
assert compat.get_extra_cmt_qty(0x1000, 1000) == 2
assert compat.get_extra_cmt(0x1000, 1000, 1) == "line@1001"
assert compat.get_segment_comment(object()) == "seg comment"
assert compat.get_reg_name(0) == "rax"
assert compat.detect_ida_version() == "9.4"
print("compat 9.4 bytes/comments/registers/version OK")

# =========================================================================
# 8.3..9.3: the pre-9.4 spellings must still win when they exist
# =========================================================================

_install({
    "ida_ida": {"get_kernel_version": lambda: "9.3"},
    "idaapi": {},
    "ida_funcs": {"FUNC_STATIC": 0x100},
    "ida_typeinf": {"get_cc_name": lambda cc: "legacy-cc"},
    "ida_bytes": {"get_original_bytes": lambda ea, size: b"\xAA" * size},
    "ida_lines": {"E_PREV": 0, "get_extra_cmt_qty": lambda ea, what: 5,
                  "get_extra_cmt": lambda ea, what, idx: "legacy@%d" % idx},
    "ida_segment": {"get_segm_cmt": lambda seg, rep: "legacy seg"},
    "ida_ua": {"get_reg_name": lambda reg, width: "legacy-reg"},
})
compat = _load_compat()

assert compat.detect_ida_version() == "9.3", compat.IDA_VERSION
assert compat.FUNC_STATIC == 0x100
assert compat.get_cc_name(80) == "legacy-cc"
assert compat.get_original_bytes(0, 2) == b"\xAA\xAA"
assert compat.get_extra_cmt_qty(0, 0) == 5
assert compat.get_extra_cmt(0, 0, 3) == "legacy@3"
assert compat.get_segment_comment(object()) == "legacy seg"
assert compat.get_reg_name(0) == "legacy-reg"
print("compat legacy helpers OK")

print("ALL COMPAT TESTS PASSED")
