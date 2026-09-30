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

IDA_MODULES = ("ida_ida", "ida_entry", "ida_bytes", "ida_name", "ida_typeinf", "idaapi")


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

print("ALL COMPAT TESTS PASSED")
