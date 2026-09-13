"""Tests for api_names.py (name management tools).

Stubs IDA modules and loads the source via exec.
"""
import json
import os
import sys
import types

# =========================================================================
# Stub IDA modules
# =========================================================================

ida_auto = types.ModuleType("ida_auto")
ida_auto.auto_wait = lambda: None
sys.modules["ida_auto"] = ida_auto

idaapi = types.ModuleType("idaapi")
idaapi.BADADDR = -1
sys.modules["idaapi"] = idaapi

_names: dict[int, str] = {0x1000: "main", 0x2000: "_Z3foov", 0x3000: "sub_3000"}
_public: set[int] = {0x1000}
_weak: set[int] = set()


def _fake_get_ea_name(ea):
    return _names.get(ea)


def _fake_set_name(ea, name, flags):
    if name in _names.values():
        return False
    _names[ea] = name
    return True


def _fake_force_name(ea, name):
    candidate = name
    i = 0
    taken = set(_names.values())
    while candidate in taken:
        candidate = f"{name}_{i}"
        i += 1
    _names[ea] = candidate
    return True


def _fake_del_name(ea):
    _names.pop(ea, None)


def _fake_demangle(name, *args):
    if name == "_Z3foov":
        return "foo()"
    return name


ida_name = types.ModuleType("ida_name")
ida_name.get_ea_name = _fake_get_ea_name
ida_name.set_name = _fake_set_name
ida_name.force_name = _fake_force_name
ida_name.del_name = _fake_del_name
ida_name.demangle_name = _fake_demangle
ida_name.is_public_name = lambda ea: ea in _public
ida_name.is_weak_name = lambda ea: ea in _weak
ida_name.make_name_public = lambda ea: _public.add(ea)
ida_name.make_name_non_public = lambda ea: _public.discard(ea)
ida_name.SN_NOWARN = 1
sys.modules["ida_name"] = ida_name

idautils = types.ModuleType("idautils")
idautils.Names = lambda: list(_names.items())
sys.modules["idautils"] = idautils

# =========================================================================
# Load api_names.py
# =========================================================================

HERE = os.path.dirname(os.path.abspath(__file__))
PKG = os.path.join(HERE, "..", "ida_mcp")
src = open(os.path.join(PKG, "api_names.py")).read()
src = src.replace(
    "from .rpc import tool, unsafe",
    "tool = lambda f: f\nunsafe = lambda f: f",
)
src = src.replace("from .sync import idasync", "idasync = lambda f: f")
src = src.replace(
    "from .api_analysis import parse_addr",
    "def parse_addr(s):\n"
    "    s = s.strip()\n"
    "    if s.startswith('0x'): return int(s, 16)\n"
    "    try: return int(s)\n"
    "    except ValueError: pass\n"
    "    table = {'main': 0x1000, 'foo': 0x2000}\n"
    "    if s in table: return table[s]\n"
    "    raise ValueError(f'Unknown: {s}')",
)
mod = types.ModuleType("names_test")
exec(compile(src, "names_test", "exec"), mod.__dict__)
sys.modules["names_test"] = mod

# =========================================================================
# Tests
# =========================================================================

# --- get_name ---
r = json.loads(mod.get_name("0x1000"))
assert r == {"addr": "0x1000", "name": "main", "demangled": None}, r
print("get_name plain OK")

r = json.loads(mod.get_name("0x2000"))
assert r["name"] == "_Z3foov" and r["demangled"] == "foo()", r
print("get_name demangled OK")

r = json.loads(mod.get_name("0x9999"))
assert r["name"] is None, r
print("get_name missing OK")

# --- get_all_names ---
r = json.loads(mod.get_all_names("*", 0, 100))
assert r["total"] == 3 and r["count"] == 3, r
r = json.loads(mod.get_all_names("sub_*", 0, 100))
assert r["total"] == 1 and r["data"][0]["name"] == "sub_3000", r
r = json.loads(mod.get_all_names("*", 1, 1))
assert r["count"] == 1 and r["offset"] == 1, r
print("get_all_names filter+page OK")

# --- demangle ---
r = json.loads(mod.get_demangled_name("0x2000"))
assert r["demangled"] == "foo()", r
r = json.loads(mod.demangle_name("_Z3foov"))
assert r["demangled"] == "foo()", r
r = json.loads(mod.demangle_name("plain_name"))
assert r["demangled"] is None, r
print("demangle OK")

# --- validate_name ---
assert json.loads(mod.validate_name("good_name"))["valid"] is True
assert json.loads(mod.validate_name(""))["valid"] is False
assert json.loads(mod.validate_name("9bad"))["valid"] is False
assert json.loads(mod.validate_name("has space"))["valid"] is False
print("validate_name OK")

# --- public / weak ---
assert json.loads(mod.is_name_public("0x1000"))["is_public"] is True
assert json.loads(mod.is_name_public("0x2000"))["is_public"] is False
assert json.loads(mod.is_name_weak("0x1000"))["is_weak"] is False
print("is_name_public/weak OK")

# --- set_name / force_name / delete_name ---
r = json.loads(mod.set_name("0x3000", "renamed"))
assert r["old_name"] == "sub_3000" and r["new_name"] == "renamed", r
assert _names[0x3000] == "renamed"
print("set_name OK")

r = json.loads(mod.set_name("0x3000", "main"))
assert "error" in r, r  # collision
print("set_name collision OK")

r = json.loads(mod.force_name("0x3000", "main"))
assert r["new_name"].startswith("main_"), r
print("force_name variant OK")

r = json.loads(mod.delete_name("0x3000"))
assert r["ok"] is True and r["old_name"] is not None, r
assert 0x3000 not in _names
print("delete_name OK")

# --- make public / non-public ---
mod.make_name_public("0x2000")
assert json.loads(mod.is_name_public("0x2000"))["is_public"] is True
mod.make_name_non_public("0x1000")
assert json.loads(mod.is_name_public("0x1000"))["is_public"] is False
print("make_name_public/non_public OK")

print("ALL NAMES TESTS PASSED")
