"""Tests for the IDA 9.4 fixes in api_typeinfo:

- ``declare_type`` / ``_declare_type_impl`` no longer calls
  ``ida_typeinf.print_decls`` (which 9.4 repurposed into the type-to-header
  printer) and interprets ``idc_parse_types`` as the *number of errors*
  (0 == success).
- ``enum_upsert`` performs a real member upsert through the ``tinfo_t`` type
  API (``enum_type_data_t`` / ``edm_t`` + ``create_enum`` / ``set_named_type``)
  instead of the broken ``idc.*enum_member*`` helpers.

Runs the real ``api_typeinfo.py`` against 9.4-shaped stubs via exec, mirroring
the other standalone harnesses in this directory.
"""
import json
import os
import sys
import types

# =========================================================================
# Stub IDA modules (IDA 9.4 surface)
# =========================================================================

ida_auto = types.ModuleType("ida_auto")
ida_auto.auto_wait = lambda: None
sys.modules["ida_auto"] = ida_auto

ida_bytes = types.ModuleType("ida_bytes")
ida_bytes.get_bytes = lambda ea, size: None
sys.modules["ida_bytes"] = ida_bytes

ida_funcs = types.ModuleType("ida_funcs")
ida_funcs.get_func = lambda ea: None
sys.modules["ida_funcs"] = ida_funcs

ida_nalt = types.ModuleType("ida_nalt")
ida_nalt.get_tinfo = lambda tif, ea: False
sys.modules["ida_nalt"] = ida_nalt

# --- type library state ---------------------------------------------------
PARSE_ERRORS: dict[str, int] = {}   # declaration -> number of parsing errors
ENUMS: dict[str, dict] = {}         # enum name -> {member: value}
STRUCTS: set[str] = set()           # names of non-enum named types
STRUCT_DEFS: dict[str, list] = {}   # struct name -> [FakeUdm]
SET_NAMED_CALLS: list = []          # (name, ntf_flags) records
ORDINAL_LIMIT = [1]                 # mutable "(#local types) + 1"


def _print_decls_poison(*args, **kwargs):
    raise AssertionError("ida_typeinf.print_decls() must not be used on 9.4")


def _idc_parse_types(declaration, flags=0):
    # Per the IDA 9.4 ``idc`` reference: number of errors (0 == success).
    return PARSE_ERRORS.get(declaration, 0)


class FakeEdm:
    """``edm_t`` shim."""

    def __init__(self):
        self.name = ""
        self.value = 0


class FakeUdmType:
    """IDA 9.x ``udm_t.type``: a tinfo_t, i.e. NO ``get()`` accessor."""

    def __init__(self, name, size):
        self._name = name
        self._size = size

    def get_type_name(self):
        return self._name

    def get_size(self):
        return self._size


class LegacyUdmType:
    """Pre-9.x shape: the member type is behind ``get(out)``."""

    def __init__(self, typ):
        self._typ = typ

    def get(self, out):
        out._type_name = self._typ._name
        out._type_size = self._typ._size
        return True


class FakeUdm:
    """``udm_t`` shim (offset is in bits, like the real one)."""

    def __init__(self, name, offset_bits, typ):
        self.name = name
        self.offset = offset_bits
        self.type = typ


class FakeUdtData:
    """``udt_type_data_t`` shim (push_back container of ``udm_t``)."""

    def __init__(self):
        self._items: list[FakeUdm] = []

    def push_back(self, udm):
        self._items.append(udm)

    def __iter__(self):
        return iter(self._items)


class FakeEnumData:
    """``enum_type_data_t`` shim (push_back container of ``edm_t``)."""

    def __init__(self):
        self._items: list[FakeEdm] = []

    def push_back(self, edm):
        copy = FakeEdm()
        copy.name = edm.name
        copy.value = edm.value
        self._items.append(copy)

    def __iter__(self):
        return iter(self._items)


class FakeTinfo:
    """``tinfo_t`` shim covering the enum path used by ``enum_upsert``."""

    def __init__(self):
        self._name = None
        self._members = None
        self._is_enum = False
        self._is_struct = False
        self._type_name = ""
        self._type_size = 0

    def get_type_name(self):
        return self._type_name

    def get_size(self):
        return self._type_size

    def get_named_type(self, til, name, *args):
        self._name = name
        if name in ENUMS:
            self._members = dict(ENUMS[name])
            self._is_enum = True
            self._is_struct = False
            return True
        if name in STRUCT_DEFS:
            self._members = list(STRUCT_DEFS[name])
            self._is_enum = False
            self._is_struct = True
            return True
        if name in STRUCTS:
            self._members = None
            self._is_enum = False
            self._is_struct = True
            return True
        self._members = None
        self._is_enum = False
        self._is_struct = False
        return False

    def is_enum(self):
        return self._is_enum

    def is_struct(self):
        return self._is_struct

    def is_union(self):
        return False

    def get_udt_details(self, udt):
        if not self._is_struct or self._members is None:
            return False
        for member in self._members:
            udt.push_back(member)
        return True

    def get_enum_details(self, edt):
        if self._members is None:
            return False
        for name, value in self._members.items():
            edm = FakeEdm()
            edm.name = name
            edm.value = value
            edt.push_back(edm)
        return True

    def create_enum(self, edt):
        self._members = {e.name: e.value for e in edt}
        self._is_enum = True
        return True

    def set_named_type(self, til, name, ntf_flags=0):
        SET_NAMED_CALLS.append((name, ntf_flags))
        ENUMS[name] = dict(self._members or {})
        self._name = name
        return ida_typeinf.TERR_OK


ida_typeinf = types.ModuleType("ida_typeinf")
ida_typeinf.tinfo_t = FakeTinfo
ida_typeinf.enum_type_data_t = FakeEnumData
ida_typeinf.udt_type_data_t = FakeUdtData
ida_typeinf.edm_t = FakeEdm
ida_typeinf.get_idati = lambda: object()
ida_typeinf.get_ordinal_limit = lambda ti=None: ORDINAL_LIMIT[0]
ida_typeinf.idc_parse_types = _idc_parse_types
ida_typeinf.print_decls = _print_decls_poison
ida_typeinf.tinfo_errstr = lambda code: f"err{code}"
ida_typeinf.NTF_REPLACE = 4
ida_typeinf.TERR_OK = 0
sys.modules["ida_typeinf"] = ida_typeinf

# =========================================================================
# Load api_typeinfo.py (relative imports redirected to inline stubs)
# =========================================================================


from _harness import API_ANALYSIS_HELPERS, RPC_STUB, SYNC_STUB, load  # noqa: E402
tinfo = load("api_typeinfo", {
    "rpc": RPC_STUB,
    "sync": SYNC_STUB,
    "compat": "get_type_ordinal_limit = lambda til=None: ida_typeinf.get_ordinal_limit(til)\n"
    "get_func_cc = lambda ftd: ftd.get_cc() if hasattr(ftd, 'get_cc') else None",
    "api_analysis": "def parse_addr(s):\n"
    "    s = str(s).strip()\n"
    "    if s.startswith('0x'):\n"
    "        return int(s, 16)\n"
    "    return int(s)\n"
    "def type_label(tif):\n"
    "    return tif.get_type_name() or '<unnamed>'" + API_ANALYSIS_HELPERS,
}, alias="ti_upsert_typeinfo")

# =========================================================================
# Tests — declare_type: print_decls removed + error-count semantics
# =========================================================================

PARSE_ERRORS["struct Foo { int a; };"] = 0
r = json.loads(tinfo.declare_type("struct Foo { int a; };"))
assert r["ok"] is True and r["errors"] is None, r
assert "declaration" in r and "parsed_count" in r, r
print("declare_type success (idc_parse_types == 0) OK")

PARSE_ERRORS["bogus decl"] = 3
r = json.loads(tinfo.declare_type("bogus decl"))
assert r["ok"] is False, r
assert "3" in r["errors"], r
print("declare_type failure (idc_parse_types > 0) OK")

# =========================================================================
# Tests — enum_upsert: tinfo_t-based upsert, no idc.del_enum_member
# =========================================================================

# --- upsert into an existing enum: merge by name --------------------------
ENUMS.clear()
SET_NAMED_CALLS.clear()
ENUMS["Color"] = {"RED": 1, "GREEN": 2}
r = json.loads(tinfo.enum_upsert(
    "Color", '[{"name": "GREEN", "value": 20}, {"name": "BLUE", "value": 3}]'))
assert r["created"] is False, r
assert r["member_count"] == 3, r
assert {m["name"]: m["value"] for m in r["members"]} == \
    {"RED": 1, "GREEN": 20, "BLUE": 3}, r
assert ENUMS["Color"] == {"RED": 1, "GREEN": 20, "BLUE": 3}, ENUMS
assert SET_NAMED_CALLS[-1] == ("Color", ida_typeinf.NTF_REPLACE), SET_NAMED_CALLS
print("enum_upsert merge (create_enum + set_named_type NTF_REPLACE) OK")

# --- create a brand new enum: no NTF_REPLACE needed -----------------------
ENUMS.clear()
SET_NAMED_CALLS.clear()
r = json.loads(tinfo.enum_upsert("Fruit", '[{"name": "APPLE", "value": 1}]'))
assert r["created"] is True and r["member_count"] == 1, r
assert ENUMS["Fruit"] == {"APPLE": 1}, ENUMS
assert SET_NAMED_CALLS[-1] == ("Fruit", 0), SET_NAMED_CALLS
print("enum_upsert create OK")

# --- refuse to clobber a non-enum type of the same name -------------------
STRUCTS.add("Thing")
r = json.loads(tinfo.enum_upsert("Thing", '[{"name": "A", "value": 1}]'))
assert "not an enum" in r["error"], r
print("enum_upsert non-enum guard OK")

# --- malformed input ------------------------------------------------------
r = json.loads(tinfo.enum_upsert("X", "not json"))
assert "Invalid JSON" in r["error"], r
r = json.loads(tinfo.enum_upsert("X", '[{"name": "A"}]'))
assert "must be" in r["error"], r
print("enum_upsert input validation OK")

# =========================================================================
# Tests — read_struct: udm_t.type is a tinfo_t on 9.x (no .get())
# =========================================================================

STRUCT_DEFS["Probe9"] = [
    FakeUdm("a", 0, FakeUdmType("int", 4)),
    FakeUdm("b", 32, FakeUdmType("char", 1)),
]
r = json.loads(tinfo.read_struct("0x2000", "Probe9"))
assert [f["name"] for f in r["fields"]] == ["a", "b"], r
assert [f["type"] for f in r["fields"]] == ["int", "char"], r
assert [f["size"] for f in r["fields"]] == [4, 1], r
assert [f["offset"] for f in r["fields"]] == [0, 4], r
print("read_struct resolves 9.x udm_t.type OK")

STRUCT_DEFS["ProbeLegacy"] = [
    FakeUdm("x", 0, LegacyUdmType(FakeUdmType("int", 4))),
]
r = json.loads(tinfo.read_struct("0x2000", "ProbeLegacy"))
assert [f["type"] for f in r["fields"]] == ["int"], r
print("read_struct keeps the legacy get(out) path OK")

print("ALL TYPEINFO 9.4 UPSERT TESTS PASSED")


