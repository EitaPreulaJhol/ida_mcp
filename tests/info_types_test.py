"""Tests for api_info additions (idb_save/idb_meta/get_analysis_prompt) and
api_typeinfo additions (get_type_by_name/infer_types).

Stubs IDA modules and loads both sources via exec.
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
ida_auto.is_auto_enabled = lambda: True
ida_auto.auto_is_ok = lambda: True
sys.modules["ida_auto"] = ida_auto

ida_entry = types.ModuleType("ida_entry")
ida_entry.get_entry_qty = lambda: 1
ida_entry.get_entry_ordinal = lambda i: 1
ida_entry.get_entry = lambda ordinal: 0x1000
ida_entry.get_entry_name = lambda ordinal: "start"
sys.modules["ida_entry"] = ida_entry

ida_ida = types.ModuleType("ida_ida")
ida_ida.inf_get_min_ea = lambda: 0x1000
ida_ida.inf_get_max_ea = lambda: 0x2000
sys.modules["ida_ida"] = ida_ida

ida_kernwin = types.ModuleType("ida_kernwin")
ida_kernwin.is_idaq = lambda: True
sys.modules["ida_kernwin"] = ida_kernwin

_SAVE_CALLS: list = []

ida_loader = types.ModuleType("ida_loader")
ida_loader.PATH_TYPE_IDB = 1
ida_loader.DBFL_COMP = 2
ida_loader.DBFL_KILL = 4
ida_loader.get_path = lambda kind: "/tmp/fake.i64"


def _fake_save(path, flags):
    _SAVE_CALLS.append((path, flags))
    return True


ida_loader.save_database = _fake_save
sys.modules["ida_loader"] = ida_loader

ida_nalt = types.ModuleType("ida_nalt")
ida_nalt.get_root_filename = lambda: "fake.exe"
ida_nalt.get_input_file_path = lambda: ""
ida_nalt.get_imagebase = lambda: 0x400000
ida_nalt.get_import_module_qty = lambda: 1
ida_nalt.get_tinfo = lambda tif, ea: False
sys.modules["ida_nalt"] = ida_nalt

idaapi = types.ModuleType("idaapi")
idaapi.BADADDR = -1
idaapi.inf_is_64bit = lambda: True
idaapi.get_imagebase = lambda: 0x400000
idaapi.get_kernel_version = lambda: "9.3"
idaapi.get_imagebase = lambda: 0x400000
sys.modules["idaapi"] = idaapi


class FakeSeg:
    pass


idaapi.getseg = lambda ea: FakeSeg()

idc = types.ModuleType("idc")
idc.get_processor_name = lambda: "metapc"
sys.modules["idc"] = idc

ida_problems = types.ModuleType("ida_problems")
sys.modules["ida_problems"] = ida_problems

ida_segment = types.ModuleType("ida_segment")
ida_segment.get_segm_name = lambda seg: ".text"
sys.modules["ida_segment"] = ida_segment

ida_typeinf = types.ModuleType("ida_typeinf")
ida_typeinf.PRTYPE_DEF = 1
ida_typeinf.PRTYPE_TYPE = 2
ida_typeinf.TINFO_DEFINITE = 1
ida_typeinf.get_compiler_name = lambda cid: "gnu"
ida_typeinf.get_abi_name = lambda: "SysV"
ida_typeinf.guess_tinfo = lambda tif, ea: False
# IDA 9.4 API: allocated ordinals + 1 (renamed from get_ordinal_qty)
ida_typeinf.get_ordinal_limit = lambda ti=None: 3


class FakeTif:
    def get_type_name(self):
        return "Point"

    def get_size(self):
        return 8

    def is_func(self):
        return False

    def is_struct(self):
        return False

    def is_enum(self):
        return False

    def is_union(self):
        return False

    def is_ptr(self):
        return False

    def is_array(self):
        return False

    def _print(self, *args):
        return "struct Point;"

    def get_named_type(self, til, name, *args):
        return name == "Point"

    def get_numbered_type(self, til, ordinal):
        # Two numbered types (ordinals 1..2) in the stubbed type library
        return 1 <= ordinal <= 2


class FakeUdmMember:
    """``udm_t`` shim: ``type`` is a plain tinfo_t, as on IDA 9."""

    def __init__(self, name, offset_bits, mtype):
        self.name = name
        self.offset = offset_bits
        self.type = mtype


class FakeUdt:
    """``udt_type_data_t`` shim filled in by ``FakeStructTif``."""

    def __init__(self, members=None):
        self._members = members or []

    def __iter__(self):
        return iter(self._members)


class FakeArg:
    def __init__(self, name, atype):
        self.name = name
        self.type = atype


class FakeFtd:
    """``func_type_data_t`` shim exposing the IDA 9.4 ``get_cc()`` only."""

    def __init__(self, rettype=None, args=None):
        self.rettype = rettype
        self._args = args or []

    def __iter__(self):
        return iter(self._args)

    def get_cc(self):
        return 80  # CM_CC_SPECIAL, as reported for x64 stdlib functions


class FakeStructTif(FakeTif):
    """Struct whose members come from ``udm_t::type`` tinfo_t values."""

    def is_struct(self):
        return True

    def get_udt_details(self, udt):
        udt._members = [FakeUdmMember("DestinationString", 256, FakeTif()),
                        FakeUdmMember("arg_0", 512, FakeAnonTif())]
        return True


class FakeAnonTif(FakeTif):
    """Anonymous member type: no name, only a C declaration."""

    def get_type_name(self):
        return None

    def dstr(self):
        return "_QWORD"


class FakeFuncTif(FakeTif):
    """Function type exposing ``get_cc()`` instead of a ``cc`` attribute."""

    def is_func(self):
        return True

    def get_func_details(self, ftd):
        ftd.rettype = "int"
        ftd._args = [FakeArg("param1", FakeTif())]
        return True


ida_typeinf.tinfo_t = FakeTif
ida_typeinf.udt_type_data_t = FakeUdt
ida_typeinf.func_type_data_t = FakeFtd
ida_typeinf.get_idati = lambda: object()
sys.modules["ida_typeinf"] = ida_typeinf

ida_bytes = types.ModuleType("ida_bytes")
ida_bytes.get_item_size = lambda ea: 4
ida_bytes.get_strlit_contents = lambda ea, length=-1, strtype=0: None
sys.modules["ida_bytes"] = ida_bytes

ida_funcs = types.ModuleType("ida_funcs")
ida_funcs.get_func = lambda ea: None
ida_funcs.get_func_name = lambda ea: None
sys.modules["ida_funcs"] = ida_funcs

idautils = types.ModuleType("idautils")
idautils.Functions = lambda: iter([0x1000, 0x2000])
idautils.Segments = lambda: iter([0x1000])
idautils.Strings = lambda: iter([])
sys.modules["idautils"] = idautils

HERE = os.path.dirname(os.path.abspath(__file__))
PKG = os.path.join(HERE, "..", "ida_mcp")


def _load(name, filename, replacements):
    src = open(os.path.join(PKG, filename)).read()
    for old, new in replacements:
        src = src.replace(old, new)
    m = types.ModuleType(name)
    exec(compile(src, name, "exec"), m.__dict__)
    sys.modules[name] = m
    return m


info = _load("info_types_info", "api_info.py", [
    ("from .rpc import tool", "tool = lambda f: f"),
    ("from .sync import idasync", "idasync = lambda f: f"),
    ("from .compat import get_entry_qty, get_entry_ordinal, get_entry, get_entry_name",
     "get_entry_qty = lambda: 1\nget_entry_ordinal = lambda i: 1\n"
     "get_entry = lambda o: 0x1000\nget_entry_name = lambda o: 'start'"),
])

tinfo = _load("info_types_tinfo", "api_typeinfo.py", [
    ("from .rpc import tool, unsafe", "tool = lambda f: f\nunsafe = lambda f: f"),
    ("from .sync import idasync", "idasync = lambda f: f"),
    ("from .compat import get_func_cc, get_type_ordinal_limit",
     "get_type_ordinal_limit = lambda til=None: ida_typeinf.get_ordinal_limit(til)\n"
     "get_func_cc = lambda ftd: ftd.get_cc()"),
    ("from .api_analysis import parse_addr, type_label",
     "def parse_addr(s):\n"
     "    s = str(s).strip()\n"
     "    if s.startswith('0x'): return int(s, 16)\n"
     "    try: return int(s)\n"
     "    except ValueError: raise ValueError(f'Unknown: {s}')\n"
     "def type_label(tif):\n"
     "    return tif.get_type_name() or tif.dstr() or '<unnamed>'"),
])

# =========================================================================
# Tests — api_info additions
# =========================================================================

r = json.loads(info.idb_save())
assert r["ok"] is True and r["path"] == "/tmp/fake.i64", r
assert _SAVE_CALLS[-1] == (None, 0), _SAVE_CALLS  # GUI in-place save
r = json.loads(info.idb_save("/tmp/other.i64"))
assert _SAVE_CALLS[-1] == ("/tmp/other.i64", 2), _SAVE_CALLS  # snapshot copy
print("idb_save OK")

r = json.loads(info.idb_meta())
assert r["idb_path"] == "/tmp/fake.i64" and r["root_filename"] == "fake.exe", r
assert r["kernel_version"] == "9.3" and r["idb_size"] is None, r  # missing file
print("idb_meta OK")

r = json.loads(info.get_analysis_prompt())
assert "fake.exe" in r["prompt"] and "survey_binary" in r["prompt"], r
print("get_analysis_prompt OK")

# =========================================================================
# Tests — api_typeinfo additions
# =========================================================================

r = json.loads(tinfo.get_type_by_name("Point"))
assert r["name"] == "Point" and r["requested_name"] == "Point", r
r = json.loads(tinfo.get_type_by_name("Nope"))
assert "not found" in r["error"], r
print("get_type_by_name OK")

r = json.loads(tinfo.infer_types("0x1000"))
assert r["results"][0]["inferred_type"] == "uint32_t", r
assert r["results"][0]["method"] == "size_based", r
assert r["results"][0]["confidence"] == "low", r
r = json.loads(tinfo.infer_types("bogus_name"))
assert r["results"][0]["confidence"] == "none", r
print("infer_types size-based OK")

# --- type_query / search_structs: enumeration via get_ordinal_limit ---
r = json.loads(tinfo.type_query(""))
assert [e["ordinal"] for e in r] == [1, 2], r
assert r[0]["name"] == "Point" and r[0]["declaration"] == "struct Point;", r
r = json.loads(tinfo.type_query("poi"))
assert len(r) == 2, r  # case-insensitive substring filter
r = json.loads(tinfo.type_query("nope"))
assert r == [], r
print("type_query ordinal enumeration OK")

r = json.loads(tinfo.search_structs(""))
assert r == [], r  # FakeTif is neither struct nor union
print("search_structs OK")

# --- _format_tinfo: udm_t::type is a tinfo_t and cc comes from get_cc() ----
info = tinfo._format_tinfo(FakeStructTif())
assert info["members"] == [{"name": "DestinationString", "offset": 32,
                            "size": 8, "type": "Point"},
                           {"name": "arg_0", "offset": 64, "size": 8,
                            "type": "_QWORD"}], info
print("_format_tinfo struct members OK")

info = tinfo._format_tinfo(FakeFuncTif())
assert info["cc"] == 80 and info["return_type"] == "int", info
assert info["arguments"] == [{"name": "param1", "type": "Point"}], info
print("_format_tinfo function cc/args OK")

# --- get_type_at reads the type via ida_nalt.get_tinfo (9.4) --------------
# (the stubs deliberately have no ida_typeinf.get_tinfo)
ida_nalt.get_tinfo = lambda tif, ea: True
r = json.loads(tinfo.get_type_at("0x1000"))
assert r["type"] is not None and r["type"]["name"] == "Point", r
ida_funcs.get_func = lambda ea: type("Fn", (), {"start_ea": 0x1000})()
r = json.loads(tinfo.get_type_at("0x1000"))
assert r["type"]["is_func"] is False, r  # FakeTif.is_func() is False
print("get_type_at (ida_nalt.get_tinfo) OK")

print("ALL INFO/TYPES TESTS PASSED")
