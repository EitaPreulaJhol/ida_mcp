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


ida_typeinf.tinfo_t = FakeTif
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
    ("from .api_analysis import parse_addr",
     "def parse_addr(s):\n"
     "    s = str(s).strip()\n"
     "    if s.startswith('0x'): return int(s, 16)\n"
     "    try: return int(s)\n"
     "    except ValueError: raise ValueError(f'Unknown: {s}')"),
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

print("ALL INFO/TYPES TESTS PASSED")
