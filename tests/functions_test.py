"""Tests for api_functions.py against the IDA 9.4 API surface.

Stubs the IDA modules the way IDA 9.4 looks (``ida_frame.get_func_frame`` with a
frame ``tinfo_t`` instead of ``frame_t``, ``func_type_data_t.get_cc()``,
``FUNC_STATICDEF``) and execs the source, so the frame/regvar/flags/signature
tools are covered outside IDA.
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

idaapi = types.ModuleType("idaapi")
idaapi.BADADDR = -1
sys.modules["idaapi"] = idaapi

FRAME_FUNC = 0x1000
PLAIN_FUNC = 0x2000


class FakeFunc:
    def __init__(self, start_ea, end_ea, flags=0):
        self.start_ea = start_ea
        self.end_ea = end_ea
        self.flags = flags


_funcs = {FRAME_FUNC: FakeFunc(FRAME_FUNC, 0x1100, 0x100),   # FUNC_STATICDEF
          PLAIN_FUNC: FakeFunc(PLAIN_FUNC, 0x2100, 0)}

ida_funcs = types.ModuleType("ida_funcs")
ida_funcs.get_func = lambda ea: _funcs.get(ea)
ida_funcs.get_func_name = lambda ea: {FRAME_FUNC: "sub_1000", PLAIN_FUNC: "sub_2000"}.get(ea)
ida_funcs.FUNC_STATICDEF = 0x100
ida_funcs.FUNC_THUNK = 0x80
ida_funcs.FUNC_LIB = 0x4
ida_funcs.FUNC_NORET = 0x1
ida_funcs.FUNC_FAR = 0x2
ida_funcs.FUNC_FRAME = 0x40
ida_funcs.FUNC_BOTTOMBP = 0x200
ida_funcs.FUNC_HIDDEN = 0x400
ida_funcs.FUNC_TAIL = 0x1000
sys.modules["ida_funcs"] = ida_funcs

# --- frame tinfo (9.4) ---------------------------------------------------
# name, frame offset (bytes), size (bytes), type name, type declaration
_FRAME_MEMBERS = [
    ("DestinationString", 0x20, 16, "_UNICODE_STRING", "struct _UNICODE_STRING"),
    ("__return_address", 0x38, 8, None, "_UNKNOWN *"),
    ("arg_0", 0x40, 8, None, "_QWORD"),
]


class FakeType:
    def __init__(self, name, decl):
        self._name = name
        self._decl = decl

    def get_type_name(self):
        return self._name

    def dstr(self):
        return self._decl

    def __str__(self):
        return self._decl


class FakeUdm:
    def __init__(self, name, offset_bytes, size_bytes, mtype):
        self.name = name
        self.offset = offset_bytes * 8   # udm_t offsets/sizes are in bits
        self.size = size_bytes * 8
        self.type = mtype


class FakeUdt:
    def __init__(self, members=None):
        self._members = members or []

    def __iter__(self):
        return iter(self._members)


class FakeArg:
    def __init__(self, name, atype):
        self.name = name
        self.type = atype


class FakeFtd:
    """func_type_data_t: IDA 9.4 exposes get_cc() instead of a cc attribute."""

    def __init__(self):
        self.rettype = "int"
        self._args = []

    def __iter__(self):
        return iter(self._args)

    def get_cc(self):
        return 80  # CM_CC_STDCALL


class FakeTif:
    """Frame + function tinfo: covers both call paths of api_functions."""

    def get_udt_details(self, udt):
        udt._members = [FakeUdm(n, o, s, FakeType(tn, td))
                        for n, o, s, tn, td in _FRAME_MEMBERS]
        return True

    def is_func(self):
        return True

    def get_func_details(self, ftd):
        ftd.rettype = "int"
        ftd._args = [FakeArg("argc", FakeType("int", "int"))]
        return True


ida_typeinf = types.ModuleType("ida_typeinf")
# tinfo_t(other) copies (as IDA does); tinfo_t() builds an empty one
ida_typeinf.tinfo_t = lambda other=None: other if other is not None else FakeTif()
ida_typeinf.udt_type_data_t = FakeUdt
ida_typeinf.func_type_data_t = FakeFtd
ida_typeinf.CM_CC_STDCALL = 80
ida_typeinf.CM_CC_LAST_USERCALL = 255
sys.modules["ida_typeinf"] = ida_typeinf

ida_nalt = types.ModuleType("ida_nalt")
ida_nalt.get_tinfo = lambda tif, ea: True
sys.modules["ida_nalt"] = ida_nalt


class FakeRegvar:
    canon, user, cmt = "rax", "i", "loop counter"
    start_ea, end_ea = FRAME_FUNC, 0x1100


class FakeRegvars:
    def __init__(self):
        self._items = []

    def push_back(self, item):
        self._items.append(item)

    def __iter__(self):
        return iter(self._items)


ida_frame = types.ModuleType("ida_frame")
ida_frame.get_func_frame = lambda tif, pfn: pfn.start_ea == FRAME_FUNC
ida_frame.soff_to_fpoff = lambda pfn, frameoff: frameoff - 0x38
ida_frame.is_funcarg_off = lambda pfn, frameoff: frameoff >= 0x40
ida_frame.get_func_regvar_qty = lambda ea: 1 if ea == FRAME_FUNC else 0


def _get_func_regvars(out, ea):
    if ea == FRAME_FUNC:
        out.push_back(FakeRegvar())
    return True


ida_frame.get_func_regvars = _get_func_regvars
ida_frame.regvars_t = FakeRegvars
sys.modules["ida_frame"] = ida_frame

idc = types.ModuleType("idc")
idc.get_frame_size = lambda ea: 0x40 if ea == FRAME_FUNC else 0
idc.get_frame_args_size = lambda ea: 0x10 if ea == FRAME_FUNC else 0
idc.get_frame_regs_size = lambda ea: 0x8 if ea == FRAME_FUNC else 0
sys.modules["idc"] = idc

for _name in ("ida_bytes", "ida_gdl", "ida_name", "idautils"):
    sys.modules[_name] = types.ModuleType(_name)


# =========================================================================
# Load compat.py + api_functions.py (relative imports redirected to stubs)
# =========================================================================

HERE = os.path.dirname(os.path.abspath(__file__))
PKG = os.path.join(HERE, "..", "ida_mcp")

compat = types.ModuleType("functions_test_compat")
exec(compile(open(os.path.join(PKG, "compat.py"), encoding="utf-8").read(),
             "functions_test_compat", "exec"), compat.__dict__)
sys.modules["functions_test_compat"] = compat

analysis = types.ModuleType("functions_test_analysis")
analysis.parse_addr = lambda s: (int(str(s).strip(), 16) if str(s).strip().startswith("0x")
                                 else int(str(s).strip()))
analysis.type_label = lambda tif: tif.get_type_name() or tif.dstr() or "<unnamed>"
sys.modules["functions_test_analysis"] = analysis

src = open(os.path.join(PKG, "api_functions.py"), encoding="utf-8").read()
src = src.replace("from .rpc import tool, unsafe", "tool = lambda f: f\nunsafe = lambda f: f")
src = src.replace("from .sync import idasync", "idasync = lambda f: f")
src = src.replace("from .api_analysis import ", "from functions_test_analysis import ")
src = src.replace("from .compat import ", "from functions_test_compat import ")
mod = types.ModuleType("functions_test")
exec(compile(src, "functions_test", "exec"), mod.__dict__)
sys.modules["functions_test"] = mod

# =========================================================================
# Tests
# =========================================================================

# --- function flags: FUNC_STATICDEF (renamed from FUNC_STATIC) -----------
r = json.loads(mod.get_function_flags("0x1000"))
assert r["is_static"] is True, r
assert r["is_thunk"] is False and r["is_library"] is False, r
assert r["flags_raw"] == 0x100, r
print("get_function_flags FUNC_STATICDEF OK")

# --- frame sizes via idc (frame_t is gone) -------------------------------
r = json.loads(mod.get_function_frame_size("0x1000"))
assert r["frame_size"] == 0x40, r
assert r["args_size"] == 0x10 and r["saved_regs_size"] == 0x8, r
r = json.loads(mod.get_function_frame_size("0x2000"))
assert "No frame" in r["error"], r
r = json.loads(mod.get_function_args_size("0x1000"))
assert r["args_size"] == 0x10, r
r = json.loads(mod.get_function_args_size("0x2000"))
assert "No frame" in r["error"], r
print("frame size/args tools OK")

# --- local variables from the frame tinfo --------------------------------
r = json.loads(mod.get_local_variables("0x1000"))
assert [v["name"] for v in r["vars"]] == ["DestinationString", "__return_address", "arg_0"], r
byname = {v["name"]: v for v in r["vars"]}
assert byname["DestinationString"]["offset"] == -24, byname  # fp-relative soff
assert byname["DestinationString"]["size"] == 16, byname
assert byname["DestinationString"]["type"] == "local", byname
assert byname["DestinationString"]["type_info"] == "_UNICODE_STRING", byname
assert byname["__return_address"]["offset"] == 0, byname
assert byname["arg_0"]["offset"] == 8, byname
assert byname["arg_0"]["type"] == "argument", byname
assert byname["arg_0"]["type_info"] == "_QWORD", byname  # anonymous -> declaration
assert r["count"] == 3, r
print("get_local_variables (frame tinfo) OK")

r = json.loads(mod.get_local_variables("0x2000"))
assert r["vars"] == [] and "No frame" in r["message"], r
print("get_local_variables frameless OK")

# _collect_frame_vars is what the api_query local-variable tools reuse
assert [v["name"] for v in mod._collect_frame_vars(_funcs[0x1000])] == \
    ["DestinationString", "__return_address", "arg_0"]
assert mod._collect_frame_vars(_funcs[0x2000]) == []
print("_collect_frame_vars OK")

# --- register variables come from the regvar API -------------------------
r = json.loads(mod.get_register_variables("0x1000"))
assert r["count"] == 1, r
rv = r["regvars"][0]
assert rv["name"] == "i" and rv["register"] == "rax", rv
assert rv["start_ea"] == "0x1000" and rv["end_ea"] == "0x1100", rv
assert rv["comment"] == "loop counter", rv
r = json.loads(mod.get_register_variables("0x2000"))
assert r["regvars"] == [] and r["count"] == 0, r
print("get_register_variables (regvars_t) OK")

# --- signature: cc comes from func_type_data_t.get_cc() ------------------
r = json.loads(mod.get_function_signature("0x1000"))
assert r["calling_convention"] == "stdcall", r
assert r["return_type"] == "int", r
assert r["arguments"] == [{"name": "argc", "type": "int"}], r
print("get_function_signature cc OK")

print("ALL FUNCTIONS TESTS PASSED")
