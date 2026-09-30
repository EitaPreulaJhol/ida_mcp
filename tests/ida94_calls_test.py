"""Tests for the IDA 9.4 call sites in api_comments / api_modify / api_segments /
api_instructions.

Runs the real ``compat.py`` against 9.4-shaped stubs and execs the four modules,
so the rewritten calls (extra comments, original bytes, segment comment,
register name) are covered outside IDA — including the shadowing trap where a
tool shares its name with the compat helper it has to call.
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

# --- extra comments: 9.4 keeps only E_PREV/E_NEXT + the free-index probe ---
_extra = {1000: "line A", 1001: "line B"}

ida_lines = types.ModuleType("ida_lines")
ida_lines.E_PREV = 1000
ida_lines.E_NEXT = 2000
ida_lines.get_first_free_extra_cmtidx = lambda ea, start: start + len(_extra)
ida_lines.get_extra_cmt = lambda ea, what: _extra.get(what)
ida_lines.tag_remove = lambda s: s
ida_lines.generate_disasm_line = lambda ea, flags=0: "mov rbx, rax"
sys.modules["ida_lines"] = ida_lines

# --- original bytes: 9.4 dropped the bulk reader --------------------------
_original = {0x1000 + i: 0xA0 + i for i in range(8)}

ida_bytes = types.ModuleType("ida_bytes")
ida_bytes.get_original_byte = lambda ea: _original.get(ea, 0)
sys.modules["ida_bytes"] = ida_bytes

# --- segment comment: get_segm_cmt -> get_segment_cmt ---------------------
class FakeSeg:
    start_ea, end_ea = 0x1000, 0x2000


ida_segment = types.ModuleType("ida_segment")
ida_segment.getseg = lambda ea: FakeSeg() if ea < 0x2000 else None
ida_segment.get_segm_name = lambda seg: ".text"
ida_segment.get_segment_cmt = lambda seg, repeatable: "segment comment"
sys.modules["ida_segment"] = ida_segment

# --- register name: ida_ua -> ida_idp -------------------------------------
# width-sensitive on purpose: the old call passed the *instruction* size
ida_idp = types.ModuleType("ida_idp")
ida_idp.get_reg_name = lambda reg, width: {1: {8: "rbx", 4: "ebx"}}.get(reg, {}).get(width)
sys.modules["ida_idp"] = ida_idp

# --- instructions ---------------------------------------------------------
class FakeOp:
    def __init__(self, otype, reg=0, addr=0, value=0, dtype=0):
        self.type = otype
        self.reg = reg
        self.addr = addr
        self.value = value
        self.dtype = dtype


class FakeInsn:
    def __init__(self):
        self.size = 4
        self.ops = [FakeOp(1, reg=1), FakeOp(0)]   # o_reg, then o_void

    def get_canon_mnem(self):
        return "mov"


ida_ua = types.ModuleType("ida_ua")
ida_ua.o_void, ida_ua.o_reg, ida_ua.o_mem = 0, 1, 2
ida_ua.o_near, ida_ua.o_far, ida_ua.o_imm = 3, 4, 5
ida_ua.decode_insn = lambda insn, ea: 4
ida_ua.get_dtype_size = lambda dtype: 8   # register operands are 64-bit here
ida_ua.insn_t = FakeInsn
sys.modules["ida_ua"] = ida_ua

ida_name = types.ModuleType("ida_name")
ida_name.get_ea_name = lambda ea: "sub_1000"
sys.modules["ida_name"] = ida_name

for _name in ("idautils", "idc", "ida_nalt", "ida_funcs"):
    sys.modules[_name] = types.ModuleType(_name)



# =========================================================================
# Load compat.py + the four modules (relative imports redirected to stubs)
# =========================================================================

HERE = os.path.dirname(os.path.abspath(__file__))
PKG = os.path.join(HERE, "..", "ida_mcp")

compat = types.ModuleType("calls_test_compat")
exec(compile(open(os.path.join(PKG, "compat.py"), encoding="utf-8").read(),
             "calls_test_compat", "exec"), compat.__dict__)
sys.modules["calls_test_compat"] = compat

analysis = types.ModuleType("calls_test_analysis")
analysis.parse_addr = lambda s: (int(str(s).strip(), 16) if str(s).strip().startswith("0x")
                                 else int(str(s).strip()))
analysis.type_label = lambda tif: "<unnamed>"
sys.modules["calls_test_analysis"] = analysis

rpc = types.ModuleType("calls_test_rpc")
rpc.tool = lambda f: f
rpc.unsafe = lambda f: f
rpc.MCP_SERVER = type("Fake", (), {"unsafe_tools": set()})()
sys.modules["calls_test_rpc"] = rpc

sync = types.ModuleType("calls_test_sync")
sync.idasync = lambda f: f
sys.modules["calls_test_sync"] = sync


def _load(name, filename):
    src = open(os.path.join(PKG, filename), encoding="utf-8").read()
    src = src.replace("from .rpc import ", "from calls_test_rpc import ")
    src = src.replace("from .sync import ", "from calls_test_sync import ")
    src = src.replace("from .api_analysis import ", "from calls_test_analysis import ")
    src = src.replace("from .compat import ", "from calls_test_compat import ")
    mod = types.ModuleType(name)
    exec(compile(src, name, "exec"), mod.__dict__)
    sys.modules[name] = mod
    return mod


comments = _load("calls_test_comments", "api_comments.py")
modify = _load("calls_test_modify", "api_modify.py")
segments = _load("calls_test_segments", "api_segments.py")
instructions = _load("calls_test_instructions", "api_instructions.py")

# =========================================================================
# Tests
# =========================================================================

# --- get_extra_comments: E_PREV + first free index -----------------------
r = json.loads(comments.get_extra_comments("0x1000"))
assert r["extra_comments"] == ["line A", "line B"], r
assert r["count"] == 2, r
print("get_extra_comments (first_free_extra_cmtidx) OK")

# --- get_original_bytes: per-byte fallback -------------------------------
r = json.loads(modify.get_original_bytes("0x1000", size=4))
assert r["size"] == 4 and r["hex"] == "a0a1a2a3", r
print("get_original_bytes (per-byte) OK")

# --- get_segment_comment: renamed API, and no self-recursion -------------
r = json.loads(segments.get_segment_comment("0x1000"))
assert r == {"name": ".text", "comment": "segment comment"}, r
print("get_segment_comment (get_segment_cmt) OK")

# --- register names come from ida_idp ------------------------------------
r = json.loads(instructions.get_instruction("0x1000"))
assert r["operands"] == [{"index": 0, "type": "register", "register": "rbx"}], r
r = json.loads(instructions.get_operand_info("0x1000", 0))
assert r["register"] == "rbx" and r["reg_no"] == 1, r
r = json.loads(instructions.get_operand_info("0x1000", 1))  # o_void is skipped
assert "out of range" in r["error"], r
print("register name via ida_idp OK")

print("ALL IDA94 CALLS TESTS PASSED")
