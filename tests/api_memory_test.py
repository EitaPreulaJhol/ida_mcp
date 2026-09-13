"""Tests for api_memory.py (scalar readers, head navigation).

Stubs IDA modules and loads the source via exec.
"""
import json
import os
import struct
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

_MEM = {0x1000: bytes([0x41, 0x42, 0x43, 0x44, 0x00, 0xC3, 0xF5, 0x48])}
_BSS = (0x2000, 0x2100)
_HEADS = [0x1000, 0x1004, 0x1008]


def _in_bss(ea):
    return _BSS[0] <= ea < _BSS[1]


ida_bytes = types.ModuleType("ida_bytes")
ida_bytes.get_item_size = lambda ea: 4
ida_bytes.get_flags = lambda ea: 0x600 if ea == 0x1000 else 0x400
ida_bytes.is_code = lambda flags: flags == 0x600
ida_bytes.is_data = lambda flags: flags == 0x400
ida_bytes.get_strlit_contents = lambda ea, length=-1, strtype=0: b"ABC" if ea == 0x1000 else None


def _next_head(ea, maxea):
    for h in _HEADS:
        if h > ea and h < maxea:
            return h
    return -1


def _prev_head(ea, minea):
    for h in reversed(_HEADS):
        if h < ea and h >= minea:
            return h
    return -1


ida_bytes.next_head = _next_head
ida_bytes.prev_head = _prev_head
ida_bytes.next_addr = lambda ea: _next_head(ea, 0x3000)
ida_bytes.prev_addr = lambda ea: _prev_head(ea, 0x1000)
sys.modules["ida_bytes"] = ida_bytes

ida_ida = types.ModuleType("ida_ida")
ida_ida.inf_is_be = lambda: False
sys.modules["ida_ida"] = ida_ida

ida_lines = types.ModuleType("ida_lines")
ida_lines.tag_remove = lambda s: s
ida_lines.generate_disasm_line = lambda ea, flags: f"mov eax, {ea:x}"
sys.modules["ida_lines"] = ida_lines

idautils = types.ModuleType("idautils")
idautils.Heads = lambda start, end: iter([h for h in _HEADS if start <= h < end])
sys.modules["idautils"] = idautils

# =========================================================================
# Load api_memory.py
# =========================================================================

HERE = os.path.dirname(os.path.abspath(__file__))
PKG = os.path.join(HERE, "..", "ida_mcp")
src = open(os.path.join(PKG, "api_memory.py")).read()
src = src.replace("from .rpc import tool", "tool = lambda f: f")
src = src.replace("from .sync import idasync", "idasync = lambda f: f")
src = src.replace(
    "from .api_analysis import parse_addr, read_bytes_bss_safe",
    "def parse_addr(s):\n"
    "    s = str(s).strip()\n"
    "    if s.startswith('0x'): return int(s, 16)\n"
    "    try: return int(s)\n"
    "    except ValueError: raise ValueError(f'Unknown: {s}')\n"
    "def read_bytes_bss_safe(ea, size):\n"
    "    if 0x2000 <= ea < 0x2100: return bytes(size)\n"
    "    base = {0x1000: bytes([0x41, 0x42, 0x43, 0x44, 0x00, 0xC3, 0xF5, 0x48])}\n"
    "    for start, data in base.items():\n"
    "        if start <= ea < start + len(data):\n"
    "            return data[ea - start:ea - start + size]\n"
    "    return None",
)
src = src.replace(
    "from .compat import inf_get_max_ea, inf_get_min_ea, is_loaded",
    "inf_get_max_ea = lambda: 0x3000\n"
    "inf_get_min_ea = lambda: 0x1000\n"
    "is_loaded = lambda ea: not (0x2000 <= ea < 0x2100)",
)
mod = types.ModuleType("api_memory_test")
exec(compile(src, "api_memory_test", "exec"), mod.__dict__)
sys.modules["api_memory_test"] = mod

# =========================================================================
# Tests
# =========================================================================

assert json.loads(mod.get_byte("0x1000"))["value"] == 0x41
assert json.loads(mod.get_word("0x1000"))["value"] == 0x4241
assert json.loads(mod.get_dword("0x1000"))["value"] == 0x44434241
assert json.loads(mod.get_qword("0x1000"))["value"] == 0x48F5C30044434241
print("byte/word/dword/qword OK")

r = json.loads(mod.get_int("0x1005", "i8"))
assert r["value"] == -61, r  # 0xC3 signed
r = json.loads(mod.get_int("0x1005", "u8"))
assert r["value"] == 0xC3, r
r = json.loads(mod.get_int("0x1000", "bogus"))
assert "error" in r, r
print("get_int signed/unsigned/ty-error OK")

r = json.loads(mod.get_float("0x1004"))
assert r["value"] == struct.unpack("<f", bytes([0x00, 0xC3, 0xF5, 0x48]))[0], r
r = json.loads(mod.get_double("0x1000"))
assert r["value"] == struct.unpack("<d", bytes([0x41, 0x42, 0x43, 0x44, 0x00, 0xC3, 0xF5, 0x48]))[0], r
print("float/double OK")

r = json.loads(mod.get_cstring("0x1000"))
assert r["value"] == "ABC" and r["length"] == 3, r
r = json.loads(mod.get_cstring("0x9999"))
assert "error" in r, r
print("get_cstring OK")

r = json.loads(mod.get_global_value("0x2000"))  # BSS -> 0
assert r["value"] == 0 and r["size"] == 4, r
r = json.loads(mod.get_global_value("0x1000"))
assert r["value"] == 0x44434241, r
r = json.loads(mod.get_global_value("0x1000", size=3))
assert "error" in r, r
print("get_global_value OK")

assert json.loads(mod.get_data_size("0x1000"))["size"] == 4
assert json.loads(mod.get_data_flags("0x1000"))["flags"] == hex(0x600)
print("data_size/flags OK")

assert json.loads(mod.get_next_head("0x1000"))["next"] == "0x1004"
assert json.loads(mod.get_next_head("0x1008"))["next"] is None
assert json.loads(mod.get_prev_head("0x1004"))["prev"] == "0x1000"
assert json.loads(mod.get_next_addr("0x1000"))["next"] == "0x1004"
assert json.loads(mod.get_prev_addr("0x1000"))["prev"] is None
print("head/addr navigation OK")

r = json.loads(mod.get_heads("0x1000", "0x1010"))
assert r["heads"] == ["0x1000", "0x1004", "0x1008"] and r["truncated"] is False, r
print("get_heads OK")

assert json.loads(mod.is_code("0x1000"))["is_code"] is True
assert json.loads(mod.is_code("0x3000"))["is_code"] is False
assert json.loads(mod.is_data("0x3000"))["is_data"] is True
assert json.loads(mod.is_data("0x1000"))["is_data"] is False
print("is_code/is_data OK")

r = json.loads(mod.get_disassembly_text("0x1000", 2))
assert r["count"] == 2 and r["lines"][0].startswith("0x1000:"), r
r = json.loads(mod.get_disassembly_text("0x2000", 2))  # BSS not loaded
assert r["count"] == 0, r
print("get_disassembly_text OK")

r = json.loads(mod.get_byte("nope"))
assert "error" in r, r
print("bad address OK")

print("ALL MEMORY SCALAR TESTS PASSED")
