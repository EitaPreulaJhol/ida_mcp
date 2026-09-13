"""Instruction analysis tools — decode, inspect, and classify instructions.

Tools ported from idamcp-extendedtools api_instructions.py, adapted for direct
in-process IDA SDK access.
"""

import json

import ida_auto
import ida_bytes
import ida_lines
import ida_name
import ida_ua
import idaapi
import idautils
import idc

from .rpc import tool
from .sync import idasync
from .api_analysis import parse_addr


def _decode_insn(ea: int) -> tuple:
    """Decode an instruction at ea. Returns (insn, success) or (None, False)."""
    insn = ida_ua.insn_t()
    if ida_ua.decode_insn(insn, ea) > 0:
        return insn, True
    return None, False


def _insn_to_dict(ea: int, insn) -> dict:
    """Convert a decoded instruction to a JSON-serializable dict."""
    result: dict = {
        "addr": hex(ea),
        "mnemonic": insn.get_canon_mnem(),
        "size": insn.size,
        "disasm": ida_lines.tag_remove(ida_lines.generate_disasm_line(ea, 0) or ""),
    }
    name = ida_name.get_ea_name(ea)
    if name:
        result["label"] = name

    # Operands
    operands: list[dict] = []
    for i, op in enumerate(insn.ops):
        if op.type == ida_ua.o_void:
            continue
        op_dict: dict = {"index": i}
        if op.type == ida_ua.o_reg:
            op_dict["type"] = "register"
            op_dict["register"] = ida_ua.get_reg_name(op.reg, insn.size)
        elif op.type == ida_ua.o_mem:
            op_dict["type"] = "memory"
            op_dict["address"] = hex(op.addr) if op.addr != idaapi.BADADDR else None
            op_dict["phrase"] = op.dtype
        elif op.type in (ida_ua.o_near, ida_ua.o_far):
            op_dict["type"] = "near"
            op_dict["address"] = hex(op.addr) if op.addr != idaapi.BADADDR else None
        elif op.type == ida_ua.o_imm:
            op_dict["type"] = "immediate"
            op_dict["value"] = op.value
        else:
            op_dict["type"] = f"unknown({op.type})"
        operands.append(op_dict)

    result["operands"] = operands
    result["operand_count"] = len(operands)
    return result


# ===========================================================================
# Tools
# ===========================================================================


@tool
@idasync
def get_instruction(address: str) -> str:
    """Get instruction details at an address (mnemonic, disassembly, operands, size).

    Returns a JSON object with full instruction metadata.
    """
    ida_auto.auto_wait()
    try:
        ea = parse_addr(address)
    except ValueError as e:
        return json.dumps({"error": str(e)})

    insn, ok = _decode_insn(ea)
    if not ok:
        return json.dumps({"error": f"No instruction at {hex(ea)}"})

    return json.dumps(_insn_to_dict(ea, insn), indent=2)


@tool
@idasync
def get_instructions(
    address: str,
    count: int = 50,
) -> str:
    """Get instructions for a function or starting address.

    ``count``: maximum number of instructions to return (max 500).
    """
    ida_auto.auto_wait()
    try:
        ea = parse_addr(address)
    except ValueError as e:
        return json.dumps({"error": str(e)})

    count = min(max(int(count), 1), 500)
    results: list[dict] = []

    for _ in range(count):
        if ea == idaapi.BADADDR:
            break
        insn, ok = _decode_insn(ea)
        if not ok:
            break
        results.append(_insn_to_dict(ea, insn))
        ea = idc.next_head(ea, idaapi.BADADDR)

    return json.dumps({"instructions": results, "count": len(results)}, indent=2)


@tool
@idasync
def get_operands(address: str) -> str:
    """Get all operands for an instruction at the given address."""
    ida_auto.auto_wait()
    try:
        ea = parse_addr(address)
    except ValueError as e:
        return json.dumps({"error": str(e)})

    insn, ok = _decode_insn(ea)
    if not ok:
        return json.dumps({"error": f"No instruction at {hex(ea)}"})

    info = _insn_to_dict(ea, insn)
    return json.dumps({"addr": hex(ea), "operands": info["operands"]}, indent=2)


@tool
@idasync
def get_operand(
    address: str,
    index: int = 0,
) -> str:
    """Get a specific operand by index for an instruction."""
    ida_auto.auto_wait()
    try:
        ea = parse_addr(address)
    except ValueError as e:
        return json.dumps({"error": str(e)})

    insn, ok = _decode_insn(ea)
    if not ok:
        return json.dumps({"error": f"No instruction at {hex(ea)}"})

    if index >= len(insn.ops) or insn.ops[index].type == ida_ua.o_void:
        return json.dumps({"error": f"No operand {index} at {hex(ea)}"})

    info = _insn_to_dict(ea, insn)
    if index < len(info.get("operands", [])):
        return json.dumps({"addr": hex(ea), "operand": info["operands"][index]}, indent=2)
    return json.dumps({"error": f"Invalid operand index {index}"})


@tool
@idasync
def get_operands_count(address: str) -> str:
    """Get the number of operands for an instruction."""
    ida_auto.auto_wait()
    try:
        ea = parse_addr(address)
    except ValueError as e:
        return json.dumps({"error": str(e)})

    insn, ok = _decode_insn(ea)
    if not ok:
        return json.dumps({"error": f"No instruction at {hex(ea)}"})

    info = _insn_to_dict(ea, insn)
    return json.dumps({"addr": hex(ea), "count": info["operand_count"]})


@tool
@idasync
def get_mnemonic(address: str) -> str:
    """Get the mnemonic of an instruction (e.g., 'mov', 'call', 'jmp')."""
    ida_auto.auto_wait()
    try:
        ea = parse_addr(address)
    except ValueError as e:
        return json.dumps({"error": str(e)})

    insn, ok = _decode_insn(ea)
    if not ok:
        return json.dumps({"error": f"No instruction at {hex(ea)}"})

    return json.dumps({"addr": hex(ea), "mnemonic": insn.get_canon_mnem()})


@tool
@idasync
def get_instruction_size(address: str) -> str:
    """Get the size of an instruction in bytes."""
    ida_auto.auto_wait()
    try:
        ea = parse_addr(address)
    except ValueError as e:
        return json.dumps({"error": str(e)})

    insn, ok = _decode_insn(ea)
    if not ok:
        return json.dumps({"error": f"No instruction at {hex(ea)}"})

    return json.dumps({"addr": hex(ea), "size": insn.size})


# ===========================================================================
# Instruction Predicates
# ===========================================================================


@tool
@idasync
def is_call_instruction(address: str) -> str:
    """Check if the instruction at the given address is a call."""
    ida_auto.auto_wait()
    try:
        ea = parse_addr(address)
    except ValueError as e:
        return json.dumps({"error": str(e)})

    insn, ok = _decode_insn(ea)
    if not ok:
        return json.dumps({"error": f"No instruction at {hex(ea)}"})

    return json.dumps({"addr": hex(ea), "is_call": insn.get_canon_mnem() in ("call", "callx")})


@tool
@idasync
def is_jump_instruction(address: str) -> str:
    """Check if the instruction is a jump (conditional or unconditional)."""
    ida_auto.auto_wait()
    try:
        ea = parse_addr(address)
    except ValueError as e:
        return json.dumps({"error": str(e)})

    insn, ok = _decode_insn(ea)
    if not ok:
        return json.dumps({"error": f"No instruction at {hex(ea)}"})

    mnem = insn.get_canon_mnem().lower()
    is_jmp = mnem.startswith("j") or mnem in ("jmp", "jmpx")
    return json.dumps({"addr": hex(ea), "is_jump": is_jmp, "mnemonic": insn.get_canon_mnem()})


@tool
@idasync
def is_ret_instruction(address: str) -> str:
    """Check if the instruction is a return instruction."""
    ida_auto.auto_wait()
    try:
        ea = parse_addr(address)
    except ValueError as e:
        return json.dumps({"error": str(e)})

    insn, ok = _decode_insn(ea)
    if not ok:
        return json.dumps({"error": f"No instruction at {hex(ea)}"})

    mnem = insn.get_canon_mnem().lower()
    return json.dumps({"addr": hex(ea), "is_ret": mnem in ("ret", "retn", "retf")})


@tool
@idasync
def is_conditional_jump(address: str) -> str:
    """Check if the instruction is a conditional jump."""
    ida_auto.auto_wait()
    try:
        ea = parse_addr(address)
    except ValueError as e:
        return json.dumps({"error": str(e)})

    insn, ok = _decode_insn(ea)
    if not ok:
        return json.dumps({"error": f"No instruction at {hex(ea)}"})

    mnem = insn.get_canon_mnem().lower()
    is_cond = mnem.startswith("j") and mnem not in ("jmp", "jmpx")
    return json.dumps({"addr": hex(ea), "is_conditional_jump": is_cond, "mnemonic": insn.get_canon_mnem()})


@tool
@idasync
def is_indirect_jump(address: str) -> str:
    """Check if the instruction is an indirect jump (target via register/memory)."""
    ida_auto.auto_wait()
    try:
        ea = parse_addr(address)
    except ValueError as e:
        return json.dumps({"error": str(e)})

    insn, ok = _decode_insn(ea)
    if not ok:
        return json.dumps({"error": f"No instruction at {hex(ea)}"})

    mnem = insn.get_canon_mnem().lower()
    is_jump = mnem.startswith("j")
    indirect = False
    if is_jump:
        target_types = [op.type for op in insn.ops if op.type != ida_ua.o_void]
        indirect = bool(target_types) and target_types[0] not in (ida_ua.o_near, ida_ua.o_far)
    return json.dumps({"addr": hex(ea), "is_indirect_jump": indirect,
                       "mnemonic": insn.get_canon_mnem()})


@tool
@idasync
def get_operand_info(address: str, index: int = 0) -> str:
    """Get extended detail for one operand: kind, dtype, registers, values.

    Reports operand type (register/memory/near/immediate/phrase/displacement),
    data-type width, involved registers, memory address or immediate value,
    and whether the operand is read, written or both (via ``specflag`` bits
    when the processor module provides them).
    """
    ida_auto.auto_wait()
    try:
        ea = parse_addr(address)
    except ValueError as e:
        return json.dumps({"error": str(e)})

    insn, ok = _decode_insn(ea)
    if not ok:
        return json.dumps({"error": f"No instruction at {hex(ea)}"})

    ops = [op for op in insn.ops if op.type != ida_ua.o_void]
    if index < 0 or index >= len(ops):
        return json.dumps({"error": f"Operand index {index} out of range (0-{len(ops) - 1})"})
    op = ops[index]
    info: dict = {"addr": hex(ea), "index": index, "dtype": op.dtype}
    if op.type == ida_ua.o_reg:
        info["type"] = "register"
        try:
            info["register"] = ida_ua.get_reg_name(op.reg, insn.size)
        except Exception:
            info["register"] = op.reg
        info["reg_no"] = op.reg
    elif op.type == ida_ua.o_mem:
        info["type"] = "memory"
        info["address"] = hex(op.addr) if op.addr != idaapi.BADADDR else None
    elif op.type in (ida_ua.o_near, ida_ua.o_far):
        info["type"] = "near" if op.type == ida_ua.o_near else "far"
        info["address"] = hex(op.addr) if op.addr != idaapi.BADADDR else None
    elif op.type == ida_ua.o_imm:
        info["type"] = "immediate"
        info["value"] = op.value
        info["hex"] = hex(op.value & 0xFFFFFFFFFFFFFFFF)
    elif op.type in (getattr(ida_ua, "o_phrase", -1), getattr(ida_ua, "o_displ", -2)):
        info["type"] = "phrase" if op.type == getattr(ida_ua, "o_phrase", -1) else "displacement"
        try:
            info["base_register"] = ida_ua.get_reg_name(op.reg, insn.size)
        except Exception:
            info["base_register"] = op.reg
        info["offset"] = op.addr
    else:
        info["type"] = f"unknown({op.type})"
    return json.dumps(info, indent=2)


@tool
@idasync
def breaks_flow(address: str) -> str:
    """Check if the instruction breaks sequential flow (ret, jmp, call, etc.)."""
    ida_auto.auto_wait()
    try:
        ea = parse_addr(address)
    except ValueError as e:
        return json.dumps({"error": str(e)})

    insn, ok = _decode_insn(ea)
    if not ok:
        return json.dumps({"error": f"No instruction at {hex(ea)}"})

    mnem = insn.get_canon_mnem().lower()
    is_break = mnem in ("ret", "retn", "retf", "jmp", "jmpx", "call", "callx")
    return json.dumps({"addr": hex(ea), "breaks_flow": is_break, "mnemonic": insn.get_canon_mnem()})


@tool
@idasync
def get_instruction_bytes(address: str) -> str:
    """Get the raw bytes of an instruction as hex string."""
    ida_auto.auto_wait()
    try:
        ea = parse_addr(address)
    except ValueError as e:
        return json.dumps({"error": str(e)})

    insn, ok = _decode_insn(ea)
    if not ok:
        return json.dumps({"error": f"No instruction at {hex(ea)}"})

    raw = ida_bytes.get_bytes(ea, insn.size)
    return json.dumps({"addr": hex(ea), "bytes": raw.hex() if raw else None, "size": insn.size})


@tool
@idasync
def get_instructions_in_range(
    start: str,
    end: str,
) -> str:
    """Get all instructions in an address range."""
    ida_auto.auto_wait()
    try:
        start_ea = parse_addr(start)
        end_ea = parse_addr(end)
    except ValueError as e:
        return json.dumps({"error": str(e)})

    results: list[dict] = []
    ea = start_ea
    while ea < end_ea and len(results) < 500:
        insn, ok = _decode_insn(ea)
        if ok:
            results.append(_insn_to_dict(ea, insn))
            ea += insn.size
        else:
            ea += 1

    return json.dumps({"instructions": results, "count": len(results), "start": hex(start_ea), "end": hex(end_ea)}, indent=2)
