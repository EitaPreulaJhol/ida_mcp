# IDA Pro Deobfuscation Guide

> **Environment:** IDA Pro 8.3+ with Hex-Rays (9.3 recommended) | All `ida_*` modules available via `execute_script` (`?unsafe=true`)

Full tool listing in `tools.md`. Recognition patterns and methodology in `algorithm-reference.md`. Microcode reading/writing reference in `microcode-guide.md`.

## Two Deobfuscation Paths (`?unsafe=true` for both)

### Path A: Read-only analysis + annotation (start here)

Read first, write nothing. This covers most string decryption and triage.

```
1. get_microcode("0x401000")  — read the microcode summary, identify patterns
2. get_flowchart               — block/CFG structure (dispatchers, junk blocks)
3. decompile_function          — confirm the reading in pseudocode
4. set_comment / set_name      — annotate decode stubs, dispatchers, handlers
```

### Path B: `execute_script` + `ida_hexrays` (for real modification)

Use when you need direct microcode/ctree access — e.g. CFF unflattening or
pattern rewriting across a function. Everything runs inside `execute_script`
(all `ida_*` modules available; assign `result`, `print()` is captured).

```python
import ida_hexrays

# Per-instruction visitor: pattern-match and rewrite in place
class Simplify(ida_hexrays.ctree_visitor_t):
    def __init__(self):
        super().__init__(ida_hexrays.CV_FAST)

    def visit_expr(self, e):
        # e.g. fold opaque predicates / MBA-on-constants here
        return 0

cfunc = ida_hexrays.decompile(func_ea)
Simplify().apply_to(cfunc.body, None)
ida_hexrays.mark_cfunc_dirty(func_ea)  # MUST invalidate cache
result = "visitor applied"
```
Then `force_recompile("0x401000")` + re-read `decompile_function` to verify.
For byte-level rewiring (jump targets, NOP padding) use `patch_bytes` instead.

### When to Use Which

| Scenario | Path |
|---|---|
| Pattern-based simplification (opaque predicates, MBA, junk) | B — `execute_script` with a ctree visitor |
| NOP specific known-bad addresses | `patch_bytes` (`0x90` fill) + `force_recompile` |
| CFF unflattening (need block-level CFG rewriting) | B — visitor with full function access, or byte-level rewiring |
| Complex multi-pass with state across blocks | B — `execute_script` with persistent state |
| String decryption (xref walking + annotation) | A — built-in tools (`get_xrefs_to`, `set_comment`) |
| Symbolic solving (z3) | B — `execute_script` |

## Technique Rules

### CFF (Control Flow Flattening)

- Run at `MMAT_PREOPTIMIZED` or `MMAT_LOCOPT`. **Never** at `MMAT_LVARS` (maturity ≥ 6).
- State variable = highest constant comparison frequency — **no entropy filtering**. State values may not look random.
- Assume **multiple dispatchers** — any block comparing the state var is a dispatcher.
- Handler = non-dispatcher target for a given state value.
- After rewiring handlers, NOP all state variable assignments.
- Call `blk.mark_lists_dirty()` per modified block, `mba.mark_chains_dirty()` after all changes.
- Let Hex-Rays prune dead dispatcher blocks in the next locopt pass.

### Opaque Predicates

- Handle in optimizer callback: detect conditional jumps where one operand is a constant at decompile time.
- Always-true: force `m_goto` to the taken target.
- Always-false: `m_nop` the branch instruction.
- Hex-Rays automatically cleans dead blocks in the next locopt pass.
- For non-trivially-constant predicates (e.g., `x*(x-1)%2 == 0`), use z3 via `execute_script` to prove the predicate, then install an optimizer to force it.

### MBA (Mixed Boolean-Arithmetic)

- In optimizer callback: match `minsn_t` patterns where both operands are constants, calculate simplified value, overwrite in-place with `m_mov` + `make_number`.
- Apply `(1 << (size * 8)) - 1` bitmask when constant-folding to handle unsigned overflow.
- For symbolic MBA (operands aren't constants), consider z3 or pattern-matching known identities:
  - `(x ^ y) + 2*(x & y)` → `x + y`
  - `(x | y) - (x & ~y)` → `y`
  - `~(~x & ~y)` → `x | y`
  - `(x & 0xFF) | (x & ~0xFF)` → `x`

### Bogus Control Flow (BCF)

- OLLVM BCF adds conditional jumps with opaque predicates branching to junk blocks.
- Detect: block with an opaque predicate where one successor contains junk (no real data flow contribution).
- Remove: force the opaque predicate (same as opaque predicate removal), then dead block elimination handles junk.

### Instruction Substitution

- OLLVM replaces simple ops with equivalent complex sequences.
- Common patterns (match and reverse):
  - `a + b` → `a - (-b)`, `(a ^ b) + 2*(a & b)`, `(a | b) + (a & b)`
  - `a - b` → `a + (-b)`, `(a ^ b) - 2*(~a & b)`
  - `a ^ b` → `(a | b) - (a & b)`, `(~a & b) | (a & ~b)`
  - `a & b` → `(a | b) - (a ^ b)`, `~(~a | ~b)`
  - `a | b` → `(a & b) + (a ^ b)`, `~(~a & ~b)`
- Use instruction optimizer to pattern-match and replace.
- Multiple passes may be needed (substitutions can be chained).

### Dead Code / Junk Instructions

- Instructions computing values never used.
- In optimizer: if an instruction writes to a register/variable that has no uses before its next definition, NOP it.
- At microcode level: `m_mov` to a variable that is immediately overwritten → dead store → NOP.

### Anti-Disassembly

- Junk bytes after unconditional jumps confuse linear disassembly.
- Pattern: `jmp +2; db 0xE8` (fake call prefix).
- Fix at byte level via `execute_script`: `ida_bytes.patch_byte(ea, 0x90)` to NOP junk bytes, or redefine function boundaries.
- IDA usually handles this at the assembly level — check disassembly first.

## Critical Rules

| Rule | Detail |
|---|---|
| **Maturity guard** | ALWAYS check `mba.maturity >= 6` and return 0. Never modify at MMAT_LVARS or later |
| **Operand equality** | Always `a.equal_mops(b, EQ_IGNSIZE)` — never bare `.equal_mops(b)` |
| **In-place mutation** | Never instantiate new `minsn_t`. Overwrite opcodes and erase operands on existing ones |
| **Mark dirty** | After modifying a block: `blk.mark_lists_dirty()`. After a pass with changes: `mba.mark_chains_dirty()` |
| **NOP operands** | When NOPing: set `ins.opcode = m_nop`, then `ins.l.erase()`, `ins.r.erase()`, `ins.d.erase()` |
| **State variable** | No entropy filtering — find the variable with highest constant comparison frequency |
| **Dispatchers** | Assume multiple dispatcher blocks — any block comparing state var is a dispatcher |
| **Cache invalidation** | Always call `ida_hexrays.mark_cfunc_dirty()` via `execute_script` before re-decompiling |
| **`force_recompile` after** | After installing/removing optimizers, call `force_recompile` to see the effect |
| **Iterative passes** | Complex obfuscation needs multiple passes — install optimizer, `force_recompile`, check, refine |

## String Decryption

```
1. list_strings / search_strings → very few readable strings → encrypted
2. func_query for small frequently-called functions → decode stub candidates
3. get_xrefs_to(decode_func) → all call sites
4. decompile_function(caller) → trace arguments to find encrypted data + key
5. execute_script → reimplement decode logic, compute plaintext
6. set_comment at each call site → "decrypted: <plaintext>"
7. set_name(decode_func, "decrypt_string")
```

## Troubleshooting

**No change after `execute_script`:**
- Did you call `ida_hexrays.mark_cfunc_dirty(ea)` inside the script, then `force_recompile()`? The decompiler caches per function.
- Print intermediate state (`print()` is captured) to confirm your visitor matched.

**Crash / internal error after microcode edit:**
- You likely modified at MMAT_LVARS or later. Add maturity guard.
- Verify you're modifying in-place, not creating new `minsn_t` objects.

**CFF not detected:**
- Entropy filtering removed state variable candidates — remove any entropy filter.
- Check for multiple dispatchers; not all comparisons may be `m_jz`.
- State variable may be a memory operand (`mop_S` stack var) not a register (`mop_r`).

**State variable rewired but CFG still wrong:**
- Jump target was an address (`mop_v`/`mop_a`), not a block ref (`mop_b`). Convert with `make_blkref()`.

**Optimizer runs but no visible change:**
- Pattern may not match at the maturity level the optimizer fires at. Try reading microcode at different levels.
- The decompiler may re-optimize your changes away. Try a different approach or maturity level.
