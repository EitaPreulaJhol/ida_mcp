---
name: firmware-re
description: Firmware analysis — embedded systems, unknown architectures, binary blobs, hardware interfaces, and proprietary file systems Use with IDA Pro via ida_mcp (triage-first, escalate per ladder).
compatibility: IDA Pro 8.3+ with the ida_mcp plugin (Hex-Rays for decompiler tools)
metadata:
  workflow: ida-pro-mcp-lazy
  ceiling: `?profile=readonly`
---

> **IDA-MCP adapter (read first).** This skill runs against the binary open in IDA Pro through ida_mcp.
> Start at `?profile=triage` (`server_health` → `survey_binary`), escalate top-down; ceiling for this skill: **`?profile=readonly`** — read-only ceiling — start at `?profile=triage`.
> Never request unsafe/dbg "just in case" — justify each escalation in one sentence. All addresses accept hex/symbol/dec; `decompile_function` returns plain text, everything else JSON.

All tool calls below are native ida_mcp tools.

---

Task: Firmware Reverse Engineering. You are analyzing embedded system firmware, often without standard debugging capabilities.

## Approach

Firmware analysis requires handling unknown architectures, proprietary formats, and binary blobs. Work backwards from the firmware structure to extract filesystems, understand hardware interfaces, and document functionality.

## When to Use

Use this skill when:
- Analyzing embedded system firmware and ROM dumps
- Reverse engineering proprietary file systems and formats
- Handling unknown architectures and instruction sets
- Extracting configuration data and embedded secrets
- Analyzing hardware interfaces and peripheral drivers
- Working with binary blobs without structure
- Understanding bootloaders and boot processes
- Extracting filesystems and resources from firmware

## Workflow

1. **Firmware Structure Analysis**
   - Identify firmware format and container structure
   - Parse headers and metadata
   - Map firmware sections and components
   - Identify compression and encryption
   - Verify checksums and integrity

2. **Decompression & Decryption**
   - Identify compression algorithms (LZMA, LZSS, Huffman, proprietary)
   - Decompress compressed sections
   - Detect encryption (encrypted firmware, obfuscated code)
   - Extract embedded filesystems (squashfs, cramfs, JFFS2, proprietary)

3. **Architecture Identification**
   - Identify instruction set architecture (ARM, MIPS, PowerPC, x86, unknown)
   - Determine endianness from magic bytes and code patterns
   - Find entry points and initialization code
   - Locate bootloader and kernel code

4. **Code Analysis**
   - Disassemble code sections for unknown ISAs
   - Identify function boundaries in binary blobs
   - Analyze bootloader and initialization
   - Locate peripheral drivers and hardware interfaces

5. **Hardware Interface Mapping**
   - Map memory-mapped I/O regions
   - Analyze hardware register accesses
   - Extract interrupt vector tables
   - Understand peripheral drivers (UART, SPI, I2C, timers)

6. **Resource Extraction**
   - Extract filesystems and files
   - Find configuration data and settings
   - Extract resources (images, fonts, strings)
   - Locate embedded secrets (keys, passwords, certificates)

## Firmware Formats

**Common Containers:**
- TRX, BIN, IMG: Generic firmware images
- Ubiquiti, TP-Link, Netgear: Vendor-specific formats
- D-Link, Belkin, Linksys: Various header structures
- Encrypted firmware: Many vendors encrypt firmware images

**Compression Schemes:**
- LZMA/LZMA2: High compression, common in embedded
- LZSS: Older devices, simpler compression
- gzip/zlib: Widespread compatibility
- Huffman: Custom implementations
- Proprietary: Vendor-specific algorithms

**Filesystems:**
- squashfs: Read-only compressed filesystem
- cramfs: Simple read-only filesystem
- JFFS2: Journaling flash filesystem
- YAFFS: NAND flash filesystem
- UBIFS: UBI filesystem
- Proprietary: Vendor-specific filesystems

## Architecture Identification

**ARM:**
- Function prologue: `push {r4-r7, lr}` or `stmdb sp!, {r4-r11,lr}`
- Common instructions: `bl` (call), `b` (jump), `ldr`, `str`
- THUMB mode: 16-bit instructions

**MIPS:**
- Function prologue: `addiu sp,sp,-XX` then `sw ra,XX(sp)`
- Delay slots: Branch instructions execute following instruction
- Common instructions: `jal` (call), `jr ra` (return)

**PowerPC:**
- Function prologue: `mflr r0`, `stw r0,4(sp)`, `stwu sp,-XX(sp)`
- Link register: `lr` holds return address

**Unknown ISAs:**
- Look for repetitive patterns that might be code
- Identify data sections (strings, tables)
- Search for standard magic bytes in code
- Use entropy analysis to find encrypted/compressed sections

## Hardware Interface Analysis

**Memory-Mapped I/O:**
- Register accesses often at fixed offsets
- Look for `ldr rX, [rY, #imm]` patterns
- Identify register addresses from documentation

**Interrupt Handling:**
- Interrupt vector tables usually at fixed addresses
- Handlers often at offset 0x00, 0x04, 0x08...
- Analyze ISR chains and priority

**Peripheral Drivers:**
- UART: Look for baud rate initialization, TX/RX functions
- SPI/I2C: Identify chip select, clock, data transfers
- Timers: Configuration registers, interrupt handlers
- DMA: Transfer descriptors, channel setup

## Extraction Techniques

**Strings Extraction:**
- Use `strings` or similar to find ASCII/Unicode
- Look for configuration keys and values
- Identify debug strings and error messages

**Constants Analysis:**
- Magic bytes for file formats
- Hardware register addresses
- Network ports and IP addresses
- Encryption keys or initialization vectors

**Data Structures:**
- Reconstruct structures from access patterns
- Identify linked lists, arrays, trees
- Map configuration structures

## Output

Detailed firmware analysis including:
- Firmware structure and layout analysis
- Architecture identification and ISA documentation
- Disassembly of key code sections
- Extracted filesystems and files
- Hardware register maps and peripheral documentation
- Configuration data and embedded secrets
- Boot process and initialization analysis
- Extracted resources and data

Focus on handling unknown architectures and binary blobs without standard tooling support. Extract maximum information from firmware without live debugging.

---

**Evidence & reporting (ida_mcp workflow).** Every claim needs decompilation/xref/data-flow evidence (`analyze_function`/`decompile_function`/`trace_data_flow`/`callgraph`); use `int_convert` for bases; write `re/summary.md`, `re/analysis.md`, `re/findings.md` with hex addresses and the tool behind each claim. Mutations (`set_name`/`set_comment`/`set_type`/`patch_*`/`execute_script`) require `?unsafe=true`; live debugging requires `?unsafe=true&ext=dbg`.
