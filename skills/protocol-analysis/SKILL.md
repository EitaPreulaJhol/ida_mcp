---
name: protocol-analysis
description: Protocol analysis — network protocols, packet structures, state machines, communication patterns, and reverse engineering Use with IDA Pro via ida_mcp (triage-first, escalate per ladder).
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

Task: Protocol Analysis. You are analyzing network protocols, reverse engineering proprietary protocols, and documenting communication patterns.

## Approach

Protocol analysis combines traffic analysis, binary reverse engineering, and state machine extraction. Work from concrete packet captures and binary implementations to reconstruct protocol specifications.

## When to Use

Use this skill when:
- Analyzing network protocols and packet structures
- Reverse engineering proprietary protocols from traffic captures
- Understanding protocol state machines and transitions
- Implementing protocol parsers and dissectors
- Analyzing binary protocol implementations
- Documenting protocol specifications
- Finding protocol security vulnerabilities
- Creating protocol fuzzers and test tools

## Workflow

1. **Traffic Collection**
   - Capture network traffic (Wireshark, tcpdump)
   - Identify protocol endpoints and ports
   - Collect diverse message samples
   - Record different protocol scenarios

2. **Pattern Recognition**
   - Identify magic bytes and fixed headers
   - Find packet boundaries and delimiters
   - Classify message types and purposes
   - Locate length fields and checksums

3. **Packet Structure Analysis**
   - Reverse engineer packet structures
   - Identify field layouts and types
   - Parse headers and payloads
   - Understand encoding schemes (TLV, fixed-width)

4. **State Machine Extraction**
   - Analyze protocol state transitions
   - Identify session establishment and teardown
   - Extract state variables and conditions
   - Build state machine models

5. **Implementation Analysis**
   - Locate protocol implementation in binary
   - Reverse engineer parsing and serialization code
   - Extract constants and configuration
   - Find error handling and validation

6. **Security Assessment**
   - Test for injection and manipulation
   - Analyze authentication and authorization
   - Evaluate cryptographic implementations
   - Design fuzzing strategies

## Protocol Structure Patterns

**Header-Body:**
- Fixed-size header with type, length, flags
- Variable-length payload
- Optional checksum or HMAC
- Common in custom protocols

**TLV (Type-Length-Value):**
- Tag/Type field
- Length field
- Value data
- Nested TLVs for complex structures

**Delimiter-Based:**
- Fixed delimiter sequences (e.g., `\r\n\r\n`)
- Variable-length fields
- Common in text-based protocols

**Binary Protocol Patterns:**
- Magic bytes at packet start
- Version field for backwards compatibility
- Message type/command field
- Sequence numbers for reliability
- Checksum/CRC for integrity

## State Machine Analysis

**Connection States:**
- Disconnected → Connecting → Connected → Disconnected
- Session establishment flows
- Handshake sequences
- Authentication phases

**Message Sequences:**
- Request → Response patterns
- Asynchronous notifications
- Keep-alive/heartbeat messages
- Error handling and recovery

**State Variables:**
- Session IDs and tokens
- Sequence numbers
- Authentication state
- Configuration parameters

## Security Assessment

**Common Vulnerabilities:**
- Missing authentication on sensitive operations
- Weak authentication (predictable tokens)
- No integrity protection (missing checksums)
- Cleartext sensitive data
- Injection in protocol fields
- Missing rate limiting

**Authentication Issues:**
- Hardcoded credentials
- Predictable session tokens
- Missing authorization checks
- Weak password hashing

**Injection Attacks:**
- Command injection in protocol fields
- SQL injection via protocol
- Buffer overflows in parsing

**Cryptographic Issues:**
- Weak encryption (RC4, DES)
- Missing authentication (encryption without MAC)
- Predictable IV/nonce
- Key management problems

## Implementation Reverse Engineering

**Locate Protocol Code:**
- Search for port numbers and constants
- Find string references (protocol messages)
- Look for socket/network API calls
- Identify packet parsing functions

**Parsing Logic:**
- Buffer management and bounds checking
- Field extraction and validation
- Error handling paths
- State machine implementation

**Serialization:**
- Packet construction routines
- Field encoding and formatting
- Checksum/CRC calculation
- Buffer allocation and copying

## Documentation Template

**Protocol Overview:**
- Purpose and functionality
- Transport protocol (TCP/UDP)
- Default port(s)
- Protocol versioning

**Message Types:**
- Type identifiers and values
- Request vs response messages
- One-way vs bidirectional
- Message sequencing rules

**Packet Structure:**
- Header fields (name, type, offset, size)
- Payload format
- Encoding schemes
- Endianness

**State Machine:**
- Connection lifecycle
- State transitions and triggers
- Error handling and recovery
- Timeout behavior

**Security:**
- Authentication mechanism
- Encryption (if any)
- Integrity protection
- Known vulnerabilities

## Output

Detailed protocol analysis including:
- Packet structure definitions and field layouts
- State machine diagrams and transition logic
- Message type classifications and purposes
- Security findings and vulnerabilities
- Parser/dissector implementations (Wireshark, Scapy)
- Protocol documentation with examples
- Test cases and fuzzing strategies

Focus on providing concrete protocol specifications with packet structure diagrams and implementation guidance.

---

**Evidence & reporting (ida_mcp workflow).** Every claim needs decompilation/xref/data-flow evidence (`analyze_function`/`decompile_function`/`trace_data_flow`/`callgraph`); use `int_convert` for bases; write `re/summary.md`, `re/analysis.md`, `re/findings.md` with hex addresses and the tool behind each claim. Mutations (`set_name`/`set_comment`/`set_type`/`patch_*`/`execute_script`) require `?unsafe=true`; live debugging requires `?unsafe=true&ext=dbg`.
