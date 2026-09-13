# Archived upstream source — NOT a loadable skill (frontmatter stripped for lazy-load hygiene).

# Protocol Analysis

Deep analysis of network protocols, packet structures, state machines, and communication patterns. Reverse engineer proprietary protocols from network traffic or binary implementations.

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

## Capabilities

### Protocol Reverse Engineering
- **Traffic Analysis**: Analyze packet captures and identify protocol patterns
- **Structure Inference**: Reverse engineer packet structures and field layouts
- **State Machine**: Extract protocol state machines and transition logic
- **Encoding Schemes**: Identify and decode encoding, compression, encryption
- **Message Types**: Classify different message types and their purposes
- **Sequence Analysis**: Understand message sequences and protocol flows

### Binary Protocol Analysis
- **Protocol Implementation**: Analyze binary code implementing protocols
- **Parser Logic**: Reverse engineer packet parsing and serialization code
- **State Tracking**: Extract state variables and protocol state machines
- **Error Handling**: Understand error cases and exception handling
- **Performance**: Identify performance bottlenecks and optimization opportunities

### Security Assessment
- **Vulnerability Analysis**: Find protocol security issues and weaknesses
- **Injection**: Test for injection, spoofing, and manipulation attacks
- **Authentication**: Analyze authentication and authorization mechanisms
- **Encryption**: Evaluate cryptographic implementations and key management
- **Fuzzing**: Design fuzzing strategies and test cases

### Documentation & Implementation
- **Protocol Specs**: Create detailed protocol documentation
- **Parser Generation**: Generate protocol parsers and dissectors
- **Test Vectors**: Create test cases and example traffic
- **Compatibility**: Ensure interoperability and version handling

## Workflow

1. **Traffic Collection**
   - Capture network traffic or trace binary execution
   - Identify protocol endpoints and ports
   - Collect diverse message samples

2. **Pattern Recognition**
   - Identify magic bytes and fixed headers
   - Reverse engineer packet structures
   - Classify message types and purposes

3. **State Machine Extraction**
   - Analyze protocol state transitions
   - Identify state variables and conditions
   - Build state machine models

4. **Implementation Analysis**
   - Locate protocol implementation in binary
   - Reverse engineer parsing and serialization logic
   - Extract constants and configuration

5. **Security Assessment**
   - Test for injection and manipulation
   - Analyze authentication and authorization
   - Evaluate cryptographic implementations

6. **Documentation**
   - Create comprehensive protocol specs
   - Generate parsers and dissectors
   - Provide test vectors and examples

## Output

Detailed protocol analysis including:
- Packet structure definitions and field layouts
- State machine diagrams and transition logic
- Message type classifications and purposes
- Security findings and vulnerabilities
- Parser/dissector implementations
- Protocol documentation with examples
- Test cases and fuzzing strategies

Focus on providing concrete protocol specifications with packet structure diagrams and implementation guidance.
