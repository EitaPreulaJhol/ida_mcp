# Archived upstream source — NOT a loadable skill (frontmatter stripped for lazy-load hygiene).

# Cryptography Analysis

Comprehensive cryptography analysis covering algorithm identification, mathematical operations, constant detection, and security evaluation of cryptographic implementations.

## When to Use

Use this skill when:
- Identifying cryptographic algorithms and primitives in binary code
- Analyzing mathematical operations and constants
- Evaluating cryptographic security and implementation quality
- Reverse engineering custom crypto implementations
- Detecting side-channel vulnerabilities
- Analyzing key management and derivation functions
- Understanding cryptographic protocols and constructions
- Assessing random number generation and entropy sources

## Capabilities

### Algorithm Identification
- **Primitive Detection**: Identify AES, DES, RSA, ECC, SHA, HMAC, etc.
- **Operation Recognition**: Recognize bitwise operations, modular arithmetic, finite fields
- **Constant Detection**: Find S-boxes, prime numbers, initialization vectors, round constants
- **Mode Recognition**: Detect ECB, CBC, GCM, CTR, CFB, OFB modes of operation
- **Padding Schemes**: Identify PKCS#7, ISO/IEC 7816-4, OAEP, PSS padding

### Mathematical Analysis
- **Bitwise Operations**: Analyze XOR, rotation, bit shifting, masking
- **Modular Arithmetic**: Understand modular exponentiation, field operations
- **Finite Fields**: Analyze GF(2^n) and prime field operations
- **Polynomial Arithmetic**: Identify polynomial multiplication and reduction
- **Number Theory**: Recognize GCD, primality testing, factorization algorithms

### Implementation Security
- **Side Channels**: Detect timing leaks, cache attacks, power analysis vulnerabilities
- **Constant-Time**: Evaluate constant-time implementation properties
- **Memory Safety**: Identify buffer overflows, use-after-free, memory leaks
- **Key Management**: Analyze key storage, derivation, rotation, and destruction
- **Randomness**: Assess RNG quality and entropy sources
- **Error Handling**: Evaluate cryptographic error handling and failure modes

### Protocol & Construction Analysis
- **Cryptographic Protocols**: Analyze TLS, SSH, Signal, WireGuard protocols
- **Hybrid Constructions**: Understand combinations of symmetric and asymmetric crypto
- **Authenticated Encryption**: Evaluate AEAD constructions and MAC compositions
- **Key Exchange**: Analyze DH, ECDH, RSA key exchange protocols
- **Hash Functions**: Evaluate hash constructions and collision resistance

## Workflow

1. **Function Identification**
   - Search for cryptographic constants and magic bytes
   - Identify bitwise and mathematical operations
   - Locate cryptographic API calls and library functions

2. **Algorithm Recognition**
   - Match known cryptographic code patterns
   - Identify S-boxes, lookup tables, and round functions
   - Recognize key schedules and expansion routines

3. **Mathematical Analysis**
   - Analyze bitwise operations and data transformations
   - Understand mathematical structures and operations
   - Identify finite field and modular arithmetic

4. **Security Evaluation**
   - Test for timing side-channels
   - Evaluate constant-time properties
   - Assess key management practices
   - Check for common implementation vulnerabilities

5. **Documentation**
   - Document identified algorithms and constructions
   - Explain mathematical operations and purposes
   - Provide security findings and recommendations

## Output

Detailed cryptographic analysis including:
- Identified algorithms and cryptographic primitives
- Mathematical operation explanations and purposes
- Constant detection and algorithm confirmation
- Security vulnerabilities and weaknesses
- Side-channel analysis and timing issues
- Implementation quality assessment
- Recommendations for improvements

Focus on mathematical precision (temperature=0.0) and concrete algorithm identification with code examples and security findings.
