# Archived upstream source — NOT a loadable skill (frontmatter stripped for lazy-load hygiene).

# Firmware Reverse Engineering

Comprehensive firmware analysis covering embedded systems, unknown architectures, binary blobs, hardware interfaces, and proprietary file systems. Specialized in analyzing firmware without standard debugging capabilities.

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

## Capabilities

### Firmware Structure Analysis
- **File Formats**: Analyze proprietary firmware formats and containers
- **Compression**: Identify and decompress LZMA, LZSS, Huffman, proprietary compression
- **Encryption**: Detect and decrypt encrypted firmware sections
- **Layout**: Map firmware sections, headers, and metadata structures
- **Checksums**: Verify integrity and validate firmware dumps

### Architecture & Code Analysis
- **Unknown ISAs**: Reverse engineer unknown instruction sets and encodings
- **Binary Blobs**: Analyze code without proper function boundaries
- **Disassembly**: Manual disassembly of non-standard code
- **Data Extraction**: Find strings, tables, constants, and configuration data
- **Code Patterns**: Identify functions, loops, and control flow in flat binaries

### Hardware & Peripheral Analysis
- **Register Analysis**: Understand hardware registers and memory-mapped I/O
- **Interrupt Vectors**: Extract and analyze interrupt vector tables
- **Peripheral Drivers**: Analyze drivers for UART, SPI, I2C, timers, etc.
- **DMA**: Analyze DMA controllers and transfer descriptors
- **Memory Maps**: Reconstruct memory layout and peripheral addresses

### Filesystem & Resource Extraction
- **File Systems**: Extract files from proprietary filesystems
- **Resources**: Extract images, fonts, strings, and embedded data
- **Configuration**: Parse configuration data and settings
- **Certificates**: Extract SSL certificates and cryptographic keys
- **Secrets**: Find embedded passwords, keys, and sensitive data

## Workflow

1. **Firmware Acquisition**
   - Dump firmware from flash memory or EEPROM
   - Extract firmware from update files or device dumps
   - Identify firmware format and structure

2. **Structure Analysis**
   - Parse firmware headers and metadata
   - Identify compression and encryption
   - Map sections and components

3. **Decompression & Decryption**
   - Decompress compressed sections
   - Decrypt encrypted firmware if possible
   - Extract embedded filesystems

4. **Code Analysis**
   - Identify architecture and instruction set
   - Disassemble code blobs
   - Analyze bootloader and initialization

5. **Hardware Analysis**
   - Map peripheral registers and memory-mapped I/O
   - Analyze interrupt handlers and vectors
   - Understand boot process and initialization

6. **Extraction**
   - Extract filesystems and files
   - Find configuration data and secrets
   - Extract resources and embedded data

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
