# ida_mcp domain skills index

All skills below run against the binary open in IDA Pro via ida_mcp. Start at `?profile=triage`, escalate top-down. Ceiling = max ladder step the skill may need.

| Skill (`/skill:<slug>`) | Ceiling | When to use |
|---|---|---|
| `0day-find` | `?unsafe=true&ext=dbg` | Next-generation 0day discovery — novel overflow patterns, allocator exploits, compiler-induced bugs, bounds-check bypass, SIMD/vector overfl |
| `ai-features` | `?profile=readonly` | Semantic search, similarity detection, auto-documentation |
| `android-exploit` | `?unsafe=true&ext=dbg` | Android vulnerability hunting and exploitation — APK analysis, native exploits, IPC bugs |
| `app-shielding-bypass` | `?profile=readonly` | Bypass application protections — root/JB detection, SSL pinning, anti-debug, obfuscation |
| `auto-exploit` | `?unsafe=true&ext=dbg` | Automatic exploit generation — detect vulnerabilities and generate working exploits |
| `automated-exploit-gen` | `?unsafe=true&ext=dbg` | Automatic exploit generation from vulnerability analysis |
| `bb-methodology` | `?profile=readonly` | Use at the START of any bug bounty hunting session, when switching targets, or when feeling lost about what to do next. Master orchestrator  |
| `bug-bounty` | `?profile=readonly` | Complete bug bounty workflow — recon (subdomain enumeration, asset discovery, fingerprinting, HackerOne scope, source code audit), pre-hunt  |
| `cloud-mobile-security` | `?profile=readonly` | Cloud mobile platform security — Firebase, AWS, Azure, GCP vulnerabilities |
| `code-quality-metrics` | `?profile=readonly` | Analyze code complexity, maintainability, and security issues |
| `code-vulnerability-analysis` | `?profile=readonly` | Next-generation 0day discovery & exploit development — comprehensive code analysis, allocator vulnerabilities, compiler-induced bugs, SIMD/v |
| `collaborative-analysis` | `?profile=readonly` | Team collaboration — share findings, merge analysis, generate reports |
| `container-escape` | `?profile=readonly` | Container escape vulnerability discovery — Docker, Kubernetes, container runtime exploitation, namespace isolation bypass, privilege escalat |
| `core-vulnerability-pipeline` | `?profile=readonly` | Shared vulnerability discovery, false positive filtering, and exploit generation pipeline for all ida_mcp security skills |
| `crypto-analysis` | `?profile=readonly` | Cryptography analysis — algorithm identification, mathematical operations, constant detection, and security evaluation |
| `crypto-vuln` | `?profile=readonly` | Crypto implementation analysis — weak algorithms, side-channels, key management flaws, padding oracles, random generation failures, implemen |
| `ctf` | `?unsafe=true` | Capture-the-flag reverse engineering — find the flag efficiently |
| `deobfuscation` | `?unsafe=true` | Systematic binary deobfuscation — string decryption, control flow flattening (CFF) removal, opaque predicate elimination, mixed boolean-arit |
| `driver-analysis` | `?unsafe=true&ext=dbg` | Windows kernel driver analysis — DriverEntry, dispatch table, IOCTL handlers, vulnerability audit |
| `firmware-re` | `?profile=readonly` | Firmware analysis — embedded systems, unknown architectures, binary blobs, hardware interfaces, and proprietary file systems |
| `generic-re` | `?unsafe=true` | General-purpose binary analysis — understand functionality, architecture, and behavior |
| `ida-scripting` | `?unsafe=true` | Write and execute IDAPython scripts — full API reference included |
| `ios-exploit` | `?unsafe=true&ext=dbg` | iOS vulnerability hunting and exploitation — IPA analysis, kernel exploits, sandbox escape |
| `iot-vuln` | `?profile=readonly` | IoT device security analysis — firmware extraction, RTOS exploits, hardware interfaces, protocol vulnerabilities, side-channel attacks, upda |
| `apk-analysis` | `?profile=readonly` | Android APK reverse engineering in IDA Pro - analyze structure, search strings, find native libs, extract manifest |
| `kernel-exploit` | `?unsafe=true&ext=dbg` | Kernel-mode exploitation — drivers, syscalls, privilege escalation |
| `kernel-mode-analysis` | `?unsafe=true&ext=dbg` | Comprehensive kernel driver vulnerability analysis — IOCTL handlers, dangerous APIs, exploitation primitives |
| `linux-driver-exploit` | `?unsafe=true&ext=dbg` | Linux kernel module exploitation — ioctl vulnerabilities, heap overflow, cred struct escalation |
| `linux-malware` | `?profile=readonly` | Expert ELF malware analysis — packing, toolchain ID, kill chain, persistence, C2, rootkits, cryptominers, Go/Rust/Mirai patterns, MITRE ATT& |
| `lpe-detection` | `?profile=readonly` | Local Privilege Escalation vulnerability detection — identify kernel exploits, service abuse, SUID/GUID, path hijacking, and cron job vulner |
| `macos-driver-exploit` | `?unsafe=true&ext=dbg` | macOS kernel extension (kext) exploitation — IOKit vulnerabilities, heap overflow, task credential escalation |
| `malware-analysis` | `?profile=readonly` | Windows PE malware analysis — kill chain, IOC extraction, MITRE ATT&CK mapping |
| `meme-coin-audit` | `?profile=readonly` | Meme coin and token security audit — rug pull detection (honeypot, hidden mint, fee manipulation, LP lock bypass), Solana SPL token analysis |
| `memory-corruption` | `?unsafe=true&ext=dbg` | Memory corruption & mitigation bypass — UAF, OOB, PAC, ASLR, CFI, CET, RCE, binary exploit |
| `mobile-malware-analysis` | `?profile=readonly` | Mobile malware analysis — Android/iOS malware reverse engineering, behavior analysis |
| `mobile-pentest` | `?profile=readonly` | Complete mobile penetration testing — ADB/SSH automation, device control, exploitation |
| `modify` | `?unsafe=true` | Modify binary behavior using natural language — explore, plan, patch, save |
| `owasp-mobile-top10` | `?profile=readonly` | OWASP Mobile Application Security Top 10 2024 — iOS/Android vulnerabilities, reverse engineering, and exploit techniques |
| `owasp-web-top10` | `?profile=readonly` | OWASP Web Top 10 security analysis — A01-A10 vulnerabilities, detection patterns, exploit techniques, and remediation |
| `prompt-injection` | `?profile=readonly` | Hunt and classify embedded prompt-injection payloads in binaries, apps and documents — agent-hijack markers, forged role text, Unicode evasi |
| `protocol-analysis` | `?profile=readonly` | Protocol analysis — network protocols, packet structures, state machines, communication patterns, and reverse engineering |
| `race-condition` | `?unsafe=true&ext=dbg` | Race condition exploitation — TOCTOU, double-fetch, thread safety |
| `rce-detection` | `?profile=readonly` | Remote Code Execution vulnerability detection — identify command injection, deserialization, template injection, and eval injection vectors |
| `report-writing` | `?profile=readonly` | Bug bounty report writing for H1/Bugcrowd/Intigriti/Immunefi — report templates, human tone guidelines, impact-first writing, CVSS 3.1 scori |
| `reverse-engineering` | `?unsafe=true` | Comprehensive reverse engineering — binary analysis, decompilation, control flow, data flow, and reconstruction techniques |
| `rop-builder` | `?unsafe=true&ext=dbg` | Build ROP chains automatically — find gadgets, construct chains, bypass ASLR/DEP |
| `scada-vuln` | `?profile=readonly` | Industrial control system security — Modbus, DNP3, IEC 104, Ethernet/IP, PLC exploitation, control logic manipulation, sensor/actuator attac |
| `security-arsenal` | `?profile=readonly` | Security payloads, bypass tables, wordlists, gf pattern names, always-rejected bug list, and conditionally-valid-with-chain table. Use when  |
| `shellcode-generator` | `?unsafe=true&ext=dbg` | Generate shellcode automatically — Linux, Windows, position-independent |
| `smart-patch-ida` | `?unsafe=true` | Patch binary code in IDA Pro using natural language — read, assemble, write, verify |
| `ssl-pinning-bypass` | `?profile=readonly` | SSL certificate pinning detection and bypass for mobile apps |
| `triage-validation` | `?profile=readonly` | Finding validation before writing any report — 7-Question Gate (all 7 questions), 4 pre-submission gates, always-rejected list, conditionall |
| `vm-escape` | `?profile=readonly` | Virtual machine escape vulnerabilities — hypervisor exploitation, hardware virtualization bugs, device emulation attacks, side-channel attac |
| `vm-obfuscation-detection` | `?unsafe=true` | Detect virtual machines, packers, and code obfuscation — VMProtect, Themida, UPX, control flow flattening |
| `vuln-audit` | `?profile=readonly` | Security audit — buffer overflows, format strings, integer issues, memory safety |
| `web-app-security` | `?profile=readonly` | Web application security — OWASP Top 10, authentication, authorization, input validation, API security, and modern web frameworks |
| `web-csharp-php-vuln` | `?profile=readonly` | Active vulnerability scanner for PHP and C# web applications — POP Chains, RCE, SQL Injection, XSS, CSRF, Auth Bypass, File Upload, Deserial |
| `web2-recon` | `?profile=readonly` | Web2 recon pipeline — subdomain enumeration (subfinder, Chaos API, assetfinder), live host discovery (dnsx, httpx), URL crawling (katana, wa |
| `web2-vuln-classes` | `?profile=readonly` | Complete reference for 20 web2 bug classes with root causes, detection patterns, bypass tables, exploit techniques, and real paid examples.  |
| `web3-audit` | `?profile=readonly` | Smart contract security audit — 10 DeFi bug classes (accounting desync, access control, incomplete path, off-by-one, oracle, ERC4626, reentr |
| `web3-vuln` | `?profile=readonly` | Blockchain/Web3 security — smart contract bugs, DeFi exploits, bridge vulnerabilities, NFT/Token exploits, reentrancy, MEV/sandwich attacks, |
| `windows-driver-exploit` | `?unsafe=true&ext=dbg` | Windows kernel driver exploitation — IOCTL vulnerabilities, pool overflow, token escalation |

Total: 62 domain skills + `ida` orchestrator.
Shared doctrine (doctrine, bypass-protocol, rce-poc-verification) expanded inline per skill where declared.
