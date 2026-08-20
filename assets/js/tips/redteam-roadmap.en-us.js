/* Red Team Roadmap — layer data (en-US).
   Structure: layer > sections > items. `d` is the difficulty: f=entry, i=mid, a=senior, e=expert.
   Topic ids are stable, opaque identifiers: they are shared with the pt-BR counterpart
   (redteam-roadmap.pt-br.js) so progress saved in one language carries over to the other,
   and they deliberately do NOT track the layer number, so reordering layers never resets
   anyone's progress. */
window.RT_LAYERS = [
{n:1,title:"Computer Architecture",extra:false,deps:[],
 desc:"Absolute foundation. Without this you cannot understand why exploits work at a real level.",
 sections:[
  {t:"CPU & Execution",items:[
   {id:"1-1",t:"x86/x64 architecture: general, segment, control (CR0,CR3,CR4), debug (DR0-DR7) registers",d:"f"},
   {id:"1-2",t:"Full x86/x64 instruction set — SYSENTER, SYSCALL, IRET, MOV SS and shellcode/exploit instructions",d:"i"},
   {id:"1-3",t:"ARM/AArch64 architecture — required for mobile and embedded devices",d:"i"},
   {id:"1-4",t:"Execution pipeline: fetch, decode, execute, writeback",d:"f"},
   {id:"1-5",t:"Out-of-order and speculative execution — foundation for Spectre/Meltdown variants",d:"a"},
   {id:"1-6",t:"Branch prediction and offensive exploitation as a side-channel vector",d:"a"},
   {id:"1-7",t:"CPU operating modes: real mode, protected mode, long mode, SMM (System Management Mode)",d:"i"},
   {id:"1-8",t:"Ring levels (0-3): what each level actually permits at hardware level",d:"f"},
   {id:"1-9",t:"Ring transitions: how a syscall happens at hardware level",d:"i"},
   {id:"1-10",t:"Intel VT-x, AMD-V, VMCS — foundation for hypervisors and evasion that exploits them",d:"a"},
   {id:"1-11",t:"TLB (Translation Lookaside Buffer) and page table walks",d:"i"},
   {id:"1-12",t:"Cache hierarchy (L1/L2/L3) and side-channel attacks: Flush+Reload, Prime+Probe",d:"a"},
   {id:"1-13",t:"SMEP and SMAP: hardware implementation and historical bypasses",d:"a"},
   {id:"1-14",t:"NX/XD bit: executing data as code and why DEP exists",d:"f"},
   {id:"1-15",t:"ASLR: hardware-level vs OS-level implementation — differences that matter for bypass",d:"i"},
   {id:"1-16",t:"Intel SGX and ARM TrustZone — TEEs as an emerging attack surface",d:"e"},
  ]},
  {t:"Firmware & Boot",items:[
   {id:"1-17",t:"Legacy BIOS vs UEFI: structure, services, full boot sequence",d:"i"},
   {id:"1-18",t:"UEFI internals: DXE, PEI, SMM — where firmware persistence lives",d:"a"},
   {id:"1-19",t:"Secure Boot: chain of trust, BootHole and BlackLotus as real case studies",d:"a"},
   {id:"1-20",t:"TPM: PCRs, sealed storage, cold boot attacks against sealed keys",d:"a"},
   {id:"1-21",t:"Option ROMs as a pre-OS persistence vector",d:"e"},
   {id:"1-22",t:"Intel ME and AMD PSP: attack surface and OPSEC implications",d:"e"},
  ]}
]},
{n:2,title:"Operating Systems",extra:false,deps:[1],
 desc:"Windows Internals at real depth. This is where most attacks and defenses actually happen.",
 sections:[
  {t:"Windows — General Architecture",items:[
   {id:"2-1",t:"User-mode/kernel-mode separation in operational detail",d:"f"},
   {id:"2-2",t:"Kernel components: Executive, HAL, kernel core, drivers",d:"i"},
   {id:"2-3",t:"Full syscall path: Win32 API → NTDLL → syscall stub → kernel",d:"i"},
   {id:"2-4",t:"Syscall numbers (SSN) and why they change between Windows versions — direct syscall relevance",d:"a"},
   {id:"2-5",t:"SSDT (System Service Descriptor Table): historical hooks and current variations",d:"a"},
  ]},
  {t:"Windows — Memory Management",items:[
   {id:"2-6",t:"x64 virtual address space layout: PEB, TEB, stack, heap, loaded modules",d:"i"},
   {id:"2-7",t:"VAD (Virtual Address Descriptor) tree: how the kernel tracks memory regions per process",d:"a"},
   {id:"2-8",t:"Working sets, page faults, demand paging",d:"i"},
   {id:"2-9",t:"Memory mapped files and sections: how DLLs are really mapped, shared sections between processes",d:"i"},
   {id:"2-10",t:"Heap internals: NT Heap vs Segment Heap (Win10+), chunks, freelists, lookaside lists",d:"a"},
   {id:"2-11",t:"Large pages and AWE (Address Windowing Extensions): use in EDR memory scan evasion",d:"a"},
   {id:"2-12",t:"CFG (Control Flow Guard): bitmap of valid functions, implementation and documented bypasses",d:"a"},
  ]},
  {t:"Windows — Processes & Threads",items:[
   {id:"2-13",t:"EPROCESS and ETHREAD: kernel structures, Token, ActiveProcessLinks, PEB pointer fields",d:"a"},
   {id:"2-14",t:"Full PEB: InMemoryOrderModuleList, BeingDebugged, NtGlobalFlag flags",d:"i"},
   {id:"2-15",t:"TEB: stack base/limit, SEH chain, TLS slots",d:"i"},
   {id:"2-16",t:"Process creation internals: NtCreateUserProcess — why process hollowing is possible",d:"a"},
   {id:"2-17",t:"Token model: impersonation vs delegation, integrity levels (MIC), privilege attributes",d:"i"},
   {id:"2-18",t:"Job objects and silos (Windows containers foundation)",d:"i"},
   {id:"2-19",t:"Fibers and their use in EDR detection evasion",d:"a"},
  ]},
  {t:"Windows — I/O, Drivers & Callbacks",items:[
   {id:"2-20",t:"IRP (I/O Request Packet): driver communication model",d:"a"},
   {id:"2-21",t:"Driver model (WDM/WDF), loading, Driver Signature Enforcement",d:"a"},
   {id:"2-22",t:"Filter drivers: filesystem minifilters — where EDRs hook file operations",d:"a"},
   {id:"2-23",t:"Kernel callbacks: PsSetCreateProcessNotifyRoutine, CmRegisterCallback — what EDRs monitor",d:"a"},
   {id:"2-24",t:"Object callbacks: ObRegisterCallbacks to intercept handle opens",d:"a"},
  ]},
  {t:"Windows — Security & Credentials",items:[
   {id:"2-25",t:"SAM, LSA, LSASS: where credentials live and how they are structured in memory",d:"i"},
   {id:"2-26",t:"Kerberos in Windows: TGT/TGS in memory, internal LSASS structure",d:"i"},
   {id:"2-27",t:"NTLM: challenge-response in detail, NT hash derivation",d:"i"},
   {id:"2-28",t:"Credential Guard: HVCI isolation, why pass-the-hash fails against it",d:"a"},
   {id:"2-29",t:"Protected Processes (PPL): LSASS protection, documented bypasses",d:"a"},
   {id:"2-30",t:"AMSI internals: hook in powershell.exe/wscript.exe, ETW-based detections",d:"a"},
  ]},
  {t:"Windows — ETW, COM & WMI",items:[
   {id:"2-31",t:"ETW: providers, consumers, sessions, controllers — full architecture",d:"i"},
   {id:"2-32",t:"How modern EDRs depend on ETW for behavioral detection",d:"i"},
   {id:"2-33",t:"ETW tampering: EtwEventWrite patch, provider removal via ioctl",d:"a"},
   {id:"2-34",t:"COM internals: apartment model, proxy/stub, moniker — lateral movement and persistence vectors",d:"i"},
   {id:"2-35",t:"WMI: repository, providers, permanent subscriptions as persistence",d:"i"},
   {id:"2-36",t:"DCOM and its network implications for lateral movement",d:"i"},
  ]},
  {t:"Linux Internals",items:[
   {id:"2-37",t:"Kernel space vs user space, Linux vs Windows syscall implementation differences",d:"f"},
   {id:"2-38",t:"VFS (Virtual Filesystem Switch): kernel abstraction of file operations",d:"i"},
   {id:"2-39",t:"Namespaces and cgroups: container foundation, container escape",d:"i"},
   {id:"2-40",t:"Capabilities: granular privilege model beyond root/non-root",d:"i"},
   {id:"2-41",t:"ptrace: debugging, code injection, Yama LSM protections",d:"i"},
   {id:"2-42",t:"LD_PRELOAD and dynamic linker: hooking and evasion on Linux",d:"i"},
   {id:"2-43",t:"/proc filesystem: what it exposes, use in recon and evasion",d:"i"},
   {id:"2-44",t:"eBPF: legitimate use, eBPF rootkits as active research area",d:"a"},
   {id:"2-45",t:"LSM (SELinux, AppArmor): how they work and documented bypasses",d:"i"},
   {id:"2-46",t:"Linux mitigations: ASLR, PIE, stack canaries, RELRO — real implementation and bypass",d:"i"},
  ]},
  {t:"macOS Internals",items:[
   {id:"2-47",t:"XNU kernel: Mach + BSD hybrid, attacker-relevant differences",d:"i"},
   {id:"2-48",t:"Mach ports: IPC primitive, privilege escalation vector",d:"a"},
   {id:"2-49",t:"SIP, TCC, Gatekeeper/notarization: security model and bypasses",d:"i"},
   {id:"2-50",t:"Endpoint Security Framework: replaced kexts for EDRs on macOS",d:"i"},
   {id:"2-51",t:"dyld and DYLD_INSERT_LIBRARIES: macOS analogue of LD_PRELOAD",d:"i"},
  ]}
]},
{n:3,title:"Networking",extra:false,deps:[1,2],
 desc:"Not 'how to configure TCP/IP' — understanding traffic at packet level and building C2 that blends into noise.",
 sections:[
  {t:"Protocols in Depth",items:[
   {id:"3-1",t:"Ethernet: frames, MAC addressing, ARP in detail (cache poisoning, gratuitous ARP)",d:"f"},
   {id:"3-2",t:"IPv4 and IPv6: fragmentation, TTL manipulation, OS implementation differences",d:"f"},
   {id:"3-3",t:"TCP: three-way handshake, full state machine, session hijacking, sequence prediction",d:"f"},
   {id:"3-4",t:"DNS: full hierarchy, record types, zone transfer, DoH/DoT, DNS tunneling as C2",d:"i"},
   {id:"3-5",t:"HTTP/1.1, HTTP/2, HTTP/3: differences relevant for proxy and WAF evasion",d:"i"},
   {id:"3-6",t:"TLS: handshake in detail, cipher suites, certificate pinning, JA3/JA3S fingerprinting and bypass",d:"i"},
   {id:"3-7",t:"SMB (v1/v2/v3): dialects, NTLM auth over SMB — relay attack foundation",d:"i"},
   {id:"3-8",t:"Kerberos on the wire: AS-REQ/AS-REP, TGS-REQ/TGS-REP at packet level",d:"i"},
   {id:"3-9",t:"LDAP: protocol, advanced queries, what can be queried unauthenticated",d:"i"},
   {id:"3-10",t:"RPC: endpoints, WMI/SCM/Task Scheduler lateral movement over RPC",d:"i"},
   {id:"3-11",t:"WinRM/WSMan: protocol, authentication, PowerShell remoting internals",d:"i"},
   {id:"3-12",t:"ICMP: types and codes, ICMP tunneling as C2",d:"i"},
  ]},
  {t:"Traffic Analysis",items:[
   {id:"3-13",t:"Wireshark in depth: display vs capture filters, stream analysis, custom dissectors",d:"i"},
   {id:"3-14",t:"Tshark for automated pcap analysis at scale",d:"i"},
   {id:"3-15",t:"C2 traffic identification: beacon intervals, jitter, packet size patterns",d:"a"},
   {id:"3-16",t:"How IDS/IPS analyze traffic: Snort/Suricata rules, what triggers alerts",d:"i"},
   {id:"3-17",t:"Network forensics: session reconstruction, file extraction from captures",d:"i"},
  ]},
  {t:"Offensive Infrastructure",items:[
   {id:"3-18",t:"DNS redirectors: separating real C2 from direct exposure",d:"a"},
   {id:"3-19",t:"HTTPS redirectors with Apache/Nginx mod_rewrite: sandbox traffic filtering",d:"a"},
   {id:"3-20",t:"CDN fronting for C2 (domain fronting): how it worked, current limitations and variants",d:"a"},
   {id:"3-21",t:"Aged domains, domain categorization and how corporate proxies verify reputation",d:"a"},
   {id:"3-22",t:"BGP hijacking: conceptual, but relevant for large-scale infrastructure attacks",d:"e"},
  ]}
]},
{n:4,title:"Programming",extra:false,deps:[1,2],
 desc:"Not just scripting — understanding code at a low level sufficient to write tools, loaders and shellcode.",
 sections:[
  {t:"Assembly x86/x64",items:[
   {id:"4-1",t:"Registers and calling conventions: cdecl, stdcall, fastcall, System V AMD64, Microsoft x64 ABI",d:"i"},
   {id:"4-2",t:"Reading and writing shellcode: understanding each instruction, identifying common patterns",d:"i"},
   {id:"4-3",t:"Position-independent code (PIC): shellcode that works at any address",d:"i"},
   {id:"4-4",t:"Shellcode techniques: egg hunters, staged shellcode, avoiding null bytes and bad chars",d:"a"},
   {id:"4-5",t:"Inline assembly in C: mixing ASM with high-level code",d:"i"},
  ]},
  {t:"C and C++",items:[
   {id:"4-6",t:"Pointers in depth: arithmetic, function pointers, pointer-to-pointer, void*",d:"i"},
   {id:"4-7",t:"Manual memory management: malloc/free internals, use-after-free, double-free, buffer overflow",d:"i"},
   {id:"4-8",t:"Structs and memory alignment: how the compiler organizes structures, padding, packing",d:"i"},
   {id:"4-9",t:"Windows API in raw C: kernel32, ntdll, advapi32 without wrappers",d:"i"},
   {id:"4-10",t:"Interacting with kernel structures from user-mode: accessing PEB, TEB via explicit pointers",d:"a"},
   {id:"4-11",t:"Compilation and linking: import tables, export tables, how DLLs are loaded",d:"i"},
   {id:"4-12",t:"SEH (Structured Exception Handling): chain mechanics, use in exploits",d:"a"},
  ]},
  {t:"Rust & Go (Modern Tooling)",items:[
   {id:"4-13",t:"Rust: FFI to Windows API, Unsafe Rust, standalone binaries harder to analyze",d:"a"},
   {id:"4-14",t:"Go: static binaries by default, goroutines, native cross-compilation",d:"i"},
   {id:"4-15",t:"Why Rust/Go dominate modern offensive tooling: signature detection is harder",d:"i"},
  ]},
  {t:"Python, PowerShell & Shell",items:[
   {id:"4-16",t:"Advanced Python: ctypes for Windows API, struct for binary data, socket for custom protocols",d:"i"},
   {id:"4-17",t:"Writing exploits and PoCs in Python: binary format parsing, simple fuzzing",d:"i"},
   {id:"4-18",t:"PowerShell internals: AMSI hook location, .NET/CLR engine, reflection to load assemblies",d:"a"},
   {id:"4-19",t:"Constrained Language Mode: what it restricts, documented bypasses",d:"a"},
   {id:"4-20",t:"Script block logging, module logging, transcription: what each captures and how to evade",d:"a"},
   {id:"4-21",t:"Bash: Linux operation automation, built-ins to avoid spawning monitored external binaries",d:"i"},
  ]}
]},
{n:5,title:"Frameworks, Legal & Methodology",extra:true,deps:[],
 desc:"What structures a professional engagement. Without this, technical execution has no context or protection.",
 sections:[
  {t:"Frameworks & Methodology",items:[
   {id:"24-1",t:"MITRE ATT&CK: using for planning and reporting, ATT&CK Navigator, custom layers per engagement",d:"f"},
   {id:"24-2",t:"PTES (Penetration Testing Execution Standard): phases and expected deliverables",d:"f"},
   {id:"24-3",t:"TIBER-EU / CBEST: threat intelligence-led red teaming — what separates it from conventional pentest",d:"i"},
   {id:"24-4",t:"Lockheed Martin Cyber Kill Chain vs ATT&CK: when to use each model",d:"f"},
   {id:"24-5",t:"OWASP Testing Guide and ASVS: references for web application scope",d:"f"},
  ]},
  {t:"Legal & Operational",items:[
   {id:"24-6",t:"Rules of Engagement: what must be included, get-out-of-jail letter, chain of custody",d:"f"},
   {id:"24-7",t:"Scoping: what to include/exclude, out-of-scope systems, notifying cloud providers",d:"f"},
   {id:"24-8",t:"Brazil Lei 12.737/2012 and international equivalents: operator legal liability",d:"f"},
   {id:"24-9",t:"CFAA (Computer Fraud and Abuse Act): why it matters even outside the US",d:"i"},
   {id:"24-10",t:"Technical reporting: structure, communicating risk to technical vs executive audience",d:"f"},
   {id:"24-11",t:"Offensive threat modeling: STRIDE from the attacker perspective, defining operational objectives",d:"i"},
   {id:"24-12",t:"Responsible disclosure: CVD, timelines, vendor communication",d:"i"},
  ]}
]},
{n:6,title:"Applied Cryptography",extra:false,deps:[3,4],
 desc:"Not deep math theory — enough to build secure C2, attack protocol implementations and crack credentials.",
 sections:[
  {t:"Applied Fundamentals",items:[
   {id:"5-1",t:"Symmetric crypto: AES (ECB vs CBC vs GCM and why it matters), ChaCha20",d:"f"},
   {id:"5-2",t:"Asymmetric crypto: RSA and ECC — how used in protocols, where implementations fail",d:"i"},
   {id:"5-3",t:"Hashing: MD5, SHA-1/256/512, NTLM hash derivation, bcrypt — cracking context",d:"f"},
   {id:"5-4",t:"PKI: certificate chain, CRL, OCSP — TLS in practice, corporate MITM cert interception",d:"i"},
   {id:"5-5",t:"Kerberos crypto: RC4-HMAC vs AES128/256 — why it matters for Kerberoasting",d:"i"},
   {id:"5-6",t:"Implementation attacks: padding oracle, CBC bit-flipping, reused nonce in CTR mode",d:"a"},
   {id:"5-7",t:"Building encrypted C2 channels that evade protocol analysis",d:"a"},
  ]}
]},
{n:7,title:"Reverse Engineering",extra:false,deps:[1,2,4],
 desc:"Reconstructing binary logic without source code. Foundation for malware analysis and exploit development.",
 sections:[
  {t:"Tools & Methodology",items:[
   {id:"6-1",t:"IDA Pro in depth: IDAPython scripting, navigating large binaries, custom structs",d:"a"},
   {id:"6-2",t:"Ghidra: decompiler, Java/Python scripting, when to use vs IDA",d:"i"},
   {id:"6-3",t:"x64dbg/WinDbg: breakpoints (software, hardware, memory), stepping, runtime analysis",d:"i"},
   {id:"6-4",t:"WinDbg kernel debugging: KD setup, crash dump analysis, kernel struct inspection",d:"a"},
   {id:"6-5",t:"Static vs dynamic analysis: when to use each, how to combine for maximum efficiency",d:"i"},
   {id:"6-6",t:"Anti-debugging: IsDebuggerPresent variants, timing checks, NtQueryInformationProcess",d:"i"},
   {id:"6-7",t:"Anti-VM and anti-sandbox: artifact checks, human interaction verification — and how to bypass",d:"i"},
   {id:"6-8",t:"Code obfuscation: control flow flattening, bogus code, string encryption — how to reverse",d:"a"},
   {id:"6-9",t:"Packing: how packers work (compress+encrypt+stub), identify packed binaries, manual unpack",d:"i"},
   {id:"6-10",t:".NET reverse engineering: dnSpy, ILSpy — many red team tools and malware are .NET",d:"i"},
   {id:"6-11",t:"Practical malware analysis: safe lab, Procmon+Procexp+Autoruns+Wireshark together",d:"i"},
   {id:"6-12",t:"Binary diffing: BinDiff for version comparison, patch-based vulnerability discovery",d:"a"},
  ]}
]},
{n:8,title:"Exploit Development",extra:false,deps:[1,2,4,6,7],
 desc:"Where red team and vuln research overlap. Requires the most complete dependency stack.",
 sections:[
  {t:"Memory Corruption",items:[
   {id:"7-1",t:"Stack buffer overflow: smashing the stack, return address overwrite, basic ROP chains",d:"i"},
   {id:"7-2",t:"Windows heap exploitation: use-after-free, double-free, heap spray — NT Heap and Segment Heap",d:"a"},
   {id:"7-3",t:"Linux heap exploitation: glibc malloc internals, tcache poisoning, fastbin corruption",d:"a"},
   {id:"7-4",t:"Format string vulnerabilities: arbitrary read/write via %n, modern exploitation",d:"i"},
   {id:"7-5",t:"Integer overflows and how they lead to memory corruption",d:"i"},
   {id:"7-6",t:"Type confusion: how it occurs, exploitation in JIT compilers and object parsers",d:"e"},
  ]},
  {t:"Modern Mitigations & Bypasses",items:[
   {id:"7-7",t:"ASLR: information leaks as a prerequisite for reliable 64-bit bypass",d:"i"},
   {id:"7-8",t:"DEP/NX bypass: ROP (Return-Oriented Programming) — building gadget chains",d:"a"},
   {id:"7-9",t:"Stack canaries: leak techniques, partial overwrites",d:"i"},
   {id:"7-10",t:"CFG and generic CFI: how they restrict call targets, documented bypasses",d:"a"},
   {id:"7-11",t:"Safe Unlinking (heap) and modern post-mitigation heap exploitation techniques",d:"e"},
  ]},
  {t:"Kernel Exploits",items:[
   {id:"7-12",t:"Attack surface: vulnerable drivers (more common than kernel core bugs), ioctl handlers",d:"a"},
   {id:"7-13",t:"Kernel exploit primitives: arbitrary read/write, null pointer dereference, type confusion",d:"a"},
   {id:"7-14",t:"Token stealing: locate privileged process token via EPROCESS chain, copy to attacker process",d:"a"},
   {id:"7-15",t:"Kernel shellcode: differences from userland shellcode running in ring 0",d:"e"},
  ]}
]},
{n:9,title:"Active Directory",extra:false,deps:[2,3,6],
 desc:"Present in virtually every enterprise. Mastering AD means mastering lateral movement and persistence.",
 sections:[
  {t:"Real Fundamentals",items:[
   {id:"8-1",t:"AD schema: how objects are defined, attributes, object classes",d:"f"},
   {id:"8-2",t:"LDAP as access protocol: advanced queries, relevant attributes (adminCount, SPN, msDS-AllowedToActOnBehalfOfOtherIdentity)",d:"i"},
   {id:"8-3",t:"Sites and subnets: how replication works, cross-site auth implications",d:"i"},
   {id:"8-4",t:"Trusts: types, directionality, transitivity, SID filtering — cross-forest attack foundation",d:"a"},
   {id:"8-5",t:"GPOs: application, LSDOU precedence, SYSVOL, GPO abuse for lateral movement/persistence",d:"i"},
   {id:"8-6",t:"OUs and delegation: delegation of control, who has permission on which objects",d:"i"},
  ]},
  {t:"Authentication in Depth",items:[
   {id:"8-7",t:"Kerberos: AS-REQ/AS-REP, pre-authentication, TGS-REQ/TGS-REP at full technical level",d:"i"},
   {id:"8-8",t:"PAC (Privilege Attribute Certificate): content, DC validation — Golden Ticket foundation",d:"a"},
   {id:"8-9",t:"S4U2Self and S4U2Proxy: constrained delegation, RBCD — how misconfiguration enables impersonation",d:"a"},
   {id:"8-10",t:"Unconstrained delegation: why it is so dangerous, exploitation via printer bug/coercion",d:"a"},
   {id:"8-11",t:"NTLM: NTLMv1 vs NTLMv2, cracking implications, NTLM relay in depth",d:"i"},
   {id:"8-12",t:"Pass-the-Hash at protocol level: authenticating directly with the hash in challenge-response",d:"i"},
  ]},
  {t:"AD Attacks",items:[
   {id:"8-13",t:"BloodHound/SharpHound: what they collect, attack graph analysis, advanced Cypher queries",d:"i"},
   {id:"8-14",t:"Kerberoasting and AS-REP Roasting at full technical depth — not just running Rubeus",d:"i"},
   {id:"8-15",t:"DCSync: replication permissions required, why it works, detection",d:"a"},
   {id:"8-16",t:"Golden, Silver, Diamond, Sapphire Tickets — differences and detection implications",d:"a"},
   {id:"8-17",t:"ADCS: ESC1-ESC8 and beyond — each misconfiguration as escalation or persistence vector",d:"a"},
   {id:"8-18",t:"ACL-based attacks: WriteDACL, GenericAll, GenericWrite, ForceChangePassword — BH chaining",d:"i"},
   {id:"8-19",t:"AdminSDHolder: how abuse persists after permission removal",d:"a"},
   {id:"8-20",t:"LAPS and gMSA: where passwords are stored, who can read them, how to enumerate",d:"i"},
  ]}
]},
{n:10,title:"Malware Dev & EDR Evasion",extra:false,deps:[2,4,7],
 desc:"What separates high-level red teams from running public tools. Requires real depth in OS internals.",
 sections:[
  {t:"Loaders & Process Injection",items:[
   {id:"9-1",t:"Classic injection: VirtualAllocEx+WriteProcessMemory+CreateRemoteThread — why it is heavily detected",d:"i"},
   {id:"9-2",t:"Process hollowing: how it works, why it is more evasive, where EDRs still catch it",d:"a"},
   {id:"9-3",t:"Process doppelganging: NTFS transaction abuse, current detection status",d:"a"},
   {id:"9-4",t:"Thread hijacking: suspend existing thread, alter CONTEXT struct, resume",d:"a"},
   {id:"9-5",t:"APC injection and Early Bird APC: execute before EDR hooks load",d:"a"},
   {id:"9-6",t:"Shellcode injection via Windows fibers",d:"a"},
   {id:"9-7",t:"Module stomping/overloading: shellcode over legitimate DLL memory, evading image-backed region scans",d:"a"},
   {id:"9-8",t:"DLL injection: LoadLibrary-based, reflective DLL injection, manual mapping",d:"i"},
  ]},
  {t:"EDR Evasion",items:[
   {id:"9-9",t:"User-mode hooking: how EDRs hook NTDLL functions (inline hooks, IAT hooks)",d:"i"},
   {id:"9-10",t:"Direct syscalls: Hell's Gate, Halo's Gate, Tartarus' Gate — variants handling hooks on stubs",d:"a"},
   {id:"9-11",t:"Unhooking: restoring original bytes — from disk, from a second NTDLL instance, fresh copy",d:"a"},
   {id:"9-12",t:"AMSI bypass: amsi.dll memory patch, via COM, via .NET reflection — lifecycle of each technique",d:"a"},
   {id:"9-13",t:"ETW tampering: EtwEventWrite patch, disabling specific providers",d:"a"},
   {id:"9-14",t:"Sleep obfuscation: Ekko, Foliage, Cronos — encrypting implant in memory between beacons",d:"a"},
   {id:"9-15",t:"Stack spoofing: synthetic call stacks to deceive EDR behavioral analysis",d:"e"},
   {id:"9-16",t:"Heap encryption between beacons and PE header obfuscation",d:"a"},
  ]},
  {t:"C2 & Communication",items:[
   {id:"9-17",t:"Malleable C2 profiles (Cobalt Strike): each field, what it controls for detection",d:"a"},
   {id:"9-18",t:"Staging vs stageless: operational and detection trade-offs",d:"i"},
   {id:"9-19",t:"C2 over legitimate protocols: HTTP/S, DNS, SMB named pipes — detection characteristics of each",d:"a"},
   {id:"9-20",t:"Beaconing: jitter, interval variation, why regular patterns are detected by traffic analysis",d:"i"},
   {id:"9-21",t:"Exfiltration: chunking, use of legitimate services (OneDrive, GitHub, Slack as channels)",d:"a"},
  ]}
]},
{n:11,title:"Web Application Security",extra:false,deps:[3,4,6],
 desc:"Largest external attack surface. Goes far beyond running a scanner — requires understanding parsers and runtimes.",
 sections:[
  {t:"Vulnerabilities in Depth",items:[
   {id:"10-1",t:"SQLi: all types, WAF bypass, second-order, stacked queries — understand how SQL parsers work",d:"i"},
   {id:"10-2",t:"XSS: stored/reflected/DOM, real CSP bypass, XSS-to-RCE in Electron apps",d:"i"},
   {id:"10-3",t:"SSRF: IP filter bypass (IPv6, encoding, redirects), cloud metadata access (IMDSv1/v2)",d:"i"},
   {id:"10-4",t:"XXE: in-band, OOB via DNS/HTTP, via file upload, XXE in XML-capable JSON parsers",d:"i"},
   {id:"10-5",t:"Deserialization: gadget chains in Java (ysoserial), .NET (TypeNameHandling), PHP (magic methods)",d:"a"},
   {id:"10-6",t:"SSTI: identify template engine by payload, exploitation in Jinja2, Twig, Freemarker",d:"i"},
   {id:"10-7",t:"OAuth 2.0 and OIDC: flows in detail, state fixation, redirect_uri bypass, token leakage",d:"a"},
   {id:"10-8",t:"JWT: algorithm confusion (RS256 to HS256 with public key), none algorithm, weak secrets",d:"i"},
   {id:"10-9",t:"HTTP request smuggling: CL.TE, TE.CL, TE.TE — parsing differences as vulnerability",d:"a"},
   {id:"10-10",t:"GraphQL: introspection, batching for rate-limit bypass, nested query DoS",d:"i"},
   {id:"10-11",t:"Race conditions: single-packet attack (Turbo Intruder), exploiting timing windows",d:"a"},
   {id:"10-12",t:"Cache poisoning vs cache deception: unkeyed headers, identification and exploitation",d:"a"},
  ]},
  {t:"Authentication & Sessions",items:[
   {id:"10-13",t:"Cookies: HttpOnly, Secure, SameSite flags, session fixation, cookie tossing",d:"i"},
   {id:"10-14",t:"MFA bypass: OTP leakage, backup codes, evilginx-style adversary-in-the-middle",d:"i"},
   {id:"10-15",t:"Subdomain takeover: identifying CNAMEs pointing to abandoned services",d:"i"},
  ]}
]},
{n:12,title:"Cloud Security",extra:false,deps:[3,9,11],
 desc:"Modern environments are largely cloud. Primary attack vector is misconfigured IAM, not software exploits.",
 sections:[
  {t:"AWS",items:[
   {id:"11-1",t:"IAM in depth: identity-based vs resource-based policies, SCPs in Organizations, permission boundaries",d:"i"},
   {id:"11-2",t:"IAM privilege escalation: PassRole+Lambda, new policy version, AttachUserPolicy vectors",d:"a"},
   {id:"11-3",t:"IMDSv1 and IMDSv2: why v1 is trivially accessible via SSRF, v2 protections and bypasses",d:"i"},
   {id:"11-4",t:"Roles and AssumeRole: cross-account, confused deputy problem",d:"i"},
   {id:"11-5",t:"S3: bucket policies, ACLs, public access settings, bucket enumeration techniques",d:"i"},
   {id:"11-6",t:"Services as vectors: Lambda injection, EC2 user data, SSM Run Command as lateral movement",d:"a"},
  ]},
  {t:"Azure / Entra ID",items:[
   {id:"11-7",t:"Entra ID vs on-premises AD: cloud-only vs hybrid, AD Connect as attack bridge",d:"i"},
   {id:"11-8",t:"Service Principals and Managed Identities: abuse of excessive permissions",d:"i"},
   {id:"11-9",t:"PRT (Primary Refresh Token): what it is, how it is stored, hybrid lateral movement",d:"a"},
   {id:"11-10",t:"Azure roles vs Entra ID roles: distinction, how they map to different resources",d:"i"},
   {id:"11-11",t:"Conditional Access: what it is, bypasses in certain configurations",d:"a"},
   {id:"11-12",t:"Microsoft Graph API: enumeration without traditional AD APIs, token abuse",d:"a"},
  ]},
  {t:"Cross-Cloud Concepts",items:[
   {id:"11-13",t:"Misconfiguration as primary vector: different from on-premises where exploits dominate",d:"f"},
   {id:"11-14",t:"Cloud data exfiltration: S3 exfil, snapshot sharing, via managed services",d:"i"},
  ]}
]},
{n:13,title:"Mobile Security",extra:false,deps:[2,4,6],
 desc:"Growing attack surface. Android and iOS have completely different security models requiring distinct approaches.",
 sections:[
  {t:"Android",items:[
   {id:"12-1",t:"APK structure: manifest, permissions, Activity/Service/BroadcastReceiver/ContentProvider attack surface",d:"i"},
   {id:"12-2",t:"Binder IPC: inter-process communication on Android — privilege escalation vector",d:"a"},
   {id:"12-3",t:"Reverse engineering APKs: jadx, apktool, Frida for dynamic hooking",d:"i"},
   {id:"12-4",t:"Certificate pinning bypass: Frida hooks, APK patching, apk-mitm",d:"i"},
   {id:"12-5",t:"Root detection bypass: common detection techniques and how to evade each",d:"i"},
  ]},
  {t:"iOS",items:[
   {id:"12-6",t:"Entitlements and sandboxing: security model, what each entitlement permits",d:"i"},
   {id:"12-7",t:"Jailbreak: what it exploits, how it modifies the system — beyond just installing it",d:"a"},
   {id:"12-8",t:"IPA analysis: extraction, class-dump, Mach-O binary analysis",d:"i"},
   {id:"12-9",t:"Frida on iOS: hooking Objective-C and Swift methods at runtime",d:"i"},
  ]}
]},
{n:14,title:"Operational OPSEC",extra:false,deps:[3,10],
 desc:"Not a final layer — a mindset permeating every action. In mature red team, staying undetected is part of the objective.",
 sections:[
  {t:"Planning",items:[
   {id:"13-1",t:"Engagement threat modeling: who detects, what they monitor, noise cost of each action",d:"i"},
   {id:"13-2",t:"OPSEC impact categorization: what to do early, what to defer, what to never do",d:"i"},
   {id:"13-3",t:"Assume the environment is monitored: design every action as if the SOC sees everything",d:"i"},
  ]},
  {t:"Infrastructure",items:[
   {id:"13-4",t:"Infrastructure separation by phase: phishing infra separate from C2, C2 from exfil",d:"i"},
   {id:"13-5",t:"Redirectors: why they exist, proper configuration, when to rebuild",d:"a"},
   {id:"13-6",t:"Infrastructure lifetime: when to burn and rebuild, never reuse between operations",d:"i"},
   {id:"13-7",t:"Operation logging: record what was done, when, from where — audit your own trail",d:"i"},
  ]},
  {t:"During Operations",items:[
   {id:"13-8",t:"Living-off-the-land: prioritize LOLBins to minimize need for dropping files",d:"i"},
   {id:"13-9",t:"Timestomping and basic anti-forensics",d:"i"},
   {id:"13-10",t:"Cleanup: what to remove, in what order, intentional vs accidental artifacts",d:"i"},
   {id:"13-11",t:"Personal OPSEC: disposable VMs per task, separate DNS, own proxy chain",d:"a"},
   {id:"13-12",t:"JA3/tooling fingerprinting: changing C2 TLS fingerprint to avoid signature detection",d:"a"},
  ]}
]},
{n:15,title:"Social Engineering & OSINT",extra:false,deps:[3],
 desc:"Often the most efficient initial access vector. Requires deep research and convincing pretext construction.",
 sections:[
  {t:"OSINT",items:[
   {id:"14-1",t:"External attack surface enumeration: ASN, IP ranges, subdomains, CT logs, exposed technologies",d:"i"},
   {id:"14-2",t:"People OSINT: LinkedIn, GitHub (secrets in commits), social networks, breach data",d:"i"},
   {id:"14-3",t:"Shodan/Censys/FOFA in depth: advanced queries, passive infrastructure tracking",d:"i"},
   {id:"14-4",t:"Advanced Google dorks: exposed files, admin interfaces, leaked configs",d:"i"},
   {id:"14-5",t:"Maltego: entity relationships, building target maps",d:"i"},
   {id:"14-6",t:"Third-party infrastructure recon: email providers, CDN, WAF identification",d:"i"},
  ]},
  {t:"Technical Phishing & Social Engineering",items:[
   {id:"14-7",t:"Evilginx/Modlishka: AiTM that captures sessions even with MFA — how it works",d:"a"},
   {id:"14-8",t:"SPF/DKIM/DMARC in depth: how each is verified, exploitable gaps",d:"i"},
   {id:"14-9",t:"Homoglyph domains, lookalike domains, URL filter bypass in email clients",d:"i"},
   {id:"14-10",t:"Pretexting: narrative construction, target research, rapport — not improvisation",d:"i"},
   {id:"14-11",t:"Vishing: scripts, pressure techniques, IT/support impersonation",d:"i"},
   {id:"14-12",t:"Cialdini principles: reciprocity, authority, urgency — psychological foundation of SE",d:"f"},
  ]}
]},
{n:16,title:"Wireless & RF",extra:true,deps:[3],
 desc:"802.11, Bluetooth, NFC/RFID, enterprise wireless, SDR. Physical surface rarely covered adequately.",
 sections:[
  {t:"Wi-Fi in Depth",items:[
   {id:"15-1",t:"802.11 frame types: management (beacon, probe, auth, assoc), control, data — what each reveals",d:"i"},
   {id:"15-2",t:"WPA2: 4-way handshake in detail, why PMKID attack doesn't need full handshake capture",d:"i"},
   {id:"15-3",t:"WPA3: SAE (Simultaneous Authentication of Equals), Dragonblood vulnerabilities",d:"a"},
   {id:"15-4",t:"Evil Twin / Rogue AP: setup, captive portals, WPA3 to WPA2 downgrade",d:"i"},
   {id:"15-5",t:"WPS: Pixie Dust attack, PIN brute force, still enabled by default on many routers",d:"i"},
   {id:"15-6",t:"KARMA attack and variants: responding to any probe request with a fake AP",d:"a"},
   {id:"15-7",t:"Deauth attacks: 802.11 management frame spoofing, forced handshake capture",d:"i"},
  ]},
  {t:"Enterprise Wireless (802.1X / RADIUS)",items:[
   {id:"15-8",t:"802.1X/EAP overview: how enterprise authentication works (supplicant, authenticator, RADIUS server)",d:"i"},
   {id:"15-9",t:"EAP types: PEAP, EAP-TLS, EAP-TTLS, LEAP — strengths and weaknesses of each",d:"i"},
   {id:"15-10",t:"Rogue RADIUS server: attacking PEAP with fake server, MSCHAPv2 challenge capture",d:"a"},
   {id:"15-11",t:"hostapd-wpe: automate rogue AP + RADIUS attack, credential capture workflow",d:"a"},
   {id:"15-12",t:"EAP-TLS attacks when certificate validation is incorrectly implemented",d:"a"},
  ]},
  {t:"Bluetooth & NFC/RFID",items:[
   {id:"15-13",t:"BLE (Bluetooth Low Energy): GATT/ATT protocol, characteristic enumeration, sniffing with Ubertooth",d:"i"},
   {id:"15-14",t:"KNOB attack: downgrade of Bluetooth session key entropy",d:"a"},
   {id:"15-15",t:"NFC/RFID: frequencies (LF 125kHz vs HF 13.56MHz), MIFARE Classic vulns, UID cloning",d:"i"},
   {id:"15-16",t:"Proxmark3 in depth: emulation, read/write of access cards, brute forcing keys",d:"i"},
  ]},
  {t:"SDR & Other RF Protocols",items:[
   {id:"15-17",t:"SDR (Software Defined Radio): GNU Radio basics, RF signal capture and analysis",d:"i"},
   {id:"15-18",t:"Replay attacks on unencrypted systems (gate openers, alarms, remote controls)",d:"i"},
   {id:"15-19",t:"Zigbee and Z-Wave: IoT protocols, replay attacks, key extraction techniques",d:"a"},
  ]}
]},
{n:17,title:"Hardware Hacking",extra:true,deps:[1],
 desc:"Physical device access. JTAG, UART, fault injection, physical side-channel. Firmware research territory.",
 sections:[
  {t:"Debug Interfaces",items:[
   {id:"16-1",t:"JTAG/SWD: debug protocol, boundary scan, JTAGulator for pin identification, OpenOCD",d:"i"},
   {id:"16-2",t:"UART: pin identification (TX/RX/GND/VCC), serial communication, exposed boot console",d:"i"},
   {id:"16-3",t:"SPI and I2C: communication protocols, flash chip reading (firmware dump), Bus Pirate",d:"i"},
   {id:"16-4",t:"flashrom: firmware extraction and reflash via clip and adapters",d:"i"},
  ]},
  {t:"Advanced Physical Attacks",items:[
   {id:"16-5",t:"Voltage glitching: pulsing VCC to skip instructions — bypass authentication checks",d:"e"},
   {id:"16-6",t:"Clock glitching: manipulating clock to corrupt execution at a precise moment",d:"e"},
   {id:"16-7",t:"Simple Power Analysis (SPA) and Differential Power Analysis (DPA): extract keys from power patterns",d:"e"},
   {id:"16-8",t:"EM side-channel: capturing electromagnetic emissions near the chip",d:"e"},
   {id:"16-9",t:"Hardware implants: keyboard interceptors, inline sniffers — conceptual operation",d:"a"},
   {id:"16-10",t:"Chip decapsulation and silicon analysis: extreme-level forensic/offensive technique",d:"e"},
  ]}
]},
{n:18,title:"Containers & Kubernetes",extra:true,deps:[2,3,12],
 desc:"Container escape and K8s attacks are increasingly common in modern enterprise environments.",
 sections:[
  {t:"Docker in Depth",items:[
   {id:"17-1",t:"Docker internals: namespaces (PID/net/mnt/uts/ipc/user) and cgroups — how isolation is implemented",d:"i"},
   {id:"17-2",t:"Container escape via Docker socket: /var/run/docker.sock mounted as volume",d:"i"},
   {id:"17-3",t:"Privileged container escape: mounting host filesystem, writing to host crontab",d:"i"},
   {id:"17-4",t:"Capabilities abuse: CAP_SYS_ADMIN, CAP_NET_ADMIN as escape vectors",d:"a"},
   {id:"17-5",t:"/proc filesystem escape: accessing host namespace via /proc/1/root",d:"a"},
  ]},
  {t:"Kubernetes",items:[
   {id:"17-6",t:"K8s architecture: API server, etcd, kubelet, controller manager, scheduler",d:"i"},
   {id:"17-7",t:"K8s RBAC: roles vs clusterroles, service account token abuse, OIDC integration",d:"i"},
   {id:"17-8",t:"SSRF via kubelet API (port 10250): command execution in pods without authentication",d:"a"},
   {id:"17-9",t:"etcd dump: secrets and credentials in plaintext in the cluster database",d:"a"},
   {id:"17-10",t:"Node compromise for cluster-admin: via DaemonSet, hostPID, hostNetwork abuse",d:"a"},
   {id:"17-11",t:"Container image supply chain: malicious layers, image scanner bypass techniques",d:"a"},
  ]}
]},
{n:19,title:"Fuzzing & Vuln Discovery",extra:true,deps:[4,7,8],
 desc:"How vulnerabilities are found before they become CVEs. Foundation for original research.",
 sections:[
  {t:"Fuzzing",items:[
   {id:"18-1",t:"Coverage-guided fuzzing: AFL++ and libFuzzer — instrumentation and coverage feedback loop",d:"a"},
   {id:"18-2",t:"Grammar-based fuzzing: protocol and parser fuzzing with grammars, Boofuzz for network",d:"a"},
   {id:"18-3",t:"Structure-aware fuzzing: custom mutators, corpus building and minimization",d:"a"},
   {id:"18-4",t:"Dumb vs smart fuzzing: when each approach has higher ROI",d:"i"},
  ]},
  {t:"Analysis & Discovery",items:[
   {id:"18-5",t:"Binary diffing: BinDiff for post-patch version comparison — variant analysis workflow",d:"a"},
   {id:"18-6",t:"Patch diffing workflow: from CVE notification to working PoC via diff analysis",d:"a"},
   {id:"18-7",t:"Symbolic execution: angr conceptual, path explosion limitations, practical use cases",d:"e"},
   {id:"18-8",t:"Taint analysis: Joern, CodeQL for tracking unsanitized data paths in source code",d:"a"},
   {id:"18-9",t:"Code auditing methodology: unsafe patterns in C/C++, where to focus review effort",d:"a"},
  ]}
]},
{n:20,title:"Browser Exploitation",extra:true,deps:[4,7,8,11],
 desc:"V8, SpiderMonkey, sandbox escape. One of the most technically demanding exploit dev fields.",
 sections:[
  {t:"Engine Internals",items:[
   {id:"19-1",t:"V8 internals: JIT compilation, hidden classes (shapes), inline caches — type confusion foundation",d:"e"},
   {id:"19-2",t:"V8 exploitation: OOB read/write via array manipulation, JIT spraying for code injection",d:"e"},
   {id:"19-3",t:"SpiderMonkey and JavaScriptCore: architecturally relevant differences for exploit dev",d:"e"},
  ]},
  {t:"Sandbox & Browser",items:[
   {id:"19-4",t:"Chromium sandbox architecture: broker/target processes, how escapes happen",d:"e"},
   {id:"19-5",t:"Site isolation: process per site model, Spectre implications, documented bypasses",d:"e"},
   {id:"19-6",t:"Extension attacks: malicious extensions, privilege escalation via browser extension APIs",d:"a"},
   {id:"19-7",t:"WebAssembly as shellcode container: detection evasion in JavaScript context",d:"a"},
  ]}
]},
{n:21,title:"OT / ICS / SCADA",extra:true,deps:[3],
 desc:"Industrial systems. The attack goal is not data — it is physical process. Requires completely different mindset.",
 sections:[
  {t:"Architecture & Protocols",items:[
   {id:"20-1",t:"Purdue model: levels (field, control, supervisory, corporate) and security zones",d:"i"},
   {id:"20-2",t:"Modbus: port 502, no authentication by default — arbitrary register read/write",d:"i"},
   {id:"20-3",t:"DNP3: electrical telemetry protocol, sensor data spoofing",d:"i"},
   {id:"20-4",t:"IEC 61850, PROFINET, OPC-UA: modern industrial automation protocols",d:"a"},
   {id:"20-5",t:"PLCs: programming and querying, IEC 61131-3 languages — Stuxnet as definitive case study",d:"a"},
  ]},
  {t:"Attack Vectors",items:[
   {id:"20-6",t:"IT/OT convergence: how corporate networks become vectors into control environments",d:"i"},
   {id:"20-7",t:"Remote maintenance VPNs: vendor credentials as classic entry point",d:"i"},
   {id:"20-8",t:"Historian servers: IT/OT bridge, frequently poorly protected",d:"i"},
   {id:"20-9",t:"Tools: PLCScan, GRASSMARLIN, Shodan with ICS filters (port:102 Siemens S7)",d:"i"},
   {id:"20-10",t:"Physical impact: the fundamental difference — the goal is a real physical process, not data",d:"f"},
  ]}
]},
{n:22,title:"Digital Forensics (Offensive View)",extra:true,deps:[2,10,14],
 desc:"Understanding what the defender sees is essential to knowing what not to leave behind.",
 sections:[
  {t:"Windows Artifacts",items:[
   {id:"21-1",t:"Prefetch, shimcache, amcache: what each records, why they matter for attribution",d:"i"},
   {id:"21-2",t:"Jump lists, LNK files, MRU registry keys: what they reveal about user activity",d:"i"},
   {id:"21-3",t:"NTFS MFT: how timestamps are generated, what timestomping actually changes (and what it does not)",d:"a"},
   {id:"21-4",t:"Critical Event IDs: 4624, 4625, 4688, 4698, 7045 — what each records and how to avoid",d:"i"},
   {id:"21-5",t:"Registry forensics: which keys reveal past execution, how to clean specific traces",d:"a"},
  ]},
  {t:"Memory & Anti-Forensics",items:[
   {id:"21-6",t:"Memory forensics: what Volatility/Rekall finds — processes, connections, strings in memory",d:"i"},
   {id:"21-7",t:"Advanced anti-forensics: log secure delete (wevtutil), removing specific MFT entries",d:"a"},
   {id:"21-8",t:"Network forensics: what persists in firewall/proxy/IDS logs — minimizing exposure",d:"i"},
   {id:"21-9",t:"Volume Shadow Copies: how they are created, what evidence they contain, how to remove",d:"i"},
  ]}
]},
{n:23,title:"Supply Chain Attacks",extra:true,deps:[3,10,11],
 desc:"SolarWinds, 3CX, XZ Utils. The hardest vector to detect and defend.",
 sections:[
  {t:"Types & Techniques",items:[
   {id:"22-1",t:"Dependency confusion: how the 2021 attack disclosed by Alex Birsan worked, identifying targets in npm/pip/gem",d:"a"},
   {id:"22-2",t:"Package typosquatting: automation, real cases (event-stream, colors.js)",d:"i"},
   {id:"22-3",t:"Build pipeline compromise: CI/CD poisoning — SolarWinds as maximum-impact case study",d:"a"},
   {id:"22-4",t:"Code signing abuse: certificate theft, signing malware with a legitimate cert",d:"e"},
   {id:"22-5",t:"Update mechanism hijacking: mechanisms without integrity verification as vectors",d:"a"},
   {id:"22-6",t:"XZ Utils (CVE-2024-3094): backdoor insertion into open-source project via compromised contributor",d:"e"},
   {id:"22-7",t:"Hardware supply chain: device interdiction in transit (NSA ANT catalog documented technique)",d:"e"},
  ]}
]},
{n:24,title:"DevSecOps & CI/CD Pipeline",extra:true,deps:[4,12,23],
 desc:"Development pipelines as attack surface. Secrets, malicious actions, artifact poisoning.",
 sections:[
  {t:"GitHub & CI/CD",items:[
   {id:"23-1",t:"GitHub Actions: secrets exposed in logs, OIDC token theft, workflow injection via malicious PR",d:"i"},
   {id:"23-2",t:"Jenkins: Groovy script console as direct RCE, pipeline poisoning via Jenkinsfile",d:"i"},
   {id:"23-3",t:"GitLab CI: environment variables as secrets, runner compromise",d:"i"},
   {id:"23-4",t:"Artifact registry attacks: pushing malicious artifacts, credential extraction from registries",d:"a"},
  ]},
  {t:"Secrets & IaC",items:[
   {id:"23-5",t:"Secrets in code: git history, .env files, hardcoded credentials — trufflehog, gitleaks",d:"i"},
   {id:"23-6",t:"Terraform state files: credentials and sensitive outputs in plaintext",d:"i"},
   {id:"23-7",t:"Ansible vault weaknesses: key management, plaintext in execution logs",d:"i"},
   {id:"23-8",t:"SBOM (Software Bill of Materials): offensive use to identify vulnerable dependencies",d:"i"},
  ]}
]},
{n:25,title:"Physical Red Team",extra:true,deps:[14,15],
 desc:"Physical facility entry. Lock picking, electronic access bypass, badge cloning, implants. Own discipline.",
 sections:[
  {t:"Lock Picking & Physical Access",items:[
   {id:"25-1",t:"Lock picking: pin tumbler, wafer, disc detainer, bump keys — each type and tools required",d:"i"},
   {id:"25-2",t:"Bypass techniques: shimming, loiding (credit card), under-door tool for lever handles",d:"i"},
   {id:"25-3",t:"Tailgating and piggybacking: social entry techniques without defeating the lock",d:"f"},
   {id:"25-4",t:"Impressioning: creating a working key by marking a blank against the lock",d:"a"},
   {id:"25-5",t:"Electronic lock bypass: relay attacks on RFID, door handle sensors, mag-lock bypass",d:"a"},
  ]},
  {t:"Badge & Access Control Cloning",items:[
   {id:"25-6",t:"RFID access card cloning: Proxmark3 workflow, identify frequency and protocol before cloning",d:"i"},
   {id:"25-7",t:"HID Proxcard, EM4100, MIFARE DESFire — difficulty spectrum for cloning each",d:"i"},
   {id:"25-8",t:"Reader bypass with shim or signal replay at the door",d:"a"},
  ]},
  {t:"Physical Recon & Infrastructure",items:[
   {id:"25-9",t:"Building recon: identify entries, cameras, movement patterns, guard schedules",d:"i"},
   {id:"25-10",t:"Dumpster diving: information recovery from corporate trash",d:"f"},
   {id:"25-11",t:"Shoulder surfing and other observation vectors",d:"f"},
   {id:"25-12",t:"Network implants: LAN Turtle, Shark Jack — drop device for persistent remote access",d:"a"},
   {id:"25-13",t:"Physical keystroke loggers: types, placement, retrieval",d:"a"},
   {id:"25-14",t:"Server room access: what to do with physical access to corporate hardware",d:"i"},
  ]}
]},
{n:26,title:"Privilege Escalation (Full Taxonomy)",extra:true,deps:[2,4,9],
 desc:"Goes far beyond GTFOBins. Full taxonomy of Windows and Linux privesc with real depth.",
 sections:[
  {t:"Windows Privilege Escalation",items:[
   {id:"26-1",t:"AlwaysInstallElevated: identify via registry, exploit via malicious MSI",d:"i"},
   {id:"26-2",t:"Unquoted service paths: how it works, identify and exploit vulnerable services",d:"i"},
   {id:"26-3",t:"DLL hijacking in services: DLL search order, services loading DLLs without absolute path",d:"i"},
   {id:"26-4",t:"Token impersonation: SeImpersonatePrivilege — Potato family (Hot, Sweet, Rotten, Juicy, PrintSpoofer)",d:"i"},
   {id:"26-5",t:"Named pipe impersonation: creating a pipe that makes a privileged service connect",d:"a"},
   {id:"26-6",t:"Weak service permissions: sc.exe permission enumeration, binary path replacement",d:"i"},
   {id:"26-7",t:"Misconfigured scheduled tasks: weak permissions on binary or directory",d:"i"},
   {id:"26-8",t:"Registry autoruns with weak permissions: HKCU vs HKLM implications",d:"i"},
   {id:"26-9",t:"UAC bypass: current and historical techniques, integrity level implications",d:"i"},
   {id:"26-10",t:"PrintNightmare and spooler variants: local privilege escalation via print spooler",d:"a"},
  ]},
  {t:"Linux Privilege Escalation",items:[
   {id:"26-11",t:"SUID/SGID binaries: identification and GTFOBins exploitation",d:"i"},
   {id:"26-12",t:"Sudo misconfigurations: NOPASSWD, sudo -l, LD_PRELOAD bypass via sudo",d:"i"},
   {id:"26-13",t:"Cron jobs: writable scripts or directories in root-owned jobs",d:"i"},
   {id:"26-14",t:"NFS no_root_squash: mounting NFS and planting a SUID binary",d:"i"},
   {id:"26-15",t:"Docker group membership: equivalent to root — escape to host via docker run",d:"i"},
   {id:"26-16",t:"Capabilities abuse: cap_setuid, cap_net_raw and others via getcap",d:"i"},
   {id:"26-17",t:"PATH hijacking: manipulating PATH in scripts running as root",d:"i"},
   {id:"26-18",t:"Local kernel exploits: DirtyPipe, DirtyCow — identifying when to apply kernel privesc",d:"a"},
   {id:"26-19",t:"Writable /etc/passwd or shadow: exploitation workflow",d:"i"},
  ]},
  {t:"Cross-Platform",items:[
   {id:"26-20",t:"Service account privilege abuse: accounts with excessive permissions in the environment",d:"i"},
   {id:"26-21",t:"Credential reuse: repeated local passwords, shared admin password across the network",d:"f"},
  ]}
]},
{n:27,title:"Post-Exploitation & Pivoting",extra:true,deps:[2,3,9,10],
 desc:"The difference between 'got access' and 'real movement inside the environment'.",
 sections:[
  {t:"Pivoting & Tunneling",items:[
   {id:"27-1",t:"SSH tunneling: local/remote/dynamic forwarding, ProxyJump, proxychains over SSH",d:"i"},
   {id:"27-2",t:"Chisel: reverse SOCKS proxy over HTTP, bypassing egress firewall restrictions",d:"i"},
   {id:"27-3",t:"ligolo-ng: L3 tunneling with TUN interface, transparent to all tools",d:"i"},
   {id:"27-4",t:"Double pivot: reaching a third network segment via two chained pivots",d:"a"},
   {id:"27-5",t:"DNS tunneling C2: iodine, dnscat2 for environments with DNS-only egress",d:"a"},
   {id:"27-6",t:"ICMP tunneling: ptunnel for environments with ICMP-only egress",d:"a"},
  ]},
  {t:"Situational Awareness",items:[
   {id:"27-7",t:"Post-compromise enumeration: users, groups, services, network connections",d:"i"},
   {id:"27-8",t:"Identify reachable network segments, routing, internal DNS resolvers",d:"i"},
   {id:"27-9",t:"Host discovery without Nmap: built-ins (ping sweep via batch, PowerShell one-liners)",d:"i"},
   {id:"27-10",t:"Identifying active defenses: EDR, AV, network monitoring from inside the host",d:"i"},
  ]},
  {t:"C2 Frameworks (Operational Use)",items:[
   {id:"27-11",t:"Cobalt Strike: Beacon, sleep, C2 profiles, BOFs, lateral movement commands",d:"a"},
   {id:"27-12",t:"Sliver: open-source alternative, implant types, mTLS/WireGuard C2",d:"i"},
   {id:"27-13",t:"Havoc, Brute Ratel C4, Mythic: architecture differences, detection profile",d:"a"},
   {id:"27-14",t:"BOFs (Beacon Object Files): in-process execution, why they evade better than fork-and-run",d:"a"},
  ]}
]},
{n:28,title:"Databases as Lateral Movement",extra:true,deps:[9,11],
 desc:"MSSQL, Oracle, PostgreSQL as pivot points. Often overlooked and highly privileged.",
 sections:[
  {t:"MSSQL",items:[
   {id:"28-1",t:"xp_cmdshell: enable, execute OS commands as the service account",d:"i"},
   {id:"28-2",t:"Linked Servers: execute queries on linked servers, cross-server privilege escalation",d:"a"},
   {id:"28-3",t:"UNC path injection: EXEC xp_dirtree to capture NetNTLM hash for relay",d:"i"},
   {id:"28-4",t:"EXECUTE AS: impersonation to switch user context within the database",d:"i"},
   {id:"28-5",t:"CLR assemblies: load .NET assembly for arbitrary code execution",d:"a"},
   {id:"28-6",t:"Credential extraction: connection strings in config files, SQL Server Agent jobs",d:"i"},
  ]},
  {t:"Oracle & PostgreSQL",items:[
   {id:"28-7",t:"Oracle UTL_HTTP: outbound requests from inside the DB (SSRF vector)",d:"i"},
   {id:"28-8",t:"Oracle Java stored procedures: code execution via enabled Java in Oracle",d:"a"},
   {id:"28-9",t:"PostgreSQL COPY TO/FROM: read/write OS files as the postgres user",d:"i"},
   {id:"28-10",t:"PostgreSQL extensions: dblink, postgres_fdw for pivoting to other databases",d:"a"},
  ]},
  {t:"NoSQL & Caches",items:[
   {id:"28-11",t:"Redis without authentication: SLAVEOF and CONFIG SET for RCE",d:"i"},
   {id:"28-12",t:"MongoDB without authentication: complete data dump, command execution",d:"i"},
   {id:"28-13",t:"Memcached: data injection, session hijacking via cache manipulation",d:"i"},
  ]}
]},
{n:29,title:"Password Attacks",extra:true,deps:[6,9],
 desc:"Hashcat in real depth, spraying with lockout evasion, credential discovery from memory and files.",
 sections:[
  {t:"Hash Cracking",items:[
   {id:"29-1",t:"Hashcat: attack modes (0,1,3,6,7), rules (OneRuleToRuleThemAll), masks, prince attack, hybrid",d:"i"},
   {id:"29-2",t:"John the Ripper: differences, cases where it outperforms Hashcat",d:"i"},
   {id:"29-3",t:"Wordlists: rockyou, weakpass, hashesorg — building domain-specific wordlists",d:"i"},
   {id:"29-4",t:"Mangling rules: how enterprises modify passwords (Company2024!, company@123) — rule creation",d:"i"},
   {id:"29-5",t:"Rainbow tables: when they still make sense, trade-off with GPU cracking",d:"i"},
  ]},
  {t:"Online Attacks",items:[
   {id:"29-6",t:"Password spraying: timing, user enumeration, lockout evasion (threshold, delay, time of day)",d:"i"},
   {id:"29-7",t:"Credential stuffing: breach data use, OpenBullet workflow",d:"i"},
   {id:"29-8",t:"Kerberos pre-auth spray (AS-REQ): spray without lockout via Kerberos protocol quirk",d:"i"},
   {id:"29-9",t:"Default credentials: catalog by manufacturer/product, common patterns",d:"f"},
  ]},
  {t:"Credential Discovery",items:[
   {id:"29-10",t:"Mimikatz in depth: logonpasswords, sekurlsa, lsadump modules, dpapi module",d:"i"},
   {id:"29-11",t:"DPAPI: what it protects, extraction with domain credentials",d:"a"},
   {id:"29-12",t:"Browser credential extraction: Chrome, Firefox — vault locations and decryption",d:"i"},
   {id:"29-13",t:"Credential files: .rdp, .vnc, WinSCP, PuTTY stored sessions",d:"i"},
   {id:"29-14",t:"Config files: web.config, appsettings.json, .env files with hardcoded credentials",d:"f"},
  ]}
]},
{n:30,title:"ADFS / SAML / SSO",extra:true,deps:[9,12],
 desc:"Golden SAML, ADFS attacks, federation abuse. Increasingly relevant in hybrid environments.",
 sections:[
  {t:"ADFS",items:[
   {id:"30-1",t:"ADFS architecture: Relying Party Trusts, Claims Providers, Attribute Store",d:"i"},
   {id:"30-2",t:"Golden SAML: sign arbitrary SAML tokens with stolen token-signing key",d:"a"},
   {id:"30-3",t:"ADFSDump: extract ADFS configuration and signing keys",d:"a"},
   {id:"30-4",t:"ADFS password spray via Autodiscover endpoint (bypasses standard AD lockout)",d:"i"},
   {id:"30-5",t:"WS-Fed vs SAML 2.0: attack-relevant differences",d:"i"},
  ]},
  {t:"SAML in Depth",items:[
   {id:"30-6",t:"XML signature wrapping: manipulate assertions while keeping signature valid",d:"a"},
   {id:"30-7",t:"SAML response replay: reusing assertions without NotOnOrAfter verification",d:"a"},
   {id:"30-8",t:"Recipient and audience bypass: assertions accepted by wrong service providers",d:"a"},
  ]},
  {t:"SSO & OAuth",items:[
   {id:"30-9",t:"OAuth misconfigurations: implicit flow, missing PKCE, token leakage via Referer",d:"i"},
   {id:"30-10",t:"OpenID Connect: id_token manipulation, claim injection",d:"a"},
   {id:"30-11",t:"SAML vs OAuth vs OIDC: attack surface differences between the three protocols",d:"i"},
  ]}
]},
{n:31,title:"Thick Client / Fat Client",extra:true,deps:[4,7,11],
 desc:"Desktop applications with custom protocols and hardcoded credentials. Underexplored surface.",
 sections:[
  {t:"Analysis",items:[
   {id:"31-1",t:"Identify tech stack: .NET, Java, Electron, C++ — different approach for each",d:"i"},
   {id:"31-2",t:"Traffic proxying: Burp with HTTPS interception for apps that ignore system proxy",d:"i"},
   {id:"31-3",t:"SSL pinning bypass in desktop: .NET (custom validator), Java (cacerts), Electron apps",d:"a"},
   {id:"31-4",t:".NET decompilation: dnSpy/ILSpy for analyzing authentication logic in the client",d:"i"},
  ]},
  {t:"Attack Vectors",items:[
   {id:"31-5",t:"DLL hijacking: installed apps loading DLLs from writable locations",d:"i"},
   {id:"31-6",t:"Config files with hardcoded credentials: web.config, app.config, XML configuration",d:"i"},
   {id:"31-7",t:"Memory scraping at runtime: extract credentials or tokens from process memory",d:"a"},
   {id:"31-8",t:"SQL injection in local queries: apps building queries with local user input",d:"i"},
   {id:"31-9",t:"Custom binary protocol: apps using proprietary binary protocol — analysis and manipulation",d:"a"},
  ]}
]},
{n:32,title:"API Security",extra:true,deps:[11,12],
 desc:"REST, gRPC, GraphQL, WebSockets. Distinct attack surface beyond generic web vulnerabilities.",
 sections:[
  {t:"REST APIs",items:[
   {id:"32-1",t:"OWASP API Top 10: BOLA (IDOR), Broken Auth, Excessive Data Exposure, BFLA",d:"i"},
   {id:"32-2",t:"BOLA (Broken Object Level Authorization): ID manipulation in endpoints",d:"i"},
   {id:"32-3",t:"BFLA (Broken Function Level Authorization): accessing admin actions without privilege",d:"i"},
   {id:"32-4",t:"Mass assignment: APIs accepting extra fields and assigning them to objects unfiltered",d:"i"},
   {id:"32-5",t:"Improper asset management: old API versions without authentication still accessible",d:"i"},
  ]},
  {t:"gRPC & GraphQL",items:[
   {id:"32-6",t:"gRPC: protobuf as binary protocol, interception and manipulation with grpcurl/Burp",d:"i"},
   {id:"32-7",t:"gRPC reflection endpoint: service discovery exposing complete schema",d:"i"},
   {id:"32-8",t:"GraphQL: introspection, batching for rate-limit bypass, nested queries for DoS",d:"i"},
  ]},
  {t:"WebSockets & Real-Time",items:[
   {id:"32-9",t:"WebSocket hijacking: CSWSH (Cross-Site WebSocket Hijacking)",d:"i"},
   {id:"32-10",t:"Missing per-message auth: authentication only on handshake, not on each message",d:"i"},
   {id:"32-11",t:"Server-Sent Events: information disclosure via SSE streams",d:"i"},
  ]}
]},
{n:33,title:"Advanced Control Evasion",extra:true,deps:[10,12,14],
 desc:"DLP, CASB, PAM, NDR/NTA. Mature environments have these — each has specific bypass techniques.",
 sections:[
  {t:"DLP (Data Loss Prevention)",items:[
   {id:"33-1",t:"How DLPs inspect: content, context, destination — data fingerprinting mechanisms",d:"i"},
   {id:"33-2",t:"Content inspection evasion: encoding, encryption, steganography",d:"a"},
   {id:"33-3",t:"Exfil channels DLPs miss: DNS, ICMP, custom protocol over allowed ports",d:"a"},
   {id:"33-4",t:"Endpoint-based vs network-based DLP: different coverage and different blind spots",d:"i"},
  ]},
  {t:"CASB & PAM",items:[
   {id:"33-5",t:"CASB inline vs API mode: coverage differences and blind spots in each deployment",d:"i"},
   {id:"33-6",t:"Inline CASB evasion: uncategorized domains, split tunneling, apps that bypass proxy",d:"a"},
   {id:"33-7",t:"Shadow IT: using unsanctioned cloud services that CASB does not monitor",d:"i"},
   {id:"33-8",t:"CyberArk, BeyondTrust, Delinea: how PAMs work, JIT access model",d:"i"},
   {id:"33-9",t:"PAM attacks: credential injection via PSM, session recording gap exploitation",d:"a"},
  ]},
  {t:"NDR / NTA (Network Detection & Response)",items:[
   {id:"33-10",t:"Darktrace, ExtraHop, Vectra: how they identify anomalous behavior",d:"i"},
   {id:"33-11",t:"Low and slow evasion: mimicking human traffic patterns, reducing IOC density",d:"a"},
   {id:"33-12",t:"Beacon timing to appear as human traffic: variable intervals, business-hour aware",d:"a"},
  ]}
]},
{n:34,title:"Persistence (Full Taxonomy)",extra:true,deps:[2,4,10],
 desc:"Full Windows and Linux persistence taxonomy — far beyond scheduled tasks and registry run keys.",
 sections:[
  {t:"Windows User-Mode Persistence",items:[
   {id:"34-1",t:"Registry Run keys: HKCU vs HKLM — privilege and detection differences",d:"f"},
   {id:"34-2",t:"Startup folder: location, how it works, HKCU vs common startup",d:"f"},
   {id:"34-3",t:"Scheduled tasks: creation, detection evasion (XML, COM object method)",d:"i"},
   {id:"34-4",t:"WMI subscriptions: EventFilter + EventConsumer + FilterToConsumerBinding",d:"i"},
   {id:"34-5",t:"COM hijacking: HKCU\\Software\\Classes overrides HKLM for current user",d:"a"},
   {id:"34-6",t:"AppInit DLLs: loaded into every process using user32.dll",d:"a"},
   {id:"34-7",t:"IFEO (Image File Execution Options): Debugger key as process backdoor",d:"a"},
  ]},
  {t:"Windows Deep Persistence",items:[
   {id:"34-8",t:"BootExecute: process running before Windows fully loads",d:"a"},
   {id:"34-9",t:"LSA security packages: DLL loaded by LSASS on startup",d:"a"},
   {id:"34-10",t:"Netsh helper DLLs: DLL registered in netsh that loads on any netsh call",d:"a"},
   {id:"34-11",t:"Print monitor DLLs: loaded by the print spooler service",d:"a"},
   {id:"34-12",t:"Accessibility features backdoor: sethc.exe, utilman.exe replacement (classic technique)",d:"i"},
  ]},
  {t:"Linux Persistence",items:[
   {id:"34-13",t:"Cron jobs: /etc/cron.*, user crontab — detection and evasion",d:"f"},
   {id:"34-14",t:"Systemd services and timers: creating persistent service with custom unit file",d:"i"},
   {id:"34-15",t:"~/.bashrc, ~/.profile, ~/.bash_profile: user-level persistence",d:"f"},
   {id:"34-16",t:"/etc/ld.so.preload: global LD_PRELOAD equivalent for all processes",d:"a"},
   {id:"34-17",t:"SSH authorized_keys: public key for passwordless access",d:"f"},
   {id:"34-18",t:"PAM modules: malicious module that captures credentials on login",d:"a"},
  ]}
]},
{n:35,title:"Purple Team & Detection Engineering",extra:true,deps:[2,10,14],
 desc:"Understanding what the blue team sees. Designing attacks that avoid detection requires knowing the detector.",
 sections:[
  {t:"Detection Rules",items:[
   {id:"35-1",t:"Sigma rules: format, writing rules, converting to SIEM (Splunk, Elastic, Sentinel)",d:"i"},
   {id:"35-2",t:"YARA rules: syntax, writing detection for malware by string or byte pattern",d:"i"},
   {id:"35-3",t:"Critical Windows Event IDs: deep understanding of what each reveals about attack activity",d:"i"},
   {id:"35-4",t:"Sysmon: configuration, critical events (1,3,7,8,10,11,12,13), which rules to filter",d:"i"},
  ]},
  {t:"SIEM & Log Analysis",items:[
   {id:"35-5",t:"Splunk: SPL (Search Processing Language), correlation searches, dashboards",d:"i"},
   {id:"35-6",t:"Elastic/ECS: KQL, field mapping, ingestion pipeline",d:"i"},
   {id:"35-7",t:"Microsoft Sentinel: advanced KQL, workbooks, hunting queries",d:"i"},
   {id:"35-8",t:"Log sources: which logs to enable, where they live, what each covers",d:"i"},
  ]},
  {t:"Purple Team Operations",items:[
   {id:"35-9",t:"Atomic Red Team: running ATT&CK-mapped atomic tests, validating detection coverage",d:"i"},
   {id:"35-10",t:"Caldera: adversary emulation automation, agents, abilities, operations",d:"i"},
   {id:"35-11",t:"Purple team exercise: planning, execution, detection gap analysis, remediation",d:"i"},
   {id:"35-12",t:"Feedback loop: how red team output improves blue team detection over time",d:"i"},
  ]}
]},
{n:36,title:"Active Defense & Honeypots",extra:true,deps:[9,14,15],
 desc:"Triggering a honeypot during an operation exposes the entire campaign. Learn to recognize traps.",
 sections:[
  {t:"Identifying Traps",items:[
   {id:"36-1",t:"Canary tokens: types (URL, Word document, DNS), how to detect before triggering",d:"i"},
   {id:"36-2",t:"AD honeyaccounts: identifying trap accounts (never used, artificial SPNs, odd UAC flags)",d:"a"},
   {id:"36-3",t:"Honeyfiles and honeydirectories: detecting before opening or accessing",d:"i"},
   {id:"36-4",t:"Network honeypots: identifying hosts that should not exist but are accessible",d:"i"},
   {id:"36-5",t:"Port scan detection: how most networks detect scans and how to avoid triggering",d:"i"},
  ]},
  {t:"Deception Technology",items:[
   {id:"36-6",t:"How enterprises deploy deception: Attivo, Illusive Networks, Thinkst Canary",d:"i"},
   {id:"36-7",t:"Common Active Directory trap patterns: honeyaccounts, fake admin shares, deceptive SPN",d:"a"},
   {id:"36-8",t:"Techniques to map honeypots before interacting: behavioral indicators of deception",d:"a"},
  ]}
]},
{n:37,title:"Threat Emulation",extra:true,deps:[5,14,15],
 desc:"Building an operation based on a real threat actor. Intelligence-led red teaming at its most advanced.",
 sections:[
  {t:"Methodology",items:[
   {id:"37-1",t:"Intelligence-led red teaming: constructing an operation based on a real adversary",d:"i"},
   {id:"37-2",t:"Threat actor selection: which group actually threatens the client's sector and technology",d:"i"},
   {id:"37-3",t:"TTP mapping: map the group's known TTPs to the client's specific environment",d:"i"},
   {id:"37-4",t:"Adaptation: what the group does that cannot be replicated, and what substitutes",d:"a"},
  ]},
  {t:"Execution & Reporting",items:[
   {id:"37-5",t:"Fidelity vs practicality: when to simplify a TTP without losing test value",d:"i"},
   {id:"37-6",t:"Deviation documentation: recording where emulation diverged from the real actor",d:"i"},
   {id:"37-7",t:"Adversary-oriented report: not just 'we found X' but 'threat actor Y could do Z'",d:"i"},
  ]},
  {t:"Tools & References",items:[
   {id:"37-8",t:"MITRE ATT&CK Evaluations: how they are structured, what they teach about detection",d:"i"},
   {id:"37-9",t:"Breach & Attack Simulation (BAS): Cymulate, SafeBreach — complement or substitute?",d:"i"},
   {id:"37-10",t:"MITRE adversary emulation plans: public plans for APT29, FIN6, Carbanak",d:"i"},
  ]}
]},
{n:38,title:"Advanced Niches",extra:true,deps:[2,3],
 desc:"Mainframes and SS7/telecom. Extremely rare knowledge — banks, governments, state-level actors.",
 sections:[
  {t:"Mainframes (IBM z/OS)",items:[
   {id:"38-1",t:"z/OS architecture: JES, RACF, VSAM — completely different from Unix/Windows systems",d:"e"},
   {id:"38-2",t:"TN3270: mainframe terminal protocol, traffic analysis",d:"e"},
   {id:"38-3",t:"RACF: mainframe access control, enumeration and privilege escalation",d:"e"},
   {id:"38-4",t:"Why it matters: banks and financial institutions frequently still have mainframe cores",d:"f"},
   {id:"38-5",t:"Tooling: Nmap scripts for z/OS, mainframe-specific pentesting tools",d:"e"},
  ]},
  {t:"SS7 & Telecom",items:[
   {id:"38-6",t:"SS7 (Signaling System 7): telecom signaling protocol, SMS/call interception",d:"e"},
   {id:"38-7",t:"SIM swapping: social engineering via carrier, MFA SMS bypass impact",d:"i"},
   {id:"38-8",t:"Diameter: SS7 successor in 4G/LTE networks, similar vulnerability classes",d:"e"},
   {id:"38-9",t:"Why it matters: bypass of SMS-based MFA and OTP interception used by APT groups",d:"i"},
  ]}
]}
];
