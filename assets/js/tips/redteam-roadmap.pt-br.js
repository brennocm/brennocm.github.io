/* Red Team Roadmap — dados das camadas (pt-BR).
   Estrutura: camada > seções > itens. `d` é a dificuldade: f=entry, i=mid, a=senior, e=expert.
   Os ids dos tópicos são identificadores estáveis e opacos: são idênticos aos da
   versão en-US (redteam-roadmap.en-us.js) — então o progresso salvo em um idioma
   vale para o outro — e propositalmente NÃO acompanham o número da camada, para que
   reordenar as camadas não zere o progresso de ninguém. Nomes de ferramentas,
   técnicas e siglas ficam em inglês, como é padrão no meio de segurança ofensiva. */
window.RT_LAYERS = [
{n:1,title:"Arquitetura de Computadores",extra:false,deps:[],
 desc:"Base absoluta. Sem isto você não entende por que os exploits funcionam num nível real.",
 sections:[
  {t:"CPU & Execução",items:[
   {id:"1-1",t:"Arquitetura x86/x64: registradores gerais, de segmento, de controle (CR0,CR3,CR4), de debug (DR0-DR7)",d:"f"},
   {id:"1-2",t:"Conjunto completo de instruções x86/x64 — SYSENTER, SYSCALL, IRET, MOV SS e instruções de shellcode/exploit",d:"i"},
   {id:"1-3",t:"Arquitetura ARM/AArch64 — necessária para mobile e dispositivos embarcados",d:"i"},
   {id:"1-4",t:"Pipeline de execução: fetch, decode, execute, writeback",d:"f"},
   {id:"1-5",t:"Execução out-of-order e especulativa — base das variantes Spectre/Meltdown",d:"a"},
   {id:"1-6",t:"Branch prediction e sua exploração ofensiva como vetor de side-channel",d:"a"},
   {id:"1-7",t:"Modos de operação da CPU: real mode, protected mode, long mode, SMM (System Management Mode)",d:"i"},
   {id:"1-8",t:"Ring levels (0-3): o que cada nível realmente permite no hardware",d:"f"},
   {id:"1-9",t:"Transições de ring: como uma syscall acontece no nível de hardware",d:"i"},
   {id:"1-10",t:"Intel VT-x, AMD-V, VMCS — base de hypervisors e da evasão que os explora",d:"a"},
   {id:"1-11",t:"TLB (Translation Lookaside Buffer) e page table walks",d:"i"},
   {id:"1-12",t:"Hierarquia de cache (L1/L2/L3) e ataques de side-channel: Flush+Reload, Prime+Probe",d:"a"},
   {id:"1-13",t:"SMEP e SMAP: implementação em hardware e bypasses históricos",d:"a"},
   {id:"1-14",t:"NX/XD bit: executar dados como código e por que o DEP existe",d:"f"},
   {id:"1-15",t:"ASLR: implementação em hardware vs no SO — diferenças que importam para o bypass",d:"i"},
   {id:"1-16",t:"Intel SGX e ARM TrustZone — TEEs como superfície de ataque emergente",d:"e"},
  ]},
  {t:"Firmware & Boot",items:[
   {id:"1-17",t:"BIOS legado vs UEFI: estrutura, serviços, sequência completa de boot",d:"i"},
   {id:"1-18",t:"Internals do UEFI: DXE, PEI, SMM — onde vive a persistência em firmware",d:"a"},
   {id:"1-19",t:"Secure Boot: chain of trust, BootHole e BlackLotus como estudos de caso reais",d:"a"},
   {id:"1-20",t:"TPM: PCRs, sealed storage, cold boot attacks contra chaves seladas",d:"a"},
   {id:"1-21",t:"Option ROMs como vetor de persistência pré-SO",d:"e"},
   {id:"1-22",t:"Intel ME e AMD PSP: superfície de ataque e implicações de OPSEC",d:"e"},
  ]}
]},
{n:2,title:"Sistemas Operacionais",extra:false,deps:[1],
 desc:"Windows Internals com profundidade real. É aqui que a maioria dos ataques e defesas de fato acontece.",
 sections:[
  {t:"Windows — Arquitetura Geral",items:[
   {id:"2-1",t:"Separação user-mode/kernel-mode em detalhe operacional",d:"f"},
   {id:"2-2",t:"Componentes do kernel: Executive, HAL, núcleo do kernel, drivers",d:"i"},
   {id:"2-3",t:"Caminho completo de syscall: Win32 API → NTDLL → syscall stub → kernel",d:"i"},
   {id:"2-4",t:"Números de syscall (SSN) e por que mudam entre versões do Windows — relevância para direct syscalls",d:"a"},
   {id:"2-5",t:"SSDT (System Service Descriptor Table): hooks históricos e variações atuais",d:"a"},
  ]},
  {t:"Windows — Gerência de Memória",items:[
   {id:"2-6",t:"Layout do espaço de endereços virtual x64: PEB, TEB, stack, heap, módulos carregados",d:"i"},
   {id:"2-7",t:"Árvore VAD (Virtual Address Descriptor): como o kernel rastreia regiões de memória por processo",d:"a"},
   {id:"2-8",t:"Working sets, page faults, demand paging",d:"i"},
   {id:"2-9",t:"Memory mapped files e sections: como DLLs são realmente mapeadas, sections compartilhadas entre processos",d:"i"},
   {id:"2-10",t:"Internals do heap: NT Heap vs Segment Heap (Win10+), chunks, freelists, lookaside lists",d:"a"},
   {id:"2-11",t:"Large pages e AWE (Address Windowing Extensions): uso na evasão de memory scan de EDR",d:"a"},
   {id:"2-12",t:"CFG (Control Flow Guard): bitmap de funções válidas, implementação e bypasses documentados",d:"a"},
  ]},
  {t:"Windows — Processos & Threads",items:[
   {id:"2-13",t:"EPROCESS e ETHREAD: estruturas de kernel, Token, ActiveProcessLinks, ponteiro para o PEB",d:"a"},
   {id:"2-14",t:"PEB completo: InMemoryOrderModuleList, BeingDebugged, flags de NtGlobalFlag",d:"i"},
   {id:"2-15",t:"TEB: stack base/limit, cadeia SEH, TLS slots",d:"i"},
   {id:"2-16",t:"Internals de criação de processo: NtCreateUserProcess — por que process hollowing é possível",d:"a"},
   {id:"2-17",t:"Modelo de token: impersonation vs delegation, integrity levels (MIC), atributos de privilégio",d:"i"},
   {id:"2-18",t:"Job objects e silos (base dos containers do Windows)",d:"i"},
   {id:"2-19",t:"Fibers e seu uso na evasão de detecção por EDR",d:"a"},
  ]},
  {t:"Windows — I/O, Drivers & Callbacks",items:[
   {id:"2-20",t:"IRP (I/O Request Packet): modelo de comunicação com drivers",d:"a"},
   {id:"2-21",t:"Modelo de driver (WDM/WDF), carregamento, Driver Signature Enforcement",d:"a"},
   {id:"2-22",t:"Filter drivers: filesystem minifilters — onde EDRs interceptam operações de arquivo",d:"a"},
   {id:"2-23",t:"Kernel callbacks: PsSetCreateProcessNotifyRoutine, CmRegisterCallback — o que os EDRs monitoram",d:"a"},
   {id:"2-24",t:"Object callbacks: ObRegisterCallbacks para interceptar aberturas de handle",d:"a"},
  ]},
  {t:"Windows — Segurança & Credenciais",items:[
   {id:"2-25",t:"SAM, LSA, LSASS: onde as credenciais vivem e como são estruturadas na memória",d:"i"},
   {id:"2-26",t:"Kerberos no Windows: TGT/TGS na memória, estrutura interna do LSASS",d:"i"},
   {id:"2-27",t:"NTLM: challenge-response em detalhe, derivação do NT hash",d:"i"},
   {id:"2-28",t:"Credential Guard: isolamento por HVCI, por que pass-the-hash falha contra ele",d:"a"},
   {id:"2-29",t:"Protected Processes (PPL): proteção do LSASS, bypasses documentados",d:"a"},
   {id:"2-30",t:"Internals do AMSI: hook em powershell.exe/wscript.exe, detecções baseadas em ETW",d:"a"},
  ]},
  {t:"Windows — ETW, COM & WMI",items:[
   {id:"2-31",t:"ETW: providers, consumers, sessions, controllers — arquitetura completa",d:"i"},
   {id:"2-32",t:"Como EDRs modernos dependem do ETW para detecção comportamental",d:"i"},
   {id:"2-33",t:"ETW tampering: patch em EtwEventWrite, remoção de provider via ioctl",d:"a"},
   {id:"2-34",t:"Internals do COM: apartment model, proxy/stub, moniker — vetores de lateral movement e persistência",d:"i"},
   {id:"2-35",t:"WMI: repository, providers, permanent subscriptions como persistência",d:"i"},
   {id:"2-36",t:"DCOM e suas implicações de rede para lateral movement",d:"i"},
  ]},
  {t:"Linux Internals",items:[
   {id:"2-37",t:"Kernel space vs user space, diferenças de implementação de syscall entre Linux e Windows",d:"f"},
   {id:"2-38",t:"VFS (Virtual Filesystem Switch): abstração de operações de arquivo pelo kernel",d:"i"},
   {id:"2-39",t:"Namespaces e cgroups: base dos containers, container escape",d:"i"},
   {id:"2-40",t:"Capabilities: modelo granular de privilégio além de root/não-root",d:"i"},
   {id:"2-41",t:"ptrace: debugging, injeção de código, proteções do Yama LSM",d:"i"},
   {id:"2-42",t:"LD_PRELOAD e dynamic linker: hooking e evasão no Linux",d:"i"},
   {id:"2-43",t:"Filesystem /proc: o que expõe, uso em recon e evasão",d:"i"},
   {id:"2-44",t:"eBPF: uso legítimo, rootkits em eBPF como área de pesquisa ativa",d:"a"},
   {id:"2-45",t:"LSM (SELinux, AppArmor): como funcionam e bypasses documentados",d:"i"},
   {id:"2-46",t:"Mitigações do Linux: ASLR, PIE, stack canaries, RELRO — implementação real e bypass",d:"i"},
  ]},
  {t:"macOS Internals",items:[
   {id:"2-47",t:"Kernel XNU: híbrido Mach + BSD, diferenças relevantes para o atacante",d:"i"},
   {id:"2-48",t:"Mach ports: primitiva de IPC, vetor de escalação de privilégios",d:"a"},
   {id:"2-49",t:"SIP, TCC, Gatekeeper/notarization: modelo de segurança e bypasses",d:"i"},
   {id:"2-50",t:"Endpoint Security Framework: substituiu as kexts para EDRs no macOS",d:"i"},
   {id:"2-51",t:"dyld e DYLD_INSERT_LIBRARIES: análogo do LD_PRELOAD no macOS",d:"i"},
  ]}
]},
{n:3,title:"Redes",extra:false,deps:[1,2],
 desc:"Não é 'como configurar TCP/IP' — é entender o tráfego no nível de pacote e construir C2 que se mistura ao ruído.",
 sections:[
  {t:"Protocolos em Profundidade",items:[
   {id:"3-1",t:"Ethernet: frames, endereçamento MAC, ARP em detalhe (cache poisoning, gratuitous ARP)",d:"f"},
   {id:"3-2",t:"IPv4 e IPv6: fragmentação, manipulação de TTL, diferenças de implementação entre SOs",d:"f"},
   {id:"3-3",t:"TCP: three-way handshake, máquina de estados completa, session hijacking, sequence prediction",d:"f"},
   {id:"3-4",t:"DNS: hierarquia completa, tipos de registro, zone transfer, DoH/DoT, DNS tunneling como C2",d:"i"},
   {id:"3-5",t:"HTTP/1.1, HTTP/2, HTTP/3: diferenças relevantes para evasão de proxy e WAF",d:"i"},
   {id:"3-6",t:"TLS: handshake em detalhe, cipher suites, certificate pinning, fingerprinting JA3/JA3S e bypass",d:"i"},
   {id:"3-7",t:"SMB (v1/v2/v3): dialetos, autenticação NTLM sobre SMB — base dos ataques de relay",d:"i"},
   {id:"3-8",t:"Kerberos na rede: AS-REQ/AS-REP, TGS-REQ/TGS-REP no nível de pacote",d:"i"},
   {id:"3-9",t:"LDAP: protocolo, queries avançadas, o que dá para consultar sem autenticação",d:"i"},
   {id:"3-10",t:"RPC: endpoints, lateral movement por RPC via WMI/SCM/Task Scheduler",d:"i"},
   {id:"3-11",t:"WinRM/WSMan: protocolo, autenticação, internals do PowerShell remoting",d:"i"},
   {id:"3-12",t:"ICMP: types e codes, ICMP tunneling como C2",d:"i"},
  ]},
  {t:"Análise de Tráfego",items:[
   {id:"3-13",t:"Wireshark a fundo: display vs capture filters, análise de stream, dissectors customizados",d:"i"},
   {id:"3-14",t:"Tshark para análise automatizada de pcap em escala",d:"i"},
   {id:"3-15",t:"Identificação de tráfego C2: intervalos de beacon, jitter, padrões de tamanho de pacote",d:"a"},
   {id:"3-16",t:"Como IDS/IPS analisam tráfego: regras Snort/Suricata, o que dispara alertas",d:"i"},
   {id:"3-17",t:"Forense de rede: reconstrução de sessão, extração de arquivos a partir de capturas",d:"i"},
  ]},
  {t:"Infraestrutura Ofensiva",items:[
   {id:"3-18",t:"Redirectors de DNS: separar o C2 real da exposição direta",d:"a"},
   {id:"3-19",t:"Redirectors HTTPS com Apache/Nginx mod_rewrite: filtragem de tráfego de sandbox",d:"a"},
   {id:"3-20",t:"CDN fronting para C2 (domain fronting): como funcionava, limitações atuais e variantes",d:"a"},
   {id:"3-21",t:"Domínios envelhecidos, categorização de domínio e como proxies corporativos verificam reputação",d:"a"},
   {id:"3-22",t:"BGP hijacking: conceitual, mas relevante para ataques de infraestrutura em larga escala",d:"e"},
  ]}
]},
{n:4,title:"Programação",extra:false,deps:[1,2],
 desc:"Não é só scripting — é entender código num nível baixo o bastante para escrever ferramentas, loaders e shellcode.",
 sections:[
  {t:"Assembly x86/x64",items:[
   {id:"4-1",t:"Registradores e calling conventions: cdecl, stdcall, fastcall, System V AMD64, Microsoft x64 ABI",d:"i"},
   {id:"4-2",t:"Ler e escrever shellcode: entender cada instrução, identificar padrões comuns",d:"i"},
   {id:"4-3",t:"Código position-independent (PIC): shellcode que funciona em qualquer endereço",d:"i"},
   {id:"4-4",t:"Técnicas de shellcode: egg hunters, staged shellcode, evitar null bytes e bad chars",d:"a"},
   {id:"4-5",t:"Assembly inline em C: misturar ASM com código de alto nível",d:"i"},
  ]},
  {t:"C e C++",items:[
   {id:"4-6",t:"Ponteiros a fundo: aritmética, function pointers, pointer-to-pointer, void*",d:"i"},
   {id:"4-7",t:"Gerência manual de memória: internals de malloc/free, use-after-free, double-free, buffer overflow",d:"i"},
   {id:"4-8",t:"Structs e alinhamento de memória: como o compilador organiza estruturas, padding, packing",d:"i"},
   {id:"4-9",t:"Windows API em C puro: kernel32, ntdll, advapi32 sem wrappers",d:"i"},
   {id:"4-10",t:"Interagir com estruturas de kernel a partir do user-mode: acessar PEB, TEB via ponteiros explícitos",d:"a"},
   {id:"4-11",t:"Compilação e linking: import tables, export tables, como DLLs são carregadas",d:"i"},
   {id:"4-12",t:"SEH (Structured Exception Handling): mecânica da cadeia, uso em exploits",d:"a"},
  ]},
  {t:"Rust & Go (Tooling Moderno)",items:[
   {id:"4-13",t:"Rust: FFI para a Windows API, Unsafe Rust, binários standalone mais difíceis de analisar",d:"a"},
   {id:"4-14",t:"Go: binários estáticos por padrão, goroutines, cross-compilation nativa",d:"i"},
   {id:"4-15",t:"Por que Rust/Go dominam o tooling ofensivo moderno: detecção por assinatura é mais difícil",d:"i"},
  ]},
  {t:"Python, PowerShell & Shell",items:[
   {id:"4-16",t:"Python avançado: ctypes para a Windows API, struct para dados binários, socket para protocolos customizados",d:"i"},
   {id:"4-17",t:"Escrever exploits e PoCs em Python: parsing de formato binário, fuzzing simples",d:"i"},
   {id:"4-18",t:"Internals do PowerShell: onde fica o hook do AMSI, engine .NET/CLR, reflection para carregar assemblies",d:"a"},
   {id:"4-19",t:"Constrained Language Mode: o que restringe, bypasses documentados",d:"a"},
   {id:"4-20",t:"Script block logging, module logging, transcription: o que cada um captura e como evadir",d:"a"},
   {id:"4-21",t:"Bash: automação de operações no Linux, built-ins para evitar spawnar binários externos monitorados",d:"i"},
  ]}
]},
{n:5,title:"Frameworks, Legal & Metodologia",extra:true,deps:[],
 desc:"O que estrutura um engagement profissional. Sem isto, a execução técnica não tem contexto nem proteção.",
 sections:[
  {t:"Frameworks & Metodologia",items:[
   {id:"24-1",t:"MITRE ATT&CK: uso para planejamento e reporte, ATT&CK Navigator, layers customizadas por engagement",d:"f"},
   {id:"24-2",t:"PTES (Penetration Testing Execution Standard): fases e entregáveis esperados",d:"f"},
   {id:"24-3",t:"TIBER-EU / CBEST: red teaming guiado por threat intelligence — o que o separa do pentest convencional",d:"i"},
   {id:"24-4",t:"Lockheed Martin Cyber Kill Chain vs ATT&CK: quando usar cada modelo",d:"f"},
   {id:"24-5",t:"OWASP Testing Guide e ASVS: referências para escopo de aplicação web",d:"f"},
  ]},
  {t:"Legal & Operacional",items:[
   {id:"24-6",t:"Rules of Engagement: o que deve constar, get-out-of-jail letter, chain of custody",d:"f"},
   {id:"24-7",t:"Scoping: o que incluir/excluir, sistemas out-of-scope, notificar provedores de cloud",d:"f"},
   {id:"24-8",t:"Lei 12.737/2012 (Brasil) e equivalentes internacionais: responsabilidade legal do operador",d:"f"},
   {id:"24-9",t:"CFAA (Computer Fraud and Abuse Act): por que importa mesmo fora dos EUA",d:"i"},
   {id:"24-10",t:"Reporte técnico: estrutura, comunicar risco para público técnico vs executivo",d:"f"},
   {id:"24-11",t:"Threat modeling ofensivo: STRIDE na perspectiva do atacante, definir objetivos operacionais",d:"i"},
   {id:"24-12",t:"Responsible disclosure: CVD, timelines, comunicação com o fornecedor",d:"i"},
  ]}
]},
{n:6,title:"Criptografia Aplicada",extra:false,deps:[3,4],
 desc:"Não é teoria matemática profunda — o suficiente para construir C2 seguro, atacar implementações de protocolo e quebrar credenciais.",
 sections:[
  {t:"Fundamentos Aplicados",items:[
   {id:"5-1",t:"Cripto simétrica: AES (ECB vs CBC vs GCM e por que importa), ChaCha20",d:"f"},
   {id:"5-2",t:"Cripto assimétrica: RSA e ECC — como são usadas em protocolos, onde as implementações falham",d:"i"},
   {id:"5-3",t:"Hashing: MD5, SHA-1/256/512, derivação do NTLM hash, bcrypt — contexto de cracking",d:"f"},
   {id:"5-4",t:"PKI: cadeia de certificados, CRL, OCSP — TLS na prática, interceptação de cert em MITM corporativo",d:"i"},
   {id:"5-5",t:"Cripto do Kerberos: RC4-HMAC vs AES128/256 — por que importa para Kerberoasting",d:"i"},
   {id:"5-6",t:"Ataques a implementação: padding oracle, CBC bit-flipping, nonce reutilizado no modo CTR",d:"a"},
   {id:"5-7",t:"Construir canais C2 cifrados que evadem análise de protocolo",d:"a"},
  ]}
]},
{n:7,title:"Engenharia Reversa",extra:false,deps:[1,2,4],
 desc:"Reconstruir a lógica de um binário sem código-fonte. Base para análise de malware e desenvolvimento de exploits.",
 sections:[
  {t:"Ferramentas & Metodologia",items:[
   {id:"6-1",t:"IDA Pro a fundo: scripting com IDAPython, navegar em binários grandes, structs customizadas",d:"a"},
   {id:"6-2",t:"Ghidra: decompiler, scripting em Java/Python, quando usar em vez do IDA",d:"i"},
   {id:"6-3",t:"x64dbg/WinDbg: breakpoints (software, hardware, memória), stepping, análise em runtime",d:"i"},
   {id:"6-4",t:"Kernel debugging com WinDbg: setup do KD, análise de crash dump, inspeção de structs do kernel",d:"a"},
   {id:"6-5",t:"Análise estática vs dinâmica: quando usar cada uma, como combinar para máxima eficiência",d:"i"},
   {id:"6-6",t:"Anti-debugging: variantes de IsDebuggerPresent, timing checks, NtQueryInformationProcess",d:"i"},
   {id:"6-7",t:"Anti-VM e anti-sandbox: checagem de artefatos, verificação de interação humana — e como fazer bypass",d:"i"},
   {id:"6-8",t:"Ofuscação de código: control flow flattening, código bogus, string encryption — como reverter",d:"a"},
   {id:"6-9",t:"Packing: como packers funcionam (compress+encrypt+stub), identificar binários empacotados, unpack manual",d:"i"},
   {id:"6-10",t:"Engenharia reversa de .NET: dnSpy, ILSpy — muitas ferramentas de red team e malwares são .NET",d:"i"},
   {id:"6-11",t:"Análise prática de malware: lab seguro, Procmon+Procexp+Autoruns+Wireshark em conjunto",d:"i"},
   {id:"6-12",t:"Binary diffing: BinDiff para comparar versões, descoberta de vulnerabilidade a partir de patch",d:"a"},
  ]}
]},
{n:8,title:"Desenvolvimento de Exploits",extra:false,deps:[1,2,4,6,7],
 desc:"Onde red team e vuln research se sobrepõem. Exige a pilha de dependências mais completa.",
 sections:[
  {t:"Corrupção de Memória",items:[
   {id:"7-1",t:"Stack buffer overflow: smashing the stack, sobrescrita de return address, ROP chains básicas",d:"i"},
   {id:"7-2",t:"Heap exploitation no Windows: use-after-free, double-free, heap spray — NT Heap e Segment Heap",d:"a"},
   {id:"7-3",t:"Heap exploitation no Linux: internals do glibc malloc, tcache poisoning, fastbin corruption",d:"a"},
   {id:"7-4",t:"Vulnerabilidades de format string: leitura/escrita arbitrária via %n, exploração moderna",d:"i"},
   {id:"7-5",t:"Integer overflows e como levam a corrupção de memória",d:"i"},
   {id:"7-6",t:"Type confusion: como ocorre, exploração em compiladores JIT e parsers de objeto",d:"e"},
  ]},
  {t:"Mitigações Modernas & Bypasses",items:[
   {id:"7-7",t:"ASLR: information leaks como pré-requisito para bypass confiável em 64 bits",d:"i"},
   {id:"7-8",t:"Bypass de DEP/NX: ROP (Return-Oriented Programming) — construir cadeias de gadgets",d:"a"},
   {id:"7-9",t:"Stack canaries: técnicas de leak, partial overwrites",d:"i"},
   {id:"7-10",t:"CFG e CFI genérico: como restringem os alvos de call, bypasses documentados",d:"a"},
   {id:"7-11",t:"Safe Unlinking (heap) e técnicas modernas de heap exploitation pós-mitigação",d:"e"},
  ]},
  {t:"Kernel Exploits",items:[
   {id:"7-12",t:"Superfície de ataque: drivers vulneráveis (mais comuns que bugs no núcleo do kernel), ioctl handlers",d:"a"},
   {id:"7-13",t:"Primitivas de kernel exploit: leitura/escrita arbitrária, null pointer dereference, type confusion",d:"a"},
   {id:"7-14",t:"Token stealing: localizar o token de um processo privilegiado via cadeia EPROCESS e copiar para o processo do atacante",d:"a"},
   {id:"7-15",t:"Kernel shellcode: diferenças do shellcode de userland rodando em ring 0",d:"e"},
  ]}
]},
{n:9,title:"Active Directory",extra:false,deps:[2,3,6],
 desc:"Presente em praticamente toda empresa. Dominar AD é dominar lateral movement e persistência.",
 sections:[
  {t:"Fundamentos Reais",items:[
   {id:"8-1",t:"Schema do AD: como objetos são definidos, atributos, object classes",d:"f"},
   {id:"8-2",t:"LDAP como protocolo de acesso: queries avançadas, atributos relevantes (adminCount, SPN, msDS-AllowedToActOnBehalfOfOtherIdentity)",d:"i"},
   {id:"8-3",t:"Sites e subnets: como a replicação funciona, implicações de autenticação cross-site",d:"i"},
   {id:"8-4",t:"Trusts: tipos, direcionalidade, transitividade, SID filtering — base de ataques cross-forest",d:"a"},
   {id:"8-5",t:"GPOs: aplicação, precedência LSDOU, SYSVOL, abuso de GPO para lateral movement/persistência",d:"i"},
   {id:"8-6",t:"OUs e delegação: delegation of control, quem tem permissão sobre quais objetos",d:"i"},
  ]},
  {t:"Autenticação em Profundidade",items:[
   {id:"8-7",t:"Kerberos: AS-REQ/AS-REP, pre-authentication, TGS-REQ/TGS-REP em nível técnico completo",d:"i"},
   {id:"8-8",t:"PAC (Privilege Attribute Certificate): conteúdo, validação pelo DC — base do Golden Ticket",d:"a"},
   {id:"8-9",t:"S4U2Self e S4U2Proxy: constrained delegation, RBCD — como a má configuração permite impersonation",d:"a"},
   {id:"8-10",t:"Unconstrained delegation: por que é tão perigosa, exploração via printer bug/coercion",d:"a"},
   {id:"8-11",t:"NTLM: NTLMv1 vs NTLMv2, implicações de cracking, NTLM relay em profundidade",d:"i"},
   {id:"8-12",t:"Pass-the-Hash em nível de protocolo: autenticar direto com o hash no challenge-response",d:"i"},
  ]},
  {t:"Ataques a AD",items:[
   {id:"8-13",t:"BloodHound/SharpHound: o que coletam, análise do grafo de ataque, queries Cypher avançadas",d:"i"},
   {id:"8-14",t:"Kerberoasting e AS-REP Roasting em profundidade técnica — não só rodar o Rubeus",d:"i"},
   {id:"8-15",t:"DCSync: permissões de replicação necessárias, por que funciona, detecção",d:"a"},
   {id:"8-16",t:"Golden, Silver, Diamond, Sapphire Tickets — diferenças e implicações de detecção",d:"a"},
   {id:"8-17",t:"ADCS: ESC1-ESC8 e além — cada má configuração como vetor de escalação ou persistência",d:"a"},
   {id:"8-18",t:"Ataques baseados em ACL: WriteDACL, GenericAll, GenericWrite, ForceChangePassword — encadeamento no BH",d:"i"},
   {id:"8-19",t:"AdminSDHolder: como o abuso persiste mesmo após remover a permissão",d:"a"},
   {id:"8-20",t:"LAPS e gMSA: onde as senhas ficam, quem pode lê-las, como enumerar",d:"i"},
  ]}
]},
{n:10,title:"Malware Dev & Evasão de EDR",extra:false,deps:[2,4,7],
 desc:"O que separa red teams de alto nível de quem só roda ferramentas públicas. Exige profundidade real em internals de SO.",
 sections:[
  {t:"Loaders & Process Injection",items:[
   {id:"9-1",t:"Injeção clássica: VirtualAllocEx+WriteProcessMemory+CreateRemoteThread — por que é muito detectada",d:"i"},
   {id:"9-2",t:"Process hollowing: como funciona, por que é mais evasivo, onde os EDRs ainda pegam",d:"a"},
   {id:"9-3",t:"Process doppelganging: abuso de transações NTFS, status atual de detecção",d:"a"},
   {id:"9-4",t:"Thread hijacking: suspender thread existente, alterar a struct CONTEXT, retomar",d:"a"},
   {id:"9-5",t:"APC injection e Early Bird APC: executar antes de os hooks do EDR carregarem",d:"a"},
   {id:"9-6",t:"Injeção de shellcode via Windows fibers",d:"a"},
   {id:"9-7",t:"Module stomping/overloading: shellcode sobre a memória de uma DLL legítima, evadindo scans de região image-backed",d:"a"},
   {id:"9-8",t:"DLL injection: baseada em LoadLibrary, reflective DLL injection, manual mapping",d:"i"},
  ]},
  {t:"Evasão de EDR",items:[
   {id:"9-9",t:"Hooking em user-mode: como EDRs interceptam funções da NTDLL (inline hooks, IAT hooks)",d:"i"},
   {id:"9-10",t:"Direct syscalls: Hell's Gate, Halo's Gate, Tartarus' Gate — variantes que lidam com hooks nos stubs",d:"a"},
   {id:"9-11",t:"Unhooking: restaurar os bytes originais — do disco, de uma segunda instância da NTDLL, cópia limpa",d:"a"},
   {id:"9-12",t:"AMSI bypass: patch em memória do amsi.dll, via COM, via reflection .NET — ciclo de vida de cada técnica",d:"a"},
   {id:"9-13",t:"ETW tampering: patch em EtwEventWrite, desabilitar providers específicos",d:"a"},
   {id:"9-14",t:"Sleep obfuscation: Ekko, Foliage, Cronos — cifrar o implant na memória entre beacons",d:"a"},
   {id:"9-15",t:"Stack spoofing: call stacks sintéticas para enganar a análise comportamental do EDR",d:"e"},
   {id:"9-16",t:"Heap encryption entre beacons e ofuscação do PE header",d:"a"},
  ]},
  {t:"C2 & Comunicação",items:[
   {id:"9-17",t:"Perfis Malleable C2 (Cobalt Strike): cada campo, o que ele controla para detecção",d:"a"},
   {id:"9-18",t:"Staging vs stageless: trade-offs operacionais e de detecção",d:"i"},
   {id:"9-19",t:"C2 sobre protocolos legítimos: HTTP/S, DNS, SMB named pipes — características de detecção de cada um",d:"a"},
   {id:"9-20",t:"Beaconing: jitter, variação de intervalo, por que padrões regulares são detectados por análise de tráfego",d:"i"},
   {id:"9-21",t:"Exfiltração: chunking, uso de serviços legítimos (OneDrive, GitHub, Slack como canais)",d:"a"},
  ]}
]},
{n:11,title:"Segurança de Aplicações Web",extra:false,deps:[3,4,6],
 desc:"Maior superfície de ataque externa. Vai muito além de rodar um scanner — exige entender parsers e runtimes.",
 sections:[
  {t:"Vulnerabilidades em Profundidade",items:[
   {id:"10-1",t:"SQLi: todos os tipos, WAF bypass, second-order, stacked queries — entender como parsers SQL funcionam",d:"i"},
   {id:"10-2",t:"XSS: stored/reflected/DOM, bypass real de CSP, XSS-to-RCE em apps Electron",d:"i"},
   {id:"10-3",t:"SSRF: bypass de filtro de IP (IPv6, encoding, redirects), acesso a metadata de cloud (IMDSv1/v2)",d:"i"},
   {id:"10-4",t:"XXE: in-band, OOB via DNS/HTTP, via file upload, XXE em parsers JSON com suporte a XML",d:"i"},
   {id:"10-5",t:"Desserialização: gadget chains em Java (ysoserial), .NET (TypeNameHandling), PHP (magic methods)",d:"a"},
   {id:"10-6",t:"SSTI: identificar o template engine pelo payload, exploração em Jinja2, Twig, Freemarker",d:"i"},
   {id:"10-7",t:"OAuth 2.0 e OIDC: fluxos em detalhe, state fixation, bypass de redirect_uri, token leakage",d:"a"},
   {id:"10-8",t:"JWT: algorithm confusion (RS256 para HS256 com chave pública), algoritmo none, secrets fracos",d:"i"},
   {id:"10-9",t:"HTTP request smuggling: CL.TE, TE.CL, TE.TE — diferença de parsing como vulnerabilidade",d:"a"},
   {id:"10-10",t:"GraphQL: introspection, batching para bypass de rate-limit, DoS por nested query",d:"i"},
   {id:"10-11",t:"Race conditions: single-packet attack (Turbo Intruder), explorar janelas de timing",d:"a"},
   {id:"10-12",t:"Cache poisoning vs cache deception: unkeyed headers, identificação e exploração",d:"a"},
  ]},
  {t:"Autenticação & Sessões",items:[
   {id:"10-13",t:"Cookies: flags HttpOnly, Secure, SameSite, session fixation, cookie tossing",d:"i"},
   {id:"10-14",t:"Bypass de MFA: leakage de OTP, backup codes, adversary-in-the-middle estilo evilginx",d:"i"},
   {id:"10-15",t:"Subdomain takeover: identificar CNAMEs apontando para serviços abandonados",d:"i"},
  ]}
]},
{n:12,title:"Segurança em Cloud",extra:false,deps:[3,9,11],
 desc:"Ambientes modernos são em grande parte cloud. O vetor principal é IAM mal configurado, não exploit de software.",
 sections:[
  {t:"AWS",items:[
   {id:"11-1",t:"IAM a fundo: políticas identity-based vs resource-based, SCPs no Organizations, permission boundaries",d:"i"},
   {id:"11-2",t:"Escalação de privilégio em IAM: vetores PassRole+Lambda, nova versão de política, AttachUserPolicy",d:"a"},
   {id:"11-3",t:"IMDSv1 e IMDSv2: por que o v1 é trivialmente acessível via SSRF, proteções do v2 e bypasses",d:"i"},
   {id:"11-4",t:"Roles e AssumeRole: cross-account, problema do confused deputy",d:"i"},
   {id:"11-5",t:"S3: bucket policies, ACLs, public access settings, técnicas de enumeração de bucket",d:"i"},
   {id:"11-6",t:"Serviços como vetores: injeção em Lambda, EC2 user data, SSM Run Command como lateral movement",d:"a"},
  ]},
  {t:"Azure / Entra ID",items:[
   {id:"11-7",t:"Entra ID vs AD on-premises: cloud-only vs híbrido, AD Connect como ponte de ataque",d:"i"},
   {id:"11-8",t:"Service Principals e Managed Identities: abuso de permissões excessivas",d:"i"},
   {id:"11-9",t:"PRT (Primary Refresh Token): o que é, como é armazenado, lateral movement híbrido",d:"a"},
   {id:"11-10",t:"Azure roles vs Entra ID roles: distinção, como mapeiam para recursos diferentes",d:"i"},
   {id:"11-11",t:"Conditional Access: o que é, bypasses em certas configurações",d:"a"},
   {id:"11-12",t:"Microsoft Graph API: enumeração sem as APIs tradicionais de AD, abuso de token",d:"a"},
  ]},
  {t:"Conceitos Cross-Cloud",items:[
   {id:"11-13",t:"Má configuração como vetor primário: diferente do on-premises, onde exploits dominam",d:"f"},
   {id:"11-14",t:"Exfiltração de dados em cloud: exfil de S3, compartilhamento de snapshot, via serviços gerenciados",d:"i"},
  ]}
]},
{n:13,title:"Segurança Mobile",extra:false,deps:[2,4,6],
 desc:"Superfície de ataque crescente. Android e iOS têm modelos de segurança completamente diferentes, exigindo abordagens distintas.",
 sections:[
  {t:"Android",items:[
   {id:"12-1",t:"Estrutura do APK: manifest, permissões, superfície de Activity/Service/BroadcastReceiver/ContentProvider",d:"i"},
   {id:"12-2",t:"Binder IPC: comunicação entre processos no Android — vetor de escalação de privilégios",d:"a"},
   {id:"12-3",t:"Engenharia reversa de APKs: jadx, apktool, Frida para hooking dinâmico",d:"i"},
   {id:"12-4",t:"Bypass de certificate pinning: hooks com Frida, patch do APK, apk-mitm",d:"i"},
   {id:"12-5",t:"Bypass de root detection: técnicas comuns de detecção e como evadir cada uma",d:"i"},
  ]},
  {t:"iOS",items:[
   {id:"12-6",t:"Entitlements e sandboxing: modelo de segurança, o que cada entitlement permite",d:"i"},
   {id:"12-7",t:"Jailbreak: o que explora, como modifica o sistema — além de só instalar",d:"a"},
   {id:"12-8",t:"Análise de IPA: extração, class-dump, análise do binário Mach-O",d:"i"},
   {id:"12-9",t:"Frida no iOS: hooking de métodos Objective-C e Swift em runtime",d:"i"},
  ]}
]},
{n:14,title:"OPSEC Operacional",extra:false,deps:[3,10],
 desc:"Não é uma camada final — é uma mentalidade que permeia cada ação. Em red team maduro, ficar indetectável é parte do objetivo.",
 sections:[
  {t:"Planejamento",items:[
   {id:"13-1",t:"Threat modeling do engagement: quem detecta, o que monitora, o custo em ruído de cada ação",d:"i"},
   {id:"13-2",t:"Categorização de impacto de OPSEC: o que fazer cedo, o que adiar, o que nunca fazer",d:"i"},
   {id:"13-3",t:"Assumir que o ambiente é monitorado: desenhar cada ação como se o SOC visse tudo",d:"i"},
  ]},
  {t:"Infraestrutura",items:[
   {id:"13-4",t:"Separação de infra por fase: infra de phishing separada do C2, C2 separado do exfil",d:"i"},
   {id:"13-5",t:"Redirectors: por que existem, configuração correta, quando reconstruir",d:"a"},
   {id:"13-6",t:"Tempo de vida da infra: quando queimar e reconstruir, nunca reutilizar entre operações",d:"i"},
   {id:"13-7",t:"Logging da operação: registrar o que foi feito, quando, de onde — auditar a própria trilha",d:"i"},
  ]},
  {t:"Durante a Operação",items:[
   {id:"13-8",t:"Living-off-the-land: priorizar LOLBins para minimizar a necessidade de dropar arquivos",d:"i"},
   {id:"13-9",t:"Timestomping e anti-forense básico",d:"i"},
   {id:"13-10",t:"Cleanup: o que remover, em que ordem, artefatos intencionais vs acidentais",d:"i"},
   {id:"13-11",t:"OPSEC pessoal: VMs descartáveis por tarefa, DNS separado, própria cadeia de proxy",d:"a"},
   {id:"13-12",t:"Fingerprinting de JA3/tooling: mudar o TLS fingerprint do C2 para evitar detecção por assinatura",d:"a"},
  ]}
]},
{n:15,title:"Engenharia Social & OSINT",extra:false,deps:[3],
 desc:"Muitas vezes o vetor de acesso inicial mais eficiente. Exige pesquisa profunda e construção de pretextos convincentes.",
 sections:[
  {t:"OSINT",items:[
   {id:"14-1",t:"Enumeração de superfície externa: ASN, faixas de IP, subdomínios, CT logs, tecnologias expostas",d:"i"},
   {id:"14-2",t:"OSINT de pessoas: LinkedIn, GitHub (secrets em commits), redes sociais, breach data",d:"i"},
   {id:"14-3",t:"Shodan/Censys/FOFA a fundo: queries avançadas, rastreio passivo de infraestrutura",d:"i"},
   {id:"14-4",t:"Google dorks avançados: arquivos expostos, interfaces admin, configs vazadas",d:"i"},
   {id:"14-5",t:"Maltego: relações entre entidades, construção de mapas do alvo",d:"i"},
   {id:"14-6",t:"Recon de infra de terceiros: provedores de e-mail, CDN, identificação de WAF",d:"i"},
  ]},
  {t:"Phishing Técnico & Engenharia Social",items:[
   {id:"14-7",t:"Evilginx/Modlishka: AiTM que captura sessões mesmo com MFA — como funciona",d:"a"},
   {id:"14-8",t:"SPF/DKIM/DMARC a fundo: como cada um é verificado, brechas exploráveis",d:"i"},
   {id:"14-9",t:"Domínios homoglyph, domínios lookalike, bypass de filtro de URL em clientes de e-mail",d:"i"},
   {id:"14-10",t:"Pretexting: construção da narrativa, pesquisa do alvo, rapport — não improviso",d:"i"},
   {id:"14-11",t:"Vishing: scripts, técnicas de pressão, impersonação de TI/suporte",d:"i"},
   {id:"14-12",t:"Princípios de Cialdini: reciprocidade, autoridade, urgência — base psicológica da SE",d:"f"},
  ]}
]},
{n:16,title:"Wireless & RF",extra:true,deps:[3],
 desc:"802.11, Bluetooth, NFC/RFID, wireless corporativo, SDR. Superfície física raramente coberta de forma adequada.",
 sections:[
  {t:"Wi-Fi em Profundidade",items:[
   {id:"15-1",t:"Tipos de frame 802.11: management (beacon, probe, auth, assoc), control, data — o que cada um revela",d:"i"},
   {id:"15-2",t:"WPA2: 4-way handshake em detalhe, por que o ataque de PMKID não precisa capturar o handshake completo",d:"i"},
   {id:"15-3",t:"WPA3: SAE (Simultaneous Authentication of Equals), vulnerabilidades Dragonblood",d:"a"},
   {id:"15-4",t:"Evil Twin / Rogue AP: setup, captive portals, downgrade de WPA3 para WPA2",d:"i"},
   {id:"15-5",t:"WPS: ataque Pixie Dust, brute force de PIN, ainda habilitado por padrão em muitos roteadores",d:"i"},
   {id:"15-6",t:"Ataque KARMA e variantes: responder a qualquer probe request com um AP falso",d:"a"},
   {id:"15-7",t:"Ataques de deauth: spoofing de management frame 802.11, captura forçada de handshake",d:"i"},
  ]},
  {t:"Wireless Corporativo (802.1X / RADIUS)",items:[
   {id:"15-8",t:"Visão geral de 802.1X/EAP: como a autenticação corporativa funciona (supplicant, authenticator, servidor RADIUS)",d:"i"},
   {id:"15-9",t:"Tipos de EAP: PEAP, EAP-TLS, EAP-TTLS, LEAP — forças e fraquezas de cada um",d:"i"},
   {id:"15-10",t:"Servidor RADIUS malicioso: atacar PEAP com servidor falso, captura do challenge MSCHAPv2",d:"a"},
   {id:"15-11",t:"hostapd-wpe: automatizar o ataque de rogue AP + RADIUS, workflow de captura de credenciais",d:"a"},
   {id:"15-12",t:"Ataques a EAP-TLS quando a validação de certificado é implementada incorretamente",d:"a"},
  ]},
  {t:"Bluetooth & NFC/RFID",items:[
   {id:"15-13",t:"BLE (Bluetooth Low Energy): protocolo GATT/ATT, enumeração de characteristics, sniffing com Ubertooth",d:"i"},
   {id:"15-14",t:"Ataque KNOB: downgrade da entropia da chave de sessão do Bluetooth",d:"a"},
   {id:"15-15",t:"NFC/RFID: frequências (LF 125kHz vs HF 13.56MHz), vulns do MIFARE Classic, clonagem de UID",d:"i"},
   {id:"15-16",t:"Proxmark3 a fundo: emulação, leitura/escrita de cartões de acesso, brute forcing de chaves",d:"i"},
  ]},
  {t:"SDR & Outros Protocolos RF",items:[
   {id:"15-17",t:"SDR (Software Defined Radio): básico de GNU Radio, captura e análise de sinal RF",d:"i"},
   {id:"15-18",t:"Replay attacks em sistemas sem criptografia (abridores de portão, alarmes, controles remotos)",d:"i"},
   {id:"15-19",t:"Zigbee e Z-Wave: protocolos de IoT, replay attacks, técnicas de extração de chave",d:"a"},
  ]}
]},
{n:17,title:"Hardware Hacking",extra:true,deps:[1],
 desc:"Acesso físico ao dispositivo. JTAG, UART, fault injection, side-channel físico. Território de pesquisa de firmware.",
 sections:[
  {t:"Interfaces de Debug",items:[
   {id:"16-1",t:"JTAG/SWD: protocolo de debug, boundary scan, JTAGulator para identificar pinos, OpenOCD",d:"i"},
   {id:"16-2",t:"UART: identificação de pinos (TX/RX/GND/VCC), comunicação serial, console de boot exposto",d:"i"},
   {id:"16-3",t:"SPI e I2C: protocolos de comunicação, leitura de chip flash (firmware dump), Bus Pirate",d:"i"},
   {id:"16-4",t:"flashrom: extração e regravação de firmware via clip e adaptadores",d:"i"},
  ]},
  {t:"Ataques Físicos Avançados",items:[
   {id:"16-5",t:"Voltage glitching: pulsar o VCC para pular instruções — burlar checagens de autenticação",d:"e"},
   {id:"16-6",t:"Clock glitching: manipular o clock para corromper a execução num momento preciso",d:"e"},
   {id:"16-7",t:"Simple Power Analysis (SPA) e Differential Power Analysis (DPA): extrair chaves de padrões de consumo",d:"e"},
   {id:"16-8",t:"Side-channel EM: capturar emissões eletromagnéticas perto do chip",d:"e"},
   {id:"16-9",t:"Implantes de hardware: interceptadores de teclado, sniffers inline — operação conceitual",d:"a"},
   {id:"16-10",t:"Decapsulamento de chip e análise de silício: técnica forense/ofensiva de nível extremo",d:"e"},
  ]}
]},
{n:18,title:"Containers & Kubernetes",extra:true,deps:[2,3,12],
 desc:"Container escape e ataques a K8s são cada vez mais comuns em ambientes corporativos modernos.",
 sections:[
  {t:"Docker em Profundidade",items:[
   {id:"17-1",t:"Internals do Docker: namespaces (PID/net/mnt/uts/ipc/user) e cgroups — como o isolamento é implementado",d:"i"},
   {id:"17-2",t:"Container escape via Docker socket: /var/run/docker.sock montado como volume",d:"i"},
   {id:"17-3",t:"Escape de container privileged: montar o filesystem do host, escrever no crontab do host",d:"i"},
   {id:"17-4",t:"Abuso de capabilities: CAP_SYS_ADMIN, CAP_NET_ADMIN como vetores de escape",d:"a"},
   {id:"17-5",t:"Escape via filesystem /proc: acessar o namespace do host via /proc/1/root",d:"a"},
  ]},
  {t:"Kubernetes",items:[
   {id:"17-6",t:"Arquitetura do K8s: API server, etcd, kubelet, controller manager, scheduler",d:"i"},
   {id:"17-7",t:"RBAC do K8s: roles vs clusterroles, abuso de token de service account, integração OIDC",d:"i"},
   {id:"17-8",t:"SSRF via API do kubelet (porta 10250): execução de comando em pods sem autenticação",d:"a"},
   {id:"17-9",t:"Dump do etcd: secrets e credenciais em texto plano no banco do cluster",d:"a"},
   {id:"17-10",t:"Comprometer um node para virar cluster-admin: via abuso de DaemonSet, hostPID, hostNetwork",d:"a"},
   {id:"17-11",t:"Supply chain de imagem de container: layers maliciosas, técnicas de bypass de image scanner",d:"a"},
  ]}
]},
{n:19,title:"Fuzzing & Descoberta de Vulns",extra:true,deps:[4,7,8],
 desc:"Como vulnerabilidades são encontradas antes de virarem CVEs. Base para pesquisa original.",
 sections:[
  {t:"Fuzzing",items:[
   {id:"18-1",t:"Coverage-guided fuzzing: AFL++ e libFuzzer — instrumentação e loop de feedback por cobertura",d:"a"},
   {id:"18-2",t:"Grammar-based fuzzing: fuzzing de protocolo e parser com gramáticas, Boofuzz para rede",d:"a"},
   {id:"18-3",t:"Structure-aware fuzzing: mutators customizados, construção e minimização de corpus",d:"a"},
   {id:"18-4",t:"Dumb vs smart fuzzing: quando cada abordagem tem maior ROI",d:"i"},
  ]},
  {t:"Análise & Descoberta",items:[
   {id:"18-5",t:"Binary diffing: BinDiff para comparação de versões pós-patch — workflow de variant analysis",d:"a"},
   {id:"18-6",t:"Workflow de patch diffing: da notificação de CVE ao PoC funcional via análise de diff",d:"a"},
   {id:"18-7",t:"Execução simbólica: angr conceitual, limitações de path explosion, casos de uso práticos",d:"e"},
   {id:"18-8",t:"Taint analysis: Joern, CodeQL para rastrear caminhos de dados não sanitizados no código-fonte",d:"a"},
   {id:"18-9",t:"Metodologia de auditoria de código: padrões inseguros em C/C++, onde focar a revisão",d:"a"},
  ]}
]},
{n:20,title:"Browser Exploitation",extra:true,deps:[4,7,8,11],
 desc:"V8, SpiderMonkey, sandbox escape. Um dos campos de exploit dev mais exigentes tecnicamente.",
 sections:[
  {t:"Internals de Engine",items:[
   {id:"19-1",t:"Internals do V8: compilação JIT, hidden classes (shapes), inline caches — base do type confusion",d:"e"},
   {id:"19-2",t:"Exploração do V8: OOB read/write via manipulação de array, JIT spraying para injeção de código",d:"e"},
   {id:"19-3",t:"SpiderMonkey e JavaScriptCore: diferenças arquiteturais relevantes para exploit dev",d:"e"},
  ]},
  {t:"Sandbox & Navegador",items:[
   {id:"19-4",t:"Arquitetura do sandbox do Chromium: processos broker/target, como os escapes acontecem",d:"e"},
   {id:"19-5",t:"Site isolation: modelo de processo por site, implicações de Spectre, bypasses documentados",d:"e"},
   {id:"19-6",t:"Ataques de extensão: extensões maliciosas, escalação de privilégio via APIs de extensão do navegador",d:"a"},
   {id:"19-7",t:"WebAssembly como contêiner de shellcode: evasão de detecção no contexto JavaScript",d:"a"},
  ]}
]},
{n:21,title:"OT / ICS / SCADA",extra:true,deps:[3],
 desc:"Sistemas industriais. O objetivo do ataque não é dado — é o processo físico. Exige uma mentalidade completamente diferente.",
 sections:[
  {t:"Arquitetura & Protocolos",items:[
   {id:"20-1",t:"Modelo Purdue: níveis (field, control, supervisory, corporate) e zonas de segurança",d:"i"},
   {id:"20-2",t:"Modbus: porta 502, sem autenticação por padrão — leitura/escrita arbitrária de registradores",d:"i"},
   {id:"20-3",t:"DNP3: protocolo de telemetria elétrica, spoofing de dados de sensor",d:"i"},
   {id:"20-4",t:"IEC 61850, PROFINET, OPC-UA: protocolos modernos de automação industrial",d:"a"},
   {id:"20-5",t:"PLCs: programação e consulta, linguagens IEC 61131-3 — Stuxnet como estudo de caso definitivo",d:"a"},
  ]},
  {t:"Vetores de Ataque",items:[
   {id:"20-6",t:"Convergência IT/OT: como redes corporativas viram vetores para o ambiente de controle",d:"i"},
   {id:"20-7",t:"VPNs de manutenção remota: credenciais de fornecedor como ponto de entrada clássico",d:"i"},
   {id:"20-8",t:"Servidores Historian: ponte IT/OT, frequentemente mal protegidos",d:"i"},
   {id:"20-9",t:"Ferramentas: PLCScan, GRASSMARLIN, Shodan com filtros ICS (port:102 Siemens S7)",d:"i"},
   {id:"20-10",t:"Impacto físico: a diferença fundamental — o objetivo é um processo físico real, não dado",d:"f"},
  ]}
]},
{n:22,title:"Forense Digital (Visão Ofensiva)",extra:true,deps:[2,10,14],
 desc:"Entender o que o defensor vê é essencial para saber o que não deixar para trás.",
 sections:[
  {t:"Artefatos do Windows",items:[
   {id:"21-1",t:"Prefetch, shimcache, amcache: o que cada um registra, por que importam para atribuição",d:"i"},
   {id:"21-2",t:"Jump lists, arquivos LNK, chaves MRU do registro: o que revelam sobre a atividade do usuário",d:"i"},
   {id:"21-3",t:"MFT do NTFS: como timestamps são gerados, o que o timestomping realmente altera (e o que não)",d:"a"},
   {id:"21-4",t:"Event IDs críticos: 4624, 4625, 4688, 4698, 7045 — o que cada um registra e como evitar",d:"i"},
   {id:"21-5",t:"Forense de registro: quais chaves revelam execução passada, como limpar rastros específicos",d:"a"},
  ]},
  {t:"Memória & Anti-Forense",items:[
   {id:"21-6",t:"Forense de memória: o que Volatility/Rekall encontram — processos, conexões, strings na memória",d:"i"},
   {id:"21-7",t:"Anti-forense avançado: secure delete de logs (wevtutil), remoção de entradas específicas da MFT",d:"a"},
   {id:"21-8",t:"Forense de rede: o que persiste em logs de firewall/proxy/IDS — minimizar exposição",d:"i"},
   {id:"21-9",t:"Volume Shadow Copies: como são criadas, que evidências contêm, como remover",d:"i"},
  ]}
]},
{n:23,title:"Ataques de Supply Chain",extra:true,deps:[3,10,11],
 desc:"SolarWinds, 3CX, XZ Utils. O vetor mais difícil de detectar e defender.",
 sections:[
  {t:"Tipos & Técnicas",items:[
   {id:"22-1",t:"Dependency confusion: como o ataque divulgado por Alex Birsan em 2021 funcionou, identificar alvos em npm/pip/gem",d:"a"},
   {id:"22-2",t:"Typosquatting de pacotes: automação, casos reais (event-stream, colors.js)",d:"i"},
   {id:"22-3",t:"Comprometer a build pipeline: envenenamento de CI/CD — SolarWinds como estudo de caso de impacto máximo",d:"a"},
   {id:"22-4",t:"Abuso de code signing: roubo de certificado, assinar malware com cert legítimo",d:"e"},
   {id:"22-5",t:"Sequestro de mecanismo de update: mecanismos sem verificação de integridade como vetores",d:"a"},
   {id:"22-6",t:"XZ Utils (CVE-2024-3094): inserção de backdoor em projeto open-source via contribuidor comprometido",d:"e"},
   {id:"22-7",t:"Supply chain de hardware: interdição de dispositivo em trânsito (técnica documentada no catálogo NSA ANT)",d:"e"},
  ]}
]},
{n:24,title:"DevSecOps & Pipeline CI/CD",extra:true,deps:[4,12,23],
 desc:"Pipelines de desenvolvimento como superfície de ataque. Secrets, actions maliciosas, envenenamento de artefato.",
 sections:[
  {t:"GitHub & CI/CD",items:[
   {id:"23-1",t:"GitHub Actions: secrets expostos em logs, roubo de token OIDC, workflow injection via PR malicioso",d:"i"},
   {id:"23-2",t:"Jenkins: console de script Groovy como RCE direto, pipeline poisoning via Jenkinsfile",d:"i"},
   {id:"23-3",t:"GitLab CI: variáveis de ambiente como secrets, comprometimento de runner",d:"i"},
   {id:"23-4",t:"Ataques a artifact registry: push de artefatos maliciosos, extração de credenciais de registries",d:"a"},
  ]},
  {t:"Secrets & IaC",items:[
   {id:"23-5",t:"Secrets no código: histórico do git, arquivos .env, credenciais hardcoded — trufflehog, gitleaks",d:"i"},
   {id:"23-6",t:"Arquivos de state do Terraform: credenciais e outputs sensíveis em texto plano",d:"i"},
   {id:"23-7",t:"Fraquezas do Ansible vault: gestão de chave, texto plano em logs de execução",d:"i"},
   {id:"23-8",t:"SBOM (Software Bill of Materials): uso ofensivo para identificar dependências vulneráveis",d:"i"},
  ]}
]},
{n:25,title:"Red Team Físico",extra:true,deps:[14,15],
 desc:"Entrada física em instalações. Lock picking, bypass de acesso eletrônico, clonagem de crachá, implantes. Disciplina própria.",
 sections:[
  {t:"Lock Picking & Acesso Físico",items:[
   {id:"25-1",t:"Lock picking: pin tumbler, wafer, disc detainer, bump keys — cada tipo e as ferramentas necessárias",d:"i"},
   {id:"25-2",t:"Técnicas de bypass: shimming, loiding (cartão de crédito), under-door tool para maçanetas de alavanca",d:"i"},
   {id:"25-3",t:"Tailgating e piggybacking: técnicas de entrada social sem derrotar a fechadura",d:"f"},
   {id:"25-4",t:"Impressioning: criar uma chave funcional marcando um blank contra a fechadura",d:"a"},
   {id:"25-5",t:"Bypass de fechadura eletrônica: relay attacks em RFID, sensores de maçaneta, bypass de mag-lock",d:"a"},
  ]},
  {t:"Clonagem de Crachá & Controle de Acesso",items:[
   {id:"25-6",t:"Clonagem de cartão de acesso RFID: workflow do Proxmark3, identificar frequência e protocolo antes de clonar",d:"i"},
   {id:"25-7",t:"HID Proxcard, EM4100, MIFARE DESFire — espectro de dificuldade para clonar cada um",d:"i"},
   {id:"25-8",t:"Bypass de leitor com shim ou replay de sinal na porta",d:"a"},
  ]},
  {t:"Recon Físico & Infraestrutura",items:[
   {id:"25-9",t:"Recon de prédio: identificar entradas, câmeras, padrões de movimento, escalas de vigilância",d:"i"},
   {id:"25-10",t:"Dumpster diving: recuperação de informação do lixo corporativo",d:"f"},
   {id:"25-11",t:"Shoulder surfing e outros vetores de observação",d:"f"},
   {id:"25-12",t:"Implantes de rede: LAN Turtle, Shark Jack — drop device para acesso remoto persistente",d:"a"},
   {id:"25-13",t:"Keystroke loggers físicos: tipos, colocação, recuperação",d:"a"},
   {id:"25-14",t:"Acesso à sala de servidores: o que fazer com acesso físico ao hardware corporativo",d:"i"},
  ]}
]},
{n:26,title:"Escalação de Privilégios (Taxonomia Completa)",extra:true,deps:[2,4,9],
 desc:"Vai muito além do GTFOBins. Taxonomia completa de privesc em Windows e Linux com profundidade real.",
 sections:[
  {t:"Escalação de Privilégios no Windows",items:[
   {id:"26-1",t:"AlwaysInstallElevated: identificar via registro, explorar via MSI malicioso",d:"i"},
   {id:"26-2",t:"Unquoted service paths: como funciona, identificar e explorar serviços vulneráveis",d:"i"},
   {id:"26-3",t:"DLL hijacking em serviços: DLL search order, serviços carregando DLLs sem caminho absoluto",d:"i"},
   {id:"26-4",t:"Token impersonation: SeImpersonatePrivilege — família Potato (Hot, Sweet, Rotten, Juicy, PrintSpoofer)",d:"i"},
   {id:"26-5",t:"Named pipe impersonation: criar um pipe que faz um serviço privilegiado conectar",d:"a"},
   {id:"26-6",t:"Permissões fracas de serviço: enumeração de permissão com sc.exe, substituição do binary path",d:"i"},
   {id:"26-7",t:"Scheduled tasks mal configuradas: permissões fracas no binário ou diretório",d:"i"},
   {id:"26-8",t:"Autoruns de registro com permissões fracas: implicações de HKCU vs HKLM",d:"i"},
   {id:"26-9",t:"UAC bypass: técnicas atuais e históricas, implicações de integrity level",d:"i"},
   {id:"26-10",t:"PrintNightmare e variantes do spooler: escalação local via print spooler",d:"a"},
  ]},
  {t:"Escalação de Privilégios no Linux",items:[
   {id:"26-11",t:"Binários SUID/SGID: identificação e exploração via GTFOBins",d:"i"},
   {id:"26-12",t:"Más configurações de sudo: NOPASSWD, sudo -l, bypass de LD_PRELOAD via sudo",d:"i"},
   {id:"26-13",t:"Cron jobs: scripts ou diretórios graváveis em jobs de propriedade do root",d:"i"},
   {id:"26-14",t:"NFS no_root_squash: montar o NFS e plantar um binário SUID",d:"i"},
   {id:"26-15",t:"Membro do grupo docker: equivalente a root — escape para o host via docker run",d:"i"},
   {id:"26-16",t:"Abuso de capabilities: cap_setuid, cap_net_raw e outras via getcap",d:"i"},
   {id:"26-17",t:"PATH hijacking: manipular o PATH em scripts que rodam como root",d:"i"},
   {id:"26-18",t:"Kernel exploits locais: DirtyPipe, DirtyCow — identificar quando aplicar privesc de kernel",d:"a"},
   {id:"26-19",t:"/etc/passwd ou shadow gravável: workflow de exploração",d:"i"},
  ]},
  {t:"Cross-Platform",items:[
   {id:"26-20",t:"Abuso de privilégio de service account: contas com permissões excessivas no ambiente",d:"i"},
   {id:"26-21",t:"Reuso de credencial: senhas locais repetidas, senha de admin compartilhada pela rede",d:"f"},
  ]}
]},
{n:27,title:"Pós-Exploração & Pivoting",extra:true,deps:[2,3,9,10],
 desc:"A diferença entre 'consegui acesso' e 'movimento real dentro do ambiente'.",
 sections:[
  {t:"Pivoting & Tunneling",items:[
   {id:"27-1",t:"SSH tunneling: local/remote/dynamic forwarding, ProxyJump, proxychains sobre SSH",d:"i"},
   {id:"27-2",t:"Chisel: reverse SOCKS proxy sobre HTTP, contornando restrições de egress firewall",d:"i"},
   {id:"27-3",t:"ligolo-ng: tunneling L3 com interface TUN, transparente para todas as ferramentas",d:"i"},
   {id:"27-4",t:"Double pivot: alcançar um terceiro segmento de rede via dois pivots encadeados",d:"a"},
   {id:"27-5",t:"C2 por DNS tunneling: iodine, dnscat2 para ambientes com egress só via DNS",d:"a"},
   {id:"27-6",t:"ICMP tunneling: ptunnel para ambientes com egress só via ICMP",d:"a"},
  ]},
  {t:"Situational Awareness",items:[
   {id:"27-7",t:"Enumeração pós-comprometimento: usuários, grupos, serviços, conexões de rede",d:"i"},
   {id:"27-8",t:"Identificar segmentos de rede alcançáveis, roteamento, resolvers DNS internos",d:"i"},
   {id:"27-9",t:"Host discovery sem Nmap: built-ins (ping sweep via batch, one-liners de PowerShell)",d:"i"},
   {id:"27-10",t:"Identificar defesas ativas: EDR, AV, monitoramento de rede a partir de dentro do host",d:"i"},
  ]},
  {t:"Frameworks C2 (Uso Operacional)",items:[
   {id:"27-11",t:"Cobalt Strike: Beacon, sleep, perfis C2, BOFs, comandos de lateral movement",d:"a"},
   {id:"27-12",t:"Sliver: alternativa open-source, tipos de implant, C2 mTLS/WireGuard",d:"i"},
   {id:"27-13",t:"Havoc, Brute Ratel C4, Mythic: diferenças de arquitetura, perfil de detecção",d:"a"},
   {id:"27-14",t:"BOFs (Beacon Object Files): execução in-process, por que evadem melhor que fork-and-run",d:"a"},
  ]}
]},
{n:28,title:"Bancos de Dados como Lateral Movement",extra:true,deps:[9,11],
 desc:"MSSQL, Oracle, PostgreSQL como pontos de pivot. Frequentemente ignorados e altamente privilegiados.",
 sections:[
  {t:"MSSQL",items:[
   {id:"28-1",t:"xp_cmdshell: habilitar, executar comandos de SO como a service account",d:"i"},
   {id:"28-2",t:"Linked Servers: executar queries em servidores linkados, escalação de privilégio cross-server",d:"a"},
   {id:"28-3",t:"UNC path injection: EXEC xp_dirtree para capturar o hash NetNTLM para relay",d:"i"},
   {id:"28-4",t:"EXECUTE AS: impersonation para trocar o contexto de usuário dentro do banco",d:"i"},
   {id:"28-5",t:"CLR assemblies: carregar assembly .NET para execução de código arbitrário",d:"a"},
   {id:"28-6",t:"Extração de credenciais: connection strings em arquivos de config, jobs do SQL Server Agent",d:"i"},
  ]},
  {t:"Oracle & PostgreSQL",items:[
   {id:"28-7",t:"Oracle UTL_HTTP: requisições outbound de dentro do banco (vetor de SSRF)",d:"i"},
   {id:"28-8",t:"Oracle Java stored procedures: execução de código via Java habilitado no Oracle",d:"a"},
   {id:"28-9",t:"PostgreSQL COPY TO/FROM: ler/escrever arquivos de SO como o usuário postgres",d:"i"},
   {id:"28-10",t:"Extensões do PostgreSQL: dblink, postgres_fdw para pivot para outros bancos",d:"a"},
  ]},
  {t:"NoSQL & Caches",items:[
   {id:"28-11",t:"Redis sem autenticação: SLAVEOF e CONFIG SET para RCE",d:"i"},
   {id:"28-12",t:"MongoDB sem autenticação: dump completo de dados, execução de comando",d:"i"},
   {id:"28-13",t:"Memcached: injeção de dados, session hijacking via manipulação de cache",d:"i"},
  ]}
]},
{n:29,title:"Ataques a Senhas",extra:true,deps:[6,9],
 desc:"Hashcat em profundidade real, spraying com evasão de lockout, descoberta de credenciais em memória e arquivos.",
 sections:[
  {t:"Cracking de Hash",items:[
   {id:"29-1",t:"Hashcat: attack modes (0,1,3,6,7), rules (OneRuleToRuleThemAll), masks, prince attack, hybrid",d:"i"},
   {id:"29-2",t:"John the Ripper: diferenças, casos em que supera o Hashcat",d:"i"},
   {id:"29-3",t:"Wordlists: rockyou, weakpass, hashesorg — construir wordlists específicas do domínio",d:"i"},
   {id:"29-4",t:"Mangling rules: como empresas modificam senhas (Company2024!, company@123) — criação de rules",d:"i"},
   {id:"29-5",t:"Rainbow tables: quando ainda fazem sentido, trade-off com cracking em GPU",d:"i"},
  ]},
  {t:"Ataques Online",items:[
   {id:"29-6",t:"Password spraying: timing, enumeração de usuário, evasão de lockout (threshold, delay, horário)",d:"i"},
   {id:"29-7",t:"Credential stuffing: uso de breach data, workflow do OpenBullet",d:"i"},
   {id:"29-8",t:"Kerberos pre-auth spray (AS-REQ): spray sem lockout via peculiaridade do protocolo Kerberos",d:"i"},
   {id:"29-9",t:"Credenciais default: catálogo por fabricante/produto, padrões comuns",d:"f"},
  ]},
  {t:"Descoberta de Credenciais",items:[
   {id:"29-10",t:"Mimikatz a fundo: módulos logonpasswords, sekurlsa, lsadump, dpapi",d:"i"},
   {id:"29-11",t:"DPAPI: o que protege, extração com credenciais de domínio",d:"a"},
   {id:"29-12",t:"Extração de credenciais de navegador: Chrome, Firefox — localização do vault e decriptação",d:"i"},
   {id:"29-13",t:"Arquivos de credencial: .rdp, .vnc, sessões salvas do WinSCP, PuTTY",d:"i"},
   {id:"29-14",t:"Arquivos de config: web.config, appsettings.json, arquivos .env com credenciais hardcoded",d:"f"},
  ]}
]},
{n:30,title:"ADFS / SAML / SSO",extra:true,deps:[9,12],
 desc:"Golden SAML, ataques a ADFS, abuso de federação. Cada vez mais relevante em ambientes híbridos.",
 sections:[
  {t:"ADFS",items:[
   {id:"30-1",t:"Arquitetura do ADFS: Relying Party Trusts, Claims Providers, Attribute Store",d:"i"},
   {id:"30-2",t:"Golden SAML: assinar tokens SAML arbitrários com a token-signing key roubada",d:"a"},
   {id:"30-3",t:"ADFSDump: extrair a configuração do ADFS e as signing keys",d:"a"},
   {id:"30-4",t:"Password spray no ADFS via endpoint Autodiscover (contorna o lockout padrão do AD)",d:"i"},
   {id:"30-5",t:"WS-Fed vs SAML 2.0: diferenças relevantes para ataque",d:"i"},
  ]},
  {t:"SAML em Profundidade",items:[
   {id:"30-6",t:"XML signature wrapping: manipular assertions mantendo a assinatura válida",d:"a"},
   {id:"30-7",t:"Replay de SAML response: reutilizar assertions sem verificação de NotOnOrAfter",d:"a"},
   {id:"30-8",t:"Bypass de recipient e audience: assertions aceitas por service providers errados",d:"a"},
  ]},
  {t:"SSO & OAuth",items:[
   {id:"30-9",t:"Más configurações de OAuth: implicit flow, PKCE ausente, token leakage via Referer",d:"i"},
   {id:"30-10",t:"OpenID Connect: manipulação de id_token, claim injection",d:"a"},
   {id:"30-11",t:"SAML vs OAuth vs OIDC: diferenças de superfície de ataque entre os três protocolos",d:"i"},
  ]}
]},
{n:31,title:"Thick Client / Fat Client",extra:true,deps:[4,7,11],
 desc:"Aplicações desktop com protocolos customizados e credenciais hardcoded. Superfície pouco explorada.",
 sections:[
  {t:"Análise",items:[
   {id:"31-1",t:"Identificar a tech stack: .NET, Java, Electron, C++ — abordagem diferente para cada",d:"i"},
   {id:"31-2",t:"Proxying de tráfego: Burp com interceptação HTTPS para apps que ignoram o proxy do sistema",d:"i"},
   {id:"31-3",t:"Bypass de SSL pinning no desktop: .NET (validator custom), Java (cacerts), apps Electron",d:"a"},
   {id:"31-4",t:"Decompilação de .NET: dnSpy/ILSpy para analisar a lógica de autenticação no cliente",d:"i"},
  ]},
  {t:"Vetores de Ataque",items:[
   {id:"31-5",t:"DLL hijacking: apps instalados carregando DLLs de locais graváveis",d:"i"},
   {id:"31-6",t:"Arquivos de config com credenciais hardcoded: web.config, app.config, configuração XML",d:"i"},
   {id:"31-7",t:"Memory scraping em runtime: extrair credenciais ou tokens da memória do processo",d:"a"},
   {id:"31-8",t:"SQL injection em queries locais: apps construindo queries com input local do usuário",d:"i"},
   {id:"31-9",t:"Protocolo binário customizado: apps usando protocolo binário proprietário — análise e manipulação",d:"a"},
  ]}
]},
{n:32,title:"Segurança de APIs",extra:true,deps:[11,12],
 desc:"REST, gRPC, GraphQL, WebSockets. Superfície de ataque distinta, além das vulns web genéricas.",
 sections:[
  {t:"APIs REST",items:[
   {id:"32-1",t:"OWASP API Top 10: BOLA (IDOR), Broken Auth, Excessive Data Exposure, BFLA",d:"i"},
   {id:"32-2",t:"BOLA (Broken Object Level Authorization): manipulação de ID nos endpoints",d:"i"},
   {id:"32-3",t:"BFLA (Broken Function Level Authorization): acessar ações de admin sem privilégio",d:"i"},
   {id:"32-4",t:"Mass assignment: APIs aceitando campos extras e atribuindo-os a objetos sem filtro",d:"i"},
   {id:"32-5",t:"Improper asset management: versões antigas de API sem autenticação ainda acessíveis",d:"i"},
  ]},
  {t:"gRPC & GraphQL",items:[
   {id:"32-6",t:"gRPC: protobuf como protocolo binário, interceptação e manipulação com grpcurl/Burp",d:"i"},
   {id:"32-7",t:"Endpoint de reflection do gRPC: service discovery expondo o schema completo",d:"i"},
   {id:"32-8",t:"GraphQL: introspection, batching para bypass de rate-limit, nested queries para DoS",d:"i"},
  ]},
  {t:"WebSockets & Real-Time",items:[
   {id:"32-9",t:"WebSocket hijacking: CSWSH (Cross-Site WebSocket Hijacking)",d:"i"},
   {id:"32-10",t:"Autenticação por mensagem ausente: autenticação só no handshake, não em cada mensagem",d:"i"},
   {id:"32-11",t:"Server-Sent Events: vazamento de informação via streams SSE",d:"i"},
  ]}
]},
{n:33,title:"Evasão Avançada de Controles",extra:true,deps:[10,12,14],
 desc:"DLP, CASB, PAM, NDR/NTA. Ambientes maduros têm isto — cada um tem técnicas de bypass específicas.",
 sections:[
  {t:"DLP (Data Loss Prevention)",items:[
   {id:"33-1",t:"Como DLPs inspecionam: conteúdo, contexto, destino — mecanismos de data fingerprinting",d:"i"},
   {id:"33-2",t:"Evasão de content inspection: encoding, criptografia, esteganografia",d:"a"},
   {id:"33-3",t:"Canais de exfil que DLPs não pegam: DNS, ICMP, protocolo custom sobre portas permitidas",d:"a"},
   {id:"33-4",t:"DLP endpoint-based vs network-based: coberturas diferentes e pontos cegos diferentes",d:"i"},
  ]},
  {t:"CASB & PAM",items:[
   {id:"33-5",t:"CASB inline vs modo API: diferenças de cobertura e pontos cegos de cada deployment",d:"i"},
   {id:"33-6",t:"Evasão de CASB inline: domínios não categorizados, split tunneling, apps que contornam o proxy",d:"a"},
   {id:"33-7",t:"Shadow IT: usar serviços de cloud não sancionados que o CASB não monitora",d:"i"},
   {id:"33-8",t:"CyberArk, BeyondTrust, Delinea: como PAMs funcionam, modelo de acesso JIT",d:"i"},
   {id:"33-9",t:"Ataques a PAM: injeção de credencial via PSM, exploração de gaps no session recording",d:"a"},
  ]},
  {t:"NDR / NTA (Network Detection & Response)",items:[
   {id:"33-10",t:"Darktrace, ExtraHop, Vectra: como identificam comportamento anômalo",d:"i"},
   {id:"33-11",t:"Evasão low and slow: imitar padrões de tráfego humano, reduzir a densidade de IOC",d:"a"},
   {id:"33-12",t:"Beacon timing para parecer tráfego humano: intervalos variáveis, ciente do horário comercial",d:"a"},
  ]}
]},
{n:34,title:"Persistência (Taxonomia Completa)",extra:true,deps:[2,4,10],
 desc:"Taxonomia completa de persistência em Windows e Linux — muito além de scheduled tasks e run keys do registro.",
 sections:[
  {t:"Persistência User-Mode no Windows",items:[
   {id:"34-1",t:"Run keys do registro: HKCU vs HKLM — diferenças de privilégio e detecção",d:"f"},
   {id:"34-2",t:"Startup folder: localização, como funciona, HKCU vs common startup",d:"f"},
   {id:"34-3",t:"Scheduled tasks: criação, evasão de detecção (XML, método via COM object)",d:"i"},
   {id:"34-4",t:"WMI subscriptions: EventFilter + EventConsumer + FilterToConsumerBinding",d:"i"},
   {id:"34-5",t:"COM hijacking: HKCU\\Software\\Classes sobrepõe o HKLM para o usuário atual",d:"a"},
   {id:"34-6",t:"AppInit DLLs: carregadas em todo processo que usa user32.dll",d:"a"},
   {id:"34-7",t:"IFEO (Image File Execution Options): chave Debugger como backdoor de processo",d:"a"},
  ]},
  {t:"Persistência Profunda no Windows",items:[
   {id:"34-8",t:"BootExecute: processo executando antes de o Windows carregar por completo",d:"a"},
   {id:"34-9",t:"LSA security packages: DLL carregada pelo LSASS na inicialização",d:"a"},
   {id:"34-10",t:"Netsh helper DLLs: DLL registrada no netsh que carrega em qualquer chamada do netsh",d:"a"},
   {id:"34-11",t:"Print monitor DLLs: carregadas pelo serviço de print spooler",d:"a"},
   {id:"34-12",t:"Backdoor de accessibility features: substituição de sethc.exe, utilman.exe (técnica clássica)",d:"i"},
  ]},
  {t:"Persistência no Linux",items:[
   {id:"34-13",t:"Cron jobs: /etc/cron.*, crontab de usuário — detecção e evasão",d:"f"},
   {id:"34-14",t:"Serviços e timers do systemd: criar serviço persistente com unit file customizado",d:"i"},
   {id:"34-15",t:"~/.bashrc, ~/.profile, ~/.bash_profile: persistência em nível de usuário",d:"f"},
   {id:"34-16",t:"/etc/ld.so.preload: equivalente global do LD_PRELOAD para todos os processos",d:"a"},
   {id:"34-17",t:"SSH authorized_keys: chave pública para acesso sem senha",d:"f"},
   {id:"34-18",t:"Módulos PAM: módulo malicioso que captura credenciais no login",d:"a"},
  ]}
]},
{n:35,title:"Purple Team & Detection Engineering",extra:true,deps:[2,10,14],
 desc:"Entender o que o blue team vê. Projetar ataques que evadem detecção exige conhecer o detector.",
 sections:[
  {t:"Regras de Detecção",items:[
   {id:"35-1",t:"Sigma rules: formato, escrever regras, converter para SIEM (Splunk, Elastic, Sentinel)",d:"i"},
   {id:"35-2",t:"YARA rules: sintaxe, escrever detecção de malware por string ou padrão de byte",d:"i"},
   {id:"35-3",t:"Event IDs críticos do Windows: entendimento profundo do que cada um revela sobre a atividade de ataque",d:"i"},
   {id:"35-4",t:"Sysmon: configuração, eventos críticos (1,3,7,8,10,11,12,13), quais regras filtrar",d:"i"},
  ]},
  {t:"SIEM & Análise de Log",items:[
   {id:"35-5",t:"Splunk: SPL (Search Processing Language), correlation searches, dashboards",d:"i"},
   {id:"35-6",t:"Elastic/ECS: KQL, field mapping, ingestion pipeline",d:"i"},
   {id:"35-7",t:"Microsoft Sentinel: KQL avançado, workbooks, hunting queries",d:"i"},
   {id:"35-8",t:"Fontes de log: quais logs habilitar, onde ficam, o que cada um cobre",d:"i"},
  ]},
  {t:"Operações de Purple Team",items:[
   {id:"35-9",t:"Atomic Red Team: rodar testes atômicos mapeados ao ATT&CK, validar cobertura de detecção",d:"i"},
   {id:"35-10",t:"Caldera: automação de adversary emulation, agents, abilities, operations",d:"i"},
   {id:"35-11",t:"Exercício de purple team: planejamento, execução, análise de gap de detecção, remediação",d:"i"},
   {id:"35-12",t:"Feedback loop: como o output do red team melhora a detecção do blue team ao longo do tempo",d:"i"},
  ]}
]},
{n:36,title:"Defesa Ativa & Honeypots",extra:true,deps:[9,14,15],
 desc:"Disparar um honeypot durante a operação expõe toda a campanha. Aprenda a reconhecer armadilhas.",
 sections:[
  {t:"Identificar Armadilhas",items:[
   {id:"36-1",t:"Canary tokens: tipos (URL, documento Word, DNS), como detectar antes de disparar",d:"i"},
   {id:"36-2",t:"Honeyaccounts de AD: identificar contas-armadilha (nunca usadas, SPNs artificiais, flags de UAC estranhas)",d:"a"},
   {id:"36-3",t:"Honeyfiles e honeydirectories: detectar antes de abrir ou acessar",d:"i"},
   {id:"36-4",t:"Honeypots de rede: identificar hosts que não deveriam existir mas estão acessíveis",d:"i"},
   {id:"36-5",t:"Detecção de port scan: como a maioria das redes detecta scans e como evitar disparar",d:"i"},
  ]},
  {t:"Deception Technology",items:[
   {id:"36-6",t:"Como empresas implantam deception: Attivo, Illusive Networks, Thinkst Canary",d:"i"},
   {id:"36-7",t:"Padrões comuns de armadilha no Active Directory: honeyaccounts, fake admin shares, SPN enganoso",d:"a"},
   {id:"36-8",t:"Técnicas para mapear honeypots antes de interagir: indicadores comportamentais de deception",d:"a"},
  ]}
]},
{n:37,title:"Threat Emulation",extra:true,deps:[5,14,15],
 desc:"Construir uma operação baseada em um threat actor real. Red teaming guiado por intelligence no seu nível mais avançado.",
 sections:[
  {t:"Metodologia",items:[
   {id:"37-1",t:"Red teaming guiado por intelligence: construir a operação baseada em um adversário real",d:"i"},
   {id:"37-2",t:"Seleção do threat actor: qual grupo de fato ameaça o setor e a tecnologia do cliente",d:"i"},
   {id:"37-3",t:"Mapeamento de TTP: mapear as TTPs conhecidas do grupo ao ambiente específico do cliente",d:"i"},
   {id:"37-4",t:"Adaptação: o que o grupo faz que não dá para replicar, e o que substitui",d:"a"},
  ]},
  {t:"Execução & Reporte",items:[
   {id:"37-5",t:"Fidelidade vs praticidade: quando simplificar uma TTP sem perder o valor do teste",d:"i"},
   {id:"37-6",t:"Documentação de desvios: registrar onde a emulação divergiu do actor real",d:"i"},
   {id:"37-7",t:"Relatório orientado ao adversário: não só 'encontramos X', mas 'o threat actor Y poderia fazer Z'",d:"i"},
  ]},
  {t:"Ferramentas & Referências",items:[
   {id:"37-8",t:"MITRE ATT&CK Evaluations: como são estruturadas, o que ensinam sobre detecção",d:"i"},
   {id:"37-9",t:"Breach & Attack Simulation (BAS): Cymulate, SafeBreach — complemento ou substituto?",d:"i"},
   {id:"37-10",t:"Planos de adversary emulation do MITRE: planos públicos para APT29, FIN6, Carbanak",d:"i"},
  ]}
]},
{n:38,title:"Nichos Avançados",extra:true,deps:[2,3],
 desc:"Mainframes e SS7/telecom. Conhecimento extremamente raro — bancos, governos, atores de nível estatal.",
 sections:[
  {t:"Mainframes (IBM z/OS)",items:[
   {id:"38-1",t:"Arquitetura do z/OS: JES, RACF, VSAM — completamente diferente de sistemas Unix/Windows",d:"e"},
   {id:"38-2",t:"TN3270: protocolo de terminal de mainframe, análise de tráfego",d:"e"},
   {id:"38-3",t:"RACF: controle de acesso do mainframe, enumeração e escalação de privilégios",d:"e"},
   {id:"38-4",t:"Por que importa: bancos e instituições financeiras frequentemente ainda têm cores em mainframe",d:"f"},
   {id:"38-5",t:"Tooling: scripts Nmap para z/OS, ferramentas de pentest específicas de mainframe",d:"e"},
  ]},
  {t:"SS7 & Telecom",items:[
   {id:"38-6",t:"SS7 (Signaling System 7): protocolo de sinalização de telecom, interceptação de SMS/chamada",d:"e"},
   {id:"38-7",t:"SIM swapping: engenharia social via operadora, impacto no bypass de MFA por SMS",d:"i"},
   {id:"38-8",t:"Diameter: sucessor do SS7 em redes 4G/LTE, classes de vulnerabilidade similares",d:"e"},
   {id:"38-9",t:"Por que importa: bypass de MFA baseado em SMS e interceptação de OTP usados por grupos APT",d:"i"},
  ]}
]}
];
