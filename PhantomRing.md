# Hack The Box: Sherlock — PhantomRing Writeup

* **Category:** Malware Forensics & Binary Triage
* **Environment:** Kali Linux / Radare2 (`r2`)
* **Primary Artifact:** Suspect PE binary (`phantomring.exe`)

---

## 1. Scenario Overview
An endpoint detection alert flagged a standalone binary executing out of a temporary directory. The objective of this Sherlock is to perform static binary analysis using Radare2, reconstruct control flow, identify execution primitives and anti-analysis checks, and recover obfuscated configurations and indicators of compromise (IOCs).

---

## 2. Static Analysis Workflow (Radare2)

### Initial Ingestion & Header Triage
The binary was imported into Radare2 with automatic analysis flags enabled:
```bash
r2 -A phantomring.exe
```

Initial metadata extraction verified architecture and binary properties:
```text
[0x00401000]> iI
file     phantomring.exe
format   pe
arch     x86
bits     32
endian   little
compiled <timestamp>
```

Section header evaluation highlighted an elevated entropy profile in `.data` / `.rdata`, indicating packed strings or encrypted configuration buffers:
```text
[0x00401000]> iS
idx=01 vaddr=0x00401000 paddr=0x00000400 sz=0x00002000 vsz=0x00002000 perm=-r-x name=.text
idx=02 vaddr=0x00403000 paddr=0x00002400 sz=0x00000e00 vsz=0x00000e00 perm=-r-- name=.rdata
idx=03 vaddr=0x00404000 paddr=0x00003200 sz=0x00000600 vsz=0x00000a00 perm=-rw- name=.data
```

### Import Address Table (IAT) Inspection
Examining imported APIs to map capability boundaries:
```text
[0x00401000]> ii
sym.imp.KERNEL32.dll_VirtualAlloc
sym.imp.KERNEL32.dll_WriteProcessMemory
sym.imp.KERNEL32.dll_GetProcAddress
sym.imp.KERNEL32.dll_LoadLibraryA
sym.imp.ADVAPI32.dll_RegSetValueExA
sym.imp.WS2_32.dll_WSAStartup
sym.imp.WS2_32.dll_connect
```
* **Capability Footprint:** Memory staging/allocation primitives, registry persistence APIs, and standard Winsock network socket setup.

---

## 3. Control Flow & Execution Tracing

### Function Enumeration & Main Entry Discovery
Listing disassembled functions to identify the core application callback:
```text
[0x00401000]> afl
0x00401000    1 5       entry0
0x00401050    3 45      fcn.00401050
0x00401210   12 280     main
0x00401440    6 110     fcn.00401440
```

Tracing the entrypoint jump thunk directly to `main`:
```text
[0x00401000]> s main
[0x00401210]> pdf
```

### Reverse Engineering Ingress Logic
Disassembly of `main` revealed three distinct phases:

1. **Privilege & Environment Triage:**
   The binary performs basic anti-analysis and execution-environment checks before entering the operational loop. If conditions are met, it advances to local staging.

2. **Host Persistence:**
   Cross-referencing imports to `RegSetValueExA`:
   ```text
   [0x00401210]> axt @ sym.imp.ADVAPI32.dll_RegSetValueExA
   main 0x0040128a [CALL] call dword [sym.imp.ADVAPI32.dll_RegSetValueExA]
   ```
   * The binary queries and writes to `Software\Microsoft\Windows\CurrentVersion\Run`, creating an auto-start registry key pointing to its drop location to maintain survival across user logons.

3. **Callback & Execution Staging:**
   `main` prepares a network socket structure using `WSAStartup` and `connect`, referencing a local memory buffer populated dynamically right before the connection loop.

---

## 4. Deobfuscation & Artifact Extraction

### Locating the Obfuscated Data Buffer
Inspecting cross-references to the helper subroutine (`fcn.00401440`) called immediately prior to socket initialization:
```text
[0x00401210]> pdf @ fcn.00401440
```
Disassembly of `fcn.00401440` revealed an in-place decoding loop:
* Counter register initialized to 0.
* Loop bound check against buffer length (`cmp ecx, <len>`).
* Sequential byte dereference followed by a bitwise XOR transformation.
* Transformed byte stored back into memory (`mov byte [eax], bl`).

### In-Session Extraction via Radare2 Shell
Using Radare2's shell escape (`!`) to execute Python and carve the decoded configuration buffer directly from memory/RVA offset without restarting the session:

```text
[0x00401440]> !python3 -c "import r2pipe; r2=r2pipe.open(); blob=bytes(r2.cmdj('pxj 64 @ 0x00404020')); key=b'<KEY>'; print(bytes(x^key[i%len(key)] for i,x in enumerate(blob)).decode(errors='ignore'))"
```

* **Extracted C2 IP / Port:** Documented callback network indicators and beaconing intervals.
* **Extracted Artifacts:** Identified internal function strings, user-agent parameters, and challenge verification tokens.

---

## 5. Key Findings & Detection Artifacts
* **Payload Family:** Persistent Backdoor / Downloader.
* **Persistence Mechanism:** Windows Registry CurrentVersion Run Key (`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`).
* **Evasion Strategy:** Inline repeating XOR string encoding to defeat static detection heuristics and raw ASCII/Unicode string scraping.
* **Analysis Paradigm:** Static triage, import cross-referencing, and in-situ deobfuscation via Radare2.
