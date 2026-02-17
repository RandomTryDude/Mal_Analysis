# Digler — Malware Campaign Analysis

> **⚠️ For educational and research purposes only.**  
> All samples are password-protected. Do not execute outside an isolated environment.  
> Password: `infected`

---

## Overview

**Digler** is a MaaS (Malware-as-a-Service) campaign disguised as an OpenVPN installer, delivered via ClickFix social engineering. The campaign spans three major versions of a Golang-based implant (`checkbinary.exe`), a JavaScript RAT executed through Deno/Bun, and a Cloudflare Workers-based C2 infrastructure.

| Field | Value |
|-------|-------|
| Campaign Name | Digler |
| Threat Actor | Unknown |
| First Seen | 2025 |
| Language | Go (1.14.11 → 1.25.5) |
| C2 Protocol | HTTPS + AES-GCM encrypted strings |
| License Model | MaaS (remote + offline key validation) |

---

## Repository Structure

```
📁 Digler/
├── 📄 DiglerV1.0.1.md          ← Full analysis — Digler v1.0.1
├── 📄 DiglerV1.0.2.md          ← Full analysis — Digler v1.0.2
│
├── 📁 Helpers/
│   ├── Key_generator.py        ← Generates valid Digler license keys
│   └── mk3.py                  ← AES-GCM string decryptor (v1.0.0 & v1.0.2)
│
└── 📁 Malware_/
    ├── Digler_Exe.7z           ← Unpacked checkbinary.exe (all versions)
    └── S3_Bucket.7z            ← Full dump of the GCS payload bucket
```

---

## Version Timeline

| Version | MSI | Go Version | Hash (MD5) |
|---------|-----|-----------|------------|
| v1.0.0 | `digler-ad2aa665.msi` | — | — |
| v1.0.0 (SWUpdate) | `digler-2de1e197.msi` | — | — |
| v1.0.1 | `OpenVPN-2.6.17-I001-amd64.msi` | 1.14.11 | `DAF1CB75EDD8E045F5F6034FC76C097F` |
| v1.0.2 | `digler-f867700a.msi` | 1.25.5 | `AD4DDF9C289F28DA9665BE0CA4742710` |

---

## S3 Bucket Contents

The threat actor used a Google Cloud Storage bucket (`storage.googleapis.com/release-v5-dl/`) to host all payloads. Full dump available in `S3_Bucket.7z`.

### Dropper Scripts

| File | Action |
|------|--------|
| `fin2.txt` | Downloads & executes `OpenVPN-2.6.17-I001-amd64.msi` (Digler v1.0.1) |
| `fin.txt` | Downloads & executes `OpenVPN-2.6.17-I001-amd64.msi` + `5becedd21a4ac155.ps1` |
| `rdy73.txt` | Downloads & executes `OpenVPN-2.6.17-I001-amd64.msi` |
| `rdy72.txt` | Downloads & executes `upd2e3b.msi` |
| `test1.txt` | Downloads & executes `upd2e3b.msi` |

### MSI Payloads

| File | Behavior |
|------|----------|
| `digler-ad2aa665.msi` | Digler v1.0.0 — first known version |
| `digler-2de1e197.msi` | SWUpdate 2.41 wrapper → Digler v1.0.0 |
| `OpenVPN-2.6.17-I001-amd64.msi` | Fake OpenVPN → Digler v1.0.1 |
| `digler-f867700a.msi` | Digler v1.0.2 |
| `upd-v020201.msi` | Extracts `papa23.vbs` → executes via `wscript.exe` → drops `sierra_handler26.js` + installs Deno under `%LOCALAPPDATA%\upd-v020201\` |
| `upd2e3b.msi` | Extracts `Mike78.vbs` → executes via `wscript.exe` → drops `sierra_handler26.js` + installs Deno under `%LOCALAPPDATA%\upd2e3b\` |
| `update.msi` | Extracts `lynx_block13.vbs` → drops `xray99.js` + installs Deno from `deno.land/install.ps1` under `%LOCALAPPDATA%\update\` |

### PowerShell / JavaScript Payloads

| File | Behavior |
|------|----------|
| `5becedd21a4ac155.ps1` | Creates JavaScript RAT at `%LOCALAPPDATA%\mike_bridge21\sierra_handler26.js` |
| `webTracking.js` | ⚠️ **Unknown** — low VT detection. Possible new initial infection vector (ClickFix?). Executes via `bun.exe`, installs startup LNK under `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\`. C2: see IOCs below. |

---

## Helpers

### `mk3.py` — AES-GCM String Decryptor

Decrypts all hardcoded strings from Digler binaries using keys dumped from memory (WinDbg/x64dbg).

```bash
python mk3.py
```

Supports **automatic key detection** — tries all known keys, selects the one producing valid UTF-8 output (validated via GCM tag or readability score).

**Known keys:**

| Version | Key (hex) |
|---------|-----------|
| v1.0.0 | `c9d1ff80f285d7d22eb95b57326504c5ac5c2e98bd972488dd636bcc46b807d0` |
| v1.0.2 | `e0d3bf915b4cc246b213768af38388b21ecb214b9620c2ad63c6fd7df67f57c7` |

### `Key_generator.py` — License Key Generator

Generates valid Digler license keys based on the offline validation scheme (MD5 of date).

---

## Indicators of Compromise (IOCs)

### Network — C2 Domains

**Digler v1.0.2 (Cloudflare Workers):**
```
https://us5-east[.]cloud-updater[.]workers[.]dev/
https://stat[.]web-analytics[.]workers[.]dev/
https://download[.]stable-releases[.]workers[.]dev/
```

**Digler v1.0.0 (Direct IP):**
```
http://91[.]210[.]165[.].153:8080
```

**JavaScript RAT — sierra_handler26.js / xray99.js (v1.0.1):**
```
http://stat[.]greenslighttcodetdat[.]net
http://aplalink[.]com
http://altsocks101[.]com
http://altsocks2[.]com
```

**webTracking.js (unknown campaign):**
```
greenlightcoding[.]net
weaplink[.]com
altsocks101[.]com
altsocks102[.]com
```

**Public IP resolution:**
```
https://ifconfig.me/ip
https://checkip.amazonaws.com
```

**Payload hosting:**
```
storage[.]googleapis[.]com/release-v5-dl/*
```

### Network — API Endpoints (v1.0.2)

```
POST /api/agent/check-in     ← Machine registration
GET  /api/agent              ← Task retrieval
GET  /api/agent/record_ops   ← Operation reporting
POST /api/agent/task_result  ← Task result report
```

### File System

```
C:\Users\%USERNAME%\AppData\Local\OnCall\<random>.exe
C:\Users\%USERNAME%\AppData\Local\mike_bridge21\sierra_handler26.js
C:\Users\%USERNAME%\AppData\Local\upd-v020201\sierra_handler26.js
C:\Users\%USERNAME%\AppData\Local\upd2e3b\sierra_handler26.js
C:\Users\%USERNAME%\AppData\Local\update\xray99.js
%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\OnCall.lnk
%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\<lnk from webTracking.js>
```

### Registry Keys

```
HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\OnCall
HKCU\Software\Microsoft\Windows\CurrentVersion\Run\OnCall
HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System → SoftwareSASGeneration
```

### Scheduled Tasks

```
OnCall-Helper-PeriodicRestart     (every 30 minutes)
```

### Firewall Rules

```
"OnCall Service"  dir=in   action=allow  program=<path>
"OnCall Service"  dir=out  action=allow  program=<path>
```

### File Hashes (MD5)

| Hash | Description |
|------|-------------|
| `AD4DDF9C289F28DA9665BE0CA4742710` | checkbinary.exe v1.0.2 |
| `DAF1CB75EDD8E045F5F6034FC76C097F` | checkbinary.exe v1.0.1 |
| `14148DB21D3F6AC4C1DAA8D9500DEC26` | Fake OpenVPN installer (Digler v1.0.1) |

### JWT Tokens (extracted from samples)

**v1.0.0:**
```
eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJidWlsZF9pZCI6IjJkZTFlMTk3IiwiZXhwIjoxODMwNjE1MTIwLCJpYXQiOjE3Njc1NDMxMjAsImp0aSI6IjZjMzU3YjdjLTZlNDItNGNlOC04Y2JiLTQyMjYwMTE5MmIxZSIsInByb2plY3RfbmFtZSI6ImRpZ2xlciIsInN1YiI6IjJkZTFlMTk3IiwidGVuYW50X3Byb2plY3RfaWQiOiIzN2tYREFoaHJQNjhRNlZnU2dxcm9nMEZPZkwiLCJ2ZXJzaW9uIjoiMS4wLjAifQ.behLSHUWKBNitozONFohoSaaBPbGHrkRhco0t3bl9P-yrC4FlntUyJQebxl6i99HU9l8tDzL6wH9tqScSR6cAA
```

**v1.0.2:**
```
eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJidWlsZF9pZCI6ImY4Njc3MDBhIiwiZXhwIjoxODMxMjQ2NjY3LCJpYXQiOjE3NjgxNzQ2NjcsImp0aSI6IjJlYTMxOWMyLWFjZjgtNDQ3Zi1hZDI0LWE5MjVkMzJlYzMyZSIsInByb2plY3RfbmFtZSI6ImRpZ2xlciIsInN1YiI6ImY4Njc3MDBhIiwidGVuYW50X3Byb2plY3RfaWQiOiIzN2tYREFoaHJQNjhRNlZnU2dxcm9nMEZPZkwiLCJ2ZXJzaW9uIjoiMS4wLjIifQ.Q8yz_ykudbSzJoL3vUtpPTTRGcpg1Lp3LQPAZqinXhAnAYSTkOGji-oOX-WdRSu-HetWuFPHUjYBYPi55lLVAA
```

---

## MITRE ATT&CK Summary

| Tactic | ID | Technique |
|--------|----|-----------|
| Initial Access | T1566.001 | Phishing: Spearphishing (ClickFix) |
| Execution | T1059.001 | PowerShell |
| Execution | T1059.007 | JavaScript (Deno / Bun) |
| Persistence | T1547.001 | Registry Run Keys / Startup Folder |
| Persistence | T1053.005 | Scheduled Task |
| Persistence | T1543.003 | Windows Service |
| Defense Evasion | T1027 | Obfuscated Files or Information |
| Defense Evasion | T1140 | Deobfuscate/Decode at Runtime (AES-GCM) |
| Defense Evasion | T1562.004 | Modify System Firewall |
| Defense Evasion | T1036 | Masquerading (fake OpenVPN, trusted-looking C2 domains) |
| Defense Evasion | T1070 | Indicator Removal (cleans previous version traces) |
| Discovery | T1082 | System Information Discovery |
| Discovery | T1016 | System Network Configuration Discovery |
| Discovery | T1033 | System Owner/User Discovery |
| C2 | T1071.001 | Web Protocols (HTTPS) |
| C2 | T1102 | Web Service (Cloudflare Workers) |
| C2 | T1573 | Encrypted Channel (AES-GCM) |
| C2 | T1568 | Dynamic Resolution (3 fallback C2 domains) |

---

## References

- [Reddit thread — initial discovery](https://www.reddit.com/r/cybersecurity_help/comments/1r4ae25/what_does_this_clickfixlumma_infostealer_ps/)
- [VirusTotal — checkbinary v1.0.2](https://www.virustotal.com/gui/file/f8fef470326c2834b213fe47a5024edbb101dc966395622a6617f686d330fb52/detection)

---

*Analysis performed on FLARE-VM — February 2026*