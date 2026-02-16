# ClickFix / Lumma Infostealer Analysis

Source Thread:\
https://www.reddit.com/r/cybersecurity_help/comments/1r4ae25/what_does_this_clickfixlumma_infostealer_ps/

------------------------------------------------------------------------

## Initial Discovery

The primary PowerShell (.ps1) command downloads and executes
instructions from:

`storage.googleapis.com/release-v5-dl/fin2.txt`

using **IEX (Invoke-Expression)**.

The downloaded script sets:

``` powershell
$errorActionPreference = "SilentlyContinue"
```

It then hides the malicious payload inside a large text blob designed to
generate errors and obstruct analysis.

After removing the junk content, we obtain a Base64 string that is:

1.  Reversed\
2.  Base64-decoded\
3.  Reversed again

The resulting payload downloads:

`OpenVPN-2.6.17-I001-amd64.msi`

from the same storage bucket and executes it.

The storage bucket contains multiple payload variants.\
The storage was reported and fully dumped into:

`S3_Content.zip`\
Password: `infected`

------------------------------------------------------------------------

## checkbinary.exe (Golang Binary)

This executable appears to validate a license key, suggesting a
**Malware-as-a-Service (MaaS)** model.

### Golang Analysis

![](https://github.com/user-attachments/assets/02d2cca6-bcb1-46a1-9068-857a66b51c28)

Further inspection suggests remote key validation:

![](https://github.com/user-attachments/assets/4a5ac6a6-fd45-4d86-b171-95ac346b8cad)

A POST request is sent to a remote worker.\
The endpoint is decoded earlier in a `decrypt()` function:

![](https://github.com/user-attachments/assets/d3ce6363-021a-4bf7-ac56-37bd93bb1194)

This confirms a centralized license verification server:

![](https://github.com/user-attachments/assets/f06c0610-6379-4729-8c9d-407517b9b81d)

Conclusion: the malware operates under a service-based model with
centralized validation.

------------------------------------------------------------------------

## License Verification Logic

![](https://github.com/user-attachments/assets/660f8716-30ea-426b-9326-ce00fa1410da)

This condition compares the length of `remote_check` (RSI) to 4.

If length ≠ 4: - The binary contacts the remote server for license
validation\
OR\
- Checks if the string equals `"none"`

![](https://github.com/user-attachments/assets/ba76e765-2510-49bc-9a62-8d54d1fa5019)

If the value equals `"none"`:

![](https://github.com/user-attachments/assets/af7d2866-066a-46cc-855d-b2b7bbffd5c8)

License verification is skipped.\
Otherwise, the program exits.

------------------------------------------------------------------------

## Tasking & Secondary Payload

The malware connects to its main C2 server to retrieve additional
instructions.

The task are of different type : 
- Execute_BAT
- Execute_Exe
- Execute_PS1
- Execute_CMD 
To know which one's which , the program basically run for a if/else

<img width="510" height="126" alt="image" src="https://github.com/user-attachments/assets/a69b9604-9d46-4df4-977b-7fdc81bb2d00" />

Compare the first letter and move on in our case we branche to ps1 
each retrieve a particular file from the s3 bucket 

A task is recieve as a json object : 

<img width="939" height="194" alt="image" src="https://github.com/user-attachments/assets/f1f2ac4b-9eb4-48f3-ab1e-f63765c82580" />

that contain the address of where to fetch it , First from base64 then from AES - GCM 

For the ps1 it will decode as such : 

<img width="875" height="74" alt="image" src="https://github.com/user-attachments/assets/d09b4ec6-901a-4ed2-9400-ce77e60105d1" />

Then be saved & executed : 

<img width="662" height="378" alt="image" src="https://github.com/user-attachments/assets/caa76d15-05e0-4e3e-9046-5f310bc5e634" />

once executed the main program will loop back for further task from the command server

It downloads a secondary file:

![](https://github.com/user-attachments/assets/850be4f1-5dc1-44a9-b74e-e02f68c439a8)

The file is executed and subsequently launched using `wscript.exe`:

![](https://github.com/user-attachments/assets/956587b3-94ec-4a0c-932c-6c743c8896b6)

![](https://github.com/user-attachments/assets/6f692881-6101-4b6a-9c98-07e7d51cbb17)

------------------------------------------------------------------------

## Deno & JavaScript Stage

The PowerShell (IRM/IEX) stage downloads **Deno**, a legitimate
JavaScript runtime, used to execute embedded Base64-encoded JavaScript.

The JavaScript contains multiple layers of obfuscation:

![](https://github.com/user-attachments/assets/807be908-2cfa-4175-b826-ce8f93565695)

### Core Functionality

-   Acts as a bridge between victim and C2\ (4 different server , hardcoded)
-   Maintains persistent connectivity\
-   Receives, schedules, and executes remote commands\
-   Manages task orchestration

### Ununsed function 
- Persistance install/uninstall
- CopyExecutable
- RegisterinRegistry
- InstallWindowsService
- AddFirewallRule
- StopAndRemoveService
- RemoveFirewallRule
- UnregisterFrom Registry

  They may be used in the upcoming version of the campaign but for now , they sit unused
------------------------------------------------------------------------

## Indicators of Compromise (IOCs)

-   Presence of a `.lnk` file under:

    `%AppData%\Microsoft\Windows\Start Menu\Programs\Startup`

-   Active C2 communication observable via:

        netstat -ano | findstr 10044

    (Port 10044 used for C2 communication)

# Campaign Name : Digler
# Threat Actor : Unknown 
# Version analysed : Digler 1.0.1 

