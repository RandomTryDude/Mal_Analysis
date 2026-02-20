#### Step 1: Disconnect from Internet ⚠️ CRITICAL
```powershell
# Disable all network adapters
Get-NetAdapter | Disable-NetAdapter -Confirm:$false
```

#### Step 2: Kill Malicious Processes
```powershell
# Kill Node.js processes
Get-Process -Name "node" -ErrorAction SilentlyContinue | Stop-Process -Force

# Kill Python processes from suspicious locations
Get-Process -Name "python*" -ErrorAction SilentlyContinue | 
    Where-Object {$_.Path -like "*AppData*"} | 
    Stop-Process -Force

# Kill PowerShell processes (if not current)
Get-Process -Name "powershell" -ErrorAction SilentlyContinue | 
    Where-Object {$_.Id -ne $PID} | 
    Stop-Process -Force
```

#### Step 3: Remove Discord Injection ⚠️ CRITICAL
```powershell
# Uninstall Discord completely
Write-Host "[*] Removing Discord..." -ForegroundColor Yellow

# Kill Discord processes
Get-Process | Where-Object {$_.ProcessName -like "*Discord*"} | Stop-Process -Force

# Remove Discord installations
$discordPaths = @(
    "$env:LOCALAPPDATA\Discord",
    "$env:LOCALAPPDATA\DiscordCanary",
    "$env:LOCALAPPDATA\DiscordPTB"
)

foreach ($path in $discordPaths) {
    if (Test-Path $path) {
        Write-Host "    Removing: $path" -ForegroundColor Yellow
        Remove-Item -Path $path -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# Remove Discord from AppData Roaming
$roamingDiscord = "$env:APPDATA\discord"
if (Test-Path $roamingDiscord) {
    Remove-Item -Path $roamingDiscord -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host "[+] Discord removed. Reinstall from official site after remediation." -ForegroundColor Green
```

#### Step 4: Remove Scheduled Tasks
```powershell
# List and remove suspicious tasks
Get-ScheduledTask | Where-Object {
    $_.Settings.Hidden -eq $true -or 
    $_.Description -like "*autochk*" -or
    $_.Description -like "*telemetry*"
} | ForEach-Object {
    Write-Host "[*] Removing task: $($_.TaskName)" -ForegroundColor Yellow
    Unregister-ScheduledTask -TaskName $_.TaskName -Confirm:$false
    Write-Host "[+] Removed: $($_.TaskName)" -ForegroundColor Green
}
```

#### Step 5: Remove Registry Keys
```powershell
# Remove Run keys (CAREFUL - only remove suspicious entries)
$runKeys = @(
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
)

foreach ($key in $runKeys) {
    if (Test-Path $key) {
        $values = Get-ItemProperty $key -ErrorAction SilentlyContinue
        $values.PSObject.Properties | Where-Object {
            $_.Name -notmatch "PS" -and $_.Value -ne $null
        } | ForEach-Object {
            Write-Host "[?] Found: $($_.Name) = $($_.Value)" -ForegroundColor Yellow
            $remove = Read-Host "    Remove this entry? (yes/no)"
            if ($remove -eq "yes") {
                Remove-ItemProperty -Path $key -Name $_.Name -Force
                Write-Host "[+] Removed: $($_.Name)" -ForegroundColor Green
            }
        }
    }
}

# Remove UAC bypass keys
$uacKeys = @(
    "HKCU:\Software\Classes\ms-settings",
    "HKCU:\Software\Classes\mscfile",
    "HKCU:\Software\Classes\Folder\shell\open\command",
    "HKCU:\Software\Classes\exefile\shell\runas"
)

foreach ($key in $uacKeys) {
    if (Test-Path $key) {
        Write-Host "[*] Removing UAC bypass key: $key" -ForegroundColor Yellow
        Remove-Item -Path $key -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "[+] Removed: $key" -ForegroundColor Green
    }
}

# Restore windir environment variable if modified
try {
    $currentWinDir = [Environment]::GetEnvironmentVariable("windir", "User")
    if ($currentWinDir -and $currentWinDir -ne "C:\Windows") {
        Write-Host "[!] Restoring windir variable..." -ForegroundColor Yellow
        [Environment]::SetEnvironmentVariable("windir", "C:\Windows", "User")
        reg delete "HKCU\Environment" /v windir /f 2>$null
        Write-Host "[+] windir restored" -ForegroundColor Green
    }
} catch {}
```

#### Step 6: Remove File Masquerading
```powershell
# Remove SystemCache folder
$systemCache = "$env:LOCALAPPDATA\Microsoft\Windows\SystemCache"
if (Test-Path $systemCache) {
    Write-Host "[*] Removing SystemCache folder..." -ForegroundColor Yellow
    
    # List files first
    Get-ChildItem $systemCache -Force | ForEach-Object {
        Write-Host "    File: $($_.Name)" -ForegroundColor Red
    }
    
    # Remove
    Remove-Item -Path $systemCache -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "[+] SystemCache folder removed" -ForegroundColor Green
} else {
    Write-Host "[+] No SystemCache folder found" -ForegroundColor Green
}
```

#### Step 7: Clear Startup Folder
```powershell
# Clear startup folder
$startupPath = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
$files = Get-ChildItem $startupPath -File -ErrorAction SilentlyContinue

foreach ($file in $files) {
    Write-Host "[?] Found in startup: $($file.Name)" -ForegroundColor Yellow
    $remove = Read-Host "    Remove this file? (yes/no)"
    if ($remove -eq "yes") {
        Remove-Item $file.FullName -Force
        Write-Host "[+] Removed: $($file.Name)" -ForegroundColor Green
    }
}
```

#### Step 8: Block C2 Domains
```powershell
# Add C2 domains to hosts file
$hostsPath = "C:\Windows\System32\drivers\etc\hosts"
$c2Domains = @(
    "network-sync-protocol.net",
    "datanetworksync.onrender.com",
    "sync-service.system-telemetry.workers.dev",
    "funnywebsiteviewer.onrender.com",
)

# Backup hosts file
Copy-Item $hostsPath "$hostsPath.backup.$(Get-Date -Format 'yyyyMMdd')"

# Add blocks
Add-Content -Path $hostsPath -Value ""
Add-Content -Path $hostsPath -Value "# Yaremos Malware C2 Blocks - Added $(Get-Date)"

foreach ($domain in $c2Domains) {
    Add-Content -Path $hostsPath -Value "127.0.0.1 $domain"
    Write-Host "[+] Blocked: $domain" -ForegroundColor Green
}
```