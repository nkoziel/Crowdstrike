<#
.SYNOPSIS
Migrate a sensor to another falcon cloud tenant.
.DESCRIPTION
Removes and installs the sensor using the new cloud and CID.

Falcon and Sensor tags are migrated to the new installation.
.PARAMETER NewFalconClientId
CrowdStrike Falcon OAuth2 API Client Id for the new Cloud [Required]
.PARAMETER NewFalconClientSecret
CrowdStrike Falcon OAuth2 API Client Secret for the new Cloud [Required]
.PARAMETER OldFalconClientId
CrowdStrike Falcon OAuth2 API Client Id for the old cloud [Required]
.PARAMETER OldFalconClientSecret
CrowdStrike Falcon OAuth2 API Client Secret for the old cloud [Required]
.PARAMETER NewFalconCloud
CrowdStrike Falcon OAuth2 API Hostname for the new cloud [default: 'autodiscover']
.PARAMETER OldFalconCloud
CrowdStrike Falcon OAuth2 API Hostname for the old cloud [default: 'autodiscover']
.PARAMETER NewFalconCid
Manually specify CrowdStrike Customer ID (CID) for the new cloud [default: $null]
.PARAMETER NewMemberCid
Member CID, used only in multi-CID ("Falcon Flight Control") configurations and with a parent management CID for the new cloud.
.PARAMETER OldMemberCid
Member CID, used only in multi-CID ("Falcon Flight Control") configurations and with a parent management CID for the old cloud.
.PARAMETER SensorUpdatePolicyName
Sensor Update Policy name to check for assigned sensor version [default: 'platform_default']
.PARAMETER InstallParams
Sensor installation parameters, without your CID value ['/install /quiet /noreboot' if left undefined]
.PARAMETER LogPath
Script log location ['Windows\Temp\csfalcon_migration_yyyy-MM-dd_HH-mm-ss.log' if left undefined]
.PARAMETER DeleteInstaller
Delete sensor installer package when complete [default: $true]
.PARAMETER DeleteUninstaller
Delete sensor uninstaller package when complete [default: $true]
.PARAMETER DeleteScript
Delete script when complete [default: $false]
.PARAMETER ProvToken
Provisioning token to use for sensor installation [default: $null]
.PARAMETER ProvWaitTime
Time to wait, in seconds, for sensor to provision [default: 1200]
.PARAMETER Tags
A comma-separated list of sensor grouping tags to apply to the host in addition to any pre-existing tags [default: $null]
.PARAMETER FalconTags
A comma-separated list of falcon grouping tags to apply to the host in addition to any pre-existing tags [default: $null]
.PARAMETER MaintenanceToken
Sensor uninstall maintenance token. If left undefined, the script will attempt to retrieve the token from the API assuming the FalconClientId|FalconClientSecret are defined.
.PARAMETER UninstallParams
Sensor uninstall parameters ['/uninstall /quiet' if left undefined]
.PARAMETER UninstallTool
Sensor uninstall tool, local installation cache or CS standalone uninstaller ['installcache' if left undefined]
.PARAMETER RemoveHost
Remove host from CrowdStrike Falcon
.PARAMETER SkipTags
Opt in/out of migrating tags. Tags passed to the Tags flag will still be added.
.PARAMETER ProxyHost
The proxy host for the sensor to use when communicating with CrowdStrike [default: $null]
.PARAMETER ProxyPort
The proxy port for the sensor to use when communicating with CrowdStrike [default: $null]
.PARAMETER ProxyDisable
By default, the Falcon sensor for Windows automatically attempts to use any available proxy connections when it connects to the CrowdStrike cloud.
This parameter forces the sensor to skip those attempts and ignore any proxy configuration, including Windows Proxy Auto Detection.
.PARAMETER Verbose
Enable verbose logging
#>
#Requires -Version 3.0

[CmdletBinding()]
param(
    [Parameter(Position = 1)]
    [ValidatePattern('\w{32}')]
    [string] $NewFalconClientId,
    [Parameter(Position = 2)]
    [ValidatePattern('\w{40}')]
    [string] $NewFalconClientSecret,
    [Parameter(Position = 3)]
    [ValidateSet('autodiscover', 'us-1', 'us-2', 'eu-1', 'us-gov-1')]
    [string] $NewFalconCloud = 'autodiscover',
    [Parameter(Position = 4)]
    [string] $NewMemberCid,
    [Parameter(Position = 5)]
    [ValidatePattern('\w{32}')]
    [string] $OldFalconClientId,
    [Parameter(Position = 6)]
    [ValidatePattern('\w{40}')]
    [string] $OldFalconClientSecret,
    [Parameter(Position = 7)]
    [ValidateSet('autodiscover', 'us-1', 'us-2', 'eu-1', 'us-gov-1')]
    [string] $OldFalconCloud = 'autodiscover',
    [Parameter(Position = 8)]
    [string] $OldMemberCid,
    [Parameter(Position = 9 )]
    [string] $SensorUpdatePolicyName,
    [Parameter(Position = 10)]
    [string] $InstallParams,
    [Parameter(Position = 11)]
    [string] $LogPath,
    [Parameter(Position = 12)]
    [string] $ProvToken,
    [Parameter(Position = 13)]
    [int] $ProvWaitTime = 1200,
    [Parameter(Position = 14)]
    [string] $Tags = '',
    [Parameter(Position = 15)]
    [string] $FalconTags = '',
    [Parameter(Position = 16)]
    [string] $MaintenanceToken,
    [Parameter(Position = 17)]
    [switch] $RemoveHost,
    [Parameter(Position = 18)]
    [string] $UninstallParams = '/uninstall /quiet',
    [Parameter(Position = 19)]
    [ValidateSet('installcache', 'standalone')]
    [string] $UninstallTool = 'installcache',
    [Parameter(Position = 20)]
    [switch] $SkipTags,
    [Parameter(Position = 21)]
    [bool] $DeleteUninstaller = $true,
    [Parameter(Position = 22)]
    [bool] $DeleteInstaller = $true,
    [Parameter(Position = 23)]
    [bool] $DeleteScript = $false,
    [Parameter(Position = 24)]
    [ValidatePattern('\w{32}-\w{2}')]
    [string] $NewFalconCid,
    [Parameter(Position = 25)]
    [string] $ProxyHost,
    [Parameter(Position = 26)]
    [int] $ProxyPort,
    [Parameter(Position = 27)]
    [switch] $ProxyDisable
)


function Write-RecoveryCsv {
    param (
        [array] $SensorGroupingTags,
        [array] $FalconGroupingTags,
        [string] $OldAid,
        [string] $Path
    )

    $directory = Split-Path -Parent $Path
    if (!(Test-Path $directory)) {
        New-Item -ItemType Directory -Path $directory | Out-Null
    }

    $data = @()
    $dataRow = [PSCustomObject]@{
        'OldAid'             = $OldAid
        'SensorGroupingTags' = ($SensorGroupingTags -join ',')
        'FalconGroupingTags' = ($FalconGroupingTags -join ',')
    }
    $data += $dataRow
    $data = $data | Select-Object * -ExcludeProperty PS*
    $data | Export-Csv -Path $Path -NoTypeInformation -Force

    if (Test-Path $Path) {
        Write-FalconLog -Source 'Write-RecoveryCsv' -Message "Recovery CSV file successfully created at $Path"
    }
    else {
        Write-FalconLog -Source 'Write-RecoveryCsv' -Message 'Error: Recovery CSV file could not be created'
    }
}


function Read-RecoveryCsv {
    param (
        [string] $Path
    )

    if (!(Test-Path $Path)) {
        Write-FalconLog -Source 'Read-RecoveryCsv' -Message "Recovery CSV file not found at $Path"
        throw "Recovery CSV does not exist at path $Path"
    }

    $data = Import-Csv -Path $Path
    $data = $data | Select-Object * -ExcludeProperty PS*
    $data = $data | ConvertTo-Json -Compress
    $data = ConvertFrom-Json -InputObject $data

    $data.SensorGroupingTags = (Format-TagArray -Tags $data.SensorGroupingTags)
    $data.FalconGroupingTags = (Format-TagArray -Tags $data.FalconGroupingTags)

    return $data
}


function Compare-TagsDiff {
    param (
        [array] $Tags,
        [array] $TagList
    )

    $Tags = $Tags -split ','

    if ($null -eq $TagList -or $TagList.Length -eq 0) {
        return $Tags
    }

    $tagsDiff = $Tags | Where-Object { $TagList -notcontains $_ }
    return $tagsDiff
}


function Format-TagArray {
    param (
        [string] $Tags,
        [string] $Seperator = ','
    )

    if ($Tags -eq '') {
        return @()
    }

    return $Tags -split $Seperator
}


function Write-FalconLog ([string] $Source, [string] $Message, [bool] $stdout = $true) {
    $Content = @(Get-Date -Format 'yyyy-MM-dd hh:MM:ss')
    if ($Source -notmatch '^(StartProcess|Delete(Installer|Script))$' -and
        $Falcon.ResponseHeaders.Keys -contains 'X-Cs-TraceId') {
        $Content += , "[$($Falcon.ResponseHeaders.Get('X-Cs-TraceId'))]"
    }

    "$(@($Content + $Source) -join ' '): $Message" | Out-File -FilePath $LogPath -Append -Encoding utf8

    if ($stdout) {
        Write-Output $Message
    }
}

function Write-VerboseLog ([psobject] $VerboseInput, [string] $PreMessage) {

    # Determine if the input is a string or an object
    if ($VerboseInput -is [string]) {
        $message = $VerboseInput
    }
    else {
        $message = $VerboseInput | ConvertTo-Json -Depth 5
    }

    # If an pre message is provided, add it to the beginning of the message
    if ($PreMessage) {
        $message = "$PreMessage`r`n$message"
    }

    # Write Verbose
    Write-Verbose $message

    # Write to log file, but not stdout
    Write-FalconLog -Source 'VERBOSE' -Message $message -stdout $false
}


# Uninstall Falcon Sensor
function Invoke-FalconUninstall ([hashtable] $WebRequestParams, [string] $UninstallParams, [switch] $RemoveHost, [bool] $DeleteUninstaller, [string] $MaintenanceToken, [string] $UninstallTool) {
    try {
        $AgentService = Get-Service -Name CSAgent -ErrorAction SilentlyContinue
        if (!$AgentService) {
            $Message = "'CSFalconService' service not found, already uninstalled"
            Write-FalconLog -Source 'Invoke-FalconUninstall' -Message $Message
            return
        }

        $UninstallerPath = $null
        switch ($UninstallTool) {
            'installcache' {
                $UninstallerName = 'WindowsSensor*.exe'
                $UninstallerPathDir = 'C:\ProgramData\Package Cache'

                if (Test-Path -Path $UninstallerPathDir) {
                    $UninstallerPath = Get-ChildItem -Include $UninstallerName -Path $UninstallerPathDir -Recurse | ForEach-Object { $_.FullName } | Sort-Object -Descending | Select-Object -First 1
                }
                else {
                    $UninstallerPath = $null
                }
            }
            Default {
                $UninstallerName = 'CsUninstallTool.exe'
                $UninstallerPath = Join-Path -Path $PSScriptRoot -ChildPath $UninstallerName
            }
        }

        if (!$UninstallerPath -or (-not (Test-Path -Path $UninstallerPath))) {
            $Message = "${UninstallerName} not found. Unable to uninstall without the cached uninstaller or the standalone uninstaller."
            Write-FalconLog -Source 'Invoke-FalconUninstall' -Message $Message
            throw $Message
        }

        # If $oldBaseUrl and $oldCloudHeaders are null, then call the Get-HeadersAndUrl function again. Could be due to recovery mode.
        if (!$oldBaseUrl -or !$oldCloudHeaders) {
            $oldBaseUrl, $oldCloudHeaders = Get-HeadersAndUrl -WebRequestParams $WebRequestParams -FalconClientId $OldFalconClientId -FalconClientSecret $OldFalconClientSecret -FalconCloud $OldFalconCloud -MemberCid $OldMemberCid
        }

        if ($RemoveHost) {
            Write-FalconLog -Source 'Invoke-FalconUninstall' -Message 'Removing host from Falcon console'
            Invoke-HostVisibility -WebRequestParams $WebRequestParams -Aid $oldAid -action 'hide' -BaseUrl $oldBaseUrl -Headers $oldCloudHeaders
        }

        if ($MaintenanceToken) {
            # Assume the maintenance token is a valid Token and skip API calls
            $UninstallParams += " MAINTENANCE_TOKEN=$MaintenanceToken"
        }
        else {
            if ($oldAid) {
                # Assume user wants to use API to retrieve token
                # Build request body for retrieving maintenance token
                Write-FalconLog -Source 'Invoke-FalconUninstall' -Message 'Retrieving maintenance token from the CrowdStrike Falcon API.'
                $Body = @{
                    'device_id'     = $oldAid
                    'audit_message' = 'CrowdStrike Falcon Uninstall Powershell Script'
                }

                $bodyJson = $Body | ConvertTo-Json

                try {
                    $url = "${oldBaseUrl}/policy/combined/reveal-uninstall-token/v1"

                    $response = Invoke-WebRequest @WebRequestParams -Uri $url -UseBasicParsing -Method 'POST' -Headers $oldCloudHeaders -Body $bodyJson -MaximumRedirection 0
                    $content = ConvertFrom-Json -InputObject $response.Content
                    Write-VerboseLog -VerboseInput $content -PreMessage 'GetToken - $content:'

                    if ($content.errors) {
                        $Message = 'Failed to retrieve maintenance token: '
                        $Message += Format-FalconResponseError -errors $content.errors
                        Write-FalconLog -Source 'Invoke-FalconUninstall' -Message $Message
                        throw $Message
                    }
                    else {
                        $MaintenanceToken = $content.resources[0].uninstall_token
                        Write-FalconLog -Source 'Invoke-FalconUninstall' -Message "Retrieved maintenance token: $MaintenanceToken"
                        $UninstallParams += " MAINTENANCE_TOKEN=$MaintenanceToken"
                    }
                }
                catch {
                    Write-VerboseLog -VerboseInput $_.Exception -PreMessage 'GetToken - CAUGHT EXCEPTION - $_.Exception:'
                    $response = $_.Exception.Response

                    if (!$response) {
                        $Message = "Unhandled error occurred while retrieving maintenance token from the CrowdStrike Falcon API. Error: $($_.Exception.Message)"
                        Write-FalconLog -Source 'Invoke-FalconUninstall' -Message $Message
                        throw $Message
                    }

                    if ($response.StatusCode -eq 403) {
                        $scope = @{
                            'Sensor update policies' = @('Write')
                        }

                        $Message = Format-403Error -url $url -scope $scope

                        Write-FalconLog -Source 'Invoke-FalconUninstall' -Message $Message
                        throw $Message
                    }
                    else {
                        $Message = "Received a $($response.StatusCode) response from $($baseUrl)$($url) Error: $($response.StatusDescription)"
                        Write-FalconLog -Source 'Invoke-FalconUninstall' -Message $Message
                        throw $Message
                    }
                }
            }
        }

        # Begin uninstallation
        Write-FalconLog -Source 'Invoke-FalconUninstall' -Message 'Uninstalling Falcon Sensor...'
        Write-FalconLog -Source 'Invoke-FalconUninstall' -Message "Starting uninstaller with parameters: '$UninstallParams'"
        $UninstallerProcess = Start-Process -FilePath "$UninstallerPath" -ArgumentList $UninstallParams -PassThru -Wait
        $UninstallerProcessId = $UninstallerProcess.Id
        Write-FalconLog -Source 'Invoke-FalconUninstall' -Message "Started '$UninstallerPath' ($UninstallerProcessId)"
        if ($UninstallerProcess.ExitCode -ne 0) {
            Write-VerboseLog -VerboseInput $UninstallerProcess -PreMessage 'PROCESS EXIT CODE ERROR - $UninstallerProcess:'
            if ($UninstallerProcess.ExitCode -eq 106) {
                $Message = 'Unable to uninstall, Falcon Sensor is protected with a maintenance token. Provide a valid maintenance token and try again.'
            }
            else {
                $Message = "Uninstaller returned exit code $($UninstallerProcess.ExitCode)"
            }
            Write-FalconLog -Source 'Invoke-FalconUninstall' -Message $Message

            if ($RemoveHost) {
                $Message = 'Uninstall failed, attempting to restore host visibility...'
                Write-FalconLog -Source 'Invoke-FalconUninstall' -Message $Message
                Invoke-HostVisibility -WebRequestParams $WebRequestParams -Aid $oldAid -action 'show' -BaseUrl $oldBaseUrl -Headers $oldCloudHeaders
            }
            throw $Message
        }

        $AgentService = Get-Service -Name CSAgent -ErrorAction SilentlyContinue
        if ($AgentService -and $AgentService.Status -eq 'Running') {
            $Message = 'Service uninstall failed...'
            Write-FalconLog -Source 'Invoke-FalconUninstall' -Message $Message
            throw $Message
        }

        if (Test-Path -Path HKLM:\System\Crowdstrike) {
            $Message = 'Registry key removal failed...'
            Write-FalconLog -Source 'Invoke-FalconUninstall' -Message $Message
            throw $Message
        }

        if (Test-Path -Path"${env:SYSTEMROOT}\System32\drivers\CrowdStrike") {
            $Message = 'Driver removal failed...'
            Write-FalconLog -Source 'Invoke-FalconUninstall' -Message $Message
            throw $Message
        }

        # Delete the uninstaller
        if ($DeleteUninstaller) {
            if (Test-Path $UninstallerPath) {
                Remove-Item -Path $UninstallerPath -Force
            }
            if (Test-Path $UninstallerPath) {
                $Message = "Failed to delete '$UninstallerPath'"
                Write-FalconLog -Source 'Invoke-FalconUninstall' -Message $Message
                throw $Message
            }
            else {
                Write-FalconLog -Source 'Invoke-FalconUninstall' -Message "Deleted '$UninstallerPath'"
            }
        }
        else {
            Write-FalconLog -Source 'Invoke-FalconUninstall' -Message "Skipping deletion of '$UninstallerPath'"
        }

        Write-FalconLog -Source 'Invoke-FalconUninstall' -Message 'Falcon Sensor successfully uninstalled.'
    }
    catch {
        Write-VerboseLog -VerboseInput $_.Exception -PreMessage 'Invoke-FalconUninstall - CAUGHT EXCEPTION - $_.Exception:'
        $message = "Error uninstalling Falcon Sensor: $($_.Exception.Message)"
        throw $message
    }
}


# Install Falcon Sensor
function Invoke-FalconInstall ([hashtable] $WebRequestParams, [string] $InstallParams, [string] $Tags, [bool] $DeleteInstaller, [string] $SensorUpdatePolicyName, [string] $ProvToken, [int] $ProvWaitTime, [string] $NewFalconCid) {
    $newBaseUrl, $newCloudHeaders = Get-HeadersAndUrl -WebRequestParams $WebRequestParams -FalconClientId $NewFalconClientId -FalconClientSecret $NewFalconClientSecret -FalconCloud $NewFalconCloud -MemberCid $NewMemberCid

    try {
        if (!$SensorUpdatePolicyName) {
            $SensorUpdatePolicyName = 'platform_default'
        }
        if (!$InstallParams) {
            $InstallParams = '/install /quiet /noreboot'
        }

        # Main install logic
        if (Get-Service | Where-Object { $_.Name -eq 'CSFalconService' }) {
            $Message = "'CSFalconService' running. Falcon sensor is already installed."
            Write-FalconLog -Source 'Invoke-FalconInstall' -Message $Message
            break
        }

        # If NewFalconCid is not provided, get it from the API
        if (!$NewFalconCid) {
            Write-FalconLog 'GetCcid' 'No CCID provided. Attempting to retrieve from the CrowdStrike Falcon API.'
            $url = "${newBaseUrl}/sensors/queries/installers/ccid/v1"
            $ccid_scope = @{
                'Sensor Download' = @('Read')
            }
            $ccid = Get-ResourceContent -WebRequestParams $WebRequestParams -url $url -logKey 'GetCcid' -scope $ccid_scope -errorMessage "Unable to grab CCID from the CrowdStrike Falcon API." -Headers $newCloudHeaders

            $message = "Retrieved CCID: $ccid"
            Write-FalconLog 'GetCcid' $message
            $InstallParams += " CID=$ccid"
        }
        else {
            $message = "Using provided CCID: $NewFalconCid"
            Write-FalconLog 'GetCcid' $message
            $InstallParams += " CID=$NewFalconCid"
        }

        # Get sensor version from policy
        $message = "Retrieving sensor policy details for '$($SensorUpdatePolicyName)'"
        Write-FalconLog -Source 'Invoke-FalconInstall' -Message $message
        $filter = "platform_name:'Windows'+name.raw:'$($SensorUpdatePolicyName)'"
        $url = "${newBaseUrl}/policy/combined/sensor-update/v2?filter=$([System.Web.HttpUtility]::UrlEncode($filter)))"
        $policy_scope = @{
            'Sensor update policies' = @('Read')
        }
        $policyDetails = Get-ResourceContent -WebRequestParams $WebRequestParams -url $url -logKey 'GetPolicy' -scope $policy_scope -errorMessage "Unable to fetch policy details from the CrowdStrike Falcon API." -Headers $newCloudHeaders
        $policyId = $policyDetails.id
        $build = $policyDetails[0].settings.build
        $version = $policyDetails[0].settings.sensor_version

        # Make sure we got a version from the policy
        if (!$version) {
            $message = "Unable to retrieve sensor version from policy '$($SensorUpdatePolicyName)'. Please check the policy and try again."
            Write-FalconLog -Source 'Invoke-FalconInstall' -Message $message
            throw $message
        }

        $message = "Retrieved sensor policy details: Policy ID: $policyId, Build: $build, Version: $version"
        Write-FalconLog -Source 'Invoke-FalconInstall' -Message $message

        # Get installer details based on policy version
        $message = "Retrieving installer details for sensor version: '$($version)'"
        Write-FalconLog -Source 'Invoke-FalconInstall' -Message $message
        $encodedFilter = [System.Web.HttpUtility]::UrlEncode("platform:'windows'+version:'$($version)'")
        $url = "${newBaseUrl}/sensors/combined/installers/v1?filter=${encodedFilter}"
        $installer_scope = @{
            'Sensor Download' = @('Read')
        }
        $installerDetails = Get-ResourceContent -WebRequestParams $WebRequestParams -url $url -logKey 'GetInstaller' -scope $installer_scope -errorMessage "Unable to fetch installer details from the CrowdStrike Falcon API." -Headers $newCloudHeaders

        if ( $installerDetails.sha256 -and $installerDetails.name ) {
            $cloudHash = $installerDetails.sha256
            $cloudFile = $installerDetails.name
            $message = "Found installer: ($cloudFile) with sha256: '$cloudHash'"
            Write-FalconLog -Source 'Invoke-FalconInstall' -Message $message
        }
        else {
            $message = "Failed to retrieve installer details."
            Write-FalconLog -Source 'Invoke-FalconInstall' -Message $message
            throw $message
        }
# Compress the second part of the script

function Get-AID {
    $reg_paths = 'HKLM:\SYSTEM\CrowdStrike\{9b03c1d9-3138-44ed-9fae-d9f4c034b88d}\{16e0423f-7058-48c9-a204-725362b67639}\Default', 'HKLM:\SYSTEM\CurrentControlSet\Services\CSAgent\Sim'
    $aid = $null
    foreach ($path in $reg_paths) {
        try {
            $agItemProperty = Get-ItemProperty -Path $path -Name AG -ErrorAction SilentlyContinue

            if ($null -eq $agItemProperty) {
                continue
            }

            $aid = [System.BitConverter]::ToString( ($agItemProperty.AG)).ToLower() -replace '-', ''
            break
        }
        catch {
            return $null
        }
    }
    return $aid
}


# Changes the host visibility status in the CrowdStrike Falcon console
# an action of $hide will hide the host, anything else will unhide the host
# should only be called to hide/unhide a host that is already in the console
function Invoke-HostVisibility ([hashtable] $WebRequestParams, [string] $Aid, [string] $action, [string] $BaseUrl, [hashtable] $Headers) {
    if ($action -eq 'hide') {
        $action = 'hide_host'
    }
    else {
        $action = 'unhide_host'
    }

    if ($null -eq $Aid) {
        $Message = "AID not found on machine. Unable to ${action} host without AID, this may be due to the sensor not being installed or being partially installed."
        Write-FalconLog -Source 'Invoke-HostVisibility' -Message $Message
        throw $Message
    }

    $Body = @{
        'ids' = @($Aid)
    }

    $bodyJson = $Body | ConvertTo-Json
    try {
        $url = "${BaseUrl}/devices/entities/devices-actions/v2?action_nam

    # Compress the second part of the script

function Get-AID {
    $reg_paths = 'HKLM:\SYSTEM\CrowdStrike\{9b03c1d9-3138-44ed-9fae-d9f4c034b88d}\{16e0423f-7058-48c9-a204-725362b67639}\Default', 'HKLM:\SYSTEM\CurrentControlSet\Services\CSAgent\Sim'
    $aid = $null
    foreach ($path in $reg_paths) {
        try {
            $agItemProperty = Get-ItemProperty -Path $path -Name AG -ErrorAction SilentlyContinue

            if ($null -eq $agItemProperty) {
                continue
            }

            $aid = [System.BitConverter]::ToString( ($agItemProperty.AG)).ToLower() -replace '-', ''
            break
        }
        catch {
            return $null
        }
    }
    return $aid
}
# Changes the host visibility status in the CrowdStrike Falcon console
# an action of $hide will hide the host, anything else will unhide the host
# should only be called to hide/unhide a host that is already in the console
function Invoke-HostVisibility ([hashtable] $WebRequestParams, [string] $Aid, [string] $action, [string] $BaseUrl, [hashtable] $Headers) {
    if ($action -eq 'hide') {
        $action = 'hide_host'
    }
    else {
        $action = 'unhide_host'
    }

    if ($null -eq $Aid) {
        $Message = "AID not found on machine. Unable to ${action} host without AID, this may be due to the sensor not being installed or being partially installed."
        Write-FalconLog -Source 'Invoke-HostVisibility' -Message $Message
        throw $Message
    }

    $Body = @{
        'ids' = @($Aid)
    }

    $bodyJson = $Body | ConvertTo-Json
    try {
        $url = "${BaseUrl}/devices/entities/devices-actions/v2?action_name=${action}"
        $response = Invoke-WebRequest @WebRequestParams -Uri $url -UseBasicParsing -Method 'POST' -Headers $Headers -Body $bodyJson -MaximumRedirection 0
        $content = ConvertFrom-Json -InputObject $response.Content
        Write-VerboseLog -VerboseInput $content -PreMessage 'Invoke-HostVisibility - $content:'

        if ($content.errors) {
            $Message = "Error when calling ${action} on host: "
            $Message += Format-FalconResponseError -errors $content.errors
            Write-FalconLog -Source 'Invoke-HostVisibility' -Message $Message
            throw $Message
        }
        else {
            $Message = "Action ${action} executed successfully on host"
            Write-FalconLog -Source 'Invoke-HostVisibility' -Message $Message
        }
    }
    catch {
        Write-VerboseLog -VerboseInput $_.Exception -PreMessage 'Invoke-HostVisibility - CAUGHT EXCEPTION - $_.Exception:'
        $response = $_.Exception.Response

        if (!$response) {
            $Message = "Unhandled error occurred while performing action '${action}' on host from the CrowdStrike Falcon API. Error: $($_.Exception.Message)"
            Write-FalconLog -Source 'Invoke-HostVisibility' -Message $Message
            throw $Message
        }

        if ($response.StatusCode -eq 409) {
            $Message = "Received a $($response.StatusCode) response from ${url} Error: $($response.StatusDescription)"
            Write-FalconLog -Source 'Invoke-HostVisibility' -Message $Message
            Write-FalconLog -Source 'Invoke-HostVisibility' -Message 'Host already removed from CrowdStrike Falcon'
        }
        elseif ($response.StatusCode -eq 403) {
            $scope = @{
                'host' = @('Write')
            }
            $Message = Format-403Error -url $url -scope $scope
            Write-FalconLog -Source 'Invoke-HostVisibility' -Message $Message
            throw $Message
        }
        else {
            $Message = "Received a $($response.StatusCode) response from ${url}. Error: $($response.StatusDescription)"
            Write-FalconLog -Source 'Invoke-HostVisibility' -Message $Message
            throw $Message
        }
    }
}

function Get-InstallerHash ([string] $Path) {
    $Output = if (Test-Path $Path) {
        $Algorithm = [System.Security.Cryptography.HashAlgorithm]::Create("SHA256")
        $Hash = [System.BitConverter]::ToString(
            $Algorithm.ComputeHash([System.IO.File]::ReadAllBytes($Path)))
        if ($Hash) {
            $Hash.Replace('-', '')
        }
        else {
            $null
        }
    }
    return $Output
}

