<#
.SYNOPSIS
Completes client setup for a client machine to communicate with the C4B Server.
#>
[CmdletBinding(DefaultParameterSetName = 'Default')]
param(
    # The URL of the the internal Nexus repository to install Chocolatey from.
    # This URL will be used to create the internal package source configuration.
    [Parameter()]
    [Alias('Url')]
    [string]
    $RepositoryUrl = 'https://{{hostname}}:8443/repository/ChocolateyInternal/index.json',

    # The credential necessary to access the internal Nexus repository. This can
    # be ignored if Anonymous authentication is enabled.
    # This parameter will be necessary if your C4B server is web-enabled.
    [Parameter()]
    [pscredential]
    $Credential,

    # Specifies a target version of Chocolatey to install. By default, the
    # latest stable version is installed.
    [Parameter()]
    [string]
    $ChocolateyVersion = $env:chocolateyVersion,

    # Specifies whether to ignore any configured proxy. This will override any
    # specified proxy environment variables.
    [Parameter()]
    [switch]
    $IgnoreProxy = [bool]$env:chocolateyIgnoreProxy,

    # The URL of a proxy server to use for connecting to the repository.
    [Parameter(Mandatory = $true, ParameterSetName = 'Proxy')]
    $ProxyUrl = $env:chocolateyProxyLocation,

    # The credentials, if required, to connect to the proxy server.
    [Parameter(ParameterSetName = 'Proxy')]
    [pscredential]
    $ProxyCredential,

    # Client salt value used to populate the centralManagementClientCommunicationSaltAdditivePassword
    # value in the Chocolatey config file
    [Parameter()]
    [string]
    $ClientSalt,

    # Server salt value used to populate the centralManagementServiceCommunicationSaltAdditivePassword
    # value in the Chocolatey config file
    [Parameter()]
    [string]
    $ServiceSalt,

    [Parameter()]
    [Switch]
    $InternetEnabled
)

Set-ExecutionPolicy Bypass -Scope Process -Force

$hostAddress = $RepositoryUrl.Split('/')[2]
$hostName = ($hostAddress -split ':')[0]

$params = @{
    ChocolateyVersion = $ChocolateyVersion
    IgnoreProxy       = $IgnoreProxy
    UseNativeUnzip    = $true
}

if (-not $IgnoreProxy) {
    if ($ProxyUrl) {
        $params.Add('ProxyUrl', $ProxyUrl)
    }

    if ($ProxyCredential) {
        $params.Add('ProxyCredential', $ProxyCredential)
    }
}

$webClient = New-Object System.Net.WebClient
if ($Credential) {
    $webClient.Credentials = $Credential.GetNetworkCredential()
}

# Find the latest version of Chocolatey, if a version was not specified
$NupkgUrl = if (-not $ChocolateyVersion) {
    $QueryUrl = ($RepositoryUrl.TrimEnd('/index.json'), "v3/registration/Chocolatey/index.json") -join '/'
    $Result = $webClient.DownloadString($QueryUrl) | ConvertFrom-Json
    $Result.items.items[-1].packageContent
} else {
    # Otherwise, assume the URL
    "$($RepositoryUrl.TrimEnd('/index.json'))/v3/content/chocolatey/$($ChocolateyVersion)/chocolatey.$($ChocolateyVersion).nupkg"
}

# Download the NUPKG
$NupkgPath = Join-Path $env:TEMP "$(New-Guid).zip"
$webClient.DownloadFile($NupkgUrl, $NupkgPath)

# Add Parameter for ChocolateyDownloadUrl, that is the NUPKG path
$params.Add('ChocolateyDownloadUrl', $NupkgPath)

# Get the script content
$script = $webClient.DownloadString("https://${hostAddress}/repository/choco-install/ChocolateyInstall.ps1")

# Run the Chocolatey Install script with the parameters provided
& ([scriptblock]::Create($script)) @params

# If FIPS is enabled, configure Chocolatey to use FIPS compliant checksums
$fipsStatus = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy" -Name Enabled
if ($fipsStatus.Enabled -eq 1) {
    Write-Warning -Message "FIPS is enabled on this system. Ensuring Chocolatey uses FIPS compliant checksums"
    choco feature enable --name='useFipsCompliantChecksums'
}

choco config set cacheLocation $env:ChocolateyInstall\choco-cache
choco config set commandExecutionTimeoutSeconds 14400

# Nexus NuGet V3 Compatibility
choco feature disable --name="'usePackageRepositoryOptimizations'"

if ($InternetEnabled) {
    choco source add --name="'ChocolateyInternal'" --source="'$RepositoryUrl'" --allow-self-service --user="'$($Credential.UserName)'" --password="'$($Credential.GetNetworkCredential().Password)'" --priority=1
}
else {
    choco source add --name="'ChocolateyInternal'" --source="'$RepositoryUrl'" --allow-self-service --priority=1
}

choco source disable --name="'Chocolatey'"
choco source disable --name="'chocolatey.licensed'"

choco upgrade chocolatey-license -y --source="'ChocolateyInternal'"
choco upgrade chocolatey.extension -y --params="'/NoContextMenu'" --source="'ChocolateyInternal'" --no-progress
choco upgrade chocolateygui -y --source="'ChocolateyInternal'" --no-progress
choco upgrade chocolateygui.extension -y --source="'ChocolateyInternal'" --no-progress

choco upgrade chocolatey-agent -y --source="'ChocolateyInternal'"

# Chocolatey Package Upgrade Resilience
choco feature enable --name="'excludeChocolateyPackagesDuringUpgradeAll'"

# Self-Service configuration
choco feature disable --name="'showNonElevatedWarnings'"
choco feature enable --name="'useBackgroundService'"
choco feature enable --name="'useBackgroundServiceWithNonAdministratorsOnly'"
choco feature enable --name="'allowBackgroundServiceUninstallsFromUserInstallsOnly'"
choco config set --name="'backgroundServiceAllowedCommands'" --value="'install,upgrade,uninstall'"

# CCM Check-in Configuration
choco config set CentralManagementServiceUrl "https://${hostName}:24020/ChocolateyManagementService"
if ($ClientSalt) {
    choco config set centralManagementClientCommunicationSaltAdditivePassword $ClientSalt
}
if ($ServiceSalt) {
    choco config set centralManagementServiceCommunicationSaltAdditivePassword $ServiceSalt
}
choco feature enable --name="'useChocolateyCentralManagement'"
choco feature enable --name="'useChocolateyCentralManagementDeployments'"
