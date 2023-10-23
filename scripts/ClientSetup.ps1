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
    $RepositoryUrl = 'https://{{hostname}}:8443/repository/ChocolateyInternal/',

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
    $QueryString = "((Id eq 'chocolatey') and (not IsPrerelease)) and IsLatestVersion"
    $Query = 'Packages()?$filter={0}' -f [uri]::EscapeUriString($queryString)
    $QueryUrl = ($RepositoryUrl.TrimEnd('/'), $Query) -join '/'

    [xml]$result = $webClient.DownloadString($QueryUrl)
    $result.feed.entry.content.src
} else {
    # Otherwise, assume the URL
    "$($RepositoryUrl.Trim('/'))/chocolatey/$($ChocolateyVersion)"
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

choco config set cacheLocation $env:ChocolateyInstall\choco-cache
choco config set commandExecutionTimeoutSeconds 14400

if ($InternetEnabled) {
    choco source add --name="'ChocolateyInternal'" --source="'$RepositoryUrl'" --allow-self-service --user="'$($Credential.UserName)'" --password="'$($Credential.GetNetworkCredential().Password)'" --priority=1
}
else {
    choco source add --name="'ChocolateyInternal'" --source="'$RepositoryUrl'" --allow-self-service --priority=1
}

choco source disable --name="'Chocolatey'"

choco upgrade chocolatey-license -y --source="'ChocolateyInternal'"
choco upgrade chocolatey.extension -y --params="'/NoContextMenu'" --source="'ChocolateyInternal'" --no-progress
choco upgrade chocolateygui -y --source="'ChocolateyInternal'" --no-progress
choco upgrade chocolateygui.extension -y --source="'ChocolateyInternal'" --no-progress

choco upgrade chocolatey-agent -y --source="'ChocolateyInternal'"

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
