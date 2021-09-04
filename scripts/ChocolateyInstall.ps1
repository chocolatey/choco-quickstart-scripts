<#
    .SYNOPSIS
    Downloads and installs Chocolatey on the local machine.

    .DESCRIPTION
    Retrieves the chocolatey nupkg for the latest or a specified version, and
    downloads and installs the application to the local machine.

    .NOTES
    =====================================================================
    Copyright 2017 - 2020 Chocolatey Software, Inc, and the
    original authors/contributors from ChocolateyGallery
    Copyright 2011 - 2017 RealDimensions Software, LLC, and the
    original authors/contributors from ChocolateyGallery
    at https://github.com/chocolatey/chocolatey.org

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
    =====================================================================

    Environment Variables, specified as $env:NAME in PowerShell.exe and %NAME% in cmd.exe.
    For explicit proxy, please set $env:chocolateyProxyLocation and optionally $env:chocolateyProxyUser and $env:chocolateyProxyPassword
    For an explicit version of Chocolatey, please set $env:chocolateyVersion = 'versionnumber'
    To target a different url for chocolatey.nupkg, please set $env:chocolateyDownloadUrl = 'full url to nupkg file'
    NOTE: $env:chocolateyDownloadUrl does not work with $env:chocolateyVersion.
    To use built-in compression instead of 7zip (requires additional download), please set $env:chocolateyUseWindowsCompression = 'true'
    To bypass the use of any proxy, please set $env:chocolateyIgnoreProxy = 'true'
#>
[CmdletBinding(DefaultParameterSetName = 'Default')]
param(
    # The URL of the the internal Nexus repository to install Chocolatey from.
    [Parameter()]
    [Alias('Url')]
    [string]
    $RepositoryUrl = 'https://{{hostname}}:8443/repository/ChocolateyInternal/',

    # The credential necessary to access the internal Nexus repository. This can
    # be ignored if Anonymous authentication is enabled.
    # This parameter will be necessary if your QDE setup is web-enabled.
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
    $ProxyCredential
)

#region Functions

function Get-Downloader {
    <#
    .SYNOPSIS
    Gets a System.Net.WebClient that respects relevant proxies to be used for
    downloading data.

    .DESCRIPTION
    Retrieves a WebClient object that is pre-configured according to specified
    environment variables for any proxy and authentication for the proxy.
    Proxy information may be omitted if the target URL is considered to be
    bypassed by the proxy (originates from the local network.)

    .PARAMETER Url
    Target url that the WebClient will be querying. This URI is not queried by
    the function, it is only a reference to determine if a proxy is needed.

    .EXAMPLE
    Get-Downloader -Url $fileUrl

    Verifies whether any proxy configuration is needed, and/or whether $fileUrl
    is a URI that would need to bypass the proxy, and then outputs the
    already-configured WebClient object.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]
        $Url,

        [Parameter()]
        [pscredential]
        $Credential,

        [Parameter()]
        [string]
        $ProxyUrl,

        [Parameter()]
        [pscredential]
        $ProxyCredential
    )

    $downloader = New-Object System.Net.WebClient

    if ($Credential) {
        $downloader.Credentials = $Credential.GetNetworkCredential()
    }
    else {
        $defaultCreds = [System.Net.CredentialCache]::DefaultCredentials
        if ($defaultCreds) {
            $downloader.Credentials = $defaultCreds
        }
    }

    if (-not ($ProxyUrl -and $ProxyCredential)) {
        Write-Verbose "Not using proxy."
        $downloader.Proxy = $null
    }
    elseif ($ProxyUrl) {
        # Use explicitly set proxy.
        Write-Verbose "Using explicit proxy server '$ProxyUrl'."
        $proxy = New-Object System.Net.WebProxy -ArgumentList $ProxyUrl, <# bypassOnLocal: #> $true

        $proxy.Credentials = if ($ProxyCredential) {
            $ProxyCredential.GetNetworkCredential()
        }
        elseif ($defaultCreds) {
            $defaultCreds
        }
        else {
            Write-Warning "Default credentials were null, and no explicitly set proxy credentials were found. Attempting backup method."
            (Get-Credential).GetNetworkCredential()
        }

        if (-not $proxy.IsBypassed($Url)) {
            $downloader.Proxy = $proxy
        }
    }
    else {
        Write-Verbose "Using empty proxy."
    }

    $downloader
}

function Request-String {
    <#
    .SYNOPSIS
    Downloads content from a remote server as a string.

    .DESCRIPTION
    Downloads target string content from a URL and outputs the resulting string.
    Any existing proxy that may be in use will be utilised.

    .PARAMETER Url
    Parameter description

    .PARAMETER ProxyConfiguration
    A hashtable containing proxy parameters (ProxyUrl and ProxyCredential)

    .EXAMPLE
    Request-String https://chocolatey.org/install.ps1

    Retrieves the contents of the string data at the targeted URI and outputs
    it to the pipeline.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $Url,

        [Parameter()]
        [pscredential]
        $Credential,

        [Parameter()]
        [hashtable]
        $ProxyConfiguration
    )

    $creds = if ($Credential) {
        @{ Credential = $Credential }
    }
    else {
        @{}
    }

    (Get-Downloader $url @ProxyConfiguration @creds).DownloadString($url)
}

function Request-File {
    <#
    .SYNOPSIS
    Downloads a file from a given URL.

    .DESCRIPTION
    Downloads a target file from a URL to the specified local path.
    Any existing proxy that may be in use will be utilised.

    .PARAMETER Url
    URI of the file to download from the remote host.

    .PARAMETER File
    Local path for the file to be downloaded to.

    .PARAMETER ProxyConfiguration
    A hashtable containing proxy parameters (ProxyUrl and ProxyCredential)

    .EXAMPLE
    Request-File -Url https://chocolatey.org/install.ps1 -File $targetFile

    Downloads the install.ps1 script to the path specified in $targetFile.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]
        $Url,

        [Parameter()]
        [string]
        $File,

        [Parameter()]
        [pscredential]
        $Credential,

        [Parameter()]
        [hashtable]
        $ProxyConfiguration
    )


    $creds = if ($Credential) {
        @{ Credential = $Credential }
    }
    else {
        @{}
    }

    Write-Verbose "Downloading $url to $file"
    (Get-Downloader $url @ProxyConfiguration @creds).DownloadFile($url, $file)
}

function Set-PSConsoleWriter {
    <#
    .SYNOPSIS
    Workaround for a bug in output stream handling PS v2 or v3.

    .DESCRIPTION
    PowerShell v2/3 caches the output stream. Then it throws errors due to the
    FileStream not being what is expected. Fixes "The OS handle's position is
    not what FileStream expected. Do not use a handle simultaneously in one
    FileStream and in Win32 code or another FileStream." error.

    .EXAMPLE
    Set-PSConsoleWriter

    .NOTES
    General notes
    #>

    [CmdletBinding()]
    param()
    if ($PSVersionTable.PSVersion.Major -gt 3) {
        return
    }

    try {
        # http://www.leeholmes.com/blog/2008/07/30/workaround-the-os-handles-position-is-not-what-filestream-expected/ plus comments
        $bindingFlags = [Reflection.BindingFlags] "Instance,NonPublic,GetField"
        $objectRef = $host.GetType().GetField("externalHostRef", $bindingFlags).GetValue($host)

        $bindingFlags = [Reflection.BindingFlags] "Instance,NonPublic,GetProperty"
        $consoleHost = $objectRef.GetType().GetProperty("Value", $bindingFlags).GetValue($objectRef, @())
        [void] $consoleHost.GetType().GetProperty("IsStandardOutputRedirected", $bindingFlags).GetValue($consoleHost, @())

        $bindingFlags = [Reflection.BindingFlags] "Instance,NonPublic,GetField"
        $field = $consoleHost.GetType().GetField("standardOutputWriter", $bindingFlags)
        $field.SetValue($consoleHost, [Console]::Out)

        [void] $consoleHost.GetType().GetProperty("IsStandardErrorRedirected", $bindingFlags).GetValue($consoleHost, @())
        $field2 = $consoleHost.GetType().GetField("standardErrorWriter", $bindingFlags)
        $field2.SetValue($consoleHost, [Console]::Error)
    }
    catch {
        Write-Warning "Unable to apply redirection fix."
    }
}

function Test-ChocolateyInstalled {
    [CmdletBinding()]
    param()

    $checkPath = if ($env:ChocolateyInstall) { $env:ChocolateyInstall } else { 'C:\ProgramData\chocolatey' }

    if (-not (Test-Path $checkPath)) {
        # Install folder doesn't exist
        $false
    }
    elseif (-not (Get-ChildItem -Path $checkPath)) {
        # Install folder exists but is empty
        $false
    }
    else {
        # Install folder exists and is not empty
        $true
    }
}

#endregion Functions

#region Pre-check

if (Test-ChocolateyInstalled) {
    Write-Warning "An existing Chocolatey installation was detected. Installation will not continue."

    return
}

#endregion Pre-check

#region Setup

$proxyConfig = if ($IgnoreProxy -or -not $ProxyUrl) {
    @{}
}
else {
    $config = @{
        ProxyUrl = $ProxyUrl
    }

    if ($ProxyCredential) {
        $config['ProxyCredential'] = $ProxyCredential
    }
    elseif ($env:chocolateyProxyUser -and $env:chocolateyProxyPassword) {
        $securePass = ConvertTo-SecureString $env:chocolateyProxyPassword -AsPlainText -Force
        $config['ProxyCredential'] = [pscredential]::new($env:chocolateyProxyUser, $securePass)
    }

    $config
}

$creds = if ($Credential) {
    @{ Credential = $Credential }
}
else {
    @{}
}

# Use the API to get the latest version (below)
Write-Host "Getting latest version of the Chocolatey package for download."
$queryString = [uri]::EscapeUriString("((Id eq 'chocolatey') and (not IsPrerelease)) and IsLatestVersion")
$query = 'Packages()?$filter={0}' -f $queryString
$queryUrl = ($RepositoryUrl.TrimEnd('/'), $query) -join '/'

[xml]$result = Request-String -Url $queryUrl -ProxyConfiguration $proxyConfig @creds
$url = $result.feed.entry.content.src

if (-not $env:TEMP) {
    $env:TEMP = Join-Path $env:SystemDrive -ChildPath 'temp'
}

$chocTempDir = Join-Path $env:TEMP -ChildPath "chocolatey"
$tempDir = Join-Path $chocTempDir -ChildPath "chocInstall"

if (-not (Test-Path $tempDir -PathType Container)) {
    $null = New-Item -Path $tempDir -ItemType Directory
}

$file = Join-Path $tempDir "chocolatey.zip"

Set-PSConsoleWriter

# Attempt to set highest encryption available for SecurityProtocol.
# PowerShell will not set this by default (until maybe .NET 4.6.x). This
# will typically produce a message for PowerShell v2 (just an info
# message though)
try {
    # Set TLS 1.2 (3072) as that is the minimum required by Chocolatey.org.
    # Use integers because the enumeration value for TLS 1.2 won't exist
    # in .NET 4.0, even though they are addressable if .NET 4.5+ is
    # installed (.NET 4.5 is an in-place upgrade).
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
}
catch {
    $errorMessage = @(
        'Unable to set PowerShell to use TLS 1.2. This is required for contacting Chocolatey as of 03 FEB 2020.'
        'https://chocolatey.org/blog/remove-support-for-old-tls-versions.'
        'If you see underlying connection closed or trust errors, you may need to do one or more of the following:'
        '(1) upgrade to .NET Framework 4.5+ and PowerShell v3+,'
        '(2) Call [System.Net.ServicePointManager]::SecurityProtocol = 3072; in PowerShell prior to attempting installation,'
        '(3) specify internal Chocolatey package location (set $env:chocolateyDownloadUrl prior to install or host the package internally),'
        '(4) use the Download + PowerShell method of install.'
        'See https://chocolatey.org/docs/installation for all install options.'
    ) -join [Environment]::NewLine
    Write-Warning $errorMessage
}

#endregion Setup

#region Download & Extract Chocolatey

Write-Verbose "Getting Chocolatey from $url."
Request-File -Url $url -File $file -ProxyConfiguration $proxyConfig @creds

# Determine unzipping method
# 7zip is the most compatible so use it unless asked to use builtin
if ($env:chocolateyUseWindowsCompression) {
    Write-Verbose 'Using built-in compression to unzip'
    $unzipMethod = 'builtin'
}
else {
    $7zaExe = Join-Path $tempDir -ChildPath '7za.exe'
    $unzipMethod = '7zip'

    if (-not (Test-Path ($7zaExe))) {
        Write-Verbose "Downloading 7-Zip commandline tool prior to extraction."
        Request-File -Url 'https://chocolatey.org/7za.exe' -File $7zaExe -ProxyConfiguration $proxyConfig
    }
}

Write-Verbose "Extracting $file to $tempDir"
if ($unzipMethod -eq '7zip') {
    $params = 'x -o{0} -bd -y "{1}"' -f $tempDir, $file

    # use more robust Process as compared to Start-Process -Wait (which doesn't
    # wait for the process to finish in PowerShell v3)
    $process = New-Object System.Diagnostics.Process

    try {
        $process.StartInfo = New-Object System.Diagnostics.ProcessStartInfo -ArgumentList $7zaExe, $params
        $process.StartInfo.RedirectStandardOutput = $true
        $process.StartInfo.UseShellExecute = $false
        $process.StartInfo.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden

        $null = $process.Start()
        $process.BeginOutputReadLine()
        $process.WaitForExit()

        $exitCode = $process.ExitCode
    }
    finally {
        $process.Dispose()
    }

    $errorMessage = "Unable to unzip package using 7zip. Perhaps try setting `$env:chocolateyUseWindowsCompression = 'true' and call install again. Error:"
    if ($exitCode -ne 0) {
        $errorDetails = switch ($exitCode) {
            1 { "Some files could not be extracted" }
            2 { "7-Zip encountered a fatal error while extracting the files" }
            7 { "7-Zip command line error" }
            8 { "7-Zip out of memory" }
            255 { "Extraction cancelled by the user" }
            default { "7-Zip signalled an unknown error (code $exitCode)" }
        }

        throw ($errorMessage, $errorDetails -join [Environment]::NewLine)
    }
}
else {
    if ($PSVersionTable.PSVersion.Major -lt 5) {
        try {
            $shellApplication = New-Object -ComObject Shell.Application
            $zipPackage = $shellApplication.NameSpace($file)
            $destinationFolder = $shellApplication.NameSpace($tempDir)
            $destinationFolder.CopyHere($zipPackage.Items(), 0x10)
        }
        catch {
            Write-Warning "Unable to unzip package using built-in compression. Set `$env:chocolateyUseWindowsCompression = 'false' and call install again to use 7zip to unzip."
            throw $_
        }
    }
    else {
        Expand-Archive -Path $file -DestinationPath $tempDir -Force
    }
}

#endregion Download & Extract Chocolatey

#region Install Chocolatey

Write-Verbose "Installing chocolatey on the local machine"
$toolsFolder = Join-Path $tempDir -ChildPath "tools"
$chocInstallPS1 = Join-Path $toolsFolder -ChildPath "chocolateyInstall.ps1"

& $chocInstallPS1

Write-Verbose 'Ensuring chocolatey commands are on the path'
$chocInstallVariableName = "ChocolateyInstall"
$chocoPath = [Environment]::GetEnvironmentVariable($chocInstallVariableName)

if (-not $chocoPath) {
    $chocoPath = "$env:ALLUSERSPROFILE\Chocolatey"
}

if (-not (Test-Path ($chocoPath))) {
    $chocoPath = "$env:SYSTEMDRIVE\ProgramData\Chocolatey"
}

$chocoExePath = Join-Path $chocoPath -ChildPath 'bin'

# Update current process PATH environment variable if it needs updating.
if ($env:Path -notlike "*$chocoExePath*") {
    $env:Path = [Environment]::GetEnvironmentVariable('Path', [System.EnvironmentVariableTarget]::Machine);
}

Write-Verbose 'Ensuring chocolatey.nupkg is in the lib folder'
$chocoPkgDir = Join-Path $chocoPath -ChildPath 'lib\chocolatey'
$nupkg = Join-Path $chocoPkgDir -ChildPath 'chocolatey.nupkg'

if (-not (Test-Path $chocoPkgDir -PathType Container)) {
    $null = New-Item -ItemType Directory -Path $chocoPkgDir
}

Copy-Item -Path $file -Destination $nupkg -Force -ErrorAction SilentlyContinue

#endregion Install Chocolatey