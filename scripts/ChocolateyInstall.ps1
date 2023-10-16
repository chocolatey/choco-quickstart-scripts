<#
    .SYNOPSIS
    Downloads and installs Chocolatey on the local machine.

    .DESCRIPTION
    Retrieves the Chocolatey nupkg for the latest or a specified version, and
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

    .LINK
    For organizational deployments of Chocolatey, please see https://docs.chocolatey.org/en-us/guides/organizations/organizational-deployment-guide

#>
[CmdletBinding(DefaultParameterSetName = 'Default')]
param(
    # The URL to download Chocolatey from. This defaults to the value of
    # $env:chocolateyDownloadUrl, if it is set, and otherwise falls back to the
    # official Chocolatey community repository to download the Chocolatey package.
    # Can be used for offline installation by providing a path to a Chocolatey.nupkg.
    [Parameter(Mandatory = $false)]
    [string]
    $ChocolateyDownloadUrl = $env:chocolateyDownloadUrl,

    # Specifies a target version of Chocolatey to install. By default, the latest
    # stable version is installed. This will use the value in
    # $env:chocolateyVersion by default, if that environment variable is present.
    # This parameter is ignored if -ChocolateyDownloadUrl is set.
    [Parameter(Mandatory = $false)]
    [string]
    $ChocolateyVersion = $env:chocolateyVersion,

    # If set, uses built-in Windows decompression tools instead of 7zip when
    # unpacking the downloaded nupkg. This will be set by default if
    # $env:chocolateyUseWindowsCompression is set to a value other than 'false' or '0'.
    #
    # This parameter will be ignored in PS 5+ in favour of using the
    # Expand-Archive built in PowerShell cmdlet directly.
    [Parameter(Mandatory = $false)]
    [switch]
    $UseNativeUnzip = $(
        $envVar = "$env:chocolateyUseWindowsCompression".Trim()
        $value = $null
        if ([bool]::TryParse($envVar, [ref] $value)) {
            $value
        } elseif ([int]::TryParse($envVar, [ref] $value)) {
            [bool]$value
        } else {
            [bool]$envVar
        }
    ),

    # If set, ignores any configured proxy. This will override any proxy
    # environment variables or parameters. This will be set by default if
    # $env:chocolateyIgnoreProxy is set to a value other than 'false' or '0'.
    [Parameter(Mandatory = $false)]
    [switch]
    $IgnoreProxy = $(
        $envVar = "$env:chocolateyIgnoreProxy".Trim()
        $value = $null
        if ([bool]::TryParse($envVar, [ref] $value)) {
            $value
        }
        elseif ([int]::TryParse($envVar, [ref] $value)) {
            [bool]$value
        }
        else {
            [bool]$envVar
        }
    ),

    # Specifies the proxy URL to use during the download. This will default to
    # the value of $env:chocolateyProxyLocation, if any is set.
    [Parameter(ParameterSetName = 'Proxy', Mandatory = $false)]
    [string]
    $ProxyUrl = $env:chocolateyProxyLocation,

    # Specifies the credential to use for an authenticated proxy. By default, a
    # proxy credential will be constructed from the $env:chocolateyProxyUser and
    # $env:chocolateyProxyPassword environment variables, if both are set.
    [Parameter(ParameterSetName = 'Proxy', Mandatory = $false)]
    [System.Management.Automation.PSCredential]
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
    Target URL that the WebClient will be querying. This URL is not queried by
    the function, it is only a reference to determine if a proxy is needed.

    .EXAMPLE
    Get-Downloader -Url $fileUrl

    Verifies whether any proxy configuration is needed, and/or whether $fileUrl
    is a URL that would need to bypass the proxy, and then outputs the
    already-configured WebClient object.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]
        $Url,

        [Parameter(Mandatory = $false)]
        [string]
        $ProxyUrl,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        $ProxyCredential
    )

    $downloader = New-Object System.Net.WebClient

    $defaultCreds = [System.Net.CredentialCache]::DefaultCredentials
    if ($defaultCreds) {
        $downloader.Credentials = $defaultCreds
    }

    if ($ProxyUrl) {
        # Use explicitly set proxy.
        Write-Host "Using explicit proxy server '$ProxyUrl'."
        $proxy = New-Object System.Net.WebProxy -ArgumentList $ProxyUrl, <# bypassOnLocal: #> $true

        $proxy.Credentials = if ($ProxyCredential) {
            $ProxyCredential.GetNetworkCredential()
        } elseif ($defaultCreds) {
            $defaultCreds
        } else {
            Write-Warning "Default credentials were null, and no explicitly set proxy credentials were found. Attempting backup method."
            (Get-Credential).GetNetworkCredential()
        }

        if (-not $proxy.IsBypassed($Url)) {
            $downloader.Proxy = $proxy
        }
    } else {
        Write-Host "Not using proxy."
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
    URL to download string data from.

    .PARAMETER ProxyConfiguration
    A hashtable containing proxy parameters (ProxyUrl and ProxyCredential)

    .EXAMPLE
    Request-String https://community.chocolatey.org/install.ps1

    Retrieves the contents of the string data at the targeted URL and outputs
    it to the pipeline.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $Url,

        [Parameter(Mandatory = $false)]
        [hashtable]
        $ProxyConfiguration
    )

    (Get-Downloader $url @ProxyConfiguration).DownloadString($url)
}

function Request-File {
    <#
    .SYNOPSIS
    Downloads a file from a given URL.

    .DESCRIPTION
    Downloads a target file from a URL to the specified local path.
    Any existing proxy that may be in use will be utilised.

    .PARAMETER Url
    URL of the file to download from the remote host.

    .PARAMETER File
    Local path for the file to be downloaded to.

    .PARAMETER ProxyConfiguration
    A hashtable containing proxy parameters (ProxyUrl and ProxyCredential)

    .EXAMPLE
    Request-File -Url https://community.chocolatey.org/install.ps1 -File $targetFile

    Downloads the install.ps1 script to the path specified in $targetFile.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]
        $Url,

        [Parameter(Mandatory = $false)]
        [string]
        $File,

        [Parameter(Mandatory = $false)]
        [hashtable]
        $ProxyConfiguration
    )

    Write-Host "Downloading $url to $file"
    (Get-Downloader $url @ProxyConfiguration).DownloadFile($url, $file)
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
    } catch {
        Write-Warning "Unable to apply redirection fix."
    }
}

function Test-ChocolateyInstalled {
    [CmdletBinding()]
    param()

    $checkPath = if ($env:ChocolateyInstall) { $env:ChocolateyInstall } else { "$env:PROGRAMDATA\chocolatey" }

    if ($Command = Get-Command choco -CommandType Application -ErrorAction Ignore) {
        # choco is on the PATH, assume it's installed
        Write-Warning "'choco' was found at '$($Command.Path)'."
        $true
    }
    elseif (-not (Test-Path $checkPath)) {
        # Install folder doesn't exist
        $false
    }
    else {
        # Install folder exists
        if (Get-ChildItem -Path $checkPath) {
            Write-Warning "Files from a previous installation of Chocolatey were found at '$($CheckPath)'."
        }

        # Return true here to prevent overwriting an existing installation
        $true
    }
}

function Install-7zip {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $Path,

        [Parameter(Mandatory = $false)]
        [hashtable]
        $ProxyConfiguration
    )
    if (-not (Test-Path ($Path))) {
        Write-Host "Downloading 7-Zip commandline tool prior to extraction."
        Request-File -Url 'https://community.chocolatey.org/7za.exe' -File $Path -ProxyConfiguration $ProxyConfiguration
    }
    else {
        Write-Host "7zip already present, skipping installation."
    }
}

#endregion Functions

#region Pre-check

# Ensure we have all our streams setup correctly, needed for older PSVersions.
Set-PSConsoleWriter

if (Test-ChocolateyInstalled) {
    $message = @(
        "An existing Chocolatey installation was detected. Installation will not continue. This script will not overwrite existing installations."
        "If there is no Chocolatey installation at '$env:ChocolateyInstall', delete the folder and attempt the installation again."
        ""
        "Please use `choco upgrade chocolatey` to handle upgrades of Chocolatey itself."
        "If the existing installation is not functional or a prior installation did not complete, follow these steps:"
        " - Backup the files at the path listed above so you can restore your previous installation if needed."
        " - Remove the existing installation manually."
        " - Rerun this installation script."
        " - Reinstall any packages previously installed, if needed (refer to the `lib` folder in the backup)."
        ""
        "Once installation is completed, the backup folder is no longer needed and can be deleted."
    ) -join [Environment]::NewLine

    Write-Warning $message

    return
}

#endregion Pre-check

#region Setup

$proxyConfig = if ($IgnoreProxy -or -not $ProxyUrl) {
    @{}
} else {
    $config = @{
        ProxyUrl = $ProxyUrl
    }

    if ($ProxyCredential) {
        $config['ProxyCredential'] = $ProxyCredential
    } elseif ($env:chocolateyProxyUser -and $env:chocolateyProxyPassword) {
        $securePass = ConvertTo-SecureString $env:chocolateyProxyPassword -AsPlainText -Force
        $config['ProxyCredential'] = [System.Management.Automation.PSCredential]::new($env:chocolateyProxyUser, $securePass)
    }

    $config
}

# Attempt to set highest encryption available for SecurityProtocol.
# PowerShell will not set this by default (until maybe .NET 4.6.x). This
# will typically produce a message for PowerShell v2 (just an info
# message though)
try {
    # Set TLS 1.2 (3072) as that is the minimum required by Chocolatey.org.
    # Use integers because the enumeration value for TLS 1.2 won't exist
    # in .NET 4.0, even though they are addressable if .NET 4.5+ is
    # installed (.NET 4.5 is an in-place upgrade).
    Write-Host "Forcing web requests to allow TLS v1.2 (Required for requests to Chocolatey.org)"
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
}
catch {
    $errorMessage = @(
        'Unable to set PowerShell to use TLS 1.2. This is required for contacting Chocolatey as of 03 FEB 2020.'
        'https://blog.chocolatey.org/2020/01/remove-support-for-old-tls-versions/.'
        'If you see underlying connection closed or trust errors, you may need to do one or more of the following:'
        '(1) upgrade to .NET Framework 4.5+ and PowerShell v3+,'
        '(2) Call [System.Net.ServicePointManager]::SecurityProtocol = 3072; in PowerShell prior to attempting installation,'
        '(3) specify internal Chocolatey package location (set $env:chocolateyDownloadUrl prior to install or host the package internally),'
        '(4) use the Download + PowerShell method of install.'
        'See https://docs.chocolatey.org/en-us/choco/setup for all install options.'
    ) -join [Environment]::NewLine
    Write-Warning $errorMessage
}

if ($ChocolateyDownloadUrl) {
    if ($ChocolateyVersion) {
        Write-Warning "Ignoring -ChocolateyVersion parameter ($ChocolateyVersion) because -ChocolateyDownloadUrl is set."
    }

    Write-Host "Downloading Chocolatey from: $ChocolateyDownloadUrl"
} elseif ($ChocolateyVersion) {
    Write-Host "Downloading specific version of Chocolatey: $ChocolateyVersion"
    $ChocolateyDownloadUrl = "https://community.chocolatey.org/api/v2/package/chocolatey/$ChocolateyVersion"
} else {
    Write-Host "Getting latest version of the Chocolatey package for download."
    $queryString = [uri]::EscapeUriString("((Id eq 'chocolatey') and (not IsPrerelease)) and IsLatestVersion")
    $queryUrl = 'https://community.chocolatey.org/api/v2/Packages()?$filter={0}' -f $queryString

    [xml]$result = Request-String -Url $queryUrl -ProxyConfiguration $proxyConfig
    $ChocolateyDownloadUrl = $result.feed.entry.content.src
}

if (-not $env:TEMP) {
    $env:TEMP = Join-Path $env:SystemDrive -ChildPath 'temp'
}

$chocoTempDir = Join-Path $env:TEMP -ChildPath "chocolatey"
$tempDir = Join-Path $chocoTempDir -ChildPath "chocoInstall"

if (-not (Test-Path $tempDir -PathType Container)) {
    $null = New-Item -Path $tempDir -ItemType Directory
}

#endregion Setup

#region Download & Extract Chocolatey

$file = Join-Path $tempDir "chocolatey.zip"

# If we are passed a valid local path, we do not need to download it.
if (Test-Path $ChocolateyDownloadUrl) {
    Write-Host "Using Chocolatey from $ChocolateyDownloadUrl."
    Copy-Item -Path $ChocolateyDownloadUrl -Destination $file
} else {
    Write-Host "Getting Chocolatey from $ChocolateyDownloadUrl."
    Request-File -Url $ChocolateyDownloadUrl -File $file -ProxyConfiguration $proxyConfig
}

Write-Host "Extracting $file to $tempDir"
if ($PSVersionTable.PSVersion.Major -lt 5) {
    # Determine unzipping method
    # 7zip is the most compatible pre-PSv5.1 so use it unless asked to use builtin
    if ($UseNativeUnzip) {
        Write-Host 'Using built-in compression to unzip'

        try {
            $shellApplication = New-Object -ComObject Shell.Application
            $zipPackage = $shellApplication.NameSpace($file)
            $destinationFolder = $shellApplication.NameSpace($tempDir)
            $destinationFolder.CopyHere($zipPackage.Items(), 0x10)
        } catch {
            Write-Warning "Unable to unzip package using built-in compression. Set `$env:chocolateyUseWindowsCompression = ''` or omit -UseNativeUnzip and retry to use 7zip to unzip."
            throw $_
        }
    } else {
        $7zaExe = Join-Path $tempDir -ChildPath '7za.exe'
        Install-7zip -Path $7zaExe -ProxyConfiguration $proxyConfig

        $params = 'x -o"{0}" -bd -y "{1}"' -f $tempDir, $file

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
} else {
    Microsoft.PowerShell.Archive\Expand-Archive -Path $file -DestinationPath $tempDir -Force
}

#endregion Download & Extract Chocolatey

#region Install Chocolatey

Write-Host "Installing Chocolatey on the local machine"
$toolsFolder = Join-Path $tempDir -ChildPath "tools"
$chocoInstallPS1 = Join-Path $toolsFolder -ChildPath "chocolateyInstall.ps1"

& $chocoInstallPS1

Write-Host 'Ensuring Chocolatey commands are on the path'
$chocoInstallVariableName = "ChocolateyInstall"
$chocoPath = [Environment]::GetEnvironmentVariable($chocoInstallVariableName)

if (-not $chocoPath) {
    $chocoPath = "$env:ALLUSERSPROFILE\Chocolatey"
}

if (-not (Test-Path ($chocoPath))) {
    $chocoPath = "$env:PROGRAMDATA\chocolatey"
}

$chocoExePath = Join-Path $chocoPath -ChildPath 'bin'

# Update current process PATH environment variable if it needs updating.
if ($env:Path -notlike "*$chocoExePath*") {
    $env:Path = [Environment]::GetEnvironmentVariable('Path', [System.EnvironmentVariableTarget]::Machine);
}

Write-Host 'Ensuring chocolatey.nupkg is in the lib folder'
$chocoPkgDir = Join-Path $chocoPath -ChildPath 'lib\chocolatey'
$nupkg = Join-Path $chocoPkgDir -ChildPath 'chocolatey.nupkg'

if (-not (Test-Path $chocoPkgDir -PathType Container)) {
    $null = New-Item -ItemType Directory -Path $chocoPkgDir
}

Copy-Item -Path $file -Destination $nupkg -Force -ErrorAction SilentlyContinue

#endregion Install Chocolatey

# SIG # Begin signature block
# MIIjXAYJKoZIhvcNAQcCoIIjTTCCI0kCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUU0WFbPDdyIKnze57eTEA8Wsc
# tTGggh16MIIFMDCCBBigAwIBAgIQBAkYG1/Vu2Z1U0O1b5VQCDANBgkqhkiG9w0B
# AQsFADBlMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYD
# VQQLExB3d3cuZGlnaWNlcnQuY29tMSQwIgYDVQQDExtEaWdpQ2VydCBBc3N1cmVk
# IElEIFJvb3QgQ0EwHhcNMTMxMDIyMTIwMDAwWhcNMjgxMDIyMTIwMDAwWjByMQsw
# CQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cu
# ZGlnaWNlcnQuY29tMTEwLwYDVQQDEyhEaWdpQ2VydCBTSEEyIEFzc3VyZWQgSUQg
# Q29kZSBTaWduaW5nIENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
# +NOzHH8OEa9ndwfTCzFJGc/Q+0WZsTrbRPV/5aid2zLXcep2nQUut4/6kkPApfmJ
# 1DcZ17aq8JyGpdglrA55KDp+6dFn08b7KSfH03sjlOSRI5aQd4L5oYQjZhJUM1B0
# sSgmuyRpwsJS8hRniolF1C2ho+mILCCVrhxKhwjfDPXiTWAYvqrEsq5wMWYzcT6s
# cKKrzn/pfMuSoeU7MRzP6vIK5Fe7SrXpdOYr/mzLfnQ5Ng2Q7+S1TqSp6moKq4Tz
# rGdOtcT3jNEgJSPrCGQ+UpbB8g8S9MWOD8Gi6CxR93O8vYWxYoNzQYIH5DiLanMg
# 0A9kczyen6Yzqf0Z3yWT0QIDAQABo4IBzTCCAckwEgYDVR0TAQH/BAgwBgEB/wIB
# ADAOBgNVHQ8BAf8EBAMCAYYwEwYDVR0lBAwwCgYIKwYBBQUHAwMweQYIKwYBBQUH
# AQEEbTBrMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wQwYI
# KwYBBQUHMAKGN2h0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFz
# c3VyZWRJRFJvb3RDQS5jcnQwgYEGA1UdHwR6MHgwOqA4oDaGNGh0dHA6Ly9jcmw0
# LmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcmwwOqA4oDaG
# NGh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RD
# QS5jcmwwTwYDVR0gBEgwRjA4BgpghkgBhv1sAAIEMCowKAYIKwYBBQUHAgEWHGh0
# dHBzOi8vd3d3LmRpZ2ljZXJ0LmNvbS9DUFMwCgYIYIZIAYb9bAMwHQYDVR0OBBYE
# FFrEuXsqCqOl6nEDwGD5LfZldQ5YMB8GA1UdIwQYMBaAFEXroq/0ksuCMS1Ri6en
# IZ3zbcgPMA0GCSqGSIb3DQEBCwUAA4IBAQA+7A1aJLPzItEVyCx8JSl2qB1dHC06
# GsTvMGHXfgtg/cM9D8Svi/3vKt8gVTew4fbRknUPUbRupY5a4l4kgU4QpO4/cY5j
# DhNLrddfRHnzNhQGivecRk5c/5CxGwcOkRX7uq+1UcKNJK4kxscnKqEpKBo6cSgC
# PC6Ro8AlEeKcFEehemhor5unXCBc2XGxDI+7qPjFEmifz0DLQESlE/DmZAwlCEIy
# sjaKJAL+L3J+HNdJRZboWR3p+nRka7LrZkPas7CM1ekN3fYBIM6ZMWM9CBoYs4Gb
# T8aTEAb8B4H6i9r5gkn3Ym6hU/oSlBiFLpKR6mhsRDKyZqHnGKSaZFHvMIIFOTCC
# BCGgAwIBAgIQCrnTEPshK+iMgbPSwujOUTANBgkqhkiG9w0BAQsFADByMQswCQYD
# VQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGln
# aWNlcnQuY29tMTEwLwYDVQQDEyhEaWdpQ2VydCBTSEEyIEFzc3VyZWQgSUQgQ29k
# ZSBTaWduaW5nIENBMB4XDTIxMDQyNzAwMDAwMFoXDTI0MDQzMDIzNTk1OVowdzEL
# MAkGA1UEBhMCVVMxDzANBgNVBAgTBkthbnNhczEPMA0GA1UEBxMGVG9wZWthMSIw
# IAYDVQQKExlDaG9jb2xhdGV5IFNvZnR3YXJlLCBJbmMuMSIwIAYDVQQDExlDaG9j
# b2xhdGV5IFNvZnR3YXJlLCBJbmMuMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
# CgKCAQEAoXGnjanjtzt4c2w2GDHMb7/0DUjxOH6SPjRhAkfhWHQztrrV/f0j8UQs
# 1ga7IJ7T7P+yD5P7hWZP8kyIjaFzvnKiROOS/di3X5+oAHMIxp2v49n/220hUnl1
# vc/ZTNwyXnBcF0JXlkf/Digpw/ndWZhwdAQOb9G0An1PGU+0tLvfigCqsqoGayck
# Ij3wVal3rPUUrmu/tElV5mgayX/Z4xwH+SjRWP0xIJta9c2MMX3LLhOXmHa9v7Ls
# rVCaTdfJvQ5gHWJu9r2tCjMaCiARrkMvQ52gyPpzInoLHYZC/bCMrCIp+z3MI5MM
# fZUZrSKiQNux34G9TGi9Dp5KcEWPlQIDAQABo4IBxDCCAcAwHwYDVR0jBBgwFoAU
# WsS5eyoKo6XqcQPAYPkt9mV1DlgwHQYDVR0OBBYEFE7zBRhdlespUGpRbfmn0V40
# mgSDMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzB3BgNVHR8E
# cDBuMDWgM6Axhi9odHRwOi8vY3JsMy5kaWdpY2VydC5jb20vc2hhMi1hc3N1cmVk
# LWNzLWcxLmNybDA1oDOgMYYvaHR0cDovL2NybDQuZGlnaWNlcnQuY29tL3NoYTIt
# YXNzdXJlZC1jcy1nMS5jcmwwSwYDVR0gBEQwQjA2BglghkgBhv1sAwEwKTAnBggr
# BgEFBQcCARYbaHR0cDovL3d3dy5kaWdpY2VydC5jb20vQ1BTMAgGBmeBDAEEATCB
# hAYIKwYBBQUHAQEEeDB2MCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2Vy
# dC5jb20wTgYIKwYBBQUHMAKGQmh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9E
# aWdpQ2VydFNIQTJBc3N1cmVkSURDb2RlU2lnbmluZ0NBLmNydDAMBgNVHRMBAf8E
# AjAAMA0GCSqGSIb3DQEBCwUAA4IBAQChcZ3BwMwxXrFCV2jNtajEZOfpyGXA7iEn
# xoCXA4zB7ES8O52uWJ+yIYjWPjrCpz1ZHz4S/zDV0hxuqJ/iKcYgdvwa8vbYair6
# UHTwXvJhTdHLSQ4K0nHskQuUgPRIjttid2DXtMlRCgBvmJNgP1oSgcwgqUbJDJUa
# +yni5ug7wILw7DH5CrXjzJdj62jjfrRTaXNm9S0yk+KJIlObgFqY2ALfbGAbCk3m
# W+TSbdGUN2pBBCAELOt/5kgwGZczDiTFjSv8r+DVOQoj1XKISdFo1CVCKwDJgFZW
# dofDYQlyTr9vHB1hID5LP86nQ3SISXwxfgC3ddCUwa8AjXGEBuvAMIIFjTCCBHWg
# AwIBAgIQDpsYjvnQLefv21DiCEAYWjANBgkqhkiG9w0BAQwFADBlMQswCQYDVQQG
# EwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNl
# cnQuY29tMSQwIgYDVQQDExtEaWdpQ2VydCBBc3N1cmVkIElEIFJvb3QgQ0EwHhcN
# MjIwODAxMDAwMDAwWhcNMzExMTA5MjM1OTU5WjBiMQswCQYDVQQGEwJVUzEVMBMG
# A1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSEw
# HwYDVQQDExhEaWdpQ2VydCBUcnVzdGVkIFJvb3QgRzQwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQC/5pBzaN675F1KPDAiMGkz7MKnJS7JIT3yithZwuEp
# pz1Yq3aaza57G4QNxDAf8xukOBbrVsaXbR2rsnnyyhHS5F/WBTxSD1Ifxp4VpX6+
# n6lXFllVcq9ok3DCsrp1mWpzMpTREEQQLt+C8weE5nQ7bXHiLQwb7iDVySAdYykt
# zuxeTsiT+CFhmzTrBcZe7FsavOvJz82sNEBfsXpm7nfISKhmV1efVFiODCu3T6cw
# 2Vbuyntd463JT17lNecxy9qTXtyOj4DatpGYQJB5w3jHtrHEtWoYOAMQjdjUN6Qu
# BX2I9YI+EJFwq1WCQTLX2wRzKm6RAXwhTNS8rhsDdV14Ztk6MUSaM0C/CNdaSaTC
# 5qmgZ92kJ7yhTzm1EVgX9yRcRo9k98FpiHaYdj1ZXUJ2h4mXaXpI8OCiEhtmmnTK
# 3kse5w5jrubU75KSOp493ADkRSWJtppEGSt+wJS00mFt6zPZxd9LBADMfRyVw4/3
# IbKyEbe7f/LVjHAsQWCqsWMYRJUadmJ+9oCw++hkpjPRiQfhvbfmQ6QYuKZ3AeEP
# lAwhHbJUKSWJbOUOUlFHdL4mrLZBdd56rF+NP8m800ERElvlEFDrMcXKchYiCd98
# THU/Y+whX8QgUWtvsauGi0/C1kVfnSD8oR7FwI+isX4KJpn15GkvmB0t9dmpsh3l
# GwIDAQABo4IBOjCCATYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQU7NfjgtJx
# XWRM3y5nP+e6mK4cD08wHwYDVR0jBBgwFoAUReuir/SSy4IxLVGLp6chnfNtyA8w
# DgYDVR0PAQH/BAQDAgGGMHkGCCsGAQUFBwEBBG0wazAkBggrBgEFBQcwAYYYaHR0
# cDovL29jc3AuZGlnaWNlcnQuY29tMEMGCCsGAQUFBzAChjdodHRwOi8vY2FjZXJ0
# cy5kaWdpY2VydC5jb20vRGlnaUNlcnRBc3N1cmVkSURSb290Q0EuY3J0MEUGA1Ud
# HwQ+MDwwOqA4oDaGNGh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFz
# c3VyZWRJRFJvb3RDQS5jcmwwEQYDVR0gBAowCDAGBgRVHSAAMA0GCSqGSIb3DQEB
# DAUAA4IBAQBwoL9DXFXnOF+go3QbPbYW1/e/Vwe9mqyhhyzshV6pGrsi+IcaaVQi
# 7aSId229GhT0E0p6Ly23OO/0/4C5+KH38nLeJLxSA8hO0Cre+i1Wz/n096wwepqL
# sl7Uz9FDRJtDIeuWcqFItJnLnU+nBgMTdydE1Od/6Fmo8L8vC6bp8jQ87PcDx4eo
# 0kxAGTVGamlUsLihVo7spNU96LHc/RzY9HdaXFSMb++hUD38dglohJ9vytsgjTVg
# HAIDyyCwrFigDkBjxZgiwbJZ9VVrzyerbHbObyMt9H5xaiNrIv8SuFQtJ37YOtnw
# toeW/VvRXKwYw02fc7cBqZ9Xql4o4rmUMIIGrjCCBJagAwIBAgIQBzY3tyRUfNhH
# rP0oZipeWzANBgkqhkiG9w0BAQsFADBiMQswCQYDVQQGEwJVUzEVMBMGA1UEChMM
# RGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSEwHwYDVQQD
# ExhEaWdpQ2VydCBUcnVzdGVkIFJvb3QgRzQwHhcNMjIwMzIzMDAwMDAwWhcNMzcw
# MzIyMjM1OTU5WjBjMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIElu
# Yy4xOzA5BgNVBAMTMkRpZ2lDZXJ0IFRydXN0ZWQgRzQgUlNBNDA5NiBTSEEyNTYg
# VGltZVN0YW1waW5nIENBMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA
# xoY1BkmzwT1ySVFVxyUDxPKRN6mXUaHW0oPRnkyibaCwzIP5WvYRoUQVQl+kiPNo
# +n3znIkLf50fng8zH1ATCyZzlm34V6gCff1DtITaEfFzsbPuK4CEiiIY3+vaPcQX
# f6sZKz5C3GeO6lE98NZW1OcoLevTsbV15x8GZY2UKdPZ7Gnf2ZCHRgB720RBidx8
# ald68Dd5n12sy+iEZLRS8nZH92GDGd1ftFQLIWhuNyG7QKxfst5Kfc71ORJn7w6l
# Y2zkpsUdzTYNXNXmG6jBZHRAp8ByxbpOH7G1WE15/tePc5OsLDnipUjW8LAxE6lX
# KZYnLvWHpo9OdhVVJnCYJn+gGkcgQ+NDY4B7dW4nJZCYOjgRs/b2nuY7W+yB3iIU
# 2YIqx5K/oN7jPqJz+ucfWmyU8lKVEStYdEAoq3NDzt9KoRxrOMUp88qqlnNCaJ+2
# RrOdOqPVA+C/8KI8ykLcGEh/FDTP0kyr75s9/g64ZCr6dSgkQe1CvwWcZklSUPRR
# 8zZJTYsg0ixXNXkrqPNFYLwjjVj33GHek/45wPmyMKVM1+mYSlg+0wOI/rOP015L
# dhJRk8mMDDtbiiKowSYI+RQQEgN9XyO7ZONj4KbhPvbCdLI/Hgl27KtdRnXiYKNY
# CQEoAA6EVO7O6V3IXjASvUaetdN2udIOa5kM0jO0zbECAwEAAaOCAV0wggFZMBIG
# A1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFLoW2W1NhS9zKXaaL3WMaiCPnshv
# MB8GA1UdIwQYMBaAFOzX44LScV1kTN8uZz/nupiuHA9PMA4GA1UdDwEB/wQEAwIB
# hjATBgNVHSUEDDAKBggrBgEFBQcDCDB3BggrBgEFBQcBAQRrMGkwJAYIKwYBBQUH
# MAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBBBggrBgEFBQcwAoY1aHR0cDov
# L2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5jcnQw
# QwYDVR0fBDwwOjA4oDagNIYyaHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lD
# ZXJ0VHJ1c3RlZFJvb3RHNC5jcmwwIAYDVR0gBBkwFzAIBgZngQwBBAIwCwYJYIZI
# AYb9bAcBMA0GCSqGSIb3DQEBCwUAA4ICAQB9WY7Ak7ZvmKlEIgF+ZtbYIULhsBgu
# EE0TzzBTzr8Y+8dQXeJLKftwig2qKWn8acHPHQfpPmDI2AvlXFvXbYf6hCAlNDFn
# zbYSlm/EUExiHQwIgqgWvalWzxVzjQEiJc6VaT9Hd/tydBTX/6tPiix6q4XNQ1/t
# YLaqT5Fmniye4Iqs5f2MvGQmh2ySvZ180HAKfO+ovHVPulr3qRCyXen/KFSJ8NWK
# cXZl2szwcqMj+sAngkSumScbqyQeJsG33irr9p6xeZmBo1aGqwpFyd/EjaDnmPv7
# pp1yr8THwcFqcdnGE4AJxLafzYeHJLtPo0m5d2aR8XKc6UsCUqc3fpNTrDsdCEkP
# lM05et3/JWOZJyw9P2un8WbDQc1PtkCbISFA0LcTJM3cHXg65J6t5TRxktcma+Q4
# c6umAU+9Pzt4rUyt+8SVe+0KXzM5h0F4ejjpnOHdI/0dKNPH+ejxmF/7K9h+8kad
# dSweJywm228Vex4Ziza4k9Tm8heZWcpw8De/mADfIBZPJ/tgZxahZrrdVcA6KYaw
# mKAr7ZVBtzrVFZgxtGIJDwq9gdkT/r+k0fNX2bwE+oLeMt8EifAAzV3C+dAjfwAL
# 5HYCJtnwZXZCpimHCUcr5n8apIUP/JiW9lVUKx+A+sDyDivl1vupL0QVSucTDh3b
# NzgaoSv27dZ8/DCCBsIwggSqoAMCAQICEAVEr/OUnQg5pr/bP1/lYRYwDQYJKoZI
# hvcNAQELBQAwYzELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMu
# MTswOQYDVQQDEzJEaWdpQ2VydCBUcnVzdGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRp
# bWVTdGFtcGluZyBDQTAeFw0yMzA3MTQwMDAwMDBaFw0zNDEwMTMyMzU5NTlaMEgx
# CzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjEgMB4GA1UEAxMX
# RGlnaUNlcnQgVGltZXN0YW1wIDIwMjMwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAw
# ggIKAoICAQCjU0WHHYOOW6w+VLMj4M+f1+XS512hDgncL0ijl3o7Kpxn3GIVWMGp
# kxGnzaqyat0QKYoeYmNp01icNXG/OpfrlFCPHCDqx5o7L5Zm42nnaf5bw9YrIBzB
# l5S0pVCB8s/LB6YwaMqDQtr8fwkklKSCGtpqutg7yl3eGRiF+0XqDWFsnf5xXsQG
# mjzwxS55DxtmUuPI1j5f2kPThPXQx/ZILV5FdZZ1/t0QoRuDwbjmUpW1R9d4KTlr
# 4HhZl+NEK0rVlc7vCBfqgmRN/yPjyobutKQhZHDr1eWg2mOzLukF7qr2JPUdvJsc
# srdf3/Dudn0xmWVHVZ1KJC+sK5e+n+T9e3M+Mu5SNPvUu+vUoCw0m+PebmQZBzcB
# kQ8ctVHNqkxmg4hoYru8QRt4GW3k2Q/gWEH72LEs4VGvtK0VBhTqYggT02kefGRN
# nQ/fztFejKqrUBXJs8q818Q7aESjpTtC/XN97t0K/3k0EH6mXApYTAA+hWl1x4Nk
# 1nXNjxJ2VqUk+tfEayG66B80mC866msBsPf7Kobse1I4qZgJoXGybHGvPrhvltXh
# EBP+YUcKjP7wtsfVx95sJPC/QoLKoHE9nJKTBLRpcCcNT7e1NtHJXwikcKPsCvER
# LmTgyyIryvEoEyFJUX4GZtM7vvrrkTjYUQfKlLfiUKHzOtOKg8tAewIDAQABo4IB
# izCCAYcwDgYDVR0PAQH/BAQDAgeAMAwGA1UdEwEB/wQCMAAwFgYDVR0lAQH/BAww
# CgYIKwYBBQUHAwgwIAYDVR0gBBkwFzAIBgZngQwBBAIwCwYJYIZIAYb9bAcBMB8G
# A1UdIwQYMBaAFLoW2W1NhS9zKXaaL3WMaiCPnshvMB0GA1UdDgQWBBSltu8T5+/N
# 0GSh1VapZTGj3tXjSTBaBgNVHR8EUzBRME+gTaBLhklodHRwOi8vY3JsMy5kaWdp
# Y2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRSU0E0MDk2U0hBMjU2VGltZVN0YW1w
# aW5nQ0EuY3JsMIGQBggrBgEFBQcBAQSBgzCBgDAkBggrBgEFBQcwAYYYaHR0cDov
# L29jc3AuZGlnaWNlcnQuY29tMFgGCCsGAQUFBzAChkxodHRwOi8vY2FjZXJ0cy5k
# aWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRSU0E0MDk2U0hBMjU2VGltZVN0
# YW1waW5nQ0EuY3J0MA0GCSqGSIb3DQEBCwUAA4ICAQCBGtbeoKm1mBe8cI1Pijxo
# nNgl/8ss5M3qXSKS7IwiAqm4z4Co2efjxe0mgopxLxjdTrbebNfhYJwr7e09SI64
# a7p8Xb3CYTdoSXej65CqEtcnhfOOHpLawkA4n13IoC4leCWdKgV6hCmYtld5j9sm
# Viuw86e9NwzYmHZPVrlSwradOKmB521BXIxp0bkrxMZ7z5z6eOKTGnaiaXXTUORE
# Er4gDZ6pRND45Ul3CFohxbTPmJUaVLq5vMFpGbrPFvKDNzRusEEm3d5al08zjdSN
# d311RaGlWCZqA0Xe2VC1UIyvVr1MxeFGxSjTredDAHDezJieGYkD6tSRN+9NUvPJ
# YCHEVkft2hFLjDLDiOZY4rbbPvlfsELWj+MXkdGqwFXjhr+sJyxB0JozSqg21Lly
# ln6XeThIX8rC3D0y33XWNmdaifj2p8flTzU8AL2+nCpseQHc2kTmOt44OwdeOVj0
# fHMxVaCAEcsUDH6uvP6k63llqmjWIso765qCNVcoFstp8jKastLYOrixRoZruhf9
# xHdsFWyuq69zOuhJRrfVf8y2OMDY7Bz1tqG4QyzfTkx9HmhwwHcK1ALgXGC7KP84
# 5VJa1qwXIiNO9OzTF/tQa/8Hdx9xl0RBybhG02wyfFgvZ0dl5Rtztpn5aywGRu9B
# HvDwX+Db2a2QgESvgBBBijGCBUwwggVIAgEBMIGGMHIxCzAJBgNVBAYTAlVTMRUw
# EwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20x
# MTAvBgNVBAMTKERpZ2lDZXJ0IFNIQTIgQXNzdXJlZCBJRCBDb2RlIFNpZ25pbmcg
# Q0ECEAq50xD7ISvojIGz0sLozlEwCQYFKw4DAhoFAKB4MBgGCisGAQQBgjcCAQwx
# CjAIoAKAAKECgAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGC
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFGYF67I0NrrUI82E
# 885xdmBa19f6MA0GCSqGSIb3DQEBAQUABIIBAJMXxr5bUcJ5eXeaHVGN7+PfC1l/
# MfoKvvupnz6ImQDoxIcwDF4o/KQEhhKXW0L4bC5+cKAon75SGk4ZaPJN8NAGK/lf
# Qb0arztv2kqtSEGYeJNgLymz1+bVwxf0mvIwHQZnoV5yT37sXCtLta3uzad75jkA
# R2g5M6Hl2hZ0A5TJ/o57I058snkorGGWi90shPucdvpUc5+bQazzLzmvpkeyxzMF
# r6XTHBrCa8FvaBTKFQKYl0029jGz62+9gNa93yPxQw1PTG0zBgIuQEXT3pY1gtfI
# tUgbQlUnENMST0k7A7LrvWFWY7Jfufqx1PiRQONa/twRj8Ac3VG38eQ+N4ShggMg
# MIIDHAYJKoZIhvcNAQkGMYIDDTCCAwkCAQEwdzBjMQswCQYDVQQGEwJVUzEXMBUG
# A1UEChMORGlnaUNlcnQsIEluYy4xOzA5BgNVBAMTMkRpZ2lDZXJ0IFRydXN0ZWQg
# RzQgUlNBNDA5NiBTSEEyNTYgVGltZVN0YW1waW5nIENBAhAFRK/zlJ0IOaa/2z9f
# 5WEWMA0GCWCGSAFlAwQCAQUAoGkwGAYJKoZIhvcNAQkDMQsGCSqGSIb3DQEHATAc
# BgkqhkiG9w0BCQUxDxcNMjMxMDAzMTk0MTAzWjAvBgkqhkiG9w0BCQQxIgQgnHdX
# DH7jG2CeWKZcKDxLf1Y5ltxMBycSBnNN7DflvvowDQYJKoZIhvcNAQEBBQAEggIA
# AmPagHQy5u/uA2Xar36F36rrHGc1isBvJQegSkFdo5CmST4cl1czO+qXdlcWf8TL
# t0XY2tT+c7B4G3D6Da97KcYdKvCSYjeA/HsmJ0RRCrw6MVopCP/3dsi5SCszdRV8
# P9MAWIr33N/voc9e5/lDi82ZwB76VTZjDkw6ph6LVXLeS1VeQdaqkqZP71yKOuXx
# gEsLjxHHwKM7BrimKxr3azsr3j+kaiN0HS307g9cMyrujUYE/n2hyFXcUAzBVbXA
# PiKOXtfA9YYDoHguIUHFk2VuS2KGGC4ZONHFcjIlGCZWZTxIX67m7QIF0006Z/pw
# OK3fj6c5DYWLDxnJaa8dCO5LA/Cn87eHVStK0uRFHTKx0M2yIItJDJj7PNnSAkVQ
# UKO9pH9zyeYeYLOyq2LVi5KeBrT6pLz9xGimZBwsLVzW7IKCQtEVIns7NMGExA1q
# fkQTx1VWvwOzrMHFGScTtVAmHfOt292kOy4/daQxl2wPDkfzbB8ZEO4S6lUtSyE2
# mjAKLB8TEkZzbJu1xvOp3LGPThWuxzg+SpfHKw5PmatWHRWcYJApBGav+Iaf2G8r
# dmcBYp+7VcCohKvJUjDeoMfrt7+mVUZ55eiw4A4gmC9mJ/5aXieGe912nYfoOrb/
# RLv21y0pKrqx4bdbfD1Zh3jaFtEJYlzxcBWgfBfCmJM=
# SIG # End signature block
