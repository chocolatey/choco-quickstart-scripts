<#
    .Synopsis
        Prepares the repository for an offline deployment.

    .Description
        These scripts can be run from a network without access to the internet,
        but it needs to prepare packages to be run offline.
        This script downloads and internalizes packages for such usage.

    .Notes
        This must be run on a Windows system with access to the internet because 
        it uses Chocolatey for Business' Package Internalizer.

    .Notes
        Instead of using this script, you can internalize all required packages manually, 
        zip them, and drop them in the files directory as shown below.

    .Example
        .\OfflineInstallPreparation.ps1 -LicensePath C:\ProgramData\chocolatey\license\chocolatey.license.xml
#>
[CmdletBinding()]
param(
    [ValidateScript({
        if (-not (Test-Path (Convert-Path $_))) {
            throw "License file does not exist at '$($_)'. Please provide a valid -LicensePath"
        }
        try {
            [xml]$License = Get-Content $_
            $Expiry = Get-Date $License.license.expiration
            if (-not $Expiry -or $Expiry -lt (Get-Date)) {throw}
        } catch {
            throw "License '$($_)' is not valid.$(if ($Expiry) {" It expired at '$($Expiry)'."})"
        }
        $true
    })]
    [string]$LicensePath = $(
        if (Test-Path $PSScriptRoot\files\chocolatey.license.xml) {
            # Offline setup has been run, we should use that license.
            Join-Path $PSScriptRoot "files\chocolatey.license.xml"
        } elseif (Test-Path $env:ChocolateyInstall\license\chocolatey.license.xml) {
            # Chocolatey is already installed, we can use that license.
            Join-Path $env:ChocolateyInstall "license\chocolatey.license.xml"
        } else {
            # Prompt the user for the license.
            $Wshell = New-Object -ComObject Wscript.Shell
            $null = $Wshell.Popup('You will need to provide the license file location. Please select your Chocolatey License in the next file dialog.')
            $null = [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms")
            $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
            $OpenFileDialog.initialDirectory = "$env:USERPROFILE\Downloads"
            $OpenFileDialog.filter = 'All Files (*.*)| *.*'
            $null = $OpenFileDialog.ShowDialog()

            $OpenFileDialog.filename
        }
    ),

    [string]$WorkingDirectory = $(Join-Path $env:Temp "choco-offline")
)
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$LicensePath = Convert-Path $LicensePath

$ChocoInstallScript = Join-Path $PSScriptRoot "scripts\ChocolateyInstall.ps1"
if (-not (Test-Path $ChocoInstallScript)) {
    Invoke-WebRequest -Uri 'https://chocolatey.org/install.ps1' -OutFile $ChocoInstallScript
}

$Signature = Get-AuthenticodeSignature -FilePath $ChocoInstallScript

if ($Signature.Status -eq 'Valid' -and $Signature.SignerCertificate.Subject -eq 'CN="Chocolatey Software, Inc", O="Chocolatey Software, Inc", L=Topeka, S=Kansas, C=US') {
    if (-not (Get-Command choco.exe -ErrorAction SilentlyContinue)) {
        if (Test-Path $PSScriptRoot\files\chocolatey.*.nupkg) {
            $env:ChocolateyDownloadUrl = (Convert-Path $PSScriptRoot\files\chocolatey.*.nupkg)[0]
        }
        & $ChocoInstallScript
    }
} else {
    Write-Error "ChocolateyInstall.ps1 script signature is not valid. Please investigate." -ErrorAction Stop
}

Import-Module $PSScriptRoot\modules\C4B-Environment -Force

# Initialize environment, ensure Chocolatey For Business, etc.
$Licensed = ($($(choco.exe)[0] -match "^Chocolatey (?<Version>\S+)\s*(?<LicenseType>Business)?$") -and $Matches.LicenseType)
$InstalledLicensePath = "$env:ChocolateyInstall\license\chocolatey.license.xml"
if (-not $Licensed) {
    if (-not (Test-Path $InstalledLicensePath)) {
        if (-not (Test-Path $env:ChocolateyInstall\license)) {
            $null = New-Item $env:ChocolateyInstall\license -ItemType Directory
        }
        Copy-Item $LicensePath $InstalledLicensePath -Force
    }
    $ExtensionSource = if (Test-Path $PSScriptRoot\files\chocolatey.extension.*.nupkg) {
        Convert-Path $PSScriptRoot\files\
    } else {
        'https://licensedpackages.chocolatey.org/api/v2/'
    }
    Invoke-Choco install chocolatey.extension --source $ExtensionSource --params="'/NoContextMenu'" --confirm
}

# Download each set of packages to the output directories
$PackageWorkingDirectory = Join-Path $WorkingDirectory "Packages"
if (-not (Test-Path $PackageWorkingDirectory)) {
    $null = New-Item -Path $PackageWorkingDirectory -ItemType Directory -Force
}
foreach ($Package in (Get-Content $PSScriptRoot\files\chocolatey.json | ConvertFrom-Json).packages) {
    $ChocoArgs = @(
        "download", "$($Package.Name)"
        "--output-directory", $PackageWorkingDirectory
        "--ignore-dependencies"
        "--no-progress"
    )
    $ChocoArgs += switch ($Package.psobject.properties.name) {
        "Version" { "--version=$($Package.Version)" }
        "Args" { $Package.Args }
    }
    if ($Package.Internalize -or $Package.PSObject.Properties.Name -notcontains "Internalize") {
        $ChocoArgs += "--internalize"  # Default to internalizing
    }

    try {
        if (-not (Get-ChocolateyPackageMetadata -Path $PackageWorkingDirectory -Id $Package.Name) -and -not (Get-ChocolateyPackageMetadata -Path "$PSScriptRoot\files\" -Id $Package.Name)) {
            Write-Host "Downloading '$($Package.Name)'"

            while ((Get-ChildItem $PackageWorkingDirectory -Filter *.nupkg).Where{$_.CreationTime -gt (Get-Date).AddMinutes(-1)}.Count -gt 5) {
                Write-Verbose "Slowing down for a minute, in order to not trigger rate-limiting..."
                Start-Sleep -Seconds 5
            }

            Invoke-Choco @ChocoArgs
        }
    } catch {
        throw $_
    }
}
Move-Item -Path $PackageWorkingDirectory\*.nupkg -Destination $PSScriptRoot\files\

# Jenkins Plugins
$PluginsWorkingDirectory = Join-Path $WorkingDirectory "JenkinsPlugins"
if (-not (Test-Path $PluginsWorkingDirectory)) {
    $null = New-Item -Path $PluginsWorkingDirectory -ItemType Directory -Force
}
if (Test-Path $PSScriptRoot\files\JenkinsPlugins.zip) {
    Expand-Archive -Path $PSScriptRoot\files\JenkinsPlugins.zip -DestinationPath $PluginsWorkingDirectory -Force
}
$ProgressPreference = "Ignore"
foreach ($Plugin in (Get-Content $PSScriptRoot\files\jenkins.json | ConvertFrom-Json).plugins) {
    $RestArgs = @{
        Uri     = "https://updates.jenkins-ci.org/latest/$($Plugin.Name).hpi"
        OutFile = Join-Path $PluginsWorkingDirectory "$($Plugin.Name).hpi"
    }
    if ($Plugin.Version -and $Plugin.Version -ne 'latest') {
        $RestArgs.Uri = "https://updates.jenkins-ci.org/download/plugins/$($Plugin.Name)/$($Plugin.Version)/$($Plugin.Name).hpi"
    }
    if (-not (Test-Path $RestArgs.OutFile)) {
        Invoke-WebRequest @RestArgs -UseBasicParsing
    }
}
Compress-Archive -Path $PluginsWorkingDirectory\* -Destination $PSScriptRoot\files\JenkinsPlugins.zip -Force

# BCryptDll
$null = Get-BcryptDll

# License
if ($LicensePath -ne "$PSScriptRoot\files\chocolatey.license.xml") {
    Copy-Item -Path (Convert-Path $LicensePath) -Destination $PSScriptRoot\files\chocolatey.license.xml
}