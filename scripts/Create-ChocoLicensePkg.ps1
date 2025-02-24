<#
.SYNOPSIS
Creates a Chocolatey package which can be used to deploy the license XML file to
client machines.

.DESCRIPTION
Finds the license file at the specified location (in your Chocolatey install
folder by default) and creates a simple package around it. The resulting package
is pushed to the ChocolateyInternal Nexus repository by default.
#>
[CmdletBinding()]
param(
    # Local path used to build the license package.
    [Parameter()]
    [string]
    $PackagesPath = "$env:SystemDrive\choco-setup\files\files",

    # Path to the license file.
    [Parameter()]
    [string]
    $LicensePath = "$env:ChocolateyInstall\license\chocolatey.license.xml",

    # The package ID of the generated license package.
    [Parameter()]
    [string]
    $LicensePackageId = "chocolatey-license",

    # The version of the license package to push. If not set, the license
    # package version is automatically generated from the expiry date in the
    # license file.
    [Parameter()]
    [string]
    $LicensePackageVersion
)

if (-not (Test-Path $LicensePath)) {
    if ($PSBoundParameters.ContainsKey('LicensePath')) {
        throw "License file '$LicensePath' not found. Please supply a path to an existing license file."
    }

    throw "License file not found at '$LicensePath'. Please add license to this location before running this script, or supply a -LicensePath value manually."
}

$PackagingFolder = "$env:SystemDrive\choco-setup\packaging"
$licensePackageFolder = "$PackagingFolder\$LicensePackageId"
$licensePackageNuspec = "$licensePackageFolder\$LicensePackageId.nuspec"

# Get license expiration date and node count
[xml]$licenseXml = Get-Content -Path $LicensePath
$licenseExpiration = [datetimeoffset]::Parse("$($licenseXml.SelectSingleNode('/license').expiration) +0")
$null = $licenseXml.license.name -match "(?<=\[).*(?=\])"
$licenseNodeCount = $Matches.Values -replace '\s[A-Za-z]+',''

if ($licenseExpiration -lt [datetimeoffset]::UtcNow) {
    Write-Warning "THE LICENSE FILE AT '$LicensePath' is EXPIRED. This is the file used by this script to generate this package, not at '$licensePackageFolder'"
    Write-Warning "Please update the license file correctly in the environment FIRST, then rerun this script."
    throw "License is expired as of $($licenseExpiration.ToString()). Please use an up to date license."
}

if (-not $LicensePackageVersion) {
    $LicensePackageVersion = ($licenseExpiration | Get-Date -Format 'yyyy.MM.dd') + '.' + "$licenseNodeCount"
}

# Ensure the packaging folder exists
Write-Verbose "Generating package/packaging folders at '$PackagingFolder'"
New-Item $PackagingFolder -ItemType Directory -Force | Out-Null
New-Item $PackagesPath -ItemType Directory -Force | Out-Null

# Create a new package
Write-Verbose "Creating package named  '$LicensePackageId'"
New-Item $licensePackageFolder -ItemType Directory -Force | Out-Null
New-Item "$licensePackageFolder\tools" -ItemType Directory -Force | Out-Null

# Set the installation script
Write-Verbose "Setting install and uninstall scripts..."
@'
    $ErrorActionPreference = 'Stop'
    $toolsDir              = Split-Path -Parent $MyInvocation.MyCommand.Definition
    $licenseFile           = "$toolsDir\chocolatey.license.xml"

    New-Item "$env:ChocolateyInstall\license" -ItemType Directory -Force
    Copy-Item -Path $licenseFile  -Destination $env:ChocolateyInstall\license\chocolatey.license.xml -Force
    Write-Output "The license has been installed."
'@ | Set-Content -Path "$licensePackageFolder\tools\chocolateyInstall.ps1" -Encoding UTF8 -Force

# Set the uninstall script
@'
    Remove-Item -Path "$env:ChocolateyInstall\license\chocolatey.license.xml" -Force
    Write-Output "The license has been removed."
'@ | Set-Content -Path "$licensePackageFolder\tools\chocolateyUninstall.ps1" -Encoding UTF8 -Force

# Copy the license to the package directory
Write-Verbose "Copying license to package from '$LicensePath' to package location."
Copy-Item -Path $LicensePath -Destination "$licensePackageFolder\tools\chocolatey.license.xml" -Force

# Set the nuspec
Write-Verbose "Setting nuspec..."
@"
<?xml version="1.0" encoding="utf-8"?>
<package xmlns="http://schemas.microsoft.com/packaging/2015/06/nuspec.xsd">
  <metadata>
    <id>chocolatey-license</id>
    <version>$LicensePackageVersion</version>
    <!--<owners>__REPLACE_YOUR_NAME__</owners>-->
    <title>Chocolatey License</title>
    <authors>Chocolatey Software, Inc</authors>
    <tags>chocolatey license</tags>
    <summary>Installs the Chocolatey commercial license file.</summary>
    <description>This package ensures installation of the Chocolatey commercial license file.

This should be installed internally prior to installing other packages, directly after Chocolatey is installed and prior to installing `chocolatey.extension` and `chocolatey-agent`.

The order for scripting is this:
* chocolatey
* chocolatey-license
* chocolatey.extension
* chocolatey-agent

If items are installed in any other order, it could have strange effects or fail.
	</description>
    <!-- <releaseNotes>__REPLACE_OR_REMOVE__MarkDown_Okay</releaseNotes> -->
  </metadata>
  <files>
    <file src="tools\**" target="tools" />
  </files>
</package>
"@.Trim() | Set-Content -Path "$licensePackageNuspec" -Encoding UTF8 -Force

# Package up everything
Write-Verbose "Creating license package..."
Invoke-Choco pack $licensePackageNuspec --output-directory="$PackagesPath"
Write-Verbose "Package has been created and is ready at $PackagesPath"

Write-Verbose "Installing newly created package on this machine, making updates to license easier in the future, if pushed from another location later."
Invoke-Choco upgrade chocolatey-license -y --source="'$PackagesPath'"
