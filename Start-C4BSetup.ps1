<#
.SYNOPSIS
C4B Quick-Start Guide initial bootstrap script

.DESCRIPTION
- Performs the following C4B Server initial bootstrapping
    - Install of Chocolatey
    - Prompt for C4B license, with validation
    - Script to help turn your C4B license into a Chocolatey package
    - Setup of local `choco-setup` directories
    - Download of Chocolatey packages required for setup
#>
[CmdletBinding()]
param(
    # Full path to Chocolatey license file.
    # Accepts any file, and moves and renames it correectly.
    # You can either define this as a parameter, or
    # script will prompt you for it.
    # Script will also validate expiry.
    [string]
    $LicenseFile
)

# Set error action preference
$DefaultEap = $ErrorActionPreference
$ErrorActionPreference = 'Stop'

# Start logging
Start-Transcript -Path "$env:SystemDrive\choco-setup\logs\Start-C4bSetup-$(Get-Date -Format 'yyyyMMdd-hhmmss').txt" -IncludeInvocationHeader

function Install-ChocoLicensed {

    [CmdletBinding()]
    Param(
        [Parameter(Position = 0)]
        [String]
        $LicenseFile
    )

    process {
        # Check if choco is installed; if not, install it
        if(-not(Test-Path "$env:ProgramData\chocolatey\choco.exe")){
            Write-Host "Chocolatey is not installed. Installing now." -ForegroundColor Green
            Invoke-Expression -Command ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
            refreshenv
        }
        # Create license directory if not present
        if (-not(Test-Path "$env:ProgramData\chocolatey\license")) {
            $null = New-Item "$env:ProgramData\chocolatey\license" -ItemType Directory -Force
        }
        if (-not($LicenseFile)){
            # Have user select license, install license, and licensed extension
            $Wshell = New-Object -ComObject Wscript.Shell
            $null = $Wshell.Popup('Please select your Chocolatey License File in the next file dialog.')
            $null = [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms")
            $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
            $OpenFileDialog.initialDirectory = "$env:USERPROFILE\Downloads"
            $OpenFileDialog.filter = 'All Files (*.*)| *.*'
            $null = $OpenFileDialog.ShowDialog()
            $LicenseFile = $OpenFileDialog.filename
        }
        # Validate license expiry
        [xml]$LicenseXml = Get-Content -Path $LicenseFile
        $LicenseExpiration = [datetimeoffset]::Parse("$($LicenseXml.SelectSingleNode('/license').expiration) +0")
        if ($LicenseExpiration -lt [datetimeoffset]::UtcNow) {
            Write-Warning "Your Chocolatey License file has EXPIRED, or is otherwise INVALID."
            Write-Warning "Please contact your Chocolatey Sales representative for assistance at sales@chocolatey.io ."
            Write-Warning "This script will now exit, as you require a valid license to proceed."
            throw "License is expired as of $($LicenseExpiration.ToString()). Please use an up to date license."
        }
        else {
            Write-Host "Installing your valid Chocolatey License." -ForegroundColor Green
            Copy-Item $LicenseFile -Destination C:\ProgramData\chocolatey\license\chocolatey.license.xml
            Write-Host "Installing the Chocolatey Licensed Extension." -ForegroundColor Green
            $null = choco install chocolatey.extension -y
        }
    }
}
if (-not($LicenseFile)) {
    Install-ChocoLicensed
}
else {
    Install-ChocoLicensed -LicenseFile $LicenseFile
}

# Setup initial choco-setup directories
Write-Host "Setting up initial directories in"$env:SystemDrive\choco-setup"" -ForegroundColor Green
@('choco-setup','choco-setup\files','choco-setup\packages') |
    Foreach-Object {
        $null = New-Item -Path "$env:SystemDrive\$_" -ItemType Directory -Force
	}

$FilesDir = "$env:SystemDrive\choco-setup\files"
$PkgsDir = "$env:SystemDrive\choco-setup\packages"

$C4bSetupFiles = @{
    'https://ch0.co/quickstart' = 'Start-C4BSetup.ps1'
    'https://ch0.co/qs-nexus' = 'Start-C4BNexusSetup.ps1'
    'https://ch0.co/qs-ccm' = 'Start-C4bCcmSetup.ps1'
    'https://ch0.co/licensepkg' = 'Create-ChocoLicensePkg.ps1'
}
$C4bSetupFiles.Keys | ForEach-Object {
    Invoke-WebRequest -Uri $_ -UseBasicParsing -OutFile "$FilesDir\$($C4bSetupFiles[$_])"
}

# Downloading all CCM setup packages below
Write-Host "Downloading nupkg files to C:\choco-setup\packages." -ForegroundColor Green
Write-Host "This will take some time. Feel free to get a tea or coffee." -ForegroundColor Green
Start-Sleep -Seconds 5
$PkgsDir = "$env:SystemDrive\choco-setup\packages"

# Download Chocolatey community related items, no internalization necessary
@('chocolatey','chocolateygui') |
    Foreach-Object {
        choco download $_ --no-progress --force --source="'https://chocolatey.org/api/v2/'" --output-directory $PkgsDir
    }

# This is for SQL Server Express and Community related items
@('sql-server-express','sql-server-management-studio','dotnet4.6.1','dotnet4.5.2') |
    Foreach-Object {
	    choco download $_ --no-progress --force --internalize --internalize-all-urls --append-use-original-location --source="'https://chocolatey.org/api/v2/'" --output-directory $PkgsDir
    }

# We must use the 2.2.7 versions of these packages, so we need to download/internalize these specific items
@('aspnetcore-runtimepackagestore','dotnetcore-windowshosting') |
    Foreach-Object {
	    choco download $_ --version 2.2.7 --no-progress --force --internalize --internalize-all-urls --append-use-original-location --source="'https://chocolatey.org/api/v2/'" --output-directory $PkgsDir
    }

# Download Licensed Packages
## DO NOT RUN WITH `--internalize` and `--internalize-all-urls` - see https://github.com/chocolatey/chocolatey-licensed-issues/issues/155
('chocolatey-agent','chocolatey.extension','chocolatey-management-database','chocolatey-management-service','chocolatey-management-web') |
    Foreach-Object {
        choco download $_ --force --no-progress --source="'https://licensedpackages.chocolatey.org/api/v2/'" --ignore-dependencies --output-directory $PkgsDir
    }

# Convert license to a "choco-license" package, and install it locally to test
Set-Location $FilesDir
.\Create-ChocoLicensePkg.ps1

#Stop logging
Stop-Transcript

# Set error action preference back to default
$ErrorActionPreference = $DefaultEap