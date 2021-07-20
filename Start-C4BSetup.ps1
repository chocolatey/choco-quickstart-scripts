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
    # Accepts any file, and moves and renames it correctly.
    # You can either define this as a parameter, or
    # script will prompt you for it.
    # Script will also validate expiry.
    [string]
    $LicenseFile
)

$DefaultEap = $ErrorActionPreference
$ErrorActionPreference = 'Stop'
Start-Transcript -Path "$env:SystemDrive\choco-setup\logs\Start-C4bSetup-$(Get-Date -Format 'yyyyMMdd-HHmmss').txt"

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
$ChocoPath = "$env:SystemDrive\choco-setup"
$FilesDir = "$ChocoPath\files"
$PkgsDir = "$ChocoPath\packages"
$TempDir = "$ChocoPath\temp"
@($ChocoPath,$FilesDir,$PkgsDir,$TempDir) |
    Foreach-Object {
        $null = New-Item -Path $_ -ItemType Directory -Force
	}

# Download and extract C4B setup files from repo
$QsRepo = "https://github.com/chocolatey/choco-quickstart-scripts/archive/main.zip"
Invoke-WebRequest -Uri $QsRepo -UseBasicParsing -OutFile "$TempDir\main.zip"
Expand-Archive "$TempDir\main.zip" $TempDir
Copy-Item "$TempDir\choco-quickstart-scripts-main\*" $FilesDir -Recurse
Remove-Item "$TempDir\*" -Recurse

# Convert license to a "choco-license" package, and install it locally to test
Write-Host "Ceating a "chocolatey-license" package, and testing install." -ForegroundColor Green
Set-Location $FilesDir
.\Create-ChocoLicensePkg.ps1

# Downloading all CCM setup packages below
Write-Host "Downloading nupkg files to C:\choco-setup\packages." -ForegroundColor Green
Write-Host "This will take some time. Feel free to get a tea or coffee." -ForegroundColor Green
Start-Sleep -Seconds 5
$PkgsDir = "$env:SystemDrive\choco-setup\packages"
$Ccr = "'https://community.chocolatey.org/api/v2/'"

# Download Chocolatey community related items, no internalization necessary
@('chocolatey','chocolateygui') |
    Foreach-Object {
        choco download $_ --no-progress --force --source $Ccr --output-directory $PkgsDir
    }

# Internalize dotnet4.5.2 for ChocolateyGUI (jsut in case)
choco download dotnet4.5.2 --no-progress --force --internalize --internalize-all-urls --append-use-original-location --source $Ccr  --output-directory $PkgsDir

# Download Licensed Packages
## DO NOT RUN WITH `--internalize` and `--internalize-all-urls` - see https://github.com/chocolatey/chocolatey-licensed-issues/issues/155
('chocolatey-agent','chocolatey.extension') |
    Foreach-Object {
        choco download $_ --force --no-progress --source="'https://licensedpackages.chocolatey.org/api/v2/'" --ignore-dependencies --output-directory $PkgsDir
    }

$ErrorActionPreference = $DefaultEap
Stop-Transcript