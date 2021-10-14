<#
.SYNOPSIS
C4B Quick-Start Guide CCM setup script, Part II

.DESCRIPTION
This is a continuation of the first CCM Setup script, and is only meant to be run if on Windows Server 2016.
#>
[CmdletBinding()]
param(
    # Credential used for the ChocolateyManagement DB user
    [Parameter()]
    [ValidateNotNull()]
    [string]$DatabaseUserPw = (Get-Content "$env:SystemDrive\choco-setup\logs\ccm.json" | ConvertFrom-Json).CCMDBPassword
)

$DefaultEap = $ErrorActionPreference
$ErrorActionPreference = 'Stop'
Start-Transcript -Path "$env:SystemDrive\choco-setup\logs\Start-C4bCcmSetup2-$(Get-Date -Format 'yyyyMMdd-HHmmss').txt"

$PkgSrc = "$env:SystemDrive\choco-setup\packages"

$chocoArgs = @('install', 'chocolatey-management-web', '-y', "--source='$PkgSrc'", "--package-parameters-sensitive='/ConnectionString:'Server=Localhost\SQLEXPRESS;Database=ChocolateyManagement;User ID=ChocoUser;Password=$DatabaseUserPw;''",'--no-progress')
& choco @chocoArgs
Write-Host "CCM Setup has now completed" -ForegroundColor Green

$ErrorActionPreference = $DefaultEap
Stop-Transcript

