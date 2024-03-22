<#
.SYNOPSIS
Certificate renewal script for Nexus.

.DESCRIPTION
Helps edit the java keystore file for Nexus when doing a certificate renewal.

.PARAMETER Thumbprint
Thumbprint value of certificate you want to run Nexus on. Make sure certificate is located at Cert:\LocalMachine\TrustedPeople\

.PARAMETER NexusPort
Port you have Nexus configured to run on.

.EXAMPLE
PS> .\Set-NexusCert.ps1 -Thumbprint 'Your_Certificate_Thumbprint_Value' -NexusPort 'Port_Number'
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]
    $Thumbprint,
    [string]$Thumbprint,

    [Parameter()]
    [uint16]$Port = 8443
)

if ($host.name -ne 'ConsoleHost') {
    Write-Warning "This script cannot be ran from within PowerShell ISE"
    Write-Warning "Please launch powershell.exe as an administrator, and run this script again"
    break
}

$ErrorActionPreference = 'Stop'

. $PSScriptRoot\Get-Helpers.ps1

Set-NexusCert -Thumbprint $Thumbprint -Port $Port

Write-Host -BackgroundColor Black -ForegroundColor DarkGreen "The script has successfully run and the Nexus service is now rebooting for the changes to take effect."