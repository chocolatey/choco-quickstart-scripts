<#
.SYNOPSIS
Certificate renewal script for Chocolatey Central Management(CCM)

.DESCRIPTION
This script will go through and renew the certificate association with both the Chocolatey Central Management Service and IIS Web hosted dashboard.

.PARAMETER CertificateThumbprint
Thumbprint value of the certificate you would like the Chocolatey Central Management Service and Web to run on.
Please make sure the certificate is located in both the Cert:\LocalMachine\TrustedPeople\ and Cert:\LocalMachine\My certificate stores.

.EXAMPLE
PS> .\Set-CCMCert.ps1 -Thumbprint 'Your_Certificate_Thumbprint_Value'
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ArgumentCompleter({
        Get-ChildItem Cert:\LocalMachine\My | ForEach-Object {
            [System.Management.Automation.CompletionResult]::new(
                $_.Thumbprint,
                $_.Thumbprint,
                'ParameterValue',
                $_.FriendlyName
            )
        }
    })]
    [string]$Thumbprint
)

if($host.name -ne 'ConsoleHost') {
    Write-Warning "This script cannot be ran from within PowerShell ISE"
    Write-Warning "Please launch powershell.exe as an administrator, and run this script again"
    break
}

. $PSScriptRoot\Get-Helpers.ps1

Stop-CCMService
Remove-CCMBinding
New-CCMBinding -Thumbprint $Thumbprint
Set-CCMCertificate -CertificateThumbprint $Thumbprint
Start-CCMService