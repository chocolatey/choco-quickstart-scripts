<#
.SYNOPSIS
C4B Quick-Start Guide Nexus setup script

.DESCRIPTION
- Performs the following Sonatype Nexus Repository setup
    - Install of Sonatype Nexus Repository Manager OSS instance
    - Edit configuration to allow running of scripts
    - Cleanup of all demo source repositories
    - `ChocolateyInternal` NuGet v2 repository
    - `ChocolateyTest` NuGet V2 repository
    - `choco-install` raw repository, with a script for offline Chocolatey install
    - Setup of `ChocolateyInternal` on C4B Server as source, with API key
    - Setup of firewall rule for repository access
#>
[CmdletBinding()]
param(
    # Choice of non-IE broswer for Nexus
    [Parameter()]
    [string]
    $Browser = 'Edge'
)

$DefaultEap = $ErrorActionPreference
$ErrorActionPreference = 'Stop'
Start-Transcript -Path "$env:SystemDrive\choco-setup\logs\Start-C4bNexusSetup-$(Get-Date -Format 'yyyyMMdd-HHmmss').txt"

# Dot-source helper functions
. /scripts/Get-Helpers.ps1

# Install base nexus-repository package
choco install nexus-repository -y --source="'https://chocolatey.org/api/v2/'"

#Build Credential Object, Connect to Nexus
$securePw = (Get-Content 'C:\programdata\sonatype-work\nexus3\admin.password') | ConvertTo-SecureString -AsPlainText -Force
$Credential = [System.Management.Automation.PSCredential]::new('admin',$securePw)

Connect-NexusServer -Hostname localhost -Credential $Credential

#Drain default repositories
Get-NexusRepository | Remove-NexusRepository -Force

#Enable NuGet Auth Realm
Enable-NexusRealm -Realm 'NuGet API-Key Realm'

#Create Chocolatey repositories
New-NexusNugetHostedRepository -Name ChocolateyInternal -DeploymentPolicy Allow
New-NexusNugetHostedRepository -Name ChocolateyTest -DeploymentPolicy Allow
New-NexusRawHostedRepository -Name choco-install -DeploymentPolicy Allow -ContentDisposition Attachment

#Surface API Key
$NuGetApiKey = (Get-NexusNuGetApiKey -Credential $Credential).apikey

# Push all packages from previous steps to NuGet repo
Get-ChildItem -Path "$env:SystemDrive\choco-setup\packages" -Filter *.nupkg |
    ForEach-Object {
        choco push $_.FullName --source "$((Get-NexusRepository -Name 'ChocolateyInternal').url)" --apikey $NugetApiKey --force
    }

# Add ChooclateyInternal as a source repository
choco source add -n 'ChocolateyInternal' -s "$((Get-NexusRepository -Name 'ChocolateyInternal').url)/" --priority 1
choco apikey -s 'ChocolateyInternal' -k $NugetApiKey

# Install a non-IE browser for browsing the Nexus web portal.
# Edge sometimes fails install due to latest Windows Updates not being installed.
# In that scenario, Google Chrome is installed instead.
$null = choco install microsoft-edge -y --source="'https://community.chocolatey.org/api/v2/'"
if ($LASTEXITCODE -eq 0) {
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Edge') {
        $RegArgs = @{
        Path = 'HKLM:\SOFTWARE\Microsoft\Edge\'
        Name = 'HideFirstRunExperience'
        Type = 'Dword'
        Value = 1
        Force = $true
        }
        Set-ItemProperty @RegArgs
    }
}
else {
    Write-Warning "Microsoft Edge install was not succesful."
    Write-Host "Installing Google Chrome as an alternative."
    choco install googlechrome -y --source="'https://community.chocolatey.org/api/v2/'"
}

# Add Nexus port 8081 access via firewall
$FwRuleParams = @{
    DisplayName    = 'Nexus Repository access on TCP 8081'
    Direction = 'Inbound'
    LocalPort = 8081
    Protocol = 'TCP'
    Action = 'Allow'
}
$null = New-NetFirewallRule @FwRuleParams

# Save useful params to JSON
$NexusJson = @{
    NexusUri = "http://localhost:8081"
    NexusUser = "admin"
    NexusPw = "$($Credential.GetNetworkCredential().Password)"
    NexusRepo = "$((Get-NexusRepository -Name 'ChocolateyInternal').url)/"
    NuGetApiKey = $NugetApiKey
}
$NexusJson | ConvertTo-Json | Out-File "$env:SystemDrive\choco-setup\logs\nexus.json"

$finishOutput = @"
##############################################################

Nexus Repository Setup Completed
Please login to the following URL to complete admin account setup:

Server Url: 'http://localhost:8081' (this will change once you add a certificate)
Chocolatey Repo: "$((Get-NexusRepository -Name 'ChocolateyInternal').url)/"
NuGet ApiKey: $NugetApiKey
Nexus 'admin' user password: $($Credential.GetNetworkCredential().Password)

##############################################################
"@

Write-Host "$finishOutput" -ForegroundColor Green

$ErrorActionPreference = $DefaultEap
Stop-Transcript
