<#
.SYNOPSIS
C4B Quick-Start Guide Nexus setup script

.DESCRIPTION
- Performs the following Sonatype Nexus Repository setup
    - Install of Sonatype Nexus Repository Manager OSS instance
    - Edit configuration to allow running of scripts
    - Cleanup of all demo source repositories
    - Creates `ChocolateyInternal` NuGet repository
    - Creates `ChocolateyTest` NuGet repository
    - Creates `choco-install` raw repository, with a script for offline Chocolatey install
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
process {
    $DefaultEap = $ErrorActionPreference
    $ErrorActionPreference = 'Stop'
    Start-Transcript -Path "$env:SystemDrive\choco-setup\logs\Start-C4bNexusSetup-$(Get-Date -Format 'yyyyMMdd-HHmmss').txt"

    # Dot-source helper functions
    . .\scripts\Get-Helpers.ps1

    # Install base nexus-repository package
    Write-Host "Installing Sonatype Nexus Repository"
    $chocoArgs = @('install', 'nexus-repository', '-y' ,'--no-progress', "--package-parameters='/Fqdn:localhost'")
    & choco @chocoArgs

    #Build Credential Object, Connect to Nexus
    Write-Host "Configuring Sonatype Nexus Repository"
    $securePw = (Get-Content 'C:\programdata\sonatype-work\nexus3\admin.password') | ConvertTo-SecureString -AsPlainText -Force
    $Credential = [System.Management.Automation.PSCredential]::new('admin',$securePw)

    Connect-NexusServer -Hostname localhost -Credential $Credential

    #Drain default repositories
    $null = Get-NexusRepository | Where-Object Name -NotLike "choco*" | Remove-NexusRepository -Force

    #Enable NuGet Auth Realm
    Enable-NexusRealm -Realm 'NuGet API-Key Realm'

    #Create Chocolatey repositories
    New-NexusNugetHostedRepository -Name ChocolateyInternal -DeploymentPolicy Allow
    New-NexusNugetHostedRepository -Name ChocolateyTest -DeploymentPolicy Allow
    New-NexusRawHostedRepository -Name choco-install -DeploymentPolicy Allow -ContentDisposition Attachment

    #Surface API Key
    $NuGetApiKey = (Get-NexusNuGetApiKey -Credential $Credential).apikey

    # Push all packages from previous steps to NuGet repo
    Get-ChildItem -Path "$env:SystemDrive\choco-setup\files\files" -Filter *.nupkg | ForEach-Object {
        choco push $_.FullName --source "$((Get-NexusRepository -Name 'ChocolateyInternal').url)/index.json" --apikey $NugetApiKey --force
    }

    # Temporary workaround to reset the NuGet v3 cache, such that it doesn't capture localhost as the FQDN
    Remove-NexusRepositoryFolder -RepositoryName ChocolateyInternal -Name v3

    # Push latest ChocolateyInstall.ps1 to raw repo
    $ScriptDir = "$env:SystemDrive\choco-setup\files\scripts"
    $ChocoInstallScript = "$ScriptDir\ChocolateyInstall.ps1"

    if (-not (Test-Path $ChocoInstallScript)) {
        Invoke-WebRequest -Uri 'https://chocolatey.org/install.ps1' -OutFile $ChocoInstallScript
    }

    $Signature = Get-AuthenticodeSignature -FilePath $ChocoInstallScript

    if ($Signature.Status -eq 'Valid' -and $Signature.SignerCertificate.Subject -eq 'CN="Chocolatey Software, Inc", O="Chocolatey Software, Inc", L=Topeka, S=Kansas, C=US') {
        New-NexusRawComponent -RepositoryName 'choco-install' -File $ChocoInstallScript
    } else {
        Write-Error "ChocolateyInstall.ps1 script signature is not valid. Please investigate."
    }

    # Add ChocolateyInternal as a source repository
    choco source add -n 'ChocolateyInternal' -s "$((Get-NexusRepository -Name 'ChocolateyInternal').url)/index.json" --priority 1

    # Install a non-IE browser for browsing the Nexus web portal.
    if (-not (Test-Path 'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe')) {
        Write-Host "Installing Microsoft Edge, to allow viewing the Nexus site"
        choco install microsoft-edge -y --source ChocolateyInternal
        if ($LASTEXITCODE -eq 0) {
            if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Edge') {
                $RegArgs = @{
                    Path = 'HKLM:\SOFTWARE\Microsoft\Edge\'
                    Name = 'HideFirstRunExperience'
                    Type = 'Dword'
                    Value = 1
                    Force = $true
                }
                $null = Set-ItemProperty @RegArgs
            }
        }
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
        NexusRepo = "$((Get-NexusRepository -Name 'ChocolateyInternal').url)/index.json"
        NuGetApiKey = $NugetApiKey
    }
    $NexusJson | ConvertTo-Json | Out-File "$env:SystemDrive\choco-setup\logs\nexus.json"

    $ErrorActionPreference = $DefaultEap
    Stop-Transcript
}