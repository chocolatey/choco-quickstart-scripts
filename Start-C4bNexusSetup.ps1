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

begin {
    if($host.name -ne 'ConsoleHost') {
        Write-Warning "This script cannot be ran from within PowerShell ISE"
        Write-Warning "Please launch powershell.exe as an administrator, and run this script again"
        break
    }
}


process {
    $DefaultEap = $ErrorActionPreference
    $ErrorActionPreference = 'Stop'
    Start-Transcript -Path "$env:SystemDrive\choco-setup\logs\Start-C4bNexusSetup-$(Get-Date -Format 'yyyyMMdd-HHmmss').txt"

    # Dot-source helper functions
    . .\scripts\Get-Helpers.ps1

    # Install base nexus-repository package
    $chocoArgs = @('install','nexus-repository','-y',"--source='https://community.chocolatey.org/api/v2/'",'--no-progress',"--package-parameters='/Fqdn:localhost'")
    & choco @chocoArgs

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

    if ($Signature.Status -eq 'Valid' -and $Signature.SignerCertificate.Subject -eq 'CN="Chocolatey Software, Inc.", O="Chocolatey Software, Inc.", L=Topeka, S=Kansas, C=US') {
        New-NexusRawComponent -RepositoryName 'choco-install' -File $ChocoInstallScript
    } else {
        Write-Error "ChocolateyInstall.ps1 script signature is not valid. Please investigate."
    }

    # Add ChocolateyInternal as a source repository
    choco source add -n 'ChocolateyInternal' -s "$((Get-NexusRepository -Name 'ChocolateyInternal').url)/index.json" --priority 1

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
        NexusRepo = "$((Get-NexusRepository -Name 'ChocolateyInternal').url)/index.json"
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
}