#requires -Modules C4B-Environment
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
    # The certificate thumbprint that identifies the target SSL certificate in
    # the local machine certificate stores.
    [Parameter()]
    [ArgumentCompleter({
        Get-ChildItem Cert:\LocalMachine\TrustedPeople | ForEach-Object {
            [System.Management.Automation.CompletionResult]::new(
                $_.Thumbprint,
                $_.Thumbprint,
                "ParameterValue",
                ($_.Subject -replace "^CN=(?<FQDN>.+),?.*$",'${FQDN}')
            )
        }
    })]
    [ValidateScript({Test-CertificateDomain -Thumbprint $_})]
    [string]
    $Thumbprint = $(
        if ((Test-Path C:\choco-setup\clixml\chocolatey-for-business.xml) -and (Import-Clixml C:\choco-setup\clixml\chocolatey-for-business.xml).CertThumbprint) {
            (Import-Clixml C:\choco-setup\clixml\chocolatey-for-business.xml).CertThumbprint
        } else {
            Get-ChildItem Cert:\LocalMachine\TrustedPeople -Recurse | Sort-Object {
                $_.Issuer -eq $_.Subject # Prioritise any certificates above self-signed
            } | Select-Object -ExpandProperty Thumbprint -First 1
        }
    )
)
process {
    $DefaultEap = $ErrorActionPreference
    $ErrorActionPreference = 'Stop'
    Start-Transcript -Path "$env:SystemDrive\choco-setup\logs\Start-C4bNexusSetup-$(Get-Date -Format 'yyyyMMdd-HHmmss').txt"
    $NexusPort = 8081

    $Packages = (Get-Content $PSScriptRoot\files\chocolatey.json | ConvertFrom-Json).packages

    # Install base nexus-repository package
    Write-Host "Installing Sonatype Nexus Repository"
    $chocoArgs = @('install', 'nexus-repository', '-y' ,'--no-progress', "--package-parameters='/Fqdn:localhost'")
    & Invoke-Choco @chocoArgs

    $chocoArgs = @('install', 'nexushell', '-y' ,'--no-progress')
    & Invoke-Choco @chocoArgs

    if ($Thumbprint) {
        $NexusPort = 8443

        $null = Set-NexusCert -Thumbprint $Thumbprint -Port $NexusPort
        
        if ($CertificateDnsName = Get-ChocoEnvironmentProperty CertSubject) {
            # Override the domain, so we don't get prompted for wildcard certificates
            Get-NexusLocalServiceUri -HostnameOverride $CertificateDnsName | Write-Verbose
        }
    }

    # Add Nexus port access via firewall
    $FwRuleParams = @{
        DisplayName = "Nexus Repository access on TCP $NexusPort"
        Direction = 'Inbound'
        LocalPort = $NexusPort
        Protocol = 'TCP'
        Action = 'Allow'
    }
    $null = New-NetFirewallRule @FwRuleParams

    Wait-Site Nexus

    Write-Host "Configuring Sonatype Nexus Repository"

    # Build Credential Object, Connect to Nexus
    if (-not ($Credential = Get-ChocoEnvironmentProperty NexusCredential)) {
        Write-Host "Setting up admin account."
        $NexusDefaultPasswordPath = 'C:\programdata\sonatype-work\nexus3\admin.password'

        $Timeout = [System.Diagnostics.Stopwatch]::StartNew()
        while (-not (Test-Path $NexusDefaultPasswordPath) -and $Timeout.Elapsed.TotalMinutes -lt 3) {
            Start-Sleep -Seconds 5
        }

        $DefaultNexusCredential = [System.Management.Automation.PSCredential]::new(
            'admin',
            (Get-Content $NexusDefaultPasswordPath | ConvertTo-SecureString -AsPlainText -Force)
        )

        try {
            Connect-NexusServer -LocalService -Credential $DefaultNexusCredential -ErrorAction Stop

            $Credential = [PSCredential]::new(
                "admin",
                (New-ServicePassword)
            )

            Set-NexusUserPassword -Username admin -NewPassword $Credential.Password -ErrorAction Stop
            Set-ChocoEnvironmentProperty -Name NexusCredential -Value $Credential
        } finally {}

        if (Test-Path $NexusDefaultPasswordPath) {
            Remove-Item -Path $NexusDefaultPasswordPath
        }
    }
    Connect-NexusServer -LocalService -Credential $Credential

    # Disable anonymous authentication
    $null = Set-NexusAnonymousAuth -Disabled

    # Drain default repositories
    $null = Get-NexusRepository | Where-Object Name -NotLike "choco*" | Remove-NexusRepository -Force

    # Enable NuGet Auth Realm
    Enable-NexusRealm -Realm 'NuGet API-Key Realm'

    # Create Chocolatey repositories
    if (-not (Get-NexusRepository -Name ChocolateyInternal)) {
        New-NexusNugetHostedRepository -Name ChocolateyInternal -DeploymentPolicy Allow
    }

    if (-not (Get-NexusRepository -Name ChocolateyTest)) {
        New-NexusNugetHostedRepository -Name ChocolateyTest -DeploymentPolicy Allow
    }

    if (-not (Get-NexusRepository -Name choco-install)) {
        New-NexusRawHostedRepository -Name choco-install -DeploymentPolicy Allow -ContentDisposition Attachment
    }

    # Create role for end user to pull from Nexus
    if (-not ($NexusRole = Get-NexusRole -Role 'chocorole' -ErrorAction SilentlyContinue)) {
        # Create Nexus role
        $RoleParams = @{
            Id          = "chocorole"
            Name        = "chocorole"
            Description = "Role for web enabled choco clients"
            Privileges  = @('nx-repository-view-nuget-*-browse', 'nx-repository-view-nuget-*-read', 'nx-repository-view-raw-*-read', 'nx-repository-view-raw-*-browse')
        }
        $NexusRole = New-NexusRole @RoleParams

        $Timeout = [System.Diagnostics.Stopwatch]::StartNew()
        while ($Timeout.Elapsed.TotalSeconds -lt 30 -and -not (Get-NexusRole -Role $RoleParams.Id -ErrorAction SilentlyContinue)) {
            Start-Sleep -Seconds 3
        }
    }

    # Create new user for endpoints
    if (-not (Get-NexusUser -User 'chocouser' -ErrorAction SilentlyContinue)) {
        $NexusPw = [System.Web.Security.Membership]::GeneratePassword(32, 12)
        # Create Nexus user
        $UserParams = @{
            Username     = 'chocouser'
            Password     = ($NexusPw | ConvertTo-SecureString -AsPlainText -Force)
            FirstName    = 'Choco'
            LastName     = 'User'
            EmailAddress = 'chocouser@example.com'
            Status       = 'Active'
            Roles        = $NexusRole.Id
        }
        $null = New-NexusUser @UserParams

        $Timeout = [System.Diagnostics.Stopwatch]::StartNew()
        while ($Timeout.Elapsed.TotalSeconds -lt 30 -and -not (Get-NexusUser -User $UserParams.Username -ErrorAction SilentlyContinue)) {
            Start-Sleep -Seconds 3
        }

        Set-ChocoEnvironmentProperty ChocoUserPassword $UserParams.Password
    }

    # Create role for task runner to push to Nexus
    if (-not ($PackageUploadRole = Get-NexusRole -Role "package-uploader" -ErrorAction SilentlyContinue)) {
        $PackageUploadRole = New-NexusRole -Name "package-uploader" -Id "package-uploader" -Description "Role allowed to push and list packages" -Privileges @(
            "nx-repository-view-nuget-*-edit"
            "nx-repository-view-nuget-*-read"
            "nx-apikey-all"
        )
    }

    # Create new user for package-upload - as this changes the usercontext, ensure this is the last thing in the script, or it's in a job
    if ($UploadUser = Get-ChocoEnvironmentProperty PackageUploadCredential) {
        Write-Verbose "Using existing PackageUpload credential '$($UploadUser.UserName)'"
    } else {
        $UploadUser = [PSCredential]::new(
            'chocoPackager',
            (New-ServicePassword -Length 64)
        )
    }

    if (-not (Get-NexusUser -User $UploadUser.UserName)) {
        $NewUser = @{
            Username     = $UploadUser.UserName
            Password     = $UploadUser.Password
            FirstName    = "Chocolatey"
            LastName     = "Packager"
            EmailAddress = "packager@$env:ComputerName.local"
            Status       = "Active"
            Roles        = $PackageUploadRole.Id
        }
        $null = New-NexusUser @NewUser

        Set-ChocoEnvironmentProperty -Name PackageUploadCredential -Value $UploadUser
    }

    # Retrieve the API Key to use in Jenkins et al
    if ($NuGetApiKey = Get-ChocoEnvironmentProperty PackageApiKey) {
        Write-Verbose "Using existing Nexus Api Key for '$($UploadUser.UserName)'"
    } else {
        $NuGetApiKey = (Get-NexusNuGetApiKey -Credential $UploadUser).apiKey
        Set-ChocoEnvironmentProperty -Name PackageApiKey -Value $NuGetApiKey
    }

    # Push latest ChocolateyInstall.ps1 to raw repo
    $ScriptDir = "$env:SystemDrive\choco-setup\files\scripts"
    $ChocoInstallScript = "$ScriptDir\ChocolateyInstall.ps1"

    if (-not (Test-Path $ChocoInstallScript)) {
        Invoke-WebRequest -Uri 'https://chocolatey.org/install.ps1' -OutFile $ChocoInstallScript
    }

    $Signature = Get-AuthenticodeSignature -FilePath $ChocoInstallScript

    if ($Signature.Status -eq 'Valid' -and $Signature.SignerCertificate.Subject -eq 'CN="Chocolatey Software, Inc", O="Chocolatey Software, Inc", L=Topeka, S=Kansas, C=US') {
        $null = New-NexusRawComponent -RepositoryName 'choco-install' -File $ChocoInstallScript
    } else {
        Write-Error "ChocolateyInstall.ps1 script signature is not valid. Please investigate."
    }

    # Push ClientSetup.ps1 to raw repo
    $ClientScript = "$PSScriptRoot\scripts\ClientSetup.ps1"
    (Get-Content -Path $ClientScript) -replace "{{hostname}}", "$((Get-NexusLocalServiceUri) -replace '^https?:\/\/')" | Set-Content -Path ($TemporaryFile = New-TemporaryFile).FullName
    $null = New-NexusRawComponent -RepositoryName 'choco-install' -File $TemporaryFile.FullName -Name "ClientSetup.ps1"

    # Nexus NuGet V3 Compatibility
    Invoke-Choco feature disable --name="'usePackageRepositoryOptimizations'"

    # Add ChocolateyInternal as a source repository
    $LocalSource = "$((Get-NexusRepository -Name 'ChocolateyInternal').url)/index.json"
    Invoke-Choco source add -n 'ChocolateyInternal' -s $LocalSource -u="$($UploadUser.UserName)" -p="$($UploadUser.GetNetworkCredential().Password)" --priority 1

    # Add ChocolateyTest as a source repository, to enable authenticated pushing
    Invoke-Choco source add -n 'ChocolateyTest' -s "$((Get-NexusRepository -Name 'ChocolateyTest').url)/index.json" -u="$($UploadUser.UserName)" -p="$($UploadUser.GetNetworkCredential().Password)"
    Invoke-Choco source disable -n 'ChocolateyTest'

    # Push all packages from previous steps to NuGet repo
    Write-Host "Pushing C4B Environment Packages to ChocolateyInternal"
    Get-ChildItem -Path "$env:SystemDrive\choco-setup\files\files" -Filter *.nupkg | ForEach-Object {
        Invoke-Choco push $_.FullName --source $LocalSource --apikey $NugetApiKey --force
    }

    # Temporary workaround to reset the NuGet v3 cache, such that it doesn't capture localhost as the FQDN
    Remove-NexusRepositoryFolder -RepositoryName ChocolateyInternal -Name v3

    # Remove Local Chocolatey Setup Source
    $chocoArgs = @('source', 'remove', '--name="LocalChocolateySetup"')
    & Invoke-Choco @chocoArgs
    
    # Install a non-IE browser for browsing the Nexus web portal.
    if (-not (Test-Path 'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe')) {
        Write-Host "Installing Microsoft Edge, to allow viewing the Nexus site"
        Invoke-Choco install microsoft-edge -y --source ChocolateyInternal
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

    # Save useful params
    Update-Clixml -Properties @{
        NexusUri = Get-NexusLocalServiceUri
        NexusCredential = $Credential
        NexusRepo = "$((Get-NexusRepository -Name 'ChocolateyInternal').url)/index.json"
        NuGetApiKey = $NugetApiKey | ConvertTo-SecureString -AsPlainText -Force
    }

    $ErrorActionPreference = $DefaultEap
    Stop-Transcript
}