#requires -Modules C4B-Environment
<#
.SYNOPSIS
C4B Quick-Start Guide Nexus setup script

.DESCRIPTION
- Performs the following Sonatype Nexus Repository setup
    - Install of Inedo ProGet instance
    - Edit configuration to allow running of scripts
    - Creates `ChocolateyInternal` NuGet repository
    - Creates `ChocolateyTest` NuGet repository
    - Creates `choco-install` Asset Directory, with a script for offline Chocolatey install
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
                    ($_.Subject -replace "^CN=(?<FQDN>.+),?.*$", '${FQDN}')
                )
            }
        })]
    [ValidateScript({ Test-CertificateDomain -Thumbprint $_ })]
    [string]
    $Thumbprint = $(
        if ((Test-Path C:\choco-setup\clixml\chocolatey-for-business.xml) -and (Import-Clixml C:\choco-setup\clixml\chocolatey-for-business.xml).CertThumbprint) {
            (Import-Clixml C:\choco-setup\clixml\chocolatey-for-business.xml).CertThumbprint
        }
        else {
            Get-ChildItem Cert:\LocalMachine\TrustedPeople -Recurse | Sort-Object {
                $_.Issuer -eq $_.Subject # Prioritise any certificates above self-signed
            } | Select-Object -ExpandProperty Thumbprint -First 1
        }
    )
)

process {
    $DefaultEap = $ErrorActionPreference
    $ErrorActionPreference = 'Stop'
    Start-Transcript -Path "$env:SystemDrive\choco-setup\logs\Start-C4bProGetSetup-$(Get-Date -Format 'yyyyMMdd-HHmmss').txt"

    # Install ProGet
    $chocoArgs = @('install', 'proget', '-y', '--no-progress')
    & Invoke-Choco @chocoArgs

    # Install Pagootle PowerShell module
    $chocoArgs = @('install', 'pagootle', '-y', '--no-progress')
    & Invoke-Choco @chocoArgs

    # Configure SSL
    if ($Thumbprint) {
        $ProGetPort = 443

        # TODO: Use Set-ProGetSSLConfiguration
    }
    # Configure firewall
    $FwRuleParams = @{
        DisplayName = "Nexus Repository access on TCP $ProGetPort"
        Direction   = 'Inbound'
        LocalPort   = $ProGetPort
        Protocol    = 'TCP'
        Action      = 'Allow'
    }
    $null = New-NetFirewallRule @FwRuleParams

    Wait-Site ProGet # TODO: Add support for Proget to Wait-Site

    Write-Host 'Configuring Inedo ProGet'

    # Create configuration
    Write-Verbose 'Setting default connection configuration'

    $Credential = [PSCredential]::new(
        "Admin",
        (New-ServicePassword)
    )
    
    Set-ProGetUserPassword -Credential $Credential

    Set-ProGetConfiguration -Hostname localhost -Credential $Credential
    
    # Create Chocolatey package repos

    # ChocolateyInternal
    if (-not (Get-ProGetFed -Feed ChocolateyInternal)) {
        New-ProGetFeed -Name ChocolateyInternal -Type chocolatey -Active
    }

    # ChocolateyTest
    if (-not (Get-ProGetFeed -Feed ChocolateyTest)) {
        New-ProGetFeed -Name ChocolateyTest -Type chocolatey -Active
    }

    # Create Asset Directory
    
    # choco-install
    if (-not (Get-ProGetFeed -Feed choco-install)) {
        New-ProGetFeed -Name choco-install -Type asset -Active
    }

    # Security

    # API key for package internalizer

    $apiArgs = @{
        DisplayName        = 'Package Internalizer'
        Description        = 'This api key is used by automation platforms to automate Chocolatey Package Internalizer'
        PackagePermissions = 'add'
        Feed               = 'ChocolateyInternal'
    }

    $automationKey = New-ProGetApiKey @apiArgs

    # Retrieve the API Key to use in Jenkins et al
    if ($NuGetApiKey = Get-ChocoEnvironmentProperty PackageApiKey) {
        Write-Verbose "Using existing ProGet Api Key"
    }
    else {
        Set-ChocoEnvironmentProperty -Name PackageApiKey -Value $automationKey.Key
    } 

    # API key for Chocolatey CLI

    $apiArgs = @{
        DisplayName        = 'Chocolatey CLI'
        Description        = 'This api key is used by Chocolatey CLI to authenticate to ProGet for package operations (install/upgrade/search)'
        PackagePermissions = 'add'
        Feed               = 'ChocolateyInternal'
    }

    $cliKey = New-ProGetApiKey @apiArgs

    # Create new user for package-upload - as this changes the usercontext, ensure this is the last thing in the script, or it's in a job
    if ($UploadUser = Get-ChocoEnvironmentProperty PackageUploadCredential) {
        Write-Verbose "Using existing PackageUpload credential '$($UploadUser.UserName)'"
    }
    else {
        $UploadUser = [PSCredential]::new(
            'chocoPackager',
            (New-ServicePassword -Length 64)
        )
    }


    # Set environment properties
    Set-ChocoEnvironmentProperty PackageUploaderApiKey $automationKey.key
    Set-ChocoEnvironmentProperty ChocolateyCLIKey $cliKey.key

    # Push latest ChocolateyInstall.ps1 to raw repo
    $ScriptDir = "$env:SystemDrive\choco-setup\files\scripts"
    $ChocoInstallScript = "$ScriptDir\ChocolateyInstall.ps1"

    if (-not (Test-Path $ChocoInstallScript)) {
        Invoke-WebRequest -Uri 'https://chocolatey.org/install.ps1' -OutFile $ChocoInstallScript
    }
     
    $Signature = Get-AuthenticodeSignature -FilePath $ChocoInstallScript

    if ($Signature.Status -eq 'Valid' -and $Signature.SignerCertificate.Subject -eq 'CN="Chocolatey Software, Inc", O="Chocolatey Software, Inc", L=Topeka, S=Kansas, C=US') {
        $null = New-ProGetAsset -Path $ChocoInstallScript -AssetDirectory 'choco-install' -AssetName (Split-Path -Leaf $ChocoInstallScript)
    }
    else {
        Write-Error "ChocolateyInstall.ps1 script signature is not valid. Please investigate."
    }

    # Push ClientSetup.ps1 to raw repo
    $ClientScript = "$PSScriptRoot\scripts\ClientSetup.ps1"
    (Get-Content -Path $ClientScript) -replace "{{hostname}}", "$((Get-NexusLocalServiceUri) -replace '^https?:\/\/')" | Set-Content -Path ($TemporaryFile = New-TemporaryFile).FullName
    $null = New-ProGetAsset -Path $TemporaryFile.FullName -AssetDirectory 'choco-install' -AssetName 'ClientSetup.ps1'

    # Nexus NuGet V3 Compatibility
    Invoke-Choco feature disable --name="'usePackageRepositoryOptimizations'"

    # Add ChocolateyInternal as a source repository
    $LocalSource = "$((Get-NexusRepository -Name 'ChocolateyInternal').url)/index.json"
    Invoke-Choco source add -n 'ChocolateyInternal' -s $LocalSource -u='api' -p="$($UploadUser.GetNetworkCredential().Password)" --priority 1

    # Add ChocolateyTest as a source repository, to enable authenticated pushing
    Invoke-Choco source add -n 'ChocolateyTest' -s "$((Get-NexusRepository -Name 'ChocolateyTest').url)/index.json" -u="$($UploadUser.UserName)" -p="$($UploadUser.GetNetworkCredential().Password)"
    Invoke-Choco source disable -n 'ChocolateyTest'

    # Push all packages from previous steps to NuGet repo
    Write-Host "Pushing C4B Environment Packages to ChocolateyInternal"
    Get-ChildItem -Path "$env:SystemDrive\choco-setup\files\files" -Filter *.nupkg | ForEach-Object {
        Invoke-Choco push $_.FullName --source $LocalSource --apikey $NugetApiKey --force
    }

    # Remove Local Chocolatey Setup Source
    $chocoArgs = @('source', 'remove', '--name="LocalChocolateySetup"')
    & Invoke-Choco @chocoArgs
    
    # Install a non-IE browser for browsing the Nexus web portal.
    if (-not (Test-Path 'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe')) {
        Write-Host "Installing Microsoft Edge, to allow viewing the Nexus site"
        Invoke-Choco install microsoft-edge -y --source ChocolateyInternal
    }
    $Key = @{ Key = 'HKLM:\Software\Policies\Microsoft\Edge' ; Value = 'HideFirstRunExperience' }
    if (-not (Test-Path $Key.Key)) {
        $null = New-Item -Path $Key.Key -Force
    }
    $null = New-ItemProperty -Path $Key.Key -Name $Key.Value -Value 1 -PropertyType DWORD -Force

    # Save useful params
    Update-Clixml -Properties @{
        NexusUri        = Get-NexusLocalServiceUri
        NexusCredential = $Credential
        NexusRepo       = "$((Get-NexusRepository -Name 'ChocolateyInternal').url)/index.json"
        NuGetApiKey     = $cliKey.key | ConvertTo-SecureString -AsPlainText -Force
    }

    $ErrorActionPreference = $DefaultEap
    Stop-Transcript
}