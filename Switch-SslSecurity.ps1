#requires -modules C4B-Environment
using namespace System.Net.Sockets
using namespace System.Net.Security
using namespace System.Security.Cryptography.X509Certificates
<#
.SYNOPSIS
Generates or retrieves certificates and generates SSL bindings for
Central Management and Nexus.

.DESCRIPTION
Removes any existing certificates which have the subject "chocoserver" to avoid
issues, and then either generates or retrieves the required certificate. The
certificate is placed in the required local machine store, and then the script
generates SSL bindings for both Nexus and the Central Management website using the
certificate.
#>
[CmdletBinding(DefaultParameterSetName='SelfSigned')]
[OutputType([string])]
param(
    # The certificate thumbprint that identifies the target SSL certificate in
    # the local machine certificate stores.
    # Ignored if supplied alongside -Subject.
    [Parameter(ValueFromPipeline, ParameterSetName='Thumbprint')]
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
    ),

    # The certificate subject that identifies the target SSL certificate in
    # the local machine certificate stores.
    [Parameter(ParameterSetName='Subject')]
    [string]
    $Subject,

    # If using a wildcard certificate, provide a DNS name you want to use to access services secured by the certificate.
    [Parameter(ParameterSetName='Subject')]
    [Parameter(ParameterSetName='Thumbprint')]
    [string]
    $CertificateDnsName = $(
        if (-not (Get-Command Get-ChocoEnvironmentProperty -ErrorAction SilentlyContinue)) {. $PSScriptRoot\scripts\Get-Helpers.ps1}
        Get-ChocoEnvironmentProperty CertSubject
    ),

    # API key of your Nexus repo, to add to the source setup on C4B Server.
    [string]$NuGetApiKey = $(
        if (-not (Get-Command Get-ChocoEnvironmentProperty -ErrorAction SilentlyContinue)) {. $PSScriptRoot\scripts\Get-Helpers.ps1}
        Get-ChocoEnvironmentProperty NuGetApiKey -AsPlainText
    )
)
process {
    $DefaultEap = $ErrorActionPreference
    $ErrorActionPreference = 'Stop'
    Start-Transcript -Path "$env:SystemDrive\choco-setup\logs\Switch-SslSecurity-$(Get-Date -Format 'yyyyMMdd-HHmmss').txt"

    # Collect current certificate configuration
    $Certificate = if ($Subject) {
        Get-Certificate -Subject $Subject
    } elseif ($Thumbprint) {
        Get-Certificate -Thumbprint $Thumbprint
    }

    if (-not $CertificateDnsName -and -not ($CertificateDnsName = Get-ChocoEnvironmentProperty CertSubject)) {
        $null = Test-CertificateDomain -Thumbprint $Certificate.Thumbprint
    } else {
        $SubjectWithoutCn = $CertificateDnsName
    }

    <# Nexus #>
    # Stop Services/Processes/Websites required
    Stop-Service nexus

    # Put certificate in TrustedPeople
    Copy-CertToStore -Certificate $Certificate

    # Generate Nexus keystore
    $null = Set-NexusCert -Thumbprint $Certificate.Thumbprint

    # Add firewall rule for Nexus
    netsh advfirewall firewall add rule name="Nexus-8443" dir=in action=allow protocol=tcp localport=8443

    Write-Verbose "Starting up Nexus"
    Start-Service nexus

    Write-Warning "Waiting to give Nexus time to start up on 'https://${SubjectWithoutCn}:8443'"
    Wait-Site Nexus

    # Build Credential Object, Connect to Nexus
    if ($Credential = Get-ChocoEnvironmentProperty NexusCredential) {
        Write-Verbose "Using stored Nexus Credential"
    } elseif (Test-Path 'C:\programdata\sonatype-work\nexus3\admin.password') {
        $securePw = (Get-Content 'C:\programdata\sonatype-work\nexus3\admin.password') | ConvertTo-SecureString -AsPlainText -Force
        $Credential = [System.Management.Automation.PSCredential]::new('admin', $securePw)
    }

    # Connect to Nexus
    Connect-NexusServer -Hostname $SubjectWithoutCn -Credential $Credential -UseSSL

    # Push ClientSetup.ps1 to raw repo
    $ClientScript = "$PSScriptRoot\scripts\ClientSetup.ps1"
    (Get-Content -Path $ClientScript) -replace "{{hostname}}", "$((Get-NexusLocalServiceUri) -replace '^https?:\/\/')" | Set-Content -Path ($TemporaryFile = New-TemporaryFile).FullName
    $null = New-NexusRawComponent -RepositoryName 'choco-install' -File $TemporaryFile.FullName -Name "ClientSetup.ps1"

    $NexusPw = Get-ChocoEnvironmentProperty ChocoUserPassword -AsPlainText

    # Update all sources with credentials and the new path
    foreach ($Repository in Get-NexusRepository -Format nuget | Where-Object Type -eq 'hosted') {
        $RepositoryUrl = "https://${SubjectWithoutCn}:8443/repository/$($Repository.Name)/index.json"

        $ChocoArgs = @(
            'source',
            'add',
            "--name='$($Repository.Name)'",
            "--source='$RepositoryUrl'",
            '--priority=1',
            "--user='chocouser'",
            "--password='$NexusPw'"
        )
        & Invoke-Choco @ChocoArgs

        # Update Repository API key
        $chocoArgs = @('apikey', "--source='$RepositoryUrl'", "--api-key='$NuGetApiKey'")
        & Invoke-Choco @chocoArgs

        # Reset the NuGet v3 cache, such that it doesn't capture localhost as the FQDN
        Remove-NexusRepositoryFolder -RepositoryName $Repository.Name -Name v3
    }

    Update-Clixml -Properties @{
        NexusUri = "https://$($SubjectWithoutCn):8443"
        NexusRepo = "https://${SubjectWithoutCn}:8443/repository/ChocolateyInternal/index.json"
    }

    <# Jenkins #>
    $JenkinsHome = "C:\ProgramData\Jenkins\.jenkins"
    $JenkinsPort = 7443

    Set-JenkinsLocationConfiguration -Url "https://$($SubjectWithoutCn):$($JenkinsPort)" -Path $JenkinsHome\jenkins.model.JenkinsLocationConfiguration.xml

    # Generate Jenkins keystore
    Set-JenkinsCertificate -Thumbprint $Certificate.Thumbprint -Port $JenkinsPort

    # Add firewall rule for Jenkins
    netsh advfirewall firewall add rule name="Jenkins-$($JenkinsPort)" dir=in action=allow protocol=tcp localport=$JenkinsPort

    # Update job parameters in Jenkins
    $NexusUri = Get-ChocoEnvironmentProperty NexusUri
    Update-JenkinsJobParameters -Replacement @{
        "P_DST_URL" = "$NexusUri/repository/ChocolateyTest/index.json"
        "P_LOCAL_REPO_URL" = "$NexusUri/repository/ChocolateyTest/index.json"
        "P_TEST_REPO_URL" = "$NexusUri/repository/ChocolateyTest/index.json"
        "P_PROD_REPO_URL" = "$NexusUri/repository/ChocolateyInternal/index.json"
    }

    Update-Clixml -Properties @{
        JenkinsUri = "https://$($SubjectWithoutCn):$($JenkinsPort)"
    }

    <# CCM #>
    # Update the service certificate
    Set-CcmCertificate -CertificateThumbprint $Certificate.Thumbprint

    # Remove old CCM web binding, and add new CCM web binding
    Stop-CcmService
    Remove-CcmBinding
    New-CcmBinding -Thumbprint $Certificate.Thumbprint
    Start-CcmService

    # Create the site hosting the certificate import script on port 80
    # Only run this if it's a self-signed cert which has 10-year validity
    if ($Certificate.NotAfter -gt (Get-Date).AddYears(5)) {
        $IsSelfSigned = $true
        .\scripts\New-IISCertificateHost.ps1
    }

    # Generate Register-C4bEndpoint.ps1
    $EndpointScript = "$PSScriptRoot\scripts\Register-C4bEndpoint.ps1"

    Invoke-TextReplacementInFile -Path $EndpointScript -Replacement @{
        "{{ ClientSaltValue }}" = Get-ChocoEnvironmentProperty ClientSalt -AsPlainText
        "{{ ServiceSaltValue }}" = Get-ChocoEnvironmentProperty ServiceSalt -AsPlainText
        "{{ FQDN }}" = $SubjectWithoutCn

        # Set a default value for TrustCertificate if we're using a self-signed cert
        '(?<Parameter>\s+\$TrustCertificate)(?<Value>\s*=\s*\$true)?(?<Comma>,)?(?!\))' = "`${Parameter}$(
        if (Test-SelfSignedCertificate -Certificate $Certificate) {' = $true'}
        )`${Comma}"
    }

    Update-Clixml -Properties @{
        CCMWebPortal = "https://$($SubjectWithoutCn)/Account/Login"
        CCMServiceURL = "https://$($SubjectWithoutCn):24020/ChocolateyManagementService"
        CertSubject    = $SubjectWithoutCn
        CertThumbprint = $Certificate.Thumbprint
        CertExpiry     = $Certificate.NotAfter
        IsSelfSigned   = $IsSelfSigned
    }
}
end {
    $ErrorActionPreference = $DefaultEap
    Stop-Transcript

    Complete-C4bSetup -SkipBrowserLaunch
}