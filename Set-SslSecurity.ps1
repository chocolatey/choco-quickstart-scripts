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
[CmdletBinding()]
[OutputType([string])]
param(
    # The certificate thumbprint that identifies the target SSL certificate in
    # the local machine certificate stores.
    # Ignored if supplied alongside -Subject.
    [Parameter(ValueFromPipeline)]
    [string]
    $Thumbprint = (Get-ChildItem Cert:\LocalMachine\TrustedPeople -Recurse | Select-Object -ExpandProperty Thumbprint),

    # The certificate subject that identifies the target SSL certificate in
    # the local machine certificate stores.
    [Parameter()]
    [string]
    $Subject,

    #If using a wildcard certificate, provide a DNS name you want to use to access services secured by the certificate.
    [Parameter()]
    [string]
    $CertificateDnsName,

    # This option security hardens your C4B server, in scenarios where you have a non-self-signed certificate.
    # It adds a role and user credential to the Nexus server, which is used to authenticate the source setup on a client endpoint.
    # It also adds a Client and Service Salt to further secure the SSL conneciton with CCM.
    # Finally, it updates the Register-C4bEndpoint.ps1 script to use these new credentials.
    [Parameter()]
    [switch]
    $Hardened,

    # The C4B server hostname for which to generate a new self-signed certificate.
    # Ignored/unused if a certificate thumbprint or subject is supplied.
    [Parameter()]
    [string]
    $Hostname = [System.Net.Dns]::GetHostName(),

    # API key of your Nexus repo, to add to the source setup on C4B Server.
    [string]$NuGetApiKey = $(Get-Content "$env:SystemDrive\choco-setup\logs\nexus.json" | ConvertFrom-Json).NuGetApiKey
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
    Start-Transcript -Path "$env:SystemDrive\choco-setup\logs\Set-SslCertificate-$(Get-Date -Format 'yyyyMMdd-HHmmss').txt"
    
    # Dot-source helper functions
    . .\scripts\Get-Helpers.ps1
    #Collect current certificate configuration
    $Certificate = if ($Subject) {
        Get-Certificate -Subject $Subject
    }
    elseif ($Thumbprint) {
        Get-Certificate -Thumbprint $Thumbprint
    }

    if (-not $CertificateDnsName) {
        $SubjectWithoutCn = $Certificate.Subject -replace 'CN=', ''
    } 
    else {
        $SubjectWithoutCn = $CertificateDnsName
    }

    if ($Hardened) {
        $CertValidation = Test-SelfSignedCertificate -Certificate $Certificate
        if ($CertValidation) {
            throw "Self-Signed Certificates not valid for Internet-Hardened configurations. Please use a valid purchased or generated certificate."
        }
    }

    #Nexus
    #Stop Services/Processes/Websites required
    Stop-Service nexus

    # Put certificate in TrustedPeople
    Copy-CertToStore -Certificate $Certificate

    # Generate Nexus keystore
    New-NexusCert -Thumbprint $Certificate.Thumbprint

    # Add firewall rule for Nexus
    netsh advfirewall firewall add rule name="Nexus-8443" dir=in action=allow protocol=tcp localport=8443
    
    Write-Verbose "Starting up Nexus"
    Start-Service nexus

    Write-Warning "Waiting to give Nexus time to start up"
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::tls12
    do {
        $response = try {
            Invoke-WebRequest "https://${SubjectWithoutCn}:8443" -UseBasicParsing -ErrorAction Stop
            Start-Sleep -Seconds 3
        }
        catch {
            
        }
            
    } until($response.StatusCode -eq '200')
    Write-Host "Nexus is ready!"

    choco source remove --name="'ChocolateyInternal'"
    $RepositoryUrl = "https://${SubjectWithoutCn}:8443/repository/ChocolateyInternal/"

    #Build Credential Object, Connect to Nexus
    $securePw = (Get-Content 'C:\programdata\sonatype-work\nexus3\admin.password') | ConvertTo-SecureString -AsPlainText -Force
    $Credential = [System.Management.Automation.PSCredential]::new('admin', $securePw)
    
    # Connect to Nexus
    Connect-NexusServer -Hostname $SubjectWithoutCn -Credential $Credential -UseSSL

    # Add updated scripts to raw repo in Nexus

    #Push ChocolateyInstall.ps1 to raw repo
    $ScriptDir = "$env:SystemDrive\choco-setup\files\scripts"
    $ChocoInstallScript = "$ScriptDir\ChocolateyInstall.ps1"
    (Get-Content -Path $ChocoInstallScript) -replace "{{hostname}}", $SubjectWithoutCn | Set-Content -Path $ChocoInstallScript
    New-NexusRawComponent -RepositoryName 'choco-install' -File "$ChocoInstallScript"

    #Push ClientSetup.ps1 to raw repo
    $ClientScript = "$ScriptDir\ClientSetup.ps1"
    (Get-Content -Path $ClientScript) -replace "{{hostname}}", $SubjectWithoutCn | Set-Content -Path $ClientScript
    New-NexusRawComponent -RepositoryName 'choco-install' -File $ClientScript

    if ($Hardened) {        
        # Disable anonymous authentication
        Set-NexusAnonymousAuth -Disabled
        
        if (-not (Get-NexusRole -Role 'chocorole' -ErrorAction SilentlyContinue)) {
            # Create Nexus role
            $RoleParams = @{
                Id          = "chocorole"
                Name        = "chocorole"
                Description = "Role for web enabled choco clients"
                Privileges  = @('nx-repository-view-nuget-*-browse', 'nx-repository-view-nuget-*-read', 'nx-repository-view-raw-*-read', 'nx-repository-view-raw-*-browse')
            }
            New-NexusRole @RoleParams
        }

        if (-not (Get-NexusUser -User 'chocouser' -ErrorAction SilentlyContinue)) {
            $NexusPw = [System.Web.Security.Membership]::GeneratePassword(32, 12)
            # Create Nexus user
            $UserParams = @{
                Username     = 'chocouser'
                Password     = ($NexusPw | ConvertTo-SecureString -AsPlainText -Force)
                FirstName    = 'Choco'
                LastName     = 'User'
                EmailAddress = 'chocouser@foo.com'
                Status       = 'Active'
                Roles        = 'chocorole'
            }
            New-NexusUser @UserParams
        }

        $ChocoArgs = @(
            'source',
            'add',
            "--name='ChocolateyInternal'",
            "--source='$RepositoryUrl'",
            '--priority=1',
            "--user='chocouser'",
            "--password='$NexusPw'"
        )
        & choco @ChocoArgs
    
    }
    
    else {
        $ChocoArgs = @(
            'source',
            'add',
            "--name='ChocolateyInternal'",
            "--source='$RepositoryUrl'",
            '--priority=1'
        )
        & choco @ChocoArgs
    }

    # Update Repository API key
    $chocoArgs = @('apikey', "--source='$RepositoryUrl'", "--api-key='$NuGetApiKey'")
    & choco @chocoArgs

    # Remove old CCM web binding, and add new CCM web binding
    Stop-CcmService
    Remove-CcmBinding
    New-CcmBinding
    Start-CcmService

    # Create the site hosting the certificate import script on port 80
    # Only run this if it's a self-signed cert which has 10-year validity
    if ($Certificate.NotAfter -gt (Get-Date).AddYears(5)) {
        $IsSelfSigned = $true
        .\scripts\New-IISCertificateHost.ps1
    }
    
    # Generate Register-C4bEndpoint.ps1
    $EndpointScript = "$ScriptDir\Register-C4bEndpoint.ps1"

    if ($Hardened) {

        $ClientSaltValue = New-CCMSalt
        $ServiceSaltValue = New-CCMSalt
        $ScriptBlock = @"
`$ClientCommunicationSalt = '$ClientSaltValue'
`$ServiceCommunicationSalt = '$ServiceSaltValue'
`$FQDN = '$SubjectWithoutCN'
`$NexusUserPW = '$NexusPw'

# Touch NOTHING below this line
`$User = 'chocouser'
`$SecurePassword = `$NexusUserPW | ConvertTo-SecureString -AsPlainText -Force
`$RepositoryUrl = "https://`$(`$fqdn):8443/repository/ChocolateyInternal/"

`$credential = [pscredential]::new(`$user, `$securePassword)

`$downloader = [System.Net.WebClient]::new()
`$downloader.Credentials = `$credential

`$script =  `$downloader.DownloadString("https://`$(`$FQDN):8443/repository/choco-install/ClientSetup.ps1")

`$params = @{
    Credential      = `$Credential
    ClientSalt      = `$ClientCommunicationSalt
    ServerSalt      = `$ServiceCommunicationSalt
    InternetEnabled = `$true
    RepositoryUrl   = `$RepositoryUrl
}

& ([scriptblock]::Create(`$script)) @params
"@

        $ScriptBlock | Set-Content -Path $EndpointScript

        #Agent Setup
        $agentArgs = @{
            CentralManagementServiceUrl = "https://$($SubjectWithoutCn):24020/ChocolateyManagementService"
            ServiceSalt = $ServiceSaltValue
            ClientSalt = $ClientSaltValue
        }

        Install-ChocolateyAgent @agentArgs
    }

    else {

         #Agent Setup
         $agentArgs = @{
            CentralManagementServiceUrl = "https://$($SubjectWithoutCn):24020/ChocolateyManagementService"
        }

        Install-ChocolateyAgent @agentArgs

        #Register endpoint script
        (Get-Content -Path $EndpointScript) -replace "{{hostname}}", "'$SubjectWithoutCn'" | Set-Content -Path $EndpointScript
        if ($IsSelfSigned) {
            $ScriptBlock = @"
`$downloader = New-Object -TypeName System.Net.WebClient
Invoke-Expression (`$downloader.DownloadString("http://`$(`$HostName):80/Import-ChocoServerCertificate.ps1"))
"@
        (Get-Content -Path $EndpointScript) -replace "# placeholder if using a self-signed cert", $ScriptBlock | Set-Content -Path $EndpointScript
        }
    }
    

    # Save useful params to JSON
    $SslJson = @{
        CertSubject    = $SubjectWithoutCn
        CertThumbprint = $Certificate.Thumbprint
        CertExpiry     = $Certificate.NotAfter
        IsSelfSigned   = $IsSelfSigned
    }
    $SslJson | ConvertTo-Json | Out-File "$env:SystemDrive\choco-setup\logs\ssl.json"
}

end {

    # Hand back the created/found certificate to the caller.
    $Certificate

    $ErrorActionPreference = $DefaultEap
    Stop-Transcript
}
