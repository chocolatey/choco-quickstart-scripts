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
    $Thumbprint = (Get-ChildItem Cert:\LocalMachine\TrustedPeople -Recurse | Select-Object -ExpandProperty thumbprint),

    # The certificate subject that identifies the target SSL certificate in
    # the local machine certificate stores.
    [Parameter()]
    [string]
    $Subject,

    #If using a wildcard certificate, provide a DNS name you want to use to access services secured by the certificate.
    [Parameter()]
    [string]
    $CertificateDnsName,

    # The QDE hostname for which to generate a new self-signed certificate.
    # Ignored/unused if a certificate thumbprint or subject is supplied.
    [Parameter()]
    [string]
    $Hostname = [System.Net.Dns]::GetHostName()
)

begin {

    $DefaultEap = $ErrorActionPreference
    $ErrorActionPreference = 'Stop'
    Start-Transcript -Path "$env:SystemDrive\choco-setup\logs\Set-SslCertificate-$(Get-Date -Format 'yyyyMMdd-HHmmss').txt"
    
    # Dot-source helper functions
    . .\scripts\Get-Helpers.ps1
}

process {

    #Collect current certificate configuration
    $Certificate = if ($Subject) {
        Get-Certificate -Subject $Subject
    }
    elseif ($Thumbprint) {
        Get-Certificate -Thumbprint $Thumbprint
    }

    if(-not $CertificateDnsName) {
        $SubjectWithoutCn = $Certificate.Subject -replace 'CN=',''
    } 
    else {
        $SubjectWithoutCn = $CertificateDnsName
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
            Invoke-WebRequest "https://${SubjectWithoutCn}:8443" -ErrorAction Stop
            Start-Sleep -Seconds 3
        }
        catch {
            
        }
            
    } until($response.StatusCode -eq '200')
    Write-Host "Nexus is ready!"

    # Update Repository URI
    choco source remove --name="'ChocolateyInternal'"
    $RepositoryUrl = "https://${SubjectWithoutCn}:8443/repository/ChocolateyInternal/"
    choco source add --name="'ChocolateyInternal'" --source="'$RepositoryUrl'" --allow-self-service --priority=1

    #Stop Central Management components
    Stop-Service chocolatey-central-management
    Get-Process chocolateysoftware.chocolateymanagement.web* | Stop-Process -ErrorAction SilentlyContinue -Force
    Stop-Website ChocolateyCentralManagement

    #Remove bindings
    netsh http delete sslcert ipport=0.0.0.0:443

    #Generate new bindings for Central Management Website
    Write-Verbose "Removing existing bindings and binding ${SubjectWithoutCn}:443 to Chocolatey Central Management"
    $guid = [Guid]::NewGuid().ToString("B")
    netsh http add sslcert ipport=0.0.0.0:443 certhash=$Thumbprint certstorename=MY appid="$guid"
    Get-WebBinding -Name ChocolateyCentralManagement | Remove-WebBinding
    New-WebBinding -Name ChocolateyCentralManagement -Protocol https -Port 443 -SslFlags 0 -IpAddress '*'

    #Start the components back up
    try {
        Start-Website ChocolateyCentralManagement -ErrorAction Stop
    }
    catch {
        #Try again...
        Start-Website ChocolateyCentralManagement  -ErrorAction SilentlyContinue

        #Try again, this time with a hammer
        if((Get-Website -Name ChocolateyCentralManagement).State -ne 'Started') {
            Start-Website ChocolateyCentralManagement -ErrorAction SilentlyContinue
        }
    }
    finally {
        if((Get-Website -Name ChocolateyCentralManagement).State -ne 'Started') {
            Write-Warning "Unable to start Chocolatey Central Management website, please start manually in IIS"
        }
    }
    Start-Service chocolatey-central-management
    # Hand back the created/found certificate to the caller.
    $Certificate

    # Create the site hosting the certificate import script on port 80
    # ONluy run this if it's a self-signed cert which has 10-year validity
    if ($Certificate.NotAfter -gt (Get-Date).AddYears(5)) {
        $IsSelfSigned = $true
        .\scripts\New-IISCertificateHost.ps1
    }

    # Add updated scripts to raw repo in Nexus

    #Build Credential Object, Connect to Nexus
    $securePw = (Get-Content 'C:\programdata\sonatype-work\nexus3\admin.password') | ConvertTo-SecureString -AsPlainText -Force
    $Credential = [System.Management.Automation.PSCredential]::new('admin', $securePw)

    # Connect to Nexus
    Connect-NexusServer -Hostname $SubjectWithoutCn -Credential $Credential -UseSSL

    #Push ChocolateyInstall.ps1 to raw repo
    $ScriptDir = "$env:SystemDrive\choco-setup\files\scripts"
    $ChocoInstallScript = "$ScriptDir\ChocolateyInstall.ps1"
    (Get-Content -Path $ChocoInstallScript) -replace "{{hostname}}", $SubjectWithoutCn | Set-Content -Path $ChocoInstallScript
    New-NexusRawComponent -RepositoryName 'choco-install' -File "$ChocoInstallScript"

    #Push ClientSetup.ps1 to raw repo
    $ClientScript = "$ScriptDir\ClientSetup.ps1"
    (Get-Content -Path $ClientScript) -replace "{{hostname}}", $SubjectWithoutCn | Set-Content -Path $ClientScript
    New-NexusRawComponent -RepositoryName 'choco-install' -File $ClientScript

    # Generate Register-C4bEndpoint.ps1
    $EndpointScript = "$ScriptDir\Register-C4bEndpoint.ps1"
    (Get-Content -Path $EndpointScript) -replace "{{hostname}}", "'$SubjectWithoutCn'" | Set-Content -Path $EndpointScript
    if ($IsSelfSigned) {
        $ScriptBlock = @"
`$downloader = New-Object -TypeName System.Net.WebClient
Invoke-Expression (`$downloader.DownloadString("http://`$(`$HostName):80/Import-ChocoServerCertificate.ps1"))
"@
        (Get-Content -Path $EndpointScript) -replace "# placeholder if using a self-signed cert", $ScriptBlock | Set-Content -Path $EndpointScript
    }

    # Save useful params to JSON
    $SslJson = @{
        CertSubject  = $SubjectWithoutCn
        CertThumbprint = $Certificate.Thumbprint
        CertExpiry = $Certificate.NotAfter
        IsSelfSigned = $IsSelfSigned
    }
    $SslJson | ConvertTo-Json | Out-File "$env:SystemDrive\choco-setup\logs\ssl.json"
}

end {
    $ErrorActionPreference = $DefaultEap
    Stop-Transcript
}