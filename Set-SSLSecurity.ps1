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

    #region Functions
    function Get-Certificate {
        [CmdletBinding()]
        param(
            [Parameter()]
            [string]
            $Thumbprint,

            [Parameter()]
            [string]
            $Subject
        )

        $filter = if ($Thumbprint) {
            { $_.Thumbprint -eq $Thumbprint }
        }
        else {
            { $_.Subject -like "CN=$Subject" }
        }

        $cert = Get-ChildItem -Path Cert:\LocalMachine\My, Cert:\LocalMachine\TrustedPeople |
        Where-Object $filter -ErrorAction Stop |
        Select-Object -First 1

        if ($null -eq $cert) {
            throw "Certificate either not found, or other issue arose."
        }
        else {
            Write-Host "Certification validation passed" -ForegroundColor Green
            $cert
        }
    }


    function New-NexusCert {
        [CmdletBinding()]
        param(
            [Parameter()]
            $Thumbprint
        )

        if ((Test-Path C:\ProgramData\nexus\etc\ssl\keystore.jks)) {
            Remove-Item C:\ProgramData\nexus\etc\ssl\keystore.jks -Force
        }

        $KeyTool = "C:\ProgramData\nexus\jre\bin\keytool.exe"
        $password = "chocolatey" | ConvertTo-SecureString -AsPlainText -Force
        $certificate = Get-ChildItem Cert:\LocalMachine\TrustedPeople\ | Where-Object { $_.Thumbprint -eq $Thumbprint } | Sort-Object | Select-Object -First 1

        Write-Host "Exporting .pfx file to C:\, will remove when finished" -ForegroundColor Green
        $certificate | Export-PfxCertificate -FilePath C:\cert.pfx -Password $password
        Get-ChildItem -Path c:\cert.pfx | Import-PfxCertificate -CertStoreLocation Cert:\LocalMachine\My -Exportable -Password $password
        Write-Warning -Message "You'll now see prompts and other outputs, things are working as expected, don't do anything"
        $string = ("chocolatey" | & $KeyTool -list -v -keystore C:\cert.pfx) -match '^Alias.*'
        $currentAlias = ($string -split ':')[1].Trim()

        $passkey = '9hPRGDmfYE3bGyBZCer6AUsh4RTZXbkw'
        & $KeyTool -importkeystore -srckeystore C:\cert.pfx -srcstoretype PKCS12 -srcstorepass chocolatey -destkeystore C:\ProgramData\nexus\etc\ssl\keystore.jks -deststoretype JKS -alias $currentAlias -destalias jetty -deststorepass $passkey
        & $KeyTool -keypasswd -keystore C:\ProgramData\nexus\etc\ssl\keystore.jks -alias jetty -storepass $passkey -keypass chocolatey -new $passkey

        $xmlPath = 'C:\ProgramData\nexus\etc\jetty\jetty-https.xml'
        [xml]$xml = Get-Content -Path 'C:\ProgramData\nexus\etc\jetty\jetty-https.xml'
        foreach ($entry in $xml.Configure.New.Where{ $_.id -match 'ssl' }.Set.Where{ $_.name -match 'password' }) {
            $entry.InnerText = $passkey
        }

        $xml.OuterXml | Set-Content -Path $xmlPath

        Remove-Item C:\cert.pfx

        $nexusPath = 'C:\ProgramData\sonatype-work\nexus3'
        $configPath = "$nexusPath\etc\nexus.properties"

        $configString = @'
jetty.https.stsMaxAge=-1
application-port-ssl=8443
nexus-args=${jetty.etc}/jetty.xml,${jetty.etc}/jetty-https.xml,${jetty.etc}/jetty-requestlog.xml
'@

        $configString | Add-Content -Path $configPath
        
        $xmlPath = 'C:\ProgramData\nexus\etc\jetty\jetty-https.xml'
        [xml]$xml = Get-Content -Path 'C:\ProgramData\nexus\etc\jetty\jetty-https.xml'
        foreach ($entry in $xml.Configure.New.Where{ $_.id -match 'ssl' }.Set.Where{ $_.name -match 'password' }) {
            $entry.InnerText = $passkey
        }

        $xml.OuterXml | Set-Content -Path $xmlPath

    }

    function Register-NetshBinding {
        [CmdletBinding()]
        param(
            [Parameter()]
            [string]
            $Hash = $Thumbprint,

            [Parameter()]
            [string]
            $Guid = $((New-Guid).ToString("B")),

            [Parameter()]
            [string]
            $CertStore = "TrustedPeople"
        )
        $ports = @('24020')

        foreach ($port in $ports) {
            & netsh http add sslcert ipport=0.0.0.0:$($port) certhash=$($Hash) appid=$($Guid) certstorename=$($CertStore)
        }
    }

    function Get-NetshSslEntries {
        $txtBindings = (& netsh http show sslcert) | Select-Object -Skip 3 | Out-String
        $newLine = [System.Environment]::NewLine
        $txtbindings = $txtBindings -split "$newLine$newLine"
        $sslEntries = foreach ($binding in $txtbindings) {
            if ($binding) {
                $binding = $binding -replace "  ", "" -split ": "
                $hostNameIPPort = ($binding[1] -split "`n")[0] -split ":"
                [pscustomobject]@{
                    HostNameIP      = $hostNameIPPort[0]
                    Port            = $hostNameIPPort[1]
                    CertificateHash = ($binding[2] -split "`n" -replace '[^a-zA-Z0-9]', '')[0]
                }
            }
        }

        # return entries, even if empty
        return $sslEntries
    }
    
    #endregion Functions
}
process {

    #Collect current certificate configuration
    $Certificate = if ($Subject) {
        Get-Certificate -Subject $Subject
    }
    elseif ($Thumbprint) {
        Get-Certificate -Thumbprint $Thumbprint
    }

    #Nexus
    #Stop Services/Processes/Websites required
    Stop-Service nexus

    # Generate Nexus keystore
    New-NexusCert -Thumbprint $Certificate.Thumbprint

    Write-Verbose "Starting up Nexus"
    Start-Service nexus

    Write-Warning "Waiting to give Nexus time to start up"
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::tls12
    do {
        $response = try {
            Invoke-WebRequest "https://${hostname}:8443" -ErrorAction Stop
            Start-Sleep -Seconds 3
        }
        catch {
            
        }
            
    } until($response.StatusCode -eq '200')
    Write-Host "Nexus is ready!"

    #Stop Central Management components
    Stop-Service chocolatey-central-management
    Get-Process chocolateysoftware.chocolateymanagement.web* | Stop-Process -ErrorAction SilentlyContinue -Force
    Stop-Website ChocolateyCentralManagement

    # Setup the new bindings
    Register-NetshBinding -Hash $Certificate.Thumbprint

    Write-Verbose "Removing existing bindings and binding ${hostname}:443 to Chocolatey Central Management"
    $guid = [Guid]::NewGuid().ToString("B")
    netsh http add sslcert ipport=0.0.0.0:443 certhash=$Thumbprint certstorename=MY appid="$guid"
    Get-WebBinding -Name ChocolateyCentralManagement | Remove-WebBinding
    New-WebBinding -Name ChocolateyCentralManagement -Protocol https -Port 443 -SslFlags 0 -IpAddress '*'

    #Start the components back up
    Start-Website ChocolateyCentralManagement
    Start-Service chocolatey-central-management
    # Hand back the created/found certificate to the caller.
    $Certificate
}

end {
    $Message = 'The CCM, Nexus & Jenkins sites will open in your browser in 10 seconds. Press any key to skip this.'
    $Timeout = New-TimeSpan -Seconds 10
    $Stopwatch = [System.Diagnostics.Stopwatch]::new()
    $Stopwatch.Start()
    Write-Host $Message -NoNewline -ForegroundColor Green
    do {
        # wait for a key to be available:
        if ([Console]::KeyAvailable) {
            # read the key, and consume it so it won't
            # be echoed to the console:
            $keyInfo = [Console]::ReadKey($true)
            Write-Host "`nSkipping the Opening of sites in your browser." -ForegroundColor Green
            # exit loop
            break
        }
        # write a dot and wait a second
        Write-Host '.' -NoNewline -ForegroundColor Green
        Start-Sleep -Seconds 1
    }
    while ($Stopwatch.Elapsed -lt $Timeout)
    $Stopwatch.Stop()

    if (-not ($keyInfo)) {
        Write-Host "`nOpening CCM, Nexus & Jenkins sites in your browser." -ForegroundColor Green
        $Ccm = "https://${hostname}/Account/Login"
        $Nexus = "https://${hostname}:8443/#browse/browse"
        $Jenkins = 'http://localhost:8080'
        try {
            Start-Process msedge.exe "$Ccm", "$Nexus", "$Jenkins"
        }
        catch {
            Start-Process chrome.exe "$Ccm", "$Nexus", "$Jenkins"
        }
    }

    $ErrorActionPreference = $DefaultEap
    Stop-Transcript
}