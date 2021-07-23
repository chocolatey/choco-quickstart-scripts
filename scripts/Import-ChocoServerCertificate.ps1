<#
.SYNOPSIS
Connects to the QDE server and adds its SSL certificate to the local certificate
store.
#>
[CmdletBinding()]
param(
    # The hostname of the QDE server to retrieve the SSL certificate from.
    [Parameter()]
    [Alias('NexusServer', 'NexusUrl')]
    [string]
    $ComputerName = '{{hostname}}'
)

add-type -TypeDefinition @"
using System;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

public static class Dummy {
    public static bool ReturnTrue(object sender,
        X509Certificate certificate,
        X509Chain chain,
        SslPolicyErrors sslPolicyErrors) { return true; }

    public static RemoteCertificateValidationCallback GetDelegate() {
        return new RemoteCertificateValidationCallback(Dummy.ReturnTrue);
    }
}
"@

$callback = [System.Net.ServicePointManager]::ServerCertificateValidationCallback = [dummy]::GetDelegate()

#Do it Matthias's way
function Get-RemoteCertificate {
    param(
        [Alias('CN')]
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$ComputerName,

        [Parameter(Position = 1)]
        [UInt16]$Port = 8443
    )

    $tcpClient = New-Object System.Net.Sockets.TcpClient($ComputerName, $Port)
    try {
        $tlsClient = New-Object System.Net.Security.SslStream($tcpClient.GetStream(),'false',$callback)
        $tlsClient.AuthenticateAsClient($ComputerName)

        return $tlsClient.RemoteCertificate -as [System.Security.Cryptography.X509Certificates.X509Certificate2]
    }
    finally {
        if ($tlsClient -is [IDisposable]) {
            $tlsClient.Dispose()
        }

        $tcpClient.Dispose()
    }
}

#Create request to CCM Service URL to get Certificate
Write-Output "Connecting to '$ComputerName' to get certificate information"
$certificateToAdd = Get-RemoteCertificate -ComputerName $ComputerName

#Create CertStore object where the certificate needs "put"
Write-Host "Adding Cert to LocalMachine\TrustedPeople Store"
$Store = [System.Security.Cryptography.X509Certificates.StoreName]::TrustedPeople
$Location = [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine
$certStore = New-Object System.Security.Cryptography.X509Certificates.X509Store($Store, $Location)

try {
    $certStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
    $certStore.Add($certificateToAdd)
}
finally {
    $certStore.Close()
    Remove-Variable certstore
}
