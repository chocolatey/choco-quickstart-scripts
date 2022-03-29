[CmdletBinding()]
Param(
    [Parameter(Mandatory)]
    [String]
    $Fqdn
)

Describe "Chocolatey Central Management Configuration" {
    Context "Services" {
        BeforeAll {
            function Get-RemoteCertificate {
                param(
                    [Alias('CN')]
                    [Parameter(Mandatory = $true, Position = 0)]
                    [string]$ComputerName,
            
                    [Parameter(Position = 1)]
                    [UInt16]$Port = 8443
                )
            
                $tcpClient = New-Object System.Net.Sockets.TcpClient($ComputerName, $Port)
                $sslProtocolType = [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
                try {
                    $tlsClient = New-Object System.Net.Security.SslStream($tcpClient.GetStream(), 'false', $callback)
                    $tlsClient.AuthenticateAsClient($ComputerName, $null, $sslProtocolType, $false)
            
                    return $tlsClient.RemoteCertificate -as [System.Security.Cryptography.X509Certificates.X509Certificate2]
                }
                finally {
                    if ($tlsClient -is [IDisposable]) {
                        $tlsClient.Dispose()
                    }
            
                    $tcpClient.Dispose()
                }
            }

            $centralManagementServiceCertificate = Get-RemoteCertificate -Computername $Fqdn -Port 24020
            $expectedServiceCertificate = Get-ChildItem Cert:\LocalMachine\TrustedPeople | Where-Object { $_.Subject -match "CN=$Fqdn" }

            $centralManagementWebCertificate = Get-RemoteCertificate -ComputerName $Fqdn -Port 443
            $expectedWebCertificate = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -match "CN=$Fqdn" }

            $centralmanagement
            $centralManagementFirewallRule = (Get-NetFirewallRule -DisplayName Choco*)

            $CCMService = try { 
                ([System.Net.WebRequest]::Create("https://$($Fqdn):24020/ChocolateyManagementService") -as [System.net.HttpWebRequest]).GetResponse().StatusCode 
            } 
            catch { 
                $_.Exception.Message -match '500'
            } 

        }

        It "Website is listening on port 443" {
            ([System.Net.WebRequest]::Create("https://$($Fqdn)") -as [System.net.HttpWebRequest]).GetResponse().StatusCode -eq 'OK' | Should -Be $true
        }
        It "Service is listening on port 24020" {
            $CCMService | Should -Be $true       
        }
        It "Web interface is using correct SSL Certificate" {
            $centralManagementWebCertificate -eq $expectedWebCertificate | Should -Be $true
        }
        It "Central Management service is using correct SSL Certificate" {
            $centralManagementServiceCertificate -eq $expectedServiceCertificate | Should -Be $true
        }
        It "Firewall rule for Central Management Service exists" {
            $centralManagementFirewallRule | Should -Not -BeNullOrEmpty
        }
        It "Firewall rule for Central Management Service is enabled" {
            $centralManagementFirewallRule.Enabled  | Should -Be $true
        }
    }
}