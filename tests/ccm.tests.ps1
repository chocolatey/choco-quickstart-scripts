[CmdletBinding()]
Param(
    [Parameter(Mandatory)]
    [String]
    $Fqdn
)

Describe "Chocolatey Central Management Configuration" {
    Context "Services" {
        BeforeAll {
            $centralManagementServiceCertificate = Get-RemoteCertificate -Computername $Fqdn -Port 24020
            $expectedServiceCertificate = Get-ChildItem Cert:\LocalMachine\TrustedPeople | Where-Object { "CN=$Fqdn" -like $_.Subject }

            $centralManagementWebCertificate = Get-RemoteCertificate -ComputerName $Fqdn -Port 443
            $expectedWebCertificate = Get-ChildItem Cert:\LocalMachine\TrustedPeople | Where-Object { "CN=$Fqdn" -like $_.Subject }

            $centralManagementFirewallRule = (Get-NetFirewallRule -DisplayName Choco*)

            $CCMService = try { 
                ([System.Net.WebRequest]::Create("https://$($Fqdn):24020/ChocolateyManagementService") -as [System.net.HttpWebRequest]).GetResponse().StatusCode 
            } 
            catch { 
                $_.Exception.Message -match '400'
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