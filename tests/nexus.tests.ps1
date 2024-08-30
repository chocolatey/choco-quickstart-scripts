[CmdletBinding()]
Param(
    [Parameter(Mandatory)]
    [String]
    $Fqdn
)

. $PSScriptRoot/packages.ps1

Describe "Nexus Configuration" {
    Context "Installation Integrity" {
        BeforeAll {
            $nexus = C:\ProgramData\chocolatey\choco.exe list -r | ConvertFrom-Csv -Delimiter '|' -Header Package, Version | Where-Object Package -EQ nexus-repository
            $service = Get-Service nexus
        }

        It "Nexus package should be installed" {
            $nexus | Should -Not -BeNullOrEmpty
        }

        It "Nexus service is installed" {
            $service | Should -Not -BeNullOrEmpty
        }

        It "Nexus service is running" {
            $service.Status | Should -Be 'Running'
        }
    }
    Context "Services" {
        BeforeAll {
            $certStoreCertificate = Get-ChildItem Cert:\LocalMachine\TrustedPeople | Where-Object { "CN=$Fqdn" -like $_.Subject }
            $serviceCertificate = Get-RemoteCertificate -ComputerName $Fqdn -Port 8443

            $ConfigurationFile = Get-Content "C:\ProgramData\sonatype-work\nexus3\etc\nexus.properties"
        }

        It "Service has HSTS disabled" {
            $ConfigurationFile -contains 'jetty.https.stsMaxAge=-1' | Should -Be $true
        }

        It "Service is using port 8443" {
            $ConfigurationFile -contains 'application-port-ssl=8443' | Should -Be $true
        }

        It "Service is using jetty-https.xml" {
            $ConfigurationFile -contains 'nexus-args=${jetty.etc}/jetty.xml,${jetty.etc}/jetty-https.xml,${jetty.etc}/jetty-requestlog.xml' | Should -Be $true
        }

        It "Service is using the appropriate SSL Certificate" {
            $certStoreCertificate -eq $serviceCertificate | Should -Be $true
        }

        It "Service responds to web requests" {
            ([System.Net.WebRequest]::Create("https://$($Fqdn):8443") -as [System.net.HttpWebRequest]).GetResponse().StatusCode -eq 'OK' | Should -Be $true
        }
    }

    Context "Repository Configuration" {
        BeforeAll {
            $password = (Get-Content 'C:\ProgramData\sonatype-work\nexus3\admin.password') | ConvertTo-SecureString -AsPlainText -Force
            $credential = [System.Management.Automation.PSCredential]::new('admin',$password)
            . "C:\choco-setup\files\scripts\Get-Helpers.ps1"
            $null = Connect-NexusServer -Hostname $Fqdn -Credential $credential -UseSSL

            $repositories = Get-NexusRepository
        }
        It "ChocolateyInternal" {
            'ChocolateyInternal' -in $repositories.Name | Should -Be $true
        }

        It "ChocolateyTest" {
            'ChocolateyTest' -in $repositories.Name | Should -Be $true
        }

        It "choco-install" {
            'choco-install' -in $repositories.Name | Should -Be $true
        }

        It 'NuGet API-Key Realm is active' {
            'NuGetApiKey' -in (Get-NexusRealm -Active).id | Should -Be $true
        }
    }

    Context "Package Availability" {
        BeforeAll {
            if (([version] (C:\ProgramData\chocolatey\choco.exe --version).Split('-')[0]) -ge [version] '2.1.0') {
                choco cache remove
            }

            $packages = C:\ProgramData\chocolatey\choco.exe search -s ChocolateyInternal -r | ConvertFrom-Csv -Delimiter '|' -Header Package, Version
        }

        It "<Name> is in the repository" -ForEach @( $JointPackages + $RepositoryOnlyPackages ) {
            $Name -in $packages.Package | Should -Be $true
        }
    }
}
