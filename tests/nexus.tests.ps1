[CmdletBinding()]
Param(
    [Parameter(Mandatory)]
    [String]
    $Fqdn
)

Describe "Nexus Configuration" {
    Context "Installation Integrity" {
        BeforeAll {
            $nexus = choco list -lo -r | ConvertFrom-Csv -Delimiter '|' -Header Package,Version | Where-Object Package -eq nexus-repository
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
    
            $certStoreCertificate = Get-ChildItem Cert:\LocalMachine\TrustedPeople | Where-Object {$_.Subject -match "CN=$Fqdn"}
            $serviceCertificate = Get-RemoteCertificate -ComputerName $Fqdn -Port 8443
            
            $ConfigurationFile = Get-Content "C:\ProgramData\sonatype-work\nexus3\etc\nexus.properties"
            $expectedConfiguation = @'
# Jetty section
# application-port=8081
# application-host=0.0.0.0
# nexus-args=${jetty.etc}/jetty.xml,${jetty.etc}/jetty-http.xml,${jetty.etc}/jetty-requestlog.xml
# nexus-context-path=/

# Nexus section
# nexus-edition=nexus-pro-edition
# nexus-features=\
#  nexus-pro-feature

# nexus.hazelcast.discovery.isEnabled=true
jetty.https.stsMaxAge=-1
application-port-ssl=8443
nexus-args=${jetty.etc}/jetty.xml,${jetty.etc}/jetty-https.xml,${jetty.etc}/jetty-requestlog.xml

'@
        }
    
        It "Service has HSTS disabled" {
            $ConfigurationFile[12] -eq 'jetty.https.stsMaxAge=-1' | Should -Be $true
        }

        It "Service is using port 8443" {
            $ConfigurationFile[13] -eq 'application-port-ssl=8443' | Should -Be $true
        }

        It "Service is using jetty-https.xml" {
            $ConfigurationFile[14] -eq 'nexus-args=${jetty.etc}/jetty.xml,${jetty.etc}/jetty-https.xml,${jetty.etc}/jetty-requestlog.xml' | Should -Be $true
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
            $packages = choco list -s ChocolateyInternal -r | ConvertFrom-Csv -Delimiter '|' -Header Package,Version
        }

        It "Chocolatey is in the repository" {
            'chocolatey' -in $packages.Package | Should -Be $true
        }

        It "Chocolatey is version 1.1.0" {
            ($packages | Where-Object Package -eq 'chocolatey').Version | Should -Be '1.1.0'
        }

        It "chocolatey.extension is in the repository" {
            'chocolatey.extension' -in $packages.Package | Should -Be $true
        }

        It "chocolatey.extension is version 4.1.0" {
            ($packages | Where-Object Package -eq 'chocolatey.extension').Version | Should -Be '4.1.0'
        }

        It "chocolatey-agent is in the repository" {
            'chocolatey-agent' -in $packages.Package | Should -Be $true
        }
       
        It "chocolatey-agent is version '1.0.0'" {
            ($packages | Where-Object Package -eq 'chocolatey-agent').Version | Should -Be '1.0.0'
        }

        It "chocolatey-core.extension is in the repository" {
            'chocolatey-core.extension' -in $packages.Package | Should -Be $true
        }

        It "chocolatey-core.extension is version '1.3.5.1'" {
            ($packages | Where-Object Package -eq 'chocolatey-core.extension').Version | Should -Be '1.3.5.1'
        }

        It "chocolatey-dotnetfx.extension is in the repository" {
            'chocolatey-dotnetfx.extension' -in $packages.Package | Should -Be $true
        }
        
        It "chocolatey-dotnetfx.extension is version '1.0.1'" {
            ($packages | Where-Object Package -eq 'chocolatey-dotnetfx.extension').Version | Should -Be '1.0.1'
        }

        It "chocolateygui is in the repository" {
            'chocolateygui' -in $packages.Package | Should -Be $true
        }

        It "chocolateygui is version '1.0.0'" {
            ($packages | Where-Object Package -eq 'chocolateygui').Version | Should -Be '1.0.0'
        }

        It "chocolateygui.extension is in the repository" {
            'chocolateygui.extension' -in $packages.Package | Should -Be $true
        }

        It "chocolateygui.extension is version '1.0.0'" {
            ($packages | Where-Object Package -eq 'chocolateygui.extension').Version | Should -Be '1.0.0'
        }

        It "chocolatey-license is in the repository" {
            'chocolatey-license' -in $packages.Package | Should -Be $true
        }

        It "chocolatey-management-database is in the repository" {
            'chocolatey-management-database' -in $packages.Package | Should -Be $true
        }

        It "chocolatey-management-database is version '0.8.0'" {
            ($packages | Where-Object Package -eq 'chocolatey-management-database').Version | Should -Be '0.8.0'
        }

        It "chocolatey-management-service is in the repository" {
            'chocolatey-management-service' -in $packages.Package | should -Be $true
        }

        It "chocolatey-management-service is version '0.8.0'" {
            ($packages | Where-Object Package -eq 'chocolatey-management-service').Version | Should -Be '0.8.0'
        }

        It "chocolatey-management-web is in the repository" {
            'chocolatey-management-web' -in $packages.Package | Should -Be $true
        }

        It "chocolatey-management-web is version '0.8.0'" {
            ($packages | Where-Object Package -eq 'chocolatey-management-web').Version | Should -Be '0.8.0'
        }

        It "DotNet4.5.2 is in the repository" {
            'dotnet4.5.2' -in $Packages.Package | Should -Be $true
        }

        It "dotnet4.5.2 is version '4.5.2.20140902'" {
            ($packages | Where-Object Package -eq 'dotnet4.5.2').Version | Should -Be '4.5.2.20140902'
        }

        It "dotnetfx is in the repository" {
            'dotnetfx' -in $packages.Package | Should -Be $true
        }

        It "dotnetfx is version '4.8.0.20190930'" {
            ($packages | Where-Object Package -eq 'dotnetfx').Version | Should -Be '4.8.0.20190930'
        }

        It "KB2919355 is in the repository" {
            'KB2919355' -in $packages.Package | Should -Be $true
        }

        It "KB2919355 is version '1.0.20160915'" {
            ($packages | Where-Object Package -eq 'KB2919355').Version | Should -Be '1.0.20160915'
        }

        It "KB2919442 is in the repository" {
            'KB2919442' -in $packages.Package | Should -Be $true
        }

        It "KB2919442 is version '1.0.20160915'" {
            ($packages | Where-Object Package -eq 'KB2919442').Version | Should -Be '1.0.20160915'
        }
    }
}