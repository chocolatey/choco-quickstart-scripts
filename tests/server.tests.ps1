Describe "Server Integrity" {
    Context "Required Packages" {
        BeforeAll {
            $packages = choco list -lo -r | ConvertFrom-Csv -Delimiter '|' -Header Package, Version
        }
        It "<name> is installed"  -Foreach @(
            @{Name = 'KB2533623' ; Version = "2.0.0" }
            @{Name = 'chocolatey-management-web' ; Version = "0.8.0" }
            @{Name = 'chocolatey' ; Version = "1.1.0" }
            @{Name = 'dotnetcore-windowshosting' ; Version = "3.1.16" }
            @{Name = 'vcredist2015' ; Version = "14.0.24215.20170201" }
            @{Name = 'chocolatey-management-database'; Version = "0.8.0" }
            @{Name = 'chocolatey-windowsupdate.extension'; Version = "1.0.4" }
            @{Name = 'DotNet4.6.1' ; Version = "4.6.01055.20170308" }
            @{Name = 'sql-server-express' ; Version = "2019.20200409" }
            @{Name = 'KB3033929' ; Version = "1.0.5" }
            @{Name = 'Temurinjre'; Version = "17.0.2.800" }
            @{Name = 'jenkins'; Version = "2.222.4" }
            @{Name = 'nexus-repository' ; Version = "3.38.1.01" }
            @{Name = 'aspnetcore-runtimepackagestore'; Version = "3.1.16" }
            @{Name = 'KB2919355' ; Version = "1.0.20160915" }
            @{Name = 'dotnetcore-sdk' ; Version = "3.1.410" }
            @{Name = 'microsoft-edge' ; Version = "99.0.1150.55" }
            @{Name = 'vcredist140' ; Version = "14.31.31103" }
            @{Name = 'chocolatey-management-service' ; Version = "0.8.0" } 
            @{Name = 'KB3063858' ; Version = "1.0.0" }
            @{Name = 'chocolatey-license' ; Version = "2022.08.18" }
            @{Name = 'KB2999226' ; Version = "1.0.20181019" }
            @{Name = 'KB2919442' ; Version = "1.0.20160915" }
            @{Name = 'chocolatey-core.extension' ; Version = "1.3.5.1" }
            @{Name = 'KB3035131' ; Version = "1.0.3" }
            @{Name = 'chocolatey.extension' ; Version = "4.1.0" }
            @{Name = 'sql-server-management-studio'  ; Version = "15.0.18410.0" }
            @{Name = 'chocolatey-agent' ; Version = "1.0.0" }
        ) {
            $_.Name -in $packages.Package | Should -Be $true
        }
    }

    Context "Readme File" {
        It "Readme file was created" {
            Test-Path (Join-Path "$env:PUBLIC\Desktop" -ChildPath 'Readme.html') | Should -Be $true
        }
    }

    Context "Server Roles and Features" {
        It "Web Server role is installed" {
            (Get-WindowsFeature -Name Web-Server).Installed | Should -Be $true
        }

        It "IIS Application Init Role is installed" {
            (Get-WindowsFeature -Name Web-AppInit).Installed | Should -Be $true
        }
    }

    Context "Log Files" {
        BeforeAll {
            $Logs = Get-ChildItem C:\choco-setup\logs -Recurse -Filter *.txt
        }

        It "<File> log file was created during installation" -Foreach @(
            @{File = 'Set-SslCertificate'}
            @{File = 'Start-C4bCcmSetup'}
            @{File = 'Start-C4bJenkinsSetup'}
            @{File = 'Start-C4bNexusSetup'}
            @{File = 'Start-C4bSetup'}
        ) {
            Test-Path "C:\choco-setup\logs\$($_.File)*.txt" | Should -Be $true
        }
    }
}