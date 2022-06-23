Describe "Server Integrity" {
    Context "Required Packages" {
        BeforeAll {
            $packages = choco list -lo -r | ConvertFrom-Csv -Delimiter '|' -Header Package, Version
        }
        
        It "<name> is installed"  -Foreach @(
            @{Name = 'dotnet-aspnetcoremodule-v2'}
            @{Name = 'dotnet-6.0-runtime'}
            @{Name = 'dotnet-6.0-aspnetruntime'}
            @{Name = 'KB2533623'}
            @{Name = 'chocolatey-management-web'}
            @{Name = 'chocolatey'}
            @{Name = 'vcredist2015'}
            @{Name = 'chocolatey-management-database'}
            @{Name = 'chocolatey-windowsupdate.extension'}
            @{Name = 'DotNet4.6.1'}
            @{Name = 'sql-server-express'}
            @{Name = 'KB3033929'}
            @{Name = 'Temurinjre'}
            @{Name = 'jenkins'}
            @{Name = 'nexus-repository'}
            @{Name = 'KB2919355'}
            @{Name = 'dotnetcore-sdk'}
            @{Name = 'microsoft-edge'}
            @{Name = 'vcredist140'}
            @{Name = 'chocolatey-management-service'} 
            @{Name = 'KB3063858'}
            @{Name = 'chocolatey-license'}
            @{Name = 'KB2999226'}
            @{Name = 'KB2919442'}
            @{Name = 'chocolatey-core.extension'}
            @{Name = 'KB3035131'}
            @{Name = 'chocolatey.extension'}
            @{Name = 'sql-server-management-studio'}
            @{Name = 'chocolatey-agent'}
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