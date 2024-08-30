. $PSScriptRoot/packages.ps1
Describe "Server Integrity" {
    Context "Required Packages" {
        BeforeAll {
            $packages = C:\ProgramData\chocolatey\choco.exe list -r | ConvertFrom-Csv -Delimiter '|' -Header Package, Version
        }

        It "<Name> is installed"  -Foreach @( $JointPackages + $ServerOnlyPackages ) {
            $Name -in $packages.Package | Should -Be $true
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
