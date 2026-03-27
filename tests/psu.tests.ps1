#requires -Modules C4B-Environment, Universal
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [String]$Fqdn,

    [PSCredential]$PSUCredential = $(
        if (Get-ChocoEnvironmentProperty PSUCredential) {
            Get-ChocoEnvironmentProperty PSUCredential
        } else {
            Get-Credential -UserName admin -Message "PowerShell Universal Account"
        }
    )
)

Describe "PowerShell Universal Configuration" -Skip:$(-not (Get-ChocoEnvironmentProperty PowerShellUniversalUri)) {
    BeforeAll {
        $null = Connect-PSUServer -ComputerName "$FQDN:5000" -Credential $PSUCredential
    }

    Context "Installation Integrity" {
        BeforeAll {
            $package = C:\ProgramData\chocolatey\choco.exe list -r | ConvertFrom-Csv -Delimiter '|' -Header Package, Version | Where-Object Package -EQ 'powershelluniversal'
            $service = Get-Service PowerShellUniversal
        }

        It "PSU package is installed" {
            $package | Should -Not -BeNullOrEmpty
        }

        It "Service is installed" {
            $service | Should -Not -BeNullOrEmpty
        }

        It "Service is running" {
            $service.Status | Should -Be 'Running'
        }
    }

    Context "Required Scripts" -Skip:$(-not $PSUCredential) {
        BeforeAll {
            $Scripts = Get-PSUScript
        }

        It "'<_>' is present" -ForEach @(
            'Get-UpdatedPackage'
            'Invoke-ChocolateyInternalizer'
            'Update-ProdRepoFromTest'
        ) {
            $Scripts.Name | Should -Contain $_
        }
    }

    Context "Web Interface" {
        It "PowerShell Universal Web UI should be available" {
            ([System.Net.WebRequest]::Create("$(Get-ChocoEnvironmentProperty PowerShellUniversalUri)/login") -as [System.net.HttpWebRequest]).GetResponse().StatusCode -eq 'OK' | Should -Be $true
        }
    }
}