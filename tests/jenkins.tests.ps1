#requires -Modules C4B-Environment
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [String]$Fqdn,

    [PSCredential]$JenkinsCredential = $(
        if (Get-ChocoEnvironmentProperty JenkinsCredential) {
            Get-ChocoEnvironmentProperty JenkinsCredential
        } else {
            Get-Credential -UserName admin -Message "Jenkins Account"
        }
    )
)

Describe "Jenkins Configuration" {
    Context "Installation Integrity" {
        BeforeAll {
            $jenkins = C:\ProgramData\chocolatey\choco.exe list -r | ConvertFrom-Csv -Delimiter '|' -Header Package,Version | Where-Object Package -eq 'jenkins'
            $service = Get-Service jenkins
        }

        It "Jenkins package is installed" {
            $jenkins | Should -Not -BeNullOrEmpty
        }

        It "Service is installed" {
            $service | Should -Not -BeNullOrEmpty
        }

        It "Service is running" {
            $service.Status | Should -Be 'Running'
        }
    }

    Context "Required Scripts" {
        BeforeAll {
            $Scripts = (Get-ChildItem 'C:\Scripts' -Recurse -Filter *.ps1).Name
        }

        It "Get-UpdatedPackage.ps1 is present" {
            'Get-UpdatedPackage.ps1' -in $Scripts | Should -Be $true
        }

        It "Invoke-ChocolateyInternalizer.ps1 is present" {
            'Invoke-ChocolateyInternalizer.ps1' -in $Scripts | Should -Be $true
        }

        It "Update-ProdRepoFromTest.ps1 is present" {
            'Update-ProdRepoFromTest.ps1' -in $Scripts | Should -Be $true
        }
    }

    Context "Required Jobs" -Skip:$(-not $JenkinsCredential) {
        BeforeAll {
            $Jobs = (Invoke-JenkinsApi -Uri "https://$($FQDN):7443" -Slug "/api/json" -Credential $JenkinsCredential).jobs
        }

        It "'<_>' is present" -ForEach @(
            'Internalize packages from the Community Repository'
            'Update Production Repository'
            'Update test repository from Chocolatey Community Repository'
        ) {
            $Jobs.Name | Should -Contain $_
        }
    }

    Context "Web Interface" {
        It "Jenkins Web UI should be available" {
            ([System.Net.WebRequest]::Create("https://$($Fqdn):7443/login?from=%2F") -as [System.net.HttpWebRequest]).GetResponse().StatusCode -eq 'OK' | Should -Be $true
        }
    }

    Context "Required Plugins" -Skip:$(-not $JenkinsCredential) {
        BeforeDiscovery {
            $ExpectedPlugins = (Get-Content $PSScriptRoot\..\files\jenkins.json | ConvertFrom-Json).plugins
            $InstalledPlugins = (Invoke-JenkinsApi -Uri "https://$($Fqdn):7443" -Slug "/manage/pluginManager/api/json?depth=1" -Credential $JenkinsCredential).plugins
        }

        BeforeAll {
            $InstalledPlugins = (Invoke-JenkinsApi -Uri "https://$($Fqdn):7443" -Slug "/manage/pluginManager/api/json?depth=1" -Credential $JenkinsCredential).plugins
        }

        It "<_.name> plugin is installed" -ForEach $ExpectedPlugins {
            $PluginShortName, $PluginVersion = $_.name, $_.version
            $InstalledPlugins.Where{
                $_.shortName -eq $PluginShortName
            }.version | Should -Be $PluginVersion -Because "$($PluginShortName) should have been version '$($PluginVersion)'"
        }

        # During our builds, we should check we're not merging outdated plugins - but on customer systems, that may be the case.
        It "<_.shortName> is not outdated" -ForEach $InstalledPlugins -Skip:$(-not $env:CI) {
            $_.hasUpdate | Should -Be $false -Because "$($_.longName) ('$($_.shortName)') should not have an available update"
        }
    }
}