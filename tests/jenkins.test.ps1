Describe "Jenkins Configuration" {
    Context "Installation Integrity" {
        BeforeAll {
            $jenkins = choco list -r | ConvertFrom-Csv -Delimiter '|' -Header Package,Version | Where-Object Package -eq 'jenkins'
            $service = Get-Service jenkins
        }

        It "Jenkins is installed" {
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

        It "ConvertTo-ChocoObject is present" {
            'ConvertTo-ChocoObject.ps1' -in $Scripts | Should -Be $true
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

    Context "Required Jobs" {
        BeforeAll {
            $jobs = (Get-ChildItem 'C:\ProgramData\Jenkins\.jenkins\jobs\' -Directory).Name
        }

        It "'Internalize packages from the Community Repository' is present" {
            'Internalize packages from the Community Repository' -in $jobs | Should -Be $true
        }

        It "'Update Production Repository' is present" {
            'Update Production Repository' -in $jobs | Should -Be $true
        }

        It "'Update test repository from Chocolatey Community Repository' is present" {
            'Update test repository from Chocolatey Community Repository' -in $jobs | Should -Be $true
        }
    }

    Context "Web Interface" {
        It "Jenkins Web UI should be available" {
            ([System.Net.WebRequest]::Create('http://localhost:8080/login?from=%2F') -as [System.net.HttpWebRequest]).GetResponse().StatusCode -eq 'OK' | Should -Be $true
        }
    }

    Context "Required Plugins" {
        BeforeAll {
            $plugins = (Get-ChildItem 'C:\ProgramData\Jenkins\.jenkins\plugins\' -Directory).Name
        }
        It "powershell is installed" {
        
            'powershell' -in $plugins | Should -be $true
        }
    }
}