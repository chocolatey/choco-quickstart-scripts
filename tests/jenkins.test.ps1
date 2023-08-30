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

        It "apache-httpcomponents-client-4-api plugin is installed" {
        
            'apache-httpcomponents-client-4-api' -in $plugins | Should -be $true
        }

        It "bouncycastle-api plugin is installed" {
        
            'bouncycastle-api' -in $plugins | Should -be $true
        }

        It "branch-api plugin is installed" {
        
            'branch-api' -in $plugins | Should -be $true
        }

        It "caffeine-api plugin is installed" {
        
            'caffeine-api' -in $plugins | Should -be $true
        }

        It "cloudbees-folder plugin is installed" {
        
            'cloudbees-folder' -in $plugins | Should -be $true
        }

        It "display-url-api plugin is installed" {
        
            'display-url-api' -in $plugins | Should -be $true
        }

        It "durable-task plugin is installed" {
        
            'durable-task' -in $plugins | Should -be $true
        }

        It "instance-identity plugin is installed" {
        
            'instance-identity' -in $plugins | Should -be $true
        }

        It "ionicons-api plugin is installed" {
        
            'ionicons-api' -in $plugins | Should -be $true
        }

        It "jakarta-activation-api plugin is installed" {
        
            'jakarta-activation-api' -in $plugins | Should -be $true
        }

        It "jakarta-mail-api plugin is installed" {
        
            'jakarta-mail-api' -in $plugins | Should -be $true
        }

        It "javax-activation-api plugin is installed" {
        
            'javax-activation-api' -in $plugins | Should -be $true
        }

        It "javax-mail-api plugin is installed" {
        
            'javax-mail-api' -in $plugins | Should -be $true
        }

        It "mailer plugin is installed" {
        
            'mailer' -in $plugins | Should -be $true
        }

        It "pipeline-groovy-lib plugin is installed" {
        
            'pipeline-groovy-lib' -in $plugins | Should -be $true
        }

        It "scm-api plugin is installed" {
        
            'scm-api' -in $plugins | Should -be $true
        }

        It "script-security plugin is installed" {
        
            'script-security' -in $plugins | Should -be $true
        }

        It "structs plugin is installed" {
        
            'structs' -in $plugins | Should -be $true
        }

        It "variant plugin is installed" {
        
            'variant' -in $plugins | Should -be $true
        }

        It "workflow-api plugin is installed" {
        
            'workflow-api' -in $plugins | Should -be $true
        }

        It "workflow-basic-steps plugin is installed" {
        
            'workflow-basic-steps' -in $plugins | Should -be $true
        }

        It "workflow-cps plugin is installed" {
        
            'workflow-cps' -in $plugins | Should -be $true
        }

        It "workflow-durable-task-step plugin is installed" {
        
            'workflow-durable-task-step' -in $plugins | Should -be $true
        }

        It "workflow-job plugin is installed" {
        
            'workflow-job' -in $plugins | Should -be $true
        }

        It "workflow-multibranch plugin is installed" {
        
            'workflow-multibranch' -in $plugins | Should -be $true
        }

        It "workflow-scm-step plugin is installed" {
        
            'workflow-scm-step' -in $plugins | Should -be $true
        }

        It "workflow-step-api plugin is installed" {
        
            'workflow-step-api' -in $plugins | Should -be $true
        }

        It "workflow-support plugin is installed" {
        
            'workflow-support' -in $plugins | Should -be $true
        }
    }
}