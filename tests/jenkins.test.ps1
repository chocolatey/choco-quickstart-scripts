Describe "Jenkins Configuration" {
    Context "Installation Integrity" {
        BeforeAll {
            $jenkins = choco list -lo -r | ConvertFrom-Csv -Delimiter '|' -Header Package,Version | Where-Object Package -eq 'jenkins'
            $service = Get-Service jenkins
        }

        It "Jenkins is installed" {
            $Jenkins | Should -Not -BeNullOrEmpty
        }

        It "Jenkins is version '2.222.4'" {
            $jenkins.version | Should -Be '2.222.4'
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
            $jobs = (Get-ChildItem 'C:\Program Files (x86)\Jenkins\jobs\' -Directory).Name
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
            $plugins = (Get-ChildItem 'C:\Program Files (x86)\Jenkins\plugins' -Directory).Name
        }
        It "<name> is installed" -Foreach @(
            @{Name = 'ace-editor' }
            @{Name = 'ant' }
            @{Name = 'antisamy-markup-formatter' }
            @{Name = 'apache-httpcomponents-client-4-api' }
            @{Name = 'bootstrap4-api' }
            @{Name = 'bouncycastle-api' }
            @{Name = 'branch-api' }
            @{Name = 'build-timeout' }
            @{Name = 'caffeine-api' }
            @{Name = 'checks-api' }
            @{Name = 'cloudbees-folder' }
            @{Name = 'command-launcher' }
            @{Name = 'credentials' }
            @{Name = 'credentials-binding' }
            @{Name = 'display-url-api' }
            @{Name = 'durable-task' }
            @{Name = 'echarts-api' }
            @{Name = 'email-ext' }
            @{Name = 'font-awesome-api' }
            @{Name = 'git' }
            @{Name = 'git-client' }
            @{Name = 'git-server' }
            @{Name = 'github' }
            @{Name = 'github-api' }
            @{Name = 'github-branch-source' }
            @{Name = 'gradle' }
            @{Name = 'handlebars' }
            @{Name = 'jackson2-api' }
            @{Name = 'jdk-tool' }
            @{Name = 'jjwt-api' }
            @{Name = 'jquery3-api' }
            @{Name = 'jsch' }
            @{Name = 'junit' }
            @{Name = 'ldap' }
            @{Name = 'lockable-resources' }
            @{Name = 'mailer' }
            @{Name = 'mapdb-api' }
            @{Name = 'matrix-auth' }
            @{Name = 'matrix-project' }
            @{Name = 'momentjs' }
            @{Name = 'okhttp-api' }
            @{Name = 'pam-auth' }
            @{Name = 'pipeline-build-step' }
            @{Name = 'pipeline-github-lib' }
            @{Name = 'pipeline-graph-analysis' }
            @{Name = 'pipeline-input-step' }
            @{Name = 'pipeline-milestone-step' }
            @{Name = 'pipeline-model-api' }
            @{Name = 'pipeline-model-definition' }
            @{Name = 'pipeline-model-extensions' }
            @{Name = 'pipeline-rest-api' }
            @{Name = 'pipeline-stage-step' }
            @{Name = 'pipeline-stage-tags-metadata' }
            @{Name = 'pipeline-stage-view' }
            @{Name = 'plain-credentials' }
            @{Name = 'plugin-util-api' }
            @{Name = 'popper-api' }
            @{Name = 'powershell' }
            @{Name = 'resource-disposer' }
            @{Name = 'scm-api' }
            @{Name = 'script-security' }
            @{Name = 'snakeyaml-api' }
            @{Name = 'ssh-credentials' }
            @{Name = 'ssh-slaves' }
            @{Name = 'structs' }
            @{Name = 'subversion' }
            @{Name = 'timestamper' }
            @{Name = 'token-macro' }
            @{Name = 'trilead-api' }
            @{Name = 'workflow-aggregator' }
            @{Name = 'workflow-api' }
            @{Name = 'workflow-basic-steps' }
            @{Name = 'workflow-cps' }
            @{Name = 'workflow-cps-global-lib' }
            @{Name = 'workflow-durable-task-step' }
            @{Name = 'workflow-job' }
            @{Name = 'workflow-multibranch' }
            @{Name = 'workflow-scm-step' }
            @{Name = 'workflow-step-api' }
            @{Name = 'workflow-support' }
            @{Name = 'ws-cleanup' }

        ) {
            $_.Name -in $plugins | Should -be $true
        }
    }
}