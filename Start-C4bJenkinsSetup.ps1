<#
.SYNOPSIS
C4B Quick-Start Guide Jenkins setup script

.DESCRIPTION
- Performs the following Jenkins setup
    - Install of Jenkins package
    - Pin to version 2.222.4
    - Silent upgrade of Jenkins plugins
    - Creation of Chocolatey-specific jobs from template files
    - Disable of first-run prompts
#>
[CmdletBinding()]
param(
    # Hostname of your C4B Server
    [string]$HostName = 'localhost',
    # Repo where you're installing Jenkins from, usually CCR
    [string]$Source = 'https://chocolatey.org/api/v2/',
    # API key of your Nexus repo, for Chocolatey Jenkins jobs to use
    [string]$NuGetApiKey = $(Get-Content "$env:SystemDrive\choco-setup\logs\nexus.json" | ConvertFrom-Json).NuGetApiKey
)

$DefaultEap = $ErrorActionPreference
$ErrorActionPreference = 'Stop'
Start-Transcript -Path "$env:SystemDrive\choco-setup\logs\Start-C4bJenkinsSetup-$(Get-Date -Format 'yyyyMMdd-HHmmss').txt"

# Install Jenkins
choco install jenkins -y --source $Source --no-progress --version 2.222.4
choco pin add --name="'jenkins'" --version="'2.222.4'" --reason="'Next version is a breaking change; see online QDE documentation FAQ'"

Write-Host "Giving Jenkins 30 seconds to complete background setup..." -ForegroundColor Green
Start-Sleep -Seconds 30  # Jenkins needs a moment

Stop-Service -Name Jenkins
$JenkinsHome = "${env:ProgramFiles(x86)}\Jenkins"
$JenkinsConfigPath = Join-Path $JenkinsHome "config.xml"
Copy-Item -Path $JenkinsConfigPath -Destination "$($JenkinsConfigPath).old" -Force

# Ignore "first startup"
Write-Host "Disabling Jenkins first-run prompts" -ForegroundColor Green
Get-Content -Path "$($JenkinsConfigPath).old" |
    Where-Object { $_ -notlike "*<installStateName>*" } |
    Set-Content -Path $JenkinsConfigPath

Write-Host "Updating Jenkins plugins" -ForegroundColor Green
$JenkinsPlugins = @{
    'cloudbees-folder' = '6.15'
    'trilead-api' = '1.0.13'
    'antisamy-markup-formatter' = '2.1'
    'structs' = '1.23'
    'workflow-step-api' = '2.23'
    'token-macro' = '2.13'
    'build-timeout' = '1.20'
    'credentials' = '2.5'
    'plain-credentials' = '1.7'
    'ssh-credentials' = '1.18.1'
    'credentials-binding' = '1.24'
    'scm-api' = '2.6.4'
    'workflow-api' = '2.46'
    'timestamper' = '1.13'
    'caffeine-api' = '2.9.1-23.v51c4e2c879c8'
    'script-security' = '1.77'
    'plugin-util-api' = '1.7.1'
    'font-awesome-api' = '5.15.2-1'
    'popper-api' = '1.16.1-1'
    'jquery3-api' = '3.5.1-2'
    'bootstrap4-api' = '4.6.0-1'
    'snakeyaml-api' = '1.29.1'
    'jackson2-api' = '2.12.3'
    'echarts-api' = '4.9.0-3'
    'display-url-api' = '2.3.5'
    'workflow-support' = '3.8'
    'workflow-job' = '2.41'
    'checks-api' = '1.5.0'
    'junit' = '1.51'
    'matrix-project' = '1.18'
    'resource-disposer' = '0.16'
    'ws-cleanup' = '0.39'
    'ant' = '1.11'
    'durable-task' = '1.37'
    'workflow-durable-task-step' = '2.35'
    'command-launcher' = '1.6'
    'jdk-tool' = '1.5'
    'bouncycastle-api' = '2.20'
    'ace-editor' = '1.1'
    'workflow-scm-step' = '2.13'
    'workflow-cps' = '2.92'
    'apache-httpcomponents-client-4-api' = '4.5.13-1.0'
    'mailer' = '1.32.1'
    'workflow-basic-steps' = '2.21'
    'gradle' = '1.36'
    'pipeline-milestone-step' = '1.3.2'
    'pipeline-input-step' = '2.12'
    'pipeline-stage-step' = '2.5'
    'pipeline-graph-analysis' = '1.11'
    'pipeline-rest-api' = '2.19'
    'handlebars' = '3.0.8'
    'momentjs' = '1.1.1'
    'pipeline-stage-view' = '2.19'
    'pipeline-build-step' = '2.13'
    'pipeline-model-api' = '1.8.5'
    'pipeline-model-extensions' = '1.8.5'
    'jsch' = '0.1.55.2'
    'git-client' = '3.6.0'
    'git-server' = '1.9'
    'workflow-cps-global-lib' = '2.19'
    'branch-api' = '2.6.2'
    'workflow-multibranch' = '2.24'
    'pipeline-stage-tags-metadata' = '1.8.5'
    'pipeline-model-definition' = '1.8.5'
    'lockable-resources' = '2.11'
    'workflow-aggregator' = '2.6'
    'jjwt-api' = '0.11.2-9.c8b45b8bb173'
    'okhttp-api' = '3.14.9'
    'github-api' = '1.123'
    'git' = '4.6.0'
    'github' = '1.33.1'
    'github-branch-source' = '2.9.9'
    'pipeline-github-lib' = '1.0'
    'mapdb-api' = '1.0.9.0'
    'subversion' = '2.14.4'
    'ssh-slaves' = '1.31.5'
    'matrix-auth' = '2.6.7'
    'pam-auth' = '1.6'
    'ldap' = '1.25'
    'email-ext' = '2.83'
    'powershell' = '1.5'
}

foreach ($PluginName in $JenkinsPlugins.Keys) {
    $PluginUri = 'https://updates.jenkins-ci.org/download/plugins/{0}/{1}/{0}.hpi' -f $PluginName,$JenkinsPlugins[$PluginName]
    $PluginPath = '{0}/plugins/{1}.hpi' -f $JenkinsHome, $PluginName
    [System.Net.WebClient]::New().DownloadFile($PluginUri,$PluginPath)
}

#region Job Config
Write-Host "Creating Chocolatey Jobs" -ForegroundColor Green
Get-ChildItem "$env:SystemDrive\choco-setup\files\jenkins" | Copy-Item -Destination "$JenkinsHome\jobs\" -Recurse


Get-ChildItem -Path "$JenkinsHome\jobs" -Recurse -File -Filter 'config.xml' | ForEach-Object {
    (Get-Content -Path $_.FullName -Raw) -replace
        '{{NugetApiKey}}', $NuGetApiKey -replace
        '{{hostname}}', 'localhost' |
        Set-Content -Path $_.FullName
}
#endregion

Write-Host "Starting Jenkins service back up" -ForegroundColor Green
Start-Service -Name Jenkins

# Save useful params to JSON
$JenkinsJson = @{
    JenkinsUri = "http://localhost:8080"
    JenkinsUser = "admin"
    JenkinsPw = $(Get-Content "${env:ProgramFiles(x86)}\Jenkins\secrets\initialAdminPassword")
}
$JenkinsJson | ConvertTo-Json | Out-File "$env:SystemDrive\choco-setup\logs\jenkins.json"

Write-Host 'Jenkins setup complete' -ForegroundColor Green
Write-Host 'Login to Jenkins at: http://locahost:8080' -ForegroundColor Green
Write-Host 'Initial default Jenkins admin user password:' -ForegroundColor Green
Write-Host "$(Get-Content "${env:ProgramFiles(x86)}\Jenkins\secrets\initialAdminPassword")" -ForegroundColor Green

$Message = 'The CCM, Nexus & Jenkins sites will open in your browser in 10 seconds. Press any key to skip this.'
$Timeout = New-TimeSpan -Seconds 10
$Stopwatch = [System.Diagnostics.Stopwatch]::new()
$Stopwatch.Start()
Write-Host $Message -NoNewline -ForegroundColor Green
do
{
    # wait for a key to be available:
    if ([Console]::KeyAvailable)
    {
        # read the key, and consume it so it won't
        # be echoed to the console:
        $keyInfo = [Console]::ReadKey($true)
        Write-Host "`nSkipping the Opening of sites in your browser." -ForegroundColor Green
        # exit loop
        break
    }
    # write a dot and wait a second
    Write-Host '.' -NoNewline -ForegroundColor Green
    Start-Sleep -Seconds 1
}
while ($Stopwatch.Elapsed -lt $Timeout)
$Stopwatch.Stop()

if (-not ($keyInfo)){
    Write-Host "`nOpening CCM, Nexus & Jenkins sites in your browser." -ForegroundColor Green
    $Ccm = 'http://localhost/Account/Login'
    $Nexus = 'http://localhost:8081/#browse/browse'
    $Jenkins = 'http://localhost:8080'
    try{
        Start-Process msedge.exe "$Ccm","$Nexus","$Jenkins"
    }
    catch {
        Start-Process chrome.exe "$Ccm","$Nexus","$Jenkins"
    }
}

$ErrorActionPreference = $DefaultEap
Stop-Transcript
