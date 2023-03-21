<#
.SYNOPSIS
C4B Quick-Start Guide Jenkins setup script

.DESCRIPTION
- Performs the following Jenkins setup
    - Install of Jenkins package
    - Silent upgrade of Jenkins plugins
    - Creation of Chocolatey-specific jobs from template files
    - Disable of first-run prompts
#>
[CmdletBinding()]
param(
    # Hostname of your C4B Server
    [string]$HostName = $(Get-Content "$env:SystemDrive\choco-setup\logs\ssl.json" | ConvertFrom-Json).CertSubject,
    # Repo where you're installing Jenkins from, usually CCR
    [string]$Source = 'https://community.chocolatey.org/api/v2/',
    # API key of your Nexus repo, for Chocolatey Jenkins jobs to use
    [string]$NuGetApiKey = $(Get-Content "$env:SystemDrive\choco-setup\logs\nexus.json" | ConvertFrom-Json).NuGetApiKey
)

begin {
    if($host.name -ne 'ConsoleHost') {
        Write-Warning "This script cannot be ran from within PowerShell ISE"
        Write-Warning "Please launch powershell.exe as an administrator, and run this script again"
        break
    }
}


process {
    $DefaultEap = $ErrorActionPreference
    $ErrorActionPreference = 'Stop'
    Start-Transcript -Path "$env:SystemDrive\choco-setup\logs\Start-C4bJenkinsSetup-$(Get-Date -Format 'yyyyMMdd-HHmmss').txt"

    # Dot-source helper functions
    . .\scripts\Get-Helpers.ps1

    # Install temurin11jre to meet JRE11 depdency of Jenkins
    $chocoArgs = @('install', 'temurin11jre', '-y', "--source='$Source'", '--no-progress')
    & choco @chocoArgs

    # Install Jenkins
    $chocoArgs = @('install', 'jenkins', '-y', "--source='$Source'", '--no-progress', "--version='2.387.1'")
    & choco @chocoArgs

    Write-Host "Giving Jenkins 30 seconds to complete background setup..." -ForegroundColor Green
    Start-Sleep -Seconds 30  # Jenkins needs a moment

    # Long winded way to get the scripts for Jenkins jobs into the right place, but easier to maintain going forward
    $root = Split-Path -Parent $MyInvocation.MyCommand.Definition
    $systemRoot = $env:SystemDrive + '\'
    $JenkinsRoot = Join-Path $root -ChildPath 'jenkins'
    $jenkinsScripts = Join-Path $JenkinsRoot -ChildPath 'scripts'

    #Set home directory of Jenkins install
    $JenkinsHome = 'C:\ProgramData\Jenkins\.jenkins'

    Copy-Item $jenkinsScripts $systemRoot -Recurse -Force

    Stop-Service -Name Jenkins
    $JenkinsConfigPath = Join-Path $JenkinsHome "config.xml"
    Copy-Item -Path $JenkinsConfigPath -Destination "$($JenkinsConfigPath).old" -Force

    # Ignore "first startup"
    Write-Host "Disabling Jenkins first-run prompts" -ForegroundColor Green
    Get-Content -Path "$($JenkinsConfigPath).old" |
        Where-Object { $_ -notlike "*<installStateName>*" } |
        Set-Content -Path $JenkinsConfigPath

    Write-Host "Updating Jenkins plugins" -ForegroundColor Green
    $JenkinsPlugins = @{
        'ant' = '481.v7b_09e538fcca'
        'apache-httpcomponents-client-4-api' = '4.5.14-150.v7a_b_9d17134a_5'
        'bootstrap5-api' = '5.2.2-1'
        'bouncycastle-api' = '2.27'
        'branch-api' = '2.1071.v1a_188a_562481'
        'build-timeout' = '1.28'
        'caffeine-api' = '2.9.3-65.v6a_47d0f4d1fe'
        'checks-api' = '2.0.0'
        'commons-lang3-api' = '3.12.0-36.vd97de6465d5b_'
        'commons-text-api' = '1.10.0-36.vc008c8fcda_7b_'
        'credentials-binding' = '523.vd859a_4b_122e6'
        'credentials' = '1224.vc23ca_a_9a_2cb_0'
        'display-url-api' = '2.3.7'
        'durable-task' = '504.vb10d1ae5ba2f'
        'echarts-api' = '5.4.0-2'
        'email-ext' = '2.95'
        'cloudbees-folder' = '6.815.v0dd5a_cb_40e0e'
        'font-awesome-api' = '6.3.0-1'
        'git-client' = '4.2.0'
        'git' = '5.0.0'
        'github-api' = '1.303-417.ve35d9dd78549'
        'github-branch-source' = '1701.v00cc8184df93'
        'github' = '1.37.0'
        'gradle' = '2.3.2'
        'instance-identity' = '142.v04572ca_5b_265'
        'ionicons-api' = '45.vf54fca_5d2154'
        'jackson2-api' = '2.14.2-319.v37853346a_229'
        'jakarta-activation-api' = '2.0.1-3'
        'jakarta-mail-api' = '2.0.1-3'
        'jjwt-api' = '0.11.5-77.v646c772fddb_0'
        'javax-activation-api' = '1.2.0-6'
        'javax-mail-api' = '1.6.2-9'
        'jaxb' = '2.3.8-1'
        'jquery3-api' = '3.6.3-1'
        'junit' = '1189.v1b_e593637fa_e'
        'ldap' = '671.v2a_9192a_7419d'
        'mailer' = '448.v5b_97805e3767'
        'matrix-auth' = '3.1.6'
        'matrix-project' = '785.v06b_7f47b_c631'
        'mina-sshd-api-common' = '2.9.2-50.va_0e1f42659a_a'
        'mina-sshd-api-core' = '2.9.2-50.va_0e1f42659a_a'
        'okhttp-api' = '4.10.0-132.v7a_7b_91cef39c'
        'antisamy-markup-formatter' = '159.v25b_c67cd35fb_'
        'pam-auth' = '1.10'
        'workflow-aggregator' = '596.v8c21c963d92d'
        'pipeline-graph-analysis' = '202.va_d268e64deb_3'
        'workflow-api' = '1208.v0cc7c6e0da_9e'
        'workflow-basic-steps' = '1010.vf7a_b_98e847c1'
        'pipeline-build-step' = '487.va_823138eee8b_'
        'pipeline-model-definition' = '2.2121.vd87fb_6536d1e'
        'pipeline-model-extensions' = '2.2121.vd87fb_6536d1e'
        'pipeline-github-lib' = '42.v0739460cda_c4'
        'workflow-cps' = '3641.vf58904a_b_b_5d8'
        'pipeline-groovy-lib' = '629.vb_5627b_ee2104'
        'pipeline-input-step' = '466.v6d0a_5df34f81'
        'workflow-job' = '1284.v2fe8ed4573d4'
        'pipeline-milestone-step' = '111.v449306f708b_7'
        'pipeline-model-api' = '2.2121.vd87fb_6536d1e'
        'workflow-multibranch' = '733.v109046189126'
        'workflow-durable-task-step' = '1234.v019404b_3832a'
        'pipeline-rest-api' = '2.31'
        'workflow-scm-step' = '400.v6b_89a_1317c9a_'
        'pipeline-stage-step' = '305.ve96d0205c1c6'
        'pipeline-stage-tags-metadata' = '2.2121.vd87fb_6536d1e'
        'pipeline-stage-view' = '2.31'
        'workflow-step-api' = '639.v6eca_cd8c04a_a_'
        'workflow-support' = '839.v35e2736cfd5c'
        'plain-credentials' = '143.v1b_df8b_d3b_e48'
        'plugin-util-api' = '3.1.0'
        'powershell' = '2.0'
        'resource-disposer' = '0.21'
        'scm-api' = '631.v9143df5b_e4a_a'
        'script-security' = '1229.v4880b_b_e905a_6'
        'snakeyaml-api' = '1.33-95.va_b_a_e3e47b_fa_4'
        'ssh-slaves' = '2.877.v365f5eb_a_b_eec'
        'ssh-credentials' = '305.v8f4381501156'
        'sshd' = '3.275.v9e17c10f2571'
        'structs' = '324.va_f5d6774f3a_d'
        'timestamper' = '1.22'
        'token-macro' = '321.vd7cc1f2a_52c8'
        'trilead-api' = '2.84.v72119de229b_7'
        'variant' = '59.vf075fe829ccb'
        'ws-cleanup' = '0.44'  
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
            '{{hostname}}', $HostName |
            Set-Content -Path $_.FullName
    }
    #endregion

    Write-Host "Starting Jenkins service back up" -ForegroundColor Green
    Start-Service -Name Jenkins

    # Save useful params to JSON
    $JenkinsJson = @{
        JenkinsUri = "http://localhost:8080"
        JenkinsUser = "admin"
        JenkinsPw = $(Get-Content "$JenkinsHome\secrets\initialAdminPassword")
    }
    $JenkinsJson | ConvertTo-Json | Out-File "$env:SystemDrive\choco-setup\logs\jenkins.json"

    Write-Host 'Jenkins setup complete' -ForegroundColor Green
    Write-Host 'Login to Jenkins at: http://locahost:8080' -ForegroundColor Green
    Write-Host 'Initial default Jenkins admin user password:' -ForegroundColor Green
    Write-Host "$(Get-Content "$JenkinsHome\secrets\initialAdminPassword")" -ForegroundColor Green

    Write-Host 'Writing README to Desktop; this file contains login information for all C4B services.'
    New-QuickstartReadme

    Write-Host 'Cleaning up temporary data'
    Remove-JsonFiles

    $Message = 'The CCM, Nexus & Jenkins sites will open in your browser in 10 seconds. Press any key to skip this.'
    $Timeout = New-TimeSpan -Seconds 10
    $Stopwatch = [System.Diagnostics.Stopwatch]::new()
    $Stopwatch.Start()
    Write-Host $Message -NoNewline -ForegroundColor Green
    do {
        # wait for a key to be available:
        if ([Console]::KeyAvailable) {
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

    if (-not ($keyInfo)) {
        Write-Host "`nOpening CCM, Nexus & Jenkins sites in your browser." -ForegroundColor Green
        $Readme = 'file:///C:/Users/Public/Desktop/README.html'
        $Ccm = "https://${hostname}/Account/Login"
        $Nexus = "https://${hostname}:8443"
        $Jenkins = 'http://localhost:8080'
        try {
            Start-Process msedge.exe "$Readme","$Ccm", "$Nexus", "$Jenkins"
        }
        catch {
            Start-Process chrome.exe "$Readme","$Ccm", "$Nexus", "$Jenkins"
        }
    }

    $ErrorActionPreference = $DefaultEap
    Stop-Transcript
}