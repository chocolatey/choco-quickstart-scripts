<#
.SYNOPSIS
C4B Quick-Start Guide Jenkins setup script

.DESCRIPTION
- Performs the following Jenkins setup
    - Install of Jenkins package
    - Silent upgrade of Jenkins plugins
    - Creation of Chocolatey-specific jobs from template files
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
    if ($host.name -ne 'ConsoleHost') {
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

    # Enviornment variable used to disbale jenkins instal login prompts
    [Environment]::SetEnvironmentVariable('JAVA_OPTS', '-Djenkins.install.runSetupWizard=false', 'Machine')

    # Install Jenkins
    $chocoArgs = @('install', 'jenkins', '--version=2.414.1', '-y', "--source='$Source'", '--no-progress')
    & choco @chocoArgs

    Write-Host "Giving Jenkins 30 seconds to complete background setup..." -ForegroundColor Green
    Start-Sleep -Seconds 30  # Jenkins needs a moment

    # Disabling inital setup prompts
    $JenkinsHome = "C:\ProgramData\Jenkins\.jenkins"

    $JenkinsVersion = (choco list jenkins --exact --limit-output).Split('|')[1]
    $JenkinsVersion | Out-File -FilePath $JenkinsHome\jenkins.install.UpgradeWizard.state -Encoding utf8
    $JenkinsVersion | Out-File -FilePath $JenkinsHome\jenkins.install.InstallUtil.lastExecVersion -Encoding utf8

    # Set the external hostname, such that it's ready for use. This may change, but we've pinned Jenkin's version.
    @"
<?xml version='1.1' encoding='UTF-8'?>
<jenkins.model.JenkinsLocationConfiguration>
<adminAddress>address not configured yet &lt;nobody@nowhere&gt;</adminAddress>
<jenkinsUrl>http://$($HostName):8080</jenkinsUrl>
</jenkins.model.JenkinsLocationConfiguration>
"@ | Out-File -FilePath $JenkinsHome\jenkins.model.JenkinsLocationConfiguration.xml -Encoding utf8

    #region BCrypt Password
    if (-not (Test-Path "$PSScriptRoot\bcrypt.net.0.1.0\lib\net35\BCrypt.Net.dll")) {
        $BCryptNugetUri = 'https://www.nuget.org/api/v2/package/BCrypt.Net/0.1.0'
        $ZipPath = "$PSScriptRoot\bcrypt.net.0.1.0.zip"

        Invoke-WebRequest -Uri $BCryptNugetUri -OutFile $ZipPath -UseBasicParsing
        Expand-Archive -Path $ZipPath
    }

    Add-Type -Path "$PSScriptRoot\bcrypt.net.0.1.0\lib\net35\BCrypt.Net.dll"
    $Salt = [bcrypt.net.bcrypt]::generatesalt(15)

    $JenkinsCred = [System.Net.NetworkCredential]::new(
        "admin",
        (New-ServicePassword -Length 32)
    )

    $AdminUserPath = Resolve-Path "$JenkinsHome\users\admin_*\config.xml"
    # Can't load as XML document as file is XML v1.1
    (Get-Content $AdminUserPath) -replace '<passwordHash>#jbcrypt:.+</passwordHash>',
    "<passwordHash>#jbcrypt:$([bcrypt.net.bcrypt]::hashpassword($JenkinsCred.Password, $Salt))</passwordHash>" |
    Set-Content $AdminUserPath -Force
    #endregion

    # Long winded way to get the scripts for Jenkins jobs into the right place, but easier to maintain going forward
    $root = Split-Path -Parent $MyInvocation.MyCommand.Definition
    $systemRoot = $env:SystemDrive + '\'
    $JenkinsRoot = Join-Path $root -ChildPath 'jenkins'
    $jenkinsScripts = Join-Path $JenkinsRoot -ChildPath 'scripts'

    #Set home directory of Jenkins install
    $JenkinsHome = 'C:\ProgramData\Jenkins\.jenkins'

    Copy-Item $jenkinsScripts $systemRoot -Recurse -Force

    Stop-Service -Name Jenkins

    #region Jenkins Plugin Install & Update 
    # Defining required plugins
    # Plugin Versions Last Updated for Jenkins V 2.414.1 on 08-25-2023
    $JenkinsPlugins = @{
        'apache-httpcomponents-client-4-api' = '4.5.14-208.v438351942757'
        'bouncycastle-api' = '2.29'
        'branch-api' = '2.1122.v09cb_8ea_8a_724'
        'caffeine-api' = '3.1.8-133.v17b_1ff2e0599'
        'cloudbees-folder' = '6.848.ve3b_fd7839a_81'
        'display-url-api' = '2.3.9'
        'durable-task' = '523.va_a_22cf15d5e0'
        'instance-identity' = '173.va_37c494ec4e5'
        'ionicons-api' = '56.v1b_1c8c49374e'
        'jakarta-activation-api' = '2.0.1-3'
        'jakarta-mail-api' = '2.0.1-3'
        'javax-activation-api' = '1.2.0-6'
        'javax-mail-api' = '1.6.2-9'
        'mailer' = '463.vedf8358e006b_'
        'pipeline-groovy-lib' = '671.v07c339c842e8'
        'scm-api' = '676.v886669a_199a_a_'
        'script-security' = '1273.v66c1964f0dfd'
        'structs' = '325.vcb_307d2a_2782'
        'variant' = '59.vf075fe829ccb'
        'workflow-api' = '1261.va_2ff5204f17e'
        'workflow-basic-steps' = '1042.ve7b_140c4a_e0c'
        'workflow-cps' = '3773.v505e0052522c'
        'workflow-durable-task-step' = '1289.v4d3e7b_01546b_'
        'workflow-job' = '1341.vd9fa_65f771dd'
        'workflow-multibranch' = '756.v891d88f2cd46'
        'workflow-scm-step' = '415.v434365564324'
        'workflow-step-api' = '639.v6eca_cd8c04a_a_'
        'workflow-support' = '848.v5a_383b_d14921'
    }

    # Performance is killed by Invoke-WebRequest's progress bars, turning them off to speed this up
    $ProgressPreference = 'SilentlyContinue'

    # Downloading Jenkins Plugins
    Write-Host "Downloading Jenkins Plugins"
    foreach ($PluginName in $JenkinsPlugins.Keys) {
        $PluginUri = if ($JenkinsPlugins[$PluginName] -ne "latest") {
            'https://updates.jenkins-ci.org/download/plugins/{0}/{1}/{0}.hpi' -f $PluginName, $JenkinsPlugins[$PluginName]
        }
        else {
            "https://updates.jenkins-ci.org/latest/$($PluginName).hpi"
        }
        $PluginPath = '{0}/plugins/{1}.hpi' -f $jenkinsHome, $PluginName
        if (-not (Test-Path $PluginPath)) {
            try {
                Invoke-WebRequest -Uri $PluginUri -OutFile $PluginPath -UseBasicParsing -ErrorAction Stop
            }
            catch {
                # We have internalized the required plugins for jobs we provide
                Write-Warning "Could not download '$($PluginName)' from '$($PluginUri)': $($_)"
            }
        }
    }

    # Restore default progress bar setting
    $ProgressPreference = 'Continue'
    #endregion

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
        JenkinsUri  = "http://$($HostName):8080"
        JenkinsUser = "admin"
        JenkinsPw   = $JenkinsCred.Password
    }
    $JenkinsJson | ConvertTo-Json | Out-File "$env:SystemDrive\choco-setup\logs\jenkins.json"

    Write-Host 'Jenkins setup complete' -ForegroundColor Green
    Write-Host 'Login to Jenkins at: http://$($HostName):8080' -ForegroundColor Green
    Write-Host 'Initial default Jenkins admin user password:' -ForegroundColor Green
    Write-Host "Admin Password is '$($JenkinsCred.Password)'" -ForegroundColor Green

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
            Start-Process msedge.exe "$Readme", "$Ccm", "$Nexus", "$Jenkins"
        }
        catch {
            Start-Process chrome.exe "$Readme", "$Ccm", "$Nexus", "$Jenkins"
        }
    }

    $ErrorActionPreference = $DefaultEap
    Stop-Transcript
}