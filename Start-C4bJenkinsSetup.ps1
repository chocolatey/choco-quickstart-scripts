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
    $chocoArgs = @('install', 'jenkins', '--version=2.401.2', '-y', "--source='$Source'", '--no-progress')
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
    $JenkinsPlugins = @{
        'ant' = '487.vd79d090d4ea_e'
        'apache-httpcomponents-client-4-api' = '4.5.14-150.v7a_b_9d17134a_5'
        'bootstrap5-api' = '5.2.2-5'
        'bouncycastle-api' = '2.28'
        'branch-api' = '2.1092.vda_3c2a_a_f0c11'
        'build-timeout' = '1.30'
        'caffeine-api' = '3.1.6-115.vb_8b_b_328e59d8'
        'checks-api' = '2.0.0'
        'commons-lang3-api' = '3.12.0-36.vd97de6465d5b_'
        'commons-text-api' = '1.10.0-36.vc008c8fcda_7b_'
        'credentials-binding' = '604.vb_64480b_c56ca_'
        'credentials' = '1254.vb_96f366e7b_a_d'
        'display-url-api' = '2.3.7'
        'durable-task' = '507.v050055d0cb_dd'
        'echarts-api' = '5.4.0-4'
        'email-ext' = '2.97'
        'cloudbees-folder' = '6.815.v0dd5a_cb_40e0e'
        'font-awesome-api' = '6.3.0-2'
        'git-client' = '4.2.0'
        'git' = '5.0.2'
        'github-api' = '1.314-431.v78d72a_3fe4c3'
        'github-branch-source' = '1703.vd5a_2b_29c6cdc'
        'github' = '1.37.1'
        'gradle' = '2.7'
        'instance-identity' = '142.v04572ca_5b_265'
        'ionicons-api' = '56.v1b_1c8c49374e'
        'jackson2-api' = '2.15.1-344.v6eb_55303dc3e'
        'jakarta-activation-api' = '2.0.1-3'
        'jakarta-mail-api' = '2.0.1-3'
        'jjwt-api' = '0.11.5-77.v646c772fddb_0'
        'javax-activation-api' = '1.2.0-6'
        'javax-mail-api' = '1.6.2-9'
        'jaxb' = '2.3.8-1'
        'jquery3-api' = '3.7.0-1'
        'junit' = '1202.v79a_986785076'
        'ldap' = '682.v7b_544c9d1512'
        'mailer' = '448.v5b_97805e3767'
        'matrix-auth' = '3.1.7'
        'matrix-project' = '789.v57a_725b_63c79'
        'mina-sshd-api-common' = '2.10.0-69.v28e3e36d18eb_'
        'mina-sshd-api-core' = '2.10.0-69.v28e3e36d18eb_'
        'okhttp-api' = '4.10.0-132.v7a_7b_91cef39c'
        'antisamy-markup-formatter' = '159.v25b_c67cd35fb_'
        'pam-auth' = '1.10'
        'workflow-aggregator' = '596.v8c21c963d92d'
        'pipeline-graph-analysis' = '202.va_d268e64deb_3'
        'workflow-api' = '1213.v646def1087f9'
        'workflow-basic-steps' = '1017.vb_45b_302f0cea_'
        'pipeline-build-step' = '491.v1fec530da_858'
        'pipeline-model-definition' = '2.2131.vb_9788088fdb_5'
        'pipeline-model-extensions' = '2.2131.vb_9788088fdb_5'
        'pipeline-github-lib' = '42.v0739460cda_c4'
        'workflow-cps' = '3668.v1763b_b_6ccffd'
        'pipeline-groovy-lib' = '656.va_a_ceeb_6ffb_f7'
        'pipeline-input-step' = '468.va_5db_051498a_4'
        'workflow-job' = '1295.v395eb_7400005'
        'pipeline-milestone-step' = '111.v449306f708b_7'
        'pipeline-model-api' = '2.2131.vb_9788088fdb_5'
        'workflow-multibranch' = '746.v05814d19c001'
        'workflow-durable-task-step' = '1246.v5524618ea_097'
        'pipeline-rest-api' = '2.32'
        'workflow-scm-step' = '408.v7d5b_135a_b_d49'
        'pipeline-stage-step' = '305.ve96d0205c1c6'
        'pipeline-stage-tags-metadata' = '2.2131.vb_9788088fdb_5'
        'pipeline-stage-view' = '2.32'
        'workflow-step-api' = '639.v6eca_cd8c04a_a_'
        'workflow-support' = '839.v35e2736cfd5c'
        'plain-credentials' = '143.v1b_df8b_d3b_e48'
        'plugin-util-api' = '3.2.1'
        'powershell' = '2.0'
        'resource-disposer' = '0.22'
        'scm-api' = '672.v64378a_b_20c60'
        'script-security' = '1244.ve463715a_f89c'
        'snakeyaml-api' = '1.33-95.va_b_a_e3e47b_fa_4'
        'ssh-slaves' = '2.877.v365f5eb_a_b_eec'
        'ssh-credentials' = '305.v8f4381501156'
        'sshd' = '3.303.vefc7119b_ec23'
        'structs' = '324.va_f5d6774f3a_d'
        'timestamper' = '1.25'
        'token-macro' = '359.vb_cde11682e0c'
        'trilead-api' = '2.84.v72119de229b_7'
        'variant' = '59.vf075fe829ccb'
        'ws-cleanup' = '0.45'
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