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
    [string]$HostName = $env:ComputerName,

    # API key of your Nexus repo, for Chocolatey Jenkins jobs to use
    [string]$NuGetApiKey = $(Get-Content "$env:SystemDrive\choco-setup\logs\nexus.json" | ConvertFrom-Json).NuGetApiKey
)
process {
    $DefaultEap = $ErrorActionPreference
    $ErrorActionPreference = 'Stop'
    Start-Transcript -Path "$env:SystemDrive\choco-setup\logs\Start-C4bJenkinsSetup-$(Get-Date -Format 'yyyyMMdd-HHmmss').txt"

    # Dot-source helper functions
    . .\scripts\Get-Helpers.ps1

    # Install temurin21jre to meet JRE>11 dependency of Jenkins
    $chocoArgs = @('install', 'temurin21jre', '-y', '--no-progress', "--params='/ADDLOCAL=FeatureJavaHome'")
    & choco @chocoArgs

    # Environment variable used to disable jenkins install login prompts
    [Environment]::SetEnvironmentVariable('JAVA_OPTS', '-Djenkins.install.runSetupWizard=false', 'Machine')

    # Install Jenkins
    Write-Host "Installing Jenkins"
    $chocoArgs = @('install', 'jenkins', '-y', '--no-progress')
    & choco @chocoArgs

    Write-Host "Giving Jenkins 30 seconds to complete background setup..." -ForegroundColor Green
    Start-Sleep -Seconds 30  # Jenkins needs a moment

    # Disabling inital setup prompts
    $JenkinsHome = "C:\ProgramData\Jenkins\.jenkins"

    $JenkinsVersion = (choco.exe list jenkins --exact --limit-output).Split('|')[1]
    $JenkinsVersion | Out-File -FilePath $JenkinsHome\jenkins.install.UpgradeWizard.state -Encoding utf8
    $JenkinsVersion | Out-File -FilePath $JenkinsHome\jenkins.install.InstallUtil.lastExecVersion -Encoding utf8

    # Set the hostname, such that it's ready for use.
    Set-JenkinsLocationConfiguration -Url "http://$($HostName):8080" -Path $JenkinsHome\jenkins.model.JenkinsLocationConfiguration.xml

    #region Set Jenkins Password
    $JenkinsCred = Set-JenkinsPassword -UserName 'admin' -NewPassword $(New-ServicePassword) -PassThru
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
    $JenkinsPlugins = (Get-Content $PSScriptRoot\files\jenkins.json | ConvertFrom-Json).plugins

    if (Test-Path $PSScriptRoot\files\JenkinsPlugins.zip) {
        Expand-Archive -Path $PSScriptRoot\files\JenkinsPlugins.zip -DestinationPath $jenkinsHome\plugins\ -Force
    }

    # Performance is killed by Invoke-WebRequest's progress bars, turning them off to speed this up
    $ProgressPreference = 'SilentlyContinue'

    # Downloading Jenkins Plugins
    Write-Host "Downloading Jenkins Plugins"
    foreach ($Plugin in $JenkinsPlugins) {
        $PluginUri = if ($Plugin.Version -ne "latest") {
            'https://updates.jenkins-ci.org/download/plugins/{0}/{1}/{0}.hpi' -f $Plugin.Name, $Plugin.Version
        }
        else {
            "https://updates.jenkins-ci.org/latest/$($Plugin.Name).hpi"
        }
        $PluginPath = '{0}/plugins/{1}.hpi' -f $jenkinsHome, $Plugin.Name
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
    Get-ChildItem "$env:SystemDrive\choco-setup\files\jenkins" | Copy-Item -Destination "$JenkinsHome\jobs\" -Recurse -Force

    Get-ChildItem -Path "$JenkinsHome\jobs" -Recurse -File -Filter 'config.xml' | Invoke-TextReplacementInFile -Replacement @{
        '{{NugetApiKey}}' = $NuGetApiKey
        '(?<=https:\/\/)(?<HostName>.+)(?=:8443\/repository\/)' = $HostName
    }
    #endregion

    Write-Host "Starting Jenkins service back up" -ForegroundColor Green
    Start-Service -Name Jenkins

    # Save useful params to JSON
    $JenkinsJson = @{
        JenkinsUri  = "http://$($HostName):8080"
        JenkinsUser = "admin"
        JenkinsPw   = $JenkinsCred.GetNetworkCredential().Password
    }
    $JenkinsJson | ConvertTo-Json | Out-File "$env:SystemDrive\choco-setup\logs\jenkins.json"

    Write-Host 'Jenkins setup complete' -ForegroundColor Green

    $ErrorActionPreference = $DefaultEap
    Stop-Transcript
}