#requires -Modules C4B-Environment
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
    [string]$NuGetApiKey = $(
        if (-not (Get-Command Get-ChocoEnvironmentProperty -ErrorAction SilentlyContinue)) {. $PSScriptRoot\scripts\Get-Helpers.ps1}
        Get-ChocoEnvironmentProperty NuGetApiKey -AsPlainText
    ),

    # The certificate thumbprint that identifies the target SSL certificate in
    # the local machine certificate stores.
    [Parameter(ValueFromPipeline, ParameterSetName='Thumbprint')]
    [ArgumentCompleter({
        Get-ChildItem Cert:\LocalMachine\TrustedPeople | ForEach-Object {
            [System.Management.Automation.CompletionResult]::new(
                $_.Thumbprint,
                $_.Thumbprint,
                "ParameterValue",
                ($_.Subject -replace "^CN=(?<FQDN>.+),?.*$",'${FQDN}')
            )
        }
    })]
    [ValidateScript({Test-CertificateDomain -Thumbprint $_})]
    [string]
    $Thumbprint = $(
        if ((Test-Path C:\choco-setup\clixml\chocolatey-for-business.xml) -and (Import-Clixml C:\choco-setup\clixml\chocolatey-for-business.xml).CertThumbprint) {
            (Import-Clixml C:\choco-setup\clixml\chocolatey-for-business.xml).CertThumbprint
        } else {
            Get-ChildItem Cert:\LocalMachine\TrustedPeople -Recurse | Sort-Object {
                $_.Issuer -eq $_.Subject # Prioritise any certificates above self-signed
            } | Select-Object -ExpandProperty Thumbprint -First 1
        }
    )
)
process {
    $DefaultEap = $ErrorActionPreference
    $ErrorActionPreference = 'Stop'
    Start-Transcript -Path "$env:SystemDrive\choco-setup\logs\Start-C4bJenkinsSetup-$(Get-Date -Format 'yyyyMMdd-HHmmss').txt"

    $JenkinsScheme, $JenkinsPort = "http", "8080"

    # Install temurin21jre to meet JRE>11 dependency of Jenkins
    $chocoArgs = @('install', 'temurin21jre', "--source='ChocolateyInternal'", '-y', '--no-progress', "--params='/ADDLOCAL=FeatureJavaHome'")
    & Invoke-Choco @chocoArgs

    # Environment variable used to disable jenkins install login prompts
    [Environment]::SetEnvironmentVariable('JAVA_OPTS', '-Djenkins.install.runSetupWizard=false', 'Machine')

    # Install Jenkins
    Write-Host "Installing Jenkins"
    $chocoArgs = @('install', 'jenkins', "--source='ChocolateyInternal'", '-y', '--no-progress')
    & Invoke-Choco @chocoArgs

    # Jenkins needs a moment
    Wait-Site Jenkins

    # Disabling inital setup prompts
    $JenkinsHome = "C:\ProgramData\Jenkins\.jenkins"

    $JenkinsVersion = (choco.exe list jenkins --exact --limit-output).Split('|')[1]
    $JenkinsVersion | Out-File -FilePath $JenkinsHome\jenkins.install.UpgradeWizard.state -Encoding utf8
    $JenkinsVersion | Out-File -FilePath $JenkinsHome\jenkins.install.InstallUtil.lastExecVersion -Encoding utf8

    #region Set Jenkins Password
    $JenkinsCred = Set-JenkinsPassword -UserName 'admin' -NewPassword $(New-ServicePassword) -PassThru
    #endregion

    Stop-Service -Name Jenkins

    if ($Thumbprint) {
        $JenkinsScheme, $JenkinsPort = "https", 7443

        if ($SubjectWithoutCn = Get-ChocoEnvironmentProperty CertSubject) {
            $Hostname = $SubjectWithoutCn
        }

        # Generate Jenkins keystore
        Set-JenkinsCertificate -Thumbprint $Thumbprint -Port $JenkinsPort

        # Add firewall rule for Jenkins
        netsh advfirewall firewall add rule name="Jenkins-$($JenkinsPort)" dir=in action=allow protocol=tcp localport=$JenkinsPort
    }
    Set-JenkinsLocationConfiguration -Url "$($JenkinsScheme)://$($SubjectWithoutCn):$($JenkinsPort)" -Path $JenkinsHome\jenkins.model.JenkinsLocationConfiguration.xml

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
    $chocoArgs = @('install', 'chocolatey-licensed-jenkins-jobs', "--source='ChocolateyInternal'", '-y', '--no-progress')
    & Invoke-Choco @chocoArgs
    #endregion

    Write-Host "Starting Jenkins service back up" -ForegroundColor Green
    Start-Service -Name Jenkins

    # Save useful params
    Update-Clixml -Properties @{
        JenkinsUri        = "$($JenkinsScheme)://$($HostName):$($JenkinsPort)"
        JenkinsCredential = $JenkinsCred
    }

    Write-Host 'Jenkins setup complete' -ForegroundColor Green

    $ErrorActionPreference = $DefaultEap
    Stop-Transcript
}