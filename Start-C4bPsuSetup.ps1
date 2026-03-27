#requires -Modules C4B-Environment
<#
.SYNOPSIS
C4B Quick-Start Guide PowerShell Universal setup script

.DESCRIPTION
- Performs the following PowerShell Universal setup
    - Install of PowerShell Universal package
    - Creation of Chocolatey-specific jobs from template files
#>
[CmdletBinding()]
param(
    # The certificate thumbprint that identifies the target SSL certificate in
    # the local machine certificate stores.
    [Parameter()]
    [ArgumentCompleter({
            Get-ChildItem Cert:\LocalMachine\TrustedPeople | ForEach-Object {
                [System.Management.Automation.CompletionResult]::new(
                    $_.Thumbprint,
                    $_.Thumbprint,
                    "ParameterValue",
                    ($_.Subject -replace "^CN=(?<FQDN>.+),?.*$", '${FQDN}')
                )
            }
        })]
    [ValidateScript({ Test-CertificateDomain -Thumbprint $_ })]
    [string]$Thumbprint = $(
        if ((Test-Path C:\choco-setup\clixml\chocolatey-for-business.xml) -and (Import-Clixml C:\choco-setup\clixml\chocolatey-for-business.xml).CertThumbprint) {
            (Import-Clixml C:\choco-setup\clixml\chocolatey-for-business.xml).CertThumbprint
        } else {
            Get-ChildItem Cert:\LocalMachine\TrustedPeople -Recurse | Sort-Object {
                $_.Issuer -eq $_.Subject # Prioritise any certificates above self-signed
            } | Select-Object -ExpandProperty Thumbprint -First 1
        }
    ),

    # Optional: Sets PSU to use a provided SQL database instead of SQLLite.
    [string]$ConnectionString,

    # Optional: Sets PSU to be available on this port. Defaults to 5000.
    [uint16]$Port = 5000
)
try {
    $DefaultEap = $ErrorActionPreference
    $ErrorActionPreference = 'Stop'
    Start-Transcript -Path "$env:SystemDrive\choco-setup\logs\Start-C4bPsuSetup-$(Get-Date -Format 'yyyyMMdd-HHmmss').txt"

    Invoke-Choco upgrade powershelluniversal-remove-default-listener.hook --confirm --no-progress

    if (Get-Service PowerShellUniversal -ErrorAction SilentlyContinue) {
        Stop-Service PowerShellUniversal
    }

    # Install PowerShell Universal
    Invoke-Choco upgrade powershelluniversal --confirm --no-progress --install-args="STARTSERVICE=0$(if ($ConnectionString) {" CONNECTIONSTRING=$ConnectionString DATABASETYPE=SQL"})"

    # Handle configuration
    $ConfigurationFile = Join-Path $env:ProgramData "PowerShellUniversal/appsettings.json"
    $CurrentConfiguration = Get-Content $ConfigurationFile | ConvertFrom-Json

    if ($Thumbprint) {
        $CurrentConfiguration.Kestrel.Endpoints = @{
            HTTPS = @{
                Url         = "https://$(Get-ChocoEnvironmentProperty CertSubject):$Port"
                Certificate = @{
                    Thumbprint   = $Thumbprint
                    Store        = "TrustedPeople"
                    Location     = "LocalMachine"
                    AllowInvalid = "true"
                }
            }
        }
    }

    if ($ConnectionString) {
        $CurrentConfiguration.Data.ConnectionString = $ConnectionString
    }

    if ((Get-Content $ConfigurationFile -Raw) -ne ($CurrentConfiguration | ConvertTo-Json -Depth 10)) {
        $CurrentConfiguration | ConvertTo-Json -Depth 10 | Set-Content $ConfigurationFile
    }

    # Future consideration: parameter to disable external access?
    $FwRuleParams = @{
        DisplayName = "PowerShellUniversal Access"
        Direction   = 'Inbound'
        LocalPort   = $Port
        Protocol    = 'TCP'
        Action      = 'Allow'
    }
    $null = New-NetFirewallRule @FwRuleParams  # Set-EnvFirewallRule @FwRuleParams

    # Create admin user
    if (-not ($User = Get-ChocoEnvironmentProperty PSUCredential)) {
        $User = [pscredential]::new(
            "admin",
            (New-ServicePassword)
        )
        Set-ChocoEnvironmentProperty PSUCredential $User

        [System.Environment]::SetEnvironmentVariable('PSUDefaultAdminName', $User.UserName, [System.EnvironmentVariableTarget]::Machine)
        [System.Environment]::SetEnvironmentVariable('PSUDefaultAdminPassword', $User.Password.ToPlainText(), [System.EnvironmentVariableTarget]::Machine)
    }

    # Set Security Defaults
    $RepositoryDirectory = Join-Path $env:ProgramData UniversalAutomation\Repository

    if (-not (Test-Path $RepositoryDirectory -PathType Container)) {
        $null = New-Item -Path $RepositoryDirectory -ItemType Directory
    }

    if (-not (Test-Path $RepositoryDirectory\.universal\settings.ps1)) {
        $null = New-Item -Path $RepositoryDirectory\.universal\settings.ps1 -Value @'
$Parameters = @{
    EnhancedAppTokenSecurity = $true
    ApiSecurityModel         = "Medium"
}
Set-PSUSetting @Parameters
'@ -Force
    }

    # Deploy jobs and dashboards
    Invoke-Choco upgrade chocolatey-licensed-psu-environment --confirm --no-progress

    $LogPath = "$env:ProgramData\PowerShellUniversal\Logs\System\systemLog$(Get-Date -Format "yyyyMMdd").txt"
    if ([System.Environment]::GetEnvironmentVariable('PSUDefaultAdminPassword', [System.EnvironmentVariableTarget]::Machine) -and (Test-Path $LogPath)) {
        Write-Verbose "Renaming '$LogPath' in order to ensure clean logs to check..."
        Rename-Item -Path $LogPath -NewName "$(([System.IO.FileInfo]$LogPath).BaseName)-$(Get-Date -Format 'HHmmss').txt"
    }

    # Start service
    Start-Service PowerShellUniversal

    # Wait until the username and password have been initialized on the first run
    if ([System.Environment]::GetEnvironmentVariable('PSUDefaultAdminPassword', [System.EnvironmentVariableTarget]::Machine)) {

        Write-Verbose "[$(Get-Date -Format 'HH:mm:ss')] Waiting for PowerShell Universal to start..."

        $Timer = [System.Diagnostics.Stopwatch]::StartNew()

        while (
            ($Timer.Elapsed.TotalSeconds -lt 180) -and
            -not (Test-Path $LogPath)
        ) { Start-Sleep -Seconds 5 }

        if (Test-Path $LogPath) {
            Write-Verbose "[$(Get-Date -Format 'HH:mm:ss')] Log has been created at '$LogPath'"
        }

        while (
            ($Timer.Elapsed.TotalSeconds -lt 180) -and
            -not ($Result = Select-String -Path $LogPath -Pattern "\[INF\]\[UniversalAutomation\.StartupService\] Startup complete.$" -ErrorAction SilentlyContinue)
        ) { Start-Sleep -Seconds 5 }

        if ($Result) {
            Write-Verbose "[$(Get-Date -Format 'HH:mm:ss')] PowerShell Universal has successfully started."
        } else {
            Write-Error "[$(Get-Date -Format 'HH:mm:ss')] PowerShell Universal has not successfully started after $($Timer.Elapsed.TotalSeconds) seconds."
        }
    }

    # Save useful params
    Update-Clixml -Properties @{
        PowerShellUniversalUri = "https://$(Get-ChocoEnvironmentProperty CertSubject):$Port"
    }
} finally {
    [System.Environment]::SetEnvironmentVariable('PSUDefaultAdminName', $null, [System.EnvironmentVariableTarget]::Machine)
    [System.Environment]::SetEnvironmentVariable('PSUDefaultAdminPassword', $null, [System.EnvironmentVariableTarget]::Machine)

    $ErrorActionPreference = $DefaultEap
    Stop-Transcript
}