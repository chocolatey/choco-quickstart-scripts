#requires -modules C4B-Environment
<#
.SYNOPSIS
C4B Quick-Start Guide CCM setup script

.DESCRIPTION
- Performs the following Chocolatey Central Management setup
    - Install of MS SQL Express
    - Creation and permissions of `ChocolateyManagement` DB
    - Install of all 3 CCM packages, with correct parameters
#>
[CmdletBinding()]
param(
    # Credential used for the ChocolateyManagement DB user
    [Parameter()]
    [ValidateNotNull()]
    [System.Management.Automation.PSCredential]
    $DatabaseCredential = $(
        if ((Test-Path C:\choco-setup\clixml\chocolatey-for-business.xml) -and (Import-Clixml C:\choco-setup\clixml\chocolatey-for-business.xml).DatabaseUser) {
            (Import-Clixml C:\choco-setup\clixml\chocolatey-for-business.xml).DatabaseUser
        } else {
            [PSCredential]::new(
                "chocodbuser",
                (ConvertTo-SecureString "$(New-Guid)-$(New-Guid)" -Force -AsPlainText)
            )
        }
    ),

    # Certificate to use for CCM service
    [Parameter()]
    [Alias('CertificateThumbprint')]
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
    [String]
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
    Start-Transcript -Path "$env:SystemDrive\choco-setup\logs\Start-C4bCcmSetup-$(Get-Date -Format 'yyyyMMdd-HHmmss').txt"

    $Packages = (Get-Content $PSScriptRoot\files\chocolatey.json | ConvertFrom-Json).packages

    Set-ChocoEnvironmentProperty -Name DatabaseUser -Value $DatabaseCredential

    # DB Setup
    Write-Host "Installing SQL Server Express"
    $chocoArgs = @('upgrade', 'sql-server-express', "--source='ChocolateyInternal'", '-y', '--no-progress')
    & Invoke-Choco @chocoArgs

    # https://docs.microsoft.com/en-us/sql/tools/configuration-manager/tcp-ip-properties-ip-addresses-tab
    Write-Verbose 'SQL Server: Configuring Remote Access on SQL Server Express.'
    $assemblyList = 'Microsoft.SqlServer.Management.Common', 'Microsoft.SqlServer.Smo', 'Microsoft.SqlServer.SqlWmiManagement', 'Microsoft.SqlServer.SmoExtended'

    foreach ($assembly in $assemblyList) {
        $assembly = [System.Reflection.Assembly]::LoadWithPartialName($assembly)
    }

    $wmi = New-Object Microsoft.SqlServer.Management.Smo.Wmi.ManagedComputer # connects to localhost by default
    $instance = $wmi.ServerInstances | Where-Object { $_.Name -eq 'SQLEXPRESS' }

    $np = $instance.ServerProtocols | Where-Object { $_.Name -eq 'Np' }
    $np.IsEnabled = $true
    $np.Alter()

    $tcp = $instance.ServerProtocols | Where-Object { $_.Name -eq 'Tcp' }
    $tcp.IsEnabled = $true
    $tcp.Alter()

    $tcpIpAll = $tcp.IpAddresses | Where-Object { $_.Name -eq 'IpAll' }

    $tcpDynamicPorts = $tcpIpAll.IpAddressProperties | Where-Object { $_.Name -eq 'TcpDynamicPorts' }
    $tcpDynamicPorts.Value = ""
    $tcp.Alter()

    $tcpPort = $tcpIpAll.IpAddressProperties | Where-Object { $_.Name -eq 'TcpPort' }
    $tcpPort.Value = "1433"
    $tcp.Alter()

    # This section will evaluate which version of SQL Express you have installed, and set a login value accordingly
    $SqlString = (Get-ChildItem -Path 'HKLM:\Software\Microsoft\Microsoft SQL Server').Name |
        Where-Object { $_ -like "HKEY_LOCAL_MACHINE\Software\Microsoft\Microsoft SQL Server\MSSQL*.SQLEXPRESS" } 
    $SqlVersion = $SqlString.Split("\") | Where-Object { $_ -like "MSSQL*.SQLEXPRESS" }
    Write-Verbose 'SQL Server: Setting Mixed Mode Authentication.'
    $null = New-ItemProperty "HKLM:\Software\Microsoft\Microsoft SQL Server\$SqlVersion\MSSQLServer\" -Name 'LoginMode' -Value 2 -Force

    Write-Verbose "SQL Server: Forcing Restart of Instance."
    Restart-Service -Force 'MSSQL$SQLEXPRESS'

    Write-Verbose "SQL Server: Setting up SQL Server Browser and starting the service."
    Set-Service 'SQLBrowser' -StartupType Automatic
    Start-Service 'SQLBrowser'

    Write-Verbose "Firewall: Enabling SQLServer TCP port 1433."
    $null = netsh advfirewall firewall add rule name="SQL Server 1433" dir=in action=allow protocol=TCP localport=1433 profile=any enable=yes service=any
    #New-NetFirewallRule -DisplayName "Allow inbound TCP Port 1433" –Direction inbound –LocalPort 1433 -Protocol TCP -Action Allow

    Write-Verbose "Firewall: Enabling SQL Server browser UDP port 1434."
    $null = netsh advfirewall firewall add rule name="SQL Server Browser 1434" dir=in action=allow protocol=UDP localport=1434 profile=any enable=yes service=any
    #New-NetFirewallRule -DisplayName "Allow inbound UDP Port 1434" –Direction inbound –LocalPort 1434 -Protocol UDP -Action Allow

    # Install prerequisites for CCM
    Write-Host "Installing Chocolatey Central Management Prerequisites"
    $chocoArgs = @('install', 'IIS-WebServer', "--source='windowsfeatures'", '--no-progress', '-y')
    & Invoke-Choco @chocoArgs -ValidExitCodes 0, 3010

    $chocoArgs = @('install', 'IIS-ApplicationInit', "--source='windowsfeatures'" ,'--no-progress', '-y')
    & Invoke-Choco @chocoArgs -ValidExitCodes 0, 3010

    $chocoArgs = @('install', 'dotnet-aspnetcoremodule-v2', "--source='ChocolateyInternal'", "--version='$($Packages.Where{$_.Name -eq 'dotnet-aspnetcoremodule-v2'}.Version)'", '--no-progress', '-y')
    & Invoke-Choco @chocoArgs

    $chocoArgs = @('install', 'dotnet-8.0-runtime', "--source='ChocolateyInternal'", "--version=$($Packages.Where{$_.Name -eq 'dotnet-8.0-runtime'}.Version)", '--no-progress', '-y')
    & Invoke-Choco @chocoArgs

    $chocoArgs = @('install', 'dotnet-8.0-aspnetruntime', "--source='ChocolateyInternal'", "--version=$($Packages.Where{$_.Name -eq 'dotnet-8.0-aspnetruntime'}.Version)", '--no-progress', '-y')
    & Invoke-Choco @chocoArgs

    Write-Host "Creating Chocolatey Central Management Database"
    $chocoArgs = @('install', 'chocolatey-management-database', '--source="ChocolateyInternal"', '-y', '--package-parameters="''/ConnectionString=Server=Localhost\SQLEXPRESS;Database=ChocolateyManagement;Trusted_Connection=true;''"', '--no-progress')
    if ($PackageVersion = $Packages.Where{ $_.Name -eq 'chocolatey-management-database' }.Version) {
        $chocoArgs += "--version='$($PackageVersion)'"
    }
    & Invoke-Choco @chocoArgs

    # Add Local Windows User:
    $DatabaseUser = $DatabaseCredential.UserName
    $DatabaseUserPw = $DatabaseCredential.GetNetworkCredential().Password
    Add-DatabaseUserAndRoles -DatabaseName 'ChocolateyManagement' -Username $DatabaseUser -SqlUserPw $DatabaseUserPw -CreateSqlUser -DatabaseRoles @('db_datareader', 'db_datawriter')

    # Find FDQN for current machine
    $hostName = [System.Net.Dns]::GetHostName()
    $domainName = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().DomainName

    if (-not $hostName.EndsWith($domainName)) {
        $hostName += "." + $domainName
    }
    $CcmEndpoint = "http://$hostName"

    Write-Host "Installing Chocolatey Central Management Service"
    $chocoArgs = @('install', 'chocolatey-management-service', "--source='ChocolateyInternal'", '-y', "--package-parameters-sensitive=`"/ConnectionString:'Server=Localhost\SQLEXPRESS;Database=ChocolateyManagement;User ID=$DatabaseUser;Password=$DatabaseUserPw;'`"", '--no-progress')
    if ($PackageVersion = $Packages.Where{ $_.Name -eq 'chocolatey-management-service' }.Version) {
        $chocoArgs += "--version='$($PackageVersion)'"
    }
    if ($Thumbprint) {
        Write-Verbose "Validating certificate is in LocalMachine\TrustedPeople Store"
        if (-not (Get-Item Cert:\LocalMachine\TrustedPeople\$Thumbprint -EA 0) -and -not (Get-Item Cert:\LocalMachine\My\$Thumbprint -EA 0)) {
            Write-Warning "You specified $Thumbprint for use with CCM service, but the certificate is not in the required LocalMachine\TrustedPeople store!"
            Write-Warning "Please place certificate with thumbprint: $Thumbprint in the LocalMachine\TrustedPeople store and re-run this step"
            throw "Certificate not in correct location... exiting."
        } elseif ($MyCertificate = Get-Item Cert:\LocalMachine\My\$Thumbprint -EA 0) {
            Write-Verbose "Copying certificate from 'Personal' store to 'TrustedPeople'"
            Copy-CertToStore $MyCertificate
        } else {
            Write-Verbose "Certificate has been successfully found in correct store"
        }
        $chocoArgs += @("--package-parameters='/CertificateThumbprint=$Thumbprint'")
    }
    & Invoke-Choco @chocoArgs
    
    if (-not $MyCertificate) { $MyCertificate = Get-Item Cert:\LocalMachine\My\* }

    Write-Host "Installing Chocolatey Central Management Website"
    $chocoArgs = @('install', 'chocolatey-management-web', "--source='ChocolateyInternal'", '-y', "--package-parameters-sensitive=""'/ConnectionString:Server=Localhost\SQLEXPRESS;Database=ChocolateyManagement;User ID=$DatabaseUser;Password=$DatabaseUserPw;'""", '--no-progress')
    if ($PackageVersion = $Packages.Where{ $_.Name -eq 'chocolatey-management-web' }.Version) {
        $chocoArgs += "--version='$($PackageVersion)'"
    }
    & Invoke-Choco @chocoArgs

    # Setup Website SSL
    if ($Thumbprint) {
        Stop-CcmService
        Remove-CcmBinding
        New-CcmBinding -Thumbprint $Thumbprint
        Start-CcmService

        $CcmEndpoint = "https://$(Get-ChocoEnvironmentProperty CertSubject)"
    }
    choco config set centralManagementServiceUrl "$($CcmEndpoint):24020/ChocolateyManagementService"

    # Updating the Registration Script
    $EndpointScript = "$PSScriptRoot\scripts\Register-C4bEndpoint.ps1"
    Invoke-TextReplacementInFile -Path $EndpointScript -Replacement @{
        "{{ ClientSaltValue }}" = Get-ChocoEnvironmentProperty ClientSalt -AsPlainText
        "{{ ServiceSaltValue }}" = Get-ChocoEnvironmentProperty ServiceSalt -AsPlainText
        "{{ FQDN }}" = Get-ChocoEnvironmentProperty CertSubject

        # Set a default value for TrustCertificate if we're using a self-signed cert
        '(?<Parameter>\s+\$TrustCertificate)(?<Value>\s*=\s*\$true)?(?<Comma>,)?(?!\))' = "`${Parameter}$(
        if (Test-SelfSignedCertificate -Certificate $MyCertificate) {' = $true'}
        )`${Comma}"
    }

    # Create the site hosting the certificate import script on port 80
    if ($MyCertificate.NotAfter -gt (Get-Date).AddYears(5)) {
        .\scripts\New-IISCertificateHost.ps1
    }

    Wait-Site CCM

    Write-Host "Configuring Chocolatey Central Management"

    # Run initial configuration for CCM Admin
    if (-not ($CCMCredential = Get-ChocoEnvironmentProperty CCMCredential)) {
        $CCMCredential = [PSCredential]::new(
            "ccmadmin",
            (New-ServicePassword)
        )
        Set-CcmAccountPassword -CcmEndpoint $CcmEndpoint -ConnectionString "Server=Localhost\SQLEXPRESS;Database=ChocolateyManagement;User ID=$DatabaseUser;Password=$DatabaseUserPw;" -NewPassword $CCMCredential.Password
        Set-ChocoEnvironmentProperty CCMCredential $CCMCredential
    }

    if (-not ($CCMEncryptionPassword = Get-ChocoEnvironmentProperty CCMEncryptionPassword)) {
        $CCMEncryptionPassword = New-ServicePassword

        Set-CcmEncryptionPassword -CcmEndpoint $CcmEndpoint -Credential $CCMCredential -NewPassword $CCMEncryptionPassword
        Set-ChocoEnvironmentProperty CCMEncryptionPassword $CCMEncryptionPassword
    }

    # Set Client and Service salts
    if (-not (Get-ChocoEnvironmentProperty ClientSalt)) {
        $ClientSaltValue = New-ServicePassword
        Set-ChocoEnvironmentProperty ClientSalt $ClientSaltValue

        Invoke-Choco config set centralManagementClientCommunicationSaltAdditivePassword $ClientSaltValue.ToPlainText()
    }

    if (-not (Get-ChocoEnvironmentProperty ServiceSalt)) {
        $ServiceSaltValue = New-ServicePassword
        Set-ChocoEnvironmentProperty ServiceSalt $ServiceSaltValue

        Invoke-Choco config set centralManagementServiceCommunicationSaltAdditivePassword $ServiceSaltValue.ToPlainText()
    }

    # Set Website Root Address
    Update-CcmSettings -CcmEndpoint $CCmEndpoint -Credential $CCMCredential -Settings @{
        website = @{
            webSiteRootAddress = $CcmEndpoint
        }
    }

    $CcmSvcUrl = Invoke-Choco config get centralManagementServiceUrl -r
    Update-Clixml -Properties @{
        CCMServiceURL        = $CcmSvcUrl
        CCMWebPortal         = "$CcmEndpoint/Account/Login"
        CCMDBUser            = $DatabaseUser
        CCMInstallUser       = whoami
    }

    Write-Host "Chocolatey Central Management Setup has now completed" -ForegroundColor Green

    $ErrorActionPreference = $DefaultEap
    Stop-Transcript
}