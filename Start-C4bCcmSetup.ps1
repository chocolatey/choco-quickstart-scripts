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
    $DatabaseCredential = (Get-Credential -Username ChocoUser -Message 'Create a credential for the ChocolateyManagement DB user (document this somewhere)'),

    #Certificate to use for CCM service
    [Parameter()]
    [String]
    $CertificateThumbprint
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
    Start-Transcript -Path "$env:SystemDrive\choco-setup\logs\Start-C4bCcmSetup-$(Get-Date -Format 'yyyyMMdd-HHmmss').txt"

    # Dot-source helper functions
    . .\scripts\Get-Helpers.ps1

    # DB Setup
    $PkgSrc = "$env:SystemDrive\choco-setup\packages"
    $Ccr = 'https://community.chocolatey.org/api/v2/'

    $chocoArgs = @('upgrade', 'sql-server-express', 'sql-server-management-studio', '-y', "--source='$Ccr'", '--no-progress')
    & choco @chocoArgs

    # https://docs.microsoft.com/en-us/sql/tools/configuration-manager/tcp-ip-properties-ip-addresses-tab
    Write-Output 'SQL Server: Configuring Remote Acess on SQL Server Express.'
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
    Write-Output 'SQL Server: Setting Mixed Mode Authentication.'
    New-ItemProperty "HKLM:\Software\Microsoft\Microsoft SQL Server\$SqlVersion\MSSQLServer\" -Name 'LoginMode' -Value 2 -Force

    Write-Output "SQL Server: Forcing Restart of Instance."
    Restart-Service -Force 'MSSQL$SQLEXPRESS'

    Write-Output "SQL Server: Setting up SQL Server Browser and starting the service."
    Set-Service 'SQLBrowser' -StartupType Automatic
    Start-Service 'SQLBrowser'

    Write-Output "Firewall: Enabling SQLServer TCP port 1433."
    netsh advfirewall firewall add rule name="SQL Server 1433" dir=in action=allow protocol=TCP localport=1433 profile=any enable=yes service=any
    #New-NetFirewallRule -DisplayName "Allow inbound TCP Port 1433" –Direction inbound –LocalPort 1433 -Protocol TCP -Action Allow

    Write-Output "Firewall: Enabling SQL Server browser UDP port 1434."
    netsh advfirewall firewall add rule name="SQL Server Browser 1434" dir=in action=allow protocol=UDP localport=1434 profile=any enable=yes service=any
    #New-NetFirewallRule -DisplayName "Allow inbound UDP Port 1434" –Direction inbound –LocalPort 1434 -Protocol UDP -Action Allow

    # Install prerequisites for CCM
    $chocoArgs = @('install', 'IIS-WebServer', "--source='windowsfeatures'", '--no-progress', '-y')
    & choco @chocoArgs

    $chocoArgs = @('install', 'IIS-ApplicationInit', "--source='windowsfeatures'" ,'--no-progress', '-y')
    & choco @chocoArgs

    $chocoArgs = @('install', 'aspnetcore-runtimepackagestore', "--version='3.1.16'", "--source='$Ccr'", '--no-progress', '-y')
    & choco @chocoArgs

    $chocoArgs = @('install', 'dotnetcore-windowshosting', "--version='3.1.16'", "--source='$Ccr'", '--no-progress', '-y')
    & choco @chocoArgs

    choco pin add --name="'aspnetcore-runtimepackagestore'" --version="'3.1.16'" --reason="'Required for CCM website'"
    choco pin add --name="'dotnetcore-windowshosting'" --version="'3.1.16'" --reason="'Required for CCM website'"
    # "reason" only available in commercial editions

    # Starting with v0.6.2 of the CCM Database package, it uses dotnetcore-sdk so that it may be installed on a system without requiring IIS.
    # At the time of publishing, the most recent version of this package is 3.1.410, but later package versions (within the 3.x.x release) are expected to work
    choco install dotnetcore-sdk --version 3.1.410 --source $Ccr --no-progress -y

    # Install CCM DB package using Local SQL Express
    choco install chocolatey-management-database -y -s $PkgSrc --package-parameters="'/ConnectionString=Server=Localhost\SQLEXPRESS;Database=ChocolateyManagement;Trusted_Connection=true;'" --no-progress

    # Add Local Windows User:
    $DatabaseUser = $DatabaseCredential.UserName
    $DatabaseUserPw = $DatabaseCredential.GetNetworkCredential().Password
    Add-DatabaseUserAndRoles -DatabaseName 'ChocolateyManagement' -Username $DatabaseUser -SqlUserPw $DatabaseUserPw -CreateSqlUser -DatabaseRoles @('db_datareader', 'db_datawriter')

    # Find FDQN for current machine
    $hostName = [System.Net.Dns]::GetHostName()
    $domainName = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().DomainName

    if(-Not $hostName.endswith($domainName)) {
        $hostName += "." + $domainName
    }

    #Install CCM Service
    if($CertificateThumbprint){
        Write-Verbose "Validating certificate is in LocalMachine\TrustedPeople Store"
        if($CertificateThumbprint -notin (Get-ChildItem Cert:\LocalMachine\TrustedPeople | Select-Object -Expand Thumbprint)){
            Write-Warning "You specified $CertificateThumbprint for use with CCM service, but the certificate is not in the required LocalMachine\TrustedPeople store!"
            Write-Warning "Please place certificate with thumbprint: $CertificateThumbprint in the LocalMachine\TrustedPeople store and re-run this step"
            throw "Certificate not in correct location....exiting."
        } 
        else {
            Write-Verbose "Certificate has been successfully found in correct store"
            $chocoArgs = @('install','chocolatey-management-service','-y',"--source='$PkgSrc'","--package-parameters-sensitive='/ConnectionString:Server=Localhost\SQLEXPRESS;Database=ChocolateyManagement;User Id=$DatabaseUser;Password=$DatabaseUserPw'")
            & choco @chocoArgs

            $jsonData = Get-Content $env:ChocolateyInstall\lib\chocolatey-management-service\tools\service\appsettings.json | ConvertFrom-Json
            $jsonData.CertificateThumbprint = $CertificateThumbprint
            $jsonData | ConvertTo-Json | Set-Content $env:chocolateyInstall\lib\chocolatey-management-service\tools\service\appsettings.json
        }
    }

    else {
        $chocoArgs = @('install', 'chocolatey-management-service', '-y', "--source='$PkgSrc'", "--package-parameters-sensitive=`"/ConnectionString:'Server=Localhost\SQLEXPRESS;Database=ChocolateyManagement;User ID=$DatabaseUser;Password=$DatabaseUserPw;'`"", '--no-progress')
        & choco @chocoArgs
    }

    # Check if OS is 2016. If so, let the user know
    # they need a reboot after IIS packages install.
    # Instruct user to run secondary script after reboot.
    $Os = (Get-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion' -Name ProductName).ProductName
    if ($Os -like '*2016*') {
        $CcmSvcUrl = choco config get centralManagementServiceUrl -r
        $CcmJson = @{
            CCMServiceURL        = $CcmSvcUrl
            CCMWebPortal         = "http://localhost/Account/Login"
            DefaultUser          = "ccmadmin"
            DefaultPwToBeChanged = "123qwe"
            CCMDBUser            = $DatabaseUser
            CCMDBPassword        = $DatabaseUserPw
        }
        $CcmJson | ConvertTo-Json | Out-File "$env:SystemDrive\choco-setup\logs\ccm.json"
        $ErrorActionPreference = $DefaultEap
        Stop-Transcript
        $Comment = @"
    Chocolatey has detected that your operating system is Windows Server 2016.
    In order to complete the installation of IIS, a restart is required.
    This server will restart in 30 seconds. Once restarted, please follow
    the steps outlined in the C4B Quick-Start Guide to contiue.
"@
        Start-Process 'shutdown.exe' -ArgumentList "/r /f /t 30 /c `"$Comment`" /d p:4:1"
    }
    else {
        #Install CCM Web package
        choco install chocolatey-management-web -y --package-parameters-sensitive="'/ConnectionString:Server=Localhost\SQLEXPRESS;Database=ChocolateyManagement;User ID=$DatabaseUser;Password=$DatabaseUserPw;'" --no-progress

        $CcmSvcUrl = choco config get centralManagementServiceUrl -r
        $CcmJson = @{
            CCMServiceURL        = $CcmSvcUrl
            CCMWebPortal         = "http://localhost/Account/Login"
            DefaultUser          = "ccmadmin"
            DefaultPwToBeChanged = "123qwe"
            CCMDBUser            = $DatabaseUser
        }
        $CcmJson | ConvertTo-Json | Out-File "$env:SystemDrive\choco-setup\logs\ccm.json"

        Write-Host "CCM Setup has now completed" -ForegroundColor Green

        $ErrorActionPreference = $DefaultEap
        Stop-Transcript
    }
}