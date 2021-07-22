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
    $DatabaseCredential = (Get-Credential -Username ChocoUser -Message 'Create a credential for the ChocolateyManagement DB user (document this somewhere)')
)

$DefaultEap = $ErrorActionPreference
$ErrorActionPreference = 'Stop'
Start-Transcript -Path "$env:SystemDrive\choco-setup\logs\Start-C4bCcmSetup-$(Get-Date -Format 'yyyyMMdd-HHmmss').txt"

# DB Setup
$PkgSrc = "$env:SystemDrive\choco-setup\packages"
$Ccr = "'https://community.chocolatey.org/api/v2/'"
choco upgrade sql-server-express sql-server-management-studio -y --source $Ccr

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

# Install CCM DB package using Local SQL Express
choco install chocolatey-management-database -y -s $PkgSrc --package-parameters="'/ConnectionString=Server=Localhost\SQLEXPRESS;Database=ChocolateyManagement;Trusted_Connection=true;'"

# Setup SQL Login and Access
function Add-DatabaseUserAndRoles {
    param(
        [parameter(Mandatory = $true)][string] $Username,
        [parameter(Mandatory = $true)][string] $DatabaseName,
        [parameter(Mandatory = $false)][string] $DatabaseServer = 'localhost\SQLEXPRESS',
        [parameter(Mandatory = $false)] $DatabaseRoles = @('db_datareader'),
        [parameter(Mandatory = $false)][string] $DatabaseServerPermissionsOptions = 'Trusted_Connection=true;',
        [parameter(Mandatory = $false)][switch] $CreateSqlUser,
        [parameter(Mandatory = $false)][string] $SqlUserPw
    )

    $LoginOptions = "FROM WINDOWS WITH DEFAULT_DATABASE=[$DatabaseName]"
    if ($CreateSqlUser) {
        $LoginOptions = "WITH PASSWORD='$SqlUserPw', DEFAULT_DATABASE=[$DatabaseName], CHECK_EXPIRATION=OFF, CHECK_POLICY=OFF"
    }

    $addUserSQLCommand = @"
USE [master]
IF EXISTS(SELECT * FROM msdb.sys.syslogins WHERE UPPER([name]) = UPPER('$Username'))
BEGIN
DROP LOGIN [$Username]
END

CREATE LOGIN [$Username] $LoginOptions

USE [$DatabaseName]
IF EXISTS(SELECT * FROM sys.sysusers WHERE UPPER([name]) = UPPER('$Username'))
BEGIN
DROP USER [$Username]
END

CREATE USER [$Username] FOR LOGIN [$Username]

"@

    foreach ($DatabaseRole in $DatabaseRoles) {
        $addUserSQLCommand += @"
ALTER ROLE [$DatabaseRole] ADD MEMBER [$Username]
"@
    }

    Write-Output "Adding $UserName to $DatabaseName with the following permissions: $($DatabaseRoles -Join ', ')"
    Write-Debug "running the following: \n $addUserSQLCommand"
    $Connection = New-Object System.Data.SQLClient.SQLConnection
    $Connection.ConnectionString = "server='$DatabaseServer';database='master';$DatabaseServerPermissionsOptions"
    $Connection.Open()
    $Command = New-Object System.Data.SQLClient.SQLCommand
    $Command.CommandText = $addUserSQLCommand
    $Command.Connection = $Connection
    $Command.ExecuteNonQuery()
    $Connection.Close()
}

# Add Local Windows User:
$DatabaseUser = $DatabaseCredential.UserName
$DatabaseUserPw = $DatabaseCredential.GetNetworkCredential().Password
Add-DatabaseUserAndRoles -DatabaseName 'ChocolateyManagement' -Username $DatabaseUser -SqlUserPw $DatabaseUserPw -CreateSqlUser -DatabaseRoles @('db_datareader', 'db_datawriter')

# Install dotnet requirement for CCM Service
choco install dotnet4.6.1 -y --source $Ccr

# Find FDQN for current machine
$hostName = [System.Net.Dns]::GetHostName()
$domainName = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().DomainName

if(-Not $hostName.endswith($domainName)) {
    $hostName += "." + $domainName
}

# Set CCM Service URL
choco config set --name="'centralManagementServiceUrl'" --value="'https://$($hostname):24020/ChocolateyManagementService'"

#Install CCM Service
choco install chocolatey-management-service -y -s $PkgSrc --package-parameters-sensitive="'/ConnectionString:Server=Localhost\SQLEXPRESS;Database=ChocolateyManagement;User ID=$DatabaseUser;Password=$DatabaseUserPw;'"

# Install prerequisites for CCM Web
choco install IIS-WebServer -s windowsfeatures --no-progress -y
choco install IIS-ApplicationInit -s windowsfeatures --no-progress -y
<<<<<<< HEAD
choco install aspnetcore-runtimepackagestore --version 2.2.7 --source $Ccr --no-progress -y
choco install dotnetcore-windowshosting --version 2.2.7 --source $Ccr --no-progress -y

choco pin add --name="'aspnetcore-runtimepackagestore'" --version="'2.2.7'" --reason="'Required for CCM website'"
choco pin add --name="'dotnetcore-windowshosting'" --version="'2.2.7'" --reason="'Required for CCM website'"
# "reason" only available in commercial editions

#Install CCM Web package
choco install chocolatey-management-web -y -s $PkgSrc --package-parameters-sensitive="'/ConnectionString:Server=Localhost\SQLEXPRESS;Database=ChocolateyManagement;User ID=$DatabaseUser;Password=$DatabaseUserPw;'"

$CcmSvcUrl = choco config get centralManagementServiceUrl -r
$CcmJson = @{
    CCMServiceURL = $CcmSvcUrl
    CCMWebPortal = "http://localhost/Account/Login"
    DefaultUser = "ccmadmin"
    DefaultPwToBeChanged = "123qwe"
    CCMDBUser = $DatabaseUser
=======

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
>>>>>>> 29c03da (Add logic to handle 2016 iis reboot)
}
else {
    choco install aspnetcore-runtimepackagestore --version 2.2.7 --source $Ccr --no-progress -y
    choco install dotnetcore-windowshosting --version 2.2.7 --source $Ccr --no-progress -y
    choco pin add --name="'aspnetcore-runtimepackagestore'" --version="'2.2.7'" --reason="'Required for CCM website'"
    choco pin add --name="'dotnetcore-windowshosting'" --version="'2.2.7'" --reason="'Required for CCM website'"
    #Install CCM Web package
    choco install chocolatey-management-web -y --package-parameters-sensitive="'/ConnectionString:Server=Localhost\SQLEXPRESS;Database=ChocolateyManagement;User ID=$DatabaseUser;Password=$DatabaseUserPw;'"

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
