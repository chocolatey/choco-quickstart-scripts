# Helper Functions for the various QSG scripts
function Invoke-Choco {
    [CmdletBinding()]
    param(
        [Parameter(Position=0)]
        [string]$Command,

        [Parameter(Position=1, ValueFromRemainingArguments)]
        [string[]]$Arguments,

        [int[]]$ValidExitCodes = @(0)
    )

    if ($Command -eq 'Install' -and $Arguments -notmatch '\b-(y|-confirm)\b') {
        $Arguments += '--confirm'
    }

    if ($Arguments -notmatch '\b-(r|-limitoutput|-limit-output)\b') {
        $Arguments += '--limit-output'
    }

    $chocoPath = if ($CommandPath = Get-Command choco.exe -ErrorAction SilentlyContinue) {
        $CommandPath.Source
    } elseif ($env:ChocolateyInstall) {
        Join-Path $env:ChocolateyInstall "choco.exe"
    } elseif (Test-Path C:\ProgramData\chocolatey\choco.exe) {
        "C:\ProgramData\chocolatey\choco.exe"
    } else {
        Write-Error "Could not find 'choco.exe' - unexpected behaviour is expected!"
        "choco.exe"
    }

    & $chocoPath $Command $Arguments | Tee-Object -Variable Result | Where-Object {$_} | ForEach-Object {
        Write-Information -MessageData $_ -Tags Choco
    }

    if ($LASTEXITCODE -notin $ValidExitCodes) {
        Write-Error -Message "$($Result[-5..-1] -join "`n")" -TargetObject "choco $Command $Arguments"
    }
}

function Test-CertificateDomain {
    param(
        [Parameter(Mandatory)]
        [string]$Thumbprint
    )
    # Check the certificate exists
    if (-not ($Certificate = Get-Item Cert:\LocalMachine\TrustedPeople\$Thumbprint)) {
        throw "Certificate could not be found in Cert:\LocalMachine\TrustedPeople\. Please ensure it is is present, and try again."
    }

    # Check that we have a domain for it
    if (-not ($CertificateDnsName = Get-ChocoEnvironmentProperty CertSubject) -and ($Certificate.Subject -match '^CN=\*')) {
        $matcher = 'CN\s?=\s?(?<Subject>[^,\s]+)'
        $null = $Certificate.Subject -match $matcher
        $CertificateDnsName = if ($Matches.Subject.StartsWith('*')) {
            # This is a wildcard cert, we need to prompt for the intended CertificateDnsName
            while ($CertificateDnsName -notlike $Matches.Subject) {
                $CertificateDnsName = Read-Host -Prompt "$(if ($CertificateDnsName) {"'$($CertificateDnsName)' is not a subdomain of '$($Matches.Subject)'. "})Please provide an FQDN to use with the certificate '$($Matches.Subject)'"
            }
            $CertificateDnsName
        } else {
            $Matches.Subject
        }
        Set-ChocoEnvironmentProperty CertSubject $CertificateDnsName
    }

    $true
}

function Wait-Site {
    <#
        .Synopsis
            Waits for a given site to be available. A simple healthcheck.
    #>
    [Alias('Wait-Nexus','Wait-CCM','Wait-Jenkins')]
    [CmdletBinding(DefaultParameterSetName="Name")]
    param(
        # The service name to check for a 200 response
        [Parameter(ParameterSetName='Name', Position=0)]
        [ValidateSet('Nexus','CCM','Jenkins')]
        [string]$Name = $MyInvocation.InvocationName.Split('-')[-1],

        # The Url to check for a 200 response
        [Parameter(ParameterSetName='Url', Mandatory, Position=0)]
        [string]$Url = @{
            'Nexus'   = {
                try {
                    Get-NexusLocalServiceUri
                } catch {
                    Write-Verbose "Nexus may not be installed yet."
                    "http://localhost:8081"
                }
            }
            'CCM'     = {
                try {
                    $Binding = Get-WebBinding -Name ChocolateyCentralManagement
                    $Domain = if (
                        $Binding.protocol -eq 'https' -and
                        ($Certificate = Get-ChildItem Cert:\LocalMachine\TrustedPeople | Where-Object Subject -notlike 'CN=`**').Count -eq 1 -and
                        $Certificate.Subject -match "^CN=(?<Domain>.+)(?:,|$)"
                    ) {
                        $Matches.Domain
                    } elseif ($Binding.protocol -eq 'https' -and ($CertSubject = Get-ChocoEnvironmentProperty CertSubject)) {
                        $CertSubject
                    } else {
                        'localhost'
                    }
                    "$($Binding.protocol)://$($Domain):$($Binding.bindingInformation.Trim('*').Trim(':'))/"
                } catch {
                    Write-Verbose "CCM may not be installed yet."
                    "http://localhost"
                }
            }
            'Jenkins' = {
                try {
                    if (Test-Path "C:\Program Files\Jenkins\jenkins.xml") {
                        [xml]$Xml = Get-Content "C:\Program Files\Jenkins\jenkins.xml"
                        if ($Xml.SelectSingleNode("/service/arguments").'#text' -match "--(?<Scheme>https?)Port=(?<PortNumber>\d+)\b") {
                            $Port = $Matches.PortNumber
                            $Scheme = $Matches.Scheme
                        }
                        $Domain = if ($Scheme -eq 'https') {
                            Get-ChocoEnvironmentProperty CertSubject
                        } else {
                            'localhost'
                        }
                        "$($Scheme)://$($Domain):$($Port)/login"  # TODO: Get PATH
                    } elseif (Test-Path "C:\Program Files\Jenkins\jenkins.model.JenkinsLocationConfiguration.xml") {
                        [xml]$Location = (Get-Content "C:\Program Files\Jenkins\jenkins.model.JenkinsLocationConfiguration.xml" -ErrorAction Stop) -replace "^\<\?xml version=['""]1\.1['""]","<?xml version='1.0'"
                        $Location."jenkins.model.JenkinsLocationConfiguration".jenkinsUrl
                    }
                } catch {
                    Write-Verbose "Jenkins may not be installed yet."
                    "http://$('localhost'):8080/login"
                }
            }
        }.$Name.Invoke(),

        # Seconds before we give up waiting and fail
        [uint16]$Timeout = 180  # seconds
    )
    begin {
        $Timer = [System.Diagnostics.Stopwatch]::StartNew()

        if ([string]::IsNullOrEmpty($Url)) {
            Write-Error "Please pass a valid -Name or -Url to wait for." -ErrorAction Stop
        }
    }
    end {
        while ($Response.StatusCode -ne '200' -and $Timer.Elapsed.TotalSeconds -lt $Timeout) {
            $Response = try {
                Invoke-WebRequest $Url -UseBasicParsing -ErrorAction Stop
            } catch { $null }
        }

        if ($Response.StatusCode -eq '200') {
            Write-Verbose "'$($Url)' is accessible!"
        } else {
            Write-Error "'$($Url)' was not accessible after $($Timer.Elapsed.TotalSeconds) seconds." -ErrorAction Stop
        }
    }
}

Update-TypeData -TypeName SecureString -MemberType ScriptMethod -MemberName ToPlainText -Force -Value {
    [System.Net.NetworkCredential]::new("TempCredential", $this).Password
}

#region Package functions (OfflineInstallPreparation.ps1)
if (-not ("System.IO.Compression.ZipArchive" -as [type])) {
    Add-Type -Assembly 'System.IO.Compression'
}

function Find-FileInArchive {
    <#
        .Synopsis
            Finds files with a name matching a pattern in an archive.
        .Example
            Find-FileInArchive -Path "C:\Archive.zip" -like "tools/files/*-x86.exe"
        .Example
            Find-FileInArchive -Path $Nupkg -match "tools/files/dotnetcore-sdk-(?<Version>\d+\.\d+\.\d+)-win-x86\.exe(\.ignore)?"
        .Notes
            Please be aware that this matches against the full name of the file, not just the file name.
            Though given that, you can easily write something to match the file name.
    #>
    [CmdletBinding(DefaultParameterSetName = "match")]
    param(
        # Path to the archive
        [Parameter(Mandatory)]
        [string]$Path,

        # Pattern to match with regex
        [Parameter(Mandatory, ValueFromPipeline, ParameterSetName = "match")]
        [string]$match,
        
        # Pattern to match with basic globbing
        [Parameter(Mandatory, ParameterSetName = "like")]
        [string]$like
    )
    begin {
        while (-not $Zip -and $AccessRetries++ -lt 3) {
            try {
                $Stream = [IO.FileStream]::new($Path, [IO.FileMode]::Open)
                $Zip = [IO.Compression.ZipArchive]::new($Stream, [IO.Compression.ZipArchiveMode]::Read)
            } catch [System.IO.IOException] {
                if ($AccessRetries -ge 3) {
                    Write-Error -Message "Accessing '$Path' failed after $AccessRetries attempts." -TargetObject $Path
                } else {
                    Write-Information "Could not access '$Path', retrying..."
                    Start-Sleep -Milliseconds 500
                }
            }
        }
    }
    process {
        if ($Zip) {
            # Improve "security"?
            $WhereBlock = [ScriptBlock]::Create("`$_.FullName -$($PSCmdlet.ParameterSetName) '$(Get-Variable -Name $PSCmdlet.ParameterSetName -ValueOnly)'")
            $Zip.Entries | Where-Object -FilterScript $WhereBlock
        }
    }
    end {
        if ($Zip) {
            $Zip.Dispose()
        }
        if ($Stream) {
            $Stream.Close()
            $Stream.Dispose()
        }
    }
}

function Get-FileContentInArchive {
    <#
        .Synopsis
            Returns the content of a file from within an archive
        .Example
            Get-FileContentInArchive -Path $ZipPath -Name "chocolateyInstall.ps1"
        .Example
            Get-FileContentInArchive -Zip $Zip -FullName "tools\chocolateyInstall.ps1"
        .Example
            Find-FileInArchive -Path $ZipPath -Like *.nuspec | Get-FileContentInArchive
    #>
    [CmdletBinding(DefaultParameterSetName = "PathFullName")]
    [OutputType([string])]
    param(
        # Path to the archive
        [Parameter(Mandatory, ParameterSetName = "PathFullName")]
        [Parameter(Mandatory, ParameterSetName = "PathName")]
        [string]$Path,

        # Zip object for the archive
        [Parameter(Mandatory, ParameterSetName = "ZipFullName", ValueFromPipelineByPropertyName)]
        [Parameter(Mandatory, ParameterSetName = "ZipName", ValueFromPipelineByPropertyName)]
        [Alias("Archive")]
        [IO.Compression.ZipArchive]$Zip,

        # Name of the file(s) to remove from the archive
        [Parameter(Mandatory, ParameterSetName = "PathFullName", ValueFromPipelineByPropertyName)]
        [Parameter(Mandatory, ParameterSetName = "ZipFullName", ValueFromPipelineByPropertyName)]
        [string]$FullName,

        # Name of the file(s) to remove from the archive
        [Parameter(Mandatory, ParameterSetName = "PathName")]
        [Parameter(Mandatory, ParameterSetName = "ZipName")]
        [string]$Name
    )
    begin {
        if (-not $PSCmdlet.ParameterSetName.StartsWith("Zip")) {
            $Stream = [IO.FileStream]::new($Path, [IO.FileMode]::Open)
            $Zip = [IO.Compression.ZipArchive]::new($Stream, [IO.Compression.ZipArchiveMode]::Read)
        }
    }
    process {
        if (-not $FullName) {
            $MatchingEntries = $Zip.Entries | Where-Object {$_.Name -eq $Name}
            if ($MatchingEntries.Count -ne 1) {
                Write-Error "File '$Name' not found in archive" -ErrorAction Stop
            }
            $FullName = $MatchingEntries[0].FullName
        }
        [System.IO.StreamReader]::new(
            $Zip.GetEntry($FullName).Open()
        ).ReadToEnd()
    }
    end {
        if (-not $PSCmdlet.ParameterSetName.StartsWith("Zip")) {
            $Zip.Dispose()
            $Stream.Close()
            $Stream.Dispose()
        }
    }
}

function Get-ChocolateyPackageMetadata {
    [CmdletBinding(DefaultParameterSetName='All')]
    param(
        # The folder or nupkg to check
        [Parameter(Mandatory, Position=0, ValueFromPipelineByPropertyName)]
        [string]$Path,

        # If provided, filters found packages by ID
        [Parameter(Mandatory, Position=1, ParameterSetName='Id')]
        [SupportsWildcards()]
        [Alias('Name')]
        [string]$Id = '*'
    )
    process {
        Get-ChildItem $Path -Filter $Id*.nupkg | ForEach-Object {
            ([xml](Find-FileInArchive -Path $_.FullName -Like *.nuspec | Get-FileContentInArchive)).package.metadata | Where-Object Id -like $Id
        }
    }
}
#endregion

#region Nexus functions (Start-C4BNexusSetup.ps1)
function Invoke-NexusScript {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory)]
        [String]
        $ServerUri,

        [Parameter(Mandatory)]
        [Hashtable]
        $ApiHeader,
    
        [Parameter(Mandatory)]
        [String]
        $Script
    )
    try {
        $scriptName = [GUID]::NewGuid().ToString()
        New-NexusScript -Name $scriptName -Content $Script -Type "groovy"
        Start-NexusScript -Name $scriptName
    } finally {
        Remove-NexusScript -Name $scriptName
    }
}

#endregion

#region SSL functions (Set-SslSecurity.ps1)

function Get-Certificate {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]
        $Thumbprint,

        [Parameter()]
        [string]
        $Subject
    )

    $filter = if ($Thumbprint) {
        { $_.Thumbprint -eq $Thumbprint }
    }
    else {
        { $_.Subject -like "CN=$Subject" }
    }

    $cert = Get-ChildItem -Path Cert:\LocalMachine\My, Cert:\LocalMachine\TrustedPeople |
    Where-Object $filter -ErrorAction Stop |
    Select-Object -First 1

    if ($null -eq $cert) {
        throw "Certificate either not found, or other issue arose."
    }
    else {
        Write-Host "Certification validation passed" -ForegroundColor Green
        $cert
    }
}

function Copy-CertToStore {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]
        $Certificate
    )

    $location = [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine
    $trustedCertStore = [System.Security.Cryptography.X509Certificates.X509Store]::new('TrustedPeople', $location)

    try {
        $trustedCertStore.Open('ReadWrite')
        $trustedCertStore.Add($Certificate)
    }
    finally {
        $trustedCertStore.Close()
        $trustedCertStore.Dispose()
    }
}

function Get-RemoteCertificate {
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$ComputerName,

        [Parameter(Position = 1)]
        [UInt16]$Port = 8443
    )

    $tcpClient = New-Object System.Net.Sockets.TcpClient($ComputerName, $Port)
    $sslProtocolType = [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
    try {
        $tlsClient = New-Object System.Net.Security.SslStream($tcpClient.GetStream(), 'false', $callback)
        $tlsClient.AuthenticateAsClient($ComputerName, $null, $sslProtocolType, $false)

        return $tlsClient.RemoteCertificate -as [System.Security.Cryptography.X509Certificates.X509Certificate2]
    }
    finally {
        if ($tlsClient -is [IDisposable]) {
            $tlsClient.Dispose()
        }

        $tcpClient.Dispose()
    }
}

function Set-NexusCert {
    [CmdletBinding()]
    param(
        # The thumbprint of the certificate to configure Nexus to use, from the LocalMachine\TrustedPeople store.
        [Parameter(Mandatory)]
        $Thumbprint,

        # The port to set Nexus to use for https.
        $Port = 8443
    )

    $KeyTool = "C:\ProgramData\nexus\jre\bin\keytool.exe"
    $KeyStorePath = 'C:\ProgramData\nexus\etc\ssl\keystore.jks'
    $KeystoreCredential = [System.Net.NetworkCredential]::new(
        "Keystore",
        (New-ServicePassword)
    )
    $TempCertPath = Join-Path $env:TEMP "$(New-Guid).pfx"

    try {
        # Temporarily export the certificate as a PFX
        Get-ChildItem Cert:\LocalMachine\TrustedPeople\ | Where-Object { $_.Thumbprint -eq $Thumbprint } | Sort-Object | Select-Object -First 1 | Export-PfxCertificate -FilePath $TempCertPath -Password $KeystoreCredential.SecurePassword
        # TODO: Is this the right place for this? # Get-ChildItem -Path $TempCertPath | Import-PfxCertificate -CertStoreLocation Cert:\LocalMachine\My -Exportable -Password $KeystoreCredential.SecurePassword
        
        if (Test-Path $KeyStorePath) {
            Remove-Item $KeyStorePath -Force
        }

        # Using a job to hide improper non-output streams
        $Job = Start-Job {
            $string = ($using:KeystoreCredential.Password | & $using:KeyTool -list -v -keystore $using:TempCertPath -J"-Duser.language=en") -match '^Alias.*'
            $currentAlias = ($string -split ':')[1].Trim()
            & $using:KeyTool -importkeystore -srckeystore $using:TempCertPath -srcstoretype PKCS12 -srcstorepass $using:KeystoreCredential.Password -destkeystore $using:KeyStorePath -deststoretype JKS -alias $currentAlias -destalias jetty -deststorepass $using:KeystoreCredential.Password
            & $using:KeyTool -keypasswd -keystore $using:KeyStorePath -alias jetty -storepass $using:KeystoreCredential.Password -keypass $using:KeystoreCredential.Password -new $using:KeystoreCredential.Password
        } | Wait-Job
        if ($Job.State -eq 'Failed') {
            $Job | Receive-Job
        } else {
            $Job | Remove-Job
        }
    } finally {
        if (Test-Path $TempCertPath) {
            Remove-Item $TempCertPath -Force
        }
    }

    # Update the Nexus configuration
    $xmlPath = 'C:\ProgramData\nexus\etc\jetty\jetty-https.xml'
    [xml]$xml = Get-Content -Path 'C:\ProgramData\nexus\etc\jetty\jetty-https.xml'
    foreach ($entry in $xml.Configure.New.Where{ $_.id -match 'ssl' }.Set.Where{ $_.name -match 'password' }) {
        $entry.InnerText = $KeystoreCredential.Password
    }

    $xml.Save($xmlPath)

    $configPath = "C:\ProgramData\sonatype-work\nexus3\etc\nexus.properties"

    # Remove existing ssl config from the configuration
    (Get-Content $configPath) | Where-Object {$_ -notmatch "application-port-ssl="} | Set-Content $configPath

    # Ensure each line is added to the configuration
    @(
        'jetty.https.stsMaxAge=-1'
        "application-port-ssl=$Port"
        'nexus-args=${jetty.etc}/jetty.xml,${jetty.etc}/jetty-https.xml,${jetty.etc}/jetty-requestlog.xml'
    ) | ForEach-Object {
        if ((Get-Content -Raw $configPath) -notmatch [regex]::Escape($_)) {
            $_ | Add-Content -Path $configPath
        }
    }

    if ((Get-Service Nexus).Status -eq 'Running') {
        Restart-Service Nexus
    }
}

function Test-SelfSignedCertificate {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline = $true)]
        $Certificate = (Get-ChildItem -Path Cert:LocalMachine\My | Where-Object { $_.FriendlyName -eq $SubjectWithoutCn })
    )

    process {

        if ($Certificate.Subject -eq $Certificate.Issuer) {
            return $true
        }
        else {
            return $false
        }

    }

}

#endregion

#region CCM functions (Start-C4bCcmSetup.ps1)
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

    Write-Host "Adding $UserName to $DatabaseName with the following permissions: $($DatabaseRoles -Join ', ')"
    Write-Debug "running the following: \n $addUserSQLCommand"
    $Connection = New-Object System.Data.SQLClient.SQLConnection
    $Connection.ConnectionString = "server='$DatabaseServer';database='master';$DatabaseServerPermissionsOptions"
    $Connection.Open()
    $Command = New-Object System.Data.SQLClient.SQLCommand
    $Command.CommandText = $addUserSQLCommand
    $Command.Connection = $Connection
    $null = $Command.ExecuteNonQuery()
    $Connection.Close()
}

function Stop-CCMService {
    #Stop Central Management components
    Stop-Service chocolatey-central-management
    Get-Process chocolateysoftware.chocolateymanagement.web* | Stop-Process -ErrorAction SilentlyContinue -Force
}

function Remove-CcmBinding {
    [CmdletBinding()]
    param()

    process {
        Write-Verbose "Removing existing bindings"
        netsh http delete sslcert ipport=0.0.0.0:443 | Write-Verbose
    }
}

function New-CcmBinding {
    [CmdletBinding()]
    param(
        [string]$Thumbprint
    )
    Write-Verbose "Adding new binding https://${SubjectWithoutCn} to Chocolatey Central Management"

    $guid = [Guid]::NewGuid().ToString("B")
    netsh http add sslcert ipport=0.0.0.0:443 certhash=$Thumbprint certstorename=TrustedPeople appid="$guid" | Write-Verbose
    Get-WebBinding -Name ChocolateyCentralManagement | Remove-WebBinding
    New-WebBinding -Name ChocolateyCentralManagement -Protocol https -Port 443 -SslFlags 0 -IpAddress '*'
}

function Start-CcmService {
    try {
        Start-Service chocolatey-central-management -ErrorAction Stop
    }
    catch {
        #Try again...
        Start-Service chocolatey-central-management -ErrorAction SilentlyContinue
    }
    finally {
        if ((Get-Service chocolatey-central-management).Status -ne 'Running') {
            Write-Warning "Unable to start Chocolatey Central Management service, please start manually in Services.msc"
        }
    }

}

function Set-CcmCertificate {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [String]
        $CertificateThumbprint
    )

    process {
        Stop-Service chocolatey-central-management
        $jsonData = Get-Content $env:ChocolateyInstall\lib\chocolatey-management-service\tools\service\appsettings.json | ConvertFrom-Json
        $jsonData.CertificateThumbprint = $CertificateThumbprint
        $jsonData | ConvertTo-Json | Set-Content $env:chocolateyInstall\lib\chocolatey-management-service\tools\service\appsettings.json
        Start-Service chocolatey-central-management
    }
}

function Get-CcmAuthenticatedSession {
    [CmdletBinding()]
    [OutputType([Microsoft.PowerShell.Commands.WebRequestSession])]
    param(
        # The CCM server to operate against
        [string]$CcmEndpoint = "http://localhost",

        # The current credential for the account to change
        [System.Net.NetworkCredential]$Credential = @{
            userName = "ccmadmin"
            password = "123qwe"
        }
    )
    end {
        # Wait-CCM -Url $CcmEndpoint

        Write-Verbose "Authenticating to CCM Web at '$($CcmEndpoint)'"
        $methodParams = @{
            Uri             = "$CcmEndpoint/Account/Login"
            Body            = @{
                usernameOrEmailAddress = $Credential.Username
                password               = $Credential.Password
            }
            ContentType     = 'application/x-www-form-urlencoded'
            Method          = "POST"
            SessionVariable = "Session"
        }
        try {
            $null = Invoke-WebRequest @methodParams -UseBasicParsing -ErrorAction Stop
        } catch {
            Write-Error "Failed to authenticate with '$($CcmEndpoint)': $($_)"
        }

        $Session
    }
}

function Set-CcmAccountPassword {
    <#
        .Synopsis
            Sets the password for a current CCM user

        .Notes
            Relies on the account not being set to reset-password-on-next-login, and not locked out.
    #>
    [CmdletBinding()]
    param(
        # The CCM server to operate against
        [string]$CcmEndpoint = "http://localhost",

        # The current credential for the account to change
        [System.Net.NetworkCredential]$Credential = @{
            userName = "ccmadmin"
            password = "123qwe"
        },

        # A Valid ConnectionString for the CCM Database
        [string]$ConnectionString,

        # The new password to set
        [Parameter(Mandatory)]
        [SecureString]$NewPassword
    )
    $NewCredential = [System.Net.NetworkCredential]::new($Credential.UserName, $NewPassword)

    if ($ConnectionString) {
        try {
            $Connection = [System.Data.SQLClient.SqlConnection]::new($ConnectionString)
            $Connection.Open()
            $Query = [System.Data.SQLClient.SqlCommand]::new(
                "UPDATE [dbo].[AbpUsers] SET ShouldChangePasswordOnNextLogin = 0, IsLockoutEnabled = 0 WHERE Name = @UserName and TenantId = '1'",
                $Connection
            )
            $null = $Query.Parameters.Add(
                [System.Data.SqlClient.SqlParameter]::new('UserName', $Credential.UserName)
            )
            $QueryResult = $Query.BeginExecuteReader()
            while (-not $QueryResult.isCompleted) {
                Write-Verbose "Waiting for SQL Query to return"
                Start-Sleep -Milliseconds 100
            }
            if ($QueryResult.isCompleted -and -not $QueryResult.IsFaulted) {
                Write-Verbose "Unset ShouldChangePasswordOnNextLogin for '$($Credential.Username)'"
            }
        } finally {
            $Query.Dispose()
            $Connection.Close()
            $Connection.Dispose()
        }
    }

    $Session = Get-CcmAuthenticatedSession -CcmEndpoint $CcmEndpoint -Credential $Credential

    Write-Verbose "Changing password for account '$($Credential.UserName)'"
    $resetParams = @{
        Uri         = "$CcmEndpoint/api/services/app/Profile/ChangePassword"
        Body        = @{
            CurrentPassword   = $Credential.Password
            NewPassword       = $NewCredential.Password
            NewPasswordRepeat = $NewCredential.Password
        } | ConvertTo-Json
        ContentType = 'application/json'
        Method      = "POST"
        WebSession  = $Session
    }
    $Result = Invoke-RestMethod @resetParams -UseBasicParsing

    if ($Result.Success -eq 'true') {
        Write-Verbose "Password for account '$($Credential.UserName)' was changed successfully."
    }
}

function Update-CcmSettings {
    [CmdletBinding()]
    param(
        # The CCM server to operate against
        [string]$CcmEndpoint = "http://localhost",

        # The current credential for the admin account
        [System.Net.NetworkCredential]$Credential = @{
            userName = "ccmadmin"
            password = "123qwe"
        },

        # A hashtable of settings to update. Only works two levels deep.
        [hashtable]$Settings
    )
    end {
        $Session = Get-CcmAuthenticatedSession -CcmEndpoint $CcmEndpoint -Credential $Credential

        # Get Current Settings
        $ServerSettings = (Invoke-RestMethod -Uri $CcmEndpoint/api/services/app/TenantSettings/GetAllSettings -WebSession $Session).result

        # Overwrite Settings via Hashtable
        foreach ($Heading in $Settings.Keys) {
            foreach ($Setting in $Settings[$Heading].Keys) {
                $ServerSettings.$Heading.$Setting = $Settings.$Heading.$Setting
            }
        }

        # PUT new Settings to CCM
        $SettingChange = @{
            Uri         = "$CcmEndpoint/api/services/app/TenantSettings/UpdateAllSettings"
            Method      = "PUT"
            ContentType = 'application/json; charset=utf-8'
            Body        = $ServerSettings | ConvertTo-Json
            WebSession  = $Session
        }
        $Result = Invoke-RestMethod @SettingChange -ErrorAction Stop

        if ($Result.success) {
            Write-Verbose "Updated Settings successfully."
        }
    }
}

function Set-CcmEncryptionPassword {
    [CmdletBinding()]
    param(
        # The CCM server to operate against
        [string]$CcmEndpoint = "http://localhost",

        # The current credential for the account to change
        [System.Net.NetworkCredential]$Credential = @{
            userName = "ccmadmin"
            password = "123qwe"
        },

        # New encryption password to set
        [SecureString]$NewPassword,

        # Previous encryption password (unset on fresh install)
        [SecureString]$OldPassword = [SecureString]::new()
    )
    end {
        Update-CcmSettings -CcmEndpoint $CcmEndpoint -Credential $Credential -Settings @{
            encryption = @{
                oldPassphrase     = $OldPassword.ToPlainText()
                passphrase        = $NewPassword.ToPlainText()
                confirmPassphrase = $NewPassword.ToPlainText()
            }
        }
    }
}
#endregion

#region Jenkins Setup

# Function to generate Jenkins password 
function New-ServicePassword {
    <#
        .Synopsis
            Generates and returns a suitably secure password suited for support calls
    #>
    [CmdletBinding()]
    [OutputType([System.Security.SecureString])]
    param(
        [ValidateRange(1,128)]
        [int]$Length = 64,

        [char[]]$AvailableCharacters = @(
            # Specifically excluding $, `, ;, #, etc such that pasting
            # passwords into support scripts will be more predictable.
            "!%()*+,-./<=>?@[\]^_"
            48..57   # 0-9
            65..90   # A-Z
            97..122  # a-z
        ).ForEach{[char[]]$_}
    )
    end {
        $NewPassword = [System.Security.SecureString]::new()

        while ($NewPassword.Length -lt $Length) {
            $NewPassword.AppendChar(($AvailableCharacters | Get-Random))
        }

        $NewPassword
    }
}

function Get-BcryptDll {
    <#
        .Synopsis
            Finds the Bcrypt DLL if present, or downloads it if missing. Returns the full path to the DLL.
        .Example
            $BCryptDllPath = Get-BcryptDll
        .Example
            $BCryptDllPath = Get-BcryptDll -DestinationPath ~\Downloads
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        # The path to find the DLL within, or extract the DLL to if unfound.
        [Parameter(Position = 0)]
        [string]$DestinationPath = (Join-Path $PSScriptRoot "bcrypt.net.0.1.0")
    )
    end {
        if (-not (Test-Path $DestinationPath)) {
            $null = New-Item -Path $DestinationPath -ItemType Directory -Force
        }
        $ZipPath = Join-Path $env:TEMP 'bcrypt.net.0.1.0.zip'
        if (-not ($Files = Get-ChildItem $DestinationPath -Filter "BCrypt.Net.dll" -Recurse)) {
            if (-not (Test-Path $ZipPath)) {
                Invoke-WebRequest -Uri 'https://www.nuget.org/api/v2/package/BCrypt.Net/0.1.0' -OutFile $ZipPath -UseBasicParsing
            }
            Expand-Archive -Path $ZipPath -DestinationPath $DestinationPath
            $Files = Get-ChildItem $DestinationPath -Recurse
        }
        $Files.Where{$_.Name -eq 'BCrypt.Net.dll'}.FullName
    }
}

function Set-JenkinsPassword {
    <#
        .Synopsis
            Sets the password for a Jenkins user.
        .Example
            Set-JenkinsPassword -UserName 'admin' -NewPassword $JenkinsCred.Password
            # Sets the password to a known value
        .Example
            Set-JenkinsPassword -Credential $JenkinsCred
            # Sets the password to a known value
        .Example
            $JenkinsCred = Set-JenkinsPassword -UserName 'admin' -NewPassword $(New-ServicePassword) -PassThru
            # Sets the password and stores a credential object in $JenkinsCred.
        .Notes
            This probably will not work for federated and other non-standard accounts.
    #>
    [CmdletBinding(DefaultParameterSetName = 'Split')]
    param(
        # The credential of the user to try and set.
        [Parameter(ParameterSetName = 'Cred', Mandatory, Position=0)]
        [PSCredential]$Credential = [PSCredential]::new($UserName, $NewPassword),

        # The name of the user to forcibly set the password for.
        [Parameter(ParameterSetName = 'Split', Mandatory, Position=0)]
        [string]$UserName = $Credential.UserName,

        # The password to set for the user.
        [Parameter(ParameterSetName = 'Split', Mandatory, Position=1)]
        [SecureString]$NewPassword = $Credential.Password,

        # If set, passes the credential object for the user back.
        [Parameter()]
        [switch]$PassThru,

        # The path to the Jenkins data directory.
        [Parameter()]
        $JenkinsHome = (Join-Path $env:ProgramData "Jenkins\.jenkins")
    )
    try {
        $BCryptDllPath = Get-BcryptDll -ErrorAction Stop
        Add-Type -Path $BCryptDllPath -ErrorAction Stop
    } catch {
        Write-Error "Could not get Bcrypt DLL:`n$_"
    }

    $UserConfigPath = Resolve-Path "$JenkinsHome\users\$($UserName)_*\config.xml"
    if ($UserConfigPath.Count -ne 1) {
        Write-Error "$($UserConfigPath.Count) user config file(s) were found for user '$($UserName)'"
    }
    Write-Verbose "Updating '$($UserConfigPath)'"

    # Can't load as XML document as file is XML v1.1
    (Get-Content $UserConfigPath) -replace '<passwordHash>#jbcrypt:.*</passwordHash>',
    "<passwordHash>#jbcrypt:$(
        [bcrypt.net.bcrypt]::hashpassword(
            ([System.Net.NetworkCredential]$Credential).Password,
            ([bcrypt.net.bcrypt]::generatesalt(15))
        )
    )</passwordHash>" |
    Set-Content $UserConfigPath -Force

    if ($PassThru) {
        $Credential
    }
}

function Set-JenkinsLocationConfiguration {
    <#
        .Synopsis
            Sets the jenkinsUrl in the location configuration file.

        .Example
            Set-JenkinsURL -Url 'http://jenkins.fabrikam.com:8080'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        # The full URI to access Jenkins on, including port and scheme.
        [string]$Url,

        # The address to use as the admin e-mail address.
        [string]$AdminAddress = 'address not configured yet &lt;nobody@nowhere&gt;',

        [string]$Path = "C:\ProgramData\Jenkins\.jenkins\jenkins.model.JenkinsLocationConfiguration.xml"
    )
    @"
<?xml version='1.1' encoding='UTF-8'?>
<jenkins.model.JenkinsLocationConfiguration>
<adminAddress>$AdminAddress</adminAddress>
<jenkinsUrl>$Url</jenkinsUrl>
</jenkins.model.JenkinsLocationConfiguration>
"@ | Out-File -FilePath $Path -Encoding utf8
}

function Invoke-TextReplacementInFile {
    [CmdletBinding()]
    param(
        # The path to the file(s) to replace text in.
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('FullName')]
        [string]$Path,

        # The replacements to make, in a key-value format.
        [hashtable]$Replacement
    )
    process {
        $Content = Get-Content -Path $Path -Raw
        $Replacement.GetEnumerator().ForEach{
            $Content = $Content -replace $_.Key, $_.Value
        }
        $Content | Set-Content -Path $Path -NoNewline
    }
}

function Update-Clixml {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$Path = "$env:SystemDrive\choco-setup\clixml\chocolatey-for-business.xml",

        [Parameter(Mandatory)]
        [hashtable]$Properties
    )
    $CliXml = if (Test-Path $Path) {
        Import-Clixml $Path
    } else {
        if (-not (Test-Path (Split-Path $Path -Parent))) {
            $null = mkdir (Split-Path $Path -Parent) -Force
        }
        [PSCustomObject]@{}
    }

    $Properties.GetEnumerator().ForEach{
        Add-Member -InputObject $CliXml -MemberType NoteProperty -Name $_.Key -Value $_.Value -Force
    }

    $CliXml | Export-Clixml $Path -Force
}

function Get-ChocoEnvironmentProperty {
    [CmdletBinding(DefaultParameterSetName="All")]
    param(
        [Parameter(ParameterSetName="Specific", Mandatory, ValueFromPipeline, Position=0)]
        [string]$Name,

        [Parameter(ParameterSetName="Specific")]
        [switch]$AsPlainText
    )
    begin {
        if (Test-Path "$env:SystemDrive\choco-setup\clixml\chocolatey-for-business.xml") {
            $Content = Import-Clixml -Path "$env:SystemDrive\choco-setup\clixml\chocolatey-for-business.xml"
        }
    }
    process {
        if ($Name) {
            if ($AsPlainText -and $Content.$Name -is [System.Security.SecureString]) {
                return $Content.$Name.ToPlainText()
            } else {
                return $Content.$Name
            }
        } else {
            $Content
        }
    }
}

function Set-ChocoEnvironmentProperty {
    [CmdletBinding(DefaultParameterSetName="Key")]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName, ParameterSetName="Key", Position=0)]
        [Alias('Key')]
        [string]$Name,

        [Parameter(Mandatory, ValueFromPipelineByPropertyName, ParameterSetName="Key", Position=1)]
        $Value,

        [Parameter(Mandatory, ValueFromPipeline, ParameterSetName="Hashtable")]
        [hashtable]$InputObject = @{}
    )
    begin {
        $Properties = $InputObject
    }
    process {
        $Properties.$Name = $Value
    }
    end {
        Update-Clixml -Path "$env:SystemDrive\choco-setup\clixml\chocolatey-for-business.xml" -Properties $Properties
    }
}

function Set-JenkinsCertificate {
    <#
        .Synopsis
            Updates a keystore and ensure Jenkins is configured to use an appropriate port and certificate for HTTPS access

        .Example
            Set-JenkinsCert -Thumbprint $Thumbprint

        .Notes
            Requires a Jenkins service restart after the changes have been made.
    #>
    [CmdletBinding()]
    param(
        # The thumbprint of the certificate to use
        [Parameter(Mandatory)]
        [String]$Thumbprint,

        # The port to have HTTPS available on
        [Parameter()]
        [uint16]$Port = 7443
    )

    $KeyStore = "C:\ProgramData\Jenkins\.jenkins\keystore.jks"
    $KeyTool = Convert-Path "C:\Program Files\Eclipse Adoptium\jre-*.*\bin\keytool.exe"  # Using Temurin jre package keytool
    $Passkey = [System.Net.NetworkCredential]::new(
        "JksPassword",
        (New-ServicePassword -AvailableCharacters @(48..57 + 65..90 + 97..122))
    ).Password

    if (Test-Path $KeyStore) {
        Remove-Item $KeyStore -Force
    }

    # Generate the Keystore file
    try {
        $CertificatePath = Join-Path $env:Temp "$($Thumbprint).pfx"
        $CertificatePassword = [System.Net.NetworkCredential]::new(
            "TemporaryCertificatePassword",
            (New-ServicePassword)
        )

        # Temporarily export the certificate as a PFX
        $null = Get-ChildItem Cert:\LocalMachine\TrustedPeople\ | Where-Object {$_.Thumbprint -eq $Thumbprint} | Export-PfxCertificate -FilePath $CertificatePath -Password $CertificatePassword.SecurePassword

        # Using a job to hide improper non-output streams
        $Job = Start-Job {
            $CurrentAlias = ($($using:CertificatePassword.Password | & $using:KeyTool -list -v -storetype PKCS12 -keystore $using:CertificatePath -J"-Duser.language=en") -match "^Alias.*").Split(':')[1].Trim()

            $null = & $using:KeyTool -importkeystore -srckeystore $using:CertificatePath -srcstoretype PKCS12 -srcstorepass $using:CertificatePassword.Password -destkeystore $using:KeyStore -deststoretype JKS -alias $currentAlias -destalias jetty -deststorepass $using:Passkey
            $null = & $using:KeyTool -keypasswd -keystore $using:KeyStore -alias jetty -storepass $using:Passkey -keypass $using:CertificatePassword.Password -new $using:Passkey
        } | Wait-Job
        if ($Job.State -eq 'Failed') {
            $Job | Receive-Job
        } else {
            $Job | Remove-Job
        }
    } finally {
        # Clean up the exported certificate
        Remove-Item $CertificatePath
    }

    # Update the Jenkins Configuration
    $XmlPath = "C:\Program Files\Jenkins\jenkins.xml"
    [xml]$Xml = Get-Content $XmlPath
    @{
        httpPort              = -1
        httpsPort             = $Port
        httpsKeyStore         = $KeyStore
        httpsKeyStorePassword = $Passkey
    }.GetEnumerator().ForEach{
        if ($Xml.SelectSingleNode("/service/arguments")."#text" -notmatch [Regex]::Escape("--$($_.Key)=$($_.Value)")) {
            $Xml.SelectSingleNode("/service/arguments")."#text" = $Xml.SelectSingleNode("/service/arguments")."#text" -replace "\s*--$($_.Key)=.+?\b", ""
            $Xml.SelectSingleNode("/service/arguments")."#text" += " --$($_.Key)=$($_.Value)"
        }
    }
    $Xml.Save($XmlPath)

    if ((Get-Service Jenkins).Status -eq 'Running') {
        Restart-Service Jenkins
    }
}

function Update-JenkinsJobParameters {
    param(
        [string]$JobsPath = "C:\ProgramData\Jenkins\.jenkins\jobs",

        [hashtable]$Replacement = @{}
    )
    process {
        foreach ($Job in Get-ChildItem $JobsPath -Filter config.xml -Recurse) {
            Write-Verbose "Updating parameters in '$($Job.DirectoryName)'"
            [xml]$Config = (Get-Content $Job.FullName) -replace "^\<\?xml version=['""]1\.1['""]","<?xml version='1.0'"

            foreach ($Node in $Config.SelectSingleNode("//parameterDefinitions").ChildNodes) {
                if ($Node.name -in $Replacement.Keys) {
                    $Node.defaultValue = $Replacement[$Node.name]
                }
            }

            $Config.Save($Job.FullName)
        }
    }
}
#endregion

#region README functions
Function New-QuickstartReadme {
    <#
.SYNOPSIS
Generates a desktop README file containing service information for all services provisioned as part of the Quickstart Guide.
.PARAMETER HostName
The host name of the C4B instance.
.EXAMPLE
./New-QuickstartReadme.ps1
.EXAMPLE
./New-QuickstartReadme.ps1 -HostName c4b.example.com
#>
    [CmdletBinding()]
    param()
    process {
        try {
            $Data = Get-ChocoEnvironmentProperty
        } catch {
            Write-Error "Unable to read stored values. Ensure the Quickstart Guide has been completed."
        }

        Copy-Item $PSScriptRoot\ReadmeTemplate.html.j2 -Destination $env:Public\Desktop\Readme.html -Force
        
        # Working around the existing j2 template, so we can keep them roughly in sync
        Invoke-TextReplacementInFile -Path $env:Public\Desktop\Readme.html -Replacement @{
            # CCM Values
            "{{ ccm_fqdn .*?}}" = ([uri]$Data.CCMWebPortal).DnsSafeHost
            "{{ ccm_port .*?}}"     = ([uri]$Data.CCMWebPortal).Port
            "{{ ccm_password .*?}}" = [System.Web.HttpUtility]::HtmlEncode($Data.CCMCredential.Password.ToPlainText())

            # Chocolatey Configuration Values
            "{{ ccm_encryption_password .*?}}" = [System.Web.HttpUtility]::HtmlEncode($Data.CCMEncryptionPassword.ToPlainText())
            "{{ ccm_client_salt .*?}}" = [System.Web.HttpUtility]::HtmlEncode($Data.ClientSalt.ToPlainText())
            "{{ ccm_service_salt .*?}}" = [System.Web.HttpUtility]::HtmlEncode($Data.ServiceSalt.ToPlainText())
            "{{ chocouser_password .*?}}" = [System.Web.HttpUtility]::HtmlEncode($Data.NexusCredential.Password.ToPlainText())

            # Nexus Values
            "{{ nexus_fqdn .*?}}" = ([uri]$Data.NexusUri).DnsSafeHost
            "{{ nexus_port .*?}}" = ([uri]$Data.NexusUri).Port
            "{{ nexus_password .*?}}" = [System.Web.HttpUtility]::HtmlEncode($Data.NexusCredential.Password.ToPlainText())
            "{{ lookup\('file', 'credentials\/nexus_apikey'\) .*?}}" = $Data.NugetApiKey.ToPlainText()

            "{{ nexus_client_username .*?}}" = 'chocouser'
            "{{ nexus_client_password .*?}}" = [System.Web.HttpUtility]::HtmlEncode($Data.ChocoUserPassword.ToPlainText())

            "{{ nexus_packager_username .*?}}" = $Data.PackageUploadCredential.Username
            "{{ nexus_packager_password .*?}}" = [System.Web.HttpUtility]::HtmlEncode($Data.PackageUploadCredential.Password.ToPlainText())

            # Jenkins Values
            "{{ jenkins_fqdn .*?}}" = ([uri]$Data.JenkinsUri).DnsSafeHost
            "{{ jenkins_port .*?}}" = ([uri]$Data.JenkinsUri).Port
            "{{ jenkins_password .*?}}" = [System.Web.HttpUtility]::HtmlEncode($Data.JenkinsCredential.Password.ToPlainText())
        }
    }
}
#endregion

function Complete-C4bSetup {
    param(
        [switch]$SkipBrowserLaunch
    )
    # Setup Agent on this machine
    if (-not (Get-Service chocolatey-agent -ErrorAction SilentlyContinue)) {
        Invoke-Choco install chocolatey-agent --confirm
        Invoke-Choco feature enable --name='useChocolateyCentralManagement'
        Invoke-Choco feature enable --name='useChocolateyCentralManagementDeployments'
    }

    # Write readme to desktop and hand over to user
    Write-Host 'Writing README to Desktop - this file contains login information for all C4B services.'
    New-QuickstartReadme

    if (-not $SkipBrowserLaunch -and $Host.Name -eq 'ConsoleHost') {
        $Message = 'The CCM, Nexus & Jenkins sites will open in your browser in 10 seconds. Press any key to skip this.'
        $Stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
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
        } while ($Stopwatch.Elapsed.TotalSeconds -lt 10)

        if (-not ($keyInfo)) {
            Write-Host "`nOpening CCM, Nexus & Jenkins sites in your browser." -ForegroundColor Green
            Start-Process msedge.exe @(
                'file:///C:/Users/Public/Desktop/README.html',
                (Get-ChocoEnvironmentProperty CCMWebPortal),
                (Get-ChocoEnvironmentProperty NexusUri),
                (Get-ChocoEnvironmentProperty JenkinsUri)
            )
        }
    }
}

# Check for and configure FIPS enforcement, if required.
if (
    (Get-ItemPropertyValue -Path "HKLM:\System\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy" -Name Enabled) -eq 1 -and
    $env:ChocolateyInstall -and
    -not [bool]::Parse(([xml](Get-Content $env:ChocolateyInstall\config\chocolatey.config)).chocolatey.features.feature.Where{$_.Name -eq 'useFipsCompliantChecksums'}.Enabled)
) {
    Write-Warning -Message "FIPS is enabled on this system. Ensuring Chocolatey uses FIPS compliant checksums"
    Invoke-Choco feature enable --name='useFipsCompliantChecksums'
}

Export-ModuleMember -Function "*"