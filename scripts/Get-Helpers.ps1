# Helper Functions for the various QSG scripts

#region Nexus functions (Start-C4BNexusSetup.ps1)
function Wait-Nexus {
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::tls12
    Do {
        $response = try {
            Invoke-WebRequest $("http://localhost:8081") -ErrorAction Stop
        }
        catch {
            $null
        }
        
    } until($response.StatusCode -eq '200')
    Write-Host "Nexus is ready!"

}

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

    $scriptName = [GUID]::NewGuid().ToString()
    $body = @{
        name    = $scriptName
        type    = 'groovy'
        content = $Script
    }

    # Call the API
    $baseUri = "$ServerUri/service/rest/v1/script"

    #Store the Script
    $uri = $baseUri
    Invoke-RestMethod -Uri $uri -ContentType 'application/json' -Body $($body | ConvertTo-Json) -Header $ApiHeader -Method Post
    #Run the script
    $uri = "{0}/{1}/run" -f $baseUri, $scriptName
    $result = Invoke-RestMethod -Uri $uri -ContentType 'text/plain' -Header $ApiHeader -Method Post
    #Delete the Script
    $uri = "{0}/{1}" -f $baseUri, $scriptName
    Invoke-RestMethod -Uri $uri -Header $ApiHeader -Method Delete -UseBasicParsing

    $result

}

function Connect-NexusServer {
    <#
    .SYNOPSIS
    Creates the authentication header needed for REST calls to your Nexus server
    
    .DESCRIPTION
    Creates the authentication header needed for REST calls to your Nexus server
    
    .PARAMETER Hostname
    The hostname or ip address of your Nexus server
    
    .PARAMETER Credential
    The credentials to authenticate to your Nexus server
    
    .PARAMETER UseSSL
    Use https instead of http for REST calls. Defaults to 8443.
    
    .PARAMETER Sslport
    If not the default 8443 provide the current SSL port your Nexus server uses
    
    .EXAMPLE
    Connect-NexusServer -Hostname nexus.fabrikam.com -Credential (Get-Credential)
    .EXAMPLE
    Connect-NexusServer -Hostname nexus.fabrikam.com -Credential (Get-Credential) -UseSSL
    .EXAMPLE
    Connect-NexusServer -Hostname nexus.fabrikam.com -Credential $Cred -UseSSL -Sslport 443
    #>
    [cmdletBinding(HelpUri='https://steviecoaster.dev/TreasureChest/Connect-NexusServer/')]
    param(
        [Parameter(Mandatory,Position=0)]
        [Alias('Server')]
        [String]
        $Hostname,

        [Parameter(Mandatory,Position=1)]
        [System.Management.Automation.PSCredential]
        $Credential,

        [Parameter()]
        [Switch]
        $UseSSL,

        [Parameter()]
        [String]
        $Sslport = '8443'
    )

    process {

        if($UseSSL){
            $script:protocol = 'https'
            $script:port = $Sslport
        } else {
            $script:protocol = 'http'
            $script:port = '8081'
        }

        $script:HostName = $Hostname

        $credPair = "{0}:{1}" -f $Credential.UserName,$Credential.GetNetworkCredential().Password

        $encodedCreds = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($credPair))

        $script:header = @{ Authorization = "Basic $encodedCreds"}

        try {
            $url = "$($protocol)://$($Hostname):$($port)/service/rest/v1/status"

            $params = @{
                Headers = $header
                ContentType = 'application/json'
                Method = 'GET'
                Uri = $url
            }

            $result =Invoke-RestMethod @params -ErrorAction Stop
            Write-Host "Connected to $Hostname" -ForegroundColor Green
        }

        catch {
            $_.Exception.Message
        }
    }
}

function Invoke-Nexus {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [String]
        $UriSlug,

        [Parameter()]
        [Hashtable]
        $Body,

        [Parameter()]
        [Array]
        $BodyAsArray,

        [Parameter()]
        [String]
        $BodyAsString,

        [Parameter()]
        [String]
        $File,

        [Parameter()]
        [String]
        $ContentType = 'application/json',

        [Parameter(Mandatory)]
        [String]
        $Method


    )
    process {

        $UriBase = "$($protocol)://$($Hostname):$($port)"
        $Uri = $UriBase + $UriSlug
        $Params = @{
            Headers = $header
            ContentType = $ContentType
            Uri = $Uri
            Method = $Method
        }

        if($Body){
                $Params.Add('Body',$($Body | ConvertTo-Json -Depth 3))
            } 
        
        if($BodyAsArray){
            $Params.Add('Body',$($BodyAsArray | ConvertTo-Json -Depth 3))
        }

        if($BodyAsString){
            $Params.Add('Body',$BodyAsString)
        }

        if($File){
            $Params.Remove('ContentType')
            $Params.Add('InFile',$File)
        }

         Invoke-RestMethod @Params
        

    }
}

function Get-NexusUserToken {
    <#
    .SYNOPSIS
    Fetches a User Token for the provided credential
    
    .DESCRIPTION
    Fetches a User Token for the provided credential
    
    .PARAMETER Credential
    The Nexus user for which to receive a token
    
    .NOTES
    This is a private function not exposed to the end user. 
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [PSCredential]
        $Credential
    )

    process {
        $UriBase = "$($protocol)://$($Hostname):$($port)"
        
        $slug = '/service/extdirect'

        $uri = $UriBase + $slug

        $data = @{
            action = 'rapture_Security'
            method = 'authenticationToken'
            data   = @("$([System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($($Credential.Username))))", "$([System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($($Credential.GetNetworkCredential().Password))))")
            type   = 'rpc'
            tid    = 16 
        }

        Write-Verbose ($data | ConvertTo-Json)
        $result = Invoke-RestMethod -Uri $uri -Method POST -Body ($data | ConvertTo-Json) -ContentType 'application/json' -Headers $header
        $token = $result.result.data
        $token
    }

}

function Get-NexusRepository {
    <#
    .SYNOPSIS
    Returns info about configured Nexus repository
    
    .DESCRIPTION
    Returns details for currently configured repositories on your Nexus server
    
    .PARAMETER Format
    Query for only a specific repository format. E.g. nuget, maven2, or docker
    
    .PARAMETER Name
    Query for a specific repository by name
    
    .EXAMPLE
    Get-NexusRepository
    .EXAMPLE
    Get-NexusRepository -Format nuget
    .EXAMPLE
    Get-NexusRepository -Name CompanyNugetPkgs
    #>
    [cmdletBinding(HelpUri='https://steviecoaster.dev/TreasureChest/Get-NexusRepository/',DefaultParameterSetName="default")]
    param(
        [Parameter(ParameterSetName="Format",Mandatory)]
        [String]
        [ValidateSet('apt','bower','cocoapods','conan','conda','docker','gitlfs','go','helm','maven2','npm','nuget','p2','pypi','r','raw','rubygems','yum')]
        $Format,

        [Parameter(ParameterSetName="Type",Mandatory)]
        [String]
        [ValidateSet('hosted','group','proxy')]
        $Type,

        [Parameter(ParameterSetName="Name",Mandatory)]
        [String]
        $Name
    )


    begin {

        if(-not $header){
            throw "Not connected to Nexus server! Run Connect-NexusServer first."
        }

        $urislug = "/service/rest/v1/repositories"
    }
    process {

        switch($PSCmdlet.ParameterSetName){
            {$Format} {
                $filter = { $_.format -eq $Format}

                $result = Invoke-Nexus -UriSlug $urislug -Method Get
                $result | Where-Object $filter
                
            }

            {$Name} {
                $filter = { $_.name -eq $Name }

                $result = Invoke-Nexus -UriSlug $urislug -Method Get
                $result | Where-Object $filter

            }

            {$Type} {
                $filter = { $_.type -eq $Type }
                $result = Invoke-Nexus -UriSlug $urislug -Method Get
                $result | Where-Object $filter
            }

            default {
                Invoke-Nexus -UriSlug $urislug -Method Get| ForEach-Object { 
                    [pscustomobject]@{
                        Name = $_.SyncRoot.name
                        Format = $_.SyncRoot.format
                        Type = $_.SyncRoot.type
                        Url = $_.SyncRoot.url
                        Attributes = $_.SyncRoot.attributes
                    }
                }
            }
        }
    }
}

function Remove-NexusRepository {
    <#
    .SYNOPSIS
    Removes a given repository from the Nexus instance
    
    .DESCRIPTION
    Removes a given repository from the Nexus instance
    
    .PARAMETER Repository
    The repository to remove
    
    .PARAMETER Force
    Disable prompt for confirmation before removal
    
    .EXAMPLE
    Remove-NexusRepository -Repository ProdNuGet
    .EXAMPLE
    Remove-NexusRepository -Repository MavenReleases -Force()
    #>
    [CmdletBinding(HelpUri = 'https://steviecoaster.dev/TreasureChest/Remove-NexusRepository/', SupportsShouldProcess, ConfirmImpact = 'High')]
    Param(
        [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [Alias('Name')]
        [ArgumentCompleter( {
                param($command, $WordToComplete, $CommandAst, $FakeBoundParams)
                $repositories = (Get-NexusRepository).Name

                if ($WordToComplete) {
                    $repositories.Where{ $_ -match "^$WordToComplete" }
                }
                else {
                    $repositories
                }
            })]
        [String[]]
        $Repository,

        [Parameter()]
        [Switch]
        $Force
    )
    begin {

        if (-not $header) {
            throw "Not connected to Nexus server! Run Connect-NexusServer first."
        }

        $urislug = "/service/rest/v1/repositories"
    }
    process {

        $Repository | Foreach-Object {
            $Uri = $urislug + "/$_"

            try {
           
                if ($Force -and -not $Confirm) {
                    $ConfirmPreference = 'None'
                    if ($PSCmdlet.ShouldProcess("$_", "Remove Repository")) {
                        $result = Invoke-Nexus -UriSlug $Uri -Method 'DELETE' -ErrorAction Stop
                        [pscustomobject]@{
                            Status     = 'Success'
                            Repository = $_     
                        }
                    }
                }
                else {
                    if ($PSCmdlet.ShouldProcess("$_", "Remove Repository")) {
                        $result = Invoke-Nexus -UriSlug $Uri -Method 'DELETE' -ErrorAction Stop
                        [pscustomobject]@{
                            Status     = 'Success'
                            Repository = $_
                            Timestamp  = $result.date
                        }
                    }
                }
            }

            catch {
                $_.exception.message
            }
        }
    }
}

function New-NexusNugetHostedRepository {
    <#
    .SYNOPSIS
    Creates a new NuGet Hosted repository
    
    .DESCRIPTION
    Creates a new NuGet Hosted repository
    
    .PARAMETER Name
    The name of the repository
    
    .PARAMETER CleanupPolicy
    The Cleanup Policies to apply to the repository
    
    
    .PARAMETER Online
    Marks the repository to accept incoming requests
    
    .PARAMETER BlobStoreName
    Blob store to use to store NuGet packages
    
    .PARAMETER StrictContentValidation
    Validate that all content uploaded to this repository is of a MIME type appropriate for the repository format
    
    .PARAMETER DeploymentPolicy
    Controls if deployments of and updates to artifacts are allowed
    
    .PARAMETER HasProprietaryComponents
    Components in this repository count as proprietary for namespace conflict attacks (requires Sonatype Nexus Firewall)
    
    .EXAMPLE
    New-NexusNugetHostedRepository -Name NugetHostedTest -DeploymentPolicy Allow
    .EXAMPLE
    $RepoParams = @{
        Name = MyNuGetRepo
        CleanupPolicy = '90 Days'
        DeploymentPolicy = 'Allow'
        UseStrictContentValidation = $true
    }
    
    New-NexusNugetHostedRepository @RepoParams
    .NOTES
    General notes
    #>
    [CmdletBinding(HelpUri = 'https://steviecoaster.dev/TreasureChest/New-NexusNugetHostedRepository/')]
    Param(
        [Parameter(Mandatory)]
        [String]
        $Name,

        [Parameter()]
        [String]
        $CleanupPolicy,

        [Parameter()]
        [Switch]
        $Online = $true,

        [Parameter()]
        [String]
        $BlobStoreName = 'default',

        [Parameter()]
        [ValidateSet('True', 'False')]
        [String]
        $UseStrictContentValidation = 'True',

        [Parameter()]
        [ValidateSet('Allow', 'Deny', 'Allow_Once')]
        [String]
        $DeploymentPolicy,

        [Parameter()]
        [Switch]
        $HasProprietaryComponents
    )

    begin {

        if (-not $header) {
            throw "Not connected to Nexus server! Run Connect-NexusServer first."
        }

        $urislug = "/service/rest/v1/repositories"

    }

    process {
        $formatUrl = $urislug + '/nuget'

        $FullUrlSlug = $formatUrl + '/hosted'


        $body = @{
            name    = $Name
            online  = [bool]$Online
            storage = @{
                blobStoreName               = $BlobStoreName
                strictContentTypeValidation = $UseStrictContentValidation
                writePolicy                 = $DeploymentPolicy
            }
            cleanup = @{
                policyNames = @($CleanupPolicy)
            }
        }

        if ($HasProprietaryComponents) {
            $Prop = @{
                proprietaryComponents = 'True'
            }
    
            $Body.Add('component', $Prop)
        }

        Write-Verbose $($Body | ConvertTo-Json)
        Invoke-Nexus -UriSlug $FullUrlSlug -Body $Body -Method POST

    }
}

function New-NexusRawHostedRepository {
    <#
    .SYNOPSIS
    Creates a new Raw Hosted repository
    
    .DESCRIPTION
    Creates a new Raw Hosted repository
    
    .PARAMETER Name
    The Name of the repository to create
    
    .PARAMETER Online
    Mark the repository as Online. Defaults to True
    
    .PARAMETER BlobStore
    The blob store to attach the repository too. Defaults to 'default'
    
    .PARAMETER UseStrictContentTypeValidation
    Validate that all content uploaded to this repository is of a MIME type appropriate for the repository format
    
    .PARAMETER DeploymentPolicy
    Controls if deployments of and updates to artifacts are allowed
    
    .PARAMETER CleanupPolicy
    Components that match any of the Applied policies will be deleted
    
    .PARAMETER HasProprietaryComponents
    Components in this repository count as proprietary for namespace conflict attacks (requires Sonatype Nexus Firewall)
    
    .PARAMETER ContentDisposition
    Add Content-Disposition header as 'Attachment' to disable some content from being inline in a browser.
    
    .EXAMPLE
    New-NexusRawHostedRepository -Name BinaryArtifacts -ContentDisposition Attachment
    .EXAMPLE
    $RepoParams = @{
        Name = 'BinaryArtifacts'
        Online = $true
        UseStrictContentTypeValidation = $true
        DeploymentPolicy = 'Allow'
        CleanupPolicy = '90Days',
        BlobStore = 'AmazonS3Bucket'
    }
    New-NexusRawHostedRepository @RepoParams
    
    .NOTES
    #>
    [CmdletBinding(HelpUri = 'https://steviecoaster.dev/TreasureChest/New-NexusRawHostedRepository/', DefaultParameterSetname = "Default")]
    Param(
        [Parameter(Mandatory)]
        [String]
        $Name,

        [Parameter()]
        [Switch]
        $Online = $true,

        [Parameter()]
        [String]
        $BlobStore = 'default',

        [Parameter()]
        [Switch]
        $UseStrictContentTypeValidation,

        [Parameter()]
        [ValidateSet('Allow', 'Deny', 'Allow_Once')]
        [String]
        $DeploymentPolicy = 'Allow_Once',

        [Parameter()]
        [String]
        $CleanupPolicy,

        [Parameter()]
        [Switch]
        $HasProprietaryComponents,

        [Parameter(Mandatory)]
        [ValidateSet('Inline','Attachment')]
        [String]
        $ContentDisposition
    )

    begin {

        if (-not $header) {
            throw "Not connected to Nexus server! Run Connect-NexusServer first."
        }

        $urislug = "/service/rest/v1/repositories/raw/hosted"

    }

    process {

        $Body = @{
            name = $Name
            online = [bool]$Online
            storage = @{
                blobStoreName = $BlobStore
                strictContentTypeValidation = [bool]$UseStrictContentTypeValidation
                writePolicy = $DeploymentPolicy.ToLower()
            }
            cleanup = @{
                policyNames = @($CleanupPolicy)
            }
            component = @{
                proprietaryComponents = [bool]$HasProprietaryComponents
            }
            raw = @{
                contentDisposition = $ContentDisposition.ToUpper()
            }
        }

        Write-Verbose $($Body | ConvertTo-Json)
        Invoke-Nexus -UriSlug $urislug -Body $Body -Method POST


    }
}

function Get-NexusRealm {
    <#
    .SYNOPSIS
    Gets Nexus Realm information
    
    .DESCRIPTION
    Gets Nexus Realm information
    
    .PARAMETER Active
    Returns only active realms
    
    .EXAMPLE
    Get-NexusRealm
    .EXAMPLE
    Get-NexusRealm -Active
    #>
    [CmdletBinding(HelpUri = 'https://steviecoaster.dev/TreasureChest/Get-NexusRealm/')]
    Param(
        [Parameter()]
        [Switch]
        $Active
    )

    begin {

        if (-not $header) {
            throw "Not connected to Nexus server! Run Connect-NexusServer first."
        }

        
        $urislug = "/service/rest/v1/security/realms/available"
        

    }

    process {

        if ($Active) {
            $current = Invoke-Nexus -UriSlug $urislug -Method 'GET'
            $urislug = '/service/rest/v1/security/realms/active'
            $Activated = Invoke-Nexus -UriSlug $urislug -Method 'GET'
            $current | Where-Object { $_.Id -in $Activated }
        }
        else {
            $result = Invoke-Nexus -UriSlug $urislug -Method 'GET' 

            $result | Foreach-Object {
                [pscustomobject]@{
                    Id   = $_.id
                    Name = $_.name
                }
            }
        }
    }
}

function Enable-NexusRealm {
    <#
    .SYNOPSIS
    Enable realms in Nexus
    
    .DESCRIPTION
    Enable realms in Nexus
    
    .PARAMETER Realm
    The realms you wish to activate
    
    .EXAMPLE
    Enable-NexusRealm -Realm 'NuGet Api-Key Realm', 'Rut Auth Realm'
    .EXAMPLE
    Enable-NexusRealm -Realm 'LDAP Realm'
    
    .NOTES
    #>
    [CmdletBinding(HelpUri = 'https://steviecoaster.dev/TreasureChest/Enable-NexusRealm/')]
    Param(
        [Parameter(Mandatory)]
        [ArgumentCompleter({
            param($Command,$Parameter,$WordToComplete,$CommandAst,$FakeBoundParams)

            $r = (Get-NexusRealm).name

            if($WordToComplete){
                $r.Where($_ -match "^$WordToComplete")
            } else {
                $r
            }
        }
        )]
        [String[]]
        $Realm
    )

    begin {

        if (-not $header) {
            throw "Not connected to Nexus server! Run Connect-NexusServer first."
        }

        $urislug = "/service/rest/v1/security/realms/active"

    }

    process {

        $collection = @()

        Get-NexusRealm -Active | ForEach-Object { $collection += $_.id }

        $Realm | Foreach-Object {

            switch($_){
                'Conan Bearer Token Realm' { $id = 'org.sonatype.repository.conan.internal.security.token.ConanTokenRealm' }
                'Default Role Realm' { $id = 'DefaultRole' }
                'Docker Bearer Token Realm' { $id = 'DockerToken' }
                'LDAP Realm' { $id = 'LdapRealm' }
                'Local Authentication Realm' { $id = 'NexusAuthenticatingRealm'}
                'Local Authorizing Realm' {$id = 'NexusAuthorizingRealm'}
                'npm Bearer Token Realm' {$id = 'NpmToken'}
                'NuGet API-Key Realm' { $id = 'NuGetApiKey'}
                'Rut Auth Realm' { $id = 'rutauth-realm'}
            }

            $collection += $id
    
        }

        $body = $collection

        Write-Verbose $($Body | ConvertTo-Json)
        Invoke-Nexus -UriSlug $urislug -BodyAsArray $Body -Method PUT

    }
}

function Get-NexusNuGetApiKey {
    <#
    .SYNOPSIS
    Retrieves the NuGet API key of the given user credential
    
    .DESCRIPTION
    Retrieves the NuGet API key of the given user credential
    
    .PARAMETER Credential
    The Nexus User whose API key you wish to retrieve
    
    .EXAMPLE
    Get-NexusNugetApiKey -Credential (Get-Credential)
    
    .NOTES
    
    #>
    [CmdletBinding(HelpUri='https://steviecoaster.dev/TreasureChest/Security/API%20Key/Get-NexusNuGetApiKey/')]
    Param(
        [Parameter(Mandatory)]
        [PSCredential]
        $Credential
    )

    process {
        $token = Get-NexusUserToken -Credential $Credential
        $base64Token = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($token))
        $UriBase = "$($protocol)://$($Hostname):$($port)"
        
        $slug = "/service/rest/internal/nuget-api-key?authToken=$base64Token&_dc=$(([DateTime]::ParseExact("01/02/0001 21:08:29", "MM/dd/yyyy HH:mm:ss",$null)).Ticks)"

        $uri = $UriBase + $slug

        Invoke-RestMethod -Uri $uri -Method GET -ContentType 'application/json' -Headers $header

    }
}

function New-NexusRawComponent {
    <#
    .SYNOPSIS
    Uploads a file to a Raw repository
    
    .DESCRIPTION
    Uploads a file to a Raw repository
    
    .PARAMETER RepositoryName
    The Raw repository to upload too
    
    .PARAMETER File
    The file to upload
    
    .PARAMETER Directory
    The directory to store the file on the repo
    
    .PARAMETER Name
    The name of the file stored into the repo. Can be different than the file name being uploaded.
    
    .EXAMPLE
    New-NexusRawComponent -RepositoryName GeneralFiles -File C:\temp\service.1234.log
    .EXAMPLE
    New-NexusRawComponent -RepositoryName GeneralFiles -File C:\temp\service.log -Directory logs
    .EXAMPLE
    New-NexusRawComponent -RepositoryName GeneralFile -File C:\temp\service.log -Directory logs -Name service.99999.log
    
    .NOTES
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [String]
        $RepositoryName,

        [Parameter(Mandatory)]
        [String]
        $File,

        [Parameter()]
        [String]
        $Directory,

        [Parameter()]
        [String]
        $Name = (Split-Path -Leaf $File)
    )

    process {

        if(-not $Directory){
            $urislug = "/repository/$($RepositoryName)/$($Name)"
        }
        else {
            $urislug = "/repository/$($RepositoryName)/$($Directory)/$($Name)"

        }
        $UriBase = "$($protocol)://$($Hostname):$($port)"
        $Uri = $UriBase + $UriSlug


        $params = @{
            Uri         = $Uri
            Method      = 'PUT'
            ContentType = 'text/plain'
            InFile        = $File
            Headers     = $header
            UseBasicParsing = $true
        }

        $null = Invoke-WebRequest @params        
    }
}

#endregion

#region Bootstrap functions (Start-C4bSetup.ps1)

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


function New-NexusCert {
    [CmdletBinding()]
    param(
        [Parameter()]
        $Thumbprint
    )

    if ((Test-Path C:\ProgramData\nexus\etc\ssl\keystore.jks)) {
        Remove-Item C:\ProgramData\nexus\etc\ssl\keystore.jks -Force
    }

    $KeyTool = "C:\ProgramData\nexus\jre\bin\keytool.exe"
    $password = "chocolatey" | ConvertTo-SecureString -AsPlainText -Force
    $certificate = Get-ChildItem  Cert:\LocalMachine\TrustedPeople\ | Where-Object { $_.Thumbprint -eq $Thumbprint } | Sort-Object | Select-Object -First 1

    Write-Host "Exporting .pfx file to C:\, will remove when finished" -ForegroundColor Green
    $certificate | Export-PfxCertificate -FilePath C:\cert.pfx -Password $password
    Get-ChildItem -Path c:\cert.pfx | Import-PfxCertificate -CertStoreLocation Cert:\LocalMachine\My -Exportable -Password $password
    Write-Warning -Message "You'll now see prompts and other outputs, things are working as expected, don't do anything"
    $string = ("chocolatey" | & $KeyTool -list -v -keystore C:\cert.pfx) -match '^Alias.*'
    $currentAlias = ($string -split ':')[1].Trim()

    $passkey = '9hPRGDmfYE3bGyBZCer6AUsh4RTZXbkw'
    & $KeyTool -importkeystore -srckeystore C:\cert.pfx -srcstoretype PKCS12 -srcstorepass chocolatey -destkeystore C:\ProgramData\nexus\etc\ssl\keystore.jks -deststoretype JKS -alias $currentAlias -destalias jetty -deststorepass $passkey
    & $KeyTool -keypasswd -keystore C:\ProgramData\nexus\etc\ssl\keystore.jks -alias jetty -storepass $passkey -keypass chocolatey -new $passkey

    $xmlPath = 'C:\ProgramData\nexus\etc\jetty\jetty-https.xml'
    [xml]$xml = Get-Content -Path 'C:\ProgramData\nexus\etc\jetty\jetty-https.xml'
    foreach ($entry in $xml.Configure.New.Where{ $_.id -match 'ssl' }.Set.Where{ $_.name -match 'password' }) {
        $entry.InnerText = $passkey
    }

    $xml.OuterXml | Set-Content -Path $xmlPath

    Remove-Item C:\cert.pfx

    $nexusPath = 'C:\ProgramData\sonatype-work\nexus3'
    $configPath = "$nexusPath\etc\nexus.properties"

    $configString = @'
jetty.https.stsMaxAge=-1
application-port-ssl=8443
nexus-args=${jetty.etc}/jetty.xml,${jetty.etc}/jetty-https.xml,${jetty.etc}/jetty-requestlog.xml
'@

    $configString | Add-Content -Path $configPath
    
    $xmlPath = 'C:\ProgramData\nexus\etc\jetty\jetty-https.xml'
    [xml]$xml = Get-Content -Path 'C:\ProgramData\nexus\etc\jetty\jetty-https.xml'
    foreach ($entry in $xml.Configure.New.Where{ $_.id -match 'ssl' }.Set.Where{ $_.name -match 'password' }) {
        $entry.InnerText = $passkey
    }

    $xml.OuterXml | Set-Content -Path $xmlPath

}

function Register-NetshBinding {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]
        $Hash = $Thumbprint,

        [Parameter()]
        [string]
        $Guid = $((New-Guid).ToString("B")),

        [Parameter()]
        [string]
        $CertStore = "TrustedPeople"
    )
    $ports = @('24020')

    foreach ($port in $ports) {
        & netsh http add sslcert ipport=0.0.0.0:$($port) certhash=$($Hash) appid=$($Guid) certstorename=$($CertStore)
    }
}

function Get-NetshSslEntries {
    $txtBindings = (& netsh http show sslcert) | Select-Object -Skip 3 | Out-String
    $newLine = [System.Environment]::NewLine
    $txtbindings = $txtBindings -split "$newLine$newLine"
    $sslEntries = foreach ($binding in $txtbindings) {
        if ($binding) {
            $binding = $binding -replace "  ", "" -split ": "
            $hostNameIPPort = ($binding[1] -split "`n")[0] -split ":"
            [pscustomobject]@{
                HostNameIP      = $hostNameIPPort[0]
                Port            = $hostNameIPPort[1]
                CertificateHash = ($binding[2] -split "`n" -replace '[^a-zA-Z0-9]', '')[0]
            }
        }
    }

    # return entries, even if empty
    return $sslEntries
}

#endregion

#region Bootstrap functions (Start-C4bSetup.ps1)

#endregion