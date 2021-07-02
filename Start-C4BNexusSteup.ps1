<#
.SYNOPSIS
C4B Quick-Start Guide Nexus setup script

.DESCRIPTION
- Performs the following Sonatype Nexus Repository setup
    - Install of Sonatype Nexus Repository Manager OSS instance
    - Edit conofiguration to allow running of scripts
    - Cleanup of all demo source repositories
    - `ChocolateyInternal` NuGet v2 repository
    - `choco-install` raw repository, with a script for offline Chocolatey install
    - Setup of `ChocolateyInternal` on C4B Server as source, with API key
    - Setup of firewall rule for repository access
#>
[CmdletBinding()]
param(
    # Local path used to build the license package.
    #[Parameter()]
    #[string]
    #$PackagesPath = "$env:SystemDrive\choco-setup\packages"
)

# Set error action preference
$DefaultEap = $ErrorActionPreference
$ErrorActionPreference = 'Stop'

# Start logging
Start-Transcript -Path "$env:SystemDrive\choco-setup\logs\Start-C4bNexusSetup-$(Get-Date -Format 'yyyyMMdd-hhmmss').txt" -IncludeInvocationHeader

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

# Install base nexus-repository package
choco install nexus-repository -y

# Edit the config to allow running of scriipts, and restart Nexus 
$configPath = "$env:SystemDrive\ProgramData\sonatype-work\nexus3\etc\nexus.properties"
Stop-Service nexus
Add-content -Path $configPath -Value 'nexus.scripts.allowCreation=true'
Start-Service nexus
Write-Host "Waiting to give Nexus time to start up"
Wait-Nexus

# default parameters
$params = @{
    ServerUri           = 'http://localhost:8081'
    NuGetRepositoryName = 'ChocolateyInternal'
    RawRepositoryName   = 'choco-install'
    BlobStoreName       = 'default'
    Username            = 'admin'
    Password            = "$(Get-Content 'C:\ProgramData\sonatype-work\nexus3\admin.password')"
}

# trim any trailing '/' from the URI
$params.ServerUri = $params.ServerUri.trim('/')

# Tell the user the details we are going to use
Write-Host "Will create a repository using these details:"
$params.Keys | ForEach-Object {
    Write-Host ("    {0,-20} : {1}" -f $_, $params.$_)
}

# Create the Api header
$credPair = ("{0}:{1}" -f $params.Username, $params.Password)
$encodedCreds = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
$header = @{
    Authorization = "Basic $encodedCreds"
}

# Check the repo does not already exist
$repositories = Invoke-RestMethod -Uri 'http://localhost:8081/service/rest/v1/repositories' -Method Get -Headers $header
if ($params.NuGetRepositoryName -in @($repositories.Name)) {
    throw "Cannot create repository '$($params.NuGetRepositoryName)' as it already exists!"
}

# Create the NuGet Repo
$createRepoParams = @{
    ServerUri = $params.ServerUri
    ApiHeader = $header
    Script    = @"
import org.sonatype.nexus.repository.Repository;
repository.createNugetHosted("$($params.NuGetRepositoryName)","$($params.BlobStoreName)");
"@
}

Write-Host "Creating Nuget repository: $($params.NuGetRepositoryName)"
$null = Invoke-NexusScript @createRepoParams

#Create the Raw Repository
$createRawParams = @{
    ServerUri = $params.ServerUri
    ApiHeader = $header
    Script    = @"
import org.sonatype.nexus.repository.Repository;
repository.createRawHosted("$($params.RawRepositoryName)","$($params.BlobStoreName)");
"@
}

Write-Host "Creating Raw repository: $($params.RawRepositoryName)"
$null = Invoke-NexusScript @createRawParams

# Enable the NuGet Relam
$enableNugetRealmParams = @{
    ServerUri = $params.ServerUri
    ApiHeader = $header
    Script    = @"
import org.sonatype.nexus.security.realm.RealmManager
realmManager = container.lookup(RealmManager.class.getName())
// enable/disable the NuGet API-Key Realm
realmManager.enableRealm("NuGetApiKey")
"@
}

Write-Host "Enabling the NuGet-ApiKey Realm"
$null = Invoke-NexusScript @enableNugetRealmParams

#Add Offline Install script to Raw Repository
$installScriptParams = @{
    Uri    = "{0}/repository/{1}/ChocolateyInstall.ps1" -f $params.ServerUri,$params.RawRepositoryName
    Header = $header
    Method = "Put"
    InFile = "$env:TEMP\Install.ps1"
}

$ScriptDir = "$env:SystemDrive\choco-setup\files"
Invoke-WebRequest -Uri 'https://ch0.co/nexus-raw' -UseBasicParsing -OutFile "$ScriptDir\ChocolateyInstall.ps1"
Invoke-Expression "$ScriptDir\ChocolateyInstall.ps1"
Write-Host "Uploading Offline Install Script to $($params.RawRepositoryName)"
$null = Invoke-WebRequest @installScriptParams -UseBasicParsing
Remove-Item "$env:TEMP\Install.ps1" -Force


#Remove default Nexus Repositories
$defaultRepositories = @('nuget-group',
    'maven-snapshots',
    'maven-central',
    'nuget.org-proxy',
    'maven-releases',
    'nuget-hosted',
    'maven-public')

Write-Host "Removing default Nexus repositories"
Foreach ($default in $defaultRepositories) {
    $removalParams = @{
        ServerUri = $params.ServerUri
        ApiHeader = $header
        Script    = @"
import org.sonatype.nexus.repository.Repository;
repository.getRepositoryManager().delete("$default");
"@
    }

    $null = Invoke-NexusScript @removalParams
}

$getApiKeyParams = @{
    ServerUri = $params.ServerUri
    ApiHeader = $header
    Script    = @" 
import org.sonatype.nexus.security.authc.apikey.ApiKeyStore
import org.sonatype.nexus.security.realm.RealmManager
import org.apache.shiro.subject.SimplePrincipalCollection

def getOrCreateNuGetApiKey(String userName) {
    realmName = "NexusAuthenticatingRealm"
    apiKeyDomain = "NuGetApiKey"
    principal = new SimplePrincipalCollection(userName, realmName)
    keyStore = container.lookup(ApiKeyStore.class.getName())
    apiKey = keyStore.getApiKey(apiKeyDomain, principal)
    if (apiKey == null) {
        apiKey = keyStore.createApiKey(apiKeyDomain, principal)
    }
    return apiKey.toString()
}

getOrCreateNuGetApiKey("$($params.Username)")
"@
}

$result = Invoke-NexusScript @getApiKeyParams

$global:NugetApiKey = $result.result

# Push all packages from previous steps to NuGet repo
Get-ChildItem -Path "$env:SystemDrive\choco-setup\packages" -Filter *.nupkg |
    ForEach-Object {
        choco push $_.FullName --source "$($params.ServerUri)/repository/$($params.NuGetRepositoryName)/" --apikey $NugetApiKey --force
    }

# Add ChooclateyInternal as a source repository
choco source add -n $($params.NuGetRepositoryName) -s "$($params.ServerUri)/repository/$($params.NuGetRepositoryName)/" --priority 1
choco apikey -s "$($params.ServerUri)/repository/$($params.NuGetRepositoryName)/" -k $NugetApiKey

# Install MS Edge for browsing the Nexus web portal
choco install microsoft-edge -y

# Add Nexus port 8081 access via firewall
$FwRuleParams = @{
    DisplayName    = 'Nexus Repository access on TCP 8081'
    Direction = 'Inbound'
    LocalPort = 8081
    Protocol = 'TCP'
    Action = 'Allow'
}
$null = New-NetFirewallRule @FwRuleParams

$finishOutput = @"
##############################################################

Nexus Repository Setup Completed
Please login to the following URL to complete admin account setup:

Server Url: $($params.ServerUri)

You will need the following API Key to complete Administrative workstation setup.
The API Key can be accessed at:  $($params.ServerUri)/#user/nugetapitoken

NuGet ApiKey: $NugetApiKey
Nexus admin user password: $($params.Password)

##############################################################
"@

Write-Host "$finishOutput" -ForegroundColor Green

#Stop logging
Stop-Transcript

# Set error action preference back to default
$ErrorActionPreference = $DefaultEap