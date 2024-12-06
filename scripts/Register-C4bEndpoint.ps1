[CmdletBinding()]
Param(
    # The DNS name of the server that hosts your repository, Jenkins, and Chocolatey Central Management
    [Parameter()]
    [String]
    $Fqdn = '{{ FQDN }}',

    # Client salt value used to populate the centralManagementClientCommunicationSaltAdditivePassword
    # value in the Chocolatey config file
    [Parameter()]
    [String]
    $ClientCommunicationSalt = '{{ ClientSaltValue }}',

    # Server salt value used to populate the centralManagementServiceCommunicationSaltAdditivePassword
    # value in the Chocolatey config file
    [Parameter()]
    [String]
    $ServiceCommunicationSalt = '{{ ServiceSaltValue }}',

    [Parameter(Mandatory)]
    [PSCredential]
    $RepositoryCredential,

    # The URL of a proxy server to use for connecting to the repository.
    [Parameter()]
    [String]
    $ProxyUrl,
    # The credentials, if required, to connect to the proxy server.
    [Parameter()]
    [PSCredential]
    $ProxyCredential,

    #Install the Chocolatey Licensed Extension with right-click context menus available
    [Parameter()]
    [Switch]
    $IncludePackageTools,
    
    # Allows for the application of user-defined configuration that is applied after the base configuration.
    # Can override base configuration with this parameter
    [Parameter()]
    [Hashtable]
    $AdditionalConfiguration,

    # Allows for the toggling of additonal features that is applied after the base configuration.
    # Can override base configuration with this parameter
    [Parameter()]
    [Hashtable]
    $AdditionalFeatures,

    # Allows for the installation of additional packages after the system base packages have been installed.
    [Parameter()]
    [Hashtable[]]
    $AdditionalPackages,

    # Allows for the addition of alternative sources after the base conifguration  has been applied.
    # Can override base configuration with this parameter
    [Parameter()]
    [Hashtable[]]
    $AdditionalSources
)

# Touch NOTHING below this line
$RepositoryUrl = "https://$($fqdn):8443/repository/ChocolateyInternal/index.json"

#Initialize params hashtable so we can add to it if needed later
$params = @{
    Credential    = $RepositoryCredential
    ClientSalt    = $ClientCommunicationSalt
    ServiceSalt   = $ServiceCommunicationSalt
    RepositoryUrl = $RepositoryUrl
}

switch ($true) {
    $PSBoundParameters.ContainsKey('AdditionalConfiguration') {
        $params.Add('AdditionalConfiguration', $AdditionalConfiguration)
    }
    $PSBoundParameters.ContainsKey('AdditionalFeatures') {
        $params.add('AdditionalFeatures', $AdditionalFeatures)
    }

    $PSBoundParameters.ContainsKey('AdditionalPackages') {
        $params.Add('AdditionalPackages', $AdditionalPackages)
    }

    $PSBoundParameters.ContainsKey('AdditionalSources') {
        $params.Add('AdditionalSources', $AdditionalSources)
    }

    $PSBoundParameters.ContainsKey('IncludePackageTools') {
        $params.Add('IncludePackageTools',$IncludePackageTools)
    }
}

$downloader = [System.Net.WebClient]::new()

#setup proxy if required
if ($ProxyUrl) {
    $params.add('ProxyUrl', $ProxyUrl)
    $proxy = [System.Net.WebProxy]::new($ProxyUrl, $true <#bypass on local#>)
   
    if ($ProxyCredential) {
        $params.Add('ProxyCredential', $ProxyCredential)
        $proxy.Credentials = $ProxyCredential
    }

    $downloader.Proxy = $proxy
}

$downloader.Credentials = $RepositoryCredential

$script = $downloader.DownloadString("https://$($FQDN):8443/repository/choco-install/ClientSetup.ps1")

& ([scriptblock]::Create($script)) @params
