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
    $AdditionalSources,

    # If passed, downloads the certificate from the client server before initializing Chocolatey Agent
    [Parameter()]
    [Switch]
    $TrustCertificate
)

# Touch NOTHING below this line
begin {
    
    $params = $PSCmdlet.MyInvocation.BoundParameters

    $commonParameters = @(
        'Verbose', 'Debug', 'ErrorAction', 'WarningAction', 'InformationAction',
        'ErrorVariable', 'WarningVariable', 'InformationVariable', 'OutVariable', 'OutBuffer', 'PipelineVariable')
    
    $PSCmdlet.MyInvocation.MyCommand.Parameters.Keys | ForEach-Object {
        if ((-not $params.ContainsKey($_)) -and ($_ -notin $commonParameters)) {
            $params[$_] = (Get-Variable -Name $_ -Scope 0 -ErrorAction SilentlyContinue).Value
        }
    }
    # Set up our downloader
    $downloader = [System.Net.WebClient]::new()

    # Setup proxy if required
    if ($ProxyUrl) {
        $proxy = [System.Net.WebProxy]::new($ProxyUrl, $true <#bypass on local#>)
   
        if ($ProxyCredential) {
            $proxy.Credentials = $ProxyCredential
        }

        $downloader.Proxy = $proxy
    }

    $downloader.Credentials = $RepositoryCredential

}

end {
    # If we use a Self-Signed certificate, we need to explicity trust it
    if ($TrustCertificate) {
        Invoke-Expression ($downloader.DownloadString("http://$($Fqdn):80/Import-ChocoServerCertificate.ps1"))
    }

    # Once we trust the SSL certificate, we can start onboarding
    $RepositoryUrl = "https://$($fqdn):8443/repository/ChocolateyInternal/index.json"

    foreach ($Parameter in @("FQDN", "TrustCertificate")) {
        $null = $params.Remove($Parameter)
    }

    $params += @{
        RepositoryUrl = $RepositoryUrl
    }

    $script = $downloader.DownloadString("https://$($FQDN):8443/repository/choco-install/ClientSetup.ps1")

    & ([scriptblock]::Create($script)) @params
}