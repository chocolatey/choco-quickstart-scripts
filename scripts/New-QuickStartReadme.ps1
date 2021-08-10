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
Param(
    [Parameter()]
    [string]
    $HostName = $(Get-Content "$env:SystemDrive\choco-setup\logs\ssl.json" | ConvertFrom-Json).CertSubject

)


process {
    $nexusPassword = Get-Content -Path 'C:\ProgramData\sonatype-work\nexus3\admin.password'
    $jenkinsPassword = Get-Content -path 'C:\Program Files (x86)\Jenkins\secrets\initialAdminPassword'

    $tableData = @([pscustomobject]@{
            Name     = 'Nexus'
            Url      = "https://${HostName}:8443"
            Username = "admin"
            Password = $nexusPassword
        },
        [pscustomobject]@{
            Name     = 'Central Management'
            Url      = "https://${HostName}"
            Username = "ccmadminadmin"
            Password = '123qwe'
        },
        [PSCustomObject]@{
            Name     = 'Jenkins'
            Url      = "http://${HostName}:8080"
            Username = "admin"
            Password = $jenkinsPassword
        }
    )
    

    $html = @"
    <html>
    <head>
    </head>
    <title>Chocolatey For Business Service Defaults</title>
    <style>
    table {
        border-collapse: collapse;
    }

    td,
    th {
        border: 0.1em solid rgba(0, 0, 0, 0.5);
        padding: 0.25em 0.5em;
        text-align: center;
    }
    blockquote {
        margin-left: 0.5em;
        padding-left: 0.5em;
        border-left: 0.1em solid rgba(0, 0, 0, 0.5);
    }</style>
    <body>
    <blockquote>
<p>📝 <strong>Note</strong></p>

<p>The following table provides the default credentials to login to each of the services made available as part of the Quickstart Guide setup process.</p> 
You'll be asked to change the credentials upon logging into each service for the first time.
Document your new credentials in a password manager, or whatever system you use.
</p>
</blockquote>
    $(($TableData | ConvertTo-Html -Fragment))
    </body>
    </html>
"@

    $folder = Join-Path $env:Public 'Desktop'
    $file = Join-Path $folder 'README.html'

    $html | Set-Content $file

}