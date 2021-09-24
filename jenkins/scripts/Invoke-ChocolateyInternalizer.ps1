<#
    .SYNOPSIS
    Internalizes packages from the community repository to an internal location.

    .DESCRIPTION
    Internalizes packages from a specified repository (the Chocolatey Community
    repository by default) into the target internal repository. All download
    URLs and necessary resources are internalized to create a self-contained
    package.

    .EXAMPLE
    ./Internalizer.ps1 -Package googlechrome -RepositoryUrl https://chocoserver:8443/repository/ChocolateyInternal/ -LocalRepoApiKey 61332b06-d849-476c-b2ab-a290372c17d7
#>
[CmdletBinding()]
param(
    # The package(s) you want to internalize (comma separated).
    [Parameter(Mandatory, Position = 0, ValueFromPipeline)]
    [string[]]
    $Package,

    # Your internal nuget repository url to push packages to.
    [Parameter(Mandatory, Position = 1)]
    [string]
    $RepositoryUrl,

    # The API key of your internal repository server.
    [Parameter(Mandatory, Position = 3)]
    [string]
    $NexusApiKey,

    # The remote repo to check against. Defaults to https://chocolatey.org/api/v2
    [Parameter(Position = 2)]
    [string]
    $RemoteRepo = 'https://chocolatey.org/api/v2'
)
begin {
    if (!(Test-Path "$env:ChocolateyInstall\license")) {
        throw "Licensed edition required to use Package Internalizer"
    }

    $Guid = [Guid]::NewGuid().Guid
    $TempFolder = [IO.Path]::GetTempPath() |
        Join-Path -ChildPath $Guid |
        New-Item -ItemType Directory -Path { $_ } |
        Select-Object -ExpandProperty FullName
}
process {
    foreach ($item in $Package) {
        choco download $item --internalize --output-directory="'$TempFolder'" --no-progress --internalize-all-urls --append-use-original-location --source="'$RemoteRepo'"
        Get-ChildItem -Path $TempFolder -Filter *.nupkg -Recurse -File | ForEach-Object {
            choco push $_.Fullname --source="'$RepositoryUrl'" --api-key="'$NexusApiKey'" --force
            Remove-Item -Path $_.FullName -Force
        }
    }
}
end {
    Remove-Item -Path $TempFolder -Recurse -Force
}
