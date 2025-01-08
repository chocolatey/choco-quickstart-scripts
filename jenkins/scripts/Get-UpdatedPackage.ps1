[CmdletBinding()]
Param (
    [Parameter(Mandatory)]
    [string]
    $LocalRepo,

    [Parameter(Mandatory)]
    [string]
    $LocalRepoApiKey,

    [Parameter(Mandatory)]
    [string]
    $RemoteRepo
)

. "$PSScriptRoot\ConvertTo-ChocoObject.ps1"

if (([version] (choco --version).Split('-')[0]) -ge [version] '2.1.0') {
    Write-Verbose "Clearing Chocolatey CLI cache to ensure latest package information is retrieved."
    choco cache remove
}

$LocalRepoSource = $(choco source --limit-output | ConvertFrom-Csv -Delimiter '|' -Header Name, Uri, Disabled).Where{
    $_.Uri -eq $LocalRepo -or
    $_.Name -eq $LocalRepo
}[0]

Write-Verbose "Getting list of local packages from '$LocalRepo'."
$localPkgs = choco search --source $LocalRepo -r | ConvertTo-ChocoObject
Write-Verbose "Retrieved list of $(($localPkgs).count) packages from '$Localrepo'."

$localPkgs | ForEach-Object {
    Write-Verbose "Getting remote package information for '$($_.name)'."
    $remotePkg = choco search $_.name --source $RemoteRepo --exact -r | ConvertTo-ChocoObject
    if ([version]($remotePkg.version) -gt ([version]$_.version)) {
        Write-Verbose "Package '$($_.name)' has a remote version of '$($remotePkg.version)' which is later than the local version '$($_.version)'."
        Write-Verbose "Internalizing package '$($_.name)' with version '$($remotePkg.version)'."
        $tempPath = Join-Path -Path $env:TEMP -ChildPath ([GUID]::NewGuid()).GUID
        choco download $_.name --no-progress --internalize --force --internalize-all-urls --append-use-original-location --output-directory=$tempPath --source=$RemoteRepo

        if ($LASTEXITCODE -eq 0) {
            try {
                if ([bool]::Parse($LocalRepoSource.Disabled)) {choco source enable --name="$($LocalRepoSource.Name)" -r | Write-Verbose}

                Write-Verbose "Pushing package '$($_.name)' to local repository '$LocalRepo'."
                (Get-Item -Path (Join-Path -Path $tempPath -ChildPath "*.nupkg")).fullname | ForEach-Object {
                    choco push $_ --source $LocalRepo --api-key $LocalRepoApiKey --force
                    if ($LASTEXITCODE -eq 0) {
                        Write-Verbose "Package '$_' pushed to '$LocalRepo'."
                    }
                    else {
                        Write-Verbose "Package '$_' could not be pushed to '$LocalRepo'.`nThis could be because it already exists in the repository at a higher version and can be mostly ignored. Check error logs."
                    }
                }
            } finally {
                if ([bool]::Parse($LocalRepoSource.Disabled)) {choco source disable --name="$($LocalRepoSource.Name)" -r | Write-Verbose}
            }
        }
        else {
            Write-Verbose "Failed to download package '$($_.name)'"
        }
        Remove-Item $tempPath -Recurse -Force
    }

    else {
        Write-Verbose "Package '$($_.name)' has a remote version of '$($remotePkg.version)' which is not later than the local version '$($_.version)'."
    }
}
