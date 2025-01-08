[CmdletBinding()]
param (
    [Parameter(Mandatory)]
    [string]
    $ProdRepo,

    [Parameter(Mandatory)]
    [string]
    $ProdRepoApiKey,

    [Parameter(Mandatory)]
    [string]
    $TestRepo
)

if (([version] (choco --version).Split('-')[0]) -ge [version] '2.1.0') {
    Write-Verbose "Clearing Chocolatey CLI cache to ensure latest package information is retrieved."
    choco cache remove
}

$LocalRepoSource = $(choco source --limit-output | ConvertFrom-Csv -Delimiter '|' -Header Name, Uri, Disabled).Where{
    $_.Uri -eq $TestRepo -or
    $_.Name -eq $TestRepo
}[0]

Write-Verbose "Checking the list of packages available in the test and prod repositories"
try {
    if ([bool]::Parse($LocalRepoSource.Disabled)) {choco source enable --name="$($LocalRepoSource.Name)" -r | Write-Verbose}
    $testPkgs = choco search --source $TestRepo --all-versions --limit-output | ConvertFrom-Csv -Delimiter '|' -Header Name, Version
} finally {
    if ([bool]::Parse($LocalRepoSource.Disabled)) {choco source disable --name="$($LocalRepoSource.Name)" -r | Write-Verbose}
}
$prodPkgs = choco search --source $ProdRepo --all-versions --limit-output | ConvertFrom-Csv -Delimiter '|' -Header Name, Version
$tempPath = Join-Path -Path $env:TEMP -ChildPath ([GUID]::NewGuid()).GUID

$Packages = if ($null -eq $testPkgs) {
    Write-Verbose "Test repository appears to be empty. Nothing to push to production."
}
elseif ($null -eq $prodPkgs) {
    $testPkgs
}
else {
    Compare-Object -ReferenceObject $testpkgs -DifferenceObject $prodpkgs -Property name, version | Where-Object SideIndicator -EQ '<='
}

$Packages | ForEach-Object {
    Write-Verbose "Downloading package '$($_.Name)' v$($_.Version) to '$tempPath'."
    try {
        if ([bool]::Parse($LocalRepoSource.Disabled)) {choco source enable --name="$($LocalRepoSource.Name)" -r | Write-Verbose}
        choco download $_.Name --version $_.Version --no-progress --output-directory=$tempPath --source=$TestRepo --ignore-dependencies
    } finally {
        if ([bool]::Parse($LocalRepoSource.Disabled)) {choco source disable --name="$($LocalRepoSource.Name)" -r | Write-Verbose}
    }

    if ($LASTEXITCODE -eq 0) {
        $pkgPath = (Get-Item -Path (Join-Path -Path $tempPath -ChildPath '*.nupkg')).FullName
        # #######################
        # INSERT CODE HERE TO TEST YOUR PACKAGE
        # #######################

        # If package testing is successful ...
        if ($LASTEXITCODE -eq 0) {
            Write-Verbose "Pushing downloaded package '$(Split-Path -Path $pkgPath -Leaf)' to production repository '$ProdRepo'."
            choco push $pkgPath --source=$ProdRepo --api-key=$ProdRepoApiKey --force

            if ($LASTEXITCODE -eq 0) {
                Write-Verbose "Pushed package successfully."
            }
            else {
                Write-Verbose "Could not push package."
            }
        }
        else {
            Write-Verbose "Package testing failed."
        }
        Remove-Item -Path $tempPath -Recurse -Force
    }
    else {
        Write-Verbose "Could not download package."
    }
}
