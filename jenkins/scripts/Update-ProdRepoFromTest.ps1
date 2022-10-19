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

Write-Verbose "Checking the list of packages available in the test and prod repositories"
$testPkgs = choco list --source $TestRepo --all-versions --limit-output | ConvertFrom-Csv -Delimiter '|' -Header Name, Version
$prodPkgs = choco list --source $ProdRepo --all-versions --limit-output | ConvertFrom-Csv -Delimiter '|' -Header Name, Version
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
    choco download $_.Name --version $_.Version --no-progress --output-directory=$tempPath --source=$TestRepo --ignore-dependencies

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
