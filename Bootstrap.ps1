[CmdletBinding()]
param(
    # The directory to output all files to. If not provided, defaults to 'C:\choco-setup\files'.
    [Parameter()]
    [string]$OutputDirectory = $(Join-Path $env:SystemDrive 'choco-setup\files'),

    # The branch or PR to download. If not provided, defaults to 'main'.
    [Parameter()]
    [Alias('PR')]
    [string]$Branch = $env:CHOCO_QSG_BRANCH,

    # If provided, overwrites any files that exist at $OutputDirectory
    [switch]$Force
)

$TempDir = Join-Path $env:TEMP "$(New-Guid)"

foreach ($Directory in @($OutputDirectory, $TempDir)) {
    if (Test-Path $Directory) {
        if ($Force) {
            Remove-Item $Directory -Recurse -Force
        } else {
            Write-Error "Directory '$Directory' already exists. Please remove it or use the -Force switch."
        }
    }
    if (-not (Test-Path $Directory)) {
        $null = New-Item -Path $Directory -ItemType Directory
    }
}

$QsRepo = if ($Branch) {
    if ((Invoke-RestMethod -Uri "https://api.github.com/repos/chocolatey/choco-quickstart-scripts/branches").name -contains $Branch) {
        "https://api.github.com/repos/chocolatey/choco-quickstart-scripts/zipball/$Branch"
    } elseif ($PullRequest = Invoke-RestMethod -Uri "https://api.github.com/repos/chocolatey/choco-quickstart-scripts/pulls/$Branch" -ErrorAction SilentlyContinue) {
        $PullRequest.head.repo.archive_url -replace '{archive_format}','zipball' -replace '{/ref}',"/$($PullRequest.head.ref)"
    } else {
        Write-Error "'$($Branch)' is not a valid branch or pull request number. Please provide a valid branch or pull request number."
    }
} else {
    "https://api.github.com/repos/chocolatey/choco-quickstart-scripts/zipball/main"
}
Write-Verbose "Using '$QSRepo' as the QuickStart URL."

# Download and extract C4B setup files from repo
try {
    Invoke-WebRequest -Uri $QsRepo -UseBasicParsing -OutFile "$TempDir\choco-quickstart-scripts.zip"
    Expand-Archive "$TempDir\choco-quickstart-scripts.zip" $TempDir
    Copy-Item "$TempDir\*\*" $OutputDirectory -Recurse
} finally {
    Remove-Item "$TempDir" -Recurse -Force
}