[CmdletBinding()]
Param(
    [Parameter(Mandatory)]
    [String]
    $Fqdn
)

process {
    Write-Host "Installing Pester 5 to run validation tests"
    $chocoArgs = @('install', 'pester', '-y', '--source="https://community.chocolatey.org/api/v2/"')
    & choco @chocoArgs

    $files = (Get-ChildItem C:\choco-setup\tests\ -Recurse -Filter *.ps1).Fullname
    Write-Host "Configuring Pester to complete verification tests"
    $containers = $files | Foreach-Object { New-PesterContainer -Path $_ -Data @{ Fqdn = $Fqdn } }
    $configuration = [PesterConfiguration]@{
        Run        = @{
            Container = $Containers
            Passthru  = $true
        }
        Output     = @{
            Verbosity = 'Detailed'
        }
        TestResult = @{
            Enabled      = $true
            OutputFormat = 'NUnitXml'
            OutputPath   = 'C:\choco-setup\test-results\verification.results.xml'
        }
    }

    $results = Invoke-Pester -Configuration $configuration
    if ($results.FailedCount -gt 0) {
        Compress-Archive -Path C:\choco-setup\test-results\verification.results.xml -DestinationPath "C:\choco-setup\files\support_archive.zip"
        Get-ChildItem C:\choco-setup\logs -Recurse -Filter *.txt | Foreach-Object { Compress-Archive -Path $_.FullName -Update -DestinationPath "C:\choco-setup\files\support_archive.zip" }
    }
}