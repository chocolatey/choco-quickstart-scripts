#requires -modules C4B-Environment
[CmdletBinding()]
Param(
    [Parameter()]
    [String]
    $Fqdn = $(Get-ChocoEnvironmentProperty CertSubject)
)
process {
    if (-not (Get-Module Pester -ListAvailable).Where{$_.Version -gt "5.0"}) {
        Write-Host "Installing Pester 5 to run validation tests"
        $chocoArgs = @('install', 'pester', "--source='ChocolateyInternal'", '-y', '--no-progress', '--source="https://community.chocolatey.org/api/v2/"')
        & Invoke-Choco @chocoArgs
    }

    $files = (Get-ChildItem C:\choco-setup\files\tests\ -Recurse -Filter *.ps1).Fullname
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
        Get-ChildItem C:\choco-setup\logs -Recurse -Include *.log,*.txt | Foreach-Object { Compress-Archive -Path $_.FullName -Update -DestinationPath "C:\choco-setup\files\support_archive.zip" }
        Write-Host "Logs have been collected into 'C:\choco-setup\files\support_archive.zip'."
        Write-Host "Please submit this archive to support@chocolatey.io so our team can assist you."
    }
}