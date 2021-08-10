<#
.SYNOPSIS
Removes unnecessary json data files from the system upon completion of the Quickstart Guide.

.PARAMETER JsonPath
The path to the JSON data files. Defaults to 'C:\choco-setup\logs'.

.EXAMPLE
./Start-C4bCleanup.ps1

.EXAMPLE
./Start-C4bCleanup.ps1 -JsonPath C:\Temp\
#>


[CmdletBinding()]
Param(
    [Parameter()]
    [String]
    $JsonPath = "$env:SystemDrive\choco-setup\logs"
)

process {

    Get-Child-Item $JsonPath  -Filter '*.json' | Foreach-Object { Remove-Item $_ -Force }
}