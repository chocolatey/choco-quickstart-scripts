[CmdletBinding()]
Param(
    [Parameter()]
    [FileInfo]
    $JsonData = (Get-ChildItem "$env:SystemDrive\choco-setup\logs\" -Filter *.json -Recurse)

process {
    $tableData = $JsonData | Foreach-Object { Get-Content $_ | ConvertFrom-Json | ConvertTo-Html -Fragment }

    $html = @"
    <html>
    <head>
    </head>
    <title></title>
    <style></style>
    <body>
    $TableData -join '`n' #Join on new lines so the html doesn't look too munged
    </body>
    </html>
"@

    $folder = Join-Path $env:Public 'Desktop'
    $file = Join-Path $folder 'README.html'

    $html | Set-Content $file

    $JsonData | Remove-Item -Force -Recurse
}