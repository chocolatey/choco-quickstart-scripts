function ConvertTo-ChocoObject {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [string]
        $InputObject
    )
    process {
        # format of the 'choco list -r' output is:
        # <PACKAGE NAME>|<VERSION> (ie. adobereader|2015.6.7)
        if (-not [string]::IsNullOrEmpty($InputObject)) {
            $props = $_.split('|')
            New-Object -TypeName psobject -Property @{ Name = $props[0]; Version = $props[1] }
        }
    }
}
