This document outlines how to help with development of the Chocolatey Quickstart Guide, particularly around testing changes.

## Development

When looking to make a change ensure any working branch is taken from `develop`. You can do this with the following:

```powershell
git checkout develop
git fetch upstream
git rebase upstream/develop
git push origin
git checkout -b $NewBranchName
```

## Testing

Test your changes before raising a Pull Request to merge your changes. In order to set things up for testing do the following:

1. Set `$env:CHOCO_QSG_DEVELOP = $true`
1. The first step of the Guide will need amended to fetch from the `develop` branch:

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::tls12
$QuickStart = 'https://raw.githubusercontent.com/chocolatey/choco-quickstart-scripts/develop/Start-C4bSetup.ps1'
$Script = [System.Net.Webclient]::new().DownloadString($QuickStart)
$sb = [ScriptBlock]::Create($Script)
& $sb
```

1. Perform each step of the Quickstart Guide, and make sure the changes you have attempted to make work appropriately.
1. If everything looks OK, push your branch and create your Pull Request.

## SSL Certificates for testing

Reach out to Stephen, and he can generate a Let's Encrypt certificate for you.
