This document outlines how to help with development of the Chocolatey Quickstart Guide, particularly around testing changes.

## Development

When looking to make a change ensure any working branch is taken from the tip of `main`. You can do this with the following:

```powershell
$ChocolateyUpstream = ((git remote -v) -match "github.com/chocolatey/choco-quickstart-scripts.git \(fetch\)$" -split "\t")[0]
git fetch $ChocolateyUpstream
git checkout -b $NewBranchName $ChocolateyUpstream/main
```

### Development Testing

You must test your changes before submitting a PR.

You should test on a clean, supported operating system.

> NB: To save time in repeated testing from a clean environment, you can run the OfflineInstallPreparation script in your repository and copy the files directory before copying.

To test the quickstart environment:

1. Copy the repository directory over to `C:\choco-setup\files\` on the test machine. You do not need to copy the `.git` directory.
1. Open an elevated Windows PowerShell console.
1. Run `C:\choco-setup\files\Start-C4bSetup.ps1`, and continue through the guide steps as detailed in `README.md`.
1. Run `C:\choco-setup\files\Start-C4bVerification.ps1` and check that all tests pass.

## Testing a PR

Changes in a PR must be tested before merging. In order to set things up for testing do the following in an elevated Windows PowerShell terminal:

1. Set `$env:CHOCO_QSG_BRANCH` to the PR ID or Branch Name to download.
1. Run Quickstart Guide as documented, in the same session.

Example:

```powershell
$env:CHOCO_QSG_BRANCH = "< Insert PR ID or Upstream BranchName Here >"

Set-ExecutionPolicy Bypass -Scope Process -Force
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::tls12
Invoke-RestMethod "https://ch0.co/qsg-go" | Invoke-Expression
```

1. Perform each step of the Quickstart Guide, and make sure the changes you have attempted to make work appropriately.
1. Run `Start-C4bVerification.ps1` and check that all tests pass.
1. If everything looks OK, push your branch and create your Pull Request.

## Creating a PR

Push your branch to a fork or repository, and create a new PR [here](https://github.com/chocolatey/choco-quickstart-scripts/compare).

You should fill out the issue template as much as possible.

### Rebasing Your Branch

If something else has been merged since you created your branch, you should rebase your branch onto the new tip of `main`. If you'd already pushed the branch, you may need to force-push the new history over the upstream version. You can do this as follows:

```powershell
$ChocolateyUpstream = ((git remote -v) -match "github.com/chocolatey/choco-quickstart-scripts.git \(fetch\)$" -split "\t")[0]
git fetch $ChocolateyUpstream
git rebase $ChocolateyUpstream\main --autostash
```