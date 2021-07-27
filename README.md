# C4B Quick-Start Guide - Supporting Scripts

This repository contains a set of supporting scripts used for the Chocolatey for Business (C4B) Quick-Start Guide (QSG).

These scripts can be used to assist in setup of a brand new Windows Server as a C4B Server.

Below is the planned revision of the QSG, which will evntually be posted in the [Chocolatey Docs](https//docs.chooclatey.org).

## Chocolatey for Business (C4B) Quick-Start Guide

Thank you for choosing Chocolatey as your partner in Windows software automation management. We are excited to help you dive in and successfully implement a deployment of all the necessary components.

> :memo: **NOTE**
>
> This quick-start guide is intended for customers who have recently purchased Chocolatey for Business (C4B), or are evaluating C4B as part of a proof-of-concept.
> It illustrates only **one** method of setting up your Chocolatey environment, and is by **NO** means exhaustive.
> Our goal is to get you up-and-running quickly, and testing out the feature set.
> For a more complete reference of possible scenarios and solutions, please refer to the [Organizational Deployment Documentation](xref:organizational-deployment-guide).

If you have any questions or would like to discuss more involved implementations, please feel free to reach out to your Chocolatey representative.

Let's get started!

## Components

![Components ofa C4B Server](c4b-server.png)

As illustrated in the diagram above, there are four main components to a default Chocolatey install, namely:

1. **C4B Licensed components**: A licensed version of Chocolatey includes:
    a. Installation of the Chocolatey OSS client package itself (`chocolatey`)
    a. your Chocolatey license installed in the correct directory
    a. Installation of the Chocolatey Licensed extension, giving you access to features like Package Bulder, Package Internalizer, etc. (full list here).
1. **NuGet V2 Repository Server App**: Chocolatey works best with a NuGet V2 repository. This application hosts and manages versioning of your Chocolatey package artifacts, in their enhanced NuGet package (.nupkg) file format. This guide will help you setup [Sonatype Nexus Repository Manager (OSS)](https://www.sonatype.com/nexus-repository-oss).
1. **Chocolatey Central Management (CCM) Server App**: This is a standalone server that hosts the Chocolatey Central Management web interface, as well as the back-end database on which it relies. Currently, this interface provides reporting on packages installed on endpoints. In future, a feature will be added to enable deployments of packages and updates from this web console, as well.  can be found on the the [Chocolatey Central Management Setup page](xref:ccm-setup).
1. **Automation Pipeline**: These are the workstation or server endpoints you wish to manage packages on, with Chocolatey. Every node requires a license.

Repo Options:
- Jfrog [Artifactory](https://jfrog.com/artifactory/)
- Inedo ProGet
- Other NuGet V2 options discussed here: [Repository Options](xref:host-packages)

## Requirements

Below are the minimum requirements for setting up your C4B server via this guide:
- Windows Server 2019+ (ideally, Windows Server 2019)
    - Windows Server 2016 is technically supported, but not recommended as it is nearing End-of-Life; also, you will require an additional setup script.
- 4+ CPU cores (more preferred)
- 8 GB+ RAM (16GB preferred; 4GB of RAM reserved specifically for Nexus)
- 500 GB+ of free space for local NuGet package artifact storage
- Open outgoing (egress) Internet access
- Administrator user rights

> :exclamation:**[IMPORTANT]** All commands should be run from an Administrator PowerShell window (and **not ISE**)

### Step 0: Preparation of C4B Server

1. Provision your C4B server on the infrastructure of your choice.

1. Install all Windows Updates.

1. If you plan on joining your domain, do so now before beginning setup below.

1. If you plan to use a Purchased/Acquired or Domain SSL certificate, please ensure the CN/Subject value matches the DNS-resolvable Fully-Qualified Domain Name (FQDN) of your C4B Server. Place this certificate in the `Local Machine > Personal` certificate store, and ensure that the private key is exportable.

1. Copy your `chocolatey.license.xml` license file (from the email you received) onto your C4B Server.


### Step 1: Begin C4B Setup

1. Open a PowerShell console with the `Run as Administrator` option, and paste and run the following code:

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::tls12
$QuickStart = 'https://raw.githubusercontent.com/chocolatey/choco-quickstart-scripts/main/Start-C4BSetup.ps1'
Invoke-Expression -Command ((New-Object System.Net.WebClient).DownloadString($QuickStart))
```

> :scroll: **What does this script do?**
> - Install of Chocolatey from https://chocolatey.org
> - Prompt for C4B license, with validation
> - Script to help turn your C4B license into a Chocolatey package
> - Setup of local `choco-setup` directories
> - Download of setup files from "choco-quickstart-scripts" GitHub repo
> - Download of Chocolatey packages required for setup
> - Output data to JSON to pass between scripts

### Step 2: Nexus Setup

1. In the same PowerShell Administrator console as above, paste and run the following code:

```powershell
Set-Location "$env:SystemDrive\choco-setup\files"
.\Start-C4BNexusSetup.ps1
```

> :scroll: **What does this script do?**
> - Install of Sonatype Nexus Repository Manager OSS instance
> - Edit conofiguration to allow running of scripts
> - Cleanup of all demo source repositories
> - Creates a `ChocolateyInternal` NuGet v2 repository
> - Creates a `ChocolateyTest` NuGet v2 repository
> - Creates a `choco-install` raw repository
> - Setup of `ChocolateyInternal` on C4B Server as source, with API key
> - Setup of firewall rule for repository access
> - Install MS Edge, and disable first-run experience
> - Output data to JSON to pass between scripts

### Step 3: CCM Setup

1. In the same PowerShell Administrator console as above, paste and run the following code:

```powershell
Set-Location "$env:SystemDrive\choco-setup\files"
.\Start-C4bCcmSetup.ps1
```

> :scroll: **What does this script do?**
> - Install of MS SQL Express
> - Creation and permissions of `ChocolateyManagement` database
> - Install of all 3 CCM packages, with correct parameters
> - Output data to JSON to pass between scripts

### Step 4: SSL Setup

1. In the same PowerShell Administrator console as above, paste and run the following code:

```powershell
Set-Location "$env:SystemDrive\choco-setup\files"
.\Set-SslSecurity.ps1
```

> :scroll: **What does this script do?**
> - Add SSL certificate configuration for Nexus and CCM Web
> - Popup web pages for user at end of scripts

### Step 5: Jenkins Setup

1. In the same PowerShell Administrator console as above, paste and run the following code:

```powershell
Set-Location "$env:SystemDrive\choco-setup\files"
.\Start-C4bJenkinsSetup.ps1
```

> :scroll: **What does this script do?**
> - Choco install of Jenkins package, pinned to versio
> - Update Jenkins plugins
> - Pre-downloaded Jenkins scripts for Package Internalizer automation
> - Setup pre-defined Jenkins jobs for the scripts above
> - Output data to JSON to pass between scripts
