# C4B Quick-Start Guide - Supporting Scripts

This repository contains a set of supporting scripts used for the Chocolatey for Business (C4B) Quick-Start Guide.

These scripts can be used to assist in setup of a brand new Windows Server as a C4B Server.

## Completed
- [X] C4B Server initial bootstrapping
    - [X] Install of Chocolatey
    - [X] Prompt for C4B license, with validation
    - [X] Script to help turn your C4B license into a Chocolatey package
    - [X] Setup of local `choco-setup` directories
    - [X] Download of Chocolatey packages required for setup
    - [X] Use repo locations for file downloads (instead of ch0.co)
    - [X] Output data to JSON to pass between scripts
- [X] Sonatype Nexus Repository setup
    - [X] Install of Sonatype Nexus Repository Manager OSS instance
    - [X] Edit conofiguration to allow running of scripts
    - [X] Cleanup of all demo source repositories
    - [X] `ChocolateyInternal` NuGet v2 repository
    - [X] Add `ChocolateyTest` NuGet v2 repo
    - [X] `choco-install` raw repository, with a script for offline Chocolatey install
    - [X] Setup of `ChocolateyInternal` on C4B Server as source, with API key
    - [X] Setup of firewall rule for repository access
    - [X] Install MS Edge, and disable first-run experience
    - [X] Output data to JSON to pass between scripts
- [X] Chocolatey Central Management setup
    - [X] Install of MS SQL Express
    - [X] Creation and permissions of `ChocolateyManagement` DB
    - [X] Install of all 3 CCM packages, with correct parameters
    - [X] Output data to JSON to pass between scripts
- [X] Add Jenkins Setup
    - [X] Choco install of the package, pinned to version
    - [X] Pre-downloaded Jenkins scripts for Package Internalizer automation
    - [X] Pre-defined Jenkins jobs for the scripts above
    - [X] Output data to JSON to pass between scripts

## TODO

- [ ] Add `ClientSetup.ps1` script to `choco-install` raw repo
- [ ] Add SSL configuration for Nexus and CCM Web
- [ ] Update Readme to reflect new QuickStart process

## Outline of Current Quick-Start Process


### Step 1: Preparation of C4B Server

1. Copy your `chocolatey.license.xml` license file (from the email you received) onto your C4B Server.

1. Open a PowerShell console with the `Run as Administrator` option, and paste and run the following code:

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::tls12
$QuickStart = 'https://raw.githubusercontent.com/adilio/choco-quickstart-scripts/main/Start-C4BSetup.ps1'
Invoke-Expression -Command ((New-Object System.Net.WebClient).DownloadString($QuickStart))
```

### Step 2: Nexus Setup

1. In the same PowerShell Administrator console as above, paste and run the following code:

```powershell
Set-Location "$env:SystemDrive\choco-setup\files"
.\Start-C4BNexusSetup.ps1
```

### Step 3: CCM Setup

1. In the same PowerShell Administrator console as above, paste and run the following code:

```powershell
Set-Location "$env:SystemDrive\choco-setup\files"
.\Start-C4bCcmSetup.ps1
```

## Old Version of Doc (being slowly rewritten)

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
    a. your Chocolatey license installed in teh correct directory
    a. Installation of the Chocolatey Licensed extension, giving you access to features like Package Bulder, Package Internalizer, etc. (full list here).
1. **NuGet V2 Repository Server App**: Chocolatey works best with a NuGet V2 repository. This application hosts and manages versioning of your Chocolatey package artifacts, in their enhanced NuGet package (.nupkg) file format. This guide will help you setup [Sonatype Nexus Repository Manager (OSS)](https://www.sonatype.com/nexus-repository-oss).
1. **Chocolatey Central Management (CCM) Server App**: This is a standalone server that hosts the Chocolatey Central Management web interface, as well as the back-end database on which it relies. Currently, this interface provides reporting on packages installed on endpoints. In future, a feature will be added to enable deployments of packages and updates from this web console, as well.  can be found on the the [Chocolatey Central Management Setup page](xref:ccm-setup).
1. **Automation Pipeline**: These are the workstation or server endpoints you wish to manage packages on, with Chocolatey. Every node requires a license.

Repo Options:
- Jfrog [Artifactory](https://jfrog.com/artifactory/)
- Inedo ProGet
- Other NuGet V2 options discussed here: [Repository Options](xref:host-packages)

## Requirements

Below are the recommended guidelines of what's required for this specific deployment. More of each resource is preferred, if available.

### Administrator Workstation

* Windows 7+ / Windows Server 2003+ (ideally, Windows 10)
* 2 cores (more preferred)
* 4-8 GB RAM
* 100 GB of free disk space (for package creation)
* Internet access
* Administrator user rights
* All commands should be run from Administrator PowerShell window

### Repository Server (Nexus):

* Windows Server 2012+ (ideally, Windows Server 2016)
* 4+ CPU cores (more preferred)
* 16 GB+ RAM (4GB of RAM reserved specifically for JRE)
* 1 TB of free space for local artifact storage (details [here](https://help.sonatype.com/repomanager3/installation/system-requirements))
* Internet access
* Administrator user rights
* All commands should be run from Administrator PowerShell window

### Deployment/Configuration Management Solution

Again, this is out of the scope of this document, but _highly_ recommended when scaling out deployments. Read more about configuration management solutions on the [Infrastructure Automation page](xref:integrations).

### Central Management Server

As with configuration managers, this is out-of-scope for this document. Generally, though, enough resources to host an ASP.NET IIS deployment and a SQL Server back end are recommended. Requirements for this server are detailed [here](xref:ccm#requirements).

### Clients/Nodes:

* Start with 1 or 2 endpoints (scale up after initial config and testing)
* Windows 7+ / Windows Server 2003+ (ideally, Windows 10 / Windows Server 2016)
* PowerShell v2+ (not PowerShell Core)
* .NET Framework 4.6.1+ (minimum required version for Chocolatey Central Management access)
