function New-TestVM {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ResourceGroupName,

        [Parameter()]
        [string]$Name = "qsg-$((New-Guid).ToString() -replace '-' -replace '^(.{11}).+$', '$1')",

        [ValidateSet("Win2022AzureEditionCore", "Win2019Datacenter")]
        [string]$Image = "Win2022AzureEditionCore",

        [ArgumentCompleter({
            param($a,$b,$WordToComplete,$d,$e)
            if (-not $script:VmSizes) {
                $script:VmSizes = Get-AzVMSize -Location 'eastus2'
            }
            $script:VmSizes.Name.Where{$_ -like "*$WordToComplete*"}
        })]
        [string]$Size = 'Standard_B4ms'
    )

    if (-not (Get-AzVM -ResourceGroupName $ResourceGroupName -Name $Name -ErrorAction SilentlyContinue)) {
        $VmArgs = @{
            ResourceGroup = $ResourceGroupName
            Name = $Name
            PublicIpAddressName = "$Name-ip"
            DomainNameLabel = $Name
            PublicIpSku = 'Basic'
            Image = $Image
            Size = $Size
            SecurityGroupName = "$ResourceGroupName-nsg"
            VirtualNetworkName = "$Name-vnet"
            NetworkInterfaceDeleteOption = 'Delete'
            OSDiskDeleteOption = 'Delete'
            Credential = [PSCredential]::new(
                'ccmadmin',
                (ConvertTo-SecureString "$(New-Guid)" -AsPlainText -Force)
            )
        }

        Write-Host "Creating VM '$($VmArgs.Name)'"
        $VM = New-AzVM @VmArgs
        $VM | Add-Member -MemberType NoteProperty -Name Credential -Value $VmArgs.Credential -PassThru
    }
}

function Request-WinRmAccessForTesting {
    param(
        [Parameter(Mandatory)]
        [string]$ResourceGroupName,

        [Parameter()]
        [string]$VmName,

        [Parameter()]
        [string]$IpAddress = $(Invoke-RestMethod https://api.ipify.org)
    )
    if ($NetworkSecurityGroup = Get-AzNetworkSecurityGroup -ResourceGroupName $ResourceGroupName -Name $ResourceGroupName-nsg -ErrorAction SilentlyContinue) {
        $RuleArgs = @{
            NetworkSecurityGroup = $NetworkSecurityGroup
            Name = "AllowWinRMSecure$($IpAddress -replace '\.')"
            Description = "Allow WinRM over HTTPS for '$($IpAddress)'"
            Access = "Allow"
            Protocol = "Tcp"
            Direction = "Inbound"
            Priority = 300
            SourceAddressPrefix = $IpAddress
            SourcePortRange = "*"
            DestinationAddressPrefix = "*"
            DestinationPortRange = 5986
        }

        if (($Rules = Get-AzNetworkSecurityRuleConfig -NetworkSecurityGroup $NetworkSecurityGroup).Name -notcontains $RuleArgs.Name) {
            Write-Host "Adding WinRM Rule to '$($NetworkSecurityGroup.Name)'"
            while ($Rules.Priority -contains $RuleArgs.Priority) {
                $RuleArgs.Priority++
            }
            $NewRules = Add-AzNetworkSecurityRuleConfig @RuleArgs
        }

        if ($NewRules) {
            $null = Set-AzNetworkSecurityGroup -NetworkSecurityGroup $NetworkSecurityGroup
        }
    }

    if ($VmName) {
        Write-Host "Enabling Remote PowerShell on '$($VMName)'"
        $null = Invoke-AzVMRunCommand -ResourceGroupName $ResourceGroupName -Name $VMName -CommandId EnableRemotePS
    }
}

function New-HoplessRemotingSession {
    [CmdletBinding()]
    [OutputType([System.Management.Automation.Runspaces.PSSession])]
    param(
        # The address to connect to
        [Parameter(Mandatory)]
        [string]$ComputerName,
        
        # The credential for the session
        [Parameter(Mandatory)]
        [PSCredential]$Credential
    )
    Write-Host "Creating remoting session for $($Credential.UserName)@$($ComputerName)"
    $RemotingArgs = @{
        ComputerName = $ComputerName
        Credential = $Credential
        UseSSL = $true
        SessionOption = New-PSSessionOption -SkipCACheck -SkipCNCheck
    }
    try {
        $Session = New-PSSession @RemotingArgs -ConfigurationName Hopless -ErrorAction Stop
    } catch [System.Management.Automation.Remoting.PSRemotingTransportException] {
        if ($_.Exception.Message -match 'Cannot find the Hopless session configuration') {
            Write-Host "Creating Hopless Configuration for $($Credential.UserName)@$($ComputerName)"
            # This throws an error when the session terminates, so we catch the PSRemotingTransportException 
            try {
                $null = Invoke-Command @RemotingArgs {
                    Register-PSSessionConfiguration -Name "Hopless" -RunAsCredential $using:Credential -Force -WarningAction SilentlyContinue
                } -ErrorAction Stop
            } catch [System.Management.Automation.Remoting.PSRemotingTransportException] {}
        
            Start-Sleep -Seconds 30  # Hate this, but just testing the idea out.
        
            Write-Verbose "Recreating Session after WinRM restart..."
            $Timeout = [System.Diagnostics.Stopwatch]::StartNew()
            while ($Session.Availability -ne 'Available' -and $Timeout.Elapsed.TotalSeconds -lt 180) {
                try {
                    $Session = New-PSSession @RemotingArgs -ConfigurationName Hopless
                } catch {
                    Start-Sleep -Seconds 5
                }
            }

            if ($Session.Availability -ne 'Available') {
                $Session
                Write-Error "Failed to re-establish a connection to '$($ComputerName)'"
            } else {
                Write-Host "Successfully reconnected after '$($Timeout.Elapsed.TotalSeconds)' seconds" 
            }
        } else {throw}
    }
    return $Session
}

function Install-DotNet {
    [OutputType([int32])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ParameterSetName = 'Separate')]
        [string]$ComputerName,

        [Parameter(Mandatory, ParameterSetName = 'Separate')]
        [PSCredential]$Credential,

        [Parameter(Mandatory, ParameterSetName = 'Session')]
        [System.Management.Automation.Runspaces.PSSession]$Session,

        [string]$DownloadPath = 'https://download.visualstudio.microsoft.com/download/pr/2d6bb6b2-226a-4baa-bdec-798822606ff1/8494001c276a4b96804cde7829c04d7f/ndp48-x86-x64-allos-enu.exe'
    )
    # Install Dotnet 4.8 if required
    $RequiresDotnet = Invoke-Command -Session $Session -ScriptBlock {
        (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full" -ErrorAction SilentlyContinue).Release -lt 528040
    }

    if ($RequiresDotnet) {
        Write-Host "Installing Dotnet 4.8 to '$($Vm.FullyQualifiedDomainName)'"
        $DotnetInstall = Invoke-Command -Session $Session -ScriptBlock {
            $NetFx48Url = $using:DownloadPath
            $NetFx48Path = $env:TEMP
            $NetFx48InstallerFile = 'ndp48-x86-x64-allos-enu.exe'
            $NetFx48Installer = Join-Path $NetFx48Path $NetFx48InstallerFile
            if (!(Test-Path $NetFx48Installer)) {
                Write-Host "Downloading `'$NetFx48Url`' to `'$NetFx48Installer`'"
                (New-Object Net.WebClient).DownloadFile("$NetFx48Url","$NetFx48Installer")
            }

            $psi = New-Object System.Diagnostics.ProcessStartInfo
            $psi.WorkingDirectory = "$NetFx48Path"
            $psi.FileName = "$NetFx48InstallerFile"
            $psi.Arguments = "/q /norestart"

            Write-Host "Installing `'$NetFx48Installer`'"
            $s = [System.Diagnostics.Process]::Start($psi);
            $s.WaitForExit();

            return $s.ExitCode
        }

        return $DotnetInstall
    } else {
        return 0  # No work performed / success
    }
}