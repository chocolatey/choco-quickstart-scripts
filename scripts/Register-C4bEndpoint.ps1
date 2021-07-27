# Here is a script you can run to setup your endpoints to connect to the C4B Server.
# This includes:
#    - Installing Chocolatey
#    - Installing your chocolatey-license
#    - Running the Client Setup, which sets up Nexus repo and CCM acccess

$HostName = {{hostname}} #This needs to be the same hostname as the CN/Subject of your SSL cert

# placeholder if using a self-signed cert

$downloader = New-Object -TypeName System.Net.WebClient
Invoke-Expression ($downloader.DownloadString("https://$($HostName):8443/repository/choco-install/ClientSetup.ps1"))