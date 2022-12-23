# oscp
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
