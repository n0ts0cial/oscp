# oscp
## NMAP
##### NMAP - TCP PORTS QUICK SCAN
time nmap -T5 -sS -Pn -p- -oA scan-ports-tcp -vv 192.168.85.112
##### FILTER TCP PORT - LINES
cat scan-ports-tcp.nmap | grep -v "#" | grep "/tcp" | awk -F"/" '{ print $1}' > tcp-port-lines.txt
##### FILTER TCP PORT - CSV
cat tcp-port-lines.txt | sed -z 's/\n/,/g;s/,$/\n/'  > tcp-port.csv
