# HackTheBox Writeup: EscapeTwo

**Difficoltà:** Easy
**OS:** Windows
**Date:** 25/03/2026

## 1. Information Gathering & Reconnaissance
IP target: 10.129.232.128
Credentials: rose:KxEPkKe6R8su

### Port Scanning
We begin by mapping the open ports and services on the target using Nmap:

`sudo nmap -sC -sV -vv -oA nmap/escapetwo 10.129.232.128`

<img width="1174" height="817" alt="image" src="https://github.com/user-attachments/assets/0c2bc363-9595-4511-9521-80bd9519f81f" />


## 2. Enumeration & Initial Access
### SMB & Authentication Mechanisms

Let's look at all the shares on the server and find an interesting one.
`nxc smb dc01.sequel.htb -u rose -p KxEPkKe6R8su --shares`

<img width="1394" height="220" alt="image" src="https://github.com/user-attachments/assets/888f6273-a6ed-4975-a849-0cf442c974b5" />


`nxc smb dc01.sequel.htb -u rose -p KxEPkKe6R8su --users`
<img width="1410" height="243" alt="image" src="https://github.com/user-attachments/assets/b15e5298-9865-40dd-8209-1c519b423c7d" />

Given these users, there will most likely be a transition to MSSQL

`smbclient "//dc01.sequel.htb/Accounting Department" -U 'rose%KxEPkKe6R8su'`

<img width="1141" height="240" alt="image" src="https://github.com/user-attachments/assets/0239f34b-f0af-414e-a3d0-1873bd39fb70" />

After downloading the .xlsx files, we can unzip them because .xlsx files are compressed XML files.

`unzip accounts.xlsx`

<img width="1896" height="138" alt="image" src="https://github.com/user-attachments/assets/f9dd118c-ab0a-4277-8f4e-d562b5a7587d" />

`cat sharedStrings.xml | sed 's/></>\n</g' | sed 's/<[^>]*>//g' | grep -v '^$'`
<img width="823" height="406" alt="image" src="https://github.com/user-attachments/assets/2a919e58-9044-466e-84ad-5414df374603" />




``
``
``
``
``
``
``
``
