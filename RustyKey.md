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



``

``
``
``
``
``
``







