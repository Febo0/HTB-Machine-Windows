# NameMachine — Forest

**Difficoltà:** Easy
**OS:** Windows
**Date:** 20/03/2025

## Scanning & Enumeration

`nmap -sC -sV -p- -oA nmap/forest 10.129.95.210`

<img width="1080" height="816" alt="image" src="https://github.com/user-attachments/assets/67510421-2b03-46b1-b0a8-ab98722ac1dd" />

Ports 80 and 443 are not open(no web server). The standard ports for a domain controller are detected: DNS(53), RPC(135), LDAP(389,3268), SMB(445), and WinRM(5985). 
So let's proceed by listing these services/ports.

### SMB Enumeration
I'm trying access a folder anonymously via SMB. But it fails, no readable share.

`smbclient -L //10.129.95.210 -N`

<img width="731" height="139" alt="image" src="https://github.com/user-attachments/assets/ff4a5332-4203-400d-ae8d-7f5b279ea82d" />

### LDAP Enumeration

`ldapsearch -H ldap://10.129.95.210 -x -b "DC=htb,DC=local" "(objectClass=User)" sAMAccountName > ldap_users.txt`

Query LDAP (port 389) anonymously (-x) by the base DN (-b "We're telling ldapsearch to start from the root of the htb.local domain and search downward from there").
(objectClass=User): This is a filter, since AD stores everything as objects: users, computers, printers, etc. So we're telling it, "I only want objects of the User type, ingore everything else".
sAMAccountName: This is a users Windows login name -> htb.local\svc-mark

`cat ldap_users.txt | grep sAMAccountName | awk '{print $2}' > users.txt`

<img width="249" height="499" alt="image" src="https://github.com/user-attachments/assets/4545c8af-8dc8-4622-9f06-7d7371680edf" />

