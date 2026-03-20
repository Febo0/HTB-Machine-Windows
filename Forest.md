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

`nxc smb 10.129.95.210  --pass-pol -u '' -p ''`

<img width="1453" height="346" alt="image" src="https://github.com/user-attachments/assets/a2096b48-4d32-4265-a9d2-ed322c8638c6" />

NetExec is a tool for enumerating Windows services on a network. This command queries the SMB service to retrieve the domain password policy anonymously. The two most important things we discovered are: 1) No lockout 2)Complexity requirements disabled.

### LDAP Enumeration

`ldapsearch -H ldap://10.129.95.210 -x -b "DC=htb,DC=local" "(objectClass=User)" sAMAccountName > ldap_users.txt`

Query LDAP (port 389) anonymously (-x) by the base DN (-b "We're telling ldapsearch to start from the root of the htb.local domain and search downward from there").
(objectClass=User): This is a filter, since AD stores everything as objects: users, computers, printers, etc. So we're telling it, "I only want objects of the User type, ingore everything else".
sAMAccountName: This is a users Windows login name -> htb.local\svc-mark

`cat ldap_users.txt | grep sAMAccountName | awk '{print $2}' > users.txt`

<img width="249" height="499" alt="image" src="https://github.com/user-attachments/assets/4545c8af-8dc8-4622-9f06-7d7371680edf" />

If you have a list of users, one thing to try is AS-REP rouasting. This attack targers users with an incorrect configuration setting called " Do not reqiore Kerberos preauthentication". But none of the users we found have this checkmark. when we performed the anonymous LDAP query, AD returned only the users located in certain public OUs. By default, anonimous LDAP access does not have read permissions on that specific OU.


### RPC Enumeration

rpcclient is a tool for interacting with the Windows RPC (Remote Procedure Call) service, a protocol that allows you to perform operations on a remote system. When listing all users in the domain, a new user named "svc-alfresco" appears.

<img width="425" height="542" alt="image" src="https://github.com/user-attachments/assets/8bb69614-4aa5-4435-9f5b-0310fb814cb4" />

## Exploitation

### AS-REP Roasting

`GetNPUsers.py htb.local/ -usersfile users.txt -format hashcat -dc-ip 10.129.95.210 `

<img width="1897" height="620" alt="image" src="https://github.com/user-attachments/assets/4d7de1b0-a8b6-4dd1-8ce4-21c7d444ee3f" />

svc-alfresco has this misconfiguration: "Dont require Kerberos preauthentication". If a user has this option checked, we can request their initial Kerberos ticket (AS-REP) from the server without needing to know theis password. The ticket contains a portion encrypted with the user's password, which we can attempt to crack offline. 

<img width="1723" height="817" alt="image" src="https://github.com/user-attachments/assets/0d19fe97-3946-47ec-98fd-3cab7c9c0022" />

## Foothold


