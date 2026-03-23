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

`nxc smb 10.129.232.127 -u 'r.parker' -p 'password'`

<img width="1080" height="58" alt="image" src="https://github.com/user-attachments/assets/36635ea3-88b5-4e93-b3c5-7d40a6d40831" />

### SMB Enumeration
