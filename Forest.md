# NameMachine — Forest

**Difficoltà:** Easy
**OS:** Windows
**Date:** 20/03/2025

## Scanning & Enumeration

`nmap -sC -sV -p- -oA nmap/forest 10.129.95.210`

<img width="1080" height="816" alt="image" src="https://github.com/user-attachments/assets/67510421-2b03-46b1-b0a8-ab98722ac1dd" />

Ports 80 and 443 are not open(no web server). The standard ports for a domain controller are detected: DNS(53), RPC(135), LDAP(389,3268), SMB(445), and WinRM(5985)
