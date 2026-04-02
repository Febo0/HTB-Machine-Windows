# HackTheBox Writeup: Vintage

**Difficoltà:** Hard
**OS:** Windows
**Date:** 02/04/2026

## 1. Information Gathering & Reconnaissance
IP target: 10.129.231.205
Credentials: P.Rosa:Rosaisbest123

### Port Scanning

We begin our enumeration by mapping the open ports and services on the target using Nmap. 
We use -sC to run default enumeration scripts, -sV to determine service versions, and -vv to print the output as it's discovered
`
sudo nmap -sC -sV -oA nmap/vintage 10.129.231.205   
`

<img width="1003" height="533" alt="image" src="https://github.com/user-attachments/assets/1982cffe-79f1-42c9-9fd7-2d94eb9f506c" />

## 2. Enumeration & Initial Access
### SMB & Authentication Mechanisms

`
nxc smb dc01.vintage.htb -u P.Rosa -p 'Rosaisbest123' -k
`

<img width="1116" height="65" alt="image" src="https://github.com/user-attachments/assets/23c4cd69-4928-4dce-83f3-82080d60206a" />

`nxc smb dc01.vintage.htb -u P.Rosa -p 'Rosaisbest123'  -k --users `

<img width="1356" height="317" alt="image" src="https://github.com/user-attachments/assets/79c4a9f1-7b8e-4c4a-bcbb-ac1160c57fd4" />

### Active Directory Enumeration (BloodHound)


<img width="1206" height="356" alt="image" src="https://github.com/user-attachments/assets/01959115-fe53-4c44-ad18-c7d394680b7c" />

<img width="971" height="347" alt="image" src="https://github.com/user-attachments/assets/f0e49c1f-013b-4c36-9a6c-58ce10823443" />
